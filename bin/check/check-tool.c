/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/symtab.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>
#include <dns/types.h>
#include <dns/zone.h>

#include "check-tool.h"

#ifndef CHECK_SIBLING
#define CHECK_SIBLING 1
#endif /* ifndef CHECK_SIBLING */

#ifndef CHECK_LOCAL
#define CHECK_LOCAL 1
#endif /* ifndef CHECK_LOCAL */

#define CHECK(r)                             \
	do {                                 \
		result = (r);                \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

#define ERR_IS_CNAME	   1
#define ERR_NO_ADDRESSES   2
#define ERR_LOOKUP_FAILURE 3
#define ERR_EXTRA_A	   4
#define ERR_EXTRA_AAAA	   5
#define ERR_MISSING_GLUE   5
#define ERR_IS_MXCNAME	   6
#define ERR_IS_SRVCNAME	   7

static const char *dbtype[] = { ZONEDB_DEFAULT };

int debug = 0;
const char *journal = NULL;
bool nomerge = true;
#if CHECK_LOCAL
bool docheckmx = true;
bool dochecksrv = true;
bool docheckns = true;
#else  /* if CHECK_LOCAL */
bool docheckmx = false;
bool dochecksrv = false;
bool docheckns = false;
#endif /* if CHECK_LOCAL */
dns_zoneopt_t zone_options = DNS_ZONEOPT_CHECKNS | DNS_ZONEOPT_CHECKMX |
			     DNS_ZONEOPT_CHECKDUPRR | DNS_ZONEOPT_CHECKSPF |
			     DNS_ZONEOPT_MANYERRORS | DNS_ZONEOPT_CHECKNAMES |
			     DNS_ZONEOPT_CHECKINTEGRITY |
#if CHECK_SIBLING
			     DNS_ZONEOPT_CHECKSIBLING |
#endif /* if CHECK_SIBLING */
			     DNS_ZONEOPT_CHECKSVCB | DNS_ZONEOPT_CHECKWILDCARD |
			     DNS_ZONEOPT_WARNMXCNAME | DNS_ZONEOPT_WARNSRVCNAME;

static isc_symtab_t *symtab = NULL;

static void
freekey(char *key, unsigned int type, isc_symvalue_t value, void *userarg) {
	UNUSED(type);
	UNUSED(value);
	isc_mem_free(userarg, key);
}

static void
add(char *key, int value) {
	isc_result_t result;
	isc_symvalue_t symvalue;

	if (symtab == NULL) {
		isc_symtab_create(isc_g_mctx, freekey, isc_g_mctx, false,
				  &symtab);
	}

	key = isc_mem_strdup(isc_g_mctx, key);

	symvalue.as_pointer = NULL;
	result = isc_symtab_define(symtab, key, value, symvalue,
				   isc_symexists_reject);
	if (result != ISC_R_SUCCESS) {
		isc_mem_free(isc_g_mctx, key);
	}
}

static bool
logged(char *key, int value) {
	isc_result_t result;

	if (symtab == NULL) {
		return false;
	}

	result = isc_symtab_lookup(symtab, key, value, NULL);
	if (result == ISC_R_SUCCESS) {
		return true;
	}
	return false;
}

static bool
checkisservedby(dns_zone_t *zone, dns_rdatatype_t type,
		const dns_name_t *name) {
	char namebuf[DNS_NAME_FORMATSIZE + 1];
	char ownerbuf[DNS_NAME_FORMATSIZE + 1];
	/*
	 * Not all getaddrinfo implementations distinguish NODATA
	 * from NXDOMAIN with PF_INET6 so use PF_UNSPEC and look at
	 * the returned ai_family values.
	 */
	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct addrinfo *ai = NULL, *cur;
	bool has_type = false;
	int eai;

	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	/*
	 * Turn off search.
	 */
	if (dns_name_countlabels(name) > 1U) {
		strlcat(namebuf, ".", sizeof(namebuf));
	}
	eai = getaddrinfo(namebuf, NULL, &hints, &ai);

	switch (eai) {
	case 0:
		cur = ai;
		while (cur != NULL) {
			if (cur->ai_family == AF_INET &&
			    type == dns_rdatatype_a)
			{
				has_type = true;
				break;
			}
			if (cur->ai_family == AF_INET6 &&
			    type == dns_rdatatype_aaaa)
			{
				has_type = true;
				break;
			}
			cur = cur->ai_next;
		}
		freeaddrinfo(ai);
		return has_type;
#if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME)
	case EAI_NODATA:
#endif /* if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME) */
	case EAI_NONAME:
		if (!logged(namebuf, ERR_NO_ADDRESSES)) {
			dns_name_format(dns_zone_getorigin(zone), ownerbuf,
					sizeof(ownerbuf));
			dns_name_format(name, namebuf, sizeof(namebuf) - 1);
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/NS '%s' (out of zone) "
				     "has no addresses records (A or AAAA)",
				     ownerbuf, namebuf);
			add(namebuf, ERR_NO_ADDRESSES);
		}
		return false;
	default:
		if (!logged(namebuf, ERR_LOOKUP_FAILURE)) {
			dns_name_format(dns_zone_getorigin(zone), ownerbuf,
					sizeof(ownerbuf));
			dns_name_format(name, namebuf, sizeof(namebuf) - 1);
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "getaddrinfo(%s) failed: %s", namebuf,
				     gai_strerror(eai));
			add(namebuf, ERR_LOOKUP_FAILURE);
		}
		return true;
	}
}

static bool
checkns(dns_zone_t *zone, const dns_name_t *name, const dns_name_t *owner,
	dns_rdataset_t *a, dns_rdataset_t *aaaa) {
	dns_rdataset_t *rdataset;
	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct addrinfo *ai = NULL, *cur;
	char namebuf[DNS_NAME_FORMATSIZE + 1];
	char ownerbuf[DNS_NAME_FORMATSIZE];
	char addrbuf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:123.123.123.123")];
	bool answer = true;
	bool match;
	const char *type;
	void *ptr = NULL;
	int eai;

	REQUIRE(a == NULL || !dns_rdataset_isassociated(a) ||
		a->type == dns_rdatatype_a);
	REQUIRE(aaaa == NULL || !dns_rdataset_isassociated(aaaa) ||
		aaaa->type == dns_rdatatype_aaaa);

	if (a == NULL || aaaa == NULL) {
		return answer;
	}

	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	/*
	 * Turn off search.
	 */
	if (dns_name_countlabels(name) > 1U) {
		strlcat(namebuf, ".", sizeof(namebuf));
	}
	dns_name_format(owner, ownerbuf, sizeof(ownerbuf));

	eai = getaddrinfo(namebuf, NULL, &hints, &ai);
	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	switch (eai) {
	case 0:
		/*
		 * Work around broken getaddrinfo() implementations that
		 * fail to set ai_canonname on first entry.
		 */
		cur = ai;
		while (cur != NULL && cur->ai_canonname == NULL &&
		       cur->ai_next != NULL)
		{
			cur = cur->ai_next;
		}
		if (cur != NULL && cur->ai_canonname != NULL &&
		    strcasecmp(cur->ai_canonname, namebuf) != 0 &&
		    !logged(namebuf, ERR_IS_CNAME))
		{
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/NS '%s' (out of zone) "
				     "is a CNAME '%s' (illegal)",
				     ownerbuf, namebuf, cur->ai_canonname);
			/* XXX950 make fatal for 9.5.0 */
			/* answer = false; */
			add(namebuf, ERR_IS_CNAME);
		}
		break;
	case EAI_NONAME:
#if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME)
	case EAI_NODATA:
#endif /* if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME) */
		if (!logged(namebuf, ERR_NO_ADDRESSES)) {
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/NS '%s' (out of zone) "
				     "has no addresses records (A or AAAA)",
				     ownerbuf, namebuf);
			add(namebuf, ERR_NO_ADDRESSES);
		}
		/* XXX950 make fatal for 9.5.0 */
		return true;

	default:
		if (!logged(namebuf, ERR_LOOKUP_FAILURE)) {
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "getaddrinfo(%s) failed: %s", namebuf,
				     gai_strerror(eai));
			add(namebuf, ERR_LOOKUP_FAILURE);
		}
		return true;
	}

	/*
	 * Check that all glue records really exist.
	 */
	if (!dns_rdataset_isassociated(a)) {
		goto checkaaaa;
	}

	DNS_RDATASET_FOREACH (a) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(a, &rdata);
		match = false;
		for (cur = ai; cur != NULL; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET) {
				continue;
			}
			ptr = &((struct sockaddr_in *)(cur->ai_addr))->sin_addr;
			if (memcmp(ptr, rdata.data, rdata.length) == 0) {
				match = true;
				break;
			}
		}
		if (!match && !logged(namebuf, ERR_EXTRA_A)) {
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/NS '%s' "
				     "extra GLUE A record (%s)",
				     ownerbuf, namebuf,
				     inet_ntop(AF_INET, rdata.data, addrbuf,
					       sizeof(addrbuf)));
			add(namebuf, ERR_EXTRA_A);
			/* XXX950 make fatal for 9.5.0 */
			/* answer = false; */
		}
	}

checkaaaa:
	if (!dns_rdataset_isassociated(aaaa)) {
		goto checkmissing;
	}
	DNS_RDATASET_FOREACH (aaaa) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(aaaa, &rdata);
		match = false;
		for (cur = ai; cur != NULL; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET6) {
				continue;
			}
			ptr = &((struct sockaddr_in6 *)(cur->ai_addr))
				       ->sin6_addr;
			if (memcmp(ptr, rdata.data, rdata.length) == 0) {
				match = true;
				break;
			}
		}
		if (!match && !logged(namebuf, ERR_EXTRA_AAAA)) {
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/NS '%s' "
				     "extra GLUE AAAA record (%s)",
				     ownerbuf, namebuf,
				     inet_ntop(AF_INET6, rdata.data, addrbuf,
					       sizeof(addrbuf)));
			add(namebuf, ERR_EXTRA_AAAA);
			/* XXX950 make fatal for 9.5.0. */
			/* answer = false; */
		}
	}

checkmissing:
	/*
	 * Check that all addresses appear in the glue.
	 */
	if (!logged(namebuf, ERR_MISSING_GLUE)) {
		bool missing_glue = false;
		for (cur = ai; cur != NULL; cur = cur->ai_next) {
			switch (cur->ai_family) {
			case AF_INET:
				rdataset = a;
				ptr = &((struct sockaddr_in *)(cur->ai_addr))
					       ->sin_addr;
				type = "A";
				break;
			case AF_INET6:
				rdataset = aaaa;
				ptr = &((struct sockaddr_in6 *)(cur->ai_addr))
					       ->sin6_addr;
				type = "AAAA";
				break;
			default:
				continue;
			}
			match = false;
			if (dns_rdataset_isassociated(rdataset)) {
				DNS_RDATASET_FOREACH (rdataset) {
					dns_rdata_t rdata = DNS_RDATA_INIT;
					dns_rdataset_current(rdataset, &rdata);
					if (memcmp(ptr, rdata.data,
						   rdata.length) == 0)
					{
						match = true;
						break;
					}
				}
			}

			if (!match) {
				dns_zone_log(zone, ISC_LOG_ERROR,
					     "%s/NS '%s' "
					     "missing GLUE %s record (%s)",
					     ownerbuf, namebuf, type,
					     inet_ntop(cur->ai_family, ptr,
						       addrbuf,
						       sizeof(addrbuf)));
				/* XXX950 make fatal for 9.5.0. */
				/* answer = false; */
				missing_glue = true;
			}
		}
		if (missing_glue) {
			add(namebuf, ERR_MISSING_GLUE);
		}
	}
	if (ai != NULL) {
		freeaddrinfo(ai);
	}
	return answer;
}

static bool
checkmx(dns_zone_t *zone, const dns_name_t *name, const dns_name_t *owner) {
	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct addrinfo *ai = NULL, *cur;
	char namebuf[DNS_NAME_FORMATSIZE + 1];
	char ownerbuf[DNS_NAME_FORMATSIZE];
	int eai;
	int level = ISC_LOG_ERROR;
	bool answer = true;

	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	/*
	 * Turn off search.
	 */
	if (dns_name_countlabels(name) > 1U) {
		strlcat(namebuf, ".", sizeof(namebuf));
	}
	dns_name_format(owner, ownerbuf, sizeof(ownerbuf));

	eai = getaddrinfo(namebuf, NULL, &hints, &ai);
	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	switch (eai) {
	case 0:
		/*
		 * Work around broken getaddrinfo() implementations that
		 * fail to set ai_canonname on first entry.
		 */
		cur = ai;
		while (cur != NULL && cur->ai_canonname == NULL &&
		       cur->ai_next != NULL)
		{
			cur = cur->ai_next;
		}
		if (cur != NULL && cur->ai_canonname != NULL &&
		    strcasecmp(cur->ai_canonname, namebuf) != 0)
		{
			if ((zone_options & DNS_ZONEOPT_WARNMXCNAME) != 0) {
				level = ISC_LOG_WARNING;
			}
			if ((zone_options & DNS_ZONEOPT_IGNOREMXCNAME) == 0) {
				if (!logged(namebuf, ERR_IS_MXCNAME)) {
					dns_zone_log(zone, level,
						     "%s/MX '%s' (out of zone)"
						     " is a CNAME '%s' "
						     "(illegal)",
						     ownerbuf, namebuf,
						     cur->ai_canonname);
					add(namebuf, ERR_IS_MXCNAME);
				}
				if (level == ISC_LOG_ERROR) {
					answer = false;
				}
			}
		}
		if (ai != NULL) {
			freeaddrinfo(ai);
		}
		return answer;

	case EAI_NONAME:
#if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME)
	case EAI_NODATA:
#endif /* if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME) */
		if (!logged(namebuf, ERR_NO_ADDRESSES)) {
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/MX '%s' (out of zone) "
				     "has no addresses records (A or AAAA)",
				     ownerbuf, namebuf);
			add(namebuf, ERR_NO_ADDRESSES);
		}
		/* XXX950 make fatal for 9.5.0. */
		return true;

	default:
		if (!logged(namebuf, ERR_LOOKUP_FAILURE)) {
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "getaddrinfo(%s) failed: %s", namebuf,
				     gai_strerror(eai));
			add(namebuf, ERR_LOOKUP_FAILURE);
		}
		return true;
	}
}

static bool
checksrv(dns_zone_t *zone, const dns_name_t *name, const dns_name_t *owner) {
	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct addrinfo *ai = NULL, *cur;
	char namebuf[DNS_NAME_FORMATSIZE + 1];
	char ownerbuf[DNS_NAME_FORMATSIZE];
	int eai;
	int level = ISC_LOG_ERROR;
	bool answer = true;

	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	/*
	 * Turn off search.
	 */
	if (dns_name_countlabels(name) > 1U) {
		strlcat(namebuf, ".", sizeof(namebuf));
	}
	dns_name_format(owner, ownerbuf, sizeof(ownerbuf));

	eai = getaddrinfo(namebuf, NULL, &hints, &ai);
	dns_name_format(name, namebuf, sizeof(namebuf) - 1);
	switch (eai) {
	case 0:
		/*
		 * Work around broken getaddrinfo() implementations that
		 * fail to set ai_canonname on first entry.
		 */
		cur = ai;
		while (cur != NULL && cur->ai_canonname == NULL &&
		       cur->ai_next != NULL)
		{
			cur = cur->ai_next;
		}
		if (cur != NULL && cur->ai_canonname != NULL &&
		    strcasecmp(cur->ai_canonname, namebuf) != 0)
		{
			if ((zone_options & DNS_ZONEOPT_WARNSRVCNAME) != 0) {
				level = ISC_LOG_WARNING;
			}
			if ((zone_options & DNS_ZONEOPT_IGNORESRVCNAME) == 0) {
				if (!logged(namebuf, ERR_IS_SRVCNAME)) {
					dns_zone_log(zone, level,
						     "%s/SRV '%s'"
						     " (out of zone) is a "
						     "CNAME '%s' (illegal)",
						     ownerbuf, namebuf,
						     cur->ai_canonname);
					add(namebuf, ERR_IS_SRVCNAME);
				}
				if (level == ISC_LOG_ERROR) {
					answer = false;
				}
			}
		}
		if (ai != NULL) {
			freeaddrinfo(ai);
		}
		return answer;

	case EAI_NONAME:
#if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME)
	case EAI_NODATA:
#endif /* if defined(EAI_NODATA) && (EAI_NODATA != EAI_NONAME) */
		if (!logged(namebuf, ERR_NO_ADDRESSES)) {
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "%s/SRV '%s' (out of zone) "
				     "has no addresses records (A or AAAA)",
				     ownerbuf, namebuf);
			add(namebuf, ERR_NO_ADDRESSES);
		}
		/* XXX950 make fatal for 9.5.0. */
		return true;

	default:
		if (!logged(namebuf, ERR_LOOKUP_FAILURE)) {
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "getaddrinfo(%s) failed: %s", namebuf,
				     gai_strerror(eai));
			add(namebuf, ERR_LOOKUP_FAILURE);
		}
		return true;
	}
}

isc_result_t
setup_logging(FILE *errout) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_FILE(errout), 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	return ISC_R_SUCCESS;
}

/*% load the zone */
isc_result_t
load_zone(isc_mem_t *mctx, const char *zonename, const char *filename,
	  dns_masterformat_t fileformat, const char *classname,
	  dns_ttl_t maxttl, dns_zone_t **zonep) {
	isc_result_t result;
	dns_rdataclass_t rdclass;
	isc_textregion_t region;
	isc_buffer_t buffer;
	dns_fixedname_t fixorigin;
	dns_name_t *origin;
	dns_zone_t *zone = NULL;

	REQUIRE(zonep == NULL || *zonep == NULL);

	if (debug) {
		fprintf(stderr, "loading \"%s\" from \"%s\" class \"%s\"\n",
			zonename, filename, classname);
	}

	dns_zone_create(&zone, mctx, 0);

	dns_zone_settype(zone, dns_zone_primary);

	isc_buffer_constinit(&buffer, zonename, strlen(zonename));
	isc_buffer_add(&buffer, strlen(zonename));
	origin = dns_fixedname_initname(&fixorigin);
	CHECK(dns_name_fromtext(origin, &buffer, dns_rootname, 0));
	dns_zone_setorigin(zone, origin);
	dns_zone_setdbtype(zone, 1, (const char *const *)dbtype);
	if (strcmp(filename, "-") == 0) {
		dns_zone_setstream(zone, stdin, fileformat,
				   &dns_master_style_default);
	} else {
		dns_zone_setfile(zone, filename, NULL, fileformat,
				 &dns_master_style_default);
	}
	if (journal != NULL) {
		dns_zone_setjournal(zone, journal);
	}

	region.base = UNCONST(classname);
	region.length = strlen(classname);
	CHECK(dns_rdataclass_fromtext(&rdclass, &region));

	dns_zone_setclass(zone, rdclass);
	dns_zone_setoption(zone, zone_options, true);
	dns_zone_setoption(zone, DNS_ZONEOPT_NOMERGE, nomerge);

	dns_zone_setmaxttl(zone, maxttl);

	if (docheckmx) {
		dns_zone_setcheckmx(zone, checkmx);
	}
	if (docheckns) {
		dns_zone_setcheckns(zone, checkns);
		dns_zone_setcheckisservedby(zone, checkisservedby);
	}
	if (dochecksrv) {
		dns_zone_setchecksrv(zone, checksrv);
	}

	CHECK(dns_zone_load(zone, false));

	if (zonep != NULL) {
		*zonep = zone;
		zone = NULL;
	}

cleanup:
	if (zone != NULL) {
		dns_zone_detach(&zone);
	}
	return result;
}

/*% dump the zone */
isc_result_t
dump_zone(const char *zonename, dns_zone_t *zone, const char *filename,
	  dns_masterformat_t fileformat, const dns_master_style_t *style,
	  const uint32_t rawversion) {
	isc_result_t result;
	FILE *output = stdout;
	const char *flags;

	flags = (fileformat == dns_masterformat_text) ? "w" : "wb";

	if (debug) {
		if (filename != NULL && strcmp(filename, "-") != 0) {
			fprintf(stderr, "dumping \"%s\" to \"%s\"\n", zonename,
				filename);
		} else {
			fprintf(stderr, "dumping \"%s\"\n", zonename);
		}
	}

	if (filename != NULL && strcmp(filename, "-") != 0) {
		result = isc_stdio_open(filename, flags, &output);

		if (result != ISC_R_SUCCESS) {
			fprintf(stderr,
				"could not open output "
				"file \"%s\" for writing\n",
				filename);
			return ISC_R_FAILURE;
		}
	}

	result = dns_zone_dumptostream(zone, output, fileformat, style,
				       rawversion);
	if (output != stdout) {
		(void)isc_stdio_close(output);
	}

	return result;
}
