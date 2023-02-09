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

/*! \file
 * \brief
 * The built-in "version", "hostname", "id", "authors" and "empty" databases.
 */

#include <stdio.h>
#include <string.h>

#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/dbiterator.h>
#include <dns/rdatalist.h>
#include <dns/rdatasetiter.h>
#include <dns/types.h>

#include <named/builtin.h>
#include <named/globals.h>
#include <named/os.h>
#include <named/server.h>

typedef struct builtin builtin_t;

static isc_result_t
do_authors_lookup(sdblookup_t *lookup);
static isc_result_t
do_dns64_lookup(sdblookup_t *lookup);
static isc_result_t
do_empty_lookup(sdblookup_t *lookup);
static isc_result_t
do_hostname_lookup(sdblookup_t *lookup);
static isc_result_t
do_id_lookup(sdblookup_t *lookup);
static isc_result_t
do_ipv4only_lookup(sdblookup_t *lookup);
static isc_result_t
do_ipv4reverse_lookup(sdblookup_t *lookup);
static isc_result_t
do_version_lookup(sdblookup_t *lookup);

/*
 * We can't use function pointers as the db_data directly
 * because ANSI C does not guarantee that function pointers
 * can safely be cast to void pointers and back.
 */

struct builtin {
	isc_result_t (*do_lookup)(sdblookup_t *lookup);
	char *server;
	char *contact;
};

static builtin_t authors_builtin = { do_authors_lookup, NULL, NULL };
static builtin_t dns64_builtin = { do_dns64_lookup, NULL, NULL };
static builtin_t empty_builtin = { do_empty_lookup, NULL, NULL };
static builtin_t hostname_builtin = { do_hostname_lookup, NULL, NULL };
static builtin_t id_builtin = { do_id_lookup, NULL, NULL };
static builtin_t ipv4only_builtin = { do_ipv4only_lookup, NULL, NULL };
static builtin_t ipv4reverse_builtin = { do_ipv4reverse_lookup, NULL, NULL };
static builtin_t version_builtin = { do_version_lookup, NULL, NULL };

static sdbimplementation_t *builtin_impl;
static sdbimplementation_t *dns64_impl;

/*
 * Pre computed HEX * 16 or 1 table.
 */
static const unsigned char hex16[256] = {
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*00*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*10*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*20*/
	0, 16,	32,  48,  64,  80,  96,	 112, 128, 144, 1, 1, 1, 1, 1, 1, /*30*/
	1, 160, 176, 192, 208, 224, 240, 1,   1,   1,	1, 1, 1, 1, 1, 1, /*40*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*50*/
	1, 160, 176, 192, 208, 224, 240, 1,   1,   1,	1, 1, 1, 1, 1, 1, /*60*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*70*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*80*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*90*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*A0*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*B0*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*C0*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*D0*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1, /*E0*/
	1, 1,	1,   1,	  1,   1,   1,	 1,   1,   1,	1, 1, 1, 1, 1, 1  /*F0*/
};

static const unsigned char decimal[] = "0123456789";
static const unsigned char ipv4only[] = "\010ipv4only\004arpa";

static size_t
dns64_rdata(unsigned char *v, size_t start, unsigned char *rdata) {
	size_t i, j = 0;

	for (i = 0; i < 4U; i++) {
		unsigned char c = v[start++];
		if (start == 7U) {
			start++;
		}
		if (c > 99) {
			rdata[j++] = 3;
			rdata[j++] = decimal[c / 100];
			c = c % 100;
			rdata[j++] = decimal[c / 10];
			c = c % 10;
			rdata[j++] = decimal[c];
		} else if (c > 9) {
			rdata[j++] = 2;
			rdata[j++] = decimal[c / 10];
			c = c % 10;
			rdata[j++] = decimal[c];
		} else {
			rdata[j++] = 1;
			rdata[j++] = decimal[c];
		}
	}
	memmove(&rdata[j], "\07in-addr\04arpa", 14);
	return (j + 14);
}

static isc_result_t
dns64_cname(const dns_name_t *zone, const dns_name_t *name,
	    sdblookup_t *lookup) {
	size_t zlen, nlen, j, len;
	unsigned char v[16], n;
	unsigned int i;
	unsigned char rdata[sizeof("123.123.123.123.in-addr.arpa.")];
	unsigned char *ndata;

	/*
	 * The combined length of the zone and name is 74.
	 *
	 * The minimum zone length is 10 ((3)ip6(4)arpa(0)).
	 *
	 * The length of name should always be even as we are expecting
	 * a series of nibbles.
	 */
	zlen = zone->length;
	nlen = name->length;
	if ((zlen + nlen) > 74U || zlen < 10U || (nlen % 2) != 0U) {
		return (ISC_R_NOTFOUND);
	}

	/*
	 * We assume the zone name is well formed.
	 */

	/*
	 * XXXMPA We could check the dns64 suffix here if we need to.
	 */
	/*
	 * Check that name is a series of nibbles.
	 * Compute the byte values that correspond to the nibbles as we go.
	 *
	 * Shift the final result 4 bits, by setting 'i' to 1, if we if we
	 * have a odd number of nibbles so that "must be zero" tests below
	 * are byte aligned and we correctly return ISC_R_NOTFOUND or
	 * ISC_R_SUCCESS.  We will not generate a CNAME in this case.
	 */
	ndata = name->ndata;
	i = (nlen % 4) == 2U ? 1 : 0;
	j = nlen;
	memset(v, 0, sizeof(v));
	while (j != 0U) {
		INSIST((i / 2) < sizeof(v));
		if (ndata[0] != 1) {
			return (ISC_R_NOTFOUND);
		}
		n = hex16[ndata[1] & 0xff];
		if (n == 1) {
			return (ISC_R_NOTFOUND);
		}
		v[i / 2] = n | (v[i / 2] >> 4);
		j -= 2;
		ndata += 2;
		i++;
	}

	/*
	 * If we get here then we know name only consisted of nibbles.
	 * Now we need to determine if the name exists or not and whether
	 * it corresponds to a empty node in the zone or there should be
	 * a CNAME.
	 */
#define ZLEN(x) (10 + (x) / 2)
	switch (zlen) {
	case ZLEN(32): /* prefix len 32 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 16U && v[(nlen - 1) / 4 - 4] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 8, rdata);
		break;
	case ZLEN(40): /* prefix len 40 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 12U && v[(nlen - 1) / 4 - 3] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 6, rdata);
		break;
	case ZLEN(48): /* prefix len 48 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 8U && v[(nlen - 1) / 4 - 2] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 5, rdata);
		break;
	case ZLEN(56): /* prefix len 56 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 4U && v[(nlen - 1) / 4 - 1] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 4, rdata);
		break;
	case ZLEN(64): /* prefix len 64 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (v[(nlen - 1) / 4] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 3, rdata);
		break;
	case ZLEN(96): /* prefix len 96 */
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_rdata(v, 0, rdata);
		break;
	default:
		/*
		 * This should never be reached unless someone adds a
		 * zone declaration with this internal type to named.conf.
		 */
		return (ISC_R_NOTFOUND);
	}

	/*
	 * Reverse of 192.0.0.170 or 192.0.0.171 maps to ipv4only.arpa.
	 */
	if ((v[0] == 170 || v[0] == 171) && v[1] == 0 && v[2] == 0 &&
	    v[3] == 192)
	{
		return (sdb_putrdata(lookup, dns_rdatatype_ptr, 3600, ipv4only,
				     sizeof(ipv4only)));
	}

	return (sdb_putrdata(lookup, dns_rdatatype_cname, 600, rdata,
			     (unsigned int)len));
}

static isc_result_t
builtin_lookup(const dns_name_t *zone, const dns_name_t *name, void *dbdata,
	       sdblookup_t *lookup, dns_clientinfomethods_t *methods,
	       dns_clientinfo_t *clientinfo) {
	builtin_t *b = (builtin_t *)dbdata;

	UNUSED(zone);
	UNUSED(methods);
	UNUSED(clientinfo);

	if (name->labels == 0 && name->length == 0) {
		return (b->do_lookup(lookup));
	} else {
		return (ISC_R_NOTFOUND);
	}
}

static isc_result_t
dns64_lookup(const dns_name_t *zone, const dns_name_t *name, void *dbdata,
	     sdblookup_t *lookup, dns_clientinfomethods_t *methods,
	     dns_clientinfo_t *clientinfo) {
	builtin_t *b = (builtin_t *)dbdata;

	UNUSED(methods);
	UNUSED(clientinfo);

	if (name->labels == 0 && name->length == 0) {
		return (b->do_lookup(lookup));
	} else {
		return (dns64_cname(zone, name, lookup));
	}
}

static isc_result_t
put_txt(sdblookup_t *lookup, const char *text) {
	unsigned char buf[256];
	unsigned int len = strlen(text);
	if (len > 255) {
		len = 255; /* Silently truncate */
	}
	buf[0] = len;
	memmove(&buf[1], text, len);
	return (sdb_putrdata(lookup, dns_rdatatype_txt, 0, buf, len + 1));
}

static isc_result_t
do_version_lookup(sdblookup_t *lookup) {
	if (named_g_server->version_set) {
		if (named_g_server->version == NULL) {
			return (ISC_R_SUCCESS);
		} else {
			return (put_txt(lookup, named_g_server->version));
		}
	} else {
		return (put_txt(lookup, PACKAGE_VERSION));
	}
}

static isc_result_t
do_hostname_lookup(sdblookup_t *lookup) {
	if (named_g_server->hostname_set) {
		if (named_g_server->hostname == NULL) {
			return (ISC_R_SUCCESS);
		} else {
			return (put_txt(lookup, named_g_server->hostname));
		}
	} else {
		char buf[256];
		if (gethostname(buf, sizeof(buf)) != 0) {
			return (ISC_R_FAILURE);
		}
		return (put_txt(lookup, buf));
	}
}

static isc_result_t
do_authors_lookup(sdblookup_t *lookup) {
	isc_result_t result;
	const char **p;
	static const char *authors[] = {
		"Mark Andrews",	  "Curtis Blackburn",	"James Brister",
		"Ben Cottrell",	  "John H. DuBois III", "Francis Dupont",
		"Michael Graff",  "Andreas Gustafsson", "Bob Halley",
		"Evan Hunt",	  "JINMEI Tatuya",	"Witold Krecicki",
		"David Lawrence", "Scott Mann",		"Danny Mayer",
		"Damien Neil",	  "Matt Nelson",	"Jeremy C. Reed",
		"Michael Sawyer", "Brian Wellington",	NULL
	};

	/*
	 * If a version string is specified, disable the authors.bind zone.
	 */
	if (named_g_server->version_set) {
		return (ISC_R_SUCCESS);
	}

	for (p = authors; *p != NULL; p++) {
		result = put_txt(lookup, *p);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
do_id_lookup(sdblookup_t *lookup) {
	if (named_g_server->sctx->usehostname) {
		char buf[256];
		if (gethostname(buf, sizeof(buf)) != 0) {
			return (ISC_R_FAILURE);
		}
		return (put_txt(lookup, buf));
	} else if (named_g_server->sctx->server_id != NULL) {
		return (put_txt(lookup, named_g_server->sctx->server_id));
	} else {
		return (ISC_R_SUCCESS);
	}
}

static isc_result_t
do_dns64_lookup(sdblookup_t *lookup) {
	UNUSED(lookup);
	return (ISC_R_SUCCESS);
}

static isc_result_t
do_empty_lookup(sdblookup_t *lookup) {
	UNUSED(lookup);
	return (ISC_R_SUCCESS);
}

static isc_result_t
do_ipv4only_lookup(sdblookup_t *lookup) {
	isc_result_t result;
	unsigned char data[2][4] = { { 192, 0, 0, 170 }, { 192, 0, 0, 171 } };

	for (int i = 0; i < 2; i++) {
		result = sdb_putrdata(lookup, dns_rdatatype_a, 3600, data[i],
				      4);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
do_ipv4reverse_lookup(sdblookup_t *lookup) {
	isc_result_t result;

	result = sdb_putrdata(lookup, dns_rdatatype_ptr, 3600, ipv4only,
			      sizeof(ipv4only));
	return (result);
}

static isc_result_t
builtin_authority(const char *zone, void *dbdata, sdblookup_t *lookup) {
	isc_result_t result;
	const char *contact = "hostmaster";
	const char *server = "@";
	builtin_t *b = (builtin_t *)dbdata;

	UNUSED(zone);
	UNUSED(dbdata);

	if (b == &empty_builtin) {
		server = ".";
		contact = ".";
	} else {
		if (b->server != NULL) {
			server = b->server;
		}
		if (b->contact != NULL) {
			contact = b->contact;
		}
	}

	result = sdb_putsoa(lookup, server, contact, 0);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_FAILURE);
	}

	result = sdb_putrr(lookup, "ns", 0, server);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_FAILURE);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
builtin_create(const char *zone, int argc, char **argv, void *driverdata,
	       void **dbdata) {
	REQUIRE(argc >= 1);

	UNUSED(zone);
	UNUSED(driverdata);

	if (strcmp(argv[0], "dns64") == 0 || strcmp(argv[0], "empty") == 0 ||
	    strcmp(argv[0], "ipv4only") == 0 ||
	    strcmp(argv[0], "ipv4reverse") == 0)
	{
		if (argc != 3) {
			return (DNS_R_SYNTAX);
		}
	} else if (argc != 1) {
		return (DNS_R_SYNTAX);
	}

	if (strcmp(argv[0], "authors") == 0) {
		*dbdata = &authors_builtin;
	} else if (strcmp(argv[0], "hostname") == 0) {
		*dbdata = &hostname_builtin;
	} else if (strcmp(argv[0], "id") == 0) {
		*dbdata = &id_builtin;
	} else if (strcmp(argv[0], "version") == 0) {
		*dbdata = &version_builtin;
	} else if (strcmp(argv[0], "dns64") == 0 ||
		   strcmp(argv[0], "empty") == 0 ||
		   strcmp(argv[0], "ipv4only") == 0 ||
		   strcmp(argv[0], "ipv4reverse") == 0)
	{
		builtin_t *empty;
		char *server;
		char *contact;

		if (argc != 3) {
			return (DNS_R_SYNTAX);
		}

		/*
		 * We don't want built-in zones to fail.  Fallback to
		 * the static configuration if memory allocation fails.
		 */
		empty = isc_mem_get(named_g_mctx, sizeof(*empty));
		server = isc_mem_strdup(named_g_mctx, argv[1]);
		contact = isc_mem_strdup(named_g_mctx, argv[2]);
		if (empty == NULL || server == NULL || contact == NULL) {
			if (strcmp(argv[0], "dns64") == 0) {
				*dbdata = &dns64_builtin;
			} else if (strcmp(argv[0], "empty") == 0) {
				*dbdata = &empty_builtin;
			} else if (strcmp(argv[0], "ipv4only") == 0) {
				*dbdata = &ipv4only_builtin;
			} else {
				*dbdata = &ipv4reverse_builtin;
			}
			if (server != NULL) {
				isc_mem_free(named_g_mctx, server);
			}
			if (contact != NULL) {
				isc_mem_free(named_g_mctx, contact);
			}
			if (empty != NULL) {
				isc_mem_put(named_g_mctx, empty,
					    sizeof(*empty));
			}
		} else {
			if (strcmp(argv[0], "dns64") == 0) {
				memmove(empty, &dns64_builtin,
					sizeof(empty_builtin));
			} else if (strcmp(argv[0], "empty") == 0) {
				memmove(empty, &empty_builtin,
					sizeof(empty_builtin));
			} else if (strcmp(argv[0], "ipv4only") == 0) {
				memmove(empty, &ipv4only_builtin,
					sizeof(empty_builtin));
			} else {
				memmove(empty, &ipv4reverse_builtin,
					sizeof(empty_builtin));
			}
			empty->server = server;
			empty->contact = contact;
			*dbdata = empty;
		}
	} else {
		return (ISC_R_NOTIMPLEMENTED);
	}
	return (ISC_R_SUCCESS);
}

static void
builtin_destroy(const char *zone, void *driverdata, void **dbdata) {
	builtin_t *b = (builtin_t *)*dbdata;

	UNUSED(zone);
	UNUSED(driverdata);

	/*
	 * Don't free the static versions.
	 */
	if (*dbdata == &authors_builtin || *dbdata == &dns64_builtin ||
	    *dbdata == &empty_builtin || *dbdata == &hostname_builtin ||
	    *dbdata == &id_builtin || *dbdata == &ipv4only_builtin ||
	    *dbdata == &ipv4reverse_builtin || *dbdata == &version_builtin)
	{
		return;
	}

	isc_mem_free(named_g_mctx, b->server);
	isc_mem_free(named_g_mctx, b->contact);
	isc_mem_put(named_g_mctx, b, sizeof(*b));
}

static sdbmethods_t builtin_methods = {
	.lookup = builtin_lookup,
	.authority = builtin_authority,
	.create = builtin_create,
	.destroy = builtin_destroy,
};

static sdbmethods_t dns64_methods = {
	.lookup = dns64_lookup,
	.authority = builtin_authority,
	.create = builtin_create,
	.destroy = builtin_destroy,
};

isc_result_t
named_builtin_init(void) {
	RUNTIME_CHECK(sdb_register("_builtin", &builtin_methods, NULL, 0,
				   named_g_mctx,
				   &builtin_impl) == ISC_R_SUCCESS);
	RUNTIME_CHECK(sdb_register("_dns64", &dns64_methods, NULL,
				   DNS_SDBFLAG_DNS64, named_g_mctx,
				   &dns64_impl) == ISC_R_SUCCESS);
	return (ISC_R_SUCCESS);
}

void
named_builtin_deinit(void) {
	sdb_unregister(&builtin_impl);
	sdb_unregister(&dns64_impl);
}

/*
 * Simple database implementation:
 * XXX this is only in builtin.c temporarily; everything from
 * here down will be moved to its own file later.
 */
struct sdbimplementation {
	const sdbmethods_t *methods;
	void *driverdata;
	unsigned int flags;
	isc_mem_t *mctx;
	isc_mutex_t driverlock;
	dns_dbimplementation_t *dbimp;
};

struct sdb {
	/* Unlocked */
	dns_db_t common;
	char *zone;
	sdbimplementation_t *implementation;
	void *dbdata;
};

struct sdblookup {
	/* Unlocked */
	unsigned int magic;
	sdb_t *sdb;
	ISC_LIST(dns_rdatalist_t) lists;
	ISC_LIST(isc_buffer_t) buffers;
	dns_name_t *name;
	ISC_LINK(sdblookup_t) link;
	dns_rdatacallbacks_t callbacks;

	/* Atomic */
	isc_refcount_t references;
};

typedef struct sdblookup sdbnode_t;

typedef struct sdb_rdatasetiter {
	dns_rdatasetiter_t common;
	dns_rdatalist_t *current;
} sdb_rdatasetiter_t;

#define SDB_MAGIC ISC_MAGIC('S', 'D', 'B', '-')

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define VALID_SDB(sdb) ((sdb) != NULL && (sdb)->common.impmagic == SDB_MAGIC)

#define SDBLOOKUP_MAGIC	      ISC_MAGIC('S', 'D', 'B', 'L')
#define VALID_SDBLOOKUP(sdbl) ISC_MAGIC_VALID(sdbl, SDBLOOKUP_MAGIC)
#define VALID_SDBNODE(sdbn)   VALID_SDBLOOKUP(sdbn)

/* These values are taken from RFC1537 */
#define SDB_DEFAULT_REFRESH 28800U  /* 8 hours */
#define SDB_DEFAULT_RETRY   7200U   /* 2 hours */
#define SDB_DEFAULT_EXPIRE  604800U /* 7 days */
#define SDB_DEFAULT_MINIMUM 86400U  /* 1 day */

/* This is a reasonable value */
#define SDB_DEFAULT_TTL (60 * 60 * 24)

static int dummy;

static isc_result_t
create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
       void *driverarg, dns_db_t **dbp);

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset);

static isc_result_t
createnode(sdb_t *sdb, sdbnode_t **nodep);

static void
destroynode(sdbnode_t *node);

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp);

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset);

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

/*
 * Functions used by implementors of simple databases
 */
isc_result_t
sdb_register(const char *drivername, const sdbmethods_t *methods,
	     void *driverdata, unsigned int flags, isc_mem_t *mctx,
	     sdbimplementation_t **sdbimp) {
	sdbimplementation_t *imp = NULL;
	isc_result_t result;

	REQUIRE(drivername != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->lookup != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(sdbimp != NULL && *sdbimp == NULL);
	REQUIRE((flags & ~DNS_SDBFLAG_DNS64) == 0);

	imp = isc_mem_get(mctx, sizeof(sdbimplementation_t));
	imp->methods = methods;
	imp->driverdata = driverdata;
	imp->flags = flags;
	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	isc_mutex_init(&imp->driverlock);

	imp->dbimp = NULL;
	result = dns_db_register(drivername, create, imp, mctx, &imp->dbimp);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_mutex;
	}
	*sdbimp = imp;

	return (ISC_R_SUCCESS);

cleanup_mutex:
	isc_mutex_destroy(&imp->driverlock);
	isc_mem_put(mctx, imp, sizeof(sdbimplementation_t));
	return (result);
}

void
sdb_unregister(sdbimplementation_t **sdbimp) {
	sdbimplementation_t *imp = NULL;

	REQUIRE(sdbimp != NULL && *sdbimp != NULL);

	imp = *sdbimp;
	*sdbimp = NULL;
	dns_db_unregister(&imp->dbimp);
	isc_mutex_destroy(&imp->driverlock);

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(sdbimplementation_t));
}

static unsigned int
initial_size(unsigned int len) {
	unsigned int size;

	for (size = 1024; size < (64 * 1024); size *= 2) {
		if (len < size) {
			return (size);
		}
	}
	return (65535);
}

isc_result_t
sdb_putrdata(sdblookup_t *lookup, dns_rdatatype_t typeval, dns_ttl_t ttl,
	     const unsigned char *rdatap, unsigned int rdlen) {
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdata_t *rdata = NULL;
	isc_buffer_t *rdatabuf = NULL;
	isc_mem_t *mctx = NULL;
	isc_region_t region;

	mctx = lookup->sdb->common.mctx;

	rdatalist = ISC_LIST_HEAD(lookup->lists);
	while (rdatalist != NULL) {
		if (rdatalist->type == typeval) {
			break;
		}
		rdatalist = ISC_LIST_NEXT(rdatalist, link);
	}

	if (rdatalist == NULL) {
		rdatalist = isc_mem_get(mctx, sizeof(dns_rdatalist_t));
		dns_rdatalist_init(rdatalist);
		rdatalist->rdclass = lookup->sdb->common.rdclass;
		rdatalist->type = typeval;
		rdatalist->ttl = ttl;
		ISC_LIST_APPEND(lookup->lists, rdatalist, link);
	} else if (rdatalist->ttl != ttl) {
		return (DNS_R_BADTTL);
	}

	rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));

	isc_buffer_allocate(mctx, &rdatabuf, rdlen);
	DE_CONST(rdatap, region.base);
	region.length = rdlen;
	isc_buffer_copyregion(rdatabuf, &region);
	isc_buffer_usedregion(rdatabuf, &region);
	dns_rdata_init(rdata);
	dns_rdata_fromregion(rdata, rdatalist->rdclass, rdatalist->type,
			     &region);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	ISC_LIST_APPEND(lookup->buffers, rdatabuf, link);

	return (ISC_R_SUCCESS);
}

isc_result_t
sdb_putrr(sdblookup_t *lookup, const char *type, dns_ttl_t ttl,
	  const char *data) {
	unsigned int datalen;
	dns_rdatatype_t typeval;
	isc_textregion_t r;
	isc_lex_t *lex = NULL;
	isc_result_t result;
	unsigned char *p = NULL;
	unsigned int size = 0; /* Init to suppress compiler warning */
	isc_mem_t *mctx = NULL;
	const dns_name_t *origin = NULL;
	isc_buffer_t b;
	isc_buffer_t rb;

	REQUIRE(VALID_SDBLOOKUP(lookup));
	REQUIRE(type != NULL);
	REQUIRE(data != NULL);

	mctx = lookup->sdb->common.mctx;

	DE_CONST(type, r.base);
	r.length = strlen(type);
	result = dns_rdatatype_fromtext(&typeval, &r);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	origin = &lookup->sdb->common.origin;

	isc_lex_create(mctx, 64, &lex);

	datalen = strlen(data);
	size = initial_size(datalen);
	do {
		isc_buffer_constinit(&b, data, datalen);
		isc_buffer_add(&b, datalen);
		result = isc_lex_openbuffer(lex, &b);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}

		if (size >= 65535) {
			size = 65535;
		}
		p = isc_mem_get(mctx, size);
		isc_buffer_init(&rb, p, size);
		result = dns_rdata_fromtext(NULL, lookup->sdb->common.rdclass,
					    typeval, lex, origin, 0, mctx, &rb,
					    &lookup->callbacks);
		if (result != ISC_R_NOSPACE) {
			break;
		}

		/*
		 * Is the RR too big?
		 */
		if (size >= 65535) {
			break;
		}
		isc_mem_put(mctx, p, size);
		p = NULL;
		size *= 2;
	} while (result == ISC_R_NOSPACE);

	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	result = sdb_putrdata(lookup, typeval, ttl, isc_buffer_base(&rb),
			      isc_buffer_usedlength(&rb));
failure:
	if (p != NULL) {
		isc_mem_put(mctx, p, size);
	}
	if (lex != NULL) {
		isc_lex_destroy(&lex);
	}

	return (result);
}

isc_result_t
sdb_putsoa(sdblookup_t *lookup, const char *mname, const char *rname,
	   uint32_t serial) {
	char str[2 * DNS_NAME_MAXTEXT + 5 * (sizeof("2147483647")) + 7];
	int n;

	REQUIRE(mname != NULL);
	REQUIRE(rname != NULL);

	n = snprintf(str, sizeof(str), "%s %s %u %u %u %u %u", mname, rname,
		     serial, SDB_DEFAULT_REFRESH, SDB_DEFAULT_RETRY,
		     SDB_DEFAULT_EXPIRE, SDB_DEFAULT_MINIMUM);
	if (n >= (int)sizeof(str) || n < 0) {
		return (ISC_R_NOSPACE);
	}
	return (sdb_putrr(lookup, "SOA", SDB_DEFAULT_TTL, str));
}

/*
 * DB routines
 */

static void
destroy(dns_db_t *db) {
	sdb_t *sdb = (sdb_t *)db;
	sdbimplementation_t *imp = sdb->implementation;

	isc_refcount_destroy(&sdb->common.references);

	if (imp != NULL && imp->methods->destroy != NULL) {
		LOCK(&sdb->implementation->driverlock);
		imp->methods->destroy(sdb->zone, imp->driverdata, &sdb->dbdata);
		UNLOCK(&sdb->implementation->driverlock);
	}

	isc_mem_free(sdb->common.mctx, sdb->zone);

	sdb->common.magic = 0;
	sdb->common.impmagic = 0;

	dns_name_free(&sdb->common.origin, sdb->common.mctx);

	isc_mem_putanddetach(&sdb->common.mctx, sdb, sizeof(sdb_t));
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	REQUIRE(versionp != NULL && *versionp == NULL);

	UNUSED(db);

	*versionp = (void *)&dummy;
	return;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	REQUIRE(source != NULL && source == (void *)&dummy);
	REQUIRE(targetp != NULL && *targetp == NULL);

	UNUSED(db);
	*targetp = source;
	return;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, bool commit) {
	REQUIRE(versionp != NULL && *versionp == (void *)&dummy);
	REQUIRE(!commit);

	UNUSED(db);
	UNUSED(commit);

	*versionp = NULL;
}

static isc_result_t
createnode(sdb_t *sdb, sdbnode_t **nodep) {
	sdbnode_t *node = NULL;

	node = isc_mem_get(sdb->common.mctx, sizeof(sdbnode_t));

	node->sdb = NULL;
	dns_db_attach((dns_db_t *)sdb, (dns_db_t **)&node->sdb);
	ISC_LIST_INIT(node->lists);
	ISC_LIST_INIT(node->buffers);
	ISC_LINK_INIT(node, link);
	node->name = NULL;
	dns_rdatacallbacks_init(&node->callbacks);

	isc_refcount_init(&node->references, 1);

	node->magic = SDBLOOKUP_MAGIC;

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static void
destroynode(sdbnode_t *node) {
	dns_rdatalist_t *list = NULL;
	dns_rdata_t *rdata = NULL;
	isc_buffer_t *b = NULL;
	sdb_t *sdb = NULL;
	isc_mem_t *mctx = NULL;

	sdb = node->sdb;
	mctx = sdb->common.mctx;

	while (!ISC_LIST_EMPTY(node->lists)) {
		list = ISC_LIST_HEAD(node->lists);
		while (!ISC_LIST_EMPTY(list->rdata)) {
			rdata = ISC_LIST_HEAD(list->rdata);
			ISC_LIST_UNLINK(list->rdata, rdata, link);
			isc_mem_put(mctx, rdata, sizeof(dns_rdata_t));
		}
		ISC_LIST_UNLINK(node->lists, list, link);
		isc_mem_put(mctx, list, sizeof(dns_rdatalist_t));
	}

	while (!ISC_LIST_EMPTY(node->buffers)) {
		b = ISC_LIST_HEAD(node->buffers);
		ISC_LIST_UNLINK(node->buffers, b, link);
		isc_buffer_free(&b);
	}

	if (node->name != NULL) {
		dns_name_free(node->name, mctx);
		isc_mem_put(mctx, node->name, sizeof(dns_name_t));
	}

	node->magic = 0;
	isc_mem_put(mctx, node, sizeof(sdbnode_t));
	dns_db_detach((dns_db_t **)(void *)&sdb);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep) {
	sdb_t *sdb = (sdb_t *)db;
	sdbnode_t *node = NULL;
	isc_result_t result;
	sdbimplementation_t *imp = NULL;
	dns_name_t relname;
	dns_name_t *name = NULL;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	imp = sdb->implementation;
	dns_name_init(&relname, NULL);
	name = &relname;

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	LOCK(&sdb->implementation->driverlock);
	result = imp->methods->lookup(&sdb->common.origin, name, sdb->dbdata,
				      node, NULL, NULL);
	UNLOCK(&sdb->implementation->driverlock);
	if (result != ISC_R_SUCCESS &&
	    !(result == ISC_R_NOTFOUND && imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (imp->methods->authority != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findnodeext(dns_db_t *db, const dns_name_t *name, bool create,
	    dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	    dns_dbnode_t **nodep) {
	sdb_t *sdb = (sdb_t *)db;
	sdbnode_t *node = NULL;
	isc_result_t result;
	bool isorigin;
	sdbimplementation_t *imp = NULL;
	dns_name_t relname;
	unsigned int labels;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	UNUSED(name);
	UNUSED(create);

	imp = sdb->implementation;

	isorigin = dns_name_equal(name, &sdb->common.origin);

	labels = dns_name_countlabels(name) - dns_name_countlabels(&db->origin);
	dns_name_init(&relname, NULL);
	dns_name_getlabelsequence(name, 0, labels, &relname);
	name = &relname;

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	LOCK(&sdb->implementation->driverlock);
	result = imp->methods->lookup(&sdb->common.origin, name, sdb->dbdata,
				      node, methods, clientinfo);
	UNLOCK(&sdb->implementation->driverlock);
	if (result != ISC_R_SUCCESS && !(result == ISC_R_NOTFOUND && isorigin &&
					 imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (isorigin && imp->methods->authority != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findext(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	dns_dbnode_t **nodep, dns_name_t *foundname,
	dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	sdb_t *sdb = (sdb_t *)db;
	dns_dbnode_t *node = NULL;
	dns_fixedname_t fname;
	dns_rdataset_t xrdataset;
	dns_name_t *xname = NULL;
	unsigned int nlabels, olabels;
	isc_result_t result;
	unsigned int i;
	unsigned int flags;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep == NULL || *nodep == NULL);
	REQUIRE(version == NULL || version == (void *)&dummy);

	UNUSED(options);

	if (!dns_name_issubdomain(name, &db->origin)) {
		return (DNS_R_NXDOMAIN);
	}

	olabels = dns_name_countlabels(&db->origin);
	nlabels = dns_name_countlabels(name);

	xname = dns_fixedname_initname(&fname);

	if (rdataset == NULL) {
		dns_rdataset_init(&xrdataset);
		rdataset = &xrdataset;
	}

	result = DNS_R_NXDOMAIN;
	flags = sdb->implementation->flags;
	i = (flags & DNS_SDBFLAG_DNS64) != 0 ? nlabels : olabels;
	for (; i <= nlabels; i++) {
		/*
		 * Look up the next label.
		 */
		dns_name_getlabelsequence(name, nlabels - i, i, xname);
		result = findnodeext(db, xname, false, methods, clientinfo,
				     &node);
		if (result == ISC_R_NOTFOUND) {
			/*
			 * No data at zone apex?
			 */
			if (i == olabels) {
				return (DNS_R_BADDB);
			}
			result = DNS_R_NXDOMAIN;
			continue;
		}
		if (result != ISC_R_SUCCESS) {
			return (result);
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * Look for a DNAME at the current label, unless this is
		 * the qname.
		 */
		if (i < nlabels) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_dname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_DNAME;
				break;
			}
		}

		/*
		 * Look for an NS at the current label, unless this is the
		 * origin or glue is ok.
		 */
		if (i != olabels && (options & DNS_DBFIND_GLUEOK) == 0) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_ns, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				if (i == nlabels && type == dns_rdatatype_any) {
					result = DNS_R_ZONECUT;
					dns_rdataset_disassociate(rdataset);
					if (sigrdataset != NULL &&
					    dns_rdataset_isassociated(
						    sigrdataset))
					{
						dns_rdataset_disassociate(
							sigrdataset);
					}
				} else {
					result = DNS_R_DELEGATION;
				}
				break;
			}
		}

		/*
		 * If the current name is not the qname, add another label
		 * and try again.
		 */
		if (i < nlabels) {
			destroynode(node);
			node = NULL;
			continue;
		}

	skip:
		/*
		 * If we're looking for ANY, we're done.
		 */
		if (type == dns_rdatatype_any) {
			result = ISC_R_SUCCESS;
			break;
		}

		/*
		 * Look for the qtype.
		 */
		result = findrdataset(db, node, version, type, 0, now, rdataset,
				      sigrdataset);
		if (result == ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Look for a CNAME
		 */
		if (type != dns_rdatatype_cname) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_cname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_CNAME;
				break;
			}
		}

		result = DNS_R_NXRRSET;
		break;
	}

	if (rdataset == &xrdataset && dns_rdataset_isassociated(rdataset)) {
		dns_rdataset_disassociate(rdataset);
	}

	if (foundname != NULL) {
		dns_name_copy(xname, foundname);
	}

	if (nodep != NULL) {
		*nodep = node;
	} else if (node != NULL) {
		detachnode(db, &node);
	}

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	sdb_t *sdb = (sdb_t *)db;
	sdbnode_t *node = (sdbnode_t *)source;

	REQUIRE(VALID_SDB(sdb));

	UNUSED(sdb);

	isc_refcount_increment(&node->references);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	sdb_t *sdb = (sdb_t *)db;
	sdbnode_t *node = NULL;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	UNUSED(sdb);

	node = (sdbnode_t *)(*targetp);

	*targetp = NULL;

	if (isc_refcount_decrement(&node->references) == 1) {
		destroynode(node);
	}
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	REQUIRE(VALID_SDBNODE(node));

	dns_rdatalist_t *list = NULL;
	sdbnode_t *sdbnode = (sdbnode_t *)node;

	UNUSED(db);
	UNUSED(version);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (type == dns_rdatatype_rrsig) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	list = ISC_LIST_HEAD(sdbnode->lists);
	while (list != NULL) {
		if (list->type == type) {
			break;
		}
		list = ISC_LIST_NEXT(list, link);
	}
	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}

	list_tordataset(list, db, node, rdataset);

	return (ISC_R_SUCCESS);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     unsigned int options, isc_stdtime_t now,
	     dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *iterator = NULL;

	REQUIRE(version == NULL || version == &dummy);

	UNUSED(version);
	UNUSED(now);

	iterator = isc_mem_get(db->mctx, sizeof(sdb_rdatasetiter_t));

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = NULL;
	attachnode(db, node, &iterator->common.node);
	iterator->common.version = version;
	iterator->common.options = options;
	iterator->common.now = now;

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static dns_dbmethods_t sdb_methods = {
	.destroy = destroy,
	.currentversion = currentversion,
	.attachversion = attachversion,
	.closeversion = closeversion,
	.attachnode = attachnode,
	.detachnode = detachnode,
	.findrdataset = findrdataset,
	.allrdatasets = allrdatasets,
	.getoriginnode = getoriginnode,
	.findnodeext = findnodeext,
	.findext = findext,
};

static isc_result_t
create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
       void *driverarg, dns_db_t **dbp) {
	sdb_t *sdb = NULL;
	isc_result_t result;
	char zonestr[DNS_NAME_MAXTEXT + 1];
	isc_buffer_t b;
	sdbimplementation_t *imp = NULL;

	REQUIRE(driverarg != NULL);

	imp = driverarg;

	if (type != dns_dbtype_zone) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	sdb = isc_mem_get(mctx, sizeof(*sdb));
	*sdb = (sdb_t){
		.common = { .methods = &sdb_methods, .rdclass = rdclass },
		.implementation = imp,
	};

	dns_name_init(&sdb->common.origin, NULL);

	isc_mem_attach(mctx, &sdb->common.mctx);

	result = dns_name_dupwithoffsets(origin, mctx, &sdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_lock;
	}

	isc_buffer_init(&b, zonestr, sizeof(zonestr));
	result = dns_name_totext(origin, true, &b);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_origin;
	}
	isc_buffer_putuint8(&b, 0);

	sdb->zone = isc_mem_strdup(mctx, zonestr);

	if (imp->methods->create != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->create(sdb->zone, argc, argv,
					      imp->driverdata, &sdb->dbdata);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_zonestr;
		}
	}

	isc_refcount_init(&sdb->common.references, 1);

	sdb->common.magic = DNS_DB_MAGIC;
	sdb->common.impmagic = SDB_MAGIC;

	*dbp = (dns_db_t *)sdb;

	return (ISC_R_SUCCESS);

cleanup_zonestr:
	isc_mem_free(mctx, sdb->zone);
cleanup_origin:
	dns_name_free(&sdb->common.origin, mctx);
cleanup_lock:
	isc_mem_putanddetach(&mctx, sdb, sizeof(sdb_t));

	return (result);
}

/*
 * Rdataset Methods
 */

static void
disassociate(dns_rdataset_t *rdataset) {
	dns_dbnode_t *node = rdataset->private5;
	sdbnode_t *sdbnode = (sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;

	detachnode(db, &node);
	dns_rdatalist_disassociate(rdataset);
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	dns_dbnode_t *node = source->private5;
	sdbnode_t *sdbnode = (sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;
	dns_dbnode_t *tempdb = NULL;

	dns_rdatalist_clone(source, target);
	attachnode(db, node, &tempdb);
	source->private5 = tempdb;
}

static dns_rdatasetmethods_t sdb_rdataset_methods = {
	disassociate,
	dns_rdatalist_first,
	dns_rdatalist_next,
	dns_rdatalist_current,
	rdataset_clone,
	dns_rdatalist_count,
	dns_rdatalist_addnoqname,
	dns_rdatalist_getnoqname,
	NULL, /* addclosest */
	NULL, /* getclosest */
	NULL, /* settrust */
	NULL, /* expire */
	NULL, /* clearprefetch */
	NULL, /* setownercase */
	NULL, /* getownercase */
	NULL  /* addglue */
};

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset) {
	/*
	 * The sdb rdataset is an rdatalist, with private5
	 * attached to the database node.
	 */
	dns_rdatalist_tordataset(rdatalist, rdataset);

	rdataset->methods = &sdb_rdataset_methods;
	dns_db_attachnode(db, node, &rdataset->private5);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)(*iteratorp);
	detachnode(sdbiterator->common.db, &sdbiterator->common.node);
	isc_mem_put(sdbiterator->common.db->mctx, sdbiterator,
		    sizeof(sdb_rdatasetiter_t));
	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;
	sdbnode_t *sdbnode = (sdbnode_t *)iterator->node;

	if (ISC_LIST_EMPTY(sdbnode->lists)) {
		return (ISC_R_NOMORE);
	}
	sdbiterator->current = ISC_LIST_HEAD(sdbnode->lists);
	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	sdbiterator->current = ISC_LIST_NEXT(sdbiterator->current, link);
	if (sdbiterator->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	list_tordataset(sdbiterator->current, iterator->db, iterator->node,
			rdataset);
}
