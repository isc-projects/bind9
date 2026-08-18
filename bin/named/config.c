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

#include <bind.keys.h>
#include <defaultconfig.h>
#include <inttypes.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/dir.h>
#include <isc/file.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/parseint.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/kasp.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/tsig.h>
#include <dns/zone.h>

#include <dst/dst.h>

#include <isccfg/check.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include <named/config.h>
#include <named/globals.h>

isc_result_t
named_config_parsedefaults(cfg_obj_t **conf) {
	isc_buffer_t b;

	isc_buffer_constinit(&b, common_named_defaultconf,
			     sizeof(common_named_defaultconf) - 1);
	isc_buffer_add(&b, sizeof(common_named_defaultconf) - 1);
	return cfg_parse_buffer(&b, __FILE__, 0, &cfg_type_namedconf,
				CFG_PCTX_NODEPRECATED | CFG_PCTX_NOOBSOLETE |
					CFG_PCTX_NOEXPERIMENTAL |
					CFG_PCTX_BUILTIN,
				conf);
}

isc_result_t
named_config_parsefile(cfg_obj_t **conf) {
	isc_result_t result;

	REQUIRE(conf && *conf == NULL);

	isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "parsing user configuration from '%s'",
		      named_g_conffile);

	CHECK(cfg_parse_file(named_g_conffile, &cfg_type_namedconf, 0, conf));

	/*
	 * Check the validity of the configuration.
	 *
	 * (Ignore plugin parameters for now; they will be
	 * checked later when the modules are actually loaded and
	 * registered.)
	 */
	CHECK(isccfg_check_namedconf(*conf, BIND_CHECK_ALGORITHMS, isc_g_mctx));

	goto out;

cleanup:
	if (*conf) {
		cfg_obj_detach(conf);
	}

out:
	return result;
}

isc_result_t
named_config_get(cfg_obj_t const *const *maps, const char *name,
		 const cfg_obj_t **obj) {
	int i;

	for (i = 0; maps[i] != NULL; i++) {
		if (cfg_map_get(maps[i], name, obj) == ISC_R_SUCCESS) {
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

isc_result_t
named_config_findopt(const cfg_obj_t *opts1, const cfg_obj_t *opts2,
		     const char *name, const cfg_obj_t **objp) {
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(*objp == NULL);

	if (opts1 != NULL) {
		result = cfg_map_get(opts1, name, objp);
	}
	if (*objp == NULL && opts2 != NULL) {
		result = cfg_map_get(opts2, name, objp);
	}

	return result;
}

isc_result_t
named_checknames_get(const cfg_obj_t **maps, const char *const names[],
		     const cfg_obj_t **obj) {
	const cfg_obj_t *checknames = NULL;
	const cfg_obj_t *type = NULL;
	const cfg_obj_t *value = NULL;
	int i;

	REQUIRE(maps != NULL);
	REQUIRE(names != NULL);
	REQUIRE(obj != NULL && *obj == NULL);

	for (i = 0; maps[i] != NULL; i++) {
		checknames = NULL;
		if (cfg_map_get(maps[i], "check-names", &checknames) ==
		    ISC_R_SUCCESS)
		{
			/*
			 * Zone map entry is not a list.
			 */
			if (checknames != NULL && !cfg_obj_islist(checknames)) {
				*obj = checknames;
				return ISC_R_SUCCESS;
			}
			CFG_LIST_FOREACH(checknames, element) {
				value = cfg_listelt_value(element);
				type = cfg_tuple_get(value, "type");

				for (size_t j = 0; names[j] != NULL; j++) {
					if (strcasecmp(cfg_obj_asstring(type),
						       names[j]) == 0)
					{
						*obj = cfg_tuple_get(value,
								     "mode");
						return ISC_R_SUCCESS;
					}
				}
			}
		}
	}
	return ISC_R_NOTFOUND;
}

int
named_config_listcount(const cfg_obj_t *list) {
	int i = 0;

	CFG_LIST_FOREACH(list, e) {
		i++;
	}

	return i;
}

isc_result_t
named_config_getclass(const cfg_obj_t *classobj, dns_rdataclass_t defclass,
		      dns_rdataclass_t *classp) {
	isc_textregion_t r;
	isc_result_t result;

	if (!cfg_obj_isstring(classobj)) {
		*classp = defclass;
		return ISC_R_SUCCESS;
	}
	r.base = UNCONST(cfg_obj_asstring(classobj));
	r.length = strlen(r.base);
	result = dns_rdataclass_fromtext(classp, &r);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(classobj, ISC_LOG_ERROR, "unknown class '%s'",
			    r.base);
	}
	return result;
}

isc_result_t
named_config_gettype(const cfg_obj_t *typeobj, dns_rdatatype_t deftype,
		     dns_rdatatype_t *typep) {
	isc_textregion_t r;
	isc_result_t result;

	if (!cfg_obj_isstring(typeobj)) {
		*typep = deftype;
		return ISC_R_SUCCESS;
	}
	r.base = UNCONST(cfg_obj_asstring(typeobj));
	r.length = strlen(r.base);
	result = dns_rdatatype_fromtext(typep, &r);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(typeobj, ISC_LOG_ERROR, "unknown type '%s'",
			    r.base);
	}
	return result;
}

dns_zonetype_t
named_config_getzonetype(const cfg_obj_t *zonetypeobj) {
	dns_zonetype_t ztype = dns_zone_none;
	const char *str;

	str = cfg_obj_asstring(zonetypeobj);
	if (strcasecmp(str, "primary") == 0 || strcasecmp(str, "master") == 0) {
		ztype = dns_zone_primary;
	} else if (strcasecmp(str, "secondary") == 0 ||
		   strcasecmp(str, "slave") == 0)
	{
		ztype = dns_zone_secondary;
	} else if (strcasecmp(str, "mirror") == 0) {
		ztype = dns_zone_mirror;
	} else if (strcasecmp(str, "stub") == 0) {
		ztype = dns_zone_stub;
	} else if (strcasecmp(str, "static-stub") == 0) {
		ztype = dns_zone_staticstub;
	} else if (strcasecmp(str, "redirect") == 0) {
		ztype = dns_zone_redirect;
	} else {
		UNREACHABLE();
	}
	return ztype;
}

isc_result_t
named_config_getremotesdef(const cfg_obj_t *cctx, const char *list,
			   const char *name, const cfg_obj_t **ret) {
	const cfg_obj_t *obj = NULL;

	REQUIRE(cctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ret != NULL && *ret == NULL);

	RETERR(cfg_map_get(cctx, list, &obj));
	CFG_LIST_FOREACH(obj, elt) {
		obj = cfg_listelt_value(elt);
		if (strcasecmp(cfg_obj_asstring(cfg_tuple_get(obj, "name")),
			       name) == 0)
		{
			*ret = obj;
			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}

static isc_result_t
named_config_getname(isc_mem_t *mctx, const cfg_obj_t *obj,
		     dns_name_t **namep) {
	REQUIRE(namep != NULL && *namep == NULL);

	const char *objstr;
	isc_result_t result;
	isc_buffer_t b;
	dns_fixedname_t fname;

	if (!cfg_obj_isstring(obj)) {
		*namep = NULL;
		return ISC_R_SUCCESS;
	}

	*namep = isc_mem_get(mctx, sizeof(**namep));
	dns_name_init(*namep);

	objstr = cfg_obj_asstring(obj);
	isc_buffer_constinit(&b, objstr, strlen(objstr));
	isc_buffer_add(&b, strlen(objstr));
	dns_fixedname_init(&fname);
	result = dns_name_fromtext(dns_fixedname_name(&fname), &b, dns_rootname,
				   0);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, *namep, sizeof(**namep));
		return result;
	}
	dns_name_dup(dns_fixedname_name(&fname), mctx, *namep);

	return ISC_R_SUCCESS;
}

#define grow_array(mctx, array, newlen, oldlen)                          \
	if (newlen >= oldlen) {                                          \
		array = isc_mem_creget(mctx, array, oldlen, newlen + 16, \
				       sizeof(array[0]));                \
		oldlen = newlen + 16;                                    \
	}

#define shrink_array(mctx, array, newlen, oldlen)                   \
	if (newlen < oldlen) {                                      \
		array = isc_mem_creget(mctx, array, oldlen, newlen, \
				       sizeof(array[0]));           \
		oldlen = newlen;                                    \
	}

static const char *remotesnames[4] = { "remote-servers", "parental-agents",
				       "primaries", "masters" };

typedef struct {
	isc_sockaddr_t *addrs;
	size_t addrsallocated;

	isc_sockaddr_t *sources;
	size_t sourcesallocated;

	dns_name_t **keys;
	size_t keysallocated;

	dns_name_t **tlss;
	size_t tlssallocated;

	size_t count; /* common to addrs, sources, keys and tlss */

	const char **seen;
	size_t seencount;
	size_t seenallocated;
} getipandkeylist_state_t;

static isc_result_t
getipandkeylist(in_port_t defport, in_port_t deftlsport,
		const cfg_obj_t *config, const cfg_obj_t *list,
		in_port_t listport, const cfg_obj_t *listkey,
		const cfg_obj_t *listtls, isc_mem_t *mctx,
		getipandkeylist_state_t *s) {
	const cfg_obj_t *addrlist = cfg_tuple_get(list, "addresses");
	const cfg_obj_t *portobj = cfg_tuple_get(list, "port");
	const cfg_obj_t *src4obj = cfg_tuple_get(list, "source");
	const cfg_obj_t *src6obj = cfg_tuple_get(list, "source-v6");
	in_port_t port = (in_port_t)0;
	isc_sockaddr_t src4;
	isc_sockaddr_t src6;
	isc_result_t result = ISC_R_SUCCESS;

	if (cfg_obj_isuint32(portobj)) {
		uint32_t val = cfg_obj_asuint32(portobj);
		if (val > UINT16_MAX) {
			cfg_obj_log(portobj, ISC_LOG_ERROR,
				    "port '%u' out of range", val);
			return ISC_R_RANGE;
		}
		port = (in_port_t)val;
	} else if (listport > 0) {
		/*
		 * No port in the current list, but it is a list named elsewhere
		 * where the port is defined, i.e:
		 *
		 * remote-servers bar { 10.53.0.4; };
		 * remote-servers foo port 5555 { bar; 10.54.0.3; };
		 *                                ^^^
		 *
		 * The current list is the list `bar`, and the server
		 * `10.53.0.4` has the port `5555` defined.
		 */
		port = listport;
	}

	if (src4obj != NULL && cfg_obj_issockaddr(src4obj)) {
		src4 = *cfg_obj_assockaddr(src4obj);
	} else {
		isc_sockaddr_any(&src4);
	}

	if (src6obj != NULL && cfg_obj_issockaddr(src6obj)) {
		src6 = *cfg_obj_assockaddr(src6obj);
	} else {
		isc_sockaddr_any6(&src6);
	}

	for (const cfg_listelt_t *element = cfg_list_first(addrlist);
	     element != NULL; element = cfg_list_next(element))
	{
		const cfg_obj_t *addr;
		const cfg_obj_t *key;
		const cfg_obj_t *tls;

		addr = cfg_tuple_get(cfg_listelt_value(element),
				     "remoteselement");
		key = cfg_tuple_get(cfg_listelt_value(element), "key");
		tls = cfg_tuple_get(cfg_listelt_value(element), "tls");

		/*
		 * If this is not an address, this is the name of a nested list,
		 * i.e.
		 *
		 * remote-servers nestedlist { 10.53.0.4; };
		 * remote-servers list { nestedlist key foo; 10.54.0.6; };
		 *                       ^^^^^^^^^^^^^^^^^^
		 *
		 * We are currently in the list `list`, and `addr` is the name
		 * `nestedlist`, so we'll immediately recurse to process
		 * `nestedlist` before processing the next element of `list`.
		 */
		if (!cfg_obj_issockaddr(addr)) {
			const char *listname = cfg_obj_asstring(addr);
			const cfg_obj_t *nestedlist = NULL;
			isc_result_t tresult;

			for (size_t i = 0; i < s->seencount; i++) {
				if (strcasecmp(s->seen[i], listname) == 0) {
					goto skiplist;
				}
			}

			grow_array(mctx, s->seen, s->seencount,
				   s->seenallocated);
			s->seen[s->seencount++] = listname;

			for (size_t i = 0; i < ARRAY_SIZE(remotesnames); i++) {
				tresult = named_config_getremotesdef(
					config, remotesnames[i], listname,
					&nestedlist);
				if (tresult == ISC_R_SUCCESS) {
					break;
				}
			}

			if (tresult != ISC_R_SUCCESS) {
				cfg_obj_log(addr, ISC_LOG_ERROR,
					    "remote-servers \"%s\" not found",
					    listname);
				/* Pop the list from the active recursion stack.
				 */
				s->seencount--;
				return tresult;
			}

			result = getipandkeylist(defport, deftlsport, config,
						 nestedlist, port, key, tls,
						 mctx, s);
			/* Pop the list from the active recursion stack. */
			s->seencount--;
			if (result != ISC_R_SUCCESS) {
				goto out;
			}
			continue;
		}

		grow_array(mctx, s->addrs, s->count, s->addrsallocated);
		grow_array(mctx, s->keys, s->count, s->keysallocated);
		grow_array(mctx, s->tlss, s->count, s->tlssallocated);
		grow_array(mctx, s->sources, s->count, s->sourcesallocated);

		s->addrs[s->count] = *cfg_obj_assockaddr(addr);

		result = named_config_getname(mctx, key, &s->keys[s->count]);
		if (result != ISC_R_SUCCESS) {
			goto out;
		}

		/*
		 * The `key` is not provided for this address, so, if we're
		 * inside a named list, get the `key` provided at the point the
		 * list is used.
		 */
		if (s->keys[s->count] == NULL && listkey != NULL) {
			result = named_config_getname(mctx, listkey,
						      &s->keys[s->count]);
			if (result != ISC_R_SUCCESS) {
				goto out;
			}
		}

		result = named_config_getname(mctx, tls, &s->tlss[s->count]);
		if (result != ISC_R_SUCCESS) {
			goto out;
		}

		/*
		 * The `tls` is not provided for this address, so, if we're
		 * inside a named list, get the `tls` provided at the point the
		 * named list is used.
		 */
		if (s->tlss[s->count] == NULL && listtls != NULL) {
			result = named_config_getname(mctx, listtls,
						      &s->tlss[s->count]);
		}

		/* If the port is unset, take it from one of the upper levels */
		if (isc_sockaddr_getport(&s->addrs[s->count]) == 0) {
			in_port_t addr_port = port;

			/* If unset, use the default port or tls-port */
			if (addr_port == 0) {
				if (s->tlss[s->count] != NULL) {
					addr_port = deftlsport;
				} else {
					addr_port = defport;
				}
			}

			isc_sockaddr_setport(&s->addrs[s->count], addr_port);
		}

		switch (isc_sockaddr_pf(&s->addrs[s->count])) {
		case PF_INET:
			s->sources[s->count] = src4;
			break;
		case PF_INET6:
			s->sources[s->count] = src6;
			break;
		default:
			result = ISC_R_NOTIMPLEMENTED;
			goto out;
		}

		s->count++;
	skiplist:
		continue;
	}

out:
	if (result != ISC_R_SUCCESS) {
		/*
		 * Reaching this point without success means we were in the
		 * middle of adding a new entry, so it needs to be counted for
		 * correctly free `s.keys` and `s.tlss` (as they potentially
		 * added a new element right before something fails)
		 */
		s->count++;
	}
	return result;
}

isc_result_t
named_config_getipandkeylist(const cfg_obj_t *config, const cfg_obj_t *list,
			     isc_mem_t *mctx, dns_ipkeylist_t *ipkl) {
	isc_result_t result;
	in_port_t def_port;
	in_port_t def_tlsport;
	getipandkeylist_state_t s = {};

	REQUIRE(ipkl != NULL);
	REQUIRE(ipkl->count == 0);
	REQUIRE(ipkl->addrs == NULL);
	REQUIRE(ipkl->keys == NULL);
	REQUIRE(ipkl->tlss == NULL);
	REQUIRE(ipkl->labels == NULL);
	REQUIRE(ipkl->allocated == 0);

	/*
	 * Get system defaults.
	 */
	CHECK(named_config_getport(config, "port", &def_port));

	CHECK(named_config_getport(config, "tls-port", &def_tlsport));

	/*
	 * Process the (nested) list(s).
	 */
	CHECK(getipandkeylist(def_port, def_tlsport, config, list, (in_port_t)0,
			      NULL, NULL, mctx, &s));

	shrink_array(mctx, s.addrs, s.count, s.addrsallocated);
	shrink_array(mctx, s.keys, s.count, s.keysallocated);
	shrink_array(mctx, s.tlss, s.count, s.tlssallocated);
	shrink_array(mctx, s.sources, s.count, s.sourcesallocated);

	ipkl->addrs = s.addrs;
	ipkl->keys = s.keys;
	ipkl->tlss = s.tlss;
	ipkl->sources = s.sources;
	ipkl->count = s.count;

	INSIST(s.addrsallocated == s.keysallocated);
	INSIST(s.addrsallocated == s.tlssallocated);
	INSIST(s.addrsallocated == s.sourcesallocated);
	ipkl->allocated = s.addrsallocated;

	if (s.seen != NULL) {
		/*
		 * `s.seen` is not shrinked (no point, as it's deleted right
		 * away anyway), so we need to use `s.seenallocated` to
		 * correctly free the array.
		 */
		isc_mem_cput(mctx, s.seen, s.seenallocated, sizeof(s.seen[0]));
	}

	return ISC_R_SUCCESS;

cleanup:
	/*
	 * Because we didn't shrinked the array back in this path, we need to
	 * use `s.*allocated` to correctly free the allocated arrays.
	 */
	if (s.addrs != NULL) {
		isc_mem_cput(mctx, s.addrs, s.count, sizeof(s.addrs[0]));
	}
	if (s.keys != NULL) {
		for (size_t i = 0; i < s.count; i++) {
			if (s.keys[i] == NULL) {
				continue;
			}
			if (dns_name_dynamic(s.keys[i])) {
				dns_name_free(s.keys[i], mctx);
			}
			isc_mem_put(mctx, s.keys[i], sizeof(*s.keys[i]));
		}
		isc_mem_cput(mctx, s.keys, s.keysallocated, sizeof(s.keys[0]));
	}
	if (s.tlss != NULL) {
		for (size_t i = 0; i < s.count; i++) {
			if (s.tlss[i] == NULL) {
				continue;
			}
			if (dns_name_dynamic(s.tlss[i])) {
				dns_name_free(s.tlss[i], mctx);
			}
			isc_mem_put(mctx, s.tlss[i], sizeof(*s.tlss[i]));
		}
		isc_mem_cput(mctx, s.tlss, s.tlssallocated, sizeof(s.tlss[0]));
	}
	if (s.sources != NULL) {
		isc_mem_cput(mctx, s.sources, s.sourcesallocated,
			     sizeof(s.sources[0]));
	}
	if (s.seen != NULL) {
		isc_mem_cput(mctx, s.seen, s.seenallocated, sizeof(s.seen[0]));
	}

	return result;
}

isc_result_t
named_config_getport(const cfg_obj_t *config, const char *type,
		     in_port_t *portp) {
	const cfg_obj_t *maps[3];
	const cfg_obj_t *options = NULL;
	const cfg_obj_t *portobj = NULL;
	isc_result_t result;
	int i;

	(void)cfg_map_get(config, "options", &options);
	i = 0;
	if (options != NULL) {
		maps[i++] = options;
	}
	maps[i] = NULL;

	result = named_config_get(maps, type, &portobj);
	INSIST(result == ISC_R_SUCCESS);
	if (cfg_obj_asuint32(portobj) > UINT16_MAX) {
		cfg_obj_log(portobj, ISC_LOG_ERROR, "port '%u' out of range",
			    cfg_obj_asuint32(portobj));
		return ISC_R_RANGE;
	}
	*portp = (in_port_t)cfg_obj_asuint32(portobj);
	return ISC_R_SUCCESS;
}

struct keyalgorithms {
	const char *str;
	enum {
		hmacnone,
		hmacmd5,
		hmacsha1,
		hmacsha224,
		hmacsha256,
		hmacsha384,
		hmacsha512
	} hmac;
	unsigned int type;
	uint16_t size;
} algorithms[] = { { "hmac-md5", hmacmd5, DST_ALG_HMACMD5, 128 },
		   { "hmac-md5.sig-alg.reg.int", hmacmd5, DST_ALG_HMACMD5, 0 },
		   { "hmac-md5.sig-alg.reg.int.", hmacmd5, DST_ALG_HMACMD5, 0 },
		   { "hmac-sha1", hmacsha1, DST_ALG_HMACSHA1, 160 },
		   { "hmac-sha224", hmacsha224, DST_ALG_HMACSHA224, 224 },
		   { "hmac-sha256", hmacsha256, DST_ALG_HMACSHA256, 256 },
		   { "hmac-sha384", hmacsha384, DST_ALG_HMACSHA384, 384 },
		   { "hmac-sha512", hmacsha512, DST_ALG_HMACSHA512, 512 },
		   { NULL, hmacnone, DST_ALG_UNKNOWN, 0 } };

isc_result_t
named_config_getkeyalgorithm(const char *str, unsigned int *typep,
			     uint16_t *digestbits) {
	int i;
	size_t len = 0;
	uint16_t bits;

	for (i = 0; algorithms[i].str != NULL; i++) {
		len = strlen(algorithms[i].str);
		if (strncasecmp(algorithms[i].str, str, len) == 0 &&
		    (str[len] == '\0' ||
		     (algorithms[i].size != 0 && str[len] == '-')))
		{
			break;
		}
	}
	if (algorithms[i].str == NULL) {
		return ISC_R_NOTFOUND;
	}
	if (str[len] == '-') {
		RETERR(isc_parse_uint16(&bits, str + len + 1, 10));
		if (bits > algorithms[i].size) {
			return ISC_R_RANGE;
		}
	} else if (algorithms[i].size == 0) {
		bits = 128;
	} else {
		bits = algorithms[i].size;
	}
	SET_IF_NOT_NULL(typep, algorithms[i].type);
	SET_IF_NOT_NULL(digestbits, bits);
	return ISC_R_SUCCESS;
}
