/*
 * Copyright (C) 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: check.c,v 1.19 2002/02/06 06:54:31 bwelling Exp $ */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/result.h>
#include <isc/symtab.h>
#include <isc/util.h>
#include <isc/region.h>

#include <dns/rdataclass.h>
#include <dns/fixedname.h>

#include <isccfg/cfg.h>

#include <bind9/check.h>

static isc_result_t
check_forward(cfg_obj_t *options, isc_log_t *logctx) {
	cfg_obj_t *forward = NULL;
	cfg_obj_t *forwarders = NULL;

	(void)cfg_map_get(options, "forward", &forward);
	(void)cfg_map_get(options, "forwarders", &forwarders);

	if (forward != NULL && forwarders == NULL) {
		cfg_obj_log(forward, logctx, ISC_LOG_ERROR,
			    "no matching 'forwarders' statement");
		return (ISC_R_FAILURE);
	}
	return (ISC_R_SUCCESS);
}

typedef struct {
	const char *name;
	unsigned int scale;
	unsigned int max;
} intervaltable;

static isc_result_t
check_options(cfg_obj_t *options, isc_log_t *logctx) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned int i;
	cfg_obj_t *obj = NULL;

	static intervaltable intervals[] = {
	{ "cleaning-interval", 60, 28 * 24 * 60 },	/* 28 days */
	{ "heartbeat-interval", 60, 28 * 24 * 60 },	/* 28 days */
	{ "interface-interval", 60, 28 * 24 * 60 },	/* 28 days */
	{ "max-transfer-idle-in", 60, 28 * 24 * 60 },	/* 28 days */
	{ "max-transfer-idle-out", 60, 28 * 24 * 60 },	/* 28 days */
	{ "max-transfer-time-in", 60, 28 * 24 * 60 },	/* 28 days */
	{ "max-transfer-time-out", 60, 28 * 24 * 60 },	/* 28 days */
	{ "sig-validity-interval", 86400, 10 * 366 },	/* 10 years */
	{ "statistics-interval", 60, 28 * 24 * 60 },	/* 28 days */
	};

	/*
	 * Check that fields specified in units of time other than seconds
	 * have reasonable values.
	 */
	for (i = 0; i < sizeof(intervals) / sizeof(intervals[0]); i++) {
		isc_uint32_t val;
		obj = NULL;
		(void)cfg_map_get(options, intervals[i].name, &obj);
		if (obj == NULL)
			continue;
		val = cfg_obj_asuint32(obj);
		if (val > intervals[i].max) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "%s '%u' is out of range (0..%u)",
				    intervals[i].name, val,
				    intervals[i].max);
			result = ISC_R_RANGE;
		} else if (val > (ISC_UINT32_MAX / intervals[i].scale)) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "%s '%d' is out of range",
				    intervals[i].name, val);
			result = ISC_R_RANGE;
		}
	}
	return (result);
}

#define MASTERZONE	1
#define SLAVEZONE	2
#define STUBZONE	4
#define HINTZONE	8
#define FORWARDZONE	16

typedef struct {
	const char *name;
	int allowed;
} optionstable;

static isc_result_t
check_zoneconf(cfg_obj_t *zconfig, isc_symtab_t *symtab,
	       dns_rdataclass_t defclass, isc_log_t *logctx)
{
	const char *zname;
	const char *typestr;
	unsigned int ztype;
	cfg_obj_t *zoptions;
	cfg_obj_t *obj = NULL;
	cfg_obj_t *addrlist = NULL;
	isc_symvalue_t symvalue;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult;
	unsigned int i;
	dns_rdataclass_t zclass;
	dns_fixedname_t fixedname;
	isc_buffer_t b;

	static optionstable options[] = {
	{ "allow-query", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "allow-notify", SLAVEZONE },
	{ "allow-transfer", MASTERZONE | SLAVEZONE },
	{ "notify", MASTERZONE | SLAVEZONE },
	{ "also-notify", MASTERZONE | SLAVEZONE },
	{ "dialup", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "forward", MASTERZONE | SLAVEZONE | STUBZONE | FORWARDZONE},
	{ "forwarders", MASTERZONE | SLAVEZONE | STUBZONE | FORWARDZONE},
	{ "maintain-ixfr-base", MASTERZONE | SLAVEZONE },
	{ "max-ixfr-log-size", MASTERZONE | SLAVEZONE },
	{ "notify-source", MASTERZONE | SLAVEZONE },
	{ "notify-source-v6", MASTERZONE | SLAVEZONE },
	{ "transfer-source", SLAVEZONE | STUBZONE },
	{ "transfer-source-v6", SLAVEZONE | STUBZONE },
	{ "max-transfer-time-in", SLAVEZONE | STUBZONE },
	{ "max-transfer-time-out", MASTERZONE | SLAVEZONE },
	{ "max-transfer-idle-in", SLAVEZONE | STUBZONE },
	{ "max-transfer-idle-out", MASTERZONE | SLAVEZONE },
	{ "max-retry-time", SLAVEZONE | STUBZONE },
	{ "min-retry-time", SLAVEZONE | STUBZONE },
	{ "max-refresh-time", SLAVEZONE | STUBZONE },
	{ "min-refresh-time", SLAVEZONE | STUBZONE },
	{ "sig-validity-interval", MASTERZONE },
	{ "zone-statistics", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "allow-update", MASTERZONE },
	{ "allow-update-forwarding", SLAVEZONE },
	{ "file", MASTERZONE | SLAVEZONE | STUBZONE | HINTZONE},
	{ "ixfr-base", MASTERZONE | SLAVEZONE },
	{ "ixfr-tmp-file", MASTERZONE | SLAVEZONE },
	{ "masters", SLAVEZONE | STUBZONE },
	{ "pubkey", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "update-policy", MASTERZONE },
	{ "database", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "key-directory", MASTERZONE },
	};

	static optionstable dialups[] = {
	{ "notify", MASTERZONE | SLAVEZONE },
	{ "notify-passive", SLAVEZONE },
	{ "refresh", SLAVEZONE | STUBZONE },
	{ "passive", SLAVEZONE | STUBZONE },
	};

	zname = cfg_obj_asstring(cfg_tuple_get(zconfig, "name"));

	zoptions = cfg_tuple_get(zconfig, "options");

	obj = NULL;
	(void)cfg_map_get(zoptions, "type", &obj);
	if (obj == NULL) {
		cfg_obj_log(zconfig, logctx, ISC_LOG_ERROR,
			    "zone '%s': type not present", zname);
		return (ISC_R_FAILURE);
	}

	typestr = cfg_obj_asstring(obj);
	if (strcasecmp(typestr, "master") == 0)
		ztype = MASTERZONE;
	else if (strcasecmp(typestr, "slave") == 0)
		ztype = SLAVEZONE;
	else if (strcasecmp(typestr, "stub") == 0)
		ztype = STUBZONE;
	else if (strcasecmp(typestr, "forward") == 0)
		ztype = FORWARDZONE;
	else if (strcasecmp(typestr, "hint") == 0)
		ztype = HINTZONE;
	else {
		cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
			    "zone '%s': invalid type %s",
			    zname, typestr);
		return (ISC_R_FAILURE);
	}

	obj = cfg_tuple_get(zconfig, "class");
	if (cfg_obj_isstring(obj)) {
		isc_textregion_t r;

		DE_CONST(cfg_obj_asstring(obj), r.base);
		r.length = strlen(r.base);
		result = dns_rdataclass_fromtext(&zclass, &r);
		if (result != ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "zone '%s': invalid class %s",
				    zname, r.base);
			return (ISC_R_FAILURE);
		}
		if (zclass != defclass) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "zone '%s': class '%s' does not "
				    "match view/default class",
				    zname, r.base);
			return (ISC_R_FAILURE);
		}
	}

	/*
	 * Look for an already existing zone.
	 * We need to make this cannonical as isc_symtab_define()
	 * deals with strings.
	 */
	dns_fixedname_init(&fixedname);
	isc_buffer_init(&b, zname, strlen(zname));
	isc_buffer_add(&b, strlen(zname));
	result = dns_name_fromtext(dns_fixedname_name(&fixedname), &b,
				   dns_rootname, ISC_TRUE, NULL);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(zconfig, logctx, ISC_LOG_ERROR,
			    "zone '%s': is not a valid name", zname);
		result = ISC_R_FAILURE;
	} else {
		char namebuf[DNS_NAME_FORMATSIZE];
		dns_name_format(dns_fixedname_name(&fixedname),
				namebuf, sizeof(namebuf));
		symvalue.as_pointer = NULL;
		tresult = isc_symtab_define(symtab, namebuf,
					    ztype == HINTZONE ? 1 : 2,
					    symvalue, isc_symexists_reject);
		if (tresult == ISC_R_EXISTS) {
			cfg_obj_log(zconfig, logctx, ISC_LOG_ERROR,
				    "zone '%s': already exists ", zname);
			result = ISC_R_FAILURE;
		} else if (tresult != ISC_R_SUCCESS)
			return (tresult);
	}

	/*
	 * Look for inappropriate options for the given zone type.
	 */
	for (i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		obj = NULL;
		if ((options[i].allowed & ztype) == 0 &&
		    cfg_map_get(zoptions, options[i].name, &obj) ==
		    ISC_R_SUCCESS)
		{
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "option '%s' is not allowed in '%s' "
				    "zone '%s'",
				    options[i].name, typestr, zname);
			result = ISC_R_FAILURE;
		}
	}

	/*
	 * Slave & stub zones must have a "masters" field.
	 */
	if (ztype == SLAVEZONE || ztype == STUBZONE) {
		obj = NULL;
		if (cfg_map_get(zoptions, "masters", &obj) != ISC_R_SUCCESS) {
			cfg_obj_log(zoptions, logctx, ISC_LOG_ERROR,
				    "zone '%s': missing 'masters' entry",
				    zname);
			result = ISC_R_FAILURE;
		}
		addrlist = cfg_tuple_get(obj, "addresses");
		if (cfg_list_first(addrlist) == NULL) {
			cfg_obj_log(zoptions, logctx, ISC_LOG_ERROR,
				    "zone '%s': empty 'masters' entry",
				    zname);
			result = ISC_R_FAILURE;
		}
	}

	/*
	 * Master zones can't have both "allow-update" and "update-policy".
	 */
	if (ztype == MASTERZONE) {
		isc_result_t res1, res2;
		obj = NULL;
		res1 = cfg_map_get(zoptions, "allow-update", &obj);
		obj = NULL;
		res2 = cfg_map_get(zoptions, "update-policy", &obj);
		if (res1 == ISC_R_SUCCESS && res2 == ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "zone '%s': 'allow-update' is ignored "
				    "when 'update-policy' is present",
				    zname);
			result = ISC_R_FAILURE;
		}
	}

	/*
	 * Check the excessively complicated "dialup" option.
	 */
	if (ztype == MASTERZONE || ztype == SLAVEZONE || ztype == STUBZONE) {
		cfg_obj_t *dialup = NULL;
		(void)cfg_map_get(zoptions, "dialup", &dialup);
		if (dialup != NULL && cfg_obj_isstring(dialup)) {
			char *str = cfg_obj_asstring(dialup);
			for (i = 0;
			     i < sizeof(dialups) / sizeof(dialups[0]);
			     i++)
			{
				if (strcasecmp(dialups[i].name, str) != 0)
					continue;
				if ((dialups[i].allowed & ztype) == 0) {
					cfg_obj_log(obj, logctx,
						    ISC_LOG_ERROR,
						    "dialup type '%s' is not "
						    "allowed in '%s' "
						    "zone '%s'",
						    str, typestr, zname);
					result = ISC_R_FAILURE;
				}
				break;
			}
			if (i == sizeof(dialups) / sizeof(dialups[0])) {
				cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
					    "invalid dialup type '%s' in zone "
					    "'%s'", str, zname);
				result = ISC_R_FAILURE;
			}
		}
	}

	/*
	 * Check that forwarding is reasonable.
	 */
	if (check_forward(zoptions, logctx) != ISC_R_SUCCESS)
		result = ISC_R_FAILURE;

	/*
	 * Check various options.
	 */
	tresult = check_options(zoptions, logctx);
	if (tresult != ISC_R_SUCCESS)
		result = tresult;

	return (result);
}

isc_result_t
bind9_check_key(cfg_obj_t *key, isc_log_t *logctx) {
	cfg_obj_t *algobj = NULL;
	cfg_obj_t *secretobj = NULL;
	const char *keyname = cfg_obj_asstring(cfg_map_getname(key));
	
	(void)cfg_map_get(key, "algorithm", &algobj);
	(void)cfg_map_get(key, "secret", &secretobj);
	if (secretobj == NULL || algobj == NULL) {
		cfg_obj_log(key, logctx, ISC_LOG_ERROR,
			    "key '%s' must have both 'secret' and "
			    "'algorithm' defined",
			    keyname);
		return (ISC_R_FAILURE);
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
check_keylist(cfg_obj_t *keys, isc_symtab_t *symtab, isc_log_t *logctx) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult;
	cfg_listelt_t *element;

	for (element = cfg_list_first(keys);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		cfg_obj_t *key = cfg_listelt_value(element);
		const char *keyname = cfg_obj_asstring(cfg_map_getname(key));
		isc_symvalue_t symvalue;

		symvalue.as_pointer = NULL;
		tresult = isc_symtab_define(symtab, keyname, 1,
					    symvalue, isc_symexists_reject);
		if (tresult == ISC_R_EXISTS) {
			cfg_obj_log(key, logctx, ISC_LOG_ERROR,
				    "key '%s': already exists ", keyname);
			result = tresult;
		} else if (tresult != ISC_R_SUCCESS)
			return (tresult);

		tresult = bind9_check_key(key, logctx);
		if (tresult != ISC_R_SUCCESS)
			return (tresult);
	}
	return (result);
}
		
static isc_result_t
check_viewconf(cfg_obj_t *config, cfg_obj_t *vconfig, dns_rdataclass_t vclass,
	       isc_log_t *logctx, isc_mem_t *mctx)
{
	cfg_obj_t *zones = NULL;
	cfg_obj_t *keys = NULL;
	cfg_listelt_t *element;
	isc_symtab_t *symtab = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult = ISC_R_SUCCESS;

	/*
	 * Check that all zone statements are syntactically correct and
	 * there are no duplicate zones.
	 */
	tresult = isc_symtab_create(mctx, 100, NULL, NULL, ISC_TRUE, &symtab);
	if (tresult != ISC_R_SUCCESS)
		return (ISC_R_NOMEMORY);

	if (vconfig != NULL)
		(void)cfg_map_get(vconfig, "zone", &zones);
	else
		(void)cfg_map_get(config, "zone", &zones);

	for (element = cfg_list_first(zones);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		isc_result_t tresult;
		cfg_obj_t *zone = cfg_listelt_value(element);

		tresult = check_zoneconf(zone, symtab, vclass, logctx);
		if (tresult != ISC_R_SUCCESS)
			result = ISC_R_FAILURE;
	}

	isc_symtab_destroy(&symtab);

	/*
	 * Check that all key statements are syntactically correct and
	 * there are no duplicate keys.
	 */
	tresult = isc_symtab_create(mctx, 100, NULL, NULL, ISC_TRUE, &symtab);
	if (tresult != ISC_R_SUCCESS)
		return (ISC_R_NOMEMORY);

	(void)cfg_map_get(config, "key", &keys);
	tresult = check_keylist(keys, symtab, logctx);
	if (tresult == ISC_R_EXISTS)
		result = ISC_R_FAILURE;
	else if (tresult != ISC_R_SUCCESS) {
		isc_symtab_destroy(&symtab);
		return (tresult);
	}
	
	if (vconfig != NULL) {
		keys = NULL;
		(void)cfg_map_get(vconfig, "key", &keys);
		tresult = check_keylist(keys, symtab, logctx);
		if (tresult == ISC_R_EXISTS)
			result = ISC_R_FAILURE;
		else if (tresult != ISC_R_SUCCESS) {
			isc_symtab_destroy(&symtab);
			return (tresult);
		}
	}

	isc_symtab_destroy(&symtab);

	/*
	 * Check that forwarding is reasonable.
	 */
	if (vconfig == NULL) {
		cfg_obj_t *options = NULL;
		(void)cfg_map_get(config, "options", &options);
		if (options != NULL)
			if (check_forward(options, logctx) != ISC_R_SUCCESS)
				result = ISC_R_FAILURE;
	} else {
		if (check_forward(vconfig, logctx) != ISC_R_SUCCESS)
			result = ISC_R_FAILURE;
	}

	if (vconfig != NULL)
		tresult = check_options(vconfig, logctx);
	else
		tresult = check_options(config, logctx);
	if (tresult != ISC_R_SUCCESS)
		result = tresult;

	return (result);
}


isc_result_t
bind9_check_namedconf(cfg_obj_t *config, isc_log_t *logctx, isc_mem_t *mctx) {
	cfg_obj_t *options = NULL;
	cfg_obj_t *views = NULL;
	cfg_obj_t *acls = NULL;
	cfg_obj_t *obj;
	cfg_listelt_t *velement;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult;

	static const char *builtin[] = { "localhost", "localnets",
					 "any", "none"};

	(void)cfg_map_get(config, "options", &options);

	if (options != NULL &&
	    check_options(options, logctx) != ISC_R_SUCCESS)
		result = ISC_R_FAILURE;

	(void)cfg_map_get(config, "view", &views);

	if (views == NULL) {
		if (check_viewconf(config, NULL, dns_rdataclass_in,
				   logctx, mctx) != ISC_R_SUCCESS)
			result = ISC_R_FAILURE;
	} else {
		cfg_obj_t *zones = NULL;

		(void)cfg_map_get(config, "zone", &zones);
		if (zones != NULL) {
			cfg_obj_log(zones, logctx, ISC_LOG_ERROR,
				    "when using 'view' statements, "
				    "all zones must be in views");
			result = ISC_R_FAILURE;
		}
	}

	for (velement = cfg_list_first(views);
	     velement != NULL;
	     velement = cfg_list_next(velement))
	{
		cfg_obj_t *view = cfg_listelt_value(velement);
		cfg_obj_t *vname = cfg_tuple_get(view, "name");
		cfg_obj_t *voptions = cfg_tuple_get(view, "options");
		cfg_obj_t *vclassobj = cfg_tuple_get(view, "class");
		dns_rdataclass_t vclass = dns_rdataclass_in;
		isc_result_t tresult = ISC_R_SUCCESS;

		if (cfg_obj_isstring(vclassobj)) {
			isc_textregion_t r;

			DE_CONST(cfg_obj_asstring(vclassobj), r.base);
			r.length = strlen(r.base);
			tresult = dns_rdataclass_fromtext(&vclass, &r);
			if (tresult != ISC_R_SUCCESS)
				cfg_obj_log(vclassobj, logctx, ISC_LOG_ERROR,
					    "view '%s': invalid class %s",
					    cfg_obj_asstring(vname), r.base);
		}
		if (tresult == ISC_R_SUCCESS)
			tresult = check_viewconf(config, voptions,
						 vclass, logctx, mctx);
		if (tresult != ISC_R_SUCCESS)
			result = ISC_R_FAILURE;
	}

	if (views != NULL && options != NULL) {
		obj = NULL;
		tresult = cfg_map_get(options, "cache-file", &obj);
		if (tresult == ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "'cache-file' cannot be a global "
				    "option if views are present");
			result = ISC_R_FAILURE;
		}
	}

        tresult = cfg_map_get(config, "acl", &acls);
        if (tresult == ISC_R_SUCCESS) {
		cfg_listelt_t *elt;
		const char *aclname;

		for (elt = cfg_list_first(acls);
		     elt != NULL;
		     elt = cfg_list_next(elt)) {
			cfg_obj_t *acl = cfg_listelt_value(elt);
			unsigned int i;

			aclname = cfg_obj_asstring(cfg_tuple_get(acl, "name"));
			for (i = 0;
			     i < sizeof(builtin) / sizeof(builtin[0]);
			     i++)
				if (strcasecmp(aclname, builtin[i]) == 0) {
					cfg_obj_log(acl, logctx, ISC_LOG_ERROR,
						    "attempt to redefine "
						    "builtin acl '%s'",
				    		    aclname);
					result = ISC_R_FAILURE;
					break;
				}
		}
	}

	return (result);
}
