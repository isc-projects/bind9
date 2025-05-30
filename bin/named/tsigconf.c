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

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/tsig.h>

#include <isccfg/cfg.h>

#include <named/config.h>
#include <named/log.h>
#include <named/tsigconf.h>

static isc_result_t
add_initial_keys(const cfg_obj_t *list, dns_tsigkeyring_t *ring,
		 isc_mem_t *mctx) {
	dns_tsigkey_t *tsigkey = NULL;
	const cfg_obj_t *key = NULL;
	const char *keyid = NULL;
	unsigned char *secret = NULL;
	int secretalloc = 0;
	isc_result_t ret;

	CFG_LIST_FOREACH (list, element) {
		const cfg_obj_t *algobj = NULL;
		const cfg_obj_t *secretobj = NULL;
		dns_fixedname_t fkey;
		dns_name_t *keyname = dns_fixedname_initname(&fkey);
		dst_algorithm_t alg = DST_ALG_UNKNOWN;
		const char *algstr = NULL;
		isc_buffer_t keynamesrc;
		const char *secretstr = NULL;
		isc_buffer_t secretbuf;
		int secretlen = 0;
		uint16_t bits;

		key = cfg_listelt_value(element);
		keyid = cfg_obj_asstring(cfg_map_getname(key));

		algobj = NULL;
		secretobj = NULL;
		(void)cfg_map_get(key, "algorithm", &algobj);
		(void)cfg_map_get(key, "secret", &secretobj);
		INSIST(algobj != NULL && secretobj != NULL);

		/*
		 * Create the key name.
		 */
		isc_buffer_constinit(&keynamesrc, keyid, strlen(keyid));
		isc_buffer_add(&keynamesrc, strlen(keyid));
		ret = dns_name_fromtext(keyname, &keynamesrc, dns_rootname,
					DNS_NAME_DOWNCASE);
		if (ret != ISC_R_SUCCESS) {
			goto failure;
		}

		/*
		 * Create the algorithm.
		 */
		algstr = cfg_obj_asstring(algobj);
		if (named_config_getkeyalgorithm(algstr, &alg, &bits) !=
		    ISC_R_SUCCESS)
		{
			cfg_obj_log(algobj, ISC_LOG_ERROR,
				    "key '%s': has a "
				    "unsupported algorithm '%s'",
				    keyid, algstr);
			ret = DNS_R_BADALG;
			goto failure;
		}

		secretstr = cfg_obj_asstring(secretobj);
		secretalloc = secretlen = strlen(secretstr) * 3 / 4;
		secret = isc_mem_get(mctx, secretlen);
		isc_buffer_init(&secretbuf, secret, secretlen);
		ret = isc_base64_decodestring(secretstr, &secretbuf);
		if (ret != ISC_R_SUCCESS) {
			goto failure;
		}
		secretlen = isc_buffer_usedlength(&secretbuf);

		ret = dns_tsigkey_create(keyname, alg, secret, secretlen, mctx,
					 &tsigkey);
		isc_mem_put(mctx, secret, secretalloc);
		if (ret == ISC_R_SUCCESS) {
			ret = dns_tsigkeyring_add(ring, tsigkey);
		}
		if (ret != ISC_R_SUCCESS) {
			if (tsigkey != NULL) {
				dns_tsigkey_detach(&tsigkey);
			}
			goto failure;
		}
		/*
		 * Set digest bits.
		 */
		dst_key_setbits(tsigkey->key, bits);
		dns_tsigkey_detach(&tsigkey);
	}

	return ISC_R_SUCCESS;

failure:
	if (secret != NULL) {
		isc_mem_put(mctx, secret, secretalloc);
	}
	cfg_obj_log(key, ISC_LOG_ERROR, "configuring key '%s': %s", keyid,
		    isc_result_totext(ret));
	return ret;
}

isc_result_t
named_tsigkeyring_fromconfig(const cfg_obj_t *config, const cfg_obj_t *vconfig,
			     isc_mem_t *mctx, dns_tsigkeyring_t **ringp) {
	const cfg_obj_t *maps[3];
	const cfg_obj_t *keylist;
	dns_tsigkeyring_t *ring = NULL;
	isc_result_t result;
	int i;

	REQUIRE(ringp != NULL && *ringp == NULL);

	i = 0;
	if (config != NULL) {
		maps[i++] = config;
	}
	if (vconfig != NULL) {
		maps[i++] = cfg_tuple_get(vconfig, "options");
	}
	maps[i] = NULL;

	dns_tsigkeyring_create(mctx, &ring);

	for (i = 0;; i++) {
		if (maps[i] == NULL) {
			break;
		}
		keylist = NULL;
		result = cfg_map_get(maps[i], "key", &keylist);
		if (result != ISC_R_SUCCESS) {
			continue;
		}
		result = add_initial_keys(keylist, ring, mctx);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}
	}

	*ringp = ring;
	return ISC_R_SUCCESS;

failure:
	dns_tsigkeyring_detach(&ring);
	return result;
}
