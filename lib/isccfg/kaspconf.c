/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <isccfg/namedconf.h>
#include <isccfg/cfg.h>
#include <isccfg/kaspconf.h>

#include <dns/kasp.h>
#include <dns/keyvalues.h>
#include <dns/log.h>


/*
 * Utility function for getting a configuration option.
 */
static isc_result_t
confget(cfg_obj_t const * const *maps, const char *name, const cfg_obj_t **obj)
{
	for (size_t i = 0;; i++) {
		if (maps[i] == NULL) {
			return (ISC_R_NOTFOUND);
		}
		if (cfg_map_get(maps[i], name, obj) == ISC_R_SUCCESS) {
			return (ISC_R_SUCCESS);
		}
	}
}

/*
 * Utility function for configuring durations.
 */
static time_t
get_duration(const cfg_obj_t **maps, const char* option, time_t dfl)
{
	const cfg_obj_t *obj;
	isc_result_t result;
	obj = NULL;

	result = confget(maps, option, &obj);
	if (result == ISC_R_NOTFOUND) {
		return (dfl);
	}
	INSIST(result == ISC_R_SUCCESS);
	return (cfg_obj_asduration(obj));
}

/*
 * Create a new kasp key derived from configuration.
 */
static isc_result_t
cfg_kaspkey_fromconfig(const cfg_obj_t *config, dns_kasp_t* kasp)
{
	isc_result_t result;
	dns_kasp_key_t *key = NULL;

	/* Create a new key reference. */
	result = dns_kasp_key_create(kasp->mctx, &key);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	if (config == NULL) {
		/* We are creating a key reference for the default kasp. */
		key->role |= DNS_KASP_KEY_ROLE_KSK | DNS_KASP_KEY_ROLE_ZSK;
		key->lifetime = 0;
		key->algorithm = DNS_KEYALG_ECDSA256;
		key->length = -1;
	} else {
		const char* rolestr;
		const cfg_obj_t* obj;

		rolestr = cfg_obj_asstring(cfg_tuple_get(config, "role"));
		if (strcmp(rolestr, "ksk") == 0) {
			key->role |= DNS_KASP_KEY_ROLE_KSK;
		} else if (strcmp(rolestr, "zsk") == 0) {
			key->role |= DNS_KASP_KEY_ROLE_ZSK;
		} else if (strcmp(rolestr, "csk") == 0) {
			key->role |= DNS_KASP_KEY_ROLE_KSK;
			key->role |= DNS_KASP_KEY_ROLE_ZSK;
		}
		key->lifetime = cfg_obj_asduration(
					     cfg_tuple_get(config, "lifetime"));
		key->algorithm = cfg_obj_asuint32(
					    cfg_tuple_get(config, "algorithm"));
		obj = cfg_tuple_get(config, "length");
		if (cfg_obj_isuint32(obj)) {
			key->length = cfg_obj_asuint32(obj);
		}
	}
	ISC_LIST_APPEND(kasp->keys, key, link);
	ISC_INSIST(!(ISC_LIST_EMPTY(kasp->keys)));
	return (result);
}

isc_result_t
cfg_kasp_fromconfig(const cfg_obj_t *config, isc_mem_t* mctx,
		    dns_kasplist_t *kasplist, dns_kasp_t **kaspp)
{
	isc_result_t result;
	const cfg_obj_t *maps[2];
	const cfg_obj_t *koptions = NULL;
	const cfg_obj_t *keys = NULL;
	const cfg_listelt_t *element = NULL;
	const char *kaspname = NULL;
	dns_kasp_t *kasp = NULL;
	int i = 0;

	REQUIRE(kaspp != NULL && *kaspp == NULL);

	kaspname = (config != NULL) ?
		    cfg_obj_asstring(cfg_tuple_get(config, "name")) :
		    "default";

	result = dns_kasplist_find(kasplist, kaspname, &kasp);

	if (result == ISC_R_SUCCESS) {
		return (ISC_R_EXISTS);
	}
	if (result != ISC_R_NOTFOUND) {
		return (result);
	}

	/* No kasp with configured name was found in list, create new one. */
	INSIST(kasp == NULL);
	result = dns_kasp_create(mctx, kaspname, &kasp);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	INSIST(kasp != NULL);

	/* Append it to the list for future lookups. */
	ISC_LIST_APPEND(*kasplist, kasp, link);
	ISC_INSIST(!(ISC_LIST_EMPTY(*kasplist)));

	/* Now configure. */
	INSIST(DNS_KASP_VALID(kasp));

	if (config != NULL) {
		koptions = cfg_tuple_get(config, "options");
		maps[i++] = koptions;
	}
	maps[i] = NULL;

	/* Configuration: Signatures */
	kasp->signatures_refresh = get_duration(
		maps, "signatures-refresh", DNS_KASP_SIG_REFRESH);
	kasp->signatures_validity = get_duration(
		maps, "signatures-validity", DNS_KASP_SIG_VALIDITY);
	kasp->signatures_validity_dnskey = get_duration(
		maps, "signatures-validity-dnskey",
		DNS_KASP_SIG_VALIDITY_DNSKEY);

	/* Configuration: Keys */
	kasp->dnskey_ttl = get_duration(maps, "dnskey-ttl", DNS_KASP_KEY_TTL);
	kasp->publish_safety = get_duration(maps, "publish-safety",
					    DNS_KASP_PUBLISH_SAFETY);
	kasp->retire_safety = get_duration(maps, "retire-safety",
					   DNS_KASP_RETIRE_SAFETY);

	(void)confget(maps, "keys", &keys);
	if (keys == NULL) {
		result = cfg_kaspkey_fromconfig(NULL, kasp);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
	} else {
		for (element = cfg_list_first(keys); element != NULL;
		     element = cfg_list_next(element))
		{
			cfg_obj_t *kobj = cfg_listelt_value(element);
			result = cfg_kaspkey_fromconfig(kobj, kasp);
			if (result != ISC_R_SUCCESS) {
				goto cleanup;
			}
		}
	}
	ISC_INSIST(!(ISC_LIST_EMPTY(kasp->keys)));

	// TODO: Rest of the configuration

	/* Success: Attach the kasp to the pointer and return. */
	dns_kasp_attach(kasp, kaspp);
	return (ISC_R_SUCCESS);

cleanup:

	/* Something bad happened, detach (destroys kasp) and return error. */
	dns_kasp_detach(&kasp);
	return (result);
}
