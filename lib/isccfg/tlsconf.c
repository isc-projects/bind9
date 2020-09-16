/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <string.h>

#include <isc/util.h>

#include <isccfg/grammar.h>
#include <isccfg/tlsconf.h>

void
cfg_tls_storage_init(isc_mem_t *mctx, isc_cfg_tls_data_storage_t *storage) {
	REQUIRE(mctx != NULL);
	REQUIRE(storage != NULL);

	memset(storage, 0, sizeof(*storage));
	isc_mem_attach(mctx, &storage->mctx);
	ISC_LIST_INIT(storage->list);
}

void
cfg_tls_storage_uninit(isc_cfg_tls_data_storage_t *storage) {
	REQUIRE(storage != NULL);

	cfg_tls_storage_clear(storage);
	isc_mem_detach(&storage->mctx);
}

void
cfg_tls_storage_clear(isc_cfg_tls_data_storage_t *storage) {
	isc_mem_t *mctx = NULL;

	REQUIRE(storage != NULL);

	mctx = storage->mctx;

	if (!ISC_LIST_EMPTY(storage->list)) {
		isc_cfg_tls_obj_t *tls_obj = ISC_LIST_HEAD(storage->list);
		while (tls_obj != NULL) {
			isc_cfg_tls_obj_t *next = ISC_LIST_NEXT(tls_obj, link);
			ISC_LIST_DEQUEUE(storage->list, tls_obj, link);
			storage->count--;

			isc_mem_free(mctx, tls_obj->name);
			isc_mem_free(mctx, tls_obj->key_file);
			isc_mem_free(mctx, tls_obj->cert_file);

			if (tls_obj->dh_param != NULL) {
				isc_mem_free(mctx, tls_obj->dh_param);
			}

			if (tls_obj->protocols != NULL) {
				isc_mem_free(mctx, tls_obj->protocols);
			}

			if (tls_obj->ciphers != NULL) {
				isc_mem_free(mctx, tls_obj->ciphers);
			}

			isc_mem_put(mctx, tls_obj, sizeof(*tls_obj));
			tls_obj = next;
		}
	}

	INSIST(storage->count == 0);
}

static isc_result_t
push_tls_obj(const cfg_obj_t *map, isc_cfg_tls_data_storage_t *storage) {
	isc_mem_t *mctx = storage->mctx;
	isc_cfg_tls_obj_t *new = NULL;
	const cfg_obj_t *key_file = NULL, *cert_file = NULL, *dh_param = NULL,
			*protocols = NULL, *ciphers = NULL;

	if (!cfg_obj_ismap(map) || map->value.map.id == NULL ||
	    !cfg_obj_isstring(map->value.map.id))
	{
		return (ISC_R_FAILURE);
	}

	if (cfg_tls_storage_find(cfg_obj_asstring(map->value.map.id),
				 storage) != NULL) {
		return (ISC_R_FAILURE);
	}

	if (cfg_map_get(map, "key-file", &key_file) != ISC_R_SUCCESS ||
	    !cfg_obj_isstring(key_file))
	{
		return (ISC_R_FAILURE);
	}
	INSIST(key_file != NULL);

	if (cfg_map_get(map, "cert-file", &cert_file) != ISC_R_SUCCESS) {
		return (ISC_R_FAILURE);
	}
	INSIST(cert_file != NULL);

	(void)cfg_map_get(map, "dh-param", &dh_param);
	(void)cfg_map_get(map, "protocols", &protocols);
	(void)cfg_map_get(map, "ciphers", &ciphers);

	new = isc_mem_get(mctx, sizeof(*new));
	*new = (isc_cfg_tls_obj_t){
		.name = isc_mem_strdup(mctx,
				       cfg_obj_asstring(map->value.map.id)),
		.key_file = isc_mem_strdup(mctx, cfg_obj_asstring(key_file)),
		.cert_file = isc_mem_strdup(mctx, cfg_obj_asstring(cert_file)),
	};

	if (dh_param != NULL && cfg_obj_isstring(dh_param)) {
		new->dh_param = isc_mem_strdup(mctx,
					       cfg_obj_asstring(dh_param));
	}

	if (protocols != NULL && cfg_obj_isstring(protocols)) {
		new->protocols = isc_mem_strdup(mctx,
						cfg_obj_asstring(protocols));
	}

	if (ciphers != NULL && cfg_obj_isstring(ciphers)) {
		new->ciphers = isc_mem_strdup(mctx, cfg_obj_asstring(ciphers));
	}

	ISC_LINK_INIT(new, link);
	ISC_LIST_PREPEND(storage->list, new, link);
	storage->count++;
	return (ISC_R_SUCCESS);
}

isc_result_t
cfg_tls_storage_load(const cfg_obj_t *cfg_ctx,
		     isc_cfg_tls_data_storage_t *storage) {
	isc_result_t result = ISC_R_SUCCESS;
	bool found = false;
	const cfg_obj_t *tls = NULL;
	const cfg_listelt_t *elt;
	const cfg_obj_t *map = NULL;

	REQUIRE(cfg_ctx != NULL);
	REQUIRE(storage != NULL);

	result = cfg_map_get(cfg_ctx, "tls", &tls);
	if (result != ISC_R_SUCCESS) {
		/* No tls statements found, but it is fine. */
		return (ISC_R_SUCCESS);
	}
	INSIST(tls != NULL);

	cfg_tls_storage_clear(storage);

	for (elt = cfg_list_first(tls); elt != NULL; elt = cfg_list_next(elt)) {
		map = cfg_listelt_value(elt);
		INSIST(map != NULL);
		found = true;
		result = push_tls_obj(map, storage);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	if (found == true && storage->count == 0) {
		return (ISC_R_FAILURE);
	}

	return (ISC_R_SUCCESS);
}

isc_cfg_tls_obj_t *
cfg_tls_storage_find(const char *name, isc_cfg_tls_data_storage_t *storage) {
	isc_cfg_tls_obj_t *tls_obj = NULL;
	REQUIRE(storage != NULL);

	if (name == NULL) {
		return (NULL);
	}

	for (tls_obj = ISC_LIST_HEAD(storage->list); tls_obj != NULL;
	     tls_obj = ISC_LIST_NEXT(tls_obj, link))
	{
		if (strcasecmp(name, tls_obj->name) == 0) {
			break;
		}
	}

	return (tls_obj);
}
