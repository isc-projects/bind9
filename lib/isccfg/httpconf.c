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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/util.h>

#include <isccfg/grammar.h>
#include <isccfg/httpconf.h>

void
cfg_http_storage_init(isc_mem_t *mctx, isc_cfg_http_storage_t *storage) {
	REQUIRE(mctx != NULL);
	REQUIRE(storage != NULL);

	memset(storage, 0, sizeof(*storage));
	isc_mem_attach(mctx, &storage->mctx);
	ISC_LIST_INIT(storage->list);
}

void
cfg_http_storage_uninit(isc_cfg_http_storage_t *storage) {
	REQUIRE(storage != NULL);

	cfg_http_storage_clear(storage);
	isc_mem_detach(&storage->mctx);
}

void
cfg_http_storage_clear(isc_cfg_http_storage_t *storage) {
	isc_mem_t *mctx = NULL;

	REQUIRE(storage != NULL);

	mctx = storage->mctx;

	if (!ISC_LIST_EMPTY(storage->list)) {
		isc_cfg_http_obj_t *http = ISC_LIST_HEAD(storage->list);
		while (http != NULL) {
			isc_cfg_http_obj_t *next = ISC_LIST_NEXT(http, link);
			ISC_LIST_DEQUEUE(storage->list, http, link);
			storage->count--;

			isc_mem_free(mctx, http->name);

			if (!ISC_LIST_EMPTY(http->endpoints)) {
				isc_cfg_http_endpoint_t *ep =
					ISC_LIST_HEAD(http->endpoints);
				while (ep != NULL) {
					isc_cfg_http_endpoint_t *epnext =
						ISC_LIST_NEXT(ep, link);
					isc_mem_free(mctx, ep->path);
					isc_mem_put(mctx, ep, sizeof(*ep));
					ep = epnext;
					http->count--;
				}
			}

			isc_mem_put(mctx, http, sizeof(*http));
			http = next;
		}
	}

	INSIST(storage->count == 0);
}

isc_cfg_http_obj_t *
cfg_http_find(const char *name, isc_cfg_http_storage_t *storage) {
	isc_cfg_http_obj_t *http = NULL;
	REQUIRE(name != NULL && *name != '\0');
	REQUIRE(storage != NULL);

	for (http = ISC_LIST_HEAD(storage->list); http != NULL;
	     http = ISC_LIST_NEXT(http, link))
	{
		if (strcasecmp(name, http->name) == 0) {
			break;
		}
	}

	return (http);
}

static isc_result_t
push_http_obj(const cfg_obj_t *map, isc_cfg_http_storage_t *storage) {
	isc_mem_t *mctx = storage->mctx;
	isc_cfg_http_obj_t *new;
	const cfg_obj_t *endpoints = NULL;
	const cfg_listelt_t *elt;

	if (!cfg_obj_ismap(map) || map->value.map.id == NULL ||
	    !cfg_obj_isstring(map->value.map.id))
	{
		return (ISC_R_FAILURE);
	}

	if (cfg_http_find(cfg_obj_asstring(map->value.map.id), storage) != NULL)
	{
		return (ISC_R_FAILURE);
	}

	if (cfg_map_get(map, "endpoints", &endpoints) != ISC_R_SUCCESS ||
	    !cfg_obj_islist(endpoints))
	{
		return (ISC_R_FAILURE);
	}

	INSIST(endpoints != NULL);

	new = isc_mem_get(mctx, sizeof(*new));
	memset(new, 0, sizeof(*new));
	ISC_LIST_INIT(new->endpoints);
	new->name = isc_mem_strdup(mctx, cfg_obj_asstring(map->value.map.id));

	for (elt = cfg_list_first(endpoints); elt != NULL;
	     elt = cfg_list_next(elt)) {
		isc_cfg_http_endpoint_t *newep = NULL;
		const cfg_obj_t *endp = cfg_listelt_value(elt);
		newep = isc_mem_get(mctx, sizeof(*newep));
		ISC_LINK_INIT(newep, link);
		newep->path = isc_mem_strdup(mctx, cfg_obj_asstring(endp));

		ISC_LIST_PREPEND(new->endpoints, newep, link);
		new->count++;
	}

	ISC_LINK_INIT(new, link);
	ISC_LIST_PREPEND(storage->list, new, link);
	storage->count++;
	return (ISC_R_SUCCESS);
}

isc_result_t
cfg_http_storage_load(const cfg_obj_t *cfg_ctx,
		      isc_cfg_http_storage_t *storage) {
	bool found = false;
	isc_result_t result = ISC_R_SUCCESS;
	const cfg_obj_t *http = NULL;
	const cfg_listelt_t *elt;
	const cfg_obj_t *map = NULL;

	REQUIRE(cfg_ctx != NULL);
	REQUIRE(storage != NULL);

	cfg_http_storage_clear(storage);
	result = cfg_map_get(cfg_ctx, "http", &http);
	if (result != ISC_R_SUCCESS) {
		/* No statements found, but it is fine. */
		return (ISC_R_SUCCESS);
	}

	INSIST(http != NULL);

	for (elt = cfg_list_first(http); elt != NULL; elt = cfg_list_next(elt))
	{
		map = cfg_listelt_value(elt);
		INSIST(map != NULL);
		found = true;
		result = push_http_obj(map, storage);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	if (found == true && storage->count == 0) {
		return (ISC_R_FAILURE);
	}

	return (ISC_R_SUCCESS);
}
