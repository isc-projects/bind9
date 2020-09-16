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

#ifndef ISCCFG_HTTPCONF_H
#define ISCCFG_HTTPCONF_H 1

#include <inttypes.h>

#include <isc/lang.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/types.h>

#include <isccfg/cfg.h>
#include <isccfg/tlsconf.h>

typedef struct isc_cfg_http_endpoint {
	char *path;
	LINK(struct isc_cfg_http_endpoint) link;
} isc_cfg_http_endpoint_t;

typedef struct isc_cfg_http_obj {
	char *name;
	LINK(struct isc_cfg_http_obj) link;
	ISC_LIST(isc_cfg_http_endpoint_t) endpoints;
	size_t count;
} isc_cfg_http_obj_t;

typedef struct isc_cfg_http_storage {
	isc_mem_t *mctx;
	ISC_LIST(isc_cfg_http_obj_t) list;
	size_t count;
} isc_cfg_http_storage_t;

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

void
cfg_http_storage_init(isc_mem_t *mctx, isc_cfg_http_storage_t *storage);

void
cfg_http_storage_uninit(isc_cfg_http_storage_t *storage);

isc_result_t
cfg_http_storage_load(const cfg_obj_t *	      cfg_ctx,
		      isc_cfg_http_storage_t *storage);

isc_cfg_http_obj_t *
cfg_http_find(const char *name, isc_cfg_http_storage_t *storage);

void
cfg_http_storage_clear(isc_cfg_http_storage_t *storage);

ISC_LANG_ENDDECLS

#endif /* ISCCFG_HTTPCONF_H */
