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

#ifndef ISCCFG_TLSCONF_H
#define ISCCFG_TLSCONF_H 1

#include <inttypes.h>

#include <isc/lang.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/types.h>

#include <isccfg/cfg.h>

typedef struct isc_cfg_tls_obj {
	char *name;
	char *key_file;
	char *cert_file;
	char *dh_param;
	char *protocols;
	char *ciphers;
	LINK(struct isc_cfg_tls_obj) link;
} isc_cfg_tls_obj_t;

typedef struct isc_cfg_tls_data_storage {
	isc_mem_t *mctx;
	size_t	   count;
	ISC_LIST(isc_cfg_tls_obj_t) list;
} isc_cfg_tls_data_storage_t;

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

void
cfg_tls_storage_init(isc_mem_t *mctx, isc_cfg_tls_data_storage_t *storage);

void
cfg_tls_storage_uninit(isc_cfg_tls_data_storage_t *storage);

isc_result_t
cfg_tls_storage_load(const cfg_obj_t *		 cfg_ctx,
		     isc_cfg_tls_data_storage_t *storage);

isc_cfg_tls_obj_t *
cfg_tls_storage_find(const char *name, isc_cfg_tls_data_storage_t *storage);
/*
 * Looks for TLS key/certificate pair.
 */

void
cfg_tls_storage_clear(isc_cfg_tls_data_storage_t *storage);

ISC_LANG_ENDDECLS

#endif /* ISCCFG_TLSCONF_H */
