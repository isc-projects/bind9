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

#pragma once

#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

typedef struct ssl_ctx_st isc_tlsctx_t;
typedef struct ssl_st	  isc_tls_t;

void
isc_tlsctx_free(isc_tlsctx_t **ctpx);
/*%<
 * Free a TLS client or server context.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' != NULL.
 */

isc_result_t
isc_tlsctx_createserver(const char *keyfile, const char *certfile,
			isc_tlsctx_t **ctxp);
/*%<
 * Set up a TLS server context, using the key and certificate specified in
 * 'keyfile' and 'certfile', or a self-generated ephemeral key and
 * certificdate if both 'keyfile' and 'certfile' are NULL.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' == NULL.
 *\li	'keyfile' and 'certfile' are either both NULL or both non-NULL.
 */

isc_result_t
isc_tlsctx_createclient(isc_tlsctx_t **ctxp);
/*%<
 * Set up a TLS client context.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' == NULL.
 */

isc_tls_t *
isc_tls_create(isc_tlsctx_t *ctx);
/*%<
 * Set up the structure to hold data for a new TLS connection.
 *
 * Requires:
 *\li	'ctx' != NULL.
 */

void
isc_tls_free(isc_tls_t **tlsp);
/*%<
 * Free a TLS structure.
 *
 * Requires:
 *\li	'tlsp' != NULL and '*tlsp' != NULL.
 */

void
isc_tlsctx_enable_http2client_alpn(isc_tlsctx_t *ctx);
void
isc_tlsctx_enable_http2server_alpn(isc_tlsctx_t *ctx);
/*%<
 *
 * Enable HTTP/2 Application Layer Protocol Negotation for 'ctx'.
 *
 * Requires:
 *\li	'ctx' is not NULL.
 */

void
isc_tls_get_http2_alpn(isc_tls_t *tls, const unsigned char **alpn,
		       unsigned int *alpnlen);
