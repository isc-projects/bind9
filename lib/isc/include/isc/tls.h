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

typedef enum isc_tls_protocol_version {
	/* these must be the powers of two */
	ISC_TLS_PROTO_VER_1_2 = 1 << 0,
	ISC_TLS_PROTO_VER_1_3 = 1 << 1,
	ISC_TLS_PROTO_VER_UNDEFINED,
} isc_tls_protocol_version_t;

void
isc_tlsctx_set_protocols(isc_tlsctx_t *ctx, const uint32_t tls_versions);
/*%<
 * Sets the supported TLS protocol versions via the 'tls_versions' bit
 * set argument (see `isc_tls_protocol_version_t` enum for the
 * expected values).
 *
 * Requires:
 *\li	'ctx' != NULL;
 *\li	'tls_versions' != 0.
 */

bool
isc_tls_protocol_supported(const isc_tls_protocol_version_t tls_ver);
/*%<
 * Check in runtime that the specified TLS protocol versions is supported.
 */

isc_tls_protocol_version_t
isc_tls_protocol_name_to_version(const char *name);
/*%<
 * Convert the protocol version string into the version of
 * 'isc_tls_protocol_version_t' type.
 * Requires:
 *\li	'name' != NULL.
 */

bool
isc_tlsctx_load_dhparams(isc_tlsctx_t *ctx, const char *dhparams_file);
/*%<
 * Load Diffie-Hellman parameters file and apply it to the given TLS context
 * 'ctx'.
 *
 * Requires:
 * \li	'ctx' != NULL;
 * \li	'dhaprams_file' a valid pointer to a non empty string.
 */

bool
isc_tls_cipherlist_valid(const char *cipherlist);
/*%<
 * Check if cipher list string is valid.
 *
 * Requires:
 * \li	'cipherlist' a valid pointer to a non empty string.
 */

void
isc_tlsctx_set_cipherlist(isc_tlsctx_t *ctx, const char *cipherlist);
/*%<
 * Set cipher list string for on the given TLS context 'ctx'.
 *
 * Requires:
 * \li	'ctx' != NULL;
 * \li	'cipherlist' a valid pointer to a non empty string.
 */

void
isc_tlsctx_prefer_server_ciphers(isc_tlsctx_t *ctx, const bool prefer);
/*%<
 * Make the given TLS context 'ctx' to prefer or to not prefer
 * server side ciphers during the ciphers negotiation.
 *
 * Requires:
 * \li	'ctx' != NULL.
 */

void
isc_tlsctx_session_tickets(isc_tlsctx_t *ctx, const bool use);
/*%<
 * Enable/Disable stateless session resumptions tickets on the given
 * TLS context 'ctx' (see RFC5077).
 *
 * Requires:
 * \li	'ctx' != NULL.
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

#if HAVE_LIBNGHTTP2
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
#endif /* HAVE_LIBNGHTTP2 */

void
isc_tls_get_selected_alpn(isc_tls_t *tls, const unsigned char **alpn,
			  unsigned int *alpnlen);

#define ISC_TLS_DOT_PROTO_ALPN_ID     "dot"
#define ISC_TLS_DOT_PROTO_ALPN_ID_LEN 3

void
isc_tlsctx_enable_dot_client_alpn(isc_tlsctx_t *ctx);
void
isc_tlsctx_enable_dot_server_alpn(isc_tlsctx_t *ctx);
/*%<
 *
 * Enable DoT Application Layer Protocol Negotation for 'ctx'.
 *
 * Requires:
 *\li	'ctx' is not NULL.
 */
