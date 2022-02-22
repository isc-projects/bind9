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

#pragma once

#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

typedef struct ssl_ctx_st isc_tlsctx_t;
typedef struct ssl_st	  isc_tls_t;

typedef struct x509_store_st isc_tls_cert_store_t;

void
isc_tlsctx_free(isc_tlsctx_t **ctpx);
/*%<
 * Free a TLS client or server context.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' != NULL.
 */

void
isc_tlsctx_attach(isc_tlsctx_t *src, isc_tlsctx_t **ptarget);
/*%<
 * Attach to the TLS context.
 *
 * Requires:
 *\li	'src' != NULL;
 *\li	'ptarget' != NULL;
 *\li	'*ptarget' == NULL.
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

isc_result_t
isc_tlsctx_load_certificate(isc_tlsctx_t *ctx, const char *keyfile,
			    const char *certfile);
/*%<
 * Load a TLS certificate into a TLS context.
 *
 * Requires:
 *\li	'ctx' != NULL;
 *\li	'keyfile' and 'certfile' are both non-NULL.
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

const char *
isc_tls_verify_peer_result_string(isc_tls_t *tls);
/*%<
 * Return a user readable description of a remote peer's certificate
 * validation.
 *
 * Requires:
 *\li	'tls' != NULL.
 */

#if HAVE_LIBNGHTTP2
void
isc_tlsctx_enable_http2client_alpn(isc_tlsctx_t *ctx);
void
isc_tlsctx_enable_http2server_alpn(isc_tlsctx_t *ctx);
/*%<
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
 * Enable DoT Application Layer Protocol Negotation for 'ctx'.
 *
 * Requires:
 *\li	'ctx' is not NULL.
 */

isc_result_t
isc_tlsctx_enable_peer_verification(isc_tlsctx_t *ctx, const bool is_server,
				    isc_tls_cert_store_t *store,
				    const char	       *hostname,
				    bool hostname_ignore_subject);
/*%<
 * Enable peer certificate and, optionally, hostname (for client contexts)
 * verification.
 *
 * Requires:
 *\li	'ctx' is not NULL;
 *\li	'store' is not NULL.
 */

isc_result_t
isc_tlsctx_load_client_ca_names(isc_tlsctx_t *ctx, const char *ca_bundle_file);
/*%<
 * Load the list of CA-certificate names from a CA-bundle file to
 * send by the server to a client when requesting a peer certificate.
 * Usually used in conjunction with
 * isc_tlsctx_enable_peer_validation().
 *
 * Requires:
 *\li	'ctx' is not NULL;
 *\li	'ca_bundle_file' is not NULL.
 */

isc_result_t
isc_tls_cert_store_create(const char	     *ca_bundle_filename,
			  isc_tls_cert_store_t **pstore);
/*%<
 * Create X509 certificate store. The 'ca_bundle_filename' might be
 * 'NULL' or an empty string, which means use the default system wide
 * bundle/directory.
 *
 * Requires:
 *\li	'pstore' is a valid pointer to a pointer containing 'NULL'.
 */

void
isc_tls_cert_store_free(isc_tls_cert_store_t **pstore);
/*%<
 * Free X509 certificate store.
 *
 * Requires:
 *\li	'pstore' is a valid pointer to a pointer containing a non-'NULL' value.
 */

typedef struct isc_tlsctx_cache isc_tlsctx_cache_t;
/*%<
 * The TLS context cache is an object which allows retrieving a
 * previously created TLS context based on the following tuple:
 *
 * 1. The name of a TLS entry, as defined in the configuration file;
 * 2. A transport type. Currently, only TLS (DoT) and HTTPS (DoH) are
 *    supported;
 * 3. An IP address family (AF_INET or AF_INET6).
 *
 * There are multiple uses for this object:
 *
 * First, it allows reuse of client-side contexts during zone transfers.
 * That, in turn, allows use of session caches associated with these
 * contexts, which enables TLS session resumption, making establishment
 * of XoT connections faster and computationally cheaper.
 *
 * Second, it can be extended to be used as storage for TLS context related
 * data, as defined in 'tls' statements in the configuration file (for
 * example, CA-bundle intermediate certificate storage, client-side contexts
 * with pre-loaded certificates in a case of Mutual TLS, etc). This will
 * be used to implement Strict/Mutual TLS.
 *
 * Third, it avoids creating an excessive number of server-side TLS
 * contexts, which might help to reduce the number of contexts
 * created during server initialisation and reconfiguration.
 */

typedef enum {
	isc_tlsctx_cache_none = 0,
	isc_tlsctx_cache_tls,
	isc_tlsctx_cache_https,
	isc_tlsctx_cache_count
} isc_tlsctx_cache_transport_t;
/*%< TLS context cache transport type values. */

isc_tlsctx_cache_t *
isc_tlsctx_cache_new(isc_mem_t *mctx);
/*%<
 * Create a new TLS context cache object.
 *
 * Requires:
 *\li	'mctx' is a valid memory context.
 */

void
isc_tlsctx_cache_attach(isc_tlsctx_cache_t  *source,
			isc_tlsctx_cache_t **targetp);
/*%<
 * Create a reference to the TLS context cache object.
 *
 * Requires:
 *\li	'source' is a valid TLS context cache object;
 *\li	'targetp' is a valid pointer to a pointer which must equal NULL.
 */

void
isc_tlsctx_cache_detach(isc_tlsctx_cache_t **cachep);
/*%<
 * Remove a reference to the TLS context cache object.
 *
 * Requires:
 *\li	'cachep' is a pointer to a pointer to a valid TLS
 *	 context cache object.
 */

isc_result_t
isc_tlsctx_cache_add(isc_tlsctx_cache_t *cache, const char *name,
		     const isc_tlsctx_cache_transport_t transport,
		     const uint16_t family, isc_tlsctx_t *ctx,
		     isc_tls_cert_store_t *store, isc_tlsctx_t **pfound,
		     isc_tls_cert_store_t **pfound_store);
/*%<
 *
 * Add a new TLS context to the TLS context cache. 'pfound' is an
 * optional pointer, which can be used to retrieve an already
 * existing TLS context object in a case it exists.
 *
 * The passed certificates store object ('store') possession is
 * transferred to the cache object in a case of success. In some cases
 * it might be destroyed immediately upon the call completion.
 *
 * Requires:
 *\li	'cache' is a valid pointer to a TLS context cache object;
 *\li	'name' is a valid pointer to a non-empty string;
 *\li	'transport' is a valid transport identifier (currently only
 *       TLS/DoT and HTTPS/DoH are supported);
 *\li	'family' - either 'AF_INET' or 'AF_INET6';
 *\li   'ctx' - a valid pointer to a valid TLS context object.
 *
 * Returns:
 *\li	#ISC_R_EXISTS - node of the same key already exists;
 *\li	#ISC_R_SUCCESS - the new entry has been added successfully.
 */

isc_result_t
isc_tlsctx_cache_find(isc_tlsctx_cache_t *cache, const char *name,
		      const isc_tlsctx_cache_transport_t transport,
		      const uint16_t family, isc_tlsctx_t **pctx,
		      isc_tls_cert_store_t **pstore);
/*%<
 * Look up a TLS context in the TLS context cache.
 *
 * Requires:
 *\li	'cache' is a valid pointer to a TLS context cache object;
 *\li	'name' is a valid pointer to a non empty string;
 *\li	'transport' - a valid transport identifier (currently only
 *       TLS/DoT and HTTPS/DoH are supported;
 *\li	'family' - either 'AF_INET' or 'AF_INET6';
 *\li   'pctx' - a valid pointer to a non-NULL pointer.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - the context has been found;
 *\li	#ISC_R_NOTFOUND	- the context has not been found.
 */
