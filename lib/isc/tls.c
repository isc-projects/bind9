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

#include <inttypes.h>
#include <string.h>
#if HAVE_LIBNGHTTP2
#include <nghttp2/nghttp2.h>
#endif /* HAVE_LIBNGHTTP2 */

#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <isc/atomic.h>
#include <isc/log.h>
#include <isc/mutex.h>
#include <isc/mutexblock.h>
#include <isc/once.h>
#include <isc/thread.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "openssl_shim.h"
#include "tls_p.h"

#define COMMON_SSL_OPTIONS \
	(SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION)

static isc_once_t init_once = ISC_ONCE_INIT;
static isc_once_t shut_once = ISC_ONCE_INIT;
static atomic_bool init_done = ATOMIC_VAR_INIT(false);
static atomic_bool shut_done = ATOMIC_VAR_INIT(false);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static isc_mutex_t *locks = NULL;
static int nlocks;

static void
isc__tls_lock_callback(int mode, int type, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	if ((mode & CRYPTO_LOCK) != 0) {
		LOCK(&locks[type]);
	} else {
		UNLOCK(&locks[type]);
	}
}

static void
isc__tls_set_thread_id(CRYPTO_THREADID *id) {
	CRYPTO_THREADID_set_numeric(id, (unsigned long)isc_thread_self());
}
#endif

static void
tls_initialize(void) {
	REQUIRE(!atomic_load(&init_done));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RUNTIME_CHECK(OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
					       OPENSSL_INIT_LOAD_CONFIG,
				       NULL) == 1);
#else
	nlocks = CRYPTO_num_locks();
	/*
	 * We can't use isc_mem API here, because it's called too
	 * early and when the isc_mem_debugging flags are changed
	 * later.
	 *
	 * Actually, since this is a single allocation at library load
	 * and deallocation at library unload, using the standard
	 * allocator without the tracking is fine for this purpose.
	 */
	locks = calloc(nlocks, sizeof(locks[0]));
	isc_mutexblock_init(locks, nlocks);
	CRYPTO_set_locking_callback(isc__tls_lock_callback);
	CRYPTO_THREADID_set_callback(isc__tls_set_thread_id);

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();

#if !defined(OPENSSL_NO_ENGINE)
	ENGINE_load_builtin_engines();
#endif
	OpenSSL_add_all_algorithms();
	OPENSSL_load_builtin_modules();

	CONF_modules_load_file(NULL, NULL,
			       CONF_MFLAGS_DEFAULT_SECTION |
				       CONF_MFLAGS_IGNORE_MISSING_FILE);
#endif

	/* Protect ourselves against unseeded PRNG */
	if (RAND_status() != 1) {
		FATAL_ERROR(__FILE__, __LINE__,
			    "OpenSSL pseudorandom number generator "
			    "cannot be initialized (see the `PRNG not "
			    "seeded' message in the OpenSSL FAQ)");
	}

	REQUIRE(atomic_compare_exchange_strong(&init_done, &(bool){ false },
					       true));
}

void
isc__tls_initialize(void) {
	isc_result_t result = isc_once_do(&init_once, tls_initialize);
	REQUIRE(result == ISC_R_SUCCESS);
	REQUIRE(atomic_load(&init_done));
}

static void
tls_shutdown(void) {
	REQUIRE(atomic_load(&init_done));
	REQUIRE(!atomic_load(&shut_done));

#if OPENSSL_VERSION_NUMBER < 0x10100000L

	CONF_modules_unload(1);
	OBJ_cleanup();
	EVP_cleanup();
#if !defined(OPENSSL_NO_ENGINE)
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	RAND_cleanup();
	ERR_free_strings();

	CRYPTO_set_locking_callback(NULL);

	if (locks != NULL) {
		isc_mutexblock_destroy(locks, nlocks);
		free(locks);
		locks = NULL;
	}
#endif

	REQUIRE(atomic_compare_exchange_strong(&shut_done, &(bool){ false },
					       true));
}

void
isc__tls_shutdown(void) {
	isc_result_t result = isc_once_do(&shut_once, tls_shutdown);
	REQUIRE(result == ISC_R_SUCCESS);
	REQUIRE(atomic_load(&shut_done));
}

void
isc_tlsctx_free(isc_tlsctx_t **ctxp) {
	SSL_CTX *ctx = NULL;
	REQUIRE(ctxp != NULL && *ctxp != NULL);

	ctx = *ctxp;
	*ctxp = NULL;

	SSL_CTX_free(ctx);
}

isc_result_t
isc_tlsctx_createclient(isc_tlsctx_t **ctxp) {
	unsigned long err;
	char errbuf[256];
	SSL_CTX *ctx = NULL;
	const SSL_METHOD *method = NULL;

	REQUIRE(ctxp != NULL && *ctxp == NULL);

	method = TLS_client_method();
	if (method == NULL) {
		goto ssl_error;
	}
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		goto ssl_error;
	}

	SSL_CTX_set_options(ctx, COMMON_SSL_OPTIONS);

#if HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#else
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
					 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif

	*ctxp = ctx;

	return (ISC_R_SUCCESS);

ssl_error:
	err = ERR_get_error();
	ERR_error_string_n(err, errbuf, sizeof(errbuf));
	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
		      ISC_LOG_ERROR, "Error initializing TLS context: %s",
		      errbuf);

	return (ISC_R_TLSERROR);
}

isc_result_t
isc_tlsctx_createserver(const char *keyfile, const char *certfile,
			isc_tlsctx_t **ctxp) {
	int rv;
	unsigned long err;
	bool ephemeral = (keyfile == NULL && certfile == NULL);
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *bn = NULL;
	SSL_CTX *ctx = NULL;
	RSA *rsa = NULL;
	char errbuf[256];
	const SSL_METHOD *method = NULL;

	REQUIRE(ctxp != NULL && *ctxp == NULL);
	REQUIRE((keyfile == NULL) == (certfile == NULL));

	method = TLS_server_method();
	if (method == NULL) {
		goto ssl_error;
	}
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		goto ssl_error;
	}
	RUNTIME_CHECK(ctx != NULL);

	SSL_CTX_set_options(ctx, COMMON_SSL_OPTIONS);

#if HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#else
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
					 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif

	if (ephemeral) {
		rsa = RSA_new();
		if (rsa == NULL) {
			goto ssl_error;
		}
		bn = BN_new();
		if (bn == NULL) {
			goto ssl_error;
		}
		BN_set_word(bn, RSA_F4);
		rv = RSA_generate_key_ex(rsa, 4096, bn, NULL);
		if (rv != 1) {
			goto ssl_error;
		}
		cert = X509_new();
		if (cert == NULL) {
			goto ssl_error;
		}
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			goto ssl_error;
		}

		/*
		 * EVP_PKEY_assign_*() set the referenced key to key
		 * however these use the supplied key internally and so
		 * key will be freed when the parent pkey is freed.
		 */
		EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
		rsa = NULL;
		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

#if OPENSSL_VERSION_NUMBER < 0x10101000L
		X509_gmtime_adj(X509_get_notBefore(cert), 0);
#else
		X509_gmtime_adj(X509_getm_notBefore(cert), 0);
#endif
		/*
		 * We set the vailidy for 10 years.
		 */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
		X509_gmtime_adj(X509_get_notAfter(cert), 3650 * 24 * 3600);
#else
		X509_gmtime_adj(X509_getm_notAfter(cert), 3650 * 24 * 3600);
#endif

		X509_set_pubkey(cert, pkey);

		X509_NAME *name = X509_get_subject_name(cert);

		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
					   (const unsigned char *)"AQ", -1, -1,
					   0);
		X509_NAME_add_entry_by_txt(
			name, "O", MBSTRING_ASC,
			(const unsigned char *)"BIND9 ephemeral "
					       "certificate",
			-1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					   (const unsigned char *)"bind9.local",
					   -1, -1, 0);

		X509_set_issuer_name(cert, name);
		X509_sign(cert, pkey, EVP_sha256());
		rv = SSL_CTX_use_certificate(ctx, cert);
		if (rv != 1) {
			goto ssl_error;
		}
		rv = SSL_CTX_use_PrivateKey(ctx, pkey);
		if (rv != 1) {
			goto ssl_error;
		}

		X509_free(cert);
		EVP_PKEY_free(pkey);
		BN_free(bn);
	} else {
		rv = SSL_CTX_use_certificate_chain_file(ctx, certfile);
		if (rv != 1) {
			goto ssl_error;
		}
		rv = SSL_CTX_use_PrivateKey_file(ctx, keyfile,
						 SSL_FILETYPE_PEM);
		if (rv != 1) {
			goto ssl_error;
		}
	}

	*ctxp = ctx;
	return (ISC_R_SUCCESS);

ssl_error:
	err = ERR_get_error();
	ERR_error_string_n(err, errbuf, sizeof(errbuf));
	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
		      ISC_LOG_ERROR, "Error initializing TLS context: %s",
		      errbuf);

	if (ctx != NULL) {
		SSL_CTX_free(ctx);
	}
	if (cert != NULL) {
		X509_free(cert);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (bn != NULL) {
		BN_free(bn);
	}
	if (rsa != NULL) {
		RSA_free(rsa);
	}

	return (ISC_R_TLSERROR);
}

static long
get_tls_version_disable_bit(const isc_tls_protocol_version_t tls_ver) {
	long bit = 0;

	switch (tls_ver) {
	case ISC_TLS_PROTO_VER_1_2:
#ifdef SSL_OP_NO_TLSv1_2
		bit = SSL_OP_NO_TLSv1_2;
#else
		bit = 0;
#endif
		break;
	case ISC_TLS_PROTO_VER_1_3:
#ifdef SSL_OP_NO_TLSv1_3
		bit = SSL_OP_NO_TLSv1_3;
#else
		bit = 0;
#endif
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
		break;
	};

	return (bit);
}

bool
isc_tls_protocol_supported(const isc_tls_protocol_version_t tls_ver) {
	return (get_tls_version_disable_bit(tls_ver) != 0);
}

isc_tls_protocol_version_t
isc_tls_protocol_name_to_version(const char *name) {
	REQUIRE(name != NULL);

	if (strcasecmp(name, "TLSv1.2") == 0) {
		return (ISC_TLS_PROTO_VER_1_2);
	} else if (strcasecmp(name, "TLSv1.3") == 0) {
		return (ISC_TLS_PROTO_VER_1_3);
	}

	return (ISC_TLS_PROTO_VER_UNDEFINED);
}

void
isc_tlsctx_set_protocols(isc_tlsctx_t *ctx, const uint32_t tls_versions) {
	REQUIRE(ctx != NULL);
	REQUIRE(tls_versions != 0);
	long set_options = 0;
	long clear_options = 0;
	uint32_t versions = tls_versions;

	/*
	 * The code below might be initially hard to follow because of the
	 * double negation that OpenSSL enforces.
	 *
	 * Taking into account that OpenSSL provides bits to *disable*
	 * specific protocol versions, like SSL_OP_NO_TLSv1_2,
	 * SSL_OP_NO_TLSv1_3, etc., the code has the following logic:
	 *
	 * If a protocol version is not specified in the bitmask, get the
	 * bit that disables it and add it to the set of TLS options to
	 * set ('set_options'). Otherwise, if a protocol version is set,
	 * add the bit to the set of options to clear ('clear_options').
	 */

	/* TLS protocol versions are defined as powers of two. */
	for (uint32_t tls_ver = ISC_TLS_PROTO_VER_1_2;
	     tls_ver < ISC_TLS_PROTO_VER_UNDEFINED; tls_ver <<= 1)
	{
		/* Only supported versions should ever be passed to the
		 * function. The configuration file was not verified
		 * properly, if we are trying to enable an unsupported
		 * TLS version */
		INSIST(isc_tls_protocol_supported(tls_ver));
		if ((tls_versions & tls_ver) == 0) {
			set_options |= get_tls_version_disable_bit(tls_ver);
		} else {
			clear_options |= get_tls_version_disable_bit(tls_ver);
		}
		versions &= ~(tls_ver);
	}

	/* All versions should be processed at this point, thus the value
	 * must equal zero. If it is not, then some garbage has been
	 * passed to the function; this situation is worth
	 * investigation. */
	INSIST(versions == 0);

	(void)SSL_CTX_set_options(ctx, set_options);
	(void)SSL_CTX_clear_options(ctx, clear_options);
}

bool
isc_tlsctx_load_dhparams(isc_tlsctx_t *ctx, const char *dhparams_file) {
	REQUIRE(ctx != NULL);
	REQUIRE(dhparams_file != NULL);
	REQUIRE(*dhparams_file != '\0');

#ifdef SSL_CTX_set_tmp_dh
	/* OpenSSL < 3.0 */
	DH *dh = NULL;
	FILE *paramfile;

	paramfile = fopen(dhparams_file, "r");

	if (paramfile) {
		int check = 0;
		dh = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
		fclose(paramfile);

		if (dh == NULL) {
			return (false);
		} else if (DH_check(dh, &check) != 1 || check != 0) {
			DH_free(dh);
			return (false);
		}
	} else {
		return (false);
	}

	if (SSL_CTX_set_tmp_dh(ctx, dh) != 1) {
		DH_free(dh);
		return (false);
	}

	DH_free(dh);
#else
	/* OpenSSL >= 3.0: SSL_CTX_set_tmp_dh() is deprecated in OpenSSL 3.0 */
	EVP_PKEY *dh = NULL;
	BIO *bio = NULL;

	bio = BIO_new_file(dhparams_file, "r");
	if (bio == NULL) {
		return (false);
	}

	dh = PEM_read_bio_Parameters(bio, NULL);
	if (dh == NULL) {
		BIO_free(bio);
		return (false);
	}

	if (SSL_CTX_set0_tmp_dh_pkey(ctx, dh) != 1) {
		BIO_free(bio);
		EVP_PKEY_free(dh);
		return (false);
	}

	/* No need to call EVP_PKEY_free(dh) as the "dh" is owned by the
	 * SSL context at this point. */

	BIO_free(bio);
#endif

	return (true);
}

bool
isc_tls_cipherlist_valid(const char *cipherlist) {
	isc_tlsctx_t *tmp_ctx = NULL;
	const SSL_METHOD *method = NULL;
	bool result;
	REQUIRE(cipherlist != NULL);

	if (*cipherlist == '\0') {
		return (false);
	}

	method = TLS_server_method();
	if (method == NULL) {
		return (false);
	}
	tmp_ctx = SSL_CTX_new(method);
	if (tmp_ctx == NULL) {
		return (false);
	}

	result = SSL_CTX_set_cipher_list(tmp_ctx, cipherlist) == 1;

	isc_tlsctx_free(&tmp_ctx);

	return (result);
}

void
isc_tlsctx_set_cipherlist(isc_tlsctx_t *ctx, const char *cipherlist) {
	REQUIRE(ctx != NULL);
	REQUIRE(cipherlist != NULL);
	REQUIRE(*cipherlist != '\0');

	RUNTIME_CHECK(SSL_CTX_set_cipher_list(ctx, cipherlist) == 1);
}

void
isc_tlsctx_prefer_server_ciphers(isc_tlsctx_t *ctx, const bool prefer) {
	REQUIRE(ctx != NULL);

	if (prefer) {
		(void)SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	} else {
		(void)SSL_CTX_clear_options(ctx,
					    SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
}

void
isc_tlsctx_session_tickets(isc_tlsctx_t *ctx, const bool use) {
	REQUIRE(ctx != NULL);

	if (!use) {
		(void)SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	} else {
		(void)SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
	}
}

isc_tls_t *
isc_tls_create(isc_tlsctx_t *ctx) {
	isc_tls_t *newctx = NULL;

	REQUIRE(ctx != NULL);

	newctx = SSL_new(ctx);
	if (newctx == NULL) {
		char errbuf[256];
		unsigned long err = ERR_get_error();

		ERR_error_string_n(err, errbuf, sizeof(errbuf));
		fprintf(stderr, "%s:SSL_new(%p) -> %s\n", __func__, ctx,
			errbuf);
	}

	return (newctx);
}

void
isc_tls_free(isc_tls_t **tlsp) {
	REQUIRE(tlsp != NULL && *tlsp != NULL);

	SSL_free(*tlsp);
	*tlsp = NULL;
}

#if HAVE_LIBNGHTTP2
#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * NPN TLS extension client callback.
 */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
		return (SSL_TLSEXT_ERR_NOACK);
	}
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

void
isc_tlsctx_enable_http2client_alpn(isc_tlsctx_t *ctx) {
	REQUIRE(ctx != NULL);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)NGHTTP2_PROTO_ALPN,
				NGHTTP2_PROTO_ALPN_LEN);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int
next_proto_cb(isc_tls_t *ssl, const unsigned char **data, unsigned int *len,
	      void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	*data = (const unsigned char *)NGHTTP2_PROTO_ALPN;
	*len = (unsigned int)NGHTTP2_PROTO_ALPN_LEN;
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int
alpn_select_proto_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	int ret;

	UNUSED(ssl);
	UNUSED(arg);

	ret = nghttp2_select_next_protocol((unsigned char **)(uintptr_t)out,
					   outlen, in, inlen);

	if (ret != 1) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	return (SSL_TLSEXT_ERR_OK);
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

void
isc_tlsctx_enable_http2server_alpn(isc_tlsctx_t *tls) {
	REQUIRE(tls != NULL);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_protos_advertised_cb(tls, next_proto_cb, NULL);
#endif // OPENSSL_NO_NEXTPROTONEG
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_select_cb(tls, alpn_select_proto_cb, NULL);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}
#endif /* HAVE_LIBNGHTTP2 */

void
isc_tls_get_selected_alpn(isc_tls_t *tls, const unsigned char **alpn,
			  unsigned int *alpnlen) {
	REQUIRE(tls != NULL);
	REQUIRE(alpn != NULL);
	REQUIRE(alpnlen != NULL);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_get0_next_proto_negotiated(tls, alpn, alpnlen);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	if (*alpn == NULL) {
		SSL_get0_alpn_selected(tls, alpn, alpnlen);
	}
#endif
}

static bool
protoneg_check_protocol(const uint8_t **pout, uint8_t *pout_len,
			const uint8_t *in, size_t in_len, const uint8_t *key,
			size_t key_len) {
	for (size_t i = 0; i + key_len <= in_len; i += (size_t)(in[i] + 1)) {
		if (memcmp(&in[i], key, key_len) == 0) {
			*pout = (const uint8_t *)(&in[i + 1]);
			*pout_len = in[i];
			return (true);
		}
	}
	return (false);
}

/* dot prepended by its length (3 bytes) */
#define DOT_PROTO_ALPN	   "\x3" ISC_TLS_DOT_PROTO_ALPN_ID
#define DOT_PROTO_ALPN_LEN (sizeof(DOT_PROTO_ALPN) - 1)

static bool
dot_select_next_protocol(const uint8_t **pout, uint8_t *pout_len,
			 const uint8_t *in, size_t in_len) {
	return (protoneg_check_protocol(pout, pout_len, in, in_len,
					(const uint8_t *)DOT_PROTO_ALPN,
					DOT_PROTO_ALPN_LEN));
}

void
isc_tlsctx_enable_dot_client_alpn(isc_tlsctx_t *ctx) {
	REQUIRE(ctx != NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ctx, (const uint8_t *)DOT_PROTO_ALPN,
				DOT_PROTO_ALPN_LEN);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int
dot_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
			 unsigned char *outlen, const unsigned char *in,
			 unsigned int inlen, void *arg) {
	bool ret;

	UNUSED(ssl);
	UNUSED(arg);

	ret = dot_select_next_protocol(out, outlen, in, inlen);

	if (!ret) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	return (SSL_TLSEXT_ERR_OK);
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

void
isc_tlsctx_enable_dot_server_alpn(isc_tlsctx_t *tls) {
	REQUIRE(tls != NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_select_cb(tls, dot_alpn_select_proto_cb, NULL);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}
