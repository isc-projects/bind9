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

#include <stdbool.h>
#include <stdint.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <isc/buffer.h>
#include <isc/crypto.h>
#include <isc/hmac.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/ossl_wrap.h>
#include <isc/region.h>
#include <isc/safe.h>
#include <isc/util.h>

#define CRYPTO_ERROR(fn)                                           \
	isc__ossl_wrap_logged_toresult(                            \
		ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO, fn, \
		ISC_R_CRYPTOFAILURE, __FILE__, __LINE__)

struct isc_hmac_key {
	uint32_t magic;
	uint32_t len;
	isc_mem_t *mctx;
	const OSSL_PARAM *params;
	uint8_t secret[];
};

constexpr uint32_t hmac_key_magic = ISC_MAGIC('H', 'M', 'A', 'C');

static OSSL_PROVIDER *base = NULL, *fips = NULL;

/*
 * Because HKDF-Expand-Label is defined in the RFC of TLS 1.3, OpenSSL
 * has named the algorithm as TLS1.3 KDF internally.
 */
static EVP_KDF *evp_tls_1_3_kdf = NULL;
static EVP_KDF *evp_hkdf = NULL;

static EVP_MAC *evp_hmac = NULL;

static isc_constregion_t md_to_name[ISC_MD_MAX] = {
	[ISC_MD_UNKNOWN] = { NULL, 0 },
	[ISC_MD_MD5] = { "MD5", sizeof("MD5") - 1 },
	[ISC_MD_SHA1] = { "SHA1", sizeof("SHA1") - 1 },
	[ISC_MD_SHA224] = { "SHA2-224", sizeof("SHA2-224") - 1 },
	[ISC_MD_SHA256] = { "SHA2-256", sizeof("SHA2-256") - 1 },
	[ISC_MD_SHA384] = { "SHA2-384", sizeof("SHA2-384") - 1 },
	[ISC_MD_SHA512] = { "SHA2-512", sizeof("SHA2-512") - 1 },
};

static OSSL_PARAM md_to_hmac_params[ISC_MD_MAX][2] = {
	[ISC_MD_UNKNOWN] = { OSSL_PARAM_END },
	[ISC_MD_MD5] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("MD5"), sizeof("MD5") - 1),
		OSSL_PARAM_END,
	},
	[ISC_MD_SHA1] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("SHA1"), sizeof("SHA1") - 1),
		OSSL_PARAM_END,
	},
	[ISC_MD_SHA224] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("SHA2-224"), sizeof("SHA2-224") - 1),
		OSSL_PARAM_END,
	},
	[ISC_MD_SHA256] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("SHA2-256"), sizeof("SHA2-256") - 1),
		OSSL_PARAM_END,
	},
	[ISC_MD_SHA384] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("SHA2-384"), sizeof("SHA2-384") - 1),
		OSSL_PARAM_END,
	},
	[ISC_MD_SHA512] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, UNCONST("SHA2-512"), sizeof("SHA2-512") - 1),
		OSSL_PARAM_END,
	},
};

#define md_register_algorithm(alg)                                             \
	{                                                                      \
		REQUIRE(isc__crypto_md[ISC_MD_##alg] == NULL);                 \
		isc__crypto_md[ISC_MD_##alg] = EVP_MD_fetch(NULL, #alg, NULL); \
		if (isc__crypto_md[ISC_MD_##alg] == NULL) {                    \
			ERR_clear_error();                                     \
		}                                                              \
	}

static isc_result_t
register_algorithms(void) {
	if (!isc_crypto_fips_mode()) {
		md_register_algorithm(MD5);
	}

	md_register_algorithm(SHA1);
	md_register_algorithm(SHA224);
	md_register_algorithm(SHA256);
	md_register_algorithm(SHA384);
	md_register_algorithm(SHA512);

	/* We _must_ have HMAC */
	evp_hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (evp_hmac == NULL) {
		ERR_clear_error();
		FATAL_ERROR("OpenSSL failed to find an HMAC implementation. "
			    "Please make sure the default provider has an "
			    "EVP_MAC-HMAC implementation");
	}

	evp_tls_1_3_kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_TLS1_3_KDF, NULL);
	if (evp_tls_1_3_kdf == NULL) {
		FATAL_ERROR(
			"OpenSSL failed to find an TLS 1.3 KDF implementation."
			"Please make sure the default provider has an "
			"EVP_KDF-TLS13_KDF implementation");
	}

	evp_hkdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
	if (evp_hkdf == NULL) {
		ERR_clear_error();
		FATAL_ERROR("OpenSSL failed to find an HKDF implementation. "
			    "Please make sure the default provider has an "
			    "EVP_KDF-HKDF implementation");
	}

	return ISC_R_SUCCESS;
}

static void
unregister_algorithms(void) {
	INSIST(evp_hkdf != NULL);
	EVP_KDF_free(evp_hkdf);
	evp_hkdf = NULL;

	INSIST(evp_tls_1_3_kdf != NULL);
	EVP_KDF_free(evp_tls_1_3_kdf);
	evp_tls_1_3_kdf = NULL;

	for (size_t i = 0; i < ISC_MD_MAX; i++) {
		if (isc__crypto_md[i] != NULL) {
			EVP_MD_free(isc__crypto_md[i]);
			isc__crypto_md[i] = NULL;
		}
	}

	INSIST(evp_hmac != NULL);
	EVP_MAC_free(evp_hmac);
	evp_hmac = NULL;
}

#undef md_register_algorithm

/*
 * HMAC
 */

/*
 * Do not call EVP_Q_mac or HMAC (since it calls EVP_Q_mac internally)
 *
 * Each invocation of the EVP_Q_mac function causes an explicit fetch.
 */
isc_result_t
isc_hmac(isc_md_type_t type, const void *key, const size_t keylen,
	 const unsigned char *buf, const size_t len, unsigned char *digest,
	 unsigned int *digestlen) {
	EVP_MAC_CTX *ctx;
	size_t maclen;

	REQUIRE(type < ISC_MD_MAX);

	if (isc__crypto_md[type] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	ctx = EVP_MAC_CTX_new(evp_hmac);
	RUNTIME_CHECK(ctx != NULL);

	if (EVP_MAC_init(ctx, key, keylen, md_to_hmac_params[type]) != 1) {
		goto fail;
	}

	if (EVP_MAC_update(ctx, buf, len) != 1) {
		goto fail;
	}

	maclen = *digestlen;
	if (EVP_MAC_final(ctx, digest, &maclen, maclen) != 1) {
		goto fail;
	}

	*digestlen = maclen;

	EVP_MAC_CTX_free(ctx);
	return ISC_R_SUCCESS;

fail:
	ERR_clear_error();
	EVP_MAC_CTX_free(ctx);
	return ISC_R_CRYPTOFAILURE;
}

/*
 * You do not need to process the key to fit the block size.
 *
 * https://github.com/openssl/openssl/blob/925e4fba1098036e8f8d22652cff6f64c5c7d571/crypto/hmac/hmac.c#L61-L80
 */
isc_result_t
isc_hmac_key_create(isc_md_type_t type, const void *secret, const size_t len,
		    isc_mem_t *mctx, isc_hmac_key_t **keyp) {
	isc_hmac_key_t *key;
	uint8_t digest[ISC_MAX_MD_SIZE];
	unsigned int digest_len = sizeof(digest);
	size_t key_len;

	REQUIRE(keyp != NULL && *keyp == NULL);
	REQUIRE(type < ISC_MD_MAX);

	if (isc__crypto_md[type] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	if (len > (size_t)EVP_MD_block_size(isc__crypto_md[type])) {
		RETERR(isc_md(type, secret, len, digest, &digest_len));
		secret = digest;
		key_len = digest_len;
	} else {
		key_len = len;
	}

	key = isc_mem_get(mctx, STRUCT_FLEX_SIZE(key, secret, key_len));
	*key = (isc_hmac_key_t){
		.magic = hmac_key_magic,
		.len = key_len,
		.params = md_to_hmac_params[type],
	};
	memmove(key->secret, secret, key_len);
	isc_mem_attach(mctx, &key->mctx);

	*keyp = key;

	return ISC_R_SUCCESS;
}

void
isc_hmac_key_destroy(isc_hmac_key_t **keyp) {
	isc_hmac_key_t *key;

	REQUIRE(keyp != NULL && *keyp != NULL);
	REQUIRE((*keyp)->magic == hmac_key_magic);

	key = *keyp;
	*keyp = NULL;

	key->magic = 0x00;

	isc_safe_memwipe(key->secret, key->len);
	isc_mem_putanddetach(&key->mctx, key,
			     STRUCT_FLEX_SIZE(key, secret, key->len));
}

isc_region_t
isc_hmac_key_expose(isc_hmac_key_t *key) {
	REQUIRE(key != NULL && key->magic == hmac_key_magic);

	return (isc_region_t){ .base = key->secret, .length = key->len };
}

bool
isc_hmac_key_equal(isc_hmac_key_t *a, isc_hmac_key_t *b) {
	REQUIRE(a != NULL && a->magic == hmac_key_magic);
	REQUIRE(b != NULL && b->magic == hmac_key_magic);

	if (a->params != b->params) {
		return false;
	}

	if (a->len != b->len) {
		return false;
	}

	return isc_safe_memequal(a->secret, b->secret, a->len);
}

isc_hmac_t *
isc_hmac_new(void) {
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(evp_hmac);
	RUNTIME_CHECK(ctx != NULL);
	return ctx;
}

void
isc_hmac_free(isc_hmac_t *hmac) {
	EVP_MAC_CTX_free(hmac);
}

isc_result_t
isc_hmac_init(isc_hmac_t *hmac, isc_hmac_key_t *key) {
	REQUIRE(key != NULL && key->magic == hmac_key_magic);
	REQUIRE(hmac != NULL);

	if (EVP_MAC_init(hmac, key->secret, key->len, key->params) != 1) {
		ERR_clear_error();
		return ISC_R_CRYPTOFAILURE;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_hmac_update(isc_hmac_t *hmac, const unsigned char *buf, const size_t len) {
	REQUIRE(hmac != NULL);

	if (buf == NULL || len == 0) {
		return ISC_R_SUCCESS;
	}

	if (EVP_MAC_update(hmac, buf, len) != 1) {
		ERR_clear_error();
		return ISC_R_CRYPTOFAILURE;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_hmac_final(isc_hmac_t *hmac, isc_buffer_t *out) {
	size_t len;

	REQUIRE(hmac != NULL);

	len = isc_buffer_availablelength(out);
	if (len < EVP_MAC_CTX_get_mac_size(hmac)) {
		return ISC_R_NOSPACE;
	}

	if (EVP_MAC_final(hmac, isc_buffer_used(out), &len, len) != 1) {
		ERR_clear_error();
		return ISC_R_CRYPTOFAILURE;
	}

	isc_buffer_add(out, len);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_crypto_hkdf_extract(isc_region_t out, isc_md_type_t md,
			isc_constregion_t secret, isc_constregion_t salt) {
	isc_result_t result;
	EVP_KDF_CTX *ctx;
	int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);

	if (isc__crypto_md[md] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,
				       UNCONST(md_to_name[md].base),
				       md_to_name[md].length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,
					UNCONST(secret.base), secret.length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, UNCONST(salt.base),
					salt.length),
		OSSL_PARAM_END,
	};

	ctx = EVP_KDF_CTX_new(evp_hkdf);
	if (ctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_CTX_new"));
	}

	if (EVP_KDF_derive(ctx, out.base, out.length, params) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_KDF_CTX_free(ctx);
	return result;
}

isc_result_t
isc_crypto_hkdf_expand(isc_region_t out, isc_md_type_t md,
		       isc_constregion_t prk, isc_constregion_t info) {
	isc_result_t result;
	EVP_KDF_CTX *ctx;
	int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(prk.base != NULL && prk.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	if (isc__crypto_md[md] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,
				       UNCONST(md_to_name[md].base),
				       md_to_name[md].length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, UNCONST(prk.base),
					prk.length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, UNCONST(info.base),
					info.length),
		OSSL_PARAM_END,
	};

	ctx = EVP_KDF_CTX_new(evp_hkdf);
	if (ctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_CTX_new"));
	}

	if (EVP_KDF_derive(ctx, out.base, out.length, params) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_KDF_CTX_free(ctx);
	return result;
}

isc_result_t
isc_crypto_hkdf_expand_label(isc_region_t out, isc_md_type_t md,
			     isc_constregion_t secret,
			     isc_constregion_t label) {
	isc_result_t result;
	EVP_KDF_CTX *ctx;
	int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;

	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(label.base != NULL && label.length != 0);

	if (isc__crypto_md[md] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,
				       UNCONST(md_to_name[md].base),
				       md_to_name[md].length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX,
					UNCONST("tls13 "),
					sizeof("tls13 ") - 1),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,
					UNCONST(secret.base), secret.length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL,
					UNCONST(label.base), label.length),
		OSSL_PARAM_END,
	};

	/* Please see the comment in `evp_tls_1_3_kdf` */
	ctx = EVP_KDF_CTX_new(evp_tls_1_3_kdf);
	if (ctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_CTX_new"));
	}

	if (EVP_KDF_derive(ctx, out.base, out.length, params) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_KDF_CTX_free(ctx);
	return result;
}

isc_result_t
isc_crypto_hkdf(isc_region_t out, isc_md_type_t md, isc_constregion_t ikm,
		isc_constregion_t salt, isc_constregion_t info) {
	isc_result_t result;
	EVP_KDF_CTX *ctx;
	int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(ikm.base != NULL && ikm.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	if (isc__crypto_md[md] == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,
				       UNCONST(md_to_name[md].base),
				       md_to_name[md].length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, UNCONST(ikm.base),
					ikm.length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, UNCONST(info.base),
					info.length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, UNCONST(salt.base),
					salt.length),
		OSSL_PARAM_END,
	};

	ctx = EVP_KDF_CTX_new(evp_hkdf);
	if (ctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_CTX_new"));
	}

	if (EVP_KDF_derive(ctx, out.base, out.length, params) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_KDF_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_KDF_CTX_free(ctx);
	return result;
}

bool
isc_crypto_fips_mode(void) {
	return EVP_default_properties_is_fips_enabled(NULL) != 0;
}

isc_result_t
isc_crypto_fips_enable(void) {
	if (isc_crypto_fips_mode()) {
		return ISC_R_SUCCESS;
	}

	INSIST(fips == NULL);
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"OSSL_PROVIDER_load", ISC_R_CRYPTOFAILURE);
	}

	INSIST(base == NULL);
	base = OSSL_PROVIDER_load(NULL, "base");
	if (base == NULL) {
		OSSL_PROVIDER_unload(fips);
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"OSS_PROVIDER_load", ISC_R_CRYPTOFAILURE);
	}

	if (EVP_default_properties_enable_fips(NULL, 1) == 0) {
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"EVP_default_properties_enable_fips",
			ISC_R_CRYPTOFAILURE);
	}

	unregister_algorithms();
	register_algorithms();

	return ISC_R_SUCCESS;
}

/*
 * OPENSSL_cleanup() in OpenSSL 4 doesn't free the memory, which is not
 * compatible with BIND 9's memory leak detection code, that is why the memory
 * tracking has been disabled in this module, and this function is a no-op.
 * This can be cleaned up once OpenSSL 1.1.x support is removed.
 *
 * See https://github.com/openssl/openssl/pull/29721
 */
void
isc__crypto_setdestroycheck(bool check) {
	UNUSED(check);
}

void
isc__crypto_initialize(void) {
	/*
	 * We call OPENSSL_cleanup() manually, in a correct order, thus disable
	 * the automatic atexit() handler.
	 */
	uint64_t opts = OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT;

	RUNTIME_CHECK(OPENSSL_init_ssl(opts, NULL) == 1);

	register_algorithms();

#if defined(ENABLE_FIPS_MODE)
	if (isc_crypto_fips_enable() != ISC_R_SUCCESS) {
		ERR_clear_error();
		FATAL_ERROR("Failed to toggle FIPS mode but is "
			    "required for this build");
	}
#endif

	/* Protect ourselves against unseeded PRNG */
	if (RAND_status() != 1) {
		isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"RAND_status", ISC_R_CRYPTOFAILURE);
		FATAL_ERROR("OpenSSL pseudorandom number generator "
			    "cannot be initialized (see the `PRNG not "
			    "seeded' message in the OpenSSL FAQ)");
	}
}

void
isc__crypto_shutdown(void) {
	unregister_algorithms();

	if (base != NULL) {
		OSSL_PROVIDER_unload(base);
	}

	if (fips != NULL) {
		OSSL_PROVIDER_unload(fips);
	}

	OPENSSL_cleanup();
}
