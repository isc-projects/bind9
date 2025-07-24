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

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#include <isc/crypto.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/tls.h>
#include <isc/util.h>

static isc_mem_t *isc__crypto_mctx = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER *base = NULL, *fips = NULL;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

const EVP_MD *isc__crypto_md5 = NULL;
const EVP_MD *isc__crypto_sha1 = NULL;
const EVP_MD *isc__crypto_sha224 = NULL;
const EVP_MD *isc__crypto_sha256 = NULL;
const EVP_MD *isc__crypto_sha384 = NULL;
const EVP_MD *isc__crypto_sha512 = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define md_register_algorithm(alg, algname)                            \
	{                                                              \
		REQUIRE(isc__crypto_##alg == NULL);                    \
		isc__crypto_##alg = EVP_MD_fetch(NULL, algname, NULL); \
		if (isc__crypto_##alg == NULL) {                       \
			ERR_clear_error();                             \
		}                                                      \
	}

#define md_unregister_algorithm(alg)                             \
	{                                                        \
		if (isc__crypto_##alg != NULL) {                 \
			EVP_MD_free(UNCONST(isc__crypto_##alg)); \
			isc__crypto_##alg = NULL;                \
		}                                                \
	}
#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#define md_register_algorithm(alg, algname)      \
	{                                        \
		isc__crypto_##alg = EVP_##alg(); \
		if (isc__crypto_##alg == NULL) { \
			ERR_clear_error();       \
		}                                \
	}
#define md_unregister_algorithm(alg)
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

static isc_result_t
register_algorithms(void) {
	if (!isc_crypto_fips_mode()) {
		md_register_algorithm(md5, "MD5");
	}

	md_register_algorithm(sha1, "SHA1");
	md_register_algorithm(sha224, "SHA224");
	md_register_algorithm(sha256, "SHA256");
	md_register_algorithm(sha384, "SHA384");
	md_register_algorithm(sha512, "SHA512");

	return ISC_R_SUCCESS;
}

static void
unregister_algorithms(void) {
	md_unregister_algorithm(sha512);
	md_unregister_algorithm(sha384);
	md_unregister_algorithm(sha256);
	md_unregister_algorithm(sha224);
	md_unregister_algorithm(sha1);
	md_unregister_algorithm(md5);
}

#undef md_unregister_algorithm
#undef md_register_algorithm

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * This was crippled with LibreSSL, so just skip it:
 * https://cvsweb.openbsd.org/src/lib/libcrypto/Attic/mem.c
 */

#if ISC_MEM_TRACKLINES
/*
 * We use the internal isc__mem API here, so we can pass the file and line
 * arguments passed from OpenSSL >= 1.1.0 to our memory functions for better
 * tracking of the OpenSSL allocations.  Without this, we would always just see
 * isc__crypto_{malloc,realloc,free} in the tracking output, but with this in
 * place we get to see the places in the OpenSSL code where the allocations
 * happen.
 */

static void *
isc__crypto_malloc_ex(size_t size, const char *file, int line) {
	return isc__mem_allocate(isc__crypto_mctx, size, 0, __func__, file,
				 (unsigned int)line);
}

static void *
isc__crypto_realloc_ex(void *ptr, size_t size, const char *file, int line) {
	return isc__mem_reallocate(isc__crypto_mctx, ptr, size, 0, __func__,
				   file, (unsigned int)line);
}

static void
isc__crypto_free_ex(void *ptr, const char *file, int line) {
	if (ptr == NULL) {
		return;
	}
	if (isc__crypto_mctx != NULL) {
		isc__mem_free(isc__crypto_mctx, ptr, 0, __func__, file,
			      (unsigned int)line);
	}
}

#else /* ISC_MEM_TRACKLINES */

static void *
isc__crypto_malloc_ex(size_t size, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	return isc_mem_allocate(isc__crypto_mctx, size);
}

static void *
isc__crypto_realloc_ex(void *ptr, size_t size, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	return isc_mem_reallocate(isc__crypto_mctx, ptr, size);
}

static void
isc__crypto_free_ex(void *ptr, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	if (ptr == NULL) {
		return;
	}
	if (isc__crypto_mctx != NULL) {
		isc__mem_free(isc__crypto_mctx, ptr, 0);
	}
}

#endif /* ISC_MEM_TRACKLINES */

#endif /* !defined(LIBRESSL_VERSION_NUMBER) */

#if defined(HAVE_EVP_DEFAULT_PROPERTIES_ENABLE_FIPS)
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
		return isc_tlserr2result(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"OSSL_PROVIDER_load", ISC_R_CRYPTOFAILURE);
	}

	INSIST(base == NULL);
	base = OSSL_PROVIDER_load(NULL, "base");
	if (base == NULL) {
		OSSL_PROVIDER_unload(fips);
		return isc_tlserr2result(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"OSS_PROVIDER_load", ISC_R_CRYPTOFAILURE);
	}

	if (EVP_default_properties_enable_fips(NULL, 1) == 0) {
		return isc_tlserr2result(ISC_LOGCATEGORY_GENERAL,
					 ISC_LOGMODULE_CRYPTO,
					 "EVP_default_properties_enable_fips",
					 ISC_R_CRYPTOFAILURE);
	}

	unregister_algorithms();
	register_algorithms();

	return ISC_R_SUCCESS;
}
#elif defined(HAVE_FIPS_MODE)
bool
isc_crypto_fips_mode(void) {
	return FIPS_mode() != 0;
}

isc_result_t
isc_crypto_fips_enable(void) {
	if (isc_crypto_fips_mode()) {
		return ISC_R_SUCCESS;
	}

	if (FIPS_mode_set(1) == 0) {
		return isc_tlserr2result(ISC_LOGCATEGORY_GENERAL,
					 ISC_LOGMODULE_CRYPTO, "FIPS_mode_set",
					 ISC_R_CRYPTOFAILURE);
	}

	unregister_algorithms();
	register_algorithms();

	return ISC_R_SUCCESS;
}
#else
bool
isc_crypto_fips_mode(void) {
	return false;
}

isc_result_t
isc_crypto_fips_enable(void) {
	return ISC_R_NOTIMPLEMENTED;
}
#endif

void
isc__crypto_setdestroycheck(bool check) {
	isc_mem_setdestroycheck(isc__crypto_mctx, check);
}

void
isc__crypto_initialize(void) {
	uint64_t opts = OPENSSL_INIT_LOAD_CONFIG;

	isc_mem_create("OpenSSL", &isc__crypto_mctx);
	isc_mem_setdebugging(isc__crypto_mctx, 0);
	isc_mem_setdestroycheck(isc__crypto_mctx, false);

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 * CRYPTO_set_mem_(_ex)_functions() returns 1 on success or 0 on
	 * failure, which means OpenSSL already allocated some memory.  There's
	 * nothing we can do about it.
	 */
	(void)CRYPTO_set_mem_functions(isc__crypto_malloc_ex,
				       isc__crypto_realloc_ex,
				       isc__crypto_free_ex);
#endif /* !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= \
	  0x30000000L  */

#if defined(OPENSSL_INIT_NO_ATEXIT)
	/*
	 * We call OPENSSL_cleanup() manually, in a correct order, thus disable
	 * the automatic atexit() handler.
	 */
	opts |= OPENSSL_INIT_NO_ATEXIT;
#endif

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
		isc_tlserr2result(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
				  "RAND_status", ISC_R_CRYPTOFAILURE);
		FATAL_ERROR("OpenSSL pseudorandom number generator "
			    "cannot be initialized (see the `PRNG not "
			    "seeded' message in the OpenSSL FAQ)");
	}
}

void
isc__crypto_shutdown(void) {
	unregister_algorithms();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (base != NULL) {
		OSSL_PROVIDER_unload(base);
	}

	if (fips != NULL) {
		OSSL_PROVIDER_unload(fips);
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

	OPENSSL_cleanup();

	isc_mem_detach(&isc__crypto_mctx);
}
