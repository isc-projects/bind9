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

#include <stdbool.h>
#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <isc/log.h>
#include <isc/types.h>

#define isc_ossl_wrap_logged_toresult(category, module, funcname, fallback)  \
	isc__ossl_wrap_logged_toresult(category, module, funcname, fallback, \
				       __FILE__, __LINE__)

typedef struct isc_ossl_wrap_rsa_components {
	bool	needs_cleanup;
	BIGNUM *e, *n, *d, *p, *q, *dmp1, *dmq1, *iqmp;
} isc_ossl_wrap_rsa_components_t;

isc_result_t
isc_ossl_wrap_generate_p256_key(EVP_PKEY **pkeyp);
/*%
 * Generates an uncompressed, named P-256 secret key.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_p256_key(char *uri, EVP_PKEY **pkeyp);
/*%
 * Generates a P-256 secret key using the PKCS#11 label specified at `uri`.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 * \li `uri != NULL` and is a NUL-terminated string
 */

isc_result_t
isc_ossl_wrap_validate_p256_pkey(EVP_PKEY *pkey);
/*%
 * Validatest that a EVP_PKEY is a P-256 EC key.
 *
 * Requires:
 * \li `pkey != NULL`
 * \li pkey is a valid EVP_PKEY
 */

isc_result_t
isc_ossl_wrap_load_p256_public_from_region(isc_region_t region,
					   EVP_PKEY   **pkeyp);
/*%
 * Create a verifying `EVP_PKEY` using the P-256 public key pointed by
 * `region`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `region.base != NULL`
 * \li `region.length == 64`
 */

isc_result_t
isc_ossl_wrap_load_p256_secret_from_region(isc_region_t region,
					   EVP_PKEY   **pkeyp);
/*%
 * Create a signing `EVP_PKEY` using the P-256 secret key pointed by
 * `region`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `region.base != NULL`
 * \li `region.length == 32`
 */

isc_result_t
isc_ossl_wrap_p256_public_region(EVP_PKEY *pkey, isc_region_t pub);
/*%
 * Export the P-256 public key to the region pointed by `pub`
 *
 * Requires:
 * \li `pkey` is a non-NULL, valid, P-256 public key.
 * \li `pub` has to a non-NULL pointer with enough space to fit the public key.
 */

isc_result_t
isc_ossl_wrap_p256_secret_region(EVP_PKEY *pkey, isc_region_t sec);
/*%
 * Export the P-256 curve secret key to the region pointed by `sec`
 *
 * Requires:
 * \li `pkey` is a non-NULL, valid P-256 secret key.
 * \li `sec` has to a non-NULL pointer with enough space to fit the secret key.
 */

isc_result_t
isc_ossl_wrap_generate_p384_key(EVP_PKEY **pkeyp);
/*%
 * Generates an uncompressed, named P-256 secret key.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_p384_key(char *uri, EVP_PKEY **pkeyp);
/*%
 * Generates a P-384 secret key using the PKCS#11 label specified at `uri`.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 * \li `uri != NULL` and is a NUL-terminated string
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_ed25519_key(char *uri, EVP_PKEY **pkeyp);
/*%
 * Generates an Ed25519 key using the PKCS#11 label specified at `uri`.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 * \li `uri != NULL` and is a NUL-terminated string
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_ed448_key(char *uri, EVP_PKEY **pkeyp);
/*%
 * Generates an Ed448 key using the PKCS#11 label specified at `uri`.
 *
 * Requires:
 * \li pkeyp != NULL
 * \li *pkeyp == NULL
 * \li `uri != NULL` and is a NUL-terminated string
 */

isc_result_t
isc_ossl_wrap_load_p384_public_from_region(isc_region_t region,
					   EVP_PKEY   **pkeyp);
/*%
 * Create a verifying `EVP_PKEY` using the P-384 public key pointed by
 * `region`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `region.base != NULL`
 * \li `region.length == 64`
 */

isc_result_t
isc_ossl_wrap_load_p384_secret_from_region(isc_region_t region,
					   EVP_PKEY   **pkeyp);
/*%
 * Create a signing `EVP_PKEY` using the P-384 secret key pointed by
 * `region`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `region.base != NULL`
 * \li `region.length == 32`
 */

isc_result_t
isc_ossl_wrap_validate_p384_pkey(EVP_PKEY *pkey);

isc_result_t
isc_ossl_wrap_p384_public_region(EVP_PKEY *pkey, isc_region_t pub);
/*%
 * Export the P-384 public key to the region pointed by `pub`
 *
 * Requires:
 * \li `pkey` is a non-NULL, valid, P-384 public key.
 * \li `pub` has to a non-NULL pointer with enough space to fit the public key.
 */

isc_result_t
isc_ossl_wrap_p384_secret_region(EVP_PKEY *pkey, isc_region_t sec);
/*%
 * Export the P-384 curve secret key to the region pointed by `sec`
 *
 * Requires:
 * \li `pkey` is a non-NULL, valid P-384 secret key.
 * \li `sec` has to a non-NULL pointer with enough space to fit the secret key.
 */

isc_result_t
isc_ossl_wrap_ecdsa_set_deterministic(EVP_PKEY_CTX *pctx, const char *hash);
/*
 * Use deterministic ECDSA to generate signatures.
 *
 * Returns:
 * \li	#ISC_R_SUCCESS		-- signature set to use RFC6979
 * \li	#ISC_R_IGNORE		-- FIPS mode is active
 * \li	#ISC_R_NOTIMPLEMENTED	-- libcrypto doesn't support
 */

isc_result_t
isc_ossl_wrap_ecdsa_set_deterministic(EVP_PKEY_CTX *pctx, const char *hash);
/*
 * Use deterministic ECDSA to generate signatures.
 *
 * Returns:
 * \li	#ISC_R_SUCCESS		-- signature set to use RFC6979
 * \li	#ISC_R_IGNORE		-- FIPS mode is active
 * \li	#ISC_R_NOTIMPLEMENTED	-- libcrypto doesn't support RFC6979
 */

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp);
/*%
 * Creates a RSA key with the specified bit-size
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp);
/*%
 * Creates a RSA key with the specified bit-size using the PKCS11 label
 * specified at `uri`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `uri != NULL` and is a NUL-terminated string
 */

bool
isc_ossl_wrap_rsa_exponent_is_allowed(EVP_PKEY *pkey);
/*%
 * Returns true if the RSA public exponent of `pkey` is odd and lies
 * within the closed range [3, 2^32 + 1].  This covers every Fermat
 * prime up to F5 plus all odd intermediate values seen in deployed
 * DNSSEC keys.  Returns false if the exponent cannot be retrieved or
 * falls outside that range.
 */

bool
isc_ossl_wrap_rsa_modulus_bits_in_range(EVP_PKEY *pkey, size_t min, size_t max);
/*%
 * Returns true if the RSA modulus bit length of `pkey` is between `min`
 * and `max` inclusive.  Returns false if the modulus bit length cannot
 * be determined.
 */

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY			   *pkey,
				    isc_ossl_wrap_rsa_components_t *c);

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY			   *pkey,
				    isc_ossl_wrap_rsa_components_t *c);

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp);
/*%
 * Create a verifying `EVP_PKEY` using the public RSA components at `c`
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `c != NULL`
 * \li `c.n != NULL`
 * \li `c.e != NULL`
 */

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp);
/*%
 * Create a signing `EVP_PKEY` using the public and secret RSA components at `c`
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `c != NULL`
 * \li `c.n != NULL`
 * \li `c.e != NULL`
 */

void
isc_ossl_wrap_rsa_components_cleanup(isc_ossl_wrap_rsa_components_t *comp);

isc_result_t
isc_ossl_wrap_toresult(isc_result_t fallback);

isc_result_t
isc__ossl_wrap_logged_toresult(isc_logcategory_t category,
			       isc_logmodule_t module, const char *funcname,
			       isc_result_t fallback, const char *file,
			       int line);

/*
 * This is a bit of a namespace convention violation but it fits the spirit of
 * this header since it is exposing OpenSSL-isms to others.
 */

extern EVP_MD *isc__crypto_md[];
