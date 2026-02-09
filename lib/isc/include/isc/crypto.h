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

#include <stddef.h>
#include <stdint.h>

#include <isc/md.h>
#include <isc/region.h>
#include <isc/types.h>

/**
 * \brief
 * Context to an AEAD cipher.
 *
 * \warning Do not rely on the fact that this typedef is a `EVP_CIPHER_CTX`.
 * It _can_ and **will** change without any announcement.
 */
#ifdef HAVE_EVP_AEAD_CTX_NEW
typedef struct evp_aead_ctx_st isc_crypto_aead_t;
#else  /* HAVE_EVP_AEAD_CTX_NEW */
typedef struct evp_cipher_ctx_st isc_crypto_aead_t;
#endif /* HAVE_EVP_AEAD_CTX_NEW */

typedef enum isc_crypto_aead_algorithm {
	ISC_CRYPTO_AEAD_ALGORITHM_INVALID = 0,
	ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM = 1,
	ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM = 2,
	ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305 = 3,
	ISC_CRYPTO_AEAD_ALGORITHM_MAX = 4,
} isc_crypto_aead_algorithm_t;

typedef enum isc_crypto_aead_direction {
	ISC_CRYPTO_AEAD_DIRECTION_INVALID = 0,
	ISC_CRYPTO_AEAD_DIRECTION_SEAL = 1,
	ISC_CRYPTO_AEAD_DIRECTION_OPEN = 2,
	ISC_CRYPTO_AEAD_DIRECTION_MAX = 3,
} isc_crypto_aead_direction_t;

constexpr size_t isc_crypto_aes128gcm_key_length = 16;
constexpr size_t isc_crypto_aes256gcm_key_length = 32;
constexpr size_t isc_crypto_chacha20poly1305_key_length = 32;

constexpr size_t isc_crypto_aes128gcm_nonce_length = 12;
constexpr size_t isc_crypto_aes256gcm_nonce_length = 12;
constexpr size_t isc_crypto_chacha20poly1305_nonce_length = 12;

constexpr size_t isc_crypto_aes128gcm_tag_length = 16;
constexpr size_t isc_crypto_aes256gcm_tag_length = 16;
constexpr size_t isc_crypto_chacha20poly1305_tag_length = 16;

constexpr size_t isc_crypto_aead_tag_length = 16;

void
isc_crypto_aead_destroy(isc_crypto_aead_t **aeadp);
/**<
 * \brief
 * Destroy the AEAD context and wipe out the keys.
 *
 * Requires:
 * - `*aeadp` must be a valid AEAD context.
 */

isc_result_t
isc_crypto_aead_create(isc_crypto_aead_algorithm_t algorithm,
		       isc_constregion_t	   key,
		       isc_crypto_aead_direction_t direction,
		       isc_crypto_aead_t	 **aeadp);
/**<
 * \brief
 * Create an AEAD context for encryption or decryption operations.
 *
 * Requires:
 * - `algorithm` must be a valid algorithm enum value.
 * - `key.base != NULL` and key.length must be equal to the exact key length of
 * the algorithm.
 * - `direction` must be either #ISC_CRYPTO_AEAD_DIRECTION_SEAL or
 * #ISC_CRYPTO_AEAD_DIRECTION_OPEN
 * - `aeadp != NULL` and `*aeadp == NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the aead algorithm is not available
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_aead_seal(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t plaintext, isc_region_t out,
		     size_t *out_sealed_len, isc_constregion_t additional_data);
/**<
 * \brief
 * Encrypt the plaintext and authenticate the ciphertext with the additional
 * data.
 *
 * Requires:
 * - `aead` is a valid AEAD context.
 * - `nonce.base != NULL` and has the appropriate length for the algorithm.
 * - `plaintext.base != NULL` and `out.base != NULL`
 * - `out.length == plaintext.length + isc_crypto_aead_tag_length`
 * - `out_sealed_len != NULL`
 * - `additional_data` must either have a `NULL` base or a non-zero length.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_CRYPTOFAILURE on opaque cryptographical failure
 */

isc_result_t
isc_crypto_aead_open(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t ciphertext, isc_region_t out,
		     size_t *out_opened_len, isc_constregion_t additional_data);
/**<
 * \brief
 * Decrypt the ciphertext and authenticate the ciphertext with the additional
 * data.
 *
 * Requires:
 * - `aead` is a valid AEAD context.
 * - `nonce.base != NULL` and has the appropriate length for the algorithm.
 * - `ciphertext.base != NULL` and `out.base != NULL`
 * - `out.length == ciphertext.length - isc_crypto_aead_tag_length`
 * - `out_opened_len != NULL`
 * - `additional_data` must either have a `NULL` base or a non-zero length.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_CRYPTOFAILURE on opaque cryptographical failure
 */

isc_result_t
isc_crypto_hkdf_extract(isc_region_t out, isc_md_type_t md,
			isc_constregion_t secret, isc_constregion_t salt);
/**<
 * HKDF-Extract as specified by RFC5869.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `secret.base != NULL` and `secret.length != 0`
 * - `salt.base != NULL` and `sakt.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf_expand(isc_region_t out, isc_md_type_t md,
		       isc_constregion_t prk, isc_constregion_t info);
/**<
 * HKDF-Expand as specified by RFC5869.
 *
 * Please note that `prk` can't be just substituted with the output of any
 * secret function. Please refer to RFC5869 Section 3.3 for more information on
 * what key values are appropriate for calling HKDF-Expand.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `prk.base != NULL` and `prk.length != 0`
 * - `info.base != NULL` and `info.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf_expand_label(isc_region_t out, isc_md_type_t md,
			     isc_constregion_t secret, isc_constregion_t label);
/**<
 * \brief
 * HKDF-Expand-Label as specified by RFC 8446 Section 7.1.
 * The context parameter is not supported and is passed as empty.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `secret.base != NULL` and `secret.length != 0`
 * - `label.base != NULL` and `label.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf(isc_region_t out, isc_md_type_t md, isc_constregion_t secret,
		isc_constregion_t salt, isc_constregion_t info);
/**<
 * \brief
 * HKDF-Extract-Expand as specified by RFC5869.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `ikm.base != NULL` and `ikm.length != 0`
 * - `salt.base != NULL` and `ikm.length != 0`
 * - `info.base != NULL` and `info.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

bool
isc_crypto_fips_mode(void);
/*
 * Return if FIPS mode is currently enabled or not.
 */

isc_result_t
isc_crypto_fips_enable(void);
/*
 * Enable FIPS mode. It cannot be disabled afterwards.
 *
 * This function is NOT thread safe.
 */

/**
 * Private
 */

void
isc__crypto_setdestroycheck(bool check);

void
isc__crypto_initialize(void);

void
isc__crypto_shutdown(void);
