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

#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <isc/buffer.h>
#include <isc/crypto.h>
#include <isc/endian.h>
#include <isc/hmac.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/ossl_wrap.h>
#include <isc/overflow.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#ifdef HAVE_OPENSSL_AEAD_H
#include <openssl/aead.h>
#endif /* HAVE_OPENSSL_AEAD_H */

#if HAVE_CRYPTO_CHACHA_20
#include <openssl/chacha.h>
#endif /* HAVE_CRYPTO_CHACHA_20 */

#ifdef HAVE_OPENSSL_HKDF_H
#include <openssl/hkdf.h>
#endif /* HAVE_OPENSSL_HKDF_H */

#define CRYPTO_ERROR(fn)                                           \
	isc__ossl_wrap_logged_toresult(                            \
		ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO, fn, \
		ISC_R_CRYPTOFAILURE, __FILE__, __LINE__)

#define HMAC_KEY_MAGIC ISC_MAGIC('H', 'M', 'A', 'C')

struct isc_hmac_key {
	uint32_t magic;
	uint32_t len;
	isc_mem_t *mctx;
	EVP_MD *md;
	uint8_t secret[];
};

struct isc_crypto_quic_hp_protect {
	uint32_t magic;
	isc_crypto_quic_hp_protect_algorithm_t algorithm;
	isc_mem_t *mctx;
	union {
		AES_KEY aes;
#if HAVE_CRYPTO_CHACHA_20
		uint8_t chacha20[32];
#else  /* HAVE_CRYPTO_CHACHA_20 */
		EVP_CIPHER_CTX *chacha20;
#endif /* HAVE_CRYPTO_CHACHA_20 */
	} key;
};

#ifdef HAVE_EVP_AEAD_CTX_NEW
STATIC_ASSERT(ISC_TYPES_COMPATIBLE(isc_crypto_aead_t, EVP_AEAD_CTX),
	      "isc_crypto_aead_t is not compatible with EVP_AEAD_CTX");
#else  /* HAVE_EVP_AEAD_CTX_NEW */
STATIC_ASSERT(ISC_TYPES_COMPATIBLE(isc_crypto_aead_t, EVP_CIPHER_CTX),
	      "isc_crypto_aead_t is not compatible with EVP_CIPHER_CTX");
#endif /* HAVE_EVP_AEAD_CTX_NEW */

constexpr uint32_t crypto_quic_hp_protect_magic = ISC_MAGIC('C', 'Q', 'h', 'p');

static isc_mem_t *isc__crypto_mctx = NULL;

#define md_register_algorithm(alg, upperalg)                              \
	{                                                                 \
		isc__crypto_md[ISC_MD_##upperalg] = UNCONST(EVP_##alg()); \
		if (isc__crypto_md[ISC_MD_##upperalg] == NULL) {          \
			ERR_clear_error();                                \
		}                                                         \
	}

static isc_result_t
register_algorithms(void) {
	if (!isc_crypto_fips_mode()) {
		md_register_algorithm(md5, MD5);
	}

	md_register_algorithm(sha1, SHA1);
	md_register_algorithm(sha224, SHA224);
	md_register_algorithm(sha256, SHA256);
	md_register_algorithm(sha384, SHA384);
	md_register_algorithm(sha512, SHA512);

	return ISC_R_SUCCESS;
}

#undef md_unregister_algorithm

/*
 * HMAC Notes
 *
 * For pre-3.0 libcrypto, we use HMAC_CTX instead of the EVP_PKEY API.
 *
 * EVP_PKEY will call HMAC_* functions internally so there is no need to add
 * even more vtables.
 */

isc_result_t
isc_hmac(isc_md_type_t type, const void *key, const size_t keylen,
	 const unsigned char *buf, const size_t len, unsigned char *digest,
	 unsigned int *digestlen) {
	EVP_MD *md;

	REQUIRE(type < ISC_MD_MAX);

	md = isc__crypto_md[type];
	if (md == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	if (HMAC(md, key, keylen, buf, len, digest, digestlen) == NULL) {
		ERR_clear_error();
		return ISC_R_CRYPTOFAILURE;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_hmac_key_create(isc_md_type_t type, const void *secret, const size_t len,
		    isc_mem_t *mctx, isc_hmac_key_t **keyp) {
	isc_hmac_key_t *key;
	EVP_MD *md;

	REQUIRE(keyp != NULL && *keyp == NULL);
	REQUIRE(type < ISC_MD_MAX);

	md = isc__crypto_md[type];
	if (md == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	key = isc_mem_get(mctx, STRUCT_FLEX_SIZE(key, secret, len));
	*key = (isc_hmac_key_t){
		.magic = HMAC_KEY_MAGIC,
		.len = len,
		.md = md,
	};
	memmove(key->secret, secret, len);
	isc_mem_attach(mctx, &key->mctx);

	*keyp = key;

	return ISC_R_SUCCESS;
}

void
isc_hmac_key_destroy(isc_hmac_key_t **keyp) {
	isc_hmac_key_t *key;

	REQUIRE(keyp != NULL && *keyp != NULL);
	REQUIRE((*keyp)->magic == HMAC_KEY_MAGIC);

	key = *keyp;
	*keyp = NULL;

	key->magic = 0x00;

	isc_safe_memwipe(key->secret, key->len);
	isc_mem_putanddetach(&key->mctx, key,
			     STRUCT_FLEX_SIZE(key, secret, key->len));
}

isc_region_t
isc_hmac_key_expose(isc_hmac_key_t *key) {
	REQUIRE(key != NULL && key->magic == HMAC_KEY_MAGIC);

	return (isc_region_t){ .base = key->secret, .length = key->len };
}

bool
isc_hmac_key_equal(isc_hmac_key_t *a, isc_hmac_key_t *b) {
	REQUIRE(a != NULL && a->magic == HMAC_KEY_MAGIC);
	REQUIRE(b != NULL && b->magic == HMAC_KEY_MAGIC);

	if (a->md != b->md) {
		return false;
	}

	if (a->len != b->len) {
		return false;
	}

	return isc_safe_memequal(a->secret, b->secret, a->len);
}

isc_hmac_t *
isc_hmac_new(void) {
	HMAC_CTX *ctx = HMAC_CTX_new();
	RUNTIME_CHECK(ctx != NULL);
	return ctx;
}

void
isc_hmac_free(isc_hmac_t *hmac) {
	if (hmac != NULL) {
		HMAC_CTX_free(hmac);
	}
}

isc_result_t
isc_hmac_init(isc_hmac_t *hmac, isc_hmac_key_t *key) {
	REQUIRE(hmac != NULL);
	REQUIRE(key != NULL && key->magic == HMAC_KEY_MAGIC);

	if (HMAC_Init_ex(hmac, key->secret, key->len, key->md, NULL) != 1) {
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

	if (HMAC_Update(hmac, buf, len) != 1) {
		ERR_clear_error();
		return ISC_R_CRYPTOFAILURE;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_hmac_final(isc_hmac_t *hmac, isc_buffer_t *out) {
	unsigned int len;

	REQUIRE(hmac != NULL);
	REQUIRE(out != NULL);

	/*
	 * LibreSSL changes HMAC_size's return from size_t to int but keeps the
	 * size_t signature in its manpage.
	 *
	 * Cast it instead of accepting LibreSSL's man(page)splaining.
	 */
	len = isc_buffer_availablelength(out);
	if (len < (unsigned int)HMAC_size(hmac)) {
		return ISC_R_NOSPACE;
	}

	if (HMAC_Final(hmac, isc_buffer_used(out), &len) != 1) {
		return ISC_R_CRYPTOFAILURE;
	}

	isc_buffer_add(out, len);

	return ISC_R_SUCCESS;
}

#ifndef LIBRESSL_VERSION_NUMBER
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

#endif /* !LIBRESSL_VERSION_NUMBER */

#ifdef HAVE_EVP_AEAD_CTX_NEW

void
isc_crypto_aead_destroy(isc_crypto_aead_t **aeadp) {
	EVP_AEAD_CTX *ctx;

	REQUIRE(aeadp != NULL && *aeadp != NULL);

	ctx = MOVE_OWNERSHIP(*aeadp);
	EVP_AEAD_CTX_free(ctx);
}

isc_result_t
isc_crypto_aead_create(isc_crypto_aead_algorithm_t algorithm,
		       isc_constregion_t key,
		       isc_crypto_aead_direction_t direction ISC_ATTR_UNUSED,
		       isc_crypto_aead_t **aeadp) {
	const EVP_AEAD *evp;
	EVP_AEAD_CTX *ctx;

	REQUIRE(aeadp != NULL && *aeadp == NULL);
	REQUIRE(key.base != NULL);

	switch (algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		evp = EVP_aead_aes_128_gcm();
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		evp = EVP_aead_aes_256_gcm();
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		evp = EVP_aead_chacha20_poly1305();
		break;
	default:
		UNREACHABLE();
	}

	/*
	 * LibreSSL's EVP_AEAD_CTX_new is *just slightly* different than the
	 * BoringSSL version.
	 */
#ifdef LIBRESSL_VERSION_NUMBER
	ctx = EVP_AEAD_CTX_new();
	if (ctx == NULL) {
		return CRYPTO_ERROR("EVP_AEAD_CTX_new");
	}

	if (EVP_AEAD_CTX_init(ctx, evp, key.base, key.length, 0, NULL) != 1) {
		EVP_AEAD_CTX_free(ctx);
		return CRYPTO_ERROR("EVP_AEAD_CTX_init");
	}
#else  /* LIBRESSL_VERSION_NUMBER */
	ctx = EVP_AEAD_CTX_new(evp, key.base, key.length, 0);
	if (ctx == NULL) {
		return CRYPTO_ERROR("EVP_AEAD_CTX_new");
	}
#endif /* LIBRESSL_VERSION_NUMBER */

	*aeadp = MOVE_OWNERSHIP(ctx);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_crypto_aead_seal(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t plaintext, isc_region_t out,
		     size_t *out_sealed_len,
		     isc_constregion_t additional_data) {
	isc_result_t result;
	size_t len = out.length;

	REQUIRE(aead != NULL);

	ERR_set_mark();

	if (EVP_AEAD_CTX_seal(aead, out.base, &len, out.length, nonce.base,
			      nonce.length, plaintext.base, plaintext.length,
			      additional_data.base,
			      additional_data.length) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	*out_sealed_len = len;

	result = ISC_R_SUCCESS;
cleanup:
	ERR_pop_to_mark();
	return result;
}

isc_result_t
isc_crypto_aead_open(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t ciphertext, isc_region_t out,
		     size_t *out_opened_len,
		     isc_constregion_t additional_data) {
	isc_result_t result;
	size_t len;

	REQUIRE(aead != NULL);

	ERR_set_mark();

	if (EVP_AEAD_CTX_open(aead, out.base, &len, out.length, nonce.base,
			      nonce.length, ciphertext.base, ciphertext.length,
			      additional_data.base,
			      additional_data.length) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	*out_opened_len = len;

	result = ISC_R_SUCCESS;
cleanup:
	ERR_pop_to_mark();
	return result;
}

#else  /* HAVE_EVP_AEAD_CTX_NEW */

void
isc_crypto_aead_destroy(isc_crypto_aead_t **aeadp) {
	EVP_CIPHER_CTX *ctx;

	REQUIRE(aeadp != NULL && *aeadp != NULL);

	ctx = MOVE_OWNERSHIP(*aeadp);

	EVP_CIPHER_CTX_free(ctx);
}

isc_result_t
isc_crypto_aead_create(isc_crypto_aead_algorithm_t algorithm,
		       isc_constregion_t key,
		       isc_crypto_aead_direction_t direction,
		       isc_crypto_aead_t **aeadp) {
	EVP_CIPHER_CTX *ctx;
	isc_result_t result;
	const EVP_CIPHER *evp;
	int dir;

	REQUIRE(aeadp != NULL && *aeadp == NULL);
	REQUIRE(key.base != NULL);

	switch (algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		evp = EVP_aes_128_gcm();
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		evp = EVP_aes_256_gcm();
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		evp = EVP_chacha20_poly1305();
		break;
	default:
		UNREACHABLE();
	}

	switch (direction) {
	case ISC_CRYPTO_AEAD_DIRECTION_SEAL:
		dir = 1;
		break;
	case ISC_CRYPTO_AEAD_DIRECTION_OPEN:
		dir = 0;
		break;
	default:
		UNREACHABLE();
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_CIPHER_CTX_new"));
	}

	if (EVP_CipherInit_ex(ctx, evp, NULL, key.base, NULL, dir) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_CipherInit_ex"));
	}

	*aeadp = MOVE_OWNERSHIP(ctx);

	result = ISC_R_SUCCESS;
cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return result;
}

isc_result_t
isc_crypto_aead_seal(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t plaintext, isc_region_t out,
		     size_t *out_sealed_len,
		     isc_constregion_t additional_data) {
	isc_result_t result;
	size_t sealed;
	int len;

	REQUIRE(aead != NULL);
	REQUIRE(nonce.base != NULL);
	REQUIRE(out.base != NULL && plaintext.base != NULL);
	REQUIRE(out.length ==
		ISC_CHECKED_ADD(plaintext.length, isc_crypto_aead_tag_length));
	REQUIRE(out_sealed_len != NULL);

	ERR_set_mark();

	if (EVP_CipherInit_ex(aead, NULL, NULL, NULL, nonce.base, 1) != 1) {
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	if (additional_data.base != NULL) {
		INSIST(additional_data.length != 0);
		if (EVP_EncryptUpdate(aead, NULL, &len, additional_data.base,
				      additional_data.length) != 1)
		{
			CLEANUP(ISC_R_CRYPTOFAILURE);
		}
	}

	len = out.length;
	if (EVP_EncryptUpdate(aead, out.base, &len, plaintext.base,
			      plaintext.length) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	sealed = len + isc_crypto_aead_tag_length;

	out.base += len;
	len = out.length - len;
	if (EVP_EncryptFinal_ex(aead, out.base, &len) != 1) {
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	if (EVP_CIPHER_CTX_ctrl(aead, EVP_CTRL_AEAD_GET_TAG,
				isc_crypto_aead_tag_length,
				out.base + len) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	*out_sealed_len = sealed;
	result = ISC_R_SUCCESS;
cleanup:
	ERR_pop_to_mark();
	return result;
}

isc_result_t
isc_crypto_aead_open(isc_crypto_aead_t *aead, isc_constregion_t nonce,
		     isc_constregion_t ciphertext, isc_region_t out,
		     size_t *out_opened_len,
		     isc_constregion_t additional_data) {
	isc_result_t result;
	const uint8_t *ct;
	size_t opened;
	int len;

	REQUIRE(aead != NULL);
	REQUIRE(nonce.base != NULL);
	REQUIRE(out.base != NULL && ciphertext.base != NULL);
	REQUIRE(out.length ==
		ISC_CHECKED_SUB(ciphertext.length, isc_crypto_aead_tag_length));
	REQUIRE(out_opened_len != NULL);

	ct = ciphertext.base;

	ERR_set_mark();

	if (EVP_CipherInit_ex(aead, NULL, NULL, NULL, nonce.base, 0) != 1) {
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	if (EVP_CIPHER_CTX_ctrl(aead, EVP_CTRL_AEAD_SET_TAG,
				isc_crypto_aead_tag_length,
				UNCONST(ct + out.length)) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	if (additional_data.base != NULL) {
		INSIST(additional_data.length != 0);
		if (EVP_DecryptUpdate(aead, NULL, &len, additional_data.base,
				      additional_data.length) != 1)
		{
			CLEANUP(ISC_R_CRYPTOFAILURE);
		}
	}

	len = out.length;
	if (EVP_DecryptUpdate(aead, out.base, &len, ciphertext.base,
			      ciphertext.length) != 1)
	{
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	opened = len;
	out.base += len;
	len = out.length - len;
	if (EVP_DecryptFinal_ex(aead, out.base, &len) != 1) {
		CLEANUP(ISC_R_CRYPTOFAILURE);
	}

	*out_opened_len = opened + len;
	result = ISC_R_SUCCESS;
cleanup:
	ERR_pop_to_mark();
	return result;
}
#endif /* HAVE_EVP_AEAD_CTX_NEW */

#ifdef HAVE_OPENSSL_HKDF_H

isc_result_t
isc_crypto_hkdf_extract(isc_region_t out, isc_md_type_t md,
			isc_constregion_t secret, isc_constregion_t salt) {
	EVP_MD *evp;
	size_t len;

	REQUIRE(out.base != NULL && out.length != 0 &&
		out.length <= EVP_MAX_MD_SIZE);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	len = out.length;
	if (HKDF_extract(out.base, &len, evp, secret.base, secret.length,
			 salt.base, salt.length) != 1)
	{
		return CRYPTO_ERROR("HKDF_extract");
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_crypto_hkdf_expand(isc_region_t out, isc_md_type_t md,
		       isc_constregion_t prk, isc_constregion_t info) {
	EVP_MD *evp;

	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(prk.base != NULL && prk.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	if (HKDF_expand(out.base, out.length, evp, prk.base, prk.length,
			info.base, info.length) != 1)
	{
		return CRYPTO_ERROR("HKDF_expand");
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_crypto_hkdf_expand_label(isc_region_t out, isc_md_type_t md,
			     isc_constregion_t secret,
			     isc_constregion_t label) {
	const uint8_t label_prefix[] = { 't', 'l', 's', '1', '3', ' ' };
	uint8_t hkdf_label[256];
	isc_buffer_t buffer;
	EVP_MD *evp;

	REQUIRE(out.base != NULL && out.length != 0 &&
		out.length <= UINT16_MAX);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(label.base != NULL && label.length != 0 && label.length <= 12);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * struct {
	 *	uint16 length = Length;
	 *	opaque label<7..255> = "tls13 " + Label;
	 *	opaque context<0..255> = Context;
	 * } HkdfLabel;
	 */
	isc_buffer_init(&buffer, hkdf_label, sizeof(hkdf_label));
	isc_buffer_putuint16(&buffer, out.length);
	isc_buffer_putuint8(&buffer, sizeof(label_prefix) + label.length);
	isc_buffer_putmem(&buffer, label_prefix, sizeof(label_prefix));
	isc_buffer_putmem(&buffer, label.base, label.length);
	isc_buffer_putuint8(&buffer, 0);

	if (HKDF_expand(out.base, out.length, evp, secret.base, secret.length,
			isc_buffer_base(&buffer),
			isc_buffer_usedlength(&buffer)) != 1)
	{
		return CRYPTO_ERROR("HKDF_expand");
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_crypto_hkdf(isc_region_t out, isc_md_type_t md, isc_constregion_t secret,
		isc_constregion_t salt, isc_constregion_t info) {
	EVP_MD *evp;

	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	if (HKDF(out.base, out.length, evp, secret.base, secret.length,
		 salt.base, salt.length, info.base, info.length) != 1)
	{
		return CRYPTO_ERROR("HKDF");
	}

	return ISC_R_SUCCESS;
}

#else /* HAVE_OPENSSL_HKDF_H */

isc_result_t
isc_crypto_hkdf_extract(isc_region_t out, isc_md_type_t md,
			isc_constregion_t secret, isc_constregion_t salt) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx;
	EVP_MD *evp;
	size_t len;

	REQUIRE(out.base != NULL && out.length != 0 &&
		out.length <= EVP_MAX_MD_SIZE);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_new_id"));
	}

	if (EVP_PKEY_derive_init(pctx) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive_init"));
	}

	if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1)
	{
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_hkdf_mode"));
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set_hkdf_md"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.base, salt.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_salt"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.base, secret.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_key"));
	}

	len = out.length;
	if (EVP_PKEY_derive(pctx, out.base, &len) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

isc_result_t
isc_crypto_hkdf_expand(isc_region_t out, isc_md_type_t md,
		       isc_constregion_t prk, isc_constregion_t info) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx;
	EVP_MD *evp;
	size_t len;

	REQUIRE(out.base != NULL && out.length != 0 &&
		out.length <= UINT16_MAX);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(prk.base != NULL && prk.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_new_id"));
	}

	if (EVP_PKEY_derive_init(pctx) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive_init"));
	}

	if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
	{
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_hkdf_mode"));
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set_hkdf_md"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk.base, prk.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_key"));
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.base, info.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_add1_hkdf_info"));
	}

	len = out.length;
	if (EVP_PKEY_derive(pctx, out.base, &len) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive"));
	}

	INSIST(len == out.length);

	result = ISC_R_SUCCESS;
cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

isc_result_t
isc_crypto_hkdf_expand_label(isc_region_t out, isc_md_type_t md,
			     isc_constregion_t secret,
			     isc_constregion_t label) {
	const uint8_t label_prefix[] = { 't', 'l', 's', '1', '3', ' ' };
	uint8_t hkdf_label[256];
	isc_buffer_t buffer;
	isc_result_t result;
	EVP_PKEY_CTX *pctx;
	EVP_MD *evp;
	size_t len;

	REQUIRE(out.base != NULL && out.length != 0 &&
		out.length <= UINT16_MAX);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(label.base != NULL && label.length != 0 && label.length <= 12);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * struct {
	 *	uint16 length = Length;
	 *	opaque label<7..255> = "tls13 " + Label;
	 *	opaque context<0..255> = Context;
	 * } HkdfLabel;
	 */
	isc_buffer_init(&buffer, hkdf_label, sizeof(hkdf_label));
	isc_buffer_putuint16(&buffer, out.length);
	isc_buffer_putuint8(&buffer, sizeof(label_prefix) + label.length);
	isc_buffer_putmem(&buffer, label_prefix, sizeof(label_prefix));
	isc_buffer_putmem(&buffer, label.base, label.length);
	isc_buffer_putuint8(&buffer, 0);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_new_id"));
	}

	if (EVP_PKEY_derive_init(pctx) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive_init"));
	}

	if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
	{
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_hkdf_mode"));
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set_hkdf_md"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.base, secret.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_key"));
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, isc_buffer_base(&buffer),
					isc_buffer_usedlength(&buffer)) != 1)
	{
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_add1_hkdf_info"));
	}

	len = out.length;
	if (EVP_PKEY_derive(pctx, out.base, &len) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive"));
	}

	INSIST(len == out.length);

	result = ISC_R_SUCCESS;
cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

isc_result_t
isc_crypto_hkdf(isc_region_t out, isc_md_type_t md, isc_constregion_t secret,
		isc_constregion_t salt, isc_constregion_t info) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx;
	EVP_MD *evp;
	size_t len;

	REQUIRE(out.base != NULL && out.length != 0);
	REQUIRE(md != ISC_MD_UNKNOWN && md < ISC_MD_MAX);
	REQUIRE(secret.base != NULL && secret.length != 0);
	REQUIRE(salt.base != NULL && salt.length != 0);
	REQUIRE(info.base != NULL && info.length != 0);

	evp = isc__crypto_md[md];
	if (evp == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_new_id"));
	}

	if (EVP_PKEY_derive_init(pctx) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive_init"));
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set_hkdf_md"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.base, salt.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_salt"));
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.base, secret.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_set1_hkdf_key"));
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.base, info.length) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_CTX_add1_hkdf_info"));
	}

	len = out.length;
	if (EVP_PKEY_derive(pctx, out.base, &len) != 1) {
		CLEANUP(CRYPTO_ERROR("EVP_PKEY_derive"));
	}

	result = ISC_R_SUCCESS;
cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

#endif /* HAVE_OPENSSL_HKDF_H */

void
isc_crypto_quic_hp_protect_destroy(isc_crypto_quic_hp_protect_t **protp) {
	isc_crypto_quic_hp_protect_t *prot;

	REQUIRE(protp != NULL && *protp != NULL &&
		(*protp)->magic == crypto_quic_hp_protect_magic);

	prot = MOVE_OWNERSHIP(*protp);

	prot->magic = 0x00;

#if !HAVE_CRYPTO_CHACHA_20
	if (prot->algorithm == ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20) {
		EVP_CIPHER_CTX_free(prot->key.chacha20);
	}
#endif /* HAVE_CRYPTO_CHACHA_20 */

	isc_safe_memwipe(&prot->key, ISC_MAX(sizeof(prot->key.aes),
					     sizeof(prot->key.chacha20)));

	isc_mem_putanddetach(&prot->mctx, prot, sizeof(*prot));
}

isc_result_t
isc_crypto_quic_hp_protect_create(
	isc_mem_t *mctx, isc_constregion_t key,
	isc_crypto_quic_hp_protect_algorithm_t algorithm,
	isc_crypto_quic_hp_protect_t **protp) {
	isc_crypto_quic_hp_protect_t *prot;
	isc_result_t result;

	REQUIRE(protp != NULL && *protp == NULL);
	REQUIRE(key.base != NULL);

	prot = isc_mem_get(mctx, sizeof(*prot));
	*prot = (isc_crypto_quic_hp_protect_t){
		.magic = crypto_quic_hp_protect_magic,
		.algorithm = algorithm,
		.mctx = isc_mem_ref(mctx),
	};

	switch (algorithm) {
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128:
		INSIST(key.length == isc_crypto_aes128gcm_key_length);
		if (AES_set_encrypt_key(key.base, 128, &prot->key.aes) != 0) {
			CLEANUP(CRYPTO_ERROR("AES_set_encrypt_key"));
		}
		break;
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES256:
		INSIST(key.length == isc_crypto_aes256gcm_key_length);
		if (AES_set_encrypt_key(key.base, 256, &prot->key.aes) != 0) {
			CLEANUP(CRYPTO_ERROR("AES_set_encrypt_key"));
		}
		break;
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20:
		INSIST(key.length == isc_crypto_chacha20poly1305_key_length);
		if (isc_crypto_fips_mode()) {
			CLEANUP(ISC_R_NOTIMPLEMENTED);
		}
#if HAVE_CRYPTO_CHACHA_20
		memmove(prot->key.chacha20, key.base,
			isc_crypto_chacha20poly1305_key_length);
#else  /* HAVE_CRYPTO_CHACHA_20 */
		prot->key.chacha20 = EVP_CIPHER_CTX_new();
		if (prot->key.chacha20 == NULL) {
			CLEANUP(CRYPTO_ERROR("EVP_CIPHER_CTX_new"));
		}

		if (EVP_EncryptInit_ex(prot->key.chacha20, EVP_chacha20(), NULL,
				       key.base, NULL) != 1)
		{
			EVP_CIPHER_CTX_free(prot->key.chacha20);
			CLEANUP(CRYPTO_ERROR("EVP_EncryptInit_ex"));
		}
#endif /* HAVE_CRYPTO_CHACHA_20 */
		break;
	default:
		UNREACHABLE();
	}

	*protp = prot;

	return ISC_R_SUCCESS;

cleanup:
	isc_mem_putanddetach(&prot->mctx, prot, sizeof(*prot));
	return result;
}

isc_result_t
isc_crypto_quic_hp_protect_mask(isc_crypto_quic_hp_protect_t *prot,
				uint8_t *out, const uint8_t *sample) {
	static const uint8_t zeros[5] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
#if HAVE_CRYPTO_CHACHA_20
	const uint8_t *nonce;
	uint64_t counter;
#else  /* HAVE_CRYPTO_CHACHA_20 */
	int len;
#endif /* HAVE_CRYPTO_CHACHA_20 */

	REQUIRE(prot != NULL && prot->magic == crypto_quic_hp_protect_magic);
	REQUIRE(out != NULL && sample != NULL);

	switch (prot->algorithm) {
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128:
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES256:
		AES_ecb_encrypt(sample, out, &prot->key.aes, 1);
		break;
	case ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20:
#if HAVE_CRYPTO_CHACHA_20
		/*
		 * `CRYPTO_chacha_20` is the IETF variant of ChaCha20 with a
		 * 32-bit counter and a 96-bit nonce in BoringSSL and its forks
		 * such as AWS-LC.
		 *
		 * However, LibreSSL implements the original paper with 64-bit
		 * counter and a 64-bit nonce. This can easily be turned into
		 * the IETF variant by reading 32-bits more to the counter from
		 * the sample and using the rest and the nonce. The ChaCha20
		 * block state will be equivalent.
		 */
#ifdef LIBRESSL_VERSION_NUMBER
		counter = ISC_U8TO64_LE(sample);
		nonce = sample + 8;
#else  /* LIBRESSL_VERSION_NUMBER */
		counter = ISC_U8TO32_LE(sample);
		nonce = sample + 4;
#endif /* LIBRESSL_VERSION_NUMBER */
		CRYPTO_chacha_20(out, zeros, sizeof(zeros), prot->key.chacha20,
				 nonce, counter);

#else  /* HAVE_CRYPTO_CHACHA_20 */
		if (EVP_EncryptInit_ex(prot->key.chacha20, NULL, NULL, NULL,
				       sample) != 1)
		{
			return CRYPTO_ERROR("EVP_EncryptInit_ex");
		}

		if (EVP_EncryptUpdate(prot->key.chacha20, out, &len, zeros,
				      sizeof(zeros)) != 1)
		{
			return CRYPTO_ERROR("EVP_EncryptUpdate");
		}

		if (EVP_EncryptFinal_ex(prot->key.chacha20, out + sizeof(zeros),
					&len) != 1)
		{
			return CRYPTO_ERROR("EVP_EncryptFinal_ex");
		}
#endif /* HAVE_CRYPTO_CHACHA_20 */
		break;
	default:
		UNREACHABLE();
	}

	return ISC_R_SUCCESS;
}

#ifdef HAVE_FIPS_MODE
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
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"FIPS_mode_set", ISC_R_CRYPTOFAILURE);
	}

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

#ifndef LIBRESSL_VERSION_NUMBER
	/*
	 * CRYPTO_set_mem_(_ex)_functions() returns 1 on success or 0 on
	 * failure, which means OpenSSL already allocated some memory.  There's
	 * nothing we can do about it.
	 */
	(void)CRYPTO_set_mem_functions(isc__crypto_malloc_ex,
				       isc__crypto_realloc_ex,
				       isc__crypto_free_ex);
#endif /* !LIBRESSL_VERSION_NUMBER */

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
	OPENSSL_cleanup();

	isc_mem_detach(&isc__crypto_mctx);
}
