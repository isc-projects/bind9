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

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
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
#include <isc/safe.h>
#include <isc/util.h>

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
