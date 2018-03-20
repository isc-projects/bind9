/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include "config.h"

#include <isc/assertions.h>
#include <isc/hmac.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/sha1.h>
#include <isc/sha2.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#ifdef PKCS11CRYPTO
#include <pk11/internal.h>
#include <pk11/pk11.h>
#endif

static size_t
isc_hmac_digestlength(isc_hmac_algo_t algo) {
	switch (algo) {
	case ISC_HMAC_ALGO_MD5: return 64;
	case ISC_HMAC_ALGO_SHA1: return ISC_SHA1_BLOCK_LENGTH;
	case ISC_HMAC_ALGO_SHA224: return ISC_SHA224_BLOCK_LENGTH;
	case ISC_HMAC_ALGO_SHA256: return ISC_SHA256_BLOCK_LENGTH;
	case ISC_HMAC_ALGO_SHA384: return ISC_SHA384_BLOCK_LENGTH;
	case ISC_HMAC_ALGO_SHA512: return ISC_SHA512_BLOCK_LENGTH;
	default:
		REQUIRE(0);
	}
}	

#define isc_hmac_blocklength(algo) isc_hmac_digestlength(algo)

#ifdef OPENSSL

static const EVP_MD *
isc_hmac_evp_md(isc_hmac_algo_t algo) {
	switch (algo) {
	case ISC_HMAC_ALGO_MD5: return EVP_md5(); break;
	case ISC_HMAC_ALGO_SHA1: return EVP_sha1(); break;
	case ISC_HMAC_ALGO_SHA224: return EVP_sha224(); break;
	case ISC_HMAC_ALGO_SHA256: return EVP_sha256(); break;
	case ISC_HMAC_ALGO_SHA384: return EVP_sha384(); break;
	case ISC_HMAC_ALGO_SHA512: return EVP_sha512(); break;
	default:
		REQUIRE(0);
	}
}

void
isc_hmac_init_openssl(isc_hmac_t *ctx, const unsigned char *key, unsigned int len, isc_hmac_algo_t algo) {
	ctx->ctx = HMAC_CTX_new();
	RUNTIME_CHECK(ctx->ctx != NULL);
	RUNTIME_CHECK(HMAC_Init_ex(ctx->ctx, (const void *)key, (int)len,
				   isc_hmac_evp_md(algo), NULL) == 1);
}

void
isc_hmac_invalidate_openssl(isc_hmac_t *ctx, isc_hmac_algo_t algo)
{
	UNUSED(algo);
	if (ctx->ctx == NULL) {
		return;
	}
	HMAC_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

void
isc_hmac_update_openssl(isc_hmac_t *ctx, const unsigned char *buf, unsigned int len,
		isc_hmac_algo_t algo)
{
	UNUSED(algo);
	if (len == 0) {
		return;
	}
	RUNTIME_CHECK(HMAC_Update(ctx->ctx, buf, (int)len) == 1);
}


void
isc_hmac_sign_openssl(isc_hmac_t *ctx, unsigned char *digest, size_t len, isc_hmac_algo_t algo)
{
	size_t digestlen = isc_hmac_digestlength(algo);
	REQUIRE(len <= digestlen);

	unsigned char newdigest[digestlen];

	RUNTIME_CHECK(HMAC_Final(ctx->ctx, newdigest, NULL));
	isc_hmac_invalidate_openssl(ctx, algo);
	memcpy(digest, newdigest, len);
	isc_safe_memwipe(newdigest, sizeof(newdigest));
}

isc_boolean_t
isc_hmac_verify_openssl(isc_hmac_t *ctx, unsigned char *digest, size_t len, isc_hmac_algo_t algo) {
	size_t digestlen = isc_hmac_digestlength(algo);
	unsigned char newdigest[digestlen];

	REQUIRE(len <= digestlen);
	isc_hmac_sign_openssl(ctx, newdigest, digestlen, algo);
	return (isc_safe_memequal(digest, newdigest, len));
}

#elif PKCS11CRYPTO

static CK_BBOOL truevalue = TRUE;
static CK_BBOOL falsevalue = FALSE;

static CK_MECHANISM_TYPE
isc_hmac_mechanism_type_pkcs11(isc_hmac_algo_t aglo)
{
	switch (algo) {
	case ISC_HMAC_ALGO_MD5: return CKM_MD5_HMAC;
	case ISC_HMAC_ALGO_SHA1: return CKM_SHA_1_HMAC;
	case ISC_HMAC_ALGO_SHA224: return CKM_SHA_224_HMAC;
	case ISC_HMAC_ALGO_SHA256: return CKM_SHA_256_HMAC;
	case ISC_HMAC_ALGO_SHA384: return CKM_SHA_384_HMAC;
	case ISC_HMAC_ALGO_SHA512: return CKM_SHA_512_HMAC;
	default:
		REQUIRE(0);
	}
}

static CK_KEY_TYPE
isc_hmac_key_type_pkcs11(isc_hmac_algo_t algo)
{
	switch (algo) {
	case ISC_HMAC_ALGO_MD5: return CKK_MD5_HMAC;
	case ISC_HMAC_ALGO_SHA1: return CKK_SHA_1_HMAC;
	case ISC_HMAC_ALGO_SHA224: return CKK_SHA_224_HMAC;
	case ISC_HMAC_ALGO_SHA256: return CKK_SHA_256_HMAC;
	case ISC_HMAC_ALGO_SHA384: return CKK_SHA_384_HMAC;
	case ISC_HMAC_ALGO_SHA512: return CKK_SHA_512_HMAC;
	default:
		REQUIRE(0);
	}
}

void
isc_hmac_init_pkcs11(isc_hmac_t *ctx, const unsigned char *key,
	      unsigned int len, isc_hmac_algo_t algo)
{
	CK_RV rv;
	CK_MECHANISM mech = { isc_hmac_mechanism_type_pkcs11(algo), NULL, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = isc_hmac_key_type_pkcs11(algo);
	CK_ATTRIBUTE keyTemplate[] =
	{
		{ CKA_CLASS, &keyClass, (CK_ULONG) sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, (CK_ULONG) sizeof(keyType) },
		{ CKA_TOKEN, &falsevalue, (CK_ULONG) sizeof(falsevalue) },
		{ CKA_PRIVATE, &falsevalue, (CK_ULONG) sizeof(falsevalue) },
		{ CKA_SIGN, &truevalue, (CK_ULONG) sizeof(truevalue) },
		{ CKA_VALUE, NULL, (CK_ULONG) len }
	};
#ifdef PK11_PAD_HMAC_KEYS
	size_t digestlen = isc_hmac_digestlength(algo);
	CK_BYTE keypad[digestlen];

	if (len < digestlen) {
		memset(keypad, 0, digestlen);
		memcpy(keypad, key, len);
		keyTemplate[5].pValue = keypad;
		keyTemplate[5].ulValueLen = digestlen;
	} else {
		DE_CONST(key, keyTemplate[5].pValue);
	}
#else
	DE_CONST(key, keyTemplate[5].pValue);
#endif
	RUNTIME_CHECK(pk11_get_session(ctx, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	ctx->object = CK_INVALID_HANDLE;
	PK11_FATALCHECK(pkcs_C_CreateObject,
			(ctx->session, keyTemplate,
			 (CK_ULONG) 6, &ctx->object));
	INSIST(ctx->object != CK_INVALID_HANDLE);
	PK11_FATALCHECK(pkcs_C_SignInit, (ctx->session, &mech, ctx->object));
}

void
isc_hmac_invalidate_pkcs11(isc_hmac_t *ctx, isc_hmac_algo_t algo) {
	digestlen = isc_hmac_digestlength(algo)
	CK_BYTE garbage[digestlen];
	CK_ULONG len = digestlen;

	if (ctx->handle == NULL) {
		return;
	}
	(void) pkcs_C_SignFinal(ctx->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	if (ctx->object != CK_INVALID_HANDLE) {
		(void) pkcs_C_DestroyObject(ctx->session, ctx->object);
	}
	ctx->object = CK_INVALID_HANDLE;
	pk11_return_session(ctx);
}

void
isc_hmac_update_pkcs11(isc_hmac_t *ctx, const unsigned char *buf,
		    unsigned int len, isc_hmac_algo_t algo)
{
	CK_RV rv;
	CK_BYTE_PTR pPart;

	UNUSED(algo);
	
	DE_CONST(buf, pPart);
	PK11_FATALCHECK(pkcs_C_SignUpdate,
			(ctx->session, pPart, (CK_ULONG) len));
}

void
isc_hmac_sign_pkcs11(isc_hmacsha1_t *ctx, unsigned char *digest, size_t len, isc_hmac_algo_t algo) {
	CK_RV rv;
	size_t digestlen = isc_hmac_digestlength(algo);
	CK_BYTE newdigest[digestlen];
	CK_ULONG psl = digestlen;

	REQUIRE(len <= digestlen);

	PK11_FATALCHECK(pkcs_C_SignFinal, (ctx->session, newdigest, &psl));
	if (ctx->object != CK_INVALID_HANDLE)
		(void) pkcs_C_DestroyObject(ctx->session, ctx->object);
	ctx->object = CK_INVALID_HANDLE;
	pk11_return_session(ctx);
	memmove(digest, newdigest, len);
	isc_safe_memwipe(newdigest, sizeof(newdigest));
}

isc_boolean_t
isc_hmac_verify_pkcs11(isc_hmac_t *ctx, unsigned char *digest, size_t len, isc_hmac_algo_t algo) {
	size_t digestlen = isc_hmac_digestlength(algo);
	unsigned char newdigest[digestlen];

	REQUIRE(len <= digestlen);
	isc_hmac_sign_pkcs11(ctx, newdigest, digestlen, algo);
	return (isc_safe_memequal(digest, newdigest, len));
}

#define PADLEN 64
#define IPAD 0x36
#define OPAD 0x5C

static CK_MECHANISM_TYPE
isc_hmac_mechanism_type_pkcs11_replace(isc_hmac_algo_t aglo)
{
	switch (algo) {
	case ISC_HMAC_ALGO_MD5: return CKM_MD5;
	case ISC_HMAC_ALGO_SHA1: return CKM_SHA_1;
	case ISC_HMAC_ALGO_SHA224: return CKM_SHA_224;
	case ISC_HMAC_ALGO_SHA256: return CKM_SHA_256;
	case ISC_HMAC_ALGO_SHA384: return CKM_SHA_384;
	case ISC_HMAC_ALGO_SHA512: return CKM_SHA_512;
	default:
		REQUIRE(0);
	}
}

void
isc_hmac_init_pkcs11_replace(isc_hmacsha1_t *ctx, const unsigned char *key,
	      unsigned int len, isc_hmac_algo_t algo)
{
	CK_RV rv;
	CK_MECHANISM mech = { isc_hmac_mechanism_type_pkcs11_replace(algo), NULL, 0 };
	size_t blocklen = isc_hmac_blocklength(algo);
	unsigned char ipad[digestlen];
	unsigned int i;

	RUNTIME_CHECK(pk11_get_session(ctx, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	RUNTIME_CHECK((ctx->key = pk11_mem_get(blocklen)) != NULL);
	if (len > blocklen) {
		CK_BYTE_PTR kPart;
		CK_ULONG kl;

		PK11_FATALCHECK(pkcs_C_DigestInit, (ctx->session, &mech));
		DE_CONST(key, kPart);
		PK11_FATALCHECK(pkcs_C_DigestUpdate,
				(ctx->session, kPart, (CK_ULONG) len));
		kl = blocklen;
		PK11_FATALCHECK(pkcs_C_DigestFinal,
				(ctx->session, (CK_BYTE_PTR) ctx->key, &kl));
	} else {
		memcpy(ctx->key, key, len);
	}
	PK11_FATALCHECK(pkcs_C_DigestInit, (ctx->session, &mech));
	memset(ipad, IPAD, blocklen);
	for (i = 0; i < blocklen; i++) {
		ipad[i] ^= ctx->key[i];
	}
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(ctx->session, ipad,
			 (CK_ULONG) blocklen));
}

void
isc_hmac_invalidate_pkcs11_replace(isc_hmac_t *ctx, isc_hmac_algo_t algo) {
	size_t blocklen = isc_hmac_blocklength(algo);
	CK_BYTE garbage[blocklen];
	CK_ULONG len = blocklen;

	if (ctx->key != NULL) {
		pk11_mem_put(ctx->key, blocklen);
		ctx->key = NULL;
	}

	if (ctx->handle == NULL) {
		return;
	}
	(void) pkcs_C_DigestFinal(ctx->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	pk11_return_session(ctx);
}

void
isc_hmac_update_pkcs11_replace(isc_hmac_t *ctx, const unsigned char *buf,
			       unsigned int len, isc_hmac_algo_t algo)
{
	CK_RV rv;
	CK_BYTE_PTR pPart;

	DE_CONST(buf, pPart);
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(ctx->session, pPart, (CK_ULONG) len));
}

void
isc_hmacs_sign_pkcs11_replace(isc_hmacsha1_t *ctx, unsigned char *digest,
			      size_t len, isc_hmac_algo_t algo)
{
	CK_RV rv;
	size_t digestlen = isc_hmac_digestlength(algo);
	size_t blocklen = isc_hmac_blocklength(algo);
	CK_BYTE newdigest[digestlen];
	CK_ULONG psl = digestlen;
	CK_MECHANISM mech = { isc_hmac_mech_type(algo), NULL, 0 };
	CK_BYTE opad[blocklen];
	unsigned int i;

	REQUIRE(len <= digestlen);

	PK11_FATALCHECK(pkcs_C_DigestFinal, (ctx->session, newdigest, &psl));
	memset(opad, OPAD, blocklen);
	for (i = 0; i < blocklen; i++) {
		opad[i] ^= ctx->key[i];
	}
	pk11_mem_put(ctx->key, blocklen);
	ctx->key = NULL;
	PK11_FATALCHECK(pkcs_C_DigestInit, (ctx->session, &mech));
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(ctx->session, opad,
			 (CK_ULONG) blocklen));
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(ctx->session, (CK_BYTE_PTR) newdigest, psl));
	PK11_FATALCHECK(pkcs_C_DigestFinal, (ctx->session, newdigest, &psl));
	pk11_return_session(ctx);
	memmove(digest, newdigest, len);
	isc_safe_memwipe(newdigest, sizeof(newdigest));
}

isc_boolean_t
isc_hmac_verify_pkcs11_replace(isc_hmac_t *ctx, unsigned char *digest, size_t len, isc_hmac_algo_t algo) {
	size_t digestlen = isc_hmac_digestlength(algo);
	unsigned char newdigest[digestlen];

	REQUIRE(len <= digestlen);
	isc_hmac_sign_pkcs11_replace(ctx, newdigest, digestlen, algo);
	return (isc_safe_memequal(digest, newdigest, len));
}


#endif /* OPENSSL || PKCS11CRYPTO */

