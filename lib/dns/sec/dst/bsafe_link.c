/*
 * Portions Copyright (C) 1999, 2000  Internet Software Consortium.
 * Portions Copyright (C) 1995-2000 by Network Associates, Inc.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM AND
 * NETWORK ASSOCIATES DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE CONSORTIUM OR NETWORK
 * ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: bsafe_link.c,v 1.32 2000/06/22 21:19:13 bwelling Exp $
 */

#if defined(DNSSAFE)

#include <config.h>

#include <isc/md5.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <global.h>
#include <bsafe2.h>

typedef struct dnssafekey {
	B_KEY_OBJ rk_Private_Key;
	B_KEY_OBJ rk_Public_Key;
} RSA_Key;

#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN (MAX_RSA_MODULUS_BITS/8)
#define MAX_RSA_PRIME_LEN (MAX_RSA_MODULUS_LEN/2)

#define NULL_SURRENDER (A_SURRENDER_CTX *)NULL_PTR
#define NULL_RANDOM (B_ALGORITHM_OBJ)NULL_PTR

static B_ALGORITHM_METHOD *CHOOSER[] =
{
	&AM_MD5,
	&AM_MD5_RANDOM,
	&AM_RSA_KEY_GEN,
	&AM_RSA_ENCRYPT,
	&AM_RSA_DECRYPT,
	&AM_RSA_CRT_ENCRYPT,
	&AM_RSA_CRT_DECRYPT,
	(B_ALGORITHM_METHOD *) NULL_PTR
};

static unsigned char pkcs1[] =
{
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
	0x04, 0x10
};

static isc_boolean_t dnssafersa_isprivate(const dst_key_t *key);

static isc_result_t
dnssafersa_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_md5_t *md5ctx;

	UNUSED(key);

	md5ctx = isc_mem_get(dctx->mctx, sizeof(isc_md5_t));
	isc_md5_init(md5ctx);
	dctx->opaque = md5ctx;
	return (ISC_R_SUCCESS);
}

static void
dnssafersa_destroyctx(dst_context_t *dctx) {
	isc_md5_t *md5ctx = dctx->opaque;

	if (md5ctx != NULL) {
		isc_md5_invalidate(md5ctx);
		isc_mem_put(dctx->mctx, md5ctx, sizeof(isc_md5_t));
		dctx->opaque = NULL;
	}
}

static isc_result_t
dnssafersa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_md5_t *md5ctx = dctx->opaque;

	isc_md5_update(md5ctx, data->base, data->length);
	return (ISC_R_SUCCESS);
}

static isc_result_t
dnssafersa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_md5_t *md5ctx = dctx->opaque;
	unsigned char digest[ISC_MD5_DIGESTLENGTH];
	isc_region_t sig_region;
	dst_key_t *key = dctx->key;
	RSA_Key *rkey = key->opaque;
	B_ALGORITHM_OBJ rsaEncryptor = (B_ALGORITHM_OBJ)NULL_PTR;
	unsigned int written = 0;

	isc_md5_final(md5ctx, digest);

	isc_buffer_availableregion(sig, &sig_region);
	if (sig_region.length * 8 < (unsigned int) key->key_size)
		return (ISC_R_NOSPACE);
		
	if (!dnssafersa_isprivate(key))
		return (DST_R_NOTPRIVATEKEY);

	if (B_CreateAlgorithmObject(&rsaEncryptor) != 0)
		return (ISC_R_NOMEMORY);
	if (B_SetAlgorithmInfo(rsaEncryptor, AI_PKCS_RSAPrivate, NULL_PTR)
	    != 0)
		goto finalfail;

	if (B_EncryptInit(rsaEncryptor, rkey->rk_Private_Key, CHOOSER,
			  NULL_SURRENDER) != 0)
		goto finalfail;

	written = 0;
	if (B_EncryptUpdate(rsaEncryptor, sig_region.base, &written,
			    sig_region.length, pkcs1, sizeof(pkcs1),
			    NULL_PTR, NULL_SURRENDER) != 0)
		goto finalfail;

	if (written > 0) {
		isc_buffer_add(sig, written);
		isc_buffer_availableregion(sig, &sig_region);
		written = 0;
	}

	if (B_EncryptUpdate(rsaEncryptor, sig_region.base, &written,
			    sig_region.length, digest, sizeof(digest),
			    NULL_PTR, NULL_SURRENDER) != 0)
		goto finalfail;

	if (written > 0) {
		isc_buffer_add(sig, written);
		isc_buffer_availableregion(sig, &sig_region);
		written = 0;
	}

	if (B_EncryptFinal(rsaEncryptor, sig_region.base, &written,
			   sig_region.length, NULL_PTR,
			   NULL_SURRENDER) != 0)
		goto finalfail;

	isc_buffer_add(sig, written);

	B_DestroyAlgorithmObject(&rsaEncryptor);
	return (ISC_R_SUCCESS);

 finalfail:
	B_DestroyAlgorithmObject(&rsaEncryptor);
	return (DST_R_SIGNFAILURE);
}


static isc_result_t
dnssafersa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_md5_t *md5ctx = dctx->opaque;
	unsigned char digest[ISC_MD5_DIGESTLENGTH];
	unsigned char work_area[ISC_MD5_DIGESTLENGTH + sizeof(pkcs1)];
	isc_buffer_t work;
	isc_region_t work_region;
	dst_key_t *key = dctx->key;
	RSA_Key *rkey = key->opaque;
	B_ALGORITHM_OBJ rsaEncryptor = (B_ALGORITHM_OBJ) NULL_PTR;
	unsigned int written = 0;

	isc_md5_final(md5ctx, digest);

	if (B_CreateAlgorithmObject(&rsaEncryptor) != 0)
		return (ISC_R_NOMEMORY);
	if (B_SetAlgorithmInfo(rsaEncryptor, AI_PKCS_RSAPublic, NULL_PTR) != 0)
		goto finalfail;
	if (B_DecryptInit(rsaEncryptor, rkey->rk_Public_Key,
			  CHOOSER, NULL_SURRENDER) != 0)
		goto finalfail;

	isc_buffer_init(&work, work_area, sizeof(work_area));
	isc_buffer_availableregion(&work, &work_region);
	if (B_DecryptUpdate(rsaEncryptor, work_region.base, &written,
			    work_region.length, sig->base, sig->length,
			    NULL_PTR, NULL_SURRENDER) != 0)
		goto finalfail;

	if (written > 0) {
		isc_buffer_add(&work, written);
		isc_buffer_availableregion(&work, &work_region);
		written = 0;
	}

	if (B_DecryptFinal(rsaEncryptor, work_region.base, &written,
			   work_region.length, NULL_PTR,
			   NULL_SURRENDER) != 0)
		goto finalfail;

	if (written > 0)
		isc_buffer_add(&work, written);

	B_DestroyAlgorithmObject(&rsaEncryptor);
	/*
	 * Skip PKCS#1 header in output from Decrypt function.
	 */
	if (memcmp(digest,
		   (char *)isc_buffer_base(&work) + sizeof(pkcs1),
		   sizeof(digest)) == 0)
		return (ISC_R_SUCCESS);
	else
		return (DST_R_VERIFYFAILURE);

 finalfail:
	B_DestroyAlgorithmObject(&rsaEncryptor);
	return (DST_R_VERIFYFAILURE);
}

static isc_boolean_t
itemcmp(ITEM i1, ITEM i2) {
	if (i1.len != i2.len || memcmp (i1.data, i2.data, i1.len) != 0)
		return (ISC_FALSE);
	else
		return (ISC_TRUE);
}

static isc_boolean_t
dnssafersa_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status;
	RSA_Key *rkey1, *rkey2;
	A_RSA_KEY *public1 = NULL, *public2 = NULL;
	A_PKCS_RSA_PRIVATE_KEY *p1 = NULL, *p2 = NULL;

	rkey1 = (RSA_Key *) key1->opaque;
	rkey2 = (RSA_Key *) key2->opaque;

	if (rkey1 == NULL && rkey2 == NULL) 
		return (ISC_TRUE);
	else if (rkey1 == NULL || rkey2 == NULL)
		return (ISC_FALSE);

	if (rkey1->rk_Public_Key) 
		(void)B_GetKeyInfo((POINTER *) &public1, rkey1->rk_Public_Key, 
				   KI_RSAPublic);
	if (rkey2->rk_Public_Key) 
		(void)B_GetKeyInfo((POINTER *) &public2, rkey2->rk_Public_Key, 
				   KI_RSAPublic);
	if (public1 == NULL && public2 == NULL)
		return (ISC_TRUE);
	else if (public1 == NULL || public2 == NULL)
		return (ISC_FALSE);

	status = itemcmp(public1->modulus, public2->modulus) ||
		 itemcmp(public1->exponent, public2->exponent);

	if (status == ISC_FALSE) 
		return (ISC_FALSE);

	if (rkey1->rk_Private_Key != NULL || rkey2->rk_Private_Key != NULL) {
		if (rkey1->rk_Private_Key == NULL ||
		    rkey2->rk_Private_Key == NULL)
			return (ISC_FALSE);

		(void)B_GetKeyInfo((POINTER *)&p1, rkey1->rk_Private_Key,
				   KI_PKCS_RSAPrivate);
		(void)B_GetKeyInfo((POINTER *)&p2, rkey2->rk_Private_Key,
				   KI_PKCS_RSAPrivate);
		if (p1 == NULL || p2 == NULL) 
			return (ISC_FALSE);

		status = itemcmp(p1->modulus, p2->modulus) &&
			 itemcmp(p1->publicExponent, p2->publicExponent) &&
			 itemcmp(p1->privateExponent, p2->privateExponent) &&
			 itemcmp(p1->prime[0], p2->prime[0]) &&
			 itemcmp(p1->prime[1], p2->prime[1]) &&
			 itemcmp(p1->primeExponent[0], p2->primeExponent[0]) &&
			 itemcmp(p1->primeExponent[1], p2->primeExponent[1]) &&
			 itemcmp(p1->coefficient, p2->coefficient);
		if (status == ISC_FALSE)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

static isc_result_t
dnssafersa_generate(dst_key_t *key, int exp) {
	B_KEY_OBJ private;
	B_KEY_OBJ public;
	B_ALGORITHM_OBJ keypairGenerator = NULL;
	B_ALGORITHM_OBJ randomAlgorithm = NULL;
	A_RSA_KEY_GEN_PARAMS keygenParams;
	char exponent[4];
	int exponent_len = 0;
	RSA_Key *rsa;
	unsigned char randomSeed[256];
	int entropylen;
	isc_buffer_t b;
	A_RSA_KEY *pub = NULL;
	isc_result_t ret;
	isc_mem_t *mctx;

	mctx = key->mctx;
	rsa = (RSA_Key *) isc_mem_get(mctx, sizeof(RSA_Key));
	if (rsa == NULL)
		return (ISC_R_NOMEMORY);

	memset(rsa, 0, sizeof(*rsa));
	keygenParams.publicExponent.data = NULL;

#define do_fail(code) {ret = code; goto fail;}
	if (B_CreateAlgorithmObject(&keypairGenerator) != 0)
		do_fail(ISC_R_NOMEMORY);

	keygenParams.modulusBits = key->key_size;

	/*
	 * exp = 0 or 1 are special (mean 3 or F4).
	 */
	if (exp == 0)
		exp = 3;
	else if (exp == 1)
		exp = 65537;

	/*
	 * Now encode the exponent and its length.
	 */
	if (exp < 256) {
		exponent_len = 1;
		exponent[0] = exp;
	} else if (exp < (1 << 16)) {
		exponent_len = 2;
		exponent[0] = exp >> 8;
		exponent[1] = exp;
	} else if (exp < (1 << 24)) {
		exponent_len = 3;
		exponent[0] = exp >> 16;
		exponent[1] = exp >> 8;
		exponent[2] = exp;
	} else {
		exponent_len = 4;
		exponent[0] = exp >> 24;
		exponent[1] = exp >> 16;
		exponent[2] = exp >> 8;
		exponent[3] = exp;
	}

	keygenParams.publicExponent.data =
		(unsigned char *)isc_mem_get(mctx, exponent_len);
	if (keygenParams.publicExponent.data == NULL)
		do_fail(ISC_R_NOMEMORY);

	memcpy(keygenParams.publicExponent.data, exponent, exponent_len);
	keygenParams.publicExponent.len = exponent_len;
	if (B_SetAlgorithmInfo(keypairGenerator, AI_RSAKeyGen,
			       (POINTER)&keygenParams) != 0)
		do_fail(DST_R_INVALIDPARAM);

	isc_mem_put(mctx, keygenParams.publicExponent.data, exponent_len);
	keygenParams.publicExponent.data = NULL;

	if (B_GenerateInit(keypairGenerator, CHOOSER, NULL_SURRENDER) != 0)
		do_fail(ISC_R_NOMEMORY);

	if (B_CreateKeyObject(&public) != 0)
		do_fail(ISC_R_NOMEMORY);

	if (B_CreateKeyObject(&private) != 0)
		do_fail(ISC_R_NOMEMORY);

	if (B_CreateAlgorithmObject(&randomAlgorithm) != 0)
		do_fail(ISC_R_NOMEMORY);

	if (B_SetAlgorithmInfo(randomAlgorithm, AI_MD5Random,
					 NULL_PTR) != 0)
		do_fail(ISC_R_NOMEMORY);

	if (B_RandomInit(randomAlgorithm, CHOOSER, NULL_SURRENDER) != 0)
		do_fail(ISC_R_NOMEMORY);

	entropylen = ISC_MIN(sizeof(randomSeed), 2 * key->key_size / 8);
	ret = dst__entropy_getdata(randomSeed, entropylen, ISC_FALSE);
	if (ret != ISC_R_SUCCESS)
		goto fail;

	if (B_RandomUpdate(randomAlgorithm, randomSeed, entropylen,
			   NULL_SURRENDER) != 0)
		do_fail(ISC_R_NOMEMORY);

	memset(randomSeed, 0, sizeof(randomSeed));

	if (B_GenerateKeypair(keypairGenerator, public, private,
			      randomAlgorithm, NULL_SURRENDER) != 0)
		do_fail(DST_R_INVALIDPARAM);

	rsa->rk_Private_Key = private;
	rsa->rk_Public_Key = public;
	key->opaque = (void *) rsa;

	B_DestroyAlgorithmObject(&keypairGenerator);
	B_DestroyAlgorithmObject(&randomAlgorithm);

	/*
	 * Fill in the footprint in generate key.
	 */
	(void)B_GetKeyInfo((POINTER *)&pub, public, KI_RSAPublic);

	isc_buffer_init(&b, pub->modulus.data + pub->modulus.len - 3, 2);
	isc_buffer_add(&b, 2);
	key->key_id = isc_buffer_getuint16(&b);
	return (ISC_R_SUCCESS);

 fail:
	if (rsa != NULL) {
		memset(rsa, 0, sizeof(*rsa));
		isc_mem_put(mctx, rsa, sizeof(*rsa));
	}
	if (keygenParams.publicExponent.data != NULL) {
		memset(keygenParams.publicExponent.data, 0, exponent_len);
		isc_mem_put(mctx, keygenParams.publicExponent.data,
			    exponent_len);
	}
	if (keypairGenerator != NULL)
		B_DestroyAlgorithmObject(&keypairGenerator);
	if (randomAlgorithm != NULL)
		B_DestroyAlgorithmObject(&randomAlgorithm);
	if (public != NULL)
		B_DestroyKeyObject(&public);
	if (private != NULL)
		B_DestroyKeyObject(&private);
	return (ret);
}

static isc_boolean_t
dnssafersa_isprivate(const dst_key_t *key) {
	RSA_Key *rkey = (RSA_Key *) key->opaque;
	return (ISC_TF(rkey != NULL && rkey->rk_Private_Key != NULL));
}

static void
dnssafersa_destroy(dst_key_t *key) {
	isc_mem_t *mctx;
	RSA_Key *rkey;

	mctx = key->mctx;
	rkey = key->opaque;
	if (rkey->rk_Private_Key != NULL)
		B_DestroyKeyObject(&rkey->rk_Private_Key);
	if (rkey->rk_Public_Key != NULL)
		B_DestroyKeyObject(&rkey->rk_Public_Key);
	memset(rkey, 0, sizeof(*rkey));
	isc_mem_put(mctx, rkey, sizeof(*rkey));
}

static isc_result_t
dnssafersa_todns(const dst_key_t *key, isc_buffer_t *data) {
	B_KEY_OBJ public;
	A_RSA_KEY *pub = NULL;
	isc_region_t r;

	REQUIRE(key->opaque != NULL);

	public = (B_KEY_OBJ)((RSA_Key *)key->opaque)->rk_Public_Key;

	if (B_GetKeyInfo((POINTER *)&pub, public, KI_RSAPublic) != 0)
		return (DST_R_INVALIDPUBLICKEY);
	isc_buffer_availableregion(data, &r);
	if (pub->exponent.len < 256) {  /* key exponent is <= 2040 bits */
		if (r.length < 1 + pub->exponent.len + pub->modulus.len)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint8(data, (isc_uint8_t)pub->exponent.len);
	} else {			/*  key exponent is > 2040 bits */
		if (r.length < 3 + pub->exponent.len + pub->modulus.len)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint8(data, 0);
		isc_buffer_putuint16(data, (isc_uint16_t)pub->exponent.len);
	}

	isc_buffer_availableregion(data, &r);
	memcpy(r.base, pub->exponent.data, pub->exponent.len);
	r.base += pub->exponent.len;
	memcpy(r.base, pub->modulus.data, pub->modulus.len);
	isc_buffer_add(data, pub->exponent.len + pub->modulus.len);

	return (ISC_R_SUCCESS);
}

static int
dnssafersa_keysize(RSA_Key *key) {
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;

	REQUIRE(key != NULL);
	REQUIRE(key->rk_Private_Key != NULL || key->rk_Public_Key != NULL);

	if (key->rk_Private_Key != NULL)
		(void)B_GetKeyInfo((POINTER *)&private, key->rk_Private_Key,
				   KI_PKCS_RSAPrivate);
	else
		(void)B_GetKeyInfo((POINTER *)&private, key->rk_Public_Key,
				   KI_RSAPublic);

	return (private->modulus.len * 8);
}

static isc_result_t
dnssafersa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	unsigned int bytes;
	RSA_Key *rkey;
	A_RSA_KEY *public;
	isc_region_t r;
	isc_buffer_t b;
	isc_mem_t *mctx;

	mctx = key->mctx;
	isc_buffer_remainingregion(data, &r);
	if (r.length == 0)
		return (ISC_R_SUCCESS);

	rkey = (RSA_Key *) isc_mem_get(mctx, sizeof(RSA_Key));
	if (rkey == NULL)
		return (ISC_R_NOMEMORY);

	memset(rkey, 0, sizeof(RSA_Key));

	if (B_CreateKeyObject(&rkey->rk_Public_Key) != 0) {
		isc_mem_put(mctx, rkey, sizeof(RSA_Key));
		return (ISC_R_NOMEMORY);
	}

	/*
	 * Length of exponent in bytes.
	 */
	bytes = isc_buffer_getuint8(data);
	if (bytes == 0)  /* special case for long exponents */
		bytes = isc_buffer_getuint16(data);

	if (bytes > MAX_RSA_MODULUS_LEN) { 
		dnssafersa_destroy(key);
		return (DST_R_INVALIDPUBLICKEY);
	}

	public = (A_RSA_KEY *) isc_mem_get(mctx, sizeof(A_RSA_KEY));
	if (public == NULL)
		return (ISC_R_NOMEMORY);
	memset(public, 0, sizeof(*public));
	public->exponent.len = bytes;
	public->exponent.data = (unsigned char *) isc_mem_get(mctx, bytes);
	if (public->exponent.data == NULL) {
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}

	isc_buffer_remainingregion(data, &r);
	if (r.length < bytes) {
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	memcpy(public->exponent.data, r.base, bytes);
	isc_buffer_forward(data, bytes);

	isc_buffer_remainingregion(data, &r);

	if (r.length > MAX_RSA_MODULUS_LEN) { 
		dnssafersa_destroy(key);
		memset(public->exponent.data, 0, bytes);
		isc_mem_put(mctx, public->exponent.data, bytes);
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	public->modulus.len = r.length;
	public->modulus.data = (unsigned char *) isc_mem_get(mctx, r.length);
	if (public->modulus.data == NULL) {
		dnssafersa_destroy(key);
		memset(public->exponent.data, 0, bytes);
		isc_mem_put(mctx, public->exponent.data, bytes);
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	memcpy(public->modulus.data, r.base, r.length);
	isc_buffer_forward(data, r.length);

	if (B_SetKeyInfo(rkey->rk_Public_Key, KI_RSAPublic, (POINTER)public)
	    != 0)
		return (DST_R_INVALIDPUBLICKEY);

	isc_buffer_init(&b, public->modulus.data + public->modulus.len - 3, 2);
	isc_buffer_add(&b, 2);
	key->key_id = isc_buffer_getuint16(&b);
	key->key_size = dnssafersa_keysize(rkey);

	memset(public->exponent.data, 0, public->exponent.len);
	isc_mem_put(mctx, public->exponent.data, public->exponent.len);
	memset(public->modulus.data, 0, public->modulus.len);
	isc_mem_put(mctx, public->modulus.data, public->modulus.len);
	isc_mem_put(mctx, public, sizeof(*public));

	key->opaque = (void *) rkey;

	return (ISC_R_SUCCESS);
}

static isc_result_t
dnssafersa_tofile(const dst_key_t *key, const char *directory) {
	int cnt = 0;
	B_KEY_OBJ rkey;
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;
	dst_private_t priv;

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

	rkey = (B_KEY_OBJ)((RSA_Key *)key->opaque)->rk_Private_Key;

	(void)B_GetKeyInfo((POINTER *)&private, rkey, KI_PKCS_RSAPrivate);

	priv.elements[cnt].tag = TAG_RSA_MODULUS;
	priv.elements[cnt].data = private->modulus.data;
	priv.elements[cnt++].length = private->modulus.len;

	priv.elements[cnt].tag = TAG_RSA_PUBLICEXPONENT;
	priv.elements[cnt].data = private->publicExponent.data;
	priv.elements[cnt++].length = private->publicExponent.len;

	priv.elements[cnt].tag = TAG_RSA_PRIVATEEXPONENT;
	priv.elements[cnt].data = private->privateExponent.data;
	priv.elements[cnt++].length = private->privateExponent.len;

	priv.elements[cnt].tag = TAG_RSA_PRIME1;
	priv.elements[cnt].data = private->prime[0].data;
	priv.elements[cnt++].length = private->prime[0].len;

	priv.elements[cnt].tag = TAG_RSA_PRIME2;
	priv.elements[cnt].data = private->prime[1].data;
	priv.elements[cnt++].length = private->prime[1].len;

	priv.elements[cnt].tag = TAG_RSA_EXPONENT1;
	priv.elements[cnt].data = private->primeExponent[0].data;
	priv.elements[cnt++].length = private->primeExponent[0].len;

	priv.elements[cnt].tag = TAG_RSA_EXPONENT2;
	priv.elements[cnt].data = private->primeExponent[1].data;
	priv.elements[cnt++].length = private->primeExponent[1].len;

	priv.elements[cnt].tag = TAG_RSA_COEFFICIENT;
	priv.elements[cnt].data = private->coefficient.data;
	priv.elements[cnt++].length = private->coefficient.len;

	priv.nelements = cnt;
	return (dst__privstruct_writefile(key, &priv, directory));
}

static isc_result_t 
dnssafersa_fromfile(dst_key_t *key, const isc_uint16_t id,
		    const char *filename) {
	dst_private_t priv;
	isc_result_t ret;
	isc_buffer_t b;
	int i;
	RSA_Key *rkey = NULL;
	A_RSA_KEY *public = NULL;
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;
	isc_mem_t *mctx;

#define DST_RET(a) {ret = a; goto err;}

	mctx = key->mctx;
	/*
	 * Read private key file.
	 */
	ret = dst__privstruct_parsefile(key, id, filename, mctx, &priv);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	/*
	 * Allocate key.
	 */
	private = (A_PKCS_RSA_PRIVATE_KEY *)
		isc_mem_get(mctx, sizeof(A_PKCS_RSA_PRIVATE_KEY));
	if (private == NULL)
		DST_RET(ISC_R_NOMEMORY);
	memset(private, 0, sizeof(*private));

	public = (A_RSA_KEY *) isc_mem_get(mctx, sizeof(A_RSA_KEY));
	if (public == NULL) 
		DST_RET(ISC_R_NOMEMORY);
	memset(public, 0, sizeof(*public));

	for (i=0; i < priv.nelements; i++) {
		int len = priv.elements[i].length;
		unsigned char *data = priv.elements[i].data;

		switch (priv.elements[i].tag){
			case TAG_RSA_MODULUS:
				public->modulus.len = len;
				private->modulus.len = len;
				public->modulus.data = data;
				private->modulus.data = data;
				break;
			case TAG_RSA_PUBLICEXPONENT:
				public->exponent.len = len;
				private->publicExponent.len = len;
				public->exponent.data = data;
				private->publicExponent.data = data;
				break;
			case TAG_RSA_PRIVATEEXPONENT:
				private->privateExponent.len = len;
				private->privateExponent.data = data;
				break;
			case TAG_RSA_PRIME1:
				private->prime[0].len = len;
				private->prime[0].data = data;
				break;
			case TAG_RSA_PRIME2:
				private->prime[1].len = len;
				private->prime[1].data = data;
				break;
			case TAG_RSA_EXPONENT1:
				private->primeExponent[0].len = len;
				private->primeExponent[0].data = data;
				break;
			case TAG_RSA_EXPONENT2:
				private->primeExponent[1].len = len;
				private->primeExponent[1].data = data;
				break;
			case TAG_RSA_COEFFICIENT:
				private->coefficient.len = len;
				private->coefficient.data = data;
				break;
		}
	}

	isc_buffer_init(&b, public->modulus.data + public->modulus.len - 3, 2);
	isc_buffer_add(&b, 2);
	key->key_id = isc_buffer_getuint16(&b);
	if (key->key_id != id)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	rkey = (RSA_Key *) isc_mem_get(mctx, sizeof(RSA_Key));
	if (rkey == NULL) 
		DST_RET(ISC_R_NOMEMORY);
	memset(rkey, 0, sizeof(*rkey));
	if (B_CreateKeyObject(&(rkey->rk_Public_Key)) != 0)
		DST_RET(ISC_R_NOMEMORY);
	if (B_SetKeyInfo(rkey->rk_Public_Key, KI_RSAPublic, (POINTER)public)
	    != 0)
		DST_RET(DST_R_INVALIDPUBLICKEY);

	if (B_CreateKeyObject(&rkey->rk_Private_Key) != 0)
		DST_RET(ISC_R_NOMEMORY);

	if (B_SetKeyInfo(rkey->rk_Private_Key, KI_PKCS_RSAPrivate,
			 (POINTER)private) != 0)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	key->key_size = dnssafersa_keysize(rkey);
	key->opaque = rkey;
	rkey = NULL;
 err:
	if (private != NULL) {
		memset(private, 0, sizeof(*private));
		isc_mem_put(mctx, private, sizeof(*private));
	}
	if (public != NULL) {
		memset(public, 0, sizeof(*public));
		isc_mem_put(mctx, public, sizeof(*public));
	}
	if (rkey != NULL) {
		memset(rkey, 0, sizeof(*rkey));
		isc_mem_put(mctx, rkey, sizeof(*rkey));
	}
	dst__privstruct_free(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

static dst_func_t dnssafersa_functions = {
	dnssafersa_createctx,
	dnssafersa_destroyctx,
	dnssafersa_adddata,
	dnssafersa_sign,
	dnssafersa_verify,
	NULL, /* computesecret */
	dnssafersa_compare,
	NULL, /* paramcompare */
	dnssafersa_generate,
	dnssafersa_isprivate,
	dnssafersa_destroy,
	dnssafersa_todns,
	dnssafersa_fromdns,
	dnssafersa_tofile,
	dnssafersa_fromfile,
};

isc_result_t
dst__dnssafersa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL && *funcp == NULL);
	*funcp = &dnssafersa_functions;
	return (ISC_R_SUCCESS);
}

void
dst__dnssafersa_destroy(void) {
}

/* 
 * define memory functions for dnssafe that use the isc_mem functions and a
 * static context.
 */
void
T_free(POINTER block) {
	dst__mem_free(block);
}

POINTER
T_malloc(unsigned int len) {
	return (dst__mem_alloc(len));
}

int
T_memcmp(POINTER firstBlock, POINTER secondBlock, unsigned int len) {
	return (memcmp(firstBlock, secondBlock, len));
}

void
T_memcpy(POINTER output, POINTER input, unsigned int len) {
	memcpy(output, input, len);
}

void
T_memmove(POINTER output, POINTER input, unsigned int len) {
	memmove(output, input, len);
}

void
T_memset(POINTER output, int value, unsigned int len) {
	memset(output, value, len);
}

POINTER
T_realloc(POINTER block, unsigned int len) {
	return (dst__mem_realloc(block, len));
}
#endif /* DNSSAFE */
