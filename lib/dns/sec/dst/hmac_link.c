/*
 * Portions Copyright (c) 1995-1998 by Network Associates, Inc.
 * Portions Copyright (C) 1999, 2000  Internet Software Consortium.
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
 * $Id: hmac_link.c,v 1.29 2000/06/02 18:57:45 bwelling Exp $
 */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <openssl/md5.h>

#define HMAC_LEN	64
#define HMAC_IPAD	0x36
#define HMAC_OPAD	0x5c

#define RETERR(x) do { \
	ret = (x); \
	if (ret != ISC_R_SUCCESS) \
		return (ret); \
	} while (0)

static isc_result_t hmacmd5_fromdns(dst_key_t *key, isc_buffer_t *data);

typedef struct hmackey {
	unsigned char ipad[64], opad[64];
} HMAC_Key;

static isc_result_t
hmacmd5_createctx(dst_key_t *key, dst_context_t *dctx) {
	dst_context_t *md5ctx = NULL;
	HMAC_Key *hkey = key->opaque;
	isc_region_t r;
	isc_result_t result;

	result = dst_context_create(DST_KEY_MD5, dctx->mctx, &md5ctx);
	if (result != ISC_R_SUCCESS)
		return (result);
	r.base = hkey->ipad;
	r.length = HMAC_LEN;
	result = dst_context_adddata(md5ctx, &r);
	if (result != ISC_R_SUCCESS) {
		dst_context_destroy(&md5ctx);
		return (result);
	}
	dctx->opaque = md5ctx;
	return (ISC_R_SUCCESS);
}

static void
hmacmd5_destroyctx(dst_context_t *dctx) {
	dst_context_t *md5ctx = dctx->opaque;

	if (md5ctx != NULL)
		dst_context_destroy(&md5ctx);
}

static isc_result_t
hmacmd5_adddata(dst_context_t *dctx, const isc_region_t *data) {
	dst_context_t *md5ctx = dctx->opaque;

	return (dst_context_adddata(md5ctx, data));
}

static isc_result_t
hmacmd5_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	dst_context_t *md5ctx = dctx->opaque;
	dst_key_t *key = dctx->key;
	HMAC_Key *hkey = key->opaque;
	isc_region_t r;
	isc_result_t result;
	unsigned char digest[MD5_DIGEST_LENGTH];
	isc_buffer_t b;

	isc_buffer_init(&b, digest, sizeof(digest));

	result = dst_context_digest(md5ctx, &b);
	if (result != ISC_R_SUCCESS)
		return (result);
	dst_context_destroy(&md5ctx);
	dctx->opaque = NULL;

	result = dst_context_create(DST_KEY_MD5, dctx->mctx, &md5ctx);
	if (result != ISC_R_SUCCESS)
		return (result);
	dctx->opaque = md5ctx;

	r.base = hkey->opad;
	r.length = HMAC_LEN;
	result = dst_context_adddata(md5ctx, &r);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_buffer_usedregion(&b, &r);
	result = dst_context_adddata(md5ctx, &r);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dst_context_digest(md5ctx, sig);
	return (result);
}

static isc_result_t
hmacmd5_verify(dst_context_t *dctx, const isc_region_t *sig) {
	dst_context_t *md5ctx = dctx->opaque;
	dst_key_t *key = dctx->key;
	HMAC_Key *hkey = key->opaque;
	isc_region_t r;
	isc_result_t result;
	unsigned char digest[MD5_DIGEST_LENGTH];
	isc_buffer_t b;

	isc_buffer_init(&b, digest, sizeof(digest));

	result = dst_context_digest(md5ctx, &b);
	if (result != ISC_R_SUCCESS)
		return (result);
	dst_context_destroy(&md5ctx);
	dctx->opaque = NULL;

	result = dst_context_create(DST_KEY_MD5, dctx->mctx, &md5ctx);
	if (result != ISC_R_SUCCESS)
		return (result);
	dctx->opaque = md5ctx;

	r.base = hkey->opad;
	r.length = HMAC_LEN;
	result = dst_context_adddata(md5ctx, &r);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_buffer_usedregion(&b, &r);
	result = dst_context_adddata(md5ctx, &r);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_buffer_clear(&b);
	result = dst_context_digest(md5ctx, &b);
	if (result != ISC_R_SUCCESS)
		return (result);

	if (memcmp(digest, sig->base, MD5_DIGEST_LENGTH) != 0)
		return (DST_R_VERIFYFAILURE);

	return (ISC_R_SUCCESS);
}

static isc_boolean_t
hmacmd5_compare(const dst_key_t *key1, const dst_key_t *key2) {
	HMAC_Key *hkey1, *hkey2;

	hkey1 = (HMAC_Key *)key1->opaque;
	hkey2 = (HMAC_Key *)key2->opaque;

	if (hkey1 == NULL && hkey2 == NULL) 
		return (ISC_TRUE);
	else if (hkey1 == NULL || hkey2 == NULL)
		return (ISC_FALSE);

	if (memcmp(hkey1->ipad, hkey2->ipad, HMAC_LEN) == 0)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

static isc_result_t
hmacmd5_generate(dst_key_t *key, int unused) {
	isc_buffer_t b;
	isc_result_t ret;
	int bytes;
	unsigned char data[HMAC_LEN];

	UNUSED(unused);

	bytes = (key->key_size + 7) / 8;
	if (bytes > 64) {
		bytes = 64;
		key->key_size = 512;
	}

	memset(data, 0, HMAC_LEN);
	isc_buffer_init(&b, data, sizeof(data));
	ret = dst_random_get(bytes, &b);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	ret = hmacmd5_fromdns(key, &b);
	memset(data, 0, HMAC_LEN);

	return (ret);
}

static isc_boolean_t
hmacmd5_isprivate(const dst_key_t *key) {
	UNUSED(key);
        return (ISC_TRUE);
}

static void
hmacmd5_destroy(dst_key_t *key) {
	HMAC_Key *hkey = key->opaque;
	memset(hkey, 0, sizeof(HMAC_Key));
	isc_mem_put(key->mctx, hkey, sizeof(HMAC_Key));
}

static isc_result_t
hmacmd5_todns(const dst_key_t *key, isc_buffer_t *data) {
	HMAC_Key *hkey;
	isc_region_t r;
	unsigned int bytes, i;

	REQUIRE(key->opaque != NULL);

	hkey = (HMAC_Key *) key->opaque;

	isc_buffer_availableregion(data, &r);

	bytes = (key->key_size + 7) / 8;
	if (r.length < bytes)
		return (ISC_R_NOSPACE);

	for (i = 0; i < bytes; i++)
		*r.base++ = hkey->ipad[i] ^ HMAC_IPAD;

	isc_buffer_add(data, bytes);

	return (ISC_R_SUCCESS);
}

static isc_result_t
hmacmd5_fromdns(dst_key_t *key, isc_buffer_t *data) {
	HMAC_Key *hkey;
	isc_region_t r;
	isc_mem_t *mctx = key->mctx;
	int i, keylen;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0)
		return (ISC_R_SUCCESS);

	hkey = (HMAC_Key *) isc_mem_get(mctx, sizeof(HMAC_Key));
	if (hkey == NULL)
		return (ISC_R_NOMEMORY);

	memset(hkey->ipad, 0, sizeof(hkey->ipad));
	memset(hkey->opad, 0, sizeof(hkey->opad));

	if (r.length > HMAC_LEN) {
		MD5_CTX ctx;
		unsigned char digest[MD5_DIGEST_LENGTH];

		MD5_Init(&ctx);
		MD5_Update(&ctx, r.base, r.length);
		MD5_Final(digest, &ctx);
		memcpy(hkey->ipad, digest, MD5_DIGEST_LENGTH);
		memcpy(hkey->opad, digest, MD5_DIGEST_LENGTH);
		keylen = MD5_DIGEST_LENGTH;
	}
	else {
		memcpy(hkey->ipad, r.base, r.length);
		memcpy(hkey->opad, r.base, r.length);
		keylen = r.length;
	}
	
	/*
	 * XOR key with ipad and opad values.
	 */
	for (i = 0; i < HMAC_LEN; i++) {
		hkey->ipad[i] ^= HMAC_IPAD;
		hkey->opad[i] ^= HMAC_OPAD;
	}
	key->key_id = dst_s_id_calc(r.base, r.length);
	key->key_size = keylen * 8;
	key->opaque = hkey;

	return (ISC_R_SUCCESS);
}

static isc_result_t
hmacmd5_tofile(const dst_key_t *key) {
	int i, cnt = 0;
	HMAC_Key *hkey;
	dst_private_t priv;
	unsigned char keydata[HMAC_LEN];
	int bytes = (key->key_size + 7) / 8;

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

	hkey = (HMAC_Key *) key->opaque;
	memset(keydata, 0, HMAC_LEN);
	for (i = 0; i < bytes; i++)
		keydata[i] = hkey->ipad[i] ^ HMAC_IPAD;

	priv.elements[cnt].tag = TAG_HMACMD5_KEY;
	priv.elements[cnt].length = bytes;
	priv.elements[cnt++].data = keydata;

	priv.nelements = cnt;
	return (dst_s_write_private_key_file(key, &priv));
}

static isc_result_t 
hmacmd5_fromfile(dst_key_t *key, const isc_uint16_t id) {
	dst_private_t priv;
	isc_result_t ret;
	isc_buffer_t b;
	isc_mem_t *mctx = key->mctx;

	/* read private key file */
	ret = dst_s_parse_private_key_file(key, id, &priv, mctx);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	isc_buffer_init(&b, priv.elements[0].data, priv.elements[0].length);
	isc_buffer_add(&b, priv.elements[0].length);
	dst_s_free_private_structure_fields(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (hmacmd5_fromdns(key, &b));
}

static struct dst_func hmacmd5_functions = {
	hmacmd5_createctx,
	hmacmd5_destroyctx,
	hmacmd5_adddata,
	hmacmd5_sign,
	hmacmd5_verify,
	NULL, /* digest */
	NULL, /* computesecret */
	hmacmd5_compare,
	NULL, /* paramcompare */
	hmacmd5_generate,
	hmacmd5_isprivate,
	hmacmd5_destroy,
	hmacmd5_todns,
	hmacmd5_fromdns,
	hmacmd5_tofile,
	hmacmd5_fromfile,
};

void
dst_s_hmacmd5_init(struct dst_func **funcp) {
	REQUIRE(funcp != NULL && *funcp == NULL);
	*funcp = &hmacmd5_functions;
}


