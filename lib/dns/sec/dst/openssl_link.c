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
 * $Id: openssl_link.c,v 1.26 2000/06/06 21:58:11 bwelling Exp $
 */
#if defined(OPENSSL)

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <openssl/dsa.h>
#include <openssl/sha.h>

static isc_result_t openssldsa_todns(const dst_key_t *key, isc_buffer_t *data);

static isc_result_t
openssldsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	SHA_CTX *ctx;

	UNUSED(key);

	ctx = isc_mem_get(dctx->mctx, sizeof(SHA_CTX));
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);
	SHA1_Init(ctx);
	dctx->opaque = ctx;
	return (ISC_R_SUCCESS);
}

static void
openssldsa_destroyctx(dst_context_t *dctx) {
	SHA_CTX *ctx = dctx->opaque;

	if (ctx != NULL) {
		unsigned char digest[SHA_DIGEST_LENGTH];
		SHA1_Final(digest, ctx);
		isc_mem_put(dctx->mctx, ctx, sizeof(SHA_CTX));
	}
}

static isc_result_t
openssldsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	SHA_CTX *ctx = dctx->opaque;

	SHA1_Update(ctx, data->base, data->length);
	return (ISC_R_SUCCESS);
}
	
static int
BN_bn2bin_fixed(BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);
	while (bytes-- > 0)
		*buf++ = 0;
	BN_bn2bin(bn, buf);
	return (size);
}	

static isc_result_t
openssldsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_region_t r;
	dst_key_t *key;
	SHA_CTX *ctx;
	DSA *dsa;
	DSA_SIG *dsasig;
	unsigned char digest[SHA_DIGEST_LENGTH];

	isc_buffer_availableregion(sig, &r);
	if (r.length < SHA_DIGEST_LENGTH * 2 + 1)
		return (ISC_R_NOSPACE);

	ctx = dctx->opaque;
	key = dctx->key;
	dsa = key->opaque;

	SHA1_Final(digest, ctx);
	isc_mem_put(dctx->mctx, ctx, sizeof(SHA_CTX));
	dctx->opaque = NULL;

	dsasig = DSA_do_sign(digest, SHA_DIGEST_LENGTH, dsa);
	if (dsasig == NULL)
		return (DST_R_SIGNFAILURE);

	*r.base++ = (key->key_size - 512)/64;
	BN_bn2bin_fixed(dsasig->r, r.base, SHA_DIGEST_LENGTH);
	r.base += SHA_DIGEST_LENGTH;
	BN_bn2bin_fixed(dsasig->s, r.base, SHA_DIGEST_LENGTH);
	r.base += SHA_DIGEST_LENGTH;
	DSA_SIG_free(dsasig);
	isc_buffer_add(sig, SHA_DIGEST_LENGTH * 2 + 1);

	return (ISC_R_SUCCESS);
}

static isc_result_t
openssldsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	int status = 0;
	dst_key_t *key;
	SHA_CTX *ctx;
	DSA *dsa;
	DSA_SIG *dsasig;
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char *cp = sig->base;

	ctx = dctx->opaque;
	key = dctx->key;
	dsa = key->opaque;

	SHA1_Final(digest, ctx);
	isc_mem_put(dctx->mctx, ctx, sizeof(SHA_CTX));
	dctx->opaque = NULL;

	if (sig->length < 2 * SHA_DIGEST_LENGTH + 1)
		return (DST_R_VERIFYFAILURE);

	cp++;	/* Skip T */
	dsasig = DSA_SIG_new();
	dsasig->r = BN_bin2bn(cp, SHA_DIGEST_LENGTH, NULL);
	cp += SHA_DIGEST_LENGTH;
	dsasig->s = BN_bin2bn(cp, SHA_DIGEST_LENGTH, NULL);
	cp += SHA_DIGEST_LENGTH;

	status = DSA_do_verify(digest, SHA_DIGEST_LENGTH, dsasig, dsa);
	DSA_SIG_free(dsasig);
	if (status == 0)
		return (DST_R_VERIFYFAILURE);

	return (ISC_R_SUCCESS);
}

static isc_boolean_t
openssldsa_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status;
	DSA *dsa1, *dsa2;

	dsa1 = (DSA *) key1->opaque;
	dsa2 = (DSA *) key2->opaque;

	if (dsa1 == NULL && dsa2 == NULL) 
		return (ISC_TRUE);
	else if (dsa1 == NULL || dsa2 == NULL)
		return (ISC_FALSE);

	status = BN_cmp(dsa1->p, dsa2->p) ||
		 BN_cmp(dsa1->q, dsa2->q) ||
		 BN_cmp(dsa1->g, dsa2->g) ||
		 BN_cmp(dsa1->pub_key, dsa2->pub_key);

	if (status != 0)
		return (ISC_FALSE);

	if (dsa1->priv_key != NULL || dsa2->priv_key != NULL) {
		if (dsa1->priv_key == NULL || dsa2->priv_key == NULL)
			return (ISC_FALSE);
		if (BN_cmp(dsa1->priv_key, dsa2->priv_key))
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

static isc_result_t
openssldsa_generate(dst_key_t *key, int unused) {
	DSA *dsa;
	unsigned char dns_array[DST_KEY_MAXSIZE];
	unsigned char rand_array[SHA_DIGEST_LENGTH];
	isc_buffer_t dns, rand;
	isc_result_t result;
	isc_region_t r;

	UNUSED(unused);

	isc_buffer_init(&rand, rand_array, sizeof(rand_array));
	result = dst_random_get(SHA_DIGEST_LENGTH, &rand);
	if (result != ISC_R_SUCCESS)
		return (result);

	dsa = DSA_generate_parameters(key->key_size, rand_array,
				      SHA_DIGEST_LENGTH, NULL, NULL,
				      NULL, NULL);

	if (dsa == NULL)
		return (ISC_R_NOMEMORY);

	if (DSA_generate_key(dsa) == 0) {
		DSA_free(dsa);
		return (ISC_R_NOMEMORY);
	}

	key->opaque = dsa;

	isc_buffer_init(&dns, dns_array, sizeof(dns_array));
	result = openssldsa_todns(key, &dns);
	if (result != ISC_R_SUCCESS) {
		DSA_free(dsa);
		return (result);
	}
	isc_buffer_usedregion(&dns, &r);
	key->key_id = dst__id_calc(r.base, r.length);

	return (ISC_R_SUCCESS);
}

static isc_boolean_t
openssldsa_isprivate(const dst_key_t *key) {
	DSA *dsa = (DSA *) key->opaque;
        return (ISC_TF(dsa != NULL && dsa->priv_key != NULL));
}

static void
openssldsa_destroy(dst_key_t *key) {
	DSA *dsa = key->opaque;
	DSA_free(dsa);
}


static isc_result_t
openssldsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	DSA *dsa;
	isc_region_t r;
	int dnslen;
	unsigned int t, p_bytes;

	REQUIRE(key->opaque != NULL);

	dsa = (DSA *) key->opaque;

	isc_buffer_availableregion(data, &r);

	t = (BN_num_bytes(dsa->p) - 64) / 8;
	if (t > 8)
		return (DST_R_INVALIDPUBLICKEY);
	p_bytes = 64 + 8 * t;

	dnslen = 1 + (key->key_size * 3)/8 + SHA_DIGEST_LENGTH;
	if (r.length < (unsigned int) dnslen)
		return (ISC_R_NOSPACE);

	*r.base++ = t;
	BN_bn2bin_fixed(dsa->q, r.base, SHA_DIGEST_LENGTH);
	r.base += SHA_DIGEST_LENGTH;
	BN_bn2bin_fixed(dsa->p, r.base, key->key_size/8);
	r.base += p_bytes;
	BN_bn2bin_fixed(dsa->g, r.base, key->key_size/8);
	r.base += p_bytes;
	BN_bn2bin_fixed(dsa->pub_key, r.base, key->key_size/8);
	r.base += p_bytes;

	isc_buffer_add(data, dnslen);

	return (ISC_R_SUCCESS);
}

static isc_result_t
openssldsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	DSA *dsa;
	isc_region_t r;
	unsigned int t, p_bytes;
	isc_mem_t *mctx = key->mctx;

	UNUSED(mctx);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0)
		return (ISC_R_SUCCESS);

	dsa = DSA_new();
	if (dsa == NULL)
		return (ISC_R_NOMEMORY);

	t = (unsigned int) *r.base++;
	if (t > 8) {
		DSA_free(dsa);
		return (DST_R_INVALIDPUBLICKEY);
	}
	p_bytes = 64 + 8 * t;

	if (r.length < 1 + SHA_DIGEST_LENGTH + 3 * p_bytes) {
		DSA_free(dsa);
		return (DST_R_INVALIDPUBLICKEY);
	}

	dsa->q = BN_bin2bn(r.base, SHA_DIGEST_LENGTH, NULL);
	r.base += SHA_DIGEST_LENGTH;

	dsa->p = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	dsa->g = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	dsa->pub_key = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	isc_buffer_remainingregion(data, &r);
	key->key_id = dst__id_calc(r.base, 1 + SHA_DIGEST_LENGTH + 3 * p_bytes);
	key->key_size = p_bytes * 8;

	isc_buffer_forward(data, 1 + SHA_DIGEST_LENGTH + 3 * p_bytes);

	key->opaque = (void *) dsa;

	return (ISC_R_SUCCESS);
}


static isc_result_t
openssldsa_tofile(const dst_key_t *key, const char *directory) {
	int cnt = 0;
	DSA *dsa;
	dst_private_t priv;
	unsigned char bufs[5][128];

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

	dsa = (DSA *) key->opaque;

	priv.elements[cnt].tag = TAG_DSA_PRIME;
	priv.elements[cnt].length = BN_num_bytes(dsa->p);
	BN_bn2bin(dsa->p, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DSA_SUBPRIME;
	priv.elements[cnt].length = BN_num_bytes(dsa->q);
	BN_bn2bin(dsa->q, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DSA_BASE;
	priv.elements[cnt].length = BN_num_bytes(dsa->g);
	BN_bn2bin(dsa->g, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DSA_PRIVATE;
	priv.elements[cnt].length = BN_num_bytes(dsa->priv_key);
	BN_bn2bin(dsa->priv_key, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DSA_PUBLIC;
	priv.elements[cnt].length = BN_num_bytes(dsa->pub_key);
	BN_bn2bin(dsa->pub_key, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.nelements = cnt;
	return (dst__privstruct_writefile(key, &priv, directory));
}

static isc_result_t 
openssldsa_fromfile(dst_key_t *key, const isc_uint16_t id, const char *filename)
{
	dst_private_t priv;
	isc_result_t ret;
	isc_buffer_t dns;
	isc_region_t r;
	unsigned char dns_array[1024];
	int i;
	DSA *dsa = NULL;
	isc_mem_t *mctx = key->mctx;
#define DST_RET(a) {ret = a; goto err;}

	/* read private key file */
	ret = dst__privstruct_parsefile(key, id, filename, mctx, &priv);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	dsa = DSA_new();
	if (dsa == NULL)
		DST_RET(ISC_R_NOMEMORY);
	key->opaque = dsa;

	for (i=0; i < priv.nelements; i++) {
		BIGNUM *bn;
		bn = BN_bin2bn(priv.elements[i].data,
			       priv.elements[i].length, NULL);
		if (bn == NULL)
			DST_RET(ISC_R_NOMEMORY);

		switch (priv.elements[i].tag) {
			case TAG_DSA_PRIME:
				dsa->p = bn;
				break;
			case TAG_DSA_SUBPRIME:
				dsa->q = bn;
				break;
			case TAG_DSA_BASE:
				dsa->g = bn;
				break;
			case TAG_DSA_PRIVATE:
				dsa->priv_key = bn;
				break;
			case TAG_DSA_PUBLIC:
				dsa->pub_key = bn;
				break;
                }
	}
	dst__privstruct_free(&priv, mctx);

	key->key_size = BN_num_bits(dsa->p);
	isc_buffer_init(&dns, dns_array, sizeof(dns_array));
	ret = openssldsa_todns(key, &dns);
	if (ret != ISC_R_SUCCESS)
		DST_RET(ret);
	isc_buffer_usedregion(&dns, &r);
	key->key_id = dst__id_calc(r.base, r.length);

	if (key->key_id != id)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	return (ISC_R_SUCCESS);

 err:
	openssldsa_destroy(key);
	dst__privstruct_free(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

static dst_func_t openssldsa_functions = {
	openssldsa_createctx,
	openssldsa_destroyctx,
	openssldsa_adddata,
	openssldsa_sign,
	openssldsa_verify,
	NULL, /* digest */
	NULL, /* computesecret */
	openssldsa_compare,
	NULL, /* paramcompare */
	openssldsa_generate,
	openssldsa_isprivate,
	openssldsa_destroy,
	openssldsa_todns,
	openssldsa_fromdns,
	openssldsa_tofile,
	openssldsa_fromfile,
};

isc_result_t
dst__openssldsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL && *funcp == NULL);
	CRYPTO_set_mem_functions(dst__mem_alloc, dst__mem_realloc,
				 dst__mem_free);
	*funcp = &openssldsa_functions;
	return (ISC_R_SUCCESS);
}

void
dst__openssldsa_destroy(void) {
}

#endif /* OPENSSL */
