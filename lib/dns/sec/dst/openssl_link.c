/*
 * Portions Copyright (C) 1999-2001  Internet Software Consortium.
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
 * $Id: openssl_link.c,v 1.39.4.2 2001/04/10 01:10:25 gson Exp $
 */
#if defined(OPENSSL)

#include <config.h>

#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/mutexblock.h>
#include <isc/sha1.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <openssl/dsa.h>
#include <openssl/rand.h>

static RAND_METHOD *rm = NULL;
static isc_mutex_t locks[CRYPTO_NUM_LOCKS];

static isc_result_t openssldsa_todns(const dst_key_t *key, isc_buffer_t *data);

static isc_result_t
openssldsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_sha1_t *sha1ctx;

	UNUSED(key);

	sha1ctx = isc_mem_get(dctx->mctx, sizeof(isc_sha1_t));
	isc_sha1_init(sha1ctx);
	dctx->opaque = sha1ctx;
	return (ISC_R_SUCCESS);
}

static void
openssldsa_destroyctx(dst_context_t *dctx) {
	isc_sha1_t *sha1ctx = dctx->opaque;

	if (sha1ctx != NULL) {
		isc_sha1_invalidate(sha1ctx);
		isc_mem_put(dctx->mctx, sha1ctx, sizeof(isc_sha1_t));
		dctx->opaque = NULL;
	}
}

static isc_result_t
openssldsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_sha1_t *sha1ctx = dctx->opaque;

	isc_sha1_update(sha1ctx, data->base, data->length);
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
	isc_sha1_t *sha1ctx = dctx->opaque;
	dst_key_t *key = dctx->key;
	DSA *dsa = key->opaque;
	DSA_SIG *dsasig;
	isc_region_t r;
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];

	isc_buffer_availableregion(sig, &r);
	if (r.length < ISC_SHA1_DIGESTLENGTH * 2 + 1)
		return (ISC_R_NOSPACE);

	isc_sha1_final(sha1ctx, digest);

	dsasig = DSA_do_sign(digest, ISC_SHA1_DIGESTLENGTH, dsa);
	if (dsasig == NULL)
		return (DST_R_SIGNFAILURE);

	*r.base++ = (key->key_size - 512)/64;
	BN_bn2bin_fixed(dsasig->r, r.base, ISC_SHA1_DIGESTLENGTH);
	r.base += ISC_SHA1_DIGESTLENGTH;
	BN_bn2bin_fixed(dsasig->s, r.base, ISC_SHA1_DIGESTLENGTH);
	r.base += ISC_SHA1_DIGESTLENGTH;
	DSA_SIG_free(dsasig);
	isc_buffer_add(sig, ISC_SHA1_DIGESTLENGTH * 2 + 1);

	return (ISC_R_SUCCESS);
}

static isc_result_t
openssldsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_sha1_t *sha1ctx = dctx->opaque;
	dst_key_t *key = dctx->key;
	DSA *dsa = key->opaque;
	DSA_SIG *dsasig;
	int status = 0;
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];
	unsigned char *cp = sig->base;

	isc_sha1_final(sha1ctx, digest);

	if (sig->length < 2 * ISC_SHA1_DIGESTLENGTH + 1)
		return (DST_R_VERIFYFAILURE);

	cp++;	/* Skip T */
	dsasig = DSA_SIG_new();
	dsasig->r = BN_bin2bn(cp, ISC_SHA1_DIGESTLENGTH, NULL);
	cp += ISC_SHA1_DIGESTLENGTH;
	dsasig->s = BN_bin2bn(cp, ISC_SHA1_DIGESTLENGTH, NULL);
	cp += ISC_SHA1_DIGESTLENGTH;

	status = DSA_do_verify(digest, ISC_SHA1_DIGESTLENGTH, dsasig, dsa);
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
	unsigned char rand_array[ISC_SHA1_DIGESTLENGTH];
	isc_result_t result;

	UNUSED(unused);

	result = dst__entropy_getdata(rand_array, sizeof(rand_array),
				      ISC_FALSE);
	if (result != ISC_R_SUCCESS)
		return (result);

	dsa = DSA_generate_parameters(key->key_size, rand_array,
				      ISC_SHA1_DIGESTLENGTH, NULL, NULL,
				      NULL, NULL);

	if (dsa == NULL)
		return (DST_R_OPENSSLFAILURE);

	if (DSA_generate_key(dsa) == 0) {
		DSA_free(dsa);
		return (DST_R_OPENSSLFAILURE);
	}
	dsa->flags &= ~DSA_FLAG_CACHE_MONT_P;

	key->opaque = dsa;

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
	key->opaque = NULL;
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

	dnslen = 1 + (key->key_size * 3)/8 + ISC_SHA1_DIGESTLENGTH;
	if (r.length < (unsigned int) dnslen)
		return (ISC_R_NOSPACE);

	*r.base++ = t;
	BN_bn2bin_fixed(dsa->q, r.base, ISC_SHA1_DIGESTLENGTH);
	r.base += ISC_SHA1_DIGESTLENGTH;
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
	dsa->flags &= ~DSA_FLAG_CACHE_MONT_P;

	t = (unsigned int) *r.base++;
	if (t > 8) {
		DSA_free(dsa);
		return (DST_R_INVALIDPUBLICKEY);
	}
	p_bytes = 64 + 8 * t;

	if (r.length < 1 + ISC_SHA1_DIGESTLENGTH + 3 * p_bytes) {
		DSA_free(dsa);
		return (DST_R_INVALIDPUBLICKEY);
	}

	dsa->q = BN_bin2bn(r.base, ISC_SHA1_DIGESTLENGTH, NULL);
	r.base += ISC_SHA1_DIGESTLENGTH;

	dsa->p = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	dsa->g = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	dsa->pub_key = BN_bin2bn(r.base, p_bytes, NULL);
	r.base += p_bytes;

	key->key_size = p_bytes * 8;

	isc_buffer_forward(data, 1 + ISC_SHA1_DIGESTLENGTH + 3 * p_bytes);

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
	dsa->flags &= ~DSA_FLAG_CACHE_MONT_P;
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
	*funcp = &openssldsa_functions;
	return (ISC_R_SUCCESS);
}

void
dst__openssldsa_destroy(void) {
}

static int
entropy_get(unsigned char *buf, int num) {
	isc_result_t result;
	if (num < 0)
		return (-1);
	result = dst__entropy_getdata(buf, (unsigned int) num, ISC_FALSE);
	return (result == ISC_R_SUCCESS ? num : -1);
}

static int
entropy_getpseudo(unsigned char *buf, int num) {
	isc_result_t result;
	if (num < 0)
		return (-1);
	result = dst__entropy_getdata(buf, (unsigned int) num, ISC_TRUE);
	return (result == ISC_R_SUCCESS ? num : -1);
}

static void
entropy_add(const void *buf, int num, double entropy) {
	/*
	 * Do nothing.  The only call to this provides no useful data anyway.
	 */
	UNUSED(buf);
	UNUSED(num);
	UNUSED(entropy);
}

static void
lock_callback(int mode, int type, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	if ((mode & CRYPTO_LOCK) != 0)
		LOCK(&locks[type]);
	else
		UNLOCK(&locks[type]);
}

static unsigned long
id_callback(void) {
	return ((unsigned long)isc_thread_self());
}

isc_result_t
dst__openssl_init(void) {
	isc_result_t result;

	CRYPTO_set_mem_functions(dst__mem_alloc, dst__mem_realloc,
				 dst__mem_free);
	result = isc_mutexblock_init(locks, CRYPTO_NUM_LOCKS);
	if (result != ISC_R_SUCCESS)
		return (result);
	CRYPTO_set_locking_callback(lock_callback);
	CRYPTO_set_id_callback(id_callback);
	rm = dst__mem_alloc(sizeof(RAND_METHOD));
	if (rm == NULL)
		return (ISC_R_NOMEMORY);
	rm->seed = NULL;
	rm->bytes = entropy_get;
	rm->cleanup = NULL;
	rm->add = entropy_add;
	rm->pseudorand = entropy_getpseudo;
	rm->status = NULL;
	RAND_set_rand_method(rm);
	return (ISC_R_SUCCESS);
}

void
dst__openssl_destroy(void) {
	RUNTIME_CHECK(isc_mutexblock_destroy(locks, CRYPTO_NUM_LOCKS) ==
		      ISC_R_SUCCESS);
	dst__mem_free(rm);
}

#endif /* OPENSSL */
