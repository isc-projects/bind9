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
 * $Id: openssl_link.c,v 1.23 2000/05/15 21:30:44 bwelling Exp $
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

static struct dst_func openssl_functions;

static isc_result_t
dst_openssl_sign(const unsigned int mode, dst_key_t *key, void **context,
		 isc_region_t *data, isc_buffer_t *sig, isc_mem_t *mctx);

static isc_result_t
dst_openssl_verify(const unsigned int mode, dst_key_t *key, void **context,
		   isc_region_t *data, isc_region_t *sig, isc_mem_t *mctx);

static isc_boolean_t
dst_openssl_compare(const dst_key_t *key1, const dst_key_t *key2);

static isc_result_t
dst_openssl_generate(dst_key_t *key, int unused, isc_mem_t *mctx);

static isc_boolean_t
dst_openssl_isprivate(const dst_key_t *key);

static void
dst_openssl_destroy(void *key, isc_mem_t *mctx);

static isc_result_t
dst_openssl_to_dns(const dst_key_t *in_key, isc_buffer_t *data);

static isc_result_t
dst_openssl_from_dns(dst_key_t *key, isc_buffer_t *data, isc_mem_t *mctx);

static isc_result_t
dst_openssl_to_file(const dst_key_t *key);

static isc_result_t
dst_openssl_from_file(dst_key_t *key, const isc_uint16_t id, isc_mem_t *mctx);

static int
BN_bn2bin_fixed(BIGNUM *bn, unsigned char *buf, int size);

/*
 * dst_s_openssldsa_init()
 * Sets up function pointers for OpenSSL related functions 
 */
void
dst_s_openssldsa_init(void) {
	REQUIRE(dst_t_func[DST_ALG_DSA] == NULL);
	dst_t_func[DST_ALG_DSA] = &openssl_functions;
	memset(&openssl_functions, 0, sizeof(struct dst_func));
	openssl_functions.sign = dst_openssl_sign;
	openssl_functions.verify = dst_openssl_verify;
	openssl_functions.computesecret = NULL;
	openssl_functions.compare = dst_openssl_compare;
	openssl_functions.paramcompare = NULL;  /* is this useful for DSA? */
	openssl_functions.generate = dst_openssl_generate;
	openssl_functions.isprivate = dst_openssl_isprivate;
	openssl_functions.destroy = dst_openssl_destroy;
	openssl_functions.to_dns = dst_openssl_to_dns;
	openssl_functions.from_dns = dst_openssl_from_dns;
	openssl_functions.to_file = dst_openssl_to_file;
	openssl_functions.from_file = dst_openssl_from_file;
	CRYPTO_set_mem_functions(dst_mem_alloc, dst_mem_realloc, dst_mem_free);
}

/*
 * dst_openssl_sign
 *	Call OpenSSL signing functions to sign a block of data.
 *	There are three steps to signing, INIT (initialize structures), 
 *	UPDATE (hash (more) data), FINAL (generate a signature).  This
 *	routine performs one or more of these steps.
 * Parameters
 *	mode		DST_SIGMODE_{INIT_UPDATE_FINAL|ALL}
 *	key		key to use for signing
 *	context		the context to use for this computation
 *	data		data to be signed
 *	signature	buffer to store signature
 *	mctx		memory context for temporary allocations
 * Returns 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssl_sign(const unsigned int mode, dst_key_t *key, void **context,
		 isc_region_t *data, isc_buffer_t *sig, isc_mem_t *mctx)
{
	isc_region_t r;
	SHA_CTX *ctx = NULL;
	
	if (mode & DST_SIGMODE_INIT) { 
		ctx = (SHA_CTX *) isc_mem_get(mctx, sizeof(SHA_CTX));
		if (ctx == NULL)
			return (ISC_R_NOMEMORY);
	}
	else if (context != NULL) 
		ctx = (SHA_CTX *) *context;
	REQUIRE (ctx != NULL);

	if (mode & DST_SIGMODE_INIT)
		SHA1_Init(ctx);

	if ((mode & DST_SIGMODE_UPDATE))
		SHA1_Update(ctx, data->base, data->length);

	if (mode & DST_SIGMODE_FINAL) {
		DSA *dsa;
		DSA_SIG *dsasig;
		unsigned char digest[SHA_DIGEST_LENGTH];

		isc_buffer_availableregion(sig, &r);
		if (r.length < SHA_DIGEST_LENGTH * 2 + 1)
			return (ISC_R_NOSPACE);

		dsa = key->opaque;

		SHA1_Final(digest, ctx);
		isc_mem_put(mctx, ctx, sizeof(SHA_CTX));

		dsasig = DSA_do_sign(digest, SHA_DIGEST_LENGTH, dsa);
		if (dsasig == NULL)
			return (DST_R_SIGNFINALFAILURE);

		*r.base++ = (key->key_size - 512)/64;
		BN_bn2bin_fixed(dsasig->r, r.base, SHA_DIGEST_LENGTH);
		r.base += SHA_DIGEST_LENGTH;
		BN_bn2bin_fixed(dsasig->s, r.base, SHA_DIGEST_LENGTH);
		r.base += SHA_DIGEST_LENGTH;
		DSA_SIG_free(dsasig);
		isc_buffer_add(sig, SHA_DIGEST_LENGTH * 2 + 1);
	}
	else
		*context = ctx;

	return (ISC_R_SUCCESS);
}


/*
 * dst_openssl_verify 
 *	Calls OpenSSL verification routines.  There are three steps to 
 *	verification, INIT (initialize structures), UPDATE (hash (more) data), 
 *	FINAL (generate a signature).  This routine performs one or more of 
 *	these steps.
 * Parameters
 *	mode		DST_SIGMODE_{INIT_UPDATE_FINAL|ALL}
 *	key		key to use for verifying
 *	context		the context to use for this computation
 *	data		signed data
 *	signature	signature
 *	mctx		memory context for temporary allocations
 * Returns 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssl_verify(const unsigned int mode, dst_key_t *key, void **context,
		   isc_region_t *data, isc_region_t *sig, isc_mem_t *mctx)
{
	int status = 0;
	SHA_CTX *ctx = NULL;
	
	if (mode & DST_SIGMODE_INIT) { 
		ctx = (SHA_CTX *) isc_mem_get(mctx, sizeof(SHA_CTX));
		if (ctx == NULL)
			return (ISC_R_NOMEMORY);
	}
	else if (context != NULL) 
		ctx = (SHA_CTX *) *context;
	REQUIRE (ctx != NULL);

	if (mode & DST_SIGMODE_INIT)
		SHA1_Init(ctx);

	if ((mode & DST_SIGMODE_UPDATE))
		SHA1_Update(ctx, data->base, data->length);

	if (mode & DST_SIGMODE_FINAL) {
		DSA *dsa;
		DSA_SIG *dsasig;
		unsigned char digest[SHA_DIGEST_LENGTH];
		unsigned char *cp = sig->base;

		dsa = key->opaque;

		SHA1_Final(digest, ctx);
		isc_mem_put(mctx, ctx, sizeof(SHA_CTX));

		if (sig->length < 2 * SHA_DIGEST_LENGTH + 1)
			return (DST_R_VERIFYFINALFAILURE);

		cp++;	/* Skip T */
		dsasig = DSA_SIG_new();
		dsasig->r = BN_bin2bn(cp, SHA_DIGEST_LENGTH, NULL);
		cp += SHA_DIGEST_LENGTH;
		dsasig->s = BN_bin2bn(cp, SHA_DIGEST_LENGTH, NULL);
		cp += SHA_DIGEST_LENGTH;

		status = DSA_do_verify(digest, SHA_DIGEST_LENGTH, dsasig, dsa);
		DSA_SIG_free(dsasig);
		if (status == 0)
			return (DST_R_VERIFYFINALFAILURE);
	}
	else
		*context = ctx;

	return (ISC_R_SUCCESS);
}


/*
 * dst_openssl_isprivate
 *	Is this a private key?
 * Parameters
 *	key		DST KEY structure
 * Returns
 *	ISC_TRUE
 *	ISC_FALSE
 */
static isc_boolean_t
dst_openssl_isprivate(const dst_key_t *key) {
	DSA *dsa = (DSA *) key->opaque;
        return (ISC_TF(dsa != NULL && dsa->priv_key != NULL));
}


/*
 * dst_openssl_to_dns
 *	Converts key from DSA to DNS distribution format
 * Parameters
 *	key		DST KEY structure
 *	data		output data
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t
dst_openssl_to_dns(const dst_key_t *key, isc_buffer_t *data) {
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


/*
 * dst_openssl_from_dns
 *	Converts from a DNS KEY RR format to a DSA KEY. 
 * Parameters
 *	key		Partially filled key structure
 *	data		Buffer containing key in DNS format
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssl_from_dns(dst_key_t *key, isc_buffer_t *data, isc_mem_t *mctx) {
	DSA *dsa;
	isc_region_t r;
	unsigned int t, p_bytes;

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
	key->key_id = dst_s_id_calc(r.base,
				    1 + SHA_DIGEST_LENGTH + 3 * p_bytes);
	key->key_size = p_bytes * 8;

	isc_buffer_forward(data, 1 + SHA_DIGEST_LENGTH + 3 * p_bytes);

	key->opaque = (void *) dsa;

	return (ISC_R_SUCCESS);
}


/*
 * dst_openssl_to_file
 *	Encodes a DSA Key into the portable file format.
 * Parameters 
 *	key		DST KEY structure 
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssl_to_file(const dst_key_t *key) {
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
	return (dst_s_write_private_key_file(key, &priv));
}


/*
 * dst_openssl_from_file
 *	Converts contents of a private key file into a private DSA key. 
 * Parameters 
 *	key		Partially filled DSA KEY structure
 *	id		The key id
 *	path		The directory that the file will be read from
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t 
dst_openssl_from_file(dst_key_t *key, const isc_uint16_t id, isc_mem_t *mctx) {
	dst_private_t priv;
	isc_result_t ret;
	isc_buffer_t dns;
	isc_region_t r;
	unsigned char dns_array[1024];
	int i;
	DSA *dsa = NULL;
#define DST_RET(a) {ret = a; goto err;}

	/* read private key file */
	ret = dst_s_parse_private_key_file(key, id, &priv, mctx);
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
	dst_s_free_private_structure_fields(&priv, mctx);

	key->key_size = BN_num_bits(dsa->p);
	isc_buffer_init(&dns, dns_array, sizeof(dns_array));
	ret = dst_openssl_to_dns(key, &dns);
	if (ret != ISC_R_SUCCESS)
		DST_RET(ret);
	isc_buffer_usedregion(&dns, &r);
	key->key_id = dst_s_id_calc(r.base, r.length);

	if (key->key_id != id)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	return (ISC_R_SUCCESS);

 err:
	key->opaque = NULL;
	dst_openssl_destroy(dsa, mctx);
	dst_s_free_private_structure_fields(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

/*
 * dst_openssl_destroy
 *	Frees all dynamically allocated structures in key.
 */
static void
dst_openssl_destroy(void *key, isc_mem_t *mctx) {
	DSA *dsa = (DSA *) key;

	UNUSED(mctx);

	if (dsa == NULL)
		return;

	DSA_free(dsa);
}


/*
 *  dst_openssl_generate
 *	Generates unique keys that are hard to predict.
 *  Parameters
 *	key		DST Key structure
 *	unused		algorithm specific data, unused for DSA.
 *	mctx		memory context to allocate key
 *  Return 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t
dst_openssl_generate(dst_key_t *key, int unused, isc_mem_t *mctx) {
	DSA *dsa;
	unsigned char dns_array[1024];
	unsigned char rand_array[SHA_DIGEST_LENGTH];
	isc_buffer_t dns, rand;
	isc_result_t ret;
	isc_region_t r;

	UNUSED(unused);
	UNUSED(mctx);

	isc_buffer_init(&rand, rand_array, sizeof(rand_array));
	ret = dst_random_get(SHA_DIGEST_LENGTH, &rand);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	dsa = DSA_generate_parameters(key->key_size, rand_array,
				      SHA_DIGEST_LENGTH, NULL, NULL,
				      NULL, NULL);

	if (dsa == NULL)
		return (ISC_R_NOMEMORY);

	if (DSA_generate_key(dsa) == 0)
		return (ISC_R_NOMEMORY);

	key->opaque = dsa;

	isc_buffer_init(&dns, dns_array, sizeof(dns_array));
	dst_openssl_to_dns(key, &dns);
	isc_buffer_usedregion(&dns, &r);
	key->key_id = dst_s_id_calc(r.base, r.length);

	return (ISC_R_SUCCESS);
}


/************************************************************************** 
 *  dst_openssl_compare
 *	Compare two keys for equality.
 *  Return
 *	ISC_TRUE	The keys are equal
 *	ISC_FALSE	The keys are not equal
 */
static isc_boolean_t
dst_openssl_compare(const dst_key_t *key1, const dst_key_t *key2) {
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

static int
BN_bn2bin_fixed(BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);
	while (bytes-- > 0)
		*buf++ = 0;
	BN_bn2bin(bn, buf);
	return (size);
}	

#endif /* OPENSSL */
