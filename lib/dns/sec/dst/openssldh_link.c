#if defined(OPENSSL)

/*
 * Portions Copyright (c) 1995-1998 by Network Associates, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND NETWORK ASSOCIATES
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * NETWORK ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: openssldh_link.c,v 1.8 2000/03/07 19:27:50 bwelling Exp $
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/int.h>
#include <isc/region.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

#define PRIME768 "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

#define PRIME1024 "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

static struct dst_func openssldh_functions;

static isc_result_t	dst_openssldh_computesecret(const dst_key_t *pub,
						    const dst_key_t *priv,
						    isc_buffer_t *secret);
static isc_boolean_t	dst_openssldh_compare(const dst_key_t *key1,
					      const dst_key_t *key2);
static isc_boolean_t	dst_openssldh_paramcompare(const dst_key_t *key1,
						   const dst_key_t *key2);
static isc_result_t	dst_openssldh_generate(dst_key_t *key, int generator,
					       isc_mem_t *mctx);
static isc_boolean_t	dst_openssldh_isprivate(const dst_key_t *key);
static void		dst_openssldh_destroy(void *key, isc_mem_t *mctx);
static isc_result_t	dst_openssldh_to_dns(const dst_key_t *in_key,
					     isc_buffer_t *data);
static isc_result_t	dst_openssldh_from_dns(dst_key_t *key,
					       isc_buffer_t *data,
					       isc_mem_t *mctx);
static isc_result_t	dst_openssldh_to_file(const dst_key_t *key);
static isc_result_t	dst_openssldh_from_file(dst_key_t *key,
						const isc_uint16_t id,
						isc_mem_t *mctx);

static void		uint16_toregion(isc_uint16_t val, isc_region_t *region);
static isc_uint16_t	uint16_fromregion(isc_region_t *region);
static void		BN_fromhex(BIGNUM *b, const char *str);

static BIGNUM bn2, bn768, bn1024;

/*
 * dst_s_openssldh_init()
 * Sets up function pointers for OpenSSL related functions 
 */
void
dst_s_openssldh_init()
{
	REQUIRE(dst_t_func[DST_ALG_DH] == NULL);
	dst_t_func[DST_ALG_DH] = &openssldh_functions;
	memset(&openssldh_functions, 0, sizeof(struct dst_func));
	openssldh_functions.sign = NULL;
	openssldh_functions.verify = NULL;
	openssldh_functions.computesecret = dst_openssldh_computesecret;
	openssldh_functions.compare = dst_openssldh_compare;
	openssldh_functions.paramcompare = dst_openssldh_paramcompare;
	openssldh_functions.generate = dst_openssldh_generate;
	openssldh_functions.isprivate = dst_openssldh_isprivate;
	openssldh_functions.destroy = dst_openssldh_destroy;
	openssldh_functions.to_dns = dst_openssldh_to_dns;
	openssldh_functions.from_dns = dst_openssldh_from_dns;
	openssldh_functions.to_file = dst_openssldh_to_file;
	openssldh_functions.from_file = dst_openssldh_from_file;
	CRYPTO_set_mem_functions(dst_mem_alloc, dst_mem_realloc, dst_mem_free);

	BN_init(&bn2);
	BN_init(&bn768);
	BN_init(&bn1024);
	BN_set_word(&bn2, 2);
	BN_fromhex(&bn768, PRIME768);
	BN_fromhex(&bn1024, PRIME1024);
}

/*
 * dst_openssldh_computesecret
 *	Compute a shared secret from this public and private key
 * Parameters
 *	pub		The public key
 *	priv		The private key
 *	secret		A buffer into which the secret is written
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssldh_computesecret(const dst_key_t *pub, const dst_key_t *priv,
			    isc_buffer_t *secret)
{
	DH *dhpub, *dhpriv;
	int ret;
	isc_region_t r;
	unsigned int len;

	REQUIRE(pub->opaque != NULL);
	REQUIRE(priv->opaque != NULL);

	dhpub = (DH *) pub->opaque;
	dhpriv = (DH *) priv->opaque;

	len = DH_size(dhpriv);
	isc_buffer_available(secret, &r);
	if (r.length < len)
		return (ISC_R_NOSPACE);
	ret = DH_compute_key(r.base, dhpub->pub_key, dhpriv);
	if (ret == 0)
		return (DST_R_COMPUTESECRETFAILURE);
	isc_buffer_add(secret, len);
	return (ISC_R_SUCCESS);
}

/*
 * dst_openssldh_isprivate
 *	Is this a private key?
 * Parameters
 *	key		DST KEY structure
 * Returns
 *	ISC_TRUE
 *	ISC_FALSE
 */
static isc_boolean_t
dst_openssldh_isprivate(const dst_key_t *key) {
	DH *dh = (DH *) key->opaque;
        return (ISC_TF(dh != NULL && dh->priv_key != NULL));
}


/*
 * dst_openssldh_to_dns
 *	Converts key from DH to DNS distribution format
 * Parameters
 *	key		DST KEY structure
 *	data		output data
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t
dst_openssldh_to_dns(const dst_key_t *key, isc_buffer_t *data) {
	DH *dh;
	isc_region_t r;
	isc_uint16_t dnslen, plen, glen, publen;

	REQUIRE(key->opaque != NULL);

	dh = (DH *) key->opaque;

	isc_buffer_available(data, &r);

	if (dh->g == &bn2 && (dh->p == &bn768 || dh->p == &bn1024)) {
		plen = 1;
		glen = 0;
	}
	else {
		plen = BN_num_bytes(dh->p);
		glen = BN_num_bytes(dh->g);
	}
	publen = BN_num_bytes(dh->pub_key);
	dnslen = plen + glen + publen + 6;
	if (r.length < (unsigned int) dnslen)
		return (ISC_R_NOSPACE);

	uint16_toregion(plen, &r);
	if (plen == 1) {
		if (dh->p == &bn768)
			*r.base = 1;
		else
			*r.base = 2;
	}
	else
		BN_bn2bin(dh->p, r.base);
	r.base += plen;

	uint16_toregion(glen, &r);
	if (glen > 0)
		BN_bn2bin(dh->g, r.base);
	r.base += glen;

	uint16_toregion(publen, &r);
	BN_bn2bin(dh->pub_key, r.base);
	r.base += publen;

	isc_buffer_add(data, dnslen);

	return (ISC_R_SUCCESS);
}


/*
 * dst_openssldh_from_dns
 *	Converts from a DNS KEY RR format to a DH KEY. 
 * Parameters
 *	key		Partially filled key structure
 *	data		Buffer containing key in DNS format
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssldh_from_dns(dst_key_t *key, isc_buffer_t *data, isc_mem_t *mctx) {
	DH *dh;
	isc_region_t r;
	isc_uint16_t plen, glen, publen;
	int special = 0;

	mctx = mctx;	/* make the compiler happy */

	isc_buffer_remaining(data, &r);
	if (r.length == 0)
		return (ISC_R_SUCCESS);

	dh = DH_new();
	if (dh == NULL)
		return (ISC_R_NOMEMORY);

	/*
	 * Read the prime length.  1 & 2 are table entries, > 16 means a
	 * prime follows, otherwise an error.
	 */
	if (r.length < 2) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	plen = uint16_fromregion(&r);
	if (plen < 16 && plen != 1 && plen != 2) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	if (r.length < plen) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	if (plen == 1 || plen == 2) {
		if (plen == 1)
			special = *r.base++;
		else
			special = uint16_fromregion(&r);
		switch (special) {
			case 1:
				dh->p = &bn768;
				break;
			case 2:
				dh->p = &bn1024;
				break;
			default:
				DH_free(dh);
				return (DST_R_INVALIDPUBLICKEY);
		}
	}
	else {
		dh->p = BN_bin2bn(r.base, plen, NULL);
		r.base += plen;
	}

	/*
	 * Read the generator length.  This should be 0 if the prime was
	 * special, but it might not be.  If it's 0 and the prime is not
	 * special, we have a problem.
	 */
	if (r.length < 2) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	glen = uint16_fromregion(&r);
	if (r.length < glen) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	if (special != 0) {
		if (glen == 0)
			dh->g = &bn2;
		else {
			dh->g = BN_bin2bn(r.base, glen, NULL);
			if (BN_cmp(dh->g, &bn2) == 0) {
				BN_free(dh->g);
				dh->g = &bn2;
			}
			else {
				DH_free(dh);
				return (DST_R_INVALIDPUBLICKEY);
			}
		}
	}
	else {
		if (glen == 0) {
			DH_free(dh);
			return (DST_R_INVALIDPUBLICKEY);
		}
		dh->g = BN_bin2bn(r.base, glen, NULL);
	}
	r.base += glen;

	if (r.length < 2) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	publen = uint16_fromregion(&r);
	if (r.length < publen) {
		DH_free(dh);
		return (DST_R_INVALIDPUBLICKEY);
	}
	dh->pub_key = BN_bin2bn(r.base, publen, NULL);
	r.base += publen;

	isc_buffer_remaining(data, &r);
	key->key_id = dst_s_id_calc(r.base, plen + glen + publen + 6);
	key->key_size = BN_num_bits(dh->p);

	isc_buffer_forward(data, plen + glen + publen + 6);

	key->opaque = (void *) dh;

	return (ISC_R_SUCCESS);
}


/*
 * dst_openssldh_to_file
 *	Encodes a DH Key into the portable file format.
 * Parameters 
 *	key		DST KEY structure 
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static isc_result_t
dst_openssldh_to_file(const dst_key_t *key) {
	int cnt = 0;
	DH *dh;
	dst_private_t priv;
	unsigned char bufs[4][128];

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

	dh = (DH *) key->opaque;

	priv.elements[cnt].tag = TAG_DH_PRIME;
	priv.elements[cnt].length = BN_num_bytes(dh->p);
	BN_bn2bin(dh->p, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DH_GENERATOR;
	priv.elements[cnt].length = BN_num_bytes(dh->g);
	BN_bn2bin(dh->g, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DH_PRIVATE;
	priv.elements[cnt].length = BN_num_bytes(dh->priv_key);
	BN_bn2bin(dh->priv_key, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.elements[cnt].tag = TAG_DH_PUBLIC;
	priv.elements[cnt].length = BN_num_bytes(dh->pub_key);
	BN_bn2bin(dh->pub_key, bufs[cnt]);
	priv.elements[cnt].data = bufs[cnt];
	cnt++;

	priv.nelements = cnt;
	return (dst_s_write_private_key_file(key->key_name, key->key_alg,
					     key->key_id, &priv));
}


/*
 * dst_openssldh_from_file
 *	Converts contents of a private key file into a private DH key. 
 * Parameters 
 *	key		Partially filled DH KEY structure
 *	id		The key id
 *	path		The directory that the file will be read from
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t 
dst_openssldh_from_file(dst_key_t *key, const isc_uint16_t id, isc_mem_t *mctx) {
	dst_private_t priv;
	isc_result_t ret;
	isc_buffer_t dns;
	isc_region_t r;
	unsigned char dns_array[1024];
	int i;
	DH *dh = NULL;
#define DST_RET(a) {ret = a; goto err;}

	/* read private key file */
	ret = dst_s_parse_private_key_file(key->key_name, key->key_alg, 
					   id, &priv, mctx);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	dh = DH_new();
	if (dh == NULL)
		DST_RET(ISC_R_NOMEMORY);
	key->opaque = dh;

	for (i=0; i < priv.nelements; i++) {
		BIGNUM *bn;
		bn = BN_bin2bn(priv.elements[i].data,
			       priv.elements[i].length, NULL);
		if (bn == NULL)
			DST_RET(ISC_R_NOMEMORY);

		switch (priv.elements[i].tag) {
			case TAG_DH_PRIME:
				dh->p = bn;
				break;
			case TAG_DH_GENERATOR:
				dh->g = bn;
				break;
			case TAG_DH_PRIVATE:
				dh->priv_key = bn;
				break;
			case TAG_DH_PUBLIC:
				dh->pub_key = bn;
				break;
                }
	}
	dst_s_free_private_structure_fields(&priv, mctx);

	key->key_size = BN_num_bits(dh->p);

	if ((key->key_size == 768 || key->key_size == 1024) &&
	    BN_cmp(dh->g, &bn2) == 0)
	{
		if (key->key_size == 768 && BN_cmp(dh->p, &bn768) == 0) {
			BN_free(dh->p);
			BN_free(dh->g);
			dh->p = &bn768;
			dh->g = &bn2;
		}
		else if (key->key_size == 1024 && BN_cmp(dh->p, &bn1024) == 0) {
			BN_free(dh->p);
			BN_free(dh->g);
			dh->p = &bn1024;
			dh->g = &bn2;
		}
	}
	isc_buffer_init(&dns, dns_array, sizeof(dns_array),
			ISC_BUFFERTYPE_BINARY);
	ret = dst_openssldh_to_dns(key, &dns);
	if (ret != ISC_R_SUCCESS)
		DST_RET(ret);
	isc_buffer_used(&dns, &r);
	key->key_id = dst_s_id_calc(r.base, r.length);

	if (key->key_id != id)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	return (ISC_R_SUCCESS);

 err:
	key->opaque = NULL;
	dst_openssldh_destroy(dh, mctx);
	dst_s_free_private_structure_fields(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

/*
 * dst_openssldh_destroy
 *	Frees all dynamically allocated structures in key.
 */
static void
dst_openssldh_destroy(void *key, isc_mem_t *mctx) {
	DH *dh = (DH *) key;
	if (dh == NULL)
		return;

	mctx = mctx;	/* make the compiler happy */

	if (dh->p == &bn768 || dh->p == &bn1024)
		dh->p = NULL;
	if (dh->g == &bn2)
		dh->g = NULL;
	DH_free(dh);
}


/*
 *  dst_openssldh_generate
 *	Generates unique keys that are hard to predict.
 *  Parameters
 *	key		DST Key structure
 *	generator	generator
 *	mctx		memory context to allocate key
 *  Return 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static isc_result_t
dst_openssldh_generate(dst_key_t *key, int generator, isc_mem_t *mctx) {
	DH *dh = NULL;
	unsigned char dns_array[1024];
	isc_buffer_t dns;
	isc_region_t r;

	mctx = mctx;		/* make the compiler happy */

	if (generator == 0) {
		if (key->key_size == 768 || key->key_size == 1024) {
			dh = DH_new();
			if (dh == NULL)
				return (ISC_R_NOMEMORY);
			if (key->key_size == 768)
				dh->p = &bn768;
			else
				dh->p = &bn1024;
			dh->g = &bn2;
		}
		else
			generator = 2;
	}

	if (generator != 0)
		dh = DH_generate_parameters(key->key_size, generator,
					    NULL, NULL);

	if (dh == NULL)
		return (DST_R_INVALIDPARAM);

	if (DH_generate_key(dh) == 0) {
		DH_free(dh);
		return (ISC_R_NOMEMORY);
	}

	key->opaque = dh;

	isc_buffer_init(&dns, dns_array, sizeof(dns_array),
			ISC_BUFFERTYPE_BINARY);
	dst_openssldh_to_dns(key, &dns);
	isc_buffer_used(&dns, &r);
	key->key_id = dst_s_id_calc(r.base, r.length);

	return (ISC_R_SUCCESS);
}


/************************************************************************** 
 *  dst_openssldh_compare
 *	Compare two keys for equality.
 *  Return
 *	ISC_TRUE	The keys are equal
 *	ISC_FALSE	The keys are not equal
 */
static isc_boolean_t
dst_openssldh_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status;
	DH *dh1, *dh2;

	dh1 = (DH *) key1->opaque;
	dh2 = (DH *) key2->opaque;

	if (dh1 == NULL && dh2 == NULL) 
		return (ISC_TRUE);
	else if (dh1 == NULL || dh2 == NULL)
		return (ISC_FALSE);

	status = BN_cmp(dh1->p, dh2->p) ||
		 BN_cmp(dh1->g, dh2->g) ||
		 BN_cmp(dh1->pub_key, dh2->pub_key);

	if (status != 0)
		return (ISC_FALSE);

	if (dh1->priv_key != NULL || dh2->priv_key != NULL) {
		if (dh1->priv_key == NULL || dh2->priv_key == NULL)
			return (ISC_FALSE);
		if (BN_cmp(dh1->priv_key, dh2->priv_key) != 0)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

/************************************************************************** 
 *  dst_openssldh_paramcompare
 *	Compare two keys' parameters for equality.
 *  Return
 *	ISC_TRUE	The keys are equal
 *	ISC_FALSE	The keys are not equal
 */
static isc_boolean_t
dst_openssldh_paramcompare(const dst_key_t *key1, const dst_key_t *key2) {
	int status;
	DH *dh1, *dh2;

	dh1 = (DH *) key1->opaque;
	dh2 = (DH *) key2->opaque;

	if (dh1 == NULL && dh2 == NULL) 
		return (ISC_TRUE);
	else if (dh1 == NULL || dh2 == NULL)
		return (ISC_FALSE);

	status = BN_cmp(dh1->p, dh2->p) ||
		 BN_cmp(dh1->g, dh2->g);

	if (status != 0)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

static void
uint16_toregion(isc_uint16_t val, isc_region_t *region) {
	*region->base++ = (val & 0xff00) >> 8;
	*region->base++ = (val & 0x00ff);
}

static isc_uint16_t
uint16_fromregion(isc_region_t *region) {
	isc_uint16_t val;
	unsigned char *cp = region->base;

	val = ((unsigned int)(cp[0])) << 8;
	val |= ((unsigned int)(cp[1]));

	region->base += 2;
	return (val);
}

static void
BN_fromhex(BIGNUM *b, const char *str) {
	static const char hexdigits[] = "0123456789abcdef";
	unsigned char data[512];
	unsigned int i;
	BIGNUM *out;

	RUNTIME_CHECK(strlen(str) < 1024 && strlen(str) % 2 == 0);
	for (i = 0; i < strlen(str); i += 2) {
		char *s;
		unsigned int high, low;

		s = strchr(hexdigits, tolower(str[i]));
		RUNTIME_CHECK(s != NULL);
		high = s - hexdigits;

		s = strchr(hexdigits, tolower(str[i + 1]));
		RUNTIME_CHECK(s != NULL);
		low = s - hexdigits;

		data[i/2] = (unsigned char)((high << 4) + low);
	}
	out = BN_bin2bn(data, strlen(str)/2, b);
	RUNTIME_CHECK(out != NULL);
}

#endif
