#if defined(BSAFE) || defined(DNSSAFE)

/*
 * Portions Copyright (c) 1995-1999 by Network Associates, Inc.
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
 * $Id: bsafe_link.c,v 1.11 1999/10/29 12:56:56 marka Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/int.h>
#include <isc/region.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_parse.h"

#  ifdef BSAFE
#    include <aglobal.h>
#    include <bsafe.h>
#  else
#    include <global.h>
#    include <bsafe2.h>
#  endif

typedef struct bsafekey {
	B_KEY_OBJ rk_Private_Key;
	B_KEY_OBJ rk_Public_Key;
} RSA_Key;

#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN (MAX_RSA_MODULUS_BITS/8)
#define MAX_RSA_PRIME_LEN (MAX_RSA_MODULUS_LEN/2)

#define NULL_SURRENDER (A_SURRENDER_CTX *)NULL_PTR
#define NULL_RANDOM (B_ALGORITHM_OBJ)NULL_PTR

static struct dst_func bsafe_functions;

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

static dst_result_t	dst_bsafe_md5digest(const unsigned int mode,
					    B_ALGORITHM_OBJ *digest_obj,
					    isc_region_t *data,
					    isc_buffer_t *digest);

static int		dst_bsafe_key_size(RSA_Key *r_key);
static isc_boolean_t	dst_s_bsafe_itemcmp(ITEM i1, ITEM i2);

static dst_result_t	dst_bsafe_sign(const unsigned int mode, dst_key_t *key,
				       void **context, isc_region_t *data,
				       isc_buffer_t *sig, isc_mem_t *mctx);
static dst_result_t	dst_bsafe_verify(const unsigned int mode,
					 dst_key_t *key,
					 void **context, isc_region_t *data,
					 isc_region_t *sig, isc_mem_t *mctx);
static isc_boolean_t	dst_bsafe_compare(const dst_key_t *key1,
					  const dst_key_t *key2);
static dst_result_t	dst_bsafe_generate(dst_key_t *key, int exp,
					   isc_mem_t *mctx);
static isc_boolean_t	dst_bsafe_isprivate(const dst_key_t *key);
static void		dst_bsafe_destroy(void *key, isc_mem_t *mctx);
static dst_result_t	dst_bsafe_to_dns(const dst_key_t *in_key,
					 isc_buffer_t *data);
static dst_result_t	dst_bsafe_from_dns(dst_key_t *key, isc_buffer_t *data,
					   isc_mem_t *mctx);
static dst_result_t	dst_bsafe_to_file(const dst_key_t *key);
static dst_result_t	dst_bsafe_from_file(dst_key_t *key,
					    const isc_uint16_t id,
					    isc_mem_t *mctx);

/*
 * dst_s_bsafersa_init()
 * Sets up function pointers for BSAFE/DNSSAFE related functions 
 */
void
dst_s_bsafersa_init() {
	REQUIRE(dst_t_func[DST_ALG_RSA] == NULL);
	dst_t_func[DST_ALG_RSA] = &bsafe_functions;
	memset(&bsafe_functions, 0, sizeof(struct dst_func));
	bsafe_functions.sign = dst_bsafe_sign;
	bsafe_functions.verify = dst_bsafe_verify;
	bsafe_functions.computesecret = NULL;
	bsafe_functions.compare = dst_bsafe_compare;
	bsafe_functions.paramcompare = NULL;
	bsafe_functions.generate = dst_bsafe_generate;
	bsafe_functions.isprivate = dst_bsafe_isprivate;
	bsafe_functions.destroy = dst_bsafe_destroy;
	bsafe_functions.to_dns = dst_bsafe_to_dns;
	bsafe_functions.from_dns = dst_bsafe_from_dns;
	bsafe_functions.to_file = dst_bsafe_to_file;
	bsafe_functions.from_file = dst_bsafe_from_file;
}

/*
 * dst_bsafe_sign
 *	Call BSAFE signing functions to sign a block of data.
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
static dst_result_t
dst_bsafe_sign(const unsigned int mode, dst_key_t *key, void **context,
	       isc_region_t *data, isc_buffer_t *sig, isc_mem_t *mctx)
{
	int status = 0;
	B_ALGORITHM_OBJ *md5_ctx = NULL;
	unsigned char digest_array[DNS_SIG_RSAMAXSIZE];
	isc_buffer_t digest;
	isc_region_t sig_region, digest_region;
	dst_result_t ret;
	
	if (mode & DST_SIGMODE_INIT) { 
		md5_ctx = (B_ALGORITHM_OBJ *) isc_mem_get(mctx,
							  sizeof(*md5_ctx));
		if (md5_ctx == NULL)
			return (ISC_R_NOMEMORY);
		if ((status = B_CreateAlgorithmObject(md5_ctx)) != 0)
			return (ISC_R_NOMEMORY);
		if ((status = B_SetAlgorithmInfo(*md5_ctx, AI_MD5, NULL)) != 0)
			return (ISC_R_NOMEMORY);
	}
	else if (context != NULL) 
		md5_ctx = (B_ALGORITHM_OBJ *) *context;
	REQUIRE (md5_ctx != NULL);

	isc_buffer_init(&digest, digest_array, sizeof(digest_array),
			ISC_BUFFERTYPE_BINARY);
	ret = dst_bsafe_md5digest(mode, md5_ctx, data, &digest);
	if (ret != ISC_R_SUCCESS || (mode & DST_SIGMODE_FINAL)) {
		B_DestroyAlgorithmObject(md5_ctx);
		memset(md5_ctx, 0, sizeof(*md5_ctx));
		isc_mem_put(mctx, md5_ctx, sizeof(*md5_ctx));
		if (ret != ISC_R_SUCCESS)
			return (ret);
	}

	if (mode & DST_SIGMODE_FINAL) {
		RSA_Key *rkey;
		B_ALGORITHM_OBJ rsaEncryptor = (B_ALGORITHM_OBJ) NULL_PTR;
		unsigned int written = 0;

		isc_buffer_available(sig, &sig_region);
		isc_buffer_remaining(&digest, &digest_region);

		if (sig_region.length * 8 < (unsigned int) key->key_size)
			return (ISC_R_NOSPACE);
		
		rkey = (RSA_Key *) key->opaque;
		if (rkey == NULL)
			return (DST_R_NULLKEY);
		if (rkey->rk_Private_Key == NULL)
			return (DST_R_NOTPRIVATEKEY);

		if ((status = B_CreateAlgorithmObject(&rsaEncryptor)) != 0)
			return (ISC_R_NOMEMORY);
		if ((status = B_SetAlgorithmInfo(rsaEncryptor,
						 AI_PKCS_RSAPrivate,
						 NULL_PTR)) != 0)

			goto finalfail;
		if ((status = B_EncryptInit(rsaEncryptor,
					    rkey->rk_Private_Key,
					    CHOOSER, NULL_SURRENDER)) != 0)
			goto finalfail;
		if ((status = B_EncryptUpdate(rsaEncryptor, sig_region.base,
					      &written, sig_region.length,
					      pkcs1, sizeof(pkcs1),
					      NULL_PTR, NULL_SURRENDER)) != 0)
			goto finalfail;

		if (written > 0) {
			isc_buffer_add(sig, written);
			isc_buffer_available(sig, &sig_region);
			written = 0;
		}

		if ((status = B_EncryptUpdate(rsaEncryptor, sig_region.base,
					      &written, sig_region.length,
					      digest_region.base,
					      digest_region.length,
					      NULL_PTR, NULL_SURRENDER)) != 0)
			goto finalfail;

		if (written > 0) {
			isc_buffer_add(sig, written);
			isc_buffer_available(sig, &sig_region);
			written = 0;
		}

		isc_buffer_forward(&digest, digest_region.length);

		if ((status = B_EncryptFinal(rsaEncryptor, sig_region.base,
					     &written, sig_region.length,
					     NULL_PTR, NULL_SURRENDER)) != 0)
			goto finalfail;
		isc_buffer_add(sig, written);

		B_DestroyAlgorithmObject(&rsaEncryptor);
		return (ISC_R_SUCCESS);
 finalfail:
		B_DestroyAlgorithmObject(&rsaEncryptor);
		return (DST_R_SIGNFINALFAILURE);
	}
	else
		*context = md5_ctx;

	return (ISC_R_SUCCESS);
}


/*
 * dst_bsafe_verify 
 *	Calls BSAFE verification routines.  There are three steps to 
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
static dst_result_t
dst_bsafe_verify(const unsigned int mode, dst_key_t *key, void **context,
		 isc_region_t *data, isc_region_t *sig, isc_mem_t *mctx)
{
	B_ALGORITHM_OBJ *md5_ctx = NULL;
	unsigned char digest_array[DST_HASH_SIZE];
	unsigned char work_area[DST_HASH_SIZE + sizeof(pkcs1)];
	isc_buffer_t work, digest;
	isc_region_t work_region, digest_region;
	dst_result_t ret;
	int status = 0;

	if (mode & DST_SIGMODE_INIT) { 
		md5_ctx = (B_ALGORITHM_OBJ *) isc_mem_get(mctx,
							  sizeof(*md5_ctx));
		if (md5_ctx == NULL)
			return (ISC_R_NOMEMORY);
		if ((status = B_CreateAlgorithmObject(md5_ctx)) != 0)
			return (ISC_R_NOMEMORY);
		if ((status = B_SetAlgorithmInfo(*md5_ctx, AI_MD5, NULL)) != 0)
			return (ISC_R_NOMEMORY);
	}
	else if (context != NULL) 
		md5_ctx = (B_ALGORITHM_OBJ *) *context;
	REQUIRE (md5_ctx != NULL);

	isc_buffer_init(&digest, digest_array, sizeof(digest_array),
			ISC_BUFFERTYPE_BINARY);
	ret = dst_bsafe_md5digest(mode, md5_ctx, data, &digest);
	if (ret != ISC_R_SUCCESS || (mode & DST_SIGMODE_FINAL)) {
		B_DestroyAlgorithmObject(md5_ctx);
		memset(md5_ctx, 0, sizeof(*md5_ctx));
		isc_mem_put(mctx, md5_ctx, sizeof(*md5_ctx));
		if (ret != ISC_R_SUCCESS)
			return (ret);
	}

	if (mode & DST_SIGMODE_FINAL) {
		RSA_Key *rkey;
		B_ALGORITHM_OBJ rsaEncryptor = (B_ALGORITHM_OBJ) NULL_PTR;
		unsigned int written = 0;

		isc_buffer_init(&work, work_area, sizeof(work_area),
				ISC_BUFFERTYPE_BINARY);

		isc_buffer_available(&work, &work_region);

		rkey = (RSA_Key *) key->opaque;
		if (rkey == NULL)
			return (DST_R_NULLKEY);
		if (rkey->rk_Public_Key == NULL)
			return (DST_R_NOTPUBLICKEY);
		if ((status = B_CreateAlgorithmObject(&rsaEncryptor)) != 0)
			return (ISC_R_NOMEMORY);
		if ((status = B_SetAlgorithmInfo(rsaEncryptor,
						 AI_PKCS_RSAPublic,
						 NULL_PTR)) != 0)
			goto finalfail;
		if ((status = B_DecryptInit(rsaEncryptor, rkey->rk_Public_Key,
					    CHOOSER, NULL_SURRENDER)) != 0)
			goto finalfail;

		if ((status = B_DecryptUpdate(rsaEncryptor, work_region.base,
					      &written, work_region.length,
					      sig->base, sig->length,
					      NULL_PTR, NULL_SURRENDER)) != 0)
			goto finalfail;

		if (written > 0) {
			isc_buffer_add(&work, written);
			isc_buffer_available(&work, &work_region);
			written = 0;
		}

		if ((status = B_DecryptFinal(rsaEncryptor, work_region.base,
					     &written, work_region.length,
					     NULL_PTR, NULL_SURRENDER)) != 0)
			goto finalfail;

		if (written > 0)
			isc_buffer_add(&work, written);

		isc_buffer_used(&work, &work_region);
		isc_buffer_used(&digest, &digest_region);
		
		B_DestroyAlgorithmObject(&rsaEncryptor);
		/* skip PKCS#1 header in output from Decrypt function */
		if (memcmp(digest_region.base, work_region.base + sizeof(pkcs1),
			   digest_region.length) == 0)
			return (ISC_R_SUCCESS);
		else
			return (DST_R_VERIFYFINALFAILURE);
 finalfail:
		B_DestroyAlgorithmObject(&rsaEncryptor);
		return (DST_R_VERIFYFINALFAILURE);
	}
	else
		*context = md5_ctx;

	return (ISC_R_SUCCESS);
}


/*
 * dst_bsafe_isprivate
 *	Is this a private key?
 * Parameters
 *	key		DST KEY structure
 * Returns
 *	ISC_TRUE
 *	ISC_FALSE
 */
static isc_boolean_t
dst_bsafe_isprivate(const dst_key_t *key) {
	RSA_Key *rkey = (RSA_Key *) key->opaque;
	return (ISC_TF(rkey != NULL && rkey->rk_Private_Key != NULL));
}


/*
 * dst_bsafe_to_dns
 *	Converts key from RSA to DNS distribution format
 * Parameters
 *	key		DST KEY structure
 *	data		output data
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static dst_result_t
dst_bsafe_to_dns(const dst_key_t *key, isc_buffer_t *data) {
	B_KEY_OBJ public;
	A_RSA_KEY *pub = NULL;
	isc_region_t r;
	int status;

	REQUIRE(key->opaque != NULL);

	public = (B_KEY_OBJ)((RSA_Key *)key->opaque)->rk_Public_Key;

	if ((status = B_GetKeyInfo((POINTER *)&pub, public, KI_RSAPublic)) != 0)
		return (DST_R_INVALIDPUBLICKEY);
	isc_buffer_available(data, &r);
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

	isc_buffer_available(data, &r);
	memcpy(r.base, pub->exponent.data, pub->exponent.len);
	r.base += pub->exponent.len;
	memcpy(r.base, pub->modulus.data, pub->modulus.len);
	isc_buffer_add(data, pub->exponent.len + pub->modulus.len);

	return (ISC_R_SUCCESS);
}


/*
 * dst_bsafe_from_dns
 *	Converts from a DNS KEY RR format to an RSA KEY. 
 * Parameters
 *	key		Partially filled key structure
 *	data		Buffer containing key in DNS format
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static dst_result_t
dst_bsafe_from_dns(dst_key_t *key, isc_buffer_t *data, isc_mem_t *mctx) {
	unsigned int bytes;
	RSA_Key *rkey;
	A_RSA_KEY *public;
	isc_region_t r;
	isc_buffer_t b;
	int status;

	isc_buffer_remaining(data, &r);
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

	/* length of exponent in bytes */
	bytes = isc_buffer_getuint8(data);
	if (bytes == 0)  /* special case for long exponents */
		bytes = isc_buffer_getuint16(data);

	if (bytes > MAX_RSA_MODULUS_LEN) { 
		dst_bsafe_destroy(rkey, mctx);
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

	isc_buffer_remaining(data, &r);
	if (r.length < bytes) {
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	memcpy(public->exponent.data, r.base, bytes);
	isc_buffer_forward(data, bytes);

	isc_buffer_remaining(data, &r);

	if (r.length > MAX_RSA_MODULUS_LEN) { 
		dst_bsafe_destroy(rkey, mctx);
		memset(public->exponent.data, 0, bytes);
		isc_mem_put(mctx, public->exponent.data, bytes);
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	public->modulus.len = r.length;
	public->modulus.data = (unsigned char *) isc_mem_get(mctx, r.length);
	if (public->modulus.data == NULL) {
		dst_bsafe_destroy(rkey, mctx);
		memset(public->exponent.data, 0, bytes);
		isc_mem_put(mctx, public->exponent.data, bytes);
		isc_mem_put(mctx, public, sizeof(*public));
		return (ISC_R_NOMEMORY);
	}
	memcpy(public->modulus.data, r.base, r.length);
	isc_buffer_forward(data, r.length);

	status = B_SetKeyInfo(rkey->rk_Public_Key, KI_RSAPublic,
			      (POINTER) public);
	if (status != 0)
		return (DST_R_INVALIDPUBLICKEY);

	isc_buffer_init(&b, public->modulus.data + public->modulus.len - 3,
			2, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&b, 2);
	key->key_id = isc_buffer_getuint16(&b);
	key->key_size = dst_bsafe_key_size(rkey);

	memset(public->exponent.data, 0, public->exponent.len);
	isc_mem_put(mctx, public->exponent.data, public->exponent.len);
	memset(public->modulus.data, 0, public->modulus.len);
	isc_mem_put(mctx, public->modulus.data, public->modulus.len);
	isc_mem_put(mctx, public, sizeof(*public));

	key->opaque = (void *) rkey;

	return (ISC_R_SUCCESS);
}


/*
 * dst_bsafe_to_file
 *	Encodes an RSA Key into the portable file format.
 * Parameters 
 *	key		DST KEY structure 
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
static dst_result_t
dst_bsafe_to_file(const dst_key_t *key) {
	int cnt = 0;
	B_KEY_OBJ rkey;
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;
	dst_private_t priv;

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

	rkey = (B_KEY_OBJ)((RSA_Key *) key->opaque)->rk_Private_Key;

	B_GetKeyInfo((POINTER *) &private, rkey, KI_PKCS_RSAPrivate);

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
	return (dst_s_write_private_key_file(key->key_name, key->key_alg,
					     key->key_id, &priv));
}


/*
 * dst_bsafe_from_file
 *	Converts contents of a private key file into a private RSA key. 
 * Parameters 
 *	key		Partially filled RSA KEY structure
 *	id		The key id
 *	path		The directory that the file will be read from
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static dst_result_t 
dst_bsafe_from_file(dst_key_t *key, const isc_uint16_t id, isc_mem_t *mctx) {
	dst_private_t priv;
	dst_result_t ret;
	isc_buffer_t b;
	int i;
	RSA_Key *rkey = NULL;
	A_RSA_KEY *public = NULL;
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;
	int status = 0;
#define DST_RET(a) {ret = a; goto err;}

	/* read private key file */
	ret = dst_s_parse_private_key_file(key->key_name, key->key_alg, 
					   id, &priv, mctx);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	/* allocate key*/
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

	isc_buffer_init(&b, public->modulus.data + public->modulus.len - 3,
			2, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&b, 2);
	key->key_id = isc_buffer_getuint16(&b);
	if (key->key_id != id)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	rkey = (RSA_Key *) isc_mem_get(mctx, sizeof(RSA_Key));
	if (rkey == NULL) 
		DST_RET(ISC_R_NOMEMORY);
	memset(rkey, 0, sizeof(*rkey));
	if ((status = B_CreateKeyObject(&(rkey->rk_Public_Key))) != 0)
		DST_RET(ISC_R_NOMEMORY);
	if ((status = B_SetKeyInfo(rkey->rk_Public_Key, KI_RSAPublic,
				   (POINTER) public)) != 0)
		DST_RET(DST_R_INVALIDPUBLICKEY);

	if ((status = B_CreateKeyObject(&rkey->rk_Private_Key)) != 0)
		DST_RET(ISC_R_NOMEMORY);

	if ((status = B_SetKeyInfo(rkey->rk_Private_Key, KI_PKCS_RSAPrivate,
				   (POINTER) private)) != 0)
		DST_RET(DST_R_INVALIDPRIVATEKEY);

	key->key_size = dst_bsafe_key_size(rkey);
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
	dst_s_free_private_structure_fields(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

/*
 * dst_bsafe_destroy
 *	Frees all dynamically allocated structures in key.
 */
static void
dst_bsafe_destroy(void *key, isc_mem_t *mctx)
{
	RSA_Key *rkey = (RSA_Key *) key;
	if (rkey == NULL)
		return;
	if (rkey->rk_Private_Key != NULL)
		B_DestroyKeyObject(&rkey->rk_Private_Key);
	if (rkey->rk_Public_Key != NULL)
		B_DestroyKeyObject(&rkey->rk_Public_Key);
	memset(rkey, 0, sizeof(*rkey));
	isc_mem_put(mctx, rkey, sizeof(*rkey));
}


/*
 *  dst_bsafe_generate
 *	Generates unique keys that are hard to predict.
 *  Parameters
 *	key		DST Key structure
 *	exp		the public exponent
 *	mctx		memory context to allocate key
 *  Return 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static dst_result_t
dst_bsafe_generate(dst_key_t *key, int exp, isc_mem_t *mctx) {
	int status;
	B_KEY_OBJ private;
	B_KEY_OBJ public;
	B_ALGORITHM_OBJ keypairGenerator = NULL;
	B_ALGORITHM_OBJ randomAlgorithm = NULL;
	A_RSA_KEY_GEN_PARAMS keygenParams;
	char exponent[4];
	int exponent_len = 0;
	RSA_Key *rsa;
	unsigned char randomSeed[256];
	isc_buffer_t b, rand;
	A_RSA_KEY *pub = NULL;
	dst_result_t ret;

	rsa = (RSA_Key *) isc_mem_get(mctx, sizeof(RSA_Key));
	if (rsa == NULL)
		return (ISC_R_NOMEMORY);

	memset(rsa, 0, sizeof(*rsa));
	keygenParams.publicExponent.data = NULL;

#define do_fail(code) {ret = code; goto fail;}
	if ((status = B_CreateAlgorithmObject(&keypairGenerator)) != 0)
		do_fail(ISC_R_NOMEMORY);

	keygenParams.modulusBits = key->key_size;

	/* exp = 0 or 1 are special (mean 3 or F4) */
	if (exp == 0)
		exp = 3;
	else if (exp == 1)
		exp = 65537;

	/* Now encode the exponent and its length */
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

	keygenParams.publicExponent.data = (unsigned char *) isc_mem_get(mctx,
								  exponent_len);
	if (keygenParams.publicExponent.data == NULL)
		do_fail(ISC_R_NOMEMORY);

	memcpy(keygenParams.publicExponent.data, exponent, exponent_len);
	keygenParams.publicExponent.len = exponent_len;
	if ((status = B_SetAlgorithmInfo
	     (keypairGenerator, AI_RSAKeyGen, (POINTER) &keygenParams)) != 0)
		do_fail(DST_R_INVALIDPARAM);

	isc_mem_put(mctx, keygenParams.publicExponent.data, exponent_len);
	keygenParams.publicExponent.data = NULL;

	if ((status = B_GenerateInit(keypairGenerator, CHOOSER,
				     NULL_SURRENDER)) != 0)
		do_fail(ISC_R_NOMEMORY);

	if ((status = B_CreateKeyObject(&public)) != 0)
		do_fail(ISC_R_NOMEMORY);

	if ((status = B_CreateKeyObject(&private)) != 0)
		do_fail(ISC_R_NOMEMORY);

	if ((status = B_CreateAlgorithmObject(&randomAlgorithm)) != 0)
		do_fail(ISC_R_NOMEMORY);

	if ((status = B_SetAlgorithmInfo(randomAlgorithm, AI_MD5Random,
					 NULL_PTR)) != 0)
		do_fail(ISC_R_NOMEMORY);

	if ((status = B_RandomInit(randomAlgorithm, CHOOSER,
				   NULL_SURRENDER)) != 0)
		do_fail(ISC_R_NOMEMORY);

	isc_buffer_init(&rand, randomSeed, sizeof(randomSeed),
			ISC_BUFFERTYPE_BINARY);
	ret = dst_random_get(sizeof(randomSeed), &rand);
	if (ret != ISC_R_SUCCESS)
		goto fail;

	if ((status = B_RandomUpdate(randomAlgorithm, randomSeed, 
				     sizeof(randomSeed), NULL_SURRENDER)) != 0)
		do_fail(ISC_R_NOMEMORY);

	memset(randomSeed, 0, sizeof(randomSeed));

	if ((status = B_GenerateKeypair(keypairGenerator, public, private,
					randomAlgorithm, NULL_SURRENDER)) != 0)
		do_fail(DST_R_INVALIDPARAM);

	rsa->rk_Private_Key = private;
	rsa->rk_Public_Key = public;
	key->opaque = (void *) rsa;

	B_DestroyAlgorithmObject(&keypairGenerator);
	B_DestroyAlgorithmObject(&randomAlgorithm);

	/* fill in the footprint in generate key */
	B_GetKeyInfo((POINTER *) &pub, public, KI_RSAPublic);

	isc_buffer_init(&b, pub->modulus.data + pub->modulus.len - 3,
			2, ISC_BUFFERTYPE_BINARY);
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
	return (ret);
}


static isc_boolean_t
dst_s_bsafe_itemcmp(ITEM i1, ITEM i2) {
	if (i1.len != i2.len || memcmp (i1.data, i2.data, i1.len) != 0)
		return (ISC_FALSE);
	else
		return (ISC_TRUE);
}

/************************************************************************** 
 *  dst_bsafe_compare
 *	Compare two keys for equality.
 *  Return
 *	ISC_TRUE	The keys are equal
 *	ISC_FALSE	The keys are not equal
 */
static isc_boolean_t
dst_bsafe_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status, s1 = 0, s2 = 0;
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
		B_GetKeyInfo((POINTER *) &public1, rkey1->rk_Public_Key, 
			     KI_RSAPublic);
	if (rkey2->rk_Public_Key) 
		B_GetKeyInfo((POINTER *) &public2, rkey2->rk_Public_Key, 
			     KI_RSAPublic);
	if (public1 == NULL && public2 == NULL)
		return (ISC_TRUE);
	else if (public1 == NULL || public2 == NULL)
		return (ISC_FALSE);

	status = dst_s_bsafe_itemcmp(public1->modulus, public2->modulus) ||
		 dst_s_bsafe_itemcmp(public1->exponent, public2->exponent);

	if (status == ISC_FALSE) 
		return (ISC_FALSE);

	if (rkey1->rk_Private_Key != NULL || rkey2->rk_Private_Key != NULL) {
		if (rkey1->rk_Private_Key == NULL ||
		    rkey2->rk_Private_Key == NULL)
			return (ISC_FALSE);

		s1 = B_GetKeyInfo((POINTER *) &p1, rkey1->rk_Private_Key,
				  KI_PKCS_RSAPrivate);
		s2 = B_GetKeyInfo((POINTER *) &p2, rkey2->rk_Private_Key,
				  KI_PKCS_RSAPrivate);
		if (p1 == NULL || p2 == NULL) 
			return (ISC_FALSE);

		status = dst_s_bsafe_itemcmp(p1->modulus, p2->modulus) &&
			 dst_s_bsafe_itemcmp(p1->publicExponent, 
					     p2->publicExponent) &&
			 dst_s_bsafe_itemcmp(p1->privateExponent, 
					     p2->privateExponent) &&
			 dst_s_bsafe_itemcmp(p1->prime[0], p2->prime[0]) &&
			 dst_s_bsafe_itemcmp(p1->prime[1], p2->prime[1]) &&
			 dst_s_bsafe_itemcmp(p1->primeExponent[0], 
					     p2->primeExponent[0]) &&
			 dst_s_bsafe_itemcmp(p1->primeExponent[1], 
					     p2->primeExponent[1]) &&
			 dst_s_bsafe_itemcmp(p1->coefficient, p2->coefficient);
		if (status == ISC_FALSE)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}


/* 
 * dst_bsafe_key_size() 
 * Function to calculate the size of the key in bits
 */
static int
dst_bsafe_key_size(RSA_Key *key)
{
	int size;
	A_PKCS_RSA_PRIVATE_KEY *private = NULL;

	REQUIRE(key != NULL);
	REQUIRE(key->rk_Private_Key != NULL || key->rk_Public_Key != NULL);

	if (key->rk_Private_Key != NULL)
		B_GetKeyInfo((POINTER *) &private, key->rk_Private_Key,
			     KI_PKCS_RSAPrivate);
	else
		B_GetKeyInfo((POINTER *) &private, key->rk_Public_Key,
			     KI_RSAPublic);

	size = dst_s_calculate_bits(private->modulus.data,
				    private->modulus.len * 8);
	return (size);
}

/* 
 * dst_bsafe_md5digest(): function to digest data using MD5 digest function 
 * if needed 
 */
static dst_result_t
dst_bsafe_md5digest(const unsigned int mode, B_ALGORITHM_OBJ *digest_obj,
		    isc_region_t *data, isc_buffer_t *digest)
{
	int status = 0;
	unsigned int written = 0;
	isc_region_t r;

	REQUIRE(digest != NULL);
	REQUIRE(digest_obj != NULL);

	if ((mode & DST_SIGMODE_INIT) &&
	    (status = B_DigestInit(*digest_obj, (B_KEY_OBJ) NULL,
				   CHOOSER, NULL_SURRENDER)) != 0)
		return (DST_R_SIGNINITFAILURE);

	if ((mode & DST_SIGMODE_UPDATE) &&
	    (status = B_DigestUpdate(*digest_obj, data->base, data->length,
				     NULL_SURRENDER)) != 0)
		return (DST_R_SIGNUPDATEFAILURE);

	isc_buffer_available(digest, &r);
	if (mode & DST_SIGMODE_FINAL) {
		if (digest == NULL ||
		    (status = B_DigestFinal(*digest_obj, r.base, &written,
					    r.length, NULL_SURRENDER)) != 0)
			return (DST_R_SIGNFINALFAILURE);
		isc_buffer_add(digest, written);
	}
	return (ISC_R_SUCCESS);
}


/* 
 * define memory functions for bsafe that use the isc_mem functions and a
 * static context.
 */
void
T_free(POINTER block) {
	dst_mem_free(block);
}

POINTER
T_malloc(unsigned int len) {
	return (dst_mem_alloc(len));
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
	return (dst_mem_realloc(block, len));
}
#endif /* BSAFE || DNSSAFE */
