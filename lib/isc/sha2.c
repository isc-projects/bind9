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

/*	$FreeBSD: src/sys/crypto/sha2/sha2.c,v 1.2.2.2 2002/03/05 08:36:47 ume Exp $	*/
/*	$KAME: sha2.c,v 1.8 2001/11/08 01:07:52 itojun Exp $	*/

/*
 * sha2.c
 *
 * Version 1.0.0beta1
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright 2000 Aaron D. Gifford.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <config.h>

#include <isc/assertions.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/sha2.h>
#include <isc/string.h>
#include <isc/util.h>

#if PKCS11CRYPTO
#include <pk11/internal.h>
#include <pk11/pk11.h>
#endif

#if defined(ISC_PLATFORM_OPENSSLHASH) && !defined(LIBRESSL_VERSION_NUMBER)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new() &(context->_ctx)
#define EVP_MD_CTX_free(ptr) EVP_MD_CTX_cleanup(ptr)
#define EVP_MD_CTX_reset(c) EVP_MD_CTX_cleanup(c)
#endif

void
isc_sha224_init(isc_sha224_t *context) {
	if (context == (isc_sha224_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha224()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA224.");
	}
}

void
isc_sha224_invalidate(isc_sha224_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha224_update(isc_sha224_t *context, const isc_uint8_t* data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha224_final(isc_uint8_t digest[], isc_sha224_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha256_init(isc_sha256_t *context) {
	if (context == (isc_sha256_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha256()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA256.");
	}
}

void
isc_sha256_invalidate(isc_sha256_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha256_update(isc_sha256_t *context, const isc_uint8_t *data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha256_final(isc_uint8_t digest[], isc_sha256_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha512_init(isc_sha512_t *context) {
	if (context == (isc_sha512_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha512()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA512.");
	}
}

void
isc_sha512_invalidate(isc_sha512_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void isc_sha512_update(isc_sha512_t *context, const isc_uint8_t *data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void isc_sha512_final(isc_uint8_t digest[], isc_sha512_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha384_init(isc_sha384_t *context) {
	if (context == (isc_sha384_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha384()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA384.");
	}
}

void
isc_sha384_invalidate(isc_sha384_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha384_update(isc_sha384_t *context, const isc_uint8_t* data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha384_final(isc_uint8_t digest[], isc_sha384_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

#elif PKCS11CRYPTO

void
isc_sha224_init(isc_sha224_t *context) {
	CK_RV rv;
	CK_MECHANISM mech = { CKM_SHA224, NULL, 0 };

	if (context == (isc_sha224_t *)0) {
		return;
	}
	RUNTIME_CHECK(pk11_get_session(context, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	PK11_FATALCHECK(pkcs_C_DigestInit, (context->session, &mech));
}

void
isc_sha224_invalidate(isc_sha224_t *context) {
	CK_BYTE garbage[ISC_SHA224_DIGESTLENGTH];
	CK_ULONG len = ISC_SHA224_DIGESTLENGTH;

	if (context->handle == NULL)
		return;
	(void) pkcs_C_DigestFinal(context->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	pk11_return_session(context);
}

void
isc_sha224_update(isc_sha224_t *context, const isc_uint8_t* data, size_t len) {
	CK_RV rv;
	CK_BYTE_PTR pPart;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0 && data != (isc_uint8_t*)0);

	DE_CONST(data, pPart);
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(context->session, pPart, (CK_ULONG) len));
}

void
isc_sha224_final(isc_uint8_t digest[], isc_sha224_t *context) {
	CK_RV rv;
	CK_ULONG len = ISC_SHA224_DIGESTLENGTH;

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		PK11_FATALCHECK(pkcs_C_DigestFinal,
				(context->session,
				 (CK_BYTE_PTR) digest,
				 &len));
	} else {
		CK_BYTE garbage[ISC_SHA224_DIGESTLENGTH];

		(void) pkcs_C_DigestFinal(context->session, garbage, &len);
		isc_safe_memwipe(garbage, sizeof(garbage));
	}
	pk11_return_session(context);
}

void
isc_sha256_init(isc_sha256_t *context) {
	CK_RV rv;
	CK_MECHANISM mech = { CKM_SHA256, NULL, 0 };

	if (context == (isc_sha256_t *)0) {
		return;
	}
	RUNTIME_CHECK(pk11_get_session(context, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	PK11_FATALCHECK(pkcs_C_DigestInit, (context->session, &mech));
}

void
isc_sha256_invalidate(isc_sha256_t *context) {
	CK_BYTE garbage[ISC_SHA256_DIGESTLENGTH];
	CK_ULONG len = ISC_SHA256_DIGESTLENGTH;

	if (context->handle == NULL)
		return;
	(void) pkcs_C_DigestFinal(context->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	pk11_return_session(context);
}

void
isc_sha256_update(isc_sha256_t *context, const isc_uint8_t* data, size_t len) {
	CK_RV rv;
	CK_BYTE_PTR pPart;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0 && data != (isc_uint8_t*)0);

	DE_CONST(data, pPart);
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(context->session, pPart, (CK_ULONG) len));
}

void
isc_sha256_final(isc_uint8_t digest[], isc_sha256_t *context) {
	CK_RV rv;
	CK_ULONG len = ISC_SHA256_DIGESTLENGTH;

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		PK11_FATALCHECK(pkcs_C_DigestFinal,
				(context->session,
				 (CK_BYTE_PTR) digest,
				 &len));
	} else {
		CK_BYTE garbage[ISC_SHA256_DIGESTLENGTH];

		(void) pkcs_C_DigestFinal(context->session, garbage, &len);
		isc_safe_memwipe(garbage, sizeof(garbage));
	}
	pk11_return_session(context);
}

void
isc_sha512_init(isc_sha512_t *context) {
	CK_RV rv;
	CK_MECHANISM mech = { CKM_SHA512, NULL, 0 };

	if (context == (isc_sha512_t *)0) {
		return;
	}
	RUNTIME_CHECK(pk11_get_session(context, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	PK11_FATALCHECK(pkcs_C_DigestInit, (context->session, &mech));
}

void
isc_sha512_invalidate(isc_sha512_t *context) {
	CK_BYTE garbage[ISC_SHA512_DIGESTLENGTH];
	CK_ULONG len = ISC_SHA512_DIGESTLENGTH;

	if (context->handle == NULL)
		return;
	(void) pkcs_C_DigestFinal(context->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	pk11_return_session(context);
}

void
isc_sha512_update(isc_sha512_t *context, const isc_uint8_t* data, size_t len) {
	CK_RV rv;
	CK_BYTE_PTR pPart;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0 && data != (isc_uint8_t*)0);

	DE_CONST(data, pPart);
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(context->session, pPart, (CK_ULONG) len));
}

void
isc_sha512_final(isc_uint8_t digest[], isc_sha512_t *context) {
	CK_RV rv;
	CK_ULONG len = ISC_SHA512_DIGESTLENGTH;

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		PK11_FATALCHECK(pkcs_C_DigestFinal,
				(context->session,
				 (CK_BYTE_PTR) digest,
				 &len));
	} else {
		CK_BYTE garbage[ISC_SHA512_DIGESTLENGTH];

		(void) pkcs_C_DigestFinal(context->session, garbage, &len);
		isc_safe_memwipe(garbage, sizeof(garbage));
	}
	pk11_return_session(context);
}

void
isc_sha384_init(isc_sha384_t *context) {
	CK_RV rv;
	CK_MECHANISM mech = { CKM_SHA384, NULL, 0 };

	if (context == (isc_sha384_t *)0) {
		return;
	}
	RUNTIME_CHECK(pk11_get_session(context, OP_DIGEST, ISC_TRUE, ISC_FALSE,
				       ISC_FALSE, NULL, 0) == ISC_R_SUCCESS);
	PK11_FATALCHECK(pkcs_C_DigestInit, (context->session, &mech));
}

void
isc_sha384_invalidate(isc_sha384_t *context) {
	CK_BYTE garbage[ISC_SHA384_DIGESTLENGTH];
	CK_ULONG len = ISC_SHA384_DIGESTLENGTH;

	if (context->handle == NULL)
		return;
	(void) pkcs_C_DigestFinal(context->session, garbage, &len);
	isc_safe_memwipe(garbage, sizeof(garbage));
	pk11_return_session(context);
}

void
isc_sha384_update(isc_sha384_t *context, const isc_uint8_t* data, size_t len) {
	CK_RV rv;
	CK_BYTE_PTR pPart;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0 && data != (isc_uint8_t*)0);

	DE_CONST(data, pPart);
	PK11_FATALCHECK(pkcs_C_DigestUpdate,
			(context->session, pPart, (CK_ULONG) len));
}

void
isc_sha384_final(isc_uint8_t digest[], isc_sha384_t *context) {
	CK_RV rv;
	CK_ULONG len = ISC_SHA384_DIGESTLENGTH;

	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		PK11_FATALCHECK(pkcs_C_DigestFinal,
				(context->session,
				 (CK_BYTE_PTR) digest,
				 &len));
	} else {
		CK_BYTE garbage[ISC_SHA384_DIGESTLENGTH];

		(void) pkcs_C_DigestFinal(context->session, garbage, &len);
		isc_safe_memwipe(garbage, sizeof(garbage));
	}
	pk11_return_session(context);
}

#else
#error No crypto provider defined
#endif

/*** SHA-224: *********************************************************/
void
isc_sha224_init(isc_sha224_t *context) {
	if (context == (isc_sha256_t *)0) {
		return;
	}
	memmove(context->state, sha224_initial_hash_value,
		ISC_SHA256_DIGESTLENGTH);
	memset(context->buffer, 0, ISC_SHA256_BLOCK_LENGTH);
	context->bitcount = 0;
}

void
isc_sha224_invalidate(isc_sha224_t *context) {
	isc_safe_memwipe(context, sizeof(*context));
}

void
isc_sha224_update(isc_sha224_t *context, const isc_uint8_t* data, size_t len) {
	isc_sha256_update((isc_sha256_t *)context, data, len);
}

void
isc_sha224_final(isc_uint8_t digest[], isc_sha224_t *context) {
	isc_uint8_t sha256_digest[ISC_SHA256_DIGESTLENGTH];
	isc_sha256_final(sha256_digest, (isc_sha256_t *)context);
	memmove(digest, sha256_digest, ISC_SHA224_DIGESTLENGTH);
	isc_safe_memwipe(sha256_digest, sizeof(sha256_digest));
}

/*** SHA-256: *********************************************************/
void
isc_sha256_init(isc_sha256_t *context) {
	if (context == (isc_sha256_t *)0) {
		return;
	}
	memmove(context->state, sha256_initial_hash_value,
	       ISC_SHA256_DIGESTLENGTH);
	memset(context->buffer, 0, ISC_SHA256_BLOCK_LENGTH);
	context->bitcount = 0;
}

void
isc_sha256_invalidate(isc_sha256_t *context) {
	isc_safe_memwipe(context, sizeof(*context));
}

#ifdef ISC_SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-256 round macros: */

#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)	\
	REVERSE32(*data++, W256[j]); \
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
	     K256[j] + W256[j]; \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++


#else /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)	\
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
	     K256[j] + (W256[j] = *data++); \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++

#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND256(a,b,c,d,e,f,g,h)	\
	s0 = W256[(j+1)&0x0f]; \
	s0 = sigma0_256(s0); \
	s1 = W256[(j+14)&0x0f]; \
	s1 = sigma1_256(s1); \
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + \
	     (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0); \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++

void isc_sha256_transform(isc_sha256_t *context, const isc_uint32_t* data) {
	isc_uint32_t	a, b, c, d, e, f, g, h, s0, s1;
	isc_uint32_t	T1, *W256;
	int		j;

	W256 = (isc_uint32_t*)context->buffer;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
		/* Rounds 0 to 15 (unrolled): */
		ROUND256_0_TO_15(a,b,c,d,e,f,g,h);
		ROUND256_0_TO_15(h,a,b,c,d,e,f,g);
		ROUND256_0_TO_15(g,h,a,b,c,d,e,f);
		ROUND256_0_TO_15(f,g,h,a,b,c,d,e);
		ROUND256_0_TO_15(e,f,g,h,a,b,c,d);
		ROUND256_0_TO_15(d,e,f,g,h,a,b,c);
		ROUND256_0_TO_15(c,d,e,f,g,h,a,b);
		ROUND256_0_TO_15(b,c,d,e,f,g,h,a);
	} while (j < 16);

	/* Now for the remaining rounds to 64: */
	do {
		ROUND256(a,b,c,d,e,f,g,h);
		ROUND256(h,a,b,c,d,e,f,g);
		ROUND256(g,h,a,b,c,d,e,f);
		ROUND256(f,g,h,a,b,c,d,e);
		ROUND256(e,f,g,h,a,b,c,d);
		ROUND256(d,e,f,g,h,a,b,c);
		ROUND256(c,d,e,f,g,h,a,b);
		ROUND256(b,c,d,e,f,g,h,a);
	} while (j < 64);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = 0;
	/* Avoid compiler warnings */
	POST(a); POST(b); POST(c); POST(d); POST(e); POST(f);
	POST(g); POST(h); POST(T1);
}

#else /* ISC_SHA2_UNROLL_TRANSFORM */

void
isc_sha256_transform(isc_sha256_t *context, const isc_uint32_t* data) {
	isc_uint32_t	a, b, c, d, e, f, g, h, s0, s1;
	isc_uint32_t	T1, T2, *W256;
	int		j;

	W256 = (isc_uint32_t*)context->buffer;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
#if BYTE_ORDER == LITTLE_ENDIAN
		/* Copy data while converting to host byte order */
		REVERSE32(*data++,W256[j]);
		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
#else /* BYTE_ORDER == LITTLE_ENDIAN */
		/* Apply the SHA-256 compression function to update a..h with copy */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do {
		/* Part of the message block expansion: */
		s0 = W256[(j+1)&0x0f];
		s0 = sigma0_256(s0);
		s1 = W256[(j+14)&0x0f];
		s1 = sigma1_256(s1);

		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
		     (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0);
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 64);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
	/* Avoid compiler warnings */
	POST(a); POST(b); POST(c); POST(d); POST(e); POST(f);
	POST(g); POST(h); POST(T1); POST(T2);
}

#endif /* ISC_SHA2_UNROLL_TRANSFORM */

void
isc_sha256_update(isc_sha256_t *context, const isc_uint8_t *data, size_t len) {
	unsigned int	freespace, usedspace;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0 && data != (isc_uint8_t*)0);

	usedspace = (unsigned int)((context->bitcount >> 3) %
				   ISC_SHA256_BLOCK_LENGTH);
	if (usedspace > 0) {
		/* Calculate how much free space is available in the buffer */
		freespace = ISC_SHA256_BLOCK_LENGTH - usedspace;

		if (len >= freespace) {
			/* Fill the buffer completely and process it */
			memmove(&context->buffer[usedspace], data, freespace);
			context->bitcount += freespace << 3;
			len -= freespace;
			data += freespace;
			isc_sha256_transform(context,
					     (isc_uint32_t*)context->buffer);
		} else {
			/* The buffer is not yet full */
			memmove(&context->buffer[usedspace], data, len);
			context->bitcount += len << 3;
			/* Clean up: */
			usedspace = freespace = 0;
			/* Avoid compiler warnings: */
			POST(usedspace); POST(freespace);
			return;
		}
	}
	while (len >= ISC_SHA256_BLOCK_LENGTH) {
		/* Process as many complete blocks as we can */
		memmove(context->buffer, data, ISC_SHA256_BLOCK_LENGTH);
		isc_sha256_transform(context, (isc_uint32_t*)context->buffer);
		context->bitcount += ISC_SHA256_BLOCK_LENGTH << 3;
		len -= ISC_SHA256_BLOCK_LENGTH;
		data += ISC_SHA256_BLOCK_LENGTH;
	}
	if (len > 0U) {
		/* There's left-overs, so save 'em */
		memmove(context->buffer, data, len);
		context->bitcount += len << 3;
	}
	/* Clean up: */
	usedspace = freespace = 0;
	/* Avoid compiler warnings: */
	POST(usedspace); POST(freespace);
}

void
isc_sha256_final(isc_uint8_t digest[], isc_sha256_t *context) {
	isc_uint32_t	*d = (isc_uint32_t*)digest;
	unsigned int	usedspace;

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		usedspace = (unsigned int)((context->bitcount >> 3) %
					   ISC_SHA256_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
		/* Convert FROM host byte order */
		REVERSE64(context->bitcount,context->bitcount);
#endif
		if (usedspace > 0) {
			/* Begin padding with a 1 bit: */
			context->buffer[usedspace++] = 0x80;

			if (usedspace <= ISC_SHA256_SHORT_BLOCK_LENGTH) {
				/* Set-up for the last transform: */
				memset(&context->buffer[usedspace], 0,
				       ISC_SHA256_SHORT_BLOCK_LENGTH - usedspace);
			} else {
				if (usedspace < ISC_SHA256_BLOCK_LENGTH) {
					memset(&context->buffer[usedspace], 0,
					       ISC_SHA256_BLOCK_LENGTH -
					       usedspace);
				}
				/* Do second-to-last transform: */
				isc_sha256_transform(context,
					       (isc_uint32_t*)context->buffer);

				/* And set-up for the last transform: */
				memset(context->buffer, 0,
				       ISC_SHA256_SHORT_BLOCK_LENGTH);
			}
		} else {
			/* Set-up for the last transform: */
			memset(context->buffer, 0, ISC_SHA256_SHORT_BLOCK_LENGTH);

			/* Begin padding with a 1 bit: */
			*context->buffer = 0x80;
		}
		/* Set the bit count: */
		*(isc_uint64_t*)&context->buffer[ISC_SHA256_SHORT_BLOCK_LENGTH] = context->bitcount;

		/* Final transform: */
		isc_sha256_transform(context, (isc_uint32_t*)context->buffer);

#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* Convert TO host byte order */
			int	j;
			for (j = 0; j < 8; j++) {
				REVERSE32(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		memmove(d, context->state, ISC_SHA256_DIGESTLENGTH);
#endif
	}

	/* Clean up state data: */
	isc_safe_memwipe(context, sizeof(*context));
	usedspace = 0;
	POST(usedspace);
}

/*** SHA-512: *********************************************************/
void
isc_sha512_init(isc_sha512_t *context) {
	if (context == (isc_sha512_t *)0) {
		return;
	}
	memmove(context->state, sha512_initial_hash_value,
		ISC_SHA512_DIGESTLENGTH);
	memset(context->buffer, 0, ISC_SHA512_BLOCK_LENGTH);
	context->bitcount[0] = context->bitcount[1] =  0;
}

void
isc_sha512_invalidate(isc_sha512_t *context) {
	isc_safe_memwipe(context, sizeof(*context));
}

#ifdef ISC_SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-512 round macros: */
#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h)	\
	REVERSE64(*data++, W512[j]); \
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + \
	     K512[j] + W512[j]; \
	(d) += T1, \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)), \
	j++


#else /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h)	\
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + \
	     K512[j] + (W512[j] = *data++); \
	(d) += T1; \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)); \
	j++

#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#define ROUND512(a,b,c,d,e,f,g,h)	\
	s0 = W512[(j+1)&0x0f]; \
	s0 = sigma0_512(s0); \
	s1 = W512[(j+14)&0x0f]; \
	s1 = sigma1_512(s1); \
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + K512[j] + \
	     (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0); \
	(d) += T1; \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)); \
	j++

void isc_sha512_transform(isc_sha512_t *context, const isc_uint64_t* data) {
	isc_uint64_t	a, b, c, d, e, f, g, h, s0, s1;
	isc_uint64_t	T1, *W512 = (isc_uint64_t*)context->buffer;
	int		j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
		ROUND512_0_TO_15(a,b,c,d,e,f,g,h);
		ROUND512_0_TO_15(h,a,b,c,d,e,f,g);
		ROUND512_0_TO_15(g,h,a,b,c,d,e,f);
		ROUND512_0_TO_15(f,g,h,a,b,c,d,e);
		ROUND512_0_TO_15(e,f,g,h,a,b,c,d);
		ROUND512_0_TO_15(d,e,f,g,h,a,b,c);
		ROUND512_0_TO_15(c,d,e,f,g,h,a,b);
		ROUND512_0_TO_15(b,c,d,e,f,g,h,a);
	} while (j < 16);

	/* Now for the remaining rounds up to 79: */
	do {
		ROUND512(a,b,c,d,e,f,g,h);
		ROUND512(h,a,b,c,d,e,f,g);
		ROUND512(g,h,a,b,c,d,e,f);
		ROUND512(f,g,h,a,b,c,d,e);
		ROUND512(e,f,g,h,a,b,c,d);
		ROUND512(d,e,f,g,h,a,b,c);
		ROUND512(c,d,e,f,g,h,a,b);
		ROUND512(b,c,d,e,f,g,h,a);
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = 0;
	/* Avoid compiler warnings */
	POST(a); POST(b); POST(c); POST(d); POST(e); POST(f);
	POST(g); POST(h); POST(T1);
}

#else /* ISC_SHA2_UNROLL_TRANSFORM */

void
isc_sha512_transform(isc_sha512_t *context, const isc_uint64_t* data) {
	isc_uint64_t	a, b, c, d, e, f, g, h, s0, s1;
	isc_uint64_t	T1, T2, *W512 = (isc_uint64_t*)context->buffer;
	int		j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
#if BYTE_ORDER == LITTLE_ENDIAN
		/* Convert TO host byte order */
		REVERSE64(*data++, W512[j]);
		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j];
#else /* BYTE_ORDER == LITTLE_ENDIAN */
		/* Apply the SHA-512 compression function to update a..h with copy */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + (W512[j] = *data++);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do {
		/* Part of the message block expansion: */
		s0 = W512[(j+1)&0x0f];
		s0 = sigma0_512(s0);
		s1 = W512[(j+14)&0x0f];
		s1 =  sigma1_512(s1);

		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] +
		     (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0);
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
	/* Avoid compiler warnings */
	POST(a); POST(b); POST(c); POST(d); POST(e); POST(f);
	POST(g); POST(h); POST(T1); POST(T2);
}

#endif /* ISC_SHA2_UNROLL_TRANSFORM */

void isc_sha512_update(isc_sha512_t *context, const isc_uint8_t *data, size_t len) {
	unsigned int	freespace, usedspace;

	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0 && data != (isc_uint8_t*)0);

	usedspace = (unsigned int)((context->bitcount[0] >> 3) %
				   ISC_SHA512_BLOCK_LENGTH);
	if (usedspace > 0) {
		/* Calculate how much free space is available in the buffer */
		freespace = ISC_SHA512_BLOCK_LENGTH - usedspace;

		if (len >= freespace) {
			/* Fill the buffer completely and process it */
			memmove(&context->buffer[usedspace], data, freespace);
			ADDINC128(context->bitcount, freespace << 3);
			len -= freespace;
			data += freespace;
			isc_sha512_transform(context,
					     (isc_uint64_t*)context->buffer);
		} else {
			/* The buffer is not yet full */
			memmove(&context->buffer[usedspace], data, len);
			ADDINC128(context->bitcount, len << 3);
			/* Clean up: */
			usedspace = freespace = 0;
			/* Avoid compiler warnings: */
			POST(usedspace); POST(freespace);
			return;
		}
	}
	while (len >= ISC_SHA512_BLOCK_LENGTH) {
		/* Process as many complete blocks as we can */
		memmove(context->buffer, data, ISC_SHA512_BLOCK_LENGTH);
		isc_sha512_transform(context, (isc_uint64_t*)context->buffer);
		ADDINC128(context->bitcount, ISC_SHA512_BLOCK_LENGTH << 3);
		len -= ISC_SHA512_BLOCK_LENGTH;
		data += ISC_SHA512_BLOCK_LENGTH;
	}
	if (len > 0U) {
		/* There's left-overs, so save 'em */
		memmove(context->buffer, data, len);
		ADDINC128(context->bitcount, len << 3);
	}
	/* Clean up: */
	usedspace = freespace = 0;
	/* Avoid compiler warnings: */
	POST(usedspace); POST(freespace);
}

void isc_sha512_last(isc_sha512_t *context) {
	unsigned int	usedspace;

	usedspace = (unsigned int)((context->bitcount[0] >> 3) %
				    ISC_SHA512_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
	/* Convert FROM host byte order */
	REVERSE64(context->bitcount[0],context->bitcount[0]);
	REVERSE64(context->bitcount[1],context->bitcount[1]);
#endif
	if (usedspace > 0) {
		/* Begin padding with a 1 bit: */
		context->buffer[usedspace++] = 0x80;

		if (usedspace <= ISC_SHA512_SHORT_BLOCK_LENGTH) {
			/* Set-up for the last transform: */
			memset(&context->buffer[usedspace], 0,
			       ISC_SHA512_SHORT_BLOCK_LENGTH - usedspace);
		} else {
			if (usedspace < ISC_SHA512_BLOCK_LENGTH) {
				memset(&context->buffer[usedspace], 0,
				       ISC_SHA512_BLOCK_LENGTH - usedspace);
			}
			/* Do second-to-last transform: */
			isc_sha512_transform(context,
					    (isc_uint64_t*)context->buffer);

			/* And set-up for the last transform: */
			memset(context->buffer, 0, ISC_SHA512_BLOCK_LENGTH - 2);
		}
	} else {
		/* Prepare for final transform: */
		memset(context->buffer, 0, ISC_SHA512_SHORT_BLOCK_LENGTH);

		/* Begin padding with a 1 bit: */
		*context->buffer = 0x80;
	}
	/* Store the length of input data (in bits): */
	*(isc_uint64_t*)&context->buffer[ISC_SHA512_SHORT_BLOCK_LENGTH] = context->bitcount[1];
	*(isc_uint64_t*)&context->buffer[ISC_SHA512_SHORT_BLOCK_LENGTH+8] = context->bitcount[0];

	/* Final transform: */
	isc_sha512_transform(context, (isc_uint64_t*)context->buffer);
}

void isc_sha512_final(isc_uint8_t digest[], isc_sha512_t *context) {
	isc_uint64_t	*d = (isc_uint64_t*)digest;

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		isc_sha512_last(context);

		/* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* Convert TO host byte order */
			int	j;
			for (j = 0; j < 8; j++) {
				REVERSE64(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		memmove(d, context->state, ISC_SHA512_DIGESTLENGTH);
#endif
	}

	/* Zero out state data */
	isc_safe_memwipe(context, sizeof(*context));
}


/*** SHA-384: *********************************************************/
void
isc_sha384_init(isc_sha384_t *context) {
	if (context == (isc_sha384_t *)0) {
		return;
	}
	memmove(context->state, sha384_initial_hash_value,
		ISC_SHA512_DIGESTLENGTH);
	memset(context->buffer, 0, ISC_SHA384_BLOCK_LENGTH);
	context->bitcount[0] = context->bitcount[1] = 0;
}

void
isc_sha384_invalidate(isc_sha384_t *context) {
	isc_safe_memwipe(context, sizeof(*context));
}

void
isc_sha384_update(isc_sha384_t *context, const isc_uint8_t* data, size_t len) {
	isc_sha512_update((isc_sha512_t *)context, data, len);
}

void
isc_sha384_final(isc_uint8_t digest[], isc_sha384_t *context) {
	isc_uint64_t	*d = (isc_uint64_t*)digest;

	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0) {
		isc_sha512_last((isc_sha512_t *)context);

		/* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* Convert TO host byte order */
			int	j;
			for (j = 0; j < 6; j++) {
				REVERSE64(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		memmove(d, context->state, ISC_SHA384_DIGESTLENGTH);
#endif
	}

	/* Zero out state data */
	isc_safe_memwipe(context, sizeof(*context));
}
#endif /* !ISC_PLATFORM_OPENSSLHASH */

/*
 * Constant used by SHA256/384/512_End() functions for converting the
 * digest to a readable hexadecimal character string:
 */
static const char *sha2_hex_digits = "0123456789abcdef";

char *
isc_sha224_end(isc_sha224_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA224_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);

	if (buffer != (char*)0) {
		isc_sha224_final(digest, context);

		for (i = 0; i < ISC_SHA224_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
#if defined(ISC_PLATFORM_OPENSSLHASH) && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_reset(context->ctx);
#elif PKCS11CRYPTO
		pk11_return_session(context);
#else
		isc_safe_memwipe(context, sizeof(*context));
#endif
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha224_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA224_DIGESTSTRINGLENGTH])
{
	isc_sha224_t context;

	isc_sha224_init(&context);
	isc_sha224_update(&context, data, len);
	return (isc_sha224_end(&context, digest));
}

char *
isc_sha256_end(isc_sha256_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA256_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);

	if (buffer != (char*)0) {
		isc_sha256_final(digest, context);

		for (i = 0; i < ISC_SHA256_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
#if defined(ISC_PLATFORM_OPENSSLHASH) && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_reset(context->ctx);
#elif PKCS11CRYPTO
		pk11_return_session(context);
#else
		isc_safe_memwipe(context, sizeof(*context));
#endif
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha256_data(const isc_uint8_t* data, size_t len,
		char digest[ISC_SHA256_DIGESTSTRINGLENGTH])
{
	isc_sha256_t context;

	isc_sha256_init(&context);
	isc_sha256_update(&context, data, len);
	return (isc_sha256_end(&context, digest));
}

char *
isc_sha512_end(isc_sha512_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA512_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);

	if (buffer != (char*)0) {
		isc_sha512_final(digest, context);

		for (i = 0; i < ISC_SHA512_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
#if defined(ISC_PLATFORM_OPENSSLHASH) && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_reset(context->ctx);
#elif PKCS11CRYPTO
		pk11_return_session(context);
#else
		isc_safe_memwipe(context, sizeof(*context));
#endif
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha512_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA512_DIGESTSTRINGLENGTH])
{
	isc_sha512_t 	context;

	isc_sha512_init(&context);
	isc_sha512_update(&context, data, len);
	return (isc_sha512_end(&context, digest));
}

char *
isc_sha384_end(isc_sha384_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA384_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);

	if (buffer != (char*)0) {
		isc_sha384_final(digest, context);

		for (i = 0; i < ISC_SHA384_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
#if defined(ISC_PLATFORM_OPENSSLHASH) && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_reset(context->ctx);
#elif PKCS11CRYPTO
		pk11_return_session(context);
#else
		isc_safe_memwipe(context, sizeof(*context));
#endif
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha384_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA384_DIGESTSTRINGLENGTH])
{
	isc_sha384_t context;

	isc_sha384_init(&context);
	isc_sha384_update(&context, data, len);
	return (isc_sha384_end(&context, digest));
}
