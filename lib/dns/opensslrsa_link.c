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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
#include <openssl/engine.h>
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
#include <openssl/err.h>
#include <openssl/objects.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif
#include <openssl/rsa.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"
#include "openssl_shim.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

static isc_result_t
opensslrsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx;
	const EVP_MD *type = NULL;

	UNUSED(key);
	REQUIRE(dctx->key->key_alg == DST_ALG_RSASHA1 ||
		dctx->key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		dctx->key->key_alg == DST_ALG_RSASHA256 ||
		dctx->key->key_alg == DST_ALG_RSASHA512);

	/*
	 * Reject incorrect RSA key lengths.
	 */
	switch (dctx->key->key_alg) {
	case DST_ALG_RSASHA1:
	case DST_ALG_NSEC3RSASHA1:
		/* From RFC 3110 */
		if (dctx->key->key_size > 4096) {
			return (ISC_R_FAILURE);
		}
		break;
	case DST_ALG_RSASHA256:
		/* From RFC 5702 */
		if (dctx->key->key_size < 512 || dctx->key->key_size > 4096) {
			return (ISC_R_FAILURE);
		}
		break;
	case DST_ALG_RSASHA512:
		/* From RFC 5702 */
		if (dctx->key->key_size < 1024 || dctx->key->key_size > 4096) {
			return (ISC_R_FAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	evp_md_ctx = EVP_MD_CTX_create();
	if (evp_md_ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	switch (dctx->key->key_alg) {
	case DST_ALG_RSASHA1:
	case DST_ALG_NSEC3RSASHA1:
		type = EVP_sha1(); /* SHA1 + RSA */
		break;
	case DST_ALG_RSASHA256:
		type = EVP_sha256(); /* SHA256 + RSA */
		break;
	case DST_ALG_RSASHA512:
		type = EVP_sha512();
		break;
	default:
		UNREACHABLE();
	}

	if (!EVP_DigestInit_ex(evp_md_ctx, type, NULL)) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		return (dst__openssl_toresult3(
			dctx->category, "EVP_DigestInit_ex", ISC_R_FAILURE));
	}
	dctx->ctxdata.evp_md_ctx = evp_md_ctx;

	return (ISC_R_SUCCESS);
}

static void
opensslrsa_destroyctx(dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSASHA1 ||
		dctx->key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		dctx->key->key_alg == DST_ALG_RSASHA256 ||
		dctx->key->key_alg == DST_ALG_RSASHA512);

	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		dctx->ctxdata.evp_md_ctx = NULL;
	}
}

static isc_result_t
opensslrsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSASHA1 ||
		dctx->key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		dctx->key->key_alg == DST_ALG_RSASHA256 ||
		dctx->key->key_alg == DST_ALG_RSASHA512);

	if (!EVP_DigestUpdate(evp_md_ctx, data->base, data->length)) {
		return (dst__openssl_toresult3(
			dctx->category, "EVP_DigestUpdate", ISC_R_FAILURE));
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslrsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	dst_key_t *key = dctx->key;
	isc_region_t r;
	unsigned int siglen = 0;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	EVP_PKEY *pkey = key->keydata.pkey;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSASHA1 ||
		dctx->key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		dctx->key->key_alg == DST_ALG_RSASHA256 ||
		dctx->key->key_alg == DST_ALG_RSASHA512);

	isc_buffer_availableregion(sig, &r);

	if (r.length < (unsigned int)EVP_PKEY_size(pkey)) {
		return (ISC_R_NOSPACE);
	}

	if (!EVP_SignFinal(evp_md_ctx, r.base, &siglen, pkey)) {
		return (dst__openssl_toresult3(dctx->category, "EVP_SignFinal",
					       ISC_R_FAILURE));
	}

	isc_buffer_add(sig, siglen);

	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslrsa_verify2(dst_context_t *dctx, int maxbits, const isc_region_t *sig) {
	dst_key_t *key = dctx->key;
	int status = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa;
	const BIGNUM *e = NULL;
#else
	BIGNUM *e = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	EVP_PKEY *pkey = key->keydata.pkey;
	int bits;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSASHA1 ||
		dctx->key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		dctx->key->key_alg == DST_ALG_RSASHA256 ||
		dctx->key->key_alg == DST_ALG_RSASHA512);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	RSA_get0_key(rsa, NULL, &e, NULL);
	if (e == NULL) {
		return (dst__openssl_toresult(DST_R_VERIFYFAILURE));
	}
	bits = BN_num_bits(e);
	RSA_free(rsa);
#else
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
	if (e == NULL) {
		return (dst__openssl_toresult(DST_R_VERIFYFAILURE));
	}
	bits = BN_num_bits(e);
	BN_free(e);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (bits > maxbits && maxbits != 0) {
		return (DST_R_VERIFYFAILURE);
	}

	status = EVP_VerifyFinal(evp_md_ctx, sig->base, sig->length, pkey);
	switch (status) {
	case 1:
		return (ISC_R_SUCCESS);
	case 0:
		return (dst__openssl_toresult(DST_R_VERIFYFAILURE));
	default:
		return (dst__openssl_toresult3(dctx->category,
					       "EVP_VerifyFinal",
					       DST_R_VERIFYFAILURE));
	}
}

static isc_result_t
opensslrsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	return (opensslrsa_verify2(dctx, 0, sig));
}

static bool
opensslrsa_compare(const dst_key_t *key1, const dst_key_t *key2) {
	bool ret;
	int status;
	EVP_PKEY *pkey1 = key1->keydata.pkey;
	EVP_PKEY *pkey2 = key2->keydata.pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa1 = NULL;
	RSA *rsa2 = NULL;
	const BIGNUM *d1 = NULL, *d2 = NULL;
	const BIGNUM *p1 = NULL, *p2 = NULL;
	const BIGNUM *q1 = NULL, *q2 = NULL;
#else
	BIGNUM *d1 = NULL, *d2 = NULL;
	BIGNUM *p1 = NULL, *p2 = NULL;
	BIGNUM *q1 = NULL, *q2 = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (pkey1 == NULL && pkey2 == NULL) {
		return (true);
	} else if (pkey1 == NULL || pkey2 == NULL) {
		return (false);
	}

	/* `EVP_PKEY_eq` checks only the public key components and paramters. */
	status = EVP_PKEY_eq(pkey1, pkey2);
	if (status != 1) {
		DST_RET(false);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa1 = EVP_PKEY_get1_RSA(pkey1);
	rsa2 = EVP_PKEY_get1_RSA(pkey2);
	if (rsa1 == NULL && rsa2 == NULL) {
		DST_RET(true);
	} else if (rsa1 == NULL || rsa2 == NULL) {
		DST_RET(false);
	}
	RSA_get0_key(rsa1, NULL, NULL, &d1);
	RSA_get0_key(rsa2, NULL, NULL, &d2);
#else
	EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_RSA_D, &d1);
	EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_D, &d2);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (d1 != NULL || d2 != NULL) {
		if (d1 == NULL || d2 == NULL) {
			DST_RET(false);
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		RSA_get0_factors(rsa1, &p1, &q1);
		RSA_get0_factors(rsa2, &p2, &q2);
#else
		EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_RSA_FACTOR1, &p1);
		EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_RSA_FACTOR2, &q1);
		EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_FACTOR1, &p2);
		EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_FACTOR2, &q2);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

		if (BN_cmp(d1, d2) != 0 || BN_cmp(p1, p2) != 0 ||
		    BN_cmp(q1, q2) != 0) {
			DST_RET(false);
		}
	}

	ret = true;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa1 != NULL) {
		RSA_free(rsa1);
	}
	if (rsa2 != NULL) {
		RSA_free(rsa2);
	}
#else
	if (d1 != NULL) {
		BN_clear_free(d1);
	}
	if (d2 != NULL) {
		BN_clear_free(d2);
	}
	if (p1 != NULL) {
		BN_clear_free(p1);
	}
	if (p2 != NULL) {
		BN_clear_free(p2);
	}
	if (q1 != NULL) {
		BN_clear_free(q1);
	}
	if (q2 != NULL) {
		BN_clear_free(q2);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	return (ret);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static int
progress_cb(int p, int n, BN_GENCB *cb) {
	union {
		void *dptr;
		void (*fptr)(int);
	} u;

	UNUSED(n);

	u.dptr = BN_GENCB_get_arg(cb);
	if (u.fptr != NULL) {
		u.fptr(p);
	}
	return (1);
}
#else
static int
progress_cb(EVP_PKEY_CTX *ctx) {
	union {
		void *dptr;
		void (*fptr)(int);
	} u;

	u.dptr = EVP_PKEY_CTX_get_app_data(ctx);
	if (u.fptr != NULL) {
		int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
		u.fptr(p);
	}
	return (1);
}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

static isc_result_t
opensslrsa_generate(dst_key_t *key, int exp, void (*callback)(int)) {
	isc_result_t ret;
	union {
		void *dptr;
		void (*fptr)(int);
	} u;
	BIGNUM *e = BN_new();
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = RSA_new();
	EVP_PKEY *pkey = EVP_PKEY_new();
#if !HAVE_BN_GENCB_NEW
	BN_GENCB _cb;
#endif /* !HAVE_BN_GENCB_NEW */
	BN_GENCB *cb = NULL;
#else
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY *pkey = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (e == NULL || rsa == NULL || pkey == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
#else
	if (e == NULL || ctx == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	/*
	 * Reject incorrect RSA key lengths.
	 */
	switch (key->key_alg) {
	case DST_ALG_RSASHA1:
	case DST_ALG_NSEC3RSASHA1:
		/* From RFC 3110 */
		if (key->key_size > 4096) {
			DST_RET(DST_R_INVALIDPARAM);
		}
		break;
	case DST_ALG_RSASHA256:
		/* From RFC 5702 */
		if (key->key_size < 512 || key->key_size > 4096) {
			DST_RET(DST_R_INVALIDPARAM);
		}
		break;
	case DST_ALG_RSASHA512:
		/* From RFC 5702 */
		if (key->key_size < 1024 || key->key_size > 4096) {
			DST_RET(DST_R_INVALIDPARAM);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (exp == 0) {
		/* RSA_F4 0x10001 */
		BN_set_bit(e, 0);
		BN_set_bit(e, 16);
	} else {
		/* (phased-out) F5 0x100000001 */
		BN_set_bit(e, 0);
		BN_set_bit(e, 32);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (callback != NULL) {
		cb = BN_GENCB_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		if (cb == NULL) {
			DST_RET(dst__openssl_toresult(ISC_R_NOMEMORY));
		}
#endif /* if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	* !defined(LIBRESSL_VERSION_NUMBER) */
		u.fptr = callback;
		BN_GENCB_set(cb, progress_cb, u.dptr);
	}

	if (RSA_generate_key_ex(rsa, key->key_size, e, cb) != 1) {
		DST_RET(dst__openssl_toresult2("RSA_generate_key_ex",
					       DST_R_OPENSSLFAILURE));
	}
#else
	if (EVP_PKEY_keygen_init(ctx) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)key->key_size) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (callback != NULL) {
		u.fptr = callback;
		EVP_PKEY_CTX_set_app_data(ctx, u.dptr);
		EVP_PKEY_CTX_set_cb(ctx, progress_cb);
	}

	if (EVP_PKEY_keygen(ctx, &pkey) != 1 || pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen",
					       DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	key->keydata.pkey = pkey;
	pkey = NULL;
	ret = ISC_R_SUCCESS;

err:
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa != NULL) {
		RSA_free(rsa);
	}
	if (cb != NULL) {
		BN_GENCB_free(cb);
	}
#else
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	if (e != NULL) {
		BN_free(e);
	}
	return (ret);
}

static bool
opensslrsa_isprivate(const dst_key_t *key) {
	bool ret;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa;
	const BIGNUM *d = NULL;
#else
	BIGNUM *d = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	REQUIRE(key->key_alg == DST_ALG_RSASHA1 ||
		key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		key->key_alg == DST_ALG_RSASHA256 ||
		key->key_alg == DST_ALG_RSASHA512);

	pkey = key->keydata.pkey;
	if (pkey == NULL) {
		return (false);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = EVP_PKEY_get1_RSA(pkey);
	INSIST(rsa != NULL);

	if (RSA_test_flags(rsa, RSA_FLAG_EXT_PKEY) != 0) {
		ret = true;
	} else {
		RSA_get0_key(rsa, NULL, NULL, &d);
		ret = (d != NULL);
	}
	RSA_free(rsa);
#else
	ret = (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) == 1 &&
	       d != NULL);
	if (d != NULL) {
		BN_clear_free(d);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	return (ret);
}

static void
opensslrsa_destroy(dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
		key->keydata.pkey = NULL;
	}
}

static isc_result_t
opensslrsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;
	unsigned int e_bytes;
	unsigned int mod_bytes;
	isc_result_t ret;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa;
	const BIGNUM *e = NULL, *n = NULL;
#else
	BIGNUM *e = NULL, *n = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	REQUIRE(key->keydata.pkey != NULL);

	pkey = key->keydata.pkey;
	isc_buffer_availableregion(data, &r);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	RSA_get0_key(rsa, &n, &e, NULL);
#else
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
	if (e == NULL || n == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	mod_bytes = BN_num_bytes(n);
	e_bytes = BN_num_bytes(e);

	if (e_bytes < 256) { /*%< key exponent is <= 2040 bits */
		if (r.length < 1) {
			DST_RET(ISC_R_NOSPACE);
		}
		isc_buffer_putuint8(data, (uint8_t)e_bytes);
		isc_region_consume(&r, 1);
	} else {
		if (r.length < 3) {
			DST_RET(ISC_R_NOSPACE);
		}
		isc_buffer_putuint8(data, 0);
		isc_buffer_putuint16(data, (uint16_t)e_bytes);
		isc_region_consume(&r, 3);
	}

	if (r.length < e_bytes + mod_bytes) {
		DST_RET(ISC_R_NOSPACE);
	}

	BN_bn2bin(e, r.base);
	isc_region_consume(&r, e_bytes);
	BN_bn2bin(n, r.base);
	isc_region_consume(&r, mod_bytes);

	isc_buffer_add(data, e_bytes + mod_bytes);

	ret = ISC_R_SUCCESS;
err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa != NULL) {
		RSA_free(rsa);
	}
#else
	if (e != NULL) {
		BN_free(e);
	}
	if (n != NULL) {
		BN_free(n);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	return (ret);
}

static isc_result_t
opensslrsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	int status;
	isc_region_t r;
	unsigned int e_bytes;
	unsigned int length;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = NULL;
#else
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	EVP_PKEY *pkey = NULL;
	BIGNUM *e = NULL, *n = NULL;

	REQUIRE(key->key_alg == DST_ALG_RSASHA1 ||
		key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		key->key_alg == DST_ALG_RSASHA256 ||
		key->key_alg == DST_ALG_RSASHA512);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		DST_RET(ISC_R_SUCCESS);
	}
	length = r.length;
	if (r.length < 1) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}

	e_bytes = *r.base;
	isc_region_consume(&r, 1);

	if (e_bytes == 0) {
		if (r.length < 2) {
			DST_RET(DST_R_INVALIDPUBLICKEY);
		}
		e_bytes = (*r.base) << 8;
		isc_region_consume(&r, 1);
		e_bytes += *r.base;
		isc_region_consume(&r, 1);
	}

	if (r.length < e_bytes) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}
	e = BN_bin2bn(r.base, e_bytes, NULL);
	isc_region_consume(&r, e_bytes);
	n = BN_bin2bn(r.base, r.length, NULL);

	key->key_size = BN_num_bits(n);

	isc_buffer_forward(data, length);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = RSA_new();
	if (rsa == NULL) {
		DST_RET(dst__openssl_toresult2("RSA_new",
					       DST_R_OPENSSLFAILURE));
	}
	status = RSA_set0_key(rsa, n, e, NULL);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("RSA_set0_key",
					       DST_R_OPENSSLFAILURE));
	}

	/* These are now managed by OpenSSL. */
	n = NULL;
	e = NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_new",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_set1_RSA(pkey, rsa);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_set1_RSA",
					       DST_R_OPENSSLFAILURE));
	}
#else
	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_new",
					       DST_R_OPENSSLFAILURE));
	}
	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1)
	{
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_push_BN",
					       DST_R_OPENSSLFAILURE));
	}
	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_to_param",
					       DST_R_OPENSSLFAILURE));
	}
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_fromdata_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_fromdata_init",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
	if (status != 1 || pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_fromdata",
					       DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	key->keydata.pkey = pkey;
	pkey = NULL;
	ret = ISC_R_SUCCESS;

err:

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa != NULL) {
		RSA_free(rsa);
	}
#else
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
	if (params != NULL) {
		OSSL_PARAM_free(params);
	}
	if (bld != NULL) {
		OSSL_PARAM_BLD_free(bld);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	if (n != NULL) {
		BN_free(n);
	}
	if (e != NULL) {
		BN_free(e);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}

	return (ret);
}

static isc_result_t
opensslrsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv = { 0 };
	unsigned char *bufs[8] = { NULL };
	unsigned short i = 0;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = NULL;
	const BIGNUM *n = NULL, *e = NULL, *d = NULL;
	const BIGNUM *p = NULL, *q = NULL;
	const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
#else
	BIGNUM *n = NULL, *e = NULL, *d = NULL;
	BIGNUM *p = NULL, *q = NULL;
	BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (key->keydata.pkey == NULL) {
		DST_RET(DST_R_NULLKEY);
	}

	if (key->external) {
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	pkey = key->keydata.pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	RSA_get0_key(rsa, &n, &e, &d);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
#else
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (n == NULL || e == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	priv.elements[i].tag = TAG_RSA_MODULUS;
	priv.elements[i].length = BN_num_bytes(n);
	bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
	BN_bn2bin(n, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_PUBLICEXPONENT;
	priv.elements[i].length = BN_num_bytes(e);
	bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
	BN_bn2bin(e, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	if (d != NULL) {
		priv.elements[i].tag = TAG_RSA_PRIVATEEXPONENT;
		priv.elements[i].length = BN_num_bytes(d);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(d, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (p != NULL) {
		priv.elements[i].tag = TAG_RSA_PRIME1;
		priv.elements[i].length = BN_num_bytes(p);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(p, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (q != NULL) {
		priv.elements[i].tag = TAG_RSA_PRIME2;
		priv.elements[i].length = BN_num_bytes(q);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(q, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (dmp1 != NULL) {
		priv.elements[i].tag = TAG_RSA_EXPONENT1;
		priv.elements[i].length = BN_num_bytes(dmp1);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(dmp1, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (dmq1 != NULL) {
		priv.elements[i].tag = TAG_RSA_EXPONENT2;
		priv.elements[i].length = BN_num_bytes(dmq1);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(dmq1, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (iqmp != NULL) {
		priv.elements[i].tag = TAG_RSA_COEFFICIENT;
		priv.elements[i].length = BN_num_bytes(iqmp);
		INSIST(i < ARRAY_SIZE(bufs));
		bufs[i] = isc_mem_get(key->mctx, priv.elements[i].length);
		BN_bn2bin(iqmp, bufs[i]);
		priv.elements[i].data = bufs[i];
		i++;
	}

	if (key->engine != NULL) {
		priv.elements[i].tag = TAG_RSA_ENGINE;
		priv.elements[i].length = (unsigned short)strlen(key->engine) +
					  1;
		priv.elements[i].data = (unsigned char *)key->engine;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_RSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	for (i = 0; i < ARRAY_SIZE(bufs); i++) {
		if (bufs[i] != NULL) {
			isc_mem_put(key->mctx, bufs[i],
				    priv.elements[i].length);
		}
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA_free(rsa);
#else
	if (n != NULL) {
		BN_free(n);
	}
	if (e != NULL) {
		BN_free(e);
	}
	if (d != NULL) {
		BN_clear_free(d);
	}
	if (p != NULL) {
		BN_clear_free(p);
	}
	if (q != NULL) {
		BN_clear_free(q);
	}
	if (dmp1 != NULL) {
		BN_clear_free(dmp1);
	}
	if (dmq1 != NULL) {
		BN_clear_free(dmq1);
	}
	if (iqmp != NULL) {
		BN_clear_free(iqmp);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	return (ret);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static isc_result_t
rsa_check(RSA *rsa, RSA *pub) {
	const BIGNUM *n1 = NULL, *n2 = NULL;
	const BIGNUM *e1 = NULL, *e2 = NULL;
	BIGNUM *n = NULL, *e = NULL;

	/*
	 * Public parameters should be the same but if they are not set
	 * copy them from the public key.
	 */
	if (pub != NULL) {
		RSA_get0_key(rsa, &n1, &e1, NULL);
		RSA_get0_key(pub, &n2, &e2, NULL);
		if (n1 != NULL) {
			if (BN_cmp(n1, n2) != 0) {
				return (DST_R_INVALIDPRIVATEKEY);
			}
		} else {
			n = BN_dup(n2);
		}
		if (e1 != NULL) {
			if (BN_cmp(e1, e2) != 0) {
				return (DST_R_INVALIDPRIVATEKEY);
			}
		} else {
			e = BN_dup(e2);
		}
		if (RSA_set0_key(rsa, n, e, NULL) == 0) {
			if (n != NULL) {
				BN_free(n);
			}
			if (e != NULL) {
				BN_free(e);
			}
		}
	}

	RSA_get0_key(rsa, &n1, &e1, NULL);
	if (n1 == NULL || e1 == NULL) {
		return (DST_R_INVALIDPRIVATEKEY);
	}

	return (ISC_R_SUCCESS);
}
#else
static isc_result_t
rsa_check(EVP_PKEY *pkey, EVP_PKEY *pubpkey) {
	isc_result_t ret = ISC_R_FAILURE;
	int status;
	BIGNUM *n1 = NULL, *n2 = NULL;
	BIGNUM *e1 = NULL, *e2 = NULL;

	/* Try to get the public key from pkey. */
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n1);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e1);

	/* Check if `pubpkey` exists and that we can extract its public key. */
	if (pubpkey == NULL ||
	    EVP_PKEY_get_bn_param(pubpkey, OSSL_PKEY_PARAM_RSA_N, &n2) != 1 ||
	    n2 == NULL ||
	    EVP_PKEY_get_bn_param(pubpkey, OSSL_PKEY_PARAM_RSA_E, &e2) != 1 ||
	    e2 == NULL)
	{
		if (n1 == NULL || e1 == NULL) {
			/* No public key both in `pkey` and in `pubpkey`. */
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		} else {
			/*
			 * `pkey` has a public key, but there is no public key
			 * in `pubpkey` to check against.
			 */
			DST_RET(ISC_R_SUCCESS);
		}
	}

	/*
	 * If `pkey` doesn't have a public key then we will copy it from
	 * `pubpkey`.
	 */
	if (n1 == NULL || e1 == NULL) {
		status = EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n2);
		if (status != 1) {
			DST_RET(ISC_R_FAILURE);
		}

		status = EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e2);
		if (status != 1) {
			DST_RET(ISC_R_FAILURE);
		}
	}

	if (EVP_PKEY_eq(pkey, pubpkey) == 1) {
		DST_RET(ISC_R_SUCCESS);
	}

err:
	if (n1 != NULL) {
		BN_free(n1);
	}
	if (n2 != NULL) {
		BN_free(n2);
	}
	if (e1 != NULL) {
		BN_free(e1);
	}
	if (e2 != NULL) {
		BN_free(e2);
	}

	return (ret);
}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

static isc_result_t
opensslrsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	int i;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = NULL, *pubrsa = NULL;
	const BIGNUM *ex = NULL;
#else
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	BIGNUM *ex = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	ENGINE *ep = NULL;
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	isc_mem_t *mctx = key->mctx;
	const char *engine = NULL, *label = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *n = NULL, *e = NULL, *d = NULL;
	BIGNUM *p = NULL, *q = NULL;
	BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	REQUIRE(key->key_alg == DST_ALG_RSASHA1 ||
		key->key_alg == DST_ALG_NSEC3RSASHA1 ||
		key->key_alg == DST_ALG_RSASHA256 ||
		key->key_alg == DST_ALG_RSASHA512);

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_RSA, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkey = pub->keydata.pkey;
		pub->keydata.pkey = NULL;
		key->key_size = pub->key_size;
		DST_RET(ISC_R_SUCCESS);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (pub != NULL && pub->keydata.pkey != NULL) {
		pubrsa = EVP_PKEY_get1_RSA(pub->keydata.pkey);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_RSA_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_RSA_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		default:
			break;
		}
	}

	/*
	 * Is this key stored in a HSM?
	 * See if we can fetch it.
	 */
	if (label != NULL) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
		if (engine == NULL) {
			DST_RET(DST_R_NOENGINE);
		}
		ep = dst__openssl_getengine(engine);
		if (ep == NULL) {
			DST_RET(dst__openssl_toresult(DST_R_NOENGINE));
		}
		pkey = ENGINE_load_private_key(ep, label, NULL, NULL);
		if (pkey == NULL) {
			DST_RET(dst__openssl_toresult2("ENGINE_load_private_"
						       "key",
						       ISC_R_NOTFOUND));
		}
		key->engine = isc_mem_strdup(key->mctx, engine);
		key->label = isc_mem_strdup(key->mctx, label);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		rsa = EVP_PKEY_get1_RSA(pkey);
		if (rsa == NULL) {
			DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
		}
		if (rsa_check(rsa, pubrsa) != ISC_R_SUCCESS) {
			DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
		RSA_get0_key(rsa, NULL, &ex, NULL);
#else
		if (rsa_check(pkey, pub != NULL ? pub->keydata.pkey : NULL) !=
		    ISC_R_SUCCESS) {
			DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &ex) !=
		    1) {
			DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

		if (ex == NULL) {
			DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
		if (BN_num_bits(ex) > RSA_MAX_PUBEXP_BITS) {
			DST_RET(ISC_R_RANGE);
		}

		key->key_size = EVP_PKEY_bits(pkey);
		key->keydata.pkey = pkey;
		pkey = NULL;
		DST_RET(ISC_R_SUCCESS);
#else  /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
		UNUSED(engine);
		UNUSED(ex);
		DST_RET(DST_R_NOENGINE);
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	}

	for (i = 0; i < priv.nelements; i++) {
		BIGNUM *bn;
		switch (priv.elements[i].tag) {
		case TAG_RSA_ENGINE:
			continue;
		case TAG_RSA_LABEL:
			continue;
		default:
			bn = BN_bin2bn(priv.elements[i].data,
				       priv.elements[i].length, NULL);
			if (bn == NULL) {
				DST_RET(ISC_R_NOMEMORY);
			}
			switch (priv.elements[i].tag) {
			case TAG_RSA_MODULUS:
				n = bn;
				break;
			case TAG_RSA_PUBLICEXPONENT:
				e = bn;
				break;
			case TAG_RSA_PRIVATEEXPONENT:
				d = bn;
				break;
			case TAG_RSA_PRIME1:
				p = bn;
				break;
			case TAG_RSA_PRIME2:
				q = bn;
				break;
			case TAG_RSA_EXPONENT1:
				dmp1 = bn;
				break;
			case TAG_RSA_EXPONENT2:
				dmq1 = bn;
				break;
			case TAG_RSA_COEFFICIENT:
				iqmp = bn;
				break;
			default:
				BN_clear_free(bn);
			}
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = RSA_new();
	if (rsa == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (RSA_set0_key(rsa, n, e, d) == 0) {
		if (n != NULL) {
			BN_free(n);
		}
		if (e != NULL) {
			BN_free(e);
		}
		if (d != NULL) {
			BN_clear_free(d);
		}
	}
	if (RSA_set0_factors(rsa, p, q) == 0) {
		if (p != NULL) {
			BN_clear_free(p);
		}
		if (q != NULL) {
			BN_clear_free(q);
		}
	}
	if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) == 0) {
		if (dmp1 != NULL) {
			BN_clear_free(dmp1);
		}
		if (dmq1 != NULL) {
			BN_clear_free(dmq1);
		}
		if (iqmp != NULL) {
			BN_clear_free(iqmp);
		}
	}
	if (rsa_check(rsa, pubrsa) != ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
#else
	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (n != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (e != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (d != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (p != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) != 1)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (q != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) != 1)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (dmp1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) !=
		    1)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (dmq1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) !=
		    1)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (iqmp != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
				   iqmp) != 1)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1 ||
	    pkey == NULL)
	{
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	if (rsa_check(pkey, pub != NULL ? pub->keydata.pkey : NULL) !=
	    ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (BN_num_bits(e) > RSA_MAX_PUBEXP_BITS) {
		DST_RET(ISC_R_RANGE);
	}

	key->key_size = BN_num_bits(n);
	key->keydata.pkey = pkey;
	pkey = NULL;

err:
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa != NULL) {
		RSA_free(rsa);
	}
	if (pubrsa != NULL) {
		RSA_free(pubrsa);
	}
#else
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
	if (params != NULL) {
		OSSL_PARAM_free(params);
	}
	if (bld != NULL) {
		OSSL_PARAM_BLD_free(bld);
	}
	if (ex != NULL) {
		BN_free(ex);
	}
	if (e != NULL) {
		BN_free(e);
	}
	if (n != NULL) {
		BN_free(n);
	}
	if (d != NULL) {
		BN_clear_free(d);
	}
	if (p != NULL) {
		BN_clear_free(p);
	}
	if (q != NULL) {
		BN_clear_free(q);
	}
	if (dmp1 != NULL) {
		BN_clear_free(dmp1);
	}
	if (dmq1 != NULL) {
		BN_clear_free(dmq1);
	}
	if (iqmp != NULL) {
		BN_clear_free(iqmp);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	if (ret != ISC_R_SUCCESS) {
		key->keydata.generic = NULL;
	}

	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return (ret);
}

static isc_result_t
opensslrsa_fromlabel(dst_key_t *key, const char *engine, const char *label,
		     const char *pin) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	ENGINE *e = NULL;
	isc_result_t ret = ISC_R_SUCCESS;
	EVP_PKEY *pkey = NULL, *pubpkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = NULL, *pubrsa = NULL;
	const BIGNUM *ex = NULL;
#else
	BIGNUM *ex = NULL;
#endif

	UNUSED(pin);

	if (engine == NULL) {
		DST_RET(DST_R_NOENGINE);
	}
	e = dst__openssl_getengine(engine);
	if (e == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_NOENGINE));
	}

	pubpkey = ENGINE_load_public_key(e, label, NULL, NULL);
	if (pubpkey == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_public_key",
					       DST_R_OPENSSLFAILURE));
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	pubrsa = EVP_PKEY_get1_RSA(pubpkey);
	if (pubrsa == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	pkey = ENGINE_load_private_key(e, label, NULL, NULL);
	if (pkey == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_private_key",
					       DST_R_OPENSSLFAILURE));
	}

	key->engine = isc_mem_strdup(key->mctx, engine);
	key->label = isc_mem_strdup(key->mctx, label);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (rsa_check(rsa, pubrsa) != ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
	RSA_get0_key(rsa, NULL, &ex, NULL);
#else
	if (rsa_check(pkey, pubpkey) != ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &ex) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	if (ex == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
	if (BN_num_bits(ex) > RSA_MAX_PUBEXP_BITS) {
		DST_RET(ISC_R_RANGE);
	}

	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkey = pkey;
	pkey = NULL;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa != NULL) {
		RSA_free(rsa);
	}
	if (pubrsa != NULL) {
		RSA_free(pubrsa);
	}
#else
	if (ex != NULL) {
		BN_free(ex);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (pubpkey != NULL) {
		EVP_PKEY_free(pubpkey);
	}
	return (ret);
#else  /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	UNUSED(key);
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pin);
	return (DST_R_NOENGINE);
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
}

static dst_func_t opensslrsa_functions = {
	opensslrsa_createctx,
	NULL, /*%< createctx2 */
	opensslrsa_destroyctx,
	opensslrsa_adddata,
	opensslrsa_sign,
	opensslrsa_verify,
	opensslrsa_verify2,
	NULL, /*%< computesecret */
	opensslrsa_compare,
	NULL, /*%< paramcompare */
	opensslrsa_generate,
	opensslrsa_isprivate,
	opensslrsa_destroy,
	opensslrsa_todns,
	opensslrsa_fromdns,
	opensslrsa_tofile,
	opensslrsa_parse,
	NULL, /*%< cleanup */
	opensslrsa_fromlabel,
	NULL, /*%< dump */
	NULL, /*%< restore */
};

isc_result_t
dst__opensslrsa_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	UNUSED(algorithm);

	if (*funcp == NULL) {
		*funcp = &opensslrsa_functions;
	}
	return (ISC_R_SUCCESS);
}
