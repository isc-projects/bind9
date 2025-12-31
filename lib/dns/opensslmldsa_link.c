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

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

/*
 * draft-westerbaan-dnssec-mldsa uses pure ML-DSA-44 with an empty context.
 * ML-DSA hashes the message with SHAKE256 before signing it (FIPS 204
 * Algorithm 7 step 6, Algorithm 8 step 7):
 *
 *	tr = H(pk, 64)
 *	mu = H(tr || M', 64), where M' = 0 || |ctx| || ctx || M
 *
 * so mu is computed incrementally as the data is added, and the provider
 * is handed mu instead of the message.  Hedged signing is left at the
 * OpenSSL default.
 */
#define MLDSA_TR_SIZE 64
#define MLDSA_MU_SIZE 64

static const unsigned char mldsa_prefix[] = { 0x00, 0x00 };

static void
opensslmldsa__setkey(dst_key_t *key, EVP_PKEY *pk, EVP_PKEY *sk,
		     uint8_t *seed) {
	key->key_size = DNS_KEY_MLDSA44SIZE * 8;
	key->keydata.pkeypair.pub = pk;
	key->keydata.pkeypair.priv = sk;
	key->keydata.pkeypair.seed = seed;
}

static isc_result_t
opensslmldsa__getpk(dst_key_t *key, unsigned char *pk, size_t prlen) {
	size_t len = prlen;
	int r = EVP_PKEY_get_raw_public_key(key->keydata.pkeypair.pub, pk,
					    &len);
	if (r != 1) {
		return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
	}
	INSIST(len == prlen);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa__addpk(dst_context_t *dctx, EVP_MD_CTX *ctx, unsigned char *pk,
		    size_t pklen, unsigned char *tr, size_t trlen) {
	int r = EVP_DigestInit_ex(ctx, isc__crypto_md[ISC_MD_SHAKE256], NULL);
	if (r != 1) {
		goto cleanup;
	}

	r = EVP_DigestUpdate(ctx, pk, pklen);
	if (r != 1) {
		goto cleanup;
	}

	r = EVP_DigestFinalXOF(ctx, tr, trlen);
	if (r != 1) {
		goto cleanup;
	}

	return ISC_R_SUCCESS;

cleanup:
	return dst__openssl_toresult3(dctx->category, "SHAKE256(pk)",
				      ISC_R_FAILURE);
}

static isc_result_t
opensslmldsa__addtr(dst_context_t *dctx, EVP_MD_CTX *ctx, unsigned char *tr,
		    size_t trlen) {
	int r = EVP_DigestInit_ex(ctx, isc__crypto_md[ISC_MD_SHAKE256], NULL);
	if (r != 1) {
		goto cleanup;
	}
	r = EVP_DigestUpdate(ctx, tr, trlen);
	if (r != 1) {
		goto cleanup;
	}
	r = EVP_DigestUpdate(ctx, mldsa_prefix, sizeof(mldsa_prefix));
	if (r != 1) {
		goto cleanup;
	}

	return ISC_R_SUCCESS;
cleanup:
	return dst__openssl_toresult3(dctx->category, "SHAKE256(tr)",
				      ISC_R_FAILURE);
}

static isc_result_t
opensslmldsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	REQUIRE(key->key_alg == DST_ALG_MLDSA44);

	isc_result_t result = ISC_R_SUCCESS;
	EVP_MD_CTX *ctx = NULL;
	unsigned char pk[DNS_KEY_MLDSA44SIZE];
	unsigned char tr[MLDSA_TR_SIZE];

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}

	CHECK(opensslmldsa__getpk(key, pk, sizeof(pk)));
	CHECK(opensslmldsa__addpk(dctx, ctx, pk, sizeof(pk), tr, sizeof(tr)));
	CHECK(opensslmldsa__addtr(dctx, ctx, tr, sizeof(tr)));

	dctx->ctxdata.evp_md_ctx = MOVE_OWNERSHIP(ctx);

cleanup:
	EVP_MD_CTX_free(ctx);
	return result;
}

static void
opensslmldsa_destroyctx(dst_context_t *dctx) {
	EVP_MD_CTX *ctx = MOVE_OWNERSHIP(dctx->ctxdata.evp_md_ctx);
	EVP_MD_CTX_free(ctx);
}

static isc_result_t
opensslmldsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	int r = EVP_DigestUpdate(dctx->ctxdata.evp_md_ctx, data->base,
				 data->length);
	if (r != 1) {
		return dst__openssl_toresult3(
			dctx->category, "EVP_DigestUpdate", ISC_R_FAILURE);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_region_t target;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pkey = dctx->key->keydata.pkeypair.priv;
	unsigned char mu[MLDSA_MU_SIZE];
	size_t siglen = DNS_SIG_MLDSA44SIZE;
	int external_mu = 1;
	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, &external_mu),
		OSSL_PARAM_END,
	};

	if (pkey == NULL) {
		return DST_R_NULLKEY;
	}
	isc_buffer_availableregion(sig, &target);
	if (target.length < siglen) {
		return ISC_R_NOSPACE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}

	int r = EVP_DigestFinalXOF(dctx->ctxdata.evp_md_ctx, mu, sizeof(mu));
	if (r != 1) {
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestFinalXOF",
					       DST_R_SIGNFAILURE));
	}

	r = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestSignInit_ex",
					       DST_R_SIGNFAILURE));
	}

	r = EVP_DigestSign(ctx, target.base, &siglen, mu, sizeof(mu));
	if (r != 1) {
		CLEANUP(dst__openssl_toresult3(dctx->category, "EVP_DigestSign",
					       DST_R_SIGNFAILURE));
	}
	INSIST(siglen == DNS_SIG_MLDSA44SIZE);
	isc_buffer_add(sig, siglen);

cleanup:
	EVP_MD_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t result = ISC_R_SUCCESS;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pkey = dctx->key->keydata.pkeypair.pub;
	unsigned char mu[MLDSA_MU_SIZE];
	int external_mu = 1;
	const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, &external_mu),
		OSSL_PARAM_END,
	};

	if (sig->length != DNS_SIG_MLDSA44SIZE) {
		return DST_R_VERIFYFAILURE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}

	int r = EVP_DigestFinalXOF(dctx->ctxdata.evp_md_ctx, mu, sizeof(mu));
	if (r != 1) {
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestFinalXOF",
					       DST_R_VERIFYFAILURE));
	}

	r = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestVerifyInit_ex",
					       DST_R_VERIFYFAILURE));
	}

	r = EVP_DigestVerify(ctx, sig->base, sig->length, mu, sizeof(mu));
	if (r != 1) {
		CLEANUP(dst__openssl_toresult(DST_R_VERIFYFAILURE));
	}

cleanup:
	EVP_MD_CTX_free(ctx);
	return result;
}

static void
opensslmldsa_destroy(dst_key_t *key) {
	if (key->keydata.pkeypair.seed != NULL) {
		isc_safe_memwipe(key->keydata.pkeypair.seed,
				 DNS_KEY_MLDSA44SEEDSIZE);
		isc_mem_put(key->mctx, key->keydata.pkeypair.seed,
			    DNS_KEY_MLDSA44SEEDSIZE);
	}
	dst__openssl_keypair_destroy(key);
}

static isc_result_t
opensslmldsa_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		      void (*callback ISC_ATTR_UNUSED)(int)) {
	isc_result_t result = ISC_R_SUCCESS;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	uint8_t *seed = NULL;
	OSSL_PARAM params[2];

	if (key->label != NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					      DST_R_OPENSSLFAILURE);
	}
	int r = EVP_PKEY_keygen_init(ctx);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_keygen_init",
					       DST_R_OPENSSLFAILURE));
	}

	/*
	 * Draw the seed from the same DRBG the provider would use and let
	 * the provider generate the key from it, so that we know the seed.
	 */
	seed = isc_mem_get(key->mctx, DNS_KEY_MLDSA44SEEDSIZE);
	r = RAND_priv_bytes_ex(NULL, seed, DNS_KEY_MLDSA44SEEDSIZE, 0);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("RAND_priv_bytes_ex",
					       DST_R_OPENSSLFAILURE));
	}
	params[0] = OSSL_PARAM_construct_octet_string(
		OSSL_PKEY_PARAM_ML_DSA_SEED, seed, DNS_KEY_MLDSA44SEEDSIZE);
	params[1] = OSSL_PARAM_construct_end();
	r = EVP_PKEY_CTX_set_params(ctx, params);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_CTX_set_params",
					       DST_R_OPENSSLFAILURE));
	}

	r = EVP_PKEY_generate(ctx, &pkey);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_generate",
					       DST_R_OPENSSLFAILURE));
	}

	opensslmldsa__setkey(key, pkey, pkey, seed);
	(void)MOVE_OWNERSHIP(pkey);
	(void)MOVE_OWNERSHIP(seed);

cleanup:
	if (seed != NULL) {
		isc_safe_memwipe(seed, DNS_KEY_MLDSA44SEEDSIZE);
		isc_mem_put(key->mctx, seed, DNS_KEY_MLDSA44SEEDSIZE);
	}
	EVP_PKEY_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t target;
	size_t len = DNS_KEY_MLDSA44SIZE;

	isc_buffer_availableregion(data, &target);
	if (target.length < len) {
		return ISC_R_NOSPACE;
	}
	if (EVP_PKEY_get_raw_public_key(key->keydata.pkeypair.pub, target.base,
					&len) != 1)
	{
		return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
	}
	INSIST(len == DNS_KEY_MLDSA44SIZE);
	isc_buffer_add(data, len);
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_region_t source;
	EVP_PKEY *pkey = NULL;

	isc_buffer_remainingregion(data, &source);
	if (source.length != DNS_KEY_MLDSA44SIZE) {
		return DST_R_INVALIDPUBLICKEY;
	}
	pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-44", NULL,
					      source.base, source.length);
	if (pkey == NULL) {
		return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
	}
	isc_buffer_forward(data, source.length);
	opensslmldsa__setkey(key, pkey, NULL, NULL);
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_tofile(const dst_key_t *key, const char *directory) {
	dst_private_t priv = { 0 };

	if (key->external) {
		return dst__privstruct_writefile(key, &priv, directory);
	}
	if (key->keydata.pkeypair.seed == NULL) {
		return DST_R_NULLKEY;
	}

	priv.nelements = 1;
	priv.elements[0].tag = TAG_MLDSA_PRIVATEKEY;
	priv.elements[0].length = DNS_KEY_MLDSA44SEEDSIZE;
	priv.elements[0].data = key->keydata.pkeypair.seed;
	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
opensslmldsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	isc_result_t result = ISC_R_SUCCESS;
	dst_private_t priv;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[2];
	uint8_t *seed = NULL;

	CHECK(dst__privstruct_parse(key, DST_ALG_MLDSA44, lexer, key->mctx,
				    &priv));
	if (key->external) {
		if (pub == NULL) {
			CLEANUP(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkeypair = pub->keydata.pkeypair;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		pub->keydata.pkeypair.seed = NULL;
		CLEANUP(ISC_R_SUCCESS);
	}

	/* check_mldsa() requires exactly one 32-byte seed. */
	if (priv.elements[0].length != DNS_KEY_MLDSA44SEEDSIZE) {
		CLEANUP(DST_R_INVALIDPRIVATEKEY);
	}
	seed = isc_mem_get(key->mctx, DNS_KEY_MLDSA44SEEDSIZE);
	memmove(seed, priv.elements[0].data, priv.elements[0].length);
	params[0] = OSSL_PARAM_construct_octet_string(
		OSSL_PKEY_PARAM_ML_DSA_SEED, seed, priv.elements[0].length);
	params[1] = OSSL_PARAM_construct_end();
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
	if (ctx == NULL) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					       DST_R_INVALIDPRIVATEKEY));
	};

	int r = EVP_PKEY_fromdata_init(ctx);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_fromdata_init",
					       DST_R_INVALIDPRIVATEKEY));
	}

	r = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
	if (r != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_fromdata",
					       DST_R_INVALIDPRIVATEKEY));
	}

	if (pub != NULL) {
		r = EVP_PKEY_eq(pkey, pub->keydata.pkeypair.pub);
		if (r != 1) {
			CLEANUP(DST_R_INVALIDPRIVATEKEY);
		}
	}

	opensslmldsa__setkey(key, pkey, pkey, seed);
	(void)MOVE_OWNERSHIP(pkey);
	(void)MOVE_OWNERSHIP(seed);

cleanup:
	if (seed != NULL) {
		isc_safe_memwipe(seed, DNS_KEY_MLDSA44SEEDSIZE);
		isc_mem_put(key->mctx, seed, DNS_KEY_MLDSA44SEEDSIZE);
	}
	EVP_PKEY_free(pkey);

	EVP_PKEY_CTX_free(ctx);
	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return result;
}

static dst_func_t opensslmldsa_functions = {
	.createctx = opensslmldsa_createctx,
	.destroyctx = opensslmldsa_destroyctx,
	.adddata = opensslmldsa_adddata,
	.sign = opensslmldsa_sign,
	.verify = opensslmldsa_verify,
	.compare = dst__openssl_keypair_compare,
	.generate = opensslmldsa_generate,
	.isprivate = dst__openssl_keypair_isprivate,
	.destroy = opensslmldsa_destroy,
	.todns = opensslmldsa_todns,
	.fromdns = opensslmldsa_fromdns,
	.tofile = opensslmldsa_tofile,
	.parse = opensslmldsa_parse,
};

void
dst__opensslmldsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);

	/* Respect the configured providers and default property query. */
	EVP_KEYMGMT *keymgmt = EVP_KEYMGMT_fetch(NULL, "ML-DSA-44", NULL);
	EVP_SIGNATURE *signature = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44", NULL);
	if (keymgmt != NULL && signature != NULL &&
	    isc__crypto_md[ISC_MD_SHAKE256] != NULL)
	{
		*funcp = &opensslmldsa_functions;
	}
	EVP_KEYMGMT_free(keymgmt);
	EVP_SIGNATURE_free(signature);
	ERR_clear_error();
}
