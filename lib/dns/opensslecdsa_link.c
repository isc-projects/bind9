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

#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <isc/crypto.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/ossl_wrap.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"
#include "openssl_shim.h"

#ifndef NID_X9_62_prime256v1
#error "P-256 group is not known (NID_X9_62_prime256v1)"
#endif /* ifndef NID_X9_62_prime256v1 */
#ifndef NID_secp384r1
#error "P-384 group is not known (NID_secp384r1)"
#endif /* ifndef NID_secp384r1 */

#define MAX_PUBKEY_SIZE DNS_KEY_ECDSA384SIZE

#define MAX_PRIVKEY_SIZE (MAX_PUBKEY_SIZE / 2)

static bool
opensslecdsa_valid_key_alg(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
	case DST_ALG_ECDSA384:
		return true;
	default:
		return false;
	}
}

static size_t
opensslecdsa_key_alg_to_publickey_size(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return DNS_KEY_ECDSA256SIZE;
	case DST_ALG_ECDSA384:
		return DNS_KEY_ECDSA384SIZE;
	default:
		UNREACHABLE();
	}
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	INSIST(bytes >= 0);

	while (bytes-- > 0) {
		*buf++ = 0;
	}
	BN_bn2bin(bn, buf);
	return size;
}

static isc_result_t
opensslecdsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_result_t result = ISC_R_SUCCESS;
	EVP_MD_CTX *evp_md_ctx;
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *type = NULL;
	const char *md = NULL;

	UNUSED(key);
	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	evp_md_ctx = EVP_MD_CTX_create();
	if (evp_md_ctx == NULL) {
		CLEANUP(dst__openssl_toresult(ISC_R_NOMEMORY));
	}
	if (dctx->key->key_alg == DST_ALG_ECDSA256) {
		type = isc__crypto_md[ISC_MD_SHA256];
		md = "SHA256";
	} else {
		type = isc__crypto_md[ISC_MD_SHA384];
		md = "SHA384";
	}

	if (dctx->use == DO_SIGN) {
		if (EVP_DigestSignInit(evp_md_ctx, &pctx, type, NULL,
				       dctx->key->keydata.pkeypair.priv) != 1)
		{
			EVP_MD_CTX_destroy(evp_md_ctx);
			CLEANUP(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestSignInit",
						       ISC_R_FAILURE));
		}

		if (!isc_crypto_fips_mode()) {
			result = isc_ossl_wrap_ecdsa_set_deterministic(pctx,
								       md);
			if (result != ISC_R_SUCCESS &&
			    result != ISC_R_NOTIMPLEMENTED)
			{
				CLEANUP(result);
			}
		}

	} else {
		if (EVP_DigestVerifyInit(evp_md_ctx, NULL, type, NULL,
					 dctx->key->keydata.pkeypair.pub) != 1)
		{
			EVP_MD_CTX_destroy(evp_md_ctx);
			CLEANUP(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestVerifyInit",
						       ISC_R_FAILURE));
		}
	}

	dctx->ctxdata.evp_md_ctx = evp_md_ctx;
	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

static void
opensslecdsa_destroyctx(dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		dctx->ctxdata.evp_md_ctx = NULL;
	}
}

static isc_result_t
opensslecdsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_result_t result = ISC_R_SUCCESS;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	if (dctx->use == DO_SIGN) {
		if (EVP_DigestSignUpdate(evp_md_ctx, data->base,
					 data->length) != 1)
		{
			CLEANUP(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestSignUpdate",
						       ISC_R_FAILURE));
		}
	} else {
		if (EVP_DigestVerifyUpdate(evp_md_ctx, data->base,
					   data->length) != 1)
		{
			CLEANUP(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestVerifyUpdate",
						       ISC_R_FAILURE));
		}
	}

cleanup:
	return result;
}

static isc_result_t
opensslecdsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t result;
	dst_key_t *key = dctx->key;
	isc_region_t region;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	ECDSA_SIG *ecdsasig = NULL;
	size_t siglen, sigder_len = 0, sigder_alloced = 0;
	unsigned char *sigder = NULL;
	const unsigned char *sigder_copy;
	const BIGNUM *r, *s;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	REQUIRE(dctx->use == DO_SIGN);

	if (key->key_alg == DST_ALG_ECDSA256) {
		siglen = DNS_SIG_ECDSA256SIZE;
	} else {
		siglen = DNS_SIG_ECDSA384SIZE;
	}

	isc_buffer_availableregion(sig, &region);
	if (region.length < siglen) {
		CLEANUP(ISC_R_NOSPACE);
	}

	if (EVP_DigestSignFinal(evp_md_ctx, NULL, &sigder_len) != 1) {
		CLEANUP(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE));
	}
	if (sigder_len == 0) {
		CLEANUP(ISC_R_FAILURE);
	}
	sigder = isc_mem_get(dctx->mctx, sigder_len);
	sigder_alloced = sigder_len;
	if (EVP_DigestSignFinal(evp_md_ctx, sigder, &sigder_len) != 1) {
		CLEANUP(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE));
	}
	sigder_copy = sigder;
	if (d2i_ECDSA_SIG(&ecdsasig, &sigder_copy, sigder_len) == NULL) {
		CLEANUP(dst__openssl_toresult3(dctx->category, "d2i_ECDSA_SIG",
					       ISC_R_FAILURE));
	}

	ECDSA_SIG_get0(ecdsasig, &r, &s);
	BN_bn2bin_fixed(r, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	BN_bn2bin_fixed(s, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	ECDSA_SIG_free(ecdsasig);
	isc_buffer_add(sig, siglen);
	result = ISC_R_SUCCESS;

cleanup:
	if (sigder != NULL && sigder_alloced != 0) {
		isc_mem_put(dctx->mctx, sigder, sigder_alloced);
	}

	return result;
}

static isc_result_t
opensslecdsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t result;
	dst_key_t *key = dctx->key;
	int status;
	unsigned char *cp = sig->base;
	ECDSA_SIG *ecdsasig = NULL;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	size_t siglen, sigder_len = 0, sigder_alloced = 0;
	unsigned char *sigder = NULL;
	unsigned char *sigder_copy;
	BIGNUM *r = NULL, *s = NULL;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	REQUIRE(dctx->use == DO_VERIFY);

	if (key->key_alg == DST_ALG_ECDSA256) {
		siglen = DNS_SIG_ECDSA256SIZE;
	} else {
		siglen = DNS_SIG_ECDSA384SIZE;
	}

	if (sig->length != siglen) {
		CLEANUP(DST_R_VERIFYFAILURE);
	}

	ecdsasig = ECDSA_SIG_new();
	if (ecdsasig == NULL) {
		CLEANUP(dst__openssl_toresult(ISC_R_NOMEMORY));
	}
	r = BN_bin2bn(cp, siglen / 2, NULL);
	cp += siglen / 2;
	s = BN_bin2bn(cp, siglen / 2, NULL);
	/* cp += siglen / 2; */
	ECDSA_SIG_set0(ecdsasig, r, s);

	status = i2d_ECDSA_SIG(ecdsasig, NULL);
	if (status < 0) {
		CLEANUP(dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					       DST_R_VERIFYFAILURE));
	}

	sigder_len = (size_t)status;
	sigder = isc_mem_get(dctx->mctx, sigder_len);
	sigder_alloced = sigder_len;

	sigder_copy = sigder;
	status = i2d_ECDSA_SIG(ecdsasig, &sigder_copy);
	if (status < 0) {
		CLEANUP(dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					       DST_R_VERIFYFAILURE));
	}

	status = EVP_DigestVerifyFinal(evp_md_ctx, sigder, sigder_len);

	switch (status) {
	case 1:
		result = ISC_R_SUCCESS;
		break;
	case 0:
		result = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		result = dst__openssl_toresult3(dctx->category,
						"EVP_DigestVerifyFinal",
						DST_R_VERIFYFAILURE);
		break;
	}

cleanup:
	if (ecdsasig != NULL) {
		ECDSA_SIG_free(ecdsasig);
	}
	if (sigder != NULL && sigder_alloced != 0) {
		isc_mem_put(dctx->mctx, sigder, sigder_alloced);
	}

	return result;
}

static isc_result_t
opensslecdsa_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	EVP_PKEY *pkey = NULL;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	UNUSED(unused);
	UNUSED(callback);

	if (key->label != NULL) {
		switch (key->key_alg) {
		case DST_ALG_ECDSA256:
			RETERR(isc_ossl_wrap_generate_pkcs11_p256_key(
				key->label, &pkey));
			break;
		case DST_ALG_ECDSA384:
			RETERR(isc_ossl_wrap_generate_pkcs11_p384_key(
				key->label, &pkey));
			break;
		default:
			UNREACHABLE();
		}
	} else {
		switch (key->key_alg) {
		case DST_ALG_ECDSA256:
			RETERR(isc_ossl_wrap_generate_p256_key(&pkey));
			break;
		case DST_ALG_ECDSA384:
			RETERR(isc_ossl_wrap_generate_p384_key(&pkey));
			break;
		default:
			UNREACHABLE();
		}
	}

	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_result_t result;
	isc_region_t r;
	EVP_PKEY *pkey;
	size_t keysize;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	REQUIRE(key->keydata.pkeypair.pub != NULL);

	keysize = opensslecdsa_key_alg_to_publickey_size(key->key_alg);
	isc_buffer_availableregion(data, &r);
	if (r.length < keysize) {
		CLEANUP(ISC_R_NOSPACE);
	}

	pkey = key->keydata.pkeypair.pub;
	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		if (isc_ossl_wrap_p256_public_region(pkey, r) != ISC_R_SUCCESS)
		{
			CLEANUP(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
		}
		break;
	case DST_ALG_ECDSA384:
		if (isc_ossl_wrap_p384_public_region(pkey, r) != ISC_R_SUCCESS)
		{
			CLEANUP(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
		}
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_add(data, keysize);
	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
opensslecdsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	isc_region_t r;
	size_t len;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	len = opensslecdsa_key_alg_to_publickey_size(key->key_alg);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		CLEANUP(ISC_R_SUCCESS);
	}
	if (r.length != len) {
		CLEANUP(DST_R_INVALIDPUBLICKEY);
	}

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		CHECK(isc_ossl_wrap_load_p256_public_from_region(r, &pkey));
		break;
	case DST_ALG_ECDSA384:
		CHECK(isc_ossl_wrap_load_p384_public_from_region(r, &pkey));
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_forward(data, len);
	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkeypair.pub = pkey;
	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
opensslecdsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t result;
	dst_private_t priv;
	unsigned char buf[MAX_PRIVKEY_SIZE];
	size_t keylen = 0;
	unsigned short i;
	EVP_PKEY *pkey;

	if (key->keydata.pkeypair.pub == NULL) {
		CLEANUP(DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		CLEANUP(dst__privstruct_writefile(key, &priv, directory));
	}

	if (key->keydata.pkeypair.priv == NULL) {
		CLEANUP(DST_R_NULLKEY);
	}

	keylen = opensslecdsa_key_alg_to_publickey_size(key->key_alg) / 2;
	INSIST(keylen <= sizeof(buf));

	pkey = key->keydata.pkeypair.priv;

	i = 0;
	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		result = isc_ossl_wrap_p256_secret_region(
			pkey, (isc_region_t){ buf, keylen });
		break;
	case DST_ALG_ECDSA384:
		result = isc_ossl_wrap_p384_secret_region(
			pkey, (isc_region_t){ buf, keylen });
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS) {
		priv.elements[i].tag = TAG_ECDSA_PRIVATEKEY;
		priv.elements[i].length = keylen;
		priv.elements[i].data = buf;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_ECDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	result = dst__privstruct_writefile(key, &priv, directory);

cleanup:
	isc_safe_memwipe(buf, keylen);
	return result;
}

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *label, const char *pin);

static isc_result_t
opensslecdsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t result;
	isc_region_t r;
	EVP_PKEY *pkey = NULL;
	const char *label = NULL;
	int i, privkey_index = -1;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));

	/* read private key file */
	CHECK(dst__privstruct_parse(key, DST_ALG_ECDSA256, lexer, key->mctx,
				    &priv));

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			CLEANUP(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
		key->keydata.pkeypair.priv = pub->keydata.pkeypair.priv;
		key->keydata.pkeypair.pub = pub->keydata.pkeypair.pub;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		CLEANUP(ISC_R_SUCCESS);
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_ECDSA_ENGINE:
			/* The Engine: tag is explicitly ignored */
			break;
		case TAG_ECDSA_LABEL:
			/* NUL terminated data? */
			CHECK(dst__privelement_is_nul_terminated(
				&priv.elements[i]));
			label = (char *)priv.elements[i].data;
			break;
		case TAG_ECDSA_PRIVATEKEY:
			privkey_index = i;
			break;
		default:
			break;
		}
	}

	if (label != NULL) {
		CHECK(opensslecdsa_fromlabel(key, label, NULL));
		/* Check that the public component matches if given */
		if (pub != NULL && EVP_PKEY_eq(key->keydata.pkeypair.pub,
					       pub->keydata.pkeypair.pub) != 1)
		{
			CLEANUP(DST_R_INVALIDPRIVATEKEY);
		}
		CLEANUP(ISC_R_SUCCESS);
	}

	if (privkey_index < 0) {
		CLEANUP(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}

	r = (isc_region_t){
		.base = priv.elements[privkey_index].data,
		.length = priv.elements[privkey_index].length,
	};

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		CHECK(isc_ossl_wrap_load_p256_secret_from_region(r, &pkey));
		break;
	case DST_ALG_ECDSA384:
		CHECK(isc_ossl_wrap_load_p384_secret_from_region(r, &pkey));
		break;
	default:
		UNREACHABLE();
	}

	/* Check that the public component matches if given */
	if (pub != NULL && EVP_PKEY_eq(pkey, pub->keydata.pkeypair.pub) != 1) {
		CLEANUP(DST_R_INVALIDPRIVATEKEY);
	}

	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	pkey = NULL;

cleanup:
	EVP_PKEY_free(pkey);
	if (result != ISC_R_SUCCESS) {
		key->keydata.generic = NULL;
	}
	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *label, const char *pin) {
	EVP_PKEY *privpkey = NULL, *pubpkey = NULL;
	isc_result_t result;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	UNUSED(pin);

	CHECK(dst__openssl_fromlabel(EVP_PKEY_EC, label, pin, &pubpkey,
				     &privpkey));

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		CHECK(isc_ossl_wrap_validate_p256_pkey(privpkey));
		CHECK(isc_ossl_wrap_validate_p256_pkey(pubpkey));
		break;
	case DST_ALG_ECDSA384:
		CHECK(isc_ossl_wrap_validate_p384_pkey(privpkey));
		CHECK(isc_ossl_wrap_validate_p384_pkey(pubpkey));
		break;
	default:
		UNREACHABLE();
	}

	key->label = isc_mem_strdup(key->mctx, label);
	key->key_size = EVP_PKEY_bits(privpkey);
	key->keydata.pkeypair.priv = privpkey;
	key->keydata.pkeypair.pub = pubpkey;
	privpkey = NULL;
	pubpkey = NULL;

cleanup:
	EVP_PKEY_free(privpkey);
	EVP_PKEY_free(pubpkey);
	return result;
}

static dst_func_t opensslecdsa_functions = {
	.createctx = opensslecdsa_createctx,
	.destroyctx = opensslecdsa_destroyctx,
	.adddata = opensslecdsa_adddata,
	.sign = opensslecdsa_sign,
	.verify = opensslecdsa_verify,
	.compare = dst__openssl_keypair_compare,
	.generate = opensslecdsa_generate,
	.isprivate = dst__openssl_keypair_isprivate,
	.destroy = dst__openssl_keypair_destroy,
	.todns = opensslecdsa_todns,
	.fromdns = opensslecdsa_fromdns,
	.tofile = opensslecdsa_tofile,
	.parse = opensslecdsa_parse,
	.fromlabel = opensslecdsa_fromlabel,
};

void
dst__opensslecdsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		*funcp = &opensslecdsa_functions;
	}
}
