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

#include <stdbool.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <isc/crypto.h>
#include <isc/ossl_wrap.h>
#include <isc/region.h>
#include <isc/util.h>

#define MAX_PUBLIC_KEY_SIZE 96
#define MAX_SECRET_KEY_SIZE 48

#define OSSL_WRAP_ERROR(fn)                                        \
	isc__ossl_wrap_logged_toresult(                            \
		ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO, fn, \
		ISC_R_CRYPTOFAILURE, __FILE__, __LINE__)

#define P_CURVE_IMPL(curve, nid)                                               \
	isc_result_t isc_ossl_wrap_generate_##curve##_key(EVP_PKEY **pkeyp) {  \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		return generate_ec_key(pkeyp, curve##_params);                 \
	}                                                                      \
	isc_result_t isc_ossl_wrap_generate_pkcs11_##curve##_key(              \
		char *uri, EVP_PKEY **pkeyp) {                                 \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		REQUIRE(uri != NULL);                                          \
		return generate_pkcs11_ec_key(uri, pkeyp, nid);                \
	}                                                                      \
	isc_result_t isc_ossl_wrap_validate_##curve##_pkey(EVP_PKEY *pkey) {   \
		REQUIRE(pkey != NULL);                                         \
		return validate_ec_pkey(pkey, curve##_params);                 \
	}                                                                      \
	isc_result_t isc_ossl_wrap_load_##curve##_public_from_region(          \
		isc_region_t region, EVP_PKEY **pkeyp) {                       \
		REQUIRE(region.base != NULL &&                                 \
			region.length <= MAX_PUBLIC_KEY_SIZE);                 \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		region.length = curve##_public_key_size;                       \
		return load_ec_public_from_region(region, pkeyp,               \
						  curve##_params);             \
	}                                                                      \
	isc_result_t isc_ossl_wrap_load_##curve##_secret_from_region(          \
		isc_region_t region, EVP_PKEY **pkeyp) {                       \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		REQUIRE(region.base != NULL &&                                 \
			region.length >= curve##_secret_key_size);             \
		region.length = curve##_secret_key_size;                       \
		return load_ec_secret_from_region(region, pkeyp,               \
						  curve##_params);             \
	}                                                                      \
	isc_result_t isc_ossl_wrap_##curve##_public_region(EVP_PKEY *pkey,     \
							   isc_region_t pub) { \
		REQUIRE(pkey != NULL);                                         \
		REQUIRE(pub.base != NULL &&                                    \
			pub.length >= curve##_public_key_size);                \
		pub.length = curve##_public_key_size;                          \
		return ec_public_region(pkey, pub);                            \
	}                                                                      \
	isc_result_t isc_ossl_wrap_##curve##_secret_region(EVP_PKEY *pkey,     \
							   isc_region_t sec) { \
		REQUIRE(pkey != NULL);                                         \
		REQUIRE(sec.base != NULL &&                                    \
			sec.length >= curve##_secret_key_size);                \
		sec.length = curve##_secret_key_size;                          \
		return ec_secret_region(pkey, sec);                            \
	}

static char pkcs11_key_usage[] = "digitalSignature";

constexpr size_t p256_public_key_size = 64;
constexpr size_t p384_public_key_size = 96;

constexpr size_t p256_secret_key_size = 32;
constexpr size_t p384_secret_key_size = 48;

/*
 * "group" MUST be the first parameter, we rely on it to get the group name.
 */

/* clang-format off */
static const OSSL_PARAM p256_params[] = {
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
			       UNCONST("prime256v1"), sizeof("prime256v1") - 1),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
			       UNCONST("named_curve"), sizeof("named_curve") - 1),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
			       UNCONST("uncompressed"), sizeof("uncompressed") - 1),
	OSSL_PARAM_END,
};

static const OSSL_PARAM p384_params[] = {
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
			       UNCONST("secp384r1"), sizeof("secp384r1") - 1),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
			       UNCONST("named_curve"), sizeof("named_curve") - 1),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
			       UNCONST("uncompressed"), sizeof("uncompressed") - 1),
	OSSL_PARAM_END,
};
/* clang-format on */

static void
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	INSIST(bytes >= 0);

	while (bytes-- > 0) {
		*buf++ = 0;
	}
	BN_bn2bin(bn, buf);
}

static int
rsa_keygen_progress_cb(EVP_PKEY_CTX *ctx) {
	void (*fptr)(int);

	fptr = EVP_PKEY_CTX_get_app_data(ctx);
	if (fptr != NULL) {
		int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
		fptr(p);
	}
	return 1;
}

static isc_result_t
generate_ec_key(EVP_PKEY **pkeyp, const OSSL_PARAM *const params) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx = NULL;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_keygen_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	/*
	 * EVP_PKEY_keygen is an older function now equivalent to
	 * EVP_PKEY_generate with an additional check that EVP_PKEY_CTX has been
	 * initialized with EVP_PKEY_keygen_init.
	 *
	 * Since we can guarantee such condition we use EVP_PKEY_generate
	 * directly.
	 */
	if (EVP_PKEY_generate(pctx, pkeyp) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_generate"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

static isc_result_t
generate_pkcs11_ec_key(char *uri, EVP_PKEY **pkeyp, int nid) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx;
	size_t len;

	INSIST(uri != NULL);
	len = strlen(uri);

	const OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string("pkcs11_uri", uri, len),
		OSSL_PARAM_utf8_string("pkcs11_key_usage", pkcs11_key_usage,
				       sizeof(pkcs11_key_usage) - 1),
		OSSL_PARAM_END,
	};

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=pkcs11");
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_keygen_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	/*
	 * Setting the P-384 curve doesn't work correctly when using:
	 * OSSL_PARAM_construct_utf8_string("ec_paramgen_curve", "P-384", 0);
	 *
	 * Instead use the OpenSSL function to set the curve nid param.
	 */
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_"
					"nid"));
	}

	/*
	 * EVP_PKEY_keygen is an older function now equivalent to
	 * EVP_PKEY_generate with an additional check that EVP_PKEY_CTX has been
	 * initialized with EVP_PKEY_keygen_init.
	 *
	 * Since we can guarantee such condition we use EVP_PKEY_generate
	 * directly.
	 */
	if (EVP_PKEY_generate(pctx, pkeyp) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_generate"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

static isc_result_t
validate_ec_pkey(EVP_PKEY *pkey, const OSSL_PARAM *const curve_params) {
	isc_result_t result;
	const char *expected = curve_params[0].data;
	char actual[64];

	if (EVP_PKEY_get_group_name(pkey, actual, sizeof(actual), NULL) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_group_name"));
	}

	if (strncmp(expected, actual, curve_params[0].data_size) != 0) {
		return ISC_R_FAILURE;
	}

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
load_ec_public_from_region(isc_region_t region, EVP_PKEY **pkeyp,
			   const OSSL_PARAM *const curve_params) {
	isc_result_t result;
	EVP_PKEY_CTX *pctx = NULL;
	uint8_t buffer[MAX_PUBLIC_KEY_SIZE + 1];
	OSSL_PARAM params[] = {
		curve_params[0], /* group */
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, buffer,
					region.length + 1),
		OSSL_PARAM_END,
	};

	buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
	memmove(buffer + 1, region.base, region.length);

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_PUBLIC_KEY, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	return result;
}

static isc_result_t
load_ec_secret_from_region(isc_region_t region, EVP_PKEY **pkeyp,
			   const OSSL_PARAM *const curve_params) {
	uint8_t public[MAX_PUBLIC_KEY_SIZE + 1];
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EC_POINT *pub_point = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *private = NULL;
	isc_result_t result;
	size_t public_len;

	/*
	 * OpenSSL requires us to set the public key portion, but since our
	 * private key file format does not contain it directly, we generate it
	 * as needed.
	 */
	group = EC_GROUP_new_from_params(curve_params, NULL, NULL);
	if (group == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_GROUP_new_by_curve_name"));
	}

	private = BN_bin2bn(region.base, region.length, NULL);
	if (private == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("BN_bin2bn"));
	}

	pub_point = EC_POINT_new(group);
	if (pub_point == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_new"));
	}

	if (EC_POINT_mul(group, pub_point, private, NULL, NULL, NULL) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_mul"));
	}

	public_len = EC_POINT_point2oct(group, pub_point,
					POINT_CONVERSION_UNCOMPRESSED, public,
					sizeof(public), NULL);
	if (public_len == 0) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_point2oct"));
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_new"));
	}

	if (OSSL_PARAM_BLD_push_utf8_string(bld, curve_params[0].key,
					    curve_params[0].data,
					    curve_params[0].data_size) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_utf8_string"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, private) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					     public, public_len) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_octet_string"));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_to_param"));
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_KEYPAIR, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EC_POINT_free(pub_point);
	BN_clear_free(private);
	EC_GROUP_free(group);
	EVP_PKEY_CTX_free(pctx);
	return result;
}

static isc_result_t
ec_public_region(EVP_PKEY *pkey, isc_region_t pub) {
	isc_result_t result;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	BN_bn2bin_fixed(x, &pub.base[0], pub.length / 2);
	BN_bn2bin_fixed(y, &pub.base[pub.length / 2], pub.length / 2);

	result = ISC_R_SUCCESS;

cleanup:
	BN_clear_free(x);
	BN_clear_free(y);
	return result;
}

static isc_result_t
ec_secret_region(EVP_PKEY *pkey, isc_region_t sec) {
	isc_result_t result;
	BIGNUM *priv = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	BN_bn2bin_fixed(priv, sec.base, sec.length);

	result = ISC_R_SUCCESS;

cleanup:
	BN_clear_free(priv);
	return result;
}

P_CURVE_IMPL(p256, NID_X9_62_prime256v1);
P_CURVE_IMPL(p384, NID_secp384r1);

isc_result_t
isc_ossl_wrap_ecdsa_set_deterministic(EVP_PKEY_CTX *pctx, const char *hash) {
	unsigned int rfc6979 = 1;
	isc_result_t result;
	OSSL_PARAM params[3] = {
		OSSL_PARAM_construct_utf8_string("digest", UNCONST(hash), 0),
		OSSL_PARAM_construct_uint("nonce-type", &rfc6979),
		OSSL_PARAM_END,
	};

	REQUIRE(pctx != NULL && hash != NULL);

	if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY_CTX *ctx;
	uint32_t e = 65537;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	/*
	 * https://docs.openssl.org/master/man7/EVP_PKEY-RSA/#rsa-key-generation-parameters
	 */
	const OSSL_PARAM params[3] = {
		OSSL_PARAM_uint(OSSL_PKEY_PARAM_RSA_E, &e),
		OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bit_size),
		OSSL_PARAM_END,
	};

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	if (callback != NULL) {
		EVP_PKEY_CTX_set_app_data(ctx, (void *)callback);
		EVP_PKEY_CTX_set_cb(ctx, rsa_keygen_progress_cb);
	}

	/*
	 * EVP_PKEY_keygen is an older function now equivalent to
	 * EVP_PKEY_generate with an additional check that EVP_PKEY_CTX has been
	 * initialized with EVP_PKEY_keygen_init.
	 *
	 * Since we can guarantee such condition we use EVP_PKEY_generate
	 * directly.
	 */
	if (EVP_PKEY_generate(ctx, pkeyp) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	return result;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp) {
	EVP_PKEY_CTX *ctx = NULL;
	isc_result_t result;
	int status;
	size_t len;

	len = strlen(uri);
	INSIST(len != 0);

	/* NUL-terminator should be left out */
	const OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string("pkcs11_uri", uri, len),
		OSSL_PARAM_utf8_string("pkcs11_key_usage", pkcs11_key_usage,
				       sizeof(pkcs11_key_usage) - 1),
		OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bit_size),
		OSSL_PARAM_END,
	};

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=pkcs11");
	if (ctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	status = EVP_PKEY_CTX_set_params(ctx, params);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	/*
	 * EVP_PKEY_keygen is an older function now equivalent to
	 * EVP_PKEY_generate with an additional check that EVP_PKEY_CTX has been
	 * initialized with EVP_PKEY_keygen_init.
	 *
	 * Since we can guarantee such condition we use EVP_PKEY_generate
	 * directly.
	 */
	status = EVP_PKEY_generate(ctx, pkeyp);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_generate"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	return result;
}

bool
isc_ossl_wrap_rsa_key_bits_leq(EVP_PKEY *pkey, size_t limit) {
	BIGNUM *e = NULL;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1) {
		int bits = BN_num_bits(e);
		BN_free(e);

		return bits > 0 && (size_t)bits <= limit;
	}
	return false;
}

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->e == NULL && c->n == NULL);

	c->needs_cleanup = true;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->d == NULL && c->p == NULL && c->q == NULL &&
		c->dmp1 == NULL && c->dmq1 == NULL && c->iqmp == NULL);

	c->needs_cleanup = true;

	/*
	 * NOTE: Errors regarding private compoments are ignored.
	 *
	 * OpenSSL allows omitting the parameters for CRT based calculations
	 * (factors, exponents, coefficients). Only the 'd'  parameter is
	 * mandatory for software keys.
	 *
	 * However, for a label based keys, all private key component queries
	 * can fail if they key is e.g. on a hardware device.
	 */
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &c->d);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &c->p);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &c->q);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1,
				    &c->dmp1);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2,
				    &c->dmq1);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
				    &c->iqmp);

	ERR_clear_error();

	return ISC_R_SUCCESS;
}

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	OSSL_PARAM_BLD *bld = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM *params = NULL;
	isc_result_t result;

	result = ISC_R_SUCCESS;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL && c->n != NULL && c->e != NULL);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_new"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_to_param"));
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_PUBLIC_KEY, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	OSSL_PARAM_BLD *bld = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM *params = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_new"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->d != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, c->d) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->p != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, c->p) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->q != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, c->q) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->dmp1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1,
				   c->dmp1) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->dmq1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2,
				   c->dmq1) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->iqmp != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
				   c->iqmp) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_to_param"));
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_KEYPAIR, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	return result;
}
