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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

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
		return generate_ec_key(pkeyp, nid);                            \
	}                                                                      \
	isc_result_t isc_ossl_wrap_generate_pkcs11_##curve##_key(              \
		char *uri, EVP_PKEY **pkeyp) {                                 \
		UNUSED(uri);                                                   \
		return isc_ossl_wrap_generate_##curve##_key(pkeyp);            \
	}                                                                      \
	isc_result_t isc_ossl_wrap_validate_##curve##_pkey(EVP_PKEY *pkey) {   \
		REQUIRE(pkey != NULL);                                         \
		return validate_ec_pkey(pkey, nid);                            \
	}                                                                      \
	isc_result_t isc_ossl_wrap_load_##curve##_public_from_region(          \
		isc_region_t region, EVP_PKEY **pkeyp) {                       \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		REQUIRE(region.base != NULL &&                                 \
			region.length >= curve##_public_key_size);             \
		region.length = curve##_public_key_size;                       \
		return load_ec_public_from_region(region, pkeyp, nid);         \
	}                                                                      \
	isc_result_t isc_ossl_wrap_load_##curve##_secret_from_region(          \
		isc_region_t region, EVP_PKEY **pkeyp) {                       \
		REQUIRE(pkeyp != NULL && *pkeyp == NULL);                      \
		REQUIRE(region.base != NULL &&                                 \
			region.length >= curve##_secret_key_size);             \
		region.length = curve##_secret_key_size;                       \
		return load_ec_secret_from_region(region, pkeyp, nid);         \
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

constexpr size_t p256_public_key_size = 64;
constexpr size_t p384_public_key_size = 96;

constexpr size_t p256_secret_key_size = 32;
constexpr size_t p384_secret_key_size = 48;

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

static int
rsa_keygen_progress_cb(int p, int n, BN_GENCB *cb) {
	void (*fptr)(int);

	UNUSED(n);

	fptr = BN_GENCB_get_arg(cb);
	if (fptr != NULL) {
		fptr(p);
	}
	return 1;
}

static isc_result_t
generate_ec_key(EVP_PKEY **pkeyp, const int nid) {
	isc_result_t result;
	EC_KEY *eckey = NULL;
	EVP_PKEY *pkey = NULL;

	eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_new_by_curve_name"));
	}

	if (EC_KEY_generate_key(eckey) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_generate_key"));
	}

	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_UNCOMPRESSED);

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_EC_KEY"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EC_KEY_free(eckey);
	EVP_PKEY_free(pkey);
	return result;
}

static isc_result_t
validate_ec_pkey(EVP_PKEY *pkey, const int nid) {
	const EC_GROUP *group;
	const EC_KEY *eckey;
	isc_result_t result;

	eckey = EVP_PKEY_get0_EC_KEY(pkey);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_EC_KEY"));
	}

	group = EC_KEY_get0_group(eckey);
	if (group == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_get0_group"));
	}

	if (EC_GROUP_get_curve_name(group) != nid) {
		return DST_R_INVALIDPRIVATEKEY;
	}

	result = ISC_R_SUCCESS;
cleanup:
	return result;
}

static isc_result_t
load_ec_public_from_region(isc_region_t region, EVP_PKEY **pkeyp,
			   const int nid) {
	isc_result_t result;
	const unsigned char *buf_launder;
	uint8_t buffer[MAX_PUBLIC_KEY_SIZE + 1];
	EC_KEY *eckey = NULL;
	EVP_PKEY *pkey = NULL;

	eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_new_curve_by_name"));
	}

	buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
	memmove(buffer + 1, region.base, region.length);

	buf_launder = buffer;
	if (o2i_ECPublicKey(&eckey, &buf_launder, region.length + 1) == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("o2i_ECPublicKey"));
	}

	if (EC_KEY_check_key(eckey) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_check_key"));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_EC_KEY"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	EC_KEY_free(eckey);
	return result;
}

static isc_result_t
load_ec_secret_from_region(isc_region_t region, EVP_PKEY **pkeyp,
			   const int nid) {
	isc_result_t result;
	const EC_GROUP *group = NULL;
	EC_POINT *public = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *private = NULL;
	EC_KEY *eckey = NULL;

	eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_new_curve_by_name"));
	}

	group = EC_KEY_get0_group(eckey);
	if (group == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_get0_group"));
	}

	private = BN_bin2bn(region.base, region.length, NULL);
	if (private == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("BN_bin2bn"));
	}

	if (EC_KEY_set_private_key(eckey, private) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_set_private_key"));
	}

	/*
	 * OpenSSL requires us to set the public key portion, but since our
	 * private key file format does not contain it directly, we generate it
	 * as needed.
	 */
	public = EC_POINT_new(group);
	if (public == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_new"));
	}

	if (EC_POINT_mul(group, public, private, NULL, NULL, NULL) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_mul"));
	}

	if (EC_KEY_set_public_key(eckey, public) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_set_public_key"));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_EC_KEY"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	EC_POINT_free(public);
	BN_clear_free(private);
	EC_KEY_free(eckey);
	return result;
}

static isc_result_t
ec_public_region(EVP_PKEY *pkey, isc_region_t pub) {
	isc_result_t result;
	uint8_t buffer[MAX_PUBLIC_KEY_SIZE + 1];
	const EC_POINT *public;
	const EC_GROUP *group;
	const EC_KEY *eckey;
	size_t len;

	eckey = EVP_PKEY_get0_EC_KEY(pkey);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_EC_KEY"));
	}

	group = EC_KEY_get0_group(eckey);
	if (group == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_get0_group"));
	}

	public = EC_KEY_get0_public_key(eckey);
	if (public == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_get0_public_key"));
	}

	len = EC_POINT_point2oct(group, public, POINT_CONVERSION_UNCOMPRESSED,
				 buffer, sizeof(buffer), NULL);
	if (len != pub.length + 1) {
		CLEANUP(OSSL_WRAP_ERROR("EC_POINT_point2oct"));
	}

	memmove(pub.base, buffer + 1, pub.length);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
ec_secret_region(EVP_PKEY *pkey, isc_region_t pub) {
	const BIGNUM *private;
	isc_result_t result;
	const EC_KEY *eckey;

	eckey = EVP_PKEY_get0_EC_KEY(pkey);
	if (eckey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_EC_KEY"));
	}

	private = EC_KEY_get0_private_key(eckey);
	if (private == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EC_KEY_get0_private_key"));
	}

	BN_bn2bin_fixed(private, pub.base, pub.length);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

P_CURVE_IMPL(p256, NID_X9_62_prime256v1);
P_CURVE_IMPL(p384, NID_secp384r1);

isc_result_t
isc_ossl_wrap_ecdsa_set_deterministic(EVP_PKEY_CTX *pctx, const char *hash) {
	UNUSED(pctx);
	UNUSED(hash);

	return ISC_R_NOTIMPLEMENTED;
}

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp) {
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	BN_GENCB *cb = NULL;
	isc_result_t result;
	BIGNUM *e;

	e = BN_new();

	/* e = 65537 (0x10001, F4) */
	BN_set_bit(e, 0);
	BN_set_bit(e, 16);

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	if (callback != NULL) {
		cb = BN_GENCB_new();
		if (cb == NULL) {
			CLEANUP(OSSL_WRAP_ERROR("BN_GENCB_new"));
		}

		BN_GENCB_set(cb, rsa_keygen_progress_cb, (void *)callback);
	}

	if (RSA_generate_key_ex(rsa, bit_size, e, cb) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_generate_key_ex"));
	}
	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	BN_GENCB_free(cb);
	BN_free(e);
	return result;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp) {
	REQUIRE(uri != NULL);
	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	UNUSED(uri);
	UNUSED(bit_size);
	UNUSED(pkeyp);
	return ISC_R_NOTIMPLEMENTED;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_ed25519_key(char *uri, EVP_PKEY **pkeyp) {
	REQUIRE(uri != NULL);
	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	UNUSED(uri);
	UNUSED(pkeyp);
	return ISC_R_NOTIMPLEMENTED;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_ed448_key(char *uri, EVP_PKEY **pkeyp) {
	REQUIRE(uri != NULL);
	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	UNUSED(uri);
	UNUSED(pkeyp);
	return ISC_R_NOTIMPLEMENTED;
}

bool
isc_ossl_wrap_rsa_key_bits_leq(EVP_PKEY *pkey, size_t limit) {
	const RSA *rsa;
	const BIGNUM *ce;

	REQUIRE(pkey != NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa != NULL) {
		ce = NULL;
		RSA_get0_key(rsa, NULL, &ce, NULL);
		if (ce != NULL) {
			int bits = BN_num_bits(ce);

			return bits > 0 && (size_t)bits <= limit;
		}
	}

	return false;
}

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;
	const RSA *rsa;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->e == NULL && c->n == NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_RSA"));
	}

	RSA_get0_key(rsa, (const BIGNUM **)&c->n, (const BIGNUM **)&c->e, NULL);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;
	const RSA *rsa;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->d == NULL && c->p == NULL && c->q == NULL &&
		c->dmp1 == NULL && c->dmq1 == NULL && c->iqmp == NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_RSA"));
	}

	/*
	 * We don't support PKCS11 with OpenSSL <=1.1.1a
	 * d *must* succeed.
	 */
	RSA_get0_key(rsa, NULL, NULL, (const BIGNUM **)&c->d);
	if (c->d == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_get0_key"));
	}

	RSA_get0_factors(rsa, (const BIGNUM **)&c->p, (const BIGNUM **)&c->q);
	RSA_get0_crt_params(rsa, (const BIGNUM **)&c->dmp1,
			    (const BIGNUM **)&c->dmq1,
			    (const BIGNUM **)&c->iqmp);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL && c->e != NULL && c->n != NULL);
	REQUIRE(c->needs_cleanup);

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	if (RSA_set0_key(rsa, c->n, c->e, NULL) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_set0_key"));
	}

	c->n = NULL;
	c->e = NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL);

	result = ISC_R_SUCCESS;

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	if (RSA_set0_key(rsa, c->n, c->e, c->d) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_set0_key"));
	}

	c->n = NULL;
	c->e = NULL;
	c->d = NULL;

	if (c->p != NULL || c->q != NULL) {
		if (RSA_set0_factors(rsa, c->p, c->q) != 1) {
			CLEANUP(OSSL_WRAP_ERROR("RSA_set0_factors"));
		}

		c->p = NULL;
		c->q = NULL;
	}

	if (c->dmp1 != NULL || c->dmq1 != NULL || c->iqmp != NULL) {
		if (RSA_set0_crt_params(rsa, c->dmp1, c->dmq1, c->iqmp) != 1) {
			CLEANUP(OSSL_WRAP_ERROR("RSA_set0_crt_params"));
		}
		c->dmp1 = NULL;
		c->dmq1 = NULL;
		c->iqmp = NULL;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	isc_ossl_wrap_rsa_components_cleanup(c);
	return result;
}
