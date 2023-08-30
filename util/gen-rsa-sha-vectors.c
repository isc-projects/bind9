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

#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

/*
 *  Generate test vectors for lib/dns/opensslrsa_link.c as:
 *
 *  Fedora 33 doesn't support RSASHA1 in future mode.  There is no easy
 *  check for this other than by attempting to perform a verification
 *  using known good signatures.  We don't attempt to sign with RSASHA1
 *  as that would not work in FIPS mode.  RSASHA1 is verify only.
 *
 *  The test vectors were generated using OpenSSL 3.0 and
 *  util/gen-rsa-sha-vectors.c.  Rerunning will generate a new set of
 *  test vectors as the private key is not preserved.
 *
 *  e.g.
 *          cc util/gen-rsa-sha-vectors.c -I /opt/local/include \
 *                  -L /opt/local/lib -lcrypto
 */

int
main() {
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY *pkey = NULL;
	unsigned char buf[512];
	size_t bytes;
	EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();
	unsigned int siglen = sizeof(buf);

	if (e == NULL || n == NULL || ctx == NULL || evp_md_ctx == NULL) {
		ERR_clear_error();
		return (1);
	}

	BN_set_bit(e, 0);
	BN_set_bit(e, 16);

	if (EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1 ||
	    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) != 1 ||
	    EVP_PKEY_keygen(ctx, &pkey) != 1 || pkey == NULL)
	{
		ERR_clear_error();
		return (1);
	}

	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
	if (n == NULL) {
		ERR_clear_error();
		return (1);
	}

	bytes = BN_num_bytes(e);
	BN_bn2bin(e, buf);
	printf("unsigned char e_bytes[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n");

	bytes = BN_num_bytes(n);
	BN_bn2bin(n, buf);
	printf("unsigned char n_bytes[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	if (EVP_DigestInit_ex(evp_md_ctx, EVP_sha1(), NULL) != 1 ||
	    EVP_DigestUpdate(evp_md_ctx, "test", 4) != 1 ||
	    EVP_SignFinal(evp_md_ctx, buf, &siglen, pkey) != 1)
	{
		ERR_clear_error();
		return (1);
	}
	bytes = siglen;
	printf("unsigned char sha1_sig[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	if (EVP_DigestInit_ex(evp_md_ctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(evp_md_ctx, "test", 4) != 1 ||
	    EVP_SignFinal(evp_md_ctx, buf, &siglen, pkey) != 1)
	{
		ERR_clear_error();
		return (1);
	}
	bytes = siglen;
	printf("unsigned char sha256_sig[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	if (EVP_DigestInit_ex(evp_md_ctx, EVP_sha512(), NULL) != 1 ||
	    EVP_DigestUpdate(evp_md_ctx, "test", 4) != 1 ||
	    EVP_SignFinal(evp_md_ctx, buf, &siglen, pkey) != 1)
	{
		ERR_clear_error();
		return (1);
	}
	bytes = siglen;
	printf("unsigned char sha512_sig[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	EVP_MD_CTX_free(evp_md_ctx);
	EVP_PKEY_free(pkey);

	return (0);
}
