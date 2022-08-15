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

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>

/*
 *  The test vectors were generated using OpenSSL 3.0 and
 *  util/gen-eddsa-vectors.c.  Rerunning will generate a new set of
 *  test vectors as the private key is not preserved.
 *
 *  e.g.
 *          cc util/gen-eddsa-vectors.c -I /opt/local/include \
 *                  -L /opt/local/lib -lcrypto
 */

int
main() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(NID_ED25519, NULL);
	EVP_PKEY *pkey = NULL;
	unsigned char buf[512];
	size_t bytes;
	EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();

	if (ctx == NULL || evp_md_ctx == NULL) {
		return (1);
	}

	if (EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_keygen(ctx, &pkey) != 1 || pkey == NULL)
	{
		return (1);
	}

	bytes = sizeof(buf);
	if (EVP_PKEY_get_raw_public_key(pkey, buf, &bytes) != 1) {
		return (1);
	}

	printf("unsigned char ed25519_pub[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n");

	bytes = sizeof(buf);
	if (EVP_DigestSignInit(evp_md_ctx, NULL, NULL, NULL, pkey) != 1 ||
	    EVP_DigestSign(evp_md_ctx, buf, &bytes,
			   (const unsigned char *)"test", 4) != 1)
	{
		return (1);
	}

	printf("unsigned char ed25519_sig[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	EVP_MD_CTX_free(evp_md_ctx);
	EVP_PKEY_free(pkey);
	pkey = NULL;

	ctx = EVP_PKEY_CTX_new_id(NID_ED448, NULL);
	evp_md_ctx = EVP_MD_CTX_create();
	if (ctx == NULL || evp_md_ctx == NULL) {
		return (1);
	}

	if (EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_keygen(ctx, &pkey) != 1 || pkey == NULL)
	{
		return (1);
	}

	bytes = sizeof(buf);
	if (EVP_PKEY_get_raw_public_key(pkey, buf, &bytes) != 1) {
		return (1);
	}

	printf("unsigned char ed448_pub[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n");

	bytes = sizeof(buf);
	if (EVP_DigestSignInit(evp_md_ctx, NULL, NULL, NULL, pkey) != 1 ||
	    EVP_DigestSign(evp_md_ctx, buf, &bytes,
			   (const unsigned char *)"test", 4) != 1)
	{
		return (1);
	}

	printf("unsigned char ed448_sig[] = \"");
	for (size_t i = 0; i < bytes; i++) {
		printf("\\x%02x", buf[i]);
	}
	printf("\";\n\n");

	return (0);
}
