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

#include <config.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#include <stdlib.h>
#include <string.h>
#include "openssl_shim.h"
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

void *OPENSSL_zalloc(size_t size)
{
	void *ret = OPENSSL_malloc(size);
	if (ret != NULL) {
		memset(ret, 0, size);
	}
	return ret;
}

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new(void)
{
	EVP_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
	return ctx;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
	if (ctx != NULL) {
		EVP_CIPHER_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(*ctx));
	}
	return ctx;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (ctx != NULL) {
		EVP_MD_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
	return EVP_MD_CTX_cleanup(ctx);
}

HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx != NULL) {
		if (!HMAC_CTX_reset(ctx)) {
			HMAC_CTX_free(ctx);
			return NULL;
		}
	}
	return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx != NULL) {
		HMAC_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

int HMAC_CTX_reset(HMAC_CTX *ctx) {
	HMAC_CTX_cleanup(ctx);
	return 1;
}

#endif
