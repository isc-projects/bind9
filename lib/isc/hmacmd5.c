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

/*! \file */

#include <config.h>

#include <stdbool.h>

#include <isc/assertions.h>
#include <isc/hmacmd5.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define HMAC_CTX_new() &(ctx->_ctx), HMAC_CTX_init(&(ctx->_ctx))
#define HMAC_CTX_free(ptr) HMAC_CTX_cleanup(ptr)
#endif

void
isc_hmacmd5_init(isc_hmacmd5_t *ctx, const unsigned char *key,
		 unsigned int len)
{
	ctx->ctx = HMAC_CTX_new();
	RUNTIME_CHECK(ctx->ctx != NULL);
	RUNTIME_CHECK(HMAC_Init_ex(ctx->ctx, (const void *) key,
				   (int) len, EVP_md5(), NULL) == 1);
}

void
isc_hmacmd5_invalidate(isc_hmacmd5_t *ctx) {
	if (ctx->ctx == NULL)
		return;
	HMAC_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

void
isc_hmacmd5_update(isc_hmacmd5_t *ctx, const unsigned char *buf,
		   unsigned int len)
{
	RUNTIME_CHECK(HMAC_Update(ctx->ctx, buf, (int) len) == 1);
}

void
isc_hmacmd5_sign(isc_hmacmd5_t *ctx, unsigned char *digest) {
	RUNTIME_CHECK(HMAC_Final(ctx->ctx, digest, NULL) == 1);
	HMAC_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

/*!
 * Verify signature - finalize MD5 operation and reapply MD5, then
 * compare to the supplied digest.
 */
bool
isc_hmacmd5_verify(isc_hmacmd5_t *ctx, unsigned char *digest) {
	return (isc_hmacmd5_verify2(ctx, digest, ISC_MD5_DIGESTLENGTH));
}

bool
isc_hmacmd5_verify2(isc_hmacmd5_t *ctx, unsigned char *digest, size_t len) {
	unsigned char newdigest[ISC_MD5_DIGESTLENGTH];

	REQUIRE(len <= ISC_MD5_DIGESTLENGTH);
	isc_hmacmd5_sign(ctx, newdigest);
	return (isc_safe_memequal(digest, newdigest, len));
}

/*
 * Check for MD5 support; if it does not work, raise a fatal error.
 *
 * Use the first test vector from RFC 2104, with a second round using
 * a too-short key.
 *
 * Standard use is testing 0 and expecting result true.
 * Testing use is testing 1..4 and expecting result false.
 */
bool
isc_hmacmd5_check(int testing) {
	isc_hmacmd5_t ctx;
	unsigned char key[] = { /* 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b */
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};
	unsigned char input[] = { /* "Hi There" */
		0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
	};
	unsigned char expected[] = {
		0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
		0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d
	};
	unsigned char expected2[] = {
		0xad, 0xb8, 0x48, 0x05, 0xb8, 0x8d, 0x03, 0xe5,
		0x90, 0x1e, 0x4b, 0x05, 0x69, 0xce, 0x35, 0xea
	};
	bool result;

	/*
	 * Introduce a fault for testing.
	 */
	switch (testing) {
	case 0:
	default:
		break;
	case 1:
		key[0] ^= 0x01;
		break;
	case 2:
		input[0] ^= 0x01;
		break;
	case 3:
		expected[0] ^= 0x01;
		break;
	case 4:
		expected2[0] ^= 0x01;
		break;
	}

	/*
	 * These functions do not return anything; any failure will be fatal.
	 */
	isc_hmacmd5_init(&ctx, key, 16U);
	isc_hmacmd5_update(&ctx, input, 8U);
	result = isc_hmacmd5_verify2(&ctx, expected, sizeof(expected));
	if (!result) {
		return (result);
	}

	/* Second round using a byte key */
	isc_hmacmd5_init(&ctx, key, 1U);
	isc_hmacmd5_update(&ctx, input, 8U);
	return (isc_hmacmd5_verify2(&ctx, expected2, sizeof(expected2)));
}
