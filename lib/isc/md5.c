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


/*! \file
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#include "config.h"

#include <isc/assertions.h>
#include <isc/md5.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/types.h>

#include <isc/util.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new() &(ctx->_ctx)
#define EVP_MD_CTX_free(ptr) EVP_MD_CTX_cleanup(ptr)
#endif

void
isc_md5_init(isc_md5_t *ctx) {
	ctx->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(ctx->ctx != NULL);
	if (EVP_DigestInit(ctx->ctx, EVP_md5()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize MD5.");
	}
}

void
isc_md5_invalidate(isc_md5_t *ctx) {
	EVP_MD_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

void
isc_md5_update(isc_md5_t *ctx, const unsigned char *buf, unsigned int len) {
	if (len == 0U)
		return;
	RUNTIME_CHECK(EVP_DigestUpdate(ctx->ctx,
				       (const void *) buf,
				       (size_t) len) == 1);
}

void
isc_md5_final(isc_md5_t *ctx, unsigned char *digest) {
	RUNTIME_CHECK(EVP_DigestFinal(ctx->ctx, digest, NULL) == 1);
	EVP_MD_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

/*
 * Check for MD5 support; if it does not work, raise a fatal error.
 *
 * Use "a" as the test vector.
 *
 * Standard use is testing false and result true.
 * Testing use is testing true and result false;
 */
isc_boolean_t
isc_md5_check(isc_boolean_t testing) {
	isc_md5_t ctx;
	unsigned char input = 'a';
	unsigned char digest[ISC_MD5_DIGESTLENGTH];
	unsigned char expected[] = {
		0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
		0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61
	};

	INSIST(sizeof(expected) == ISC_MD5_DIGESTLENGTH);

	/*
	 * Introduce a fault for testing.
	 */
	if (testing) {
		input ^= 0x01;
	}

	/*
	 * These functions do not return anything; any failure will be fatal.
	 */
	isc_md5_init(&ctx);
	isc_md5_update(&ctx, &input, 1U);
	isc_md5_final(&ctx, digest);

	/*
	 * Must return true in standard case, should return false for testing.
	 */
	return (ISC_TF(memcmp(digest, expected, ISC_MD5_DIGESTLENGTH) == 0));
}
