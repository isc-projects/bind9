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

#include <isc/assertions.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/sha2.h>
#include <isc/string.h>
#include <isc/util.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new() &(context->_ctx)
#define EVP_MD_CTX_free(ptr) EVP_MD_CTX_cleanup(ptr)
#define EVP_MD_CTX_reset(c) EVP_MD_CTX_cleanup(c)
#endif

void
isc_sha224_init(isc_sha224_t *context) {
	if (context == (isc_sha224_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha224()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA224.");
	}
}

void
isc_sha224_invalidate(isc_sha224_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha224_update(isc_sha224_t *context, const isc_uint8_t* data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha224_final(isc_uint8_t digest[], isc_sha224_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha256_init(isc_sha256_t *context) {
	if (context == (isc_sha256_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha256()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA256.");
	}
}

void
isc_sha256_invalidate(isc_sha256_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha256_update(isc_sha256_t *context, const isc_uint8_t *data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha256_final(isc_uint8_t digest[], isc_sha256_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha512_init(isc_sha512_t *context) {
	if (context == (isc_sha512_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha512()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA512.");
	}
}

void
isc_sha512_invalidate(isc_sha512_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void isc_sha512_update(isc_sha512_t *context, const isc_uint8_t *data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void isc_sha512_final(isc_uint8_t digest[], isc_sha512_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha384_init(isc_sha384_t *context) {
	if (context == (isc_sha384_t *)0) {
		return;
	}
	context->ctx = EVP_MD_CTX_new();
	RUNTIME_CHECK(context->ctx != NULL);
	if (EVP_DigestInit(context->ctx, EVP_sha384()) != 1) {
		FATAL_ERROR(__FILE__, __LINE__, "Cannot initialize SHA384.");
	}
}

void
isc_sha384_invalidate(isc_sha384_t *context) {
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

void
isc_sha384_update(isc_sha384_t *context, const isc_uint8_t* data, size_t len) {
	if (len == 0U) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);
	REQUIRE(data != (isc_uint8_t*)0);

	RUNTIME_CHECK(EVP_DigestUpdate(context->ctx,
				       (const void *) data, len) == 1);
}

void
isc_sha384_final(isc_uint8_t digest[], isc_sha384_t *context) {
	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);
	REQUIRE(context->ctx != (EVP_MD_CTX *)0);

	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != (isc_uint8_t*)0)
		RUNTIME_CHECK(EVP_DigestFinal(context->ctx,
					      digest, NULL) == 1);
	EVP_MD_CTX_free(context->ctx);
	context->ctx = NULL;
}

/*
 * Constant used by SHA256/384/512_End() functions for converting the
 * digest to a readable hexadecimal character string:
 */
static const char *sha2_hex_digits = "0123456789abcdef";

char *
isc_sha224_end(isc_sha224_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA224_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha224_t *)0);

	if (buffer != (char*)0) {
		isc_sha224_final(digest, context);

		for (i = 0; i < ISC_SHA224_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		EVP_MD_CTX_reset(context->ctx);
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha224_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA224_DIGESTSTRINGLENGTH])
{
	isc_sha224_t context;

	isc_sha224_init(&context);
	isc_sha224_update(&context, data, len);
	return (isc_sha224_end(&context, digest));
}

char *
isc_sha256_end(isc_sha256_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA256_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha256_t *)0);

	if (buffer != (char*)0) {
		isc_sha256_final(digest, context);

		for (i = 0; i < ISC_SHA256_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		EVP_MD_CTX_reset(context->ctx);
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha256_data(const isc_uint8_t* data, size_t len,
		char digest[ISC_SHA256_DIGESTSTRINGLENGTH])
{
	isc_sha256_t context;

	isc_sha256_init(&context);
	isc_sha256_update(&context, data, len);
	return (isc_sha256_end(&context, digest));
}

char *
isc_sha512_end(isc_sha512_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA512_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha512_t *)0);

	if (buffer != (char*)0) {
		isc_sha512_final(digest, context);

		for (i = 0; i < ISC_SHA512_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		EVP_MD_CTX_reset(context->ctx);
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha512_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA512_DIGESTSTRINGLENGTH])
{
	isc_sha512_t 	context;

	isc_sha512_init(&context);
	isc_sha512_update(&context, data, len);
	return (isc_sha512_end(&context, digest));
}

char *
isc_sha384_end(isc_sha384_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA384_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha384_t *)0);

	if (buffer != (char*)0) {
		isc_sha384_final(digest, context);

		for (i = 0; i < ISC_SHA384_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		EVP_MD_CTX_reset(context->ctx);
	}
	isc_safe_memwipe(digest, sizeof(digest));
	return buffer;
}

char *
isc_sha384_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA384_DIGESTSTRINGLENGTH])
{
	isc_sha384_t context;

	isc_sha384_init(&context);
	isc_sha384_update(&context, data, len);
	return (isc_sha384_end(&context, digest));
}
