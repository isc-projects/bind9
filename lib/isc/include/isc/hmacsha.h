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


/*! \file isc/hmacsha.h
 * This is the header file for the HMAC-SHA1, HMAC-SHA224, HMAC-SHA256,
 * HMAC-SHA334 and HMAC-SHA512 hash algorithm described in RFC 2104.
 */

#pragma once

#include <stdbool.h>

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/md.h>
#include <isc/types.h>

#define ISC_HMACSHA1_KEYLENGTH   ISC_SHA1_BLOCK_LENGTH
#define ISC_HMACSHA224_KEYLENGTH ISC_SHA224_BLOCK_LENGTH
#define ISC_HMACSHA256_KEYLENGTH ISC_SHA256_BLOCK_LENGTH
#define ISC_HMACSHA384_KEYLENGTH ISC_SHA384_BLOCK_LENGTH
#define ISC_HMACSHA512_KEYLENGTH ISC_SHA512_BLOCK_LENGTH

#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#define ISC_HMAC_MAX_MD_CBLOCK HMAC_MAX_MD_CBLOCK

typedef struct {
	HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX _ctx;
#endif
} isc_hmacsha_t;

typedef isc_hmacsha_t isc_hmacsha1_t;
typedef isc_hmacsha_t isc_hmacsha224_t;
typedef isc_hmacsha_t isc_hmacsha256_t;
typedef isc_hmacsha_t isc_hmacsha384_t;
typedef isc_hmacsha_t isc_hmacsha512_t;

ISC_LANG_BEGINDECLS

void
isc_hmacsha1_init(isc_hmacsha1_t *ctx, const unsigned char *key,
		  unsigned int len);

void
isc_hmacsha1_invalidate(isc_hmacsha1_t *ctx);

void
isc_hmacsha1_update(isc_hmacsha1_t *ctx, const unsigned char *buf,
		    unsigned int len);

void
isc_hmacsha1_sign(isc_hmacsha1_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha1_verify(isc_hmacsha1_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha1_check(int testing);


void
isc_hmacsha224_init(isc_hmacsha224_t *ctx, const unsigned char *key,
		    unsigned int len);

void
isc_hmacsha224_invalidate(isc_hmacsha224_t *ctx);

void
isc_hmacsha224_update(isc_hmacsha224_t *ctx, const unsigned char *buf,
		      unsigned int len);

void
isc_hmacsha224_sign(isc_hmacsha224_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha224_verify(isc_hmacsha224_t *ctx, unsigned char *digest, size_t len);


void
isc_hmacsha256_init(isc_hmacsha256_t *ctx, const unsigned char *key,
		    unsigned int len);

void
isc_hmacsha256_invalidate(isc_hmacsha256_t *ctx);

void
isc_hmacsha256_update(isc_hmacsha256_t *ctx, const unsigned char *buf,
		      unsigned int len);

void
isc_hmacsha256_sign(isc_hmacsha256_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha256_verify(isc_hmacsha256_t *ctx, unsigned char *digest, size_t len);


void
isc_hmacsha384_init(isc_hmacsha384_t *ctx, const unsigned char *key,
		    unsigned int len);

void
isc_hmacsha384_invalidate(isc_hmacsha384_t *ctx);

void
isc_hmacsha384_update(isc_hmacsha384_t *ctx, const unsigned char *buf,
		      unsigned int len);

void
isc_hmacsha384_sign(isc_hmacsha384_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha384_verify(isc_hmacsha384_t *ctx, unsigned char *digest, size_t len);


void
isc_hmacsha512_init(isc_hmacsha512_t *ctx, const unsigned char *key,
		    unsigned int len);

void
isc_hmacsha512_invalidate(isc_hmacsha512_t *ctx);

void
isc_hmacsha512_update(isc_hmacsha512_t *ctx, const unsigned char *buf,
		      unsigned int len);

void
isc_hmacsha512_sign(isc_hmacsha512_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacsha512_verify(isc_hmacsha512_t *ctx, unsigned char *digest, size_t len);

ISC_LANG_ENDDECLS
