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


/*! \file isc/hmacmd5.h
 * \brief This is the header file for the HMAC-MD5 keyed hash algorithm
 * described in RFC2104.
 */

#pragma once

#include <stdbool.h>

#include <isc/lang.h>
#include <isc/md.h>
#include <isc/platform.h>
#include <isc/types.h>

#define ISC_HMACMD5_KEYLENGTH 64

#include <openssl/opensslv.h>
#include <openssl/hmac.h>

typedef struct {
	HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX _ctx;
#endif
} isc_hmacmd5_t;

ISC_LANG_BEGINDECLS

void
isc_hmacmd5_init(isc_hmacmd5_t *ctx, const unsigned char *key,
		 unsigned int len);

void
isc_hmacmd5_invalidate(isc_hmacmd5_t *ctx);

void
isc_hmacmd5_update(isc_hmacmd5_t *ctx, const unsigned char *buf,
		   unsigned int len);

void
isc_hmacmd5_sign(isc_hmacmd5_t *ctx, unsigned char *digest);

bool
isc_hmacmd5_verify(isc_hmacmd5_t *ctx, unsigned char *digest);

bool
isc_hmacmd5_verify2(isc_hmacmd5_t *ctx, unsigned char *digest, size_t len);

bool
isc_hmacmd5_check(int testing);

ISC_LANG_ENDDECLS
