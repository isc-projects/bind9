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


/*! \file isc/md5.h
 * \brief This is the header file for the MD5 message-digest algorithm.
 */

#pragma once

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

#define ISC_MD5_DIGESTLENGTH 16U
#define ISC_MD5_BLOCK_LENGTH 64U

#include <openssl/opensslv.h>
#include <openssl/evp.h>

typedef struct {
	EVP_MD_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_MD_CTX _ctx;
#endif
} isc_md5_t;

ISC_LANG_BEGINDECLS

void
isc_md5_init(isc_md5_t *ctx);

void
isc_md5_invalidate(isc_md5_t *ctx);

void
isc_md5_update(isc_md5_t *ctx, const unsigned char *buf, unsigned int len);

void
isc_md5_final(isc_md5_t *ctx, unsigned char *digest);

isc_boolean_t
isc_md5_check(isc_boolean_t testing);

ISC_LANG_ENDDECLS
