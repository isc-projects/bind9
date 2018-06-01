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

#pragma once

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>
#include <isc/result.h>

#if HAVE_OPENSSL

#include <openssl/evp.h>

#define ISC_MAX_MD_SIZE EVP_MAX_MD_SIZE

typedef EVP_MD_CTX isc_md_t;

typedef enum {
	ISC_MD_MD5    = NID_md5,
	ISC_MD_SHA1   = NID_sha1,
	ISC_MD_SHA224 = NID_sha224,
	ISC_MD_SHA256 = NID_sha256,
	ISC_MD_SHA384 = NID_sha384,
	ISC_MD_SHA512 = NID_sha512
} isc_md_type_t;

isc_result_t
isc_md(isc_md_type_t type, const unsigned char *buf, const size_t len, unsigned char *digest, unsigned int *digestlen);

isc_md_t *
isc_md_new(void);

void
isc_md_free(isc_md_t *md);

isc_result_t
isc_md_init(isc_md_t *md, const isc_md_type_t type);

isc_result_t
isc_md_reset(isc_md_t *ctx);

isc_result_t
isc_md_update(isc_md_t *md, const unsigned char *buf, const size_t len);

isc_result_t
isc_md_final(isc_md_t *md, unsigned char *digest, unsigned int *digestlen);

int
isc_md_size(const isc_md_t *md);

int
isc_md_block_size(const isc_md_t *md);

#elif HAVE_PKCS11

/* XXX */

#endif
