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

/*!
 * \file isc/md.h
 * \brief This is the header file for message digest algorithms.
 */

#pragma once

#include <config.h>

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>
#include <isc/result.h>

#include <openssl/evp.h>

/* XXXOND: EVP_<alg>() can return NULL if not supported
 *         This needs more complicated macro :)
 */
#define ISC_MD5_DIGESTLENGTH    (size_t)EVP_MD_size(EVP_md5())
#define ISC_MD5_BLOCK_LENGTH    (size_t)EVP_MD_block_size(EVP_md5())
#define ISC_SHA1_DIGESTLENGTH   (size_t)EVP_MD_size(EVP_sha1())
#define ISC_SHA1_BLOCK_LENGTH   (size_t)EVP_MD_block_size(EVP_sha1())
#define ISC_SHA224_DIGESTLENGTH (size_t)EVP_MD_size(EVP_sha224())
#define ISC_SHA224_BLOCK_LENGTH (size_t)EVP_MD_block_size(EVP_sha224())
#define ISC_SHA256_DIGESTLENGTH (size_t)EVP_MD_size(EVP_sha256())
#define ISC_SHA256_BLOCK_LENGTH (size_t)EVP_MD_block_size(EVP_sha256())
#define ISC_SHA384_DIGESTLENGTH (size_t)EVP_MD_size(EVP_sha384())
#define ISC_SHA384_BLOCK_LENGTH (size_t)EVP_MD_block_size(EVP_sha384())
#define ISC_SHA512_DIGESTLENGTH (size_t)EVP_MD_size(EVP_sha512())
#define ISC_SHA512_BLOCK_LENGTH (size_t)EVP_MD_block_size(EVP_sha512())

#define ISC_MAX_MD_SIZE EVP_MAX_MD_SIZE
#define ISC_MAX_BLOCK_SIZE EVP_MAX_BLOCK_LENGTH
#define ISC_MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH

typedef EVP_MD_CTX isc_md_t;

/**
 * isc_md_type_t:
 * @ISC_MD_MD5: MD5
 * @ISC_MD_SHA1: SHA-1
 * @ISC_MD_SHA224: SHA-224
 * @ISC_MD_SHA256: SHA-256
 * @ISC_MD_SHA384: SHA-384
 * @ISC_MD_SHA512: SHA-512
 *
 * Enumeration of supported message digest algorithms.
 */
typedef enum {
	ISC_MD_MD5    = NID_md5,
	ISC_MD_SHA1   = NID_sha1,
	ISC_MD_SHA224 = NID_sha224,
	ISC_MD_SHA256 = NID_sha256,
	ISC_MD_SHA384 = NID_sha384,
	ISC_MD_SHA512 = NID_sha512
} isc_md_type_t;

isc_md_t *
isc_md_new(void);

void
isc_md_free(isc_md_t *md);

isc_result_t
isc_md_init(isc_md_t *md, const isc_md_type_t type);

isc_result_t
isc_md_reset(isc_md_t *md);

isc_result_t
isc_md_update(isc_md_t *md, const unsigned char *buf, const size_t len);

isc_result_t
isc_md_final(isc_md_t *md, unsigned char *digest, unsigned int *digestlen);

isc_result_t
isc_md(isc_md_type_t type, const unsigned char *buf, const size_t len, unsigned char *digest, unsigned int *digestlen);
