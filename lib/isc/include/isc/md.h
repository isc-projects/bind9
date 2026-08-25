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

/*!
 * \file isc/md.h
 * \brief This is the header file for message digest algorithms.
 */

#pragma once

#include <isc/result.h>
#include <isc/types.h>

typedef void isc_md_t;

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
typedef enum isc_md_type {
	ISC_MD_UNKNOWN = 0x00,
	ISC_MD_MD5 = 0x01,
	ISC_MD_SHA1 = 0x02,
	ISC_MD_SHA224 = 0x03,
	ISC_MD_SHA256 = 0x04,
	ISC_MD_SHA384 = 0x05,
	ISC_MD_SHA512 = 0x06,
	ISC_MD_MAX = 0x07,
} isc_md_type_t;

#define ISC_MD5_DIGESTLENGTH	16
#define ISC_MD5_BLOCK_LENGTH	64
#define ISC_SHA1_DIGESTLENGTH	20
#define ISC_SHA1_BLOCK_LENGTH	64
#define ISC_SHA224_DIGESTLENGTH 28
#define ISC_SHA224_BLOCK_LENGTH 64
#define ISC_SHA256_DIGESTLENGTH 32
#define ISC_SHA256_BLOCK_LENGTH 64
#define ISC_SHA384_DIGESTLENGTH 48
#define ISC_SHA384_BLOCK_LENGTH 128
#define ISC_SHA512_DIGESTLENGTH 64
#define ISC_SHA512_BLOCK_LENGTH 128

#define ISC_MAX_MD_SIZE	   64U	/* EVP_MAX_MD_SIZE */
#define ISC_MAX_BLOCK_SIZE 128U /* ISC_SHA512_BLOCK_LENGTH */

/**
 * isc_md:
 * @type: the digest type
 * @buf: the data to hash
 * @len: the length of the data to hash
 * @digest: the output buffer
 * @digestlen: the length of the data written to @digest
 *
 * This function hashes @len bytes of data at @buf and places the result in
 * @digest.  If the @digestlen parameter is not NULL then the number of bytes of
 * data written (i.e. the length of the digest) will be written to the integer
 * at @digestlen, at most ISC_MAX_MD_SIZE bytes will be written.
 */
isc_result_t
isc_md(isc_md_type_t type, const unsigned char *buf, const size_t len,
       unsigned char *digest, unsigned int *digestlen);

/**
 * isc_md_new:
 *
 * This function allocates, initializes and returns a digest context.
 */
isc_md_t *
isc_md_new(void);

/**
 * isc_md_free:
 * @md: message digest context
 *
 * This function cleans up digest context ctx and frees up the space allocated
 * to it.
 */
void
isc_md_free(isc_md_t *md);

/**
 * isc_md_init:
 * @md: message digest context
 * @type: digest type
 *
 * This function sets up digest context @md to use a digest @type. @md must be
 * initialized before calling this function.
 */
isc_result_t
isc_md_init(isc_md_t *md, isc_md_type_t type);

/**
 * isc_md_reset:
 * @md: message digest context
 *
 * This function resets the digest context ctx. This can be used to reuse an
 * already existing context.
 */
isc_result_t
isc_md_reset(isc_md_t *md);

/**
 * isc_md_update:
 * @md: message digest context
 * @buf: data to hash
 * @len: length of the data to hash
 *
 * This function hashes @len bytes of data at @buf into the digest context @md.
 * This function can be called several times on the same @md to hash additional
 * data.
 */
isc_result_t
isc_md_update(isc_md_t *md, const unsigned char *buf, const size_t len);

/**
 * isc_md_final:
 * @md: message digest context
 * @digest: the output buffer
 * @digestlen: the length of the data written to @digest
 *
 * This function retrieves the digest value from @md and places it in @digest.
 * If the @digestlen parameter is not NULL then the number of bytes of data
 * written (i.e. the length of the digest) will be written to the integer at
 * @digestlen, at most ISC_MAX_MD_SIZE bytes will be written.  After calling
 * this function no additional calls to isc_md_update() can be made.
 */
isc_result_t
isc_md_final(isc_md_t *md, unsigned char *digest, unsigned int *digestlen);

/**
 * isc_md_size:
 *
 * This function return the size of the message digest when passed an isc_md_t
 * structure, i.e. the size of the hash.
 */
size_t
isc_md_get_size(isc_md_t *md);

/**
 * isc_md_block_size:
 *
 * This function return the block size of the message digest when passed an
 * isc_md_t structure.
 */
size_t
isc_md_get_block_size(isc_md_t *md);

/**
 * isc_md_block_size:
 *
 * This function return the block size of the message digest when passed an
 * isc_md_type_t.
 */
size_t
isc_md_type_get_block_size(isc_md_type_t type);
