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
 * \file isc/hmac.h
 * \brief This is the header for message authentication code.
 */

#pragma once

#include <stdbool.h>

#include <isc/md.h>
#include <isc/result.h>
#include <isc/types.h>

typedef void isc_hmac_t;

typedef struct isc_hmac_key isc_hmac_key_t;

/**
 * isc_hmac:
 * @type: the digest type
 * @key: the key
 * @keylen: the length of the key
 * @buf: data to hash
 * @len: length of the data to hash
 * @digest: the output buffer
 * @digestlen: in: the length of @digest
 *             out: the length of the data written to @digest
 *
 * This function computes the message authentication code using a digest type
 * @type with key @key which is @keylen bytes long from data in @buf which is
 * @len bytes long, and places the output into @digest, which must have space
 * for the hash function output (use ISC_MAX_MD_SIZE if unsure). @digestlen
 * is used to pass in the length of the digest buffer and returns the length
 * of digest written to @digest.
 */
isc_result_t
isc_hmac(isc_md_type_t type, const void *key, const size_t keylen,
	 const unsigned char *buf, const size_t len, unsigned char *digest,
	 unsigned int *digestlen);

/*
 * isc_hmac_key_create:
 * @type: the digest type
 * @secret: the secret key
 * @len: length of the secret key
 * @mctx: memory context
 * @keyp: pointer to the key pointer
 *
 * This initializes the an HMAC key bound to a specific digest.
 */
isc_result_t
isc_hmac_key_create(isc_md_type_t type, const void *secret, const size_t len,
		    isc_mem_t *mctx, isc_hmac_key_t **keyp);

void
isc_hmac_key_destroy(isc_hmac_key_t **keyp);

/**
 * isc_hmac_key_expose:
 * @key: The key to be exposed
 *
 * This function exposes the raw bytes of the HMAC key.
 *
 * The region is bound to the lifetime of the @key and MUST NOT be used after
 * calling isc_hmac_key_destroy.
 */
isc_region_t
isc_hmac_key_expose(isc_hmac_key_t *key);

/**
 * isc_hmac_key_equal:
 * @key1: The first key to be compared
 * @key2: The second key to be compared
 *
 * Returns true is the two HMAC keys have the same contents and use the same
 * digest function.
 */
bool
isc_hmac_key_equal(isc_hmac_key_t *key1, isc_hmac_key_t *key2);

/**
 * isc_hmac_new:
 *
 * This function allocates, initializes and returns HMAC context.
 */
isc_hmac_t *
isc_hmac_new(void);

/**
 * isc_hmac_free:
 * @md: HMAC context
 *
 * This function cleans up HMAC context and frees up the space allocated to it.
 */
void
isc_hmac_free(isc_hmac_t *hmac);

/**
 * isc_hmac_init:
 * @md: HMAC context
 * @key: HMAC key
 *
 * This function sets up HMAC context to use the secret specified in @key.
 */
isc_result_t
isc_hmac_init(isc_hmac_t *hmac, isc_hmac_key_t *key);

/**
 * isc_hmac_update:
 * @hmac: HMAC context
 * @buf: data to hash
 * @len: length of the data to hash
 *
 * This function can be called repeatedly with chunks of the message @buf to be
 * authenticated which is @len bytes long.
 */
isc_result_t
isc_hmac_update(isc_hmac_t *hmac, const unsigned char *buf, const size_t len);

/**
 * isc_hmac_final:
 * @hmac: HMAC context
 * @out: the output buffer
 *
 * This function retrieves the message authentication code from @hmac and places
 * it in @out, which must have space for the hash function output.
 *
 * After calling this function no additional calls to isc_hmac_update() can be
 * made. Use isc_hmac_init() to reset/re-initialize the context.
 */
isc_result_t
isc_hmac_final(isc_hmac_t *hmac, isc_buffer_t *out);
