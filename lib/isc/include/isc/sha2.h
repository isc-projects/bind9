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

#include <stdint.h>

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

/*** SHA-224/256/384/512 Various Length Definitions ***********************/

#define ISC_SHA224_BLOCK_LENGTH		64U
#define ISC_SHA224_DIGESTLENGTH	28U
#define ISC_SHA224_DIGESTSTRINGLENGTH	(ISC_SHA224_DIGESTLENGTH * 2 + 1)
#define ISC_SHA256_BLOCK_LENGTH		64U
#define ISC_SHA256_DIGESTLENGTH	32U
#define ISC_SHA256_DIGESTSTRINGLENGTH	(ISC_SHA256_DIGESTLENGTH * 2 + 1)
#define ISC_SHA384_BLOCK_LENGTH		128
#define ISC_SHA384_DIGESTLENGTH	48U
#define ISC_SHA384_DIGESTSTRINGLENGTH	(ISC_SHA384_DIGESTLENGTH * 2 + 1)
#define ISC_SHA512_BLOCK_LENGTH		128U
#define ISC_SHA512_DIGESTLENGTH	64U
#define ISC_SHA512_DIGESTSTRINGLENGTH	(ISC_SHA512_DIGESTLENGTH * 2 + 1)

/*** SHA-256/384/512 Context Structures *******************************/

#include <openssl/opensslv.h>
#include <openssl/evp.h>

typedef struct {
	EVP_MD_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_MD_CTX _ctx;
#endif
} isc_sha2_t;

typedef isc_sha2_t isc_sha256_t;
typedef isc_sha2_t isc_sha512_t;

typedef isc_sha256_t isc_sha224_t;
typedef isc_sha512_t isc_sha384_t;

ISC_LANG_BEGINDECLS

/*** SHA-224/256/384/512 Function Prototypes ******************************/

void isc_sha224_init (isc_sha224_t *);
void isc_sha224_invalidate (isc_sha224_t *);
void isc_sha224_update (isc_sha224_t *, const uint8_t *, size_t);
void isc_sha224_final (uint8_t[ISC_SHA224_DIGESTLENGTH], isc_sha224_t *);
char *isc_sha224_end (isc_sha224_t *, char[ISC_SHA224_DIGESTSTRINGLENGTH]);
char *isc_sha224_data (const uint8_t *, size_t, char[ISC_SHA224_DIGESTSTRINGLENGTH]);

void isc_sha256_init (isc_sha256_t *);
void isc_sha256_invalidate (isc_sha256_t *);
void isc_sha256_update (isc_sha256_t *, const uint8_t *, size_t);
void isc_sha256_final (uint8_t[ISC_SHA256_DIGESTLENGTH], isc_sha256_t *);
char *isc_sha256_end (isc_sha256_t *, char[ISC_SHA256_DIGESTSTRINGLENGTH]);
char *isc_sha256_data (const uint8_t *, size_t, char[ISC_SHA256_DIGESTSTRINGLENGTH]);

void isc_sha384_init (isc_sha384_t *);
void isc_sha384_invalidate (isc_sha384_t *);
void isc_sha384_update (isc_sha384_t *, const uint8_t *, size_t);
void isc_sha384_final (uint8_t[ISC_SHA384_DIGESTLENGTH], isc_sha384_t *);
char *isc_sha384_end (isc_sha384_t *, char[ISC_SHA384_DIGESTSTRINGLENGTH]);
char *isc_sha384_data (const uint8_t *, size_t, char[ISC_SHA384_DIGESTSTRINGLENGTH]);

void isc_sha512_init (isc_sha512_t *);
void isc_sha512_invalidate (isc_sha512_t *);
void isc_sha512_update (isc_sha512_t *, const uint8_t *, size_t);
void isc_sha512_final (uint8_t[ISC_SHA512_DIGESTLENGTH], isc_sha512_t *);
char *isc_sha512_end (isc_sha512_t *, char[ISC_SHA512_DIGESTSTRINGLENGTH]);
char *isc_sha512_data (const uint8_t *, size_t, char[ISC_SHA512_DIGESTSTRINGLENGTH]);

ISC_LANG_ENDDECLS
