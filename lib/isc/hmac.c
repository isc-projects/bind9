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
#include <isc/hmac.h>
#include <isc/md.h>
#include <isc/once.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#include "openssl_shim.h"

#if OPENSSL_API_COMPAT < 0x10100000L
static isc_once_t isc_hmac_once = ISC_ONCE_INIT;
#endif

isc_hmac_t *
isc_hmac_new(void) {
#if OPENSSL_API_COMPAT < 0x10100000L
	RUNTIME_CHECK(isc_once_do(&isc_hmac_once,
				  OpenSSL_add_all_ciphers) == ISC_R_SUCCESS);
#endif

	isc_hmac_t *hmac = HMAC_CTX_new();
	RUNTIME_CHECK(hmac != NULL);
	return (hmac);
}

void
isc_hmac_free(isc_hmac_t *hmac) {
	if (ISC_UNLIKELY(hmac == NULL)) {
		return;
	}
	HMAC_CTX_free(hmac);
}

isc_result_t
isc_hmac_init(isc_hmac_t *hmac,
	      const void *key,
	      size_t keylen,
	      isc_md_type_t md_type) {
	REQUIRE(hmac != NULL);

	if (md_type == NULL) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	return (HMAC_Init_ex(hmac, key, keylen, md_type, NULL) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_hmac_reset(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (HMAC_CTX_reset(hmac) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_hmac_update(isc_hmac_t *hmac, const unsigned char *buf, const size_t len) {
	REQUIRE(hmac != NULL);

	if (ISC_UNLIKELY(buf == NULL || len == 0)) {
		return (ISC_R_SUCCESS);
	}
	return (HMAC_Update(hmac, buf, len) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_hmac_final(isc_hmac_t *hmac, unsigned char *digest,
	       unsigned int *digestlen) {
	REQUIRE(hmac != NULL);
	REQUIRE(digest != NULL);

	return (HMAC_Final(hmac, digest, digestlen) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_md_type_t
isc_hmac_get_md_type(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (HMAC_CTX_get_md(hmac));
}

int
isc_hmac_get_size(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (EVP_MD_size(HMAC_CTX_get_md(hmac)));
}

int
isc_hmac_get_block_size(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (EVP_MD_block_size(HMAC_CTX_get_md(hmac)));
}

isc_result_t
isc_hmac(isc_md_type_t type,
	 const void *key,
	 const int keylen,
	 const unsigned char *buf,
	 const size_t len,
	 unsigned char *digest,
	 unsigned int *digestlen)
{
	isc_hmac_t *hmac = NULL;
	isc_result_t res;

	hmac = isc_hmac_new();

	res = isc_hmac_init(hmac, key, keylen, type);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}

	res = isc_hmac_update(hmac, buf, len);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}

	res = isc_hmac_final(hmac, digest, digestlen);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}
 end:
	isc_hmac_free(hmac);

	return (res);
}
