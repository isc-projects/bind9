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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <isc/assertions.h>
#include <isc/hmac.h>
#include <isc/md.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include "openssl_shim.h"

isc_hmac_t *
isc_hmac_new(void) {
	EVP_MD_CTX *hmac = EVP_MD_CTX_new();
	RUNTIME_CHECK(hmac != NULL);
	return ((isc_hmac_t *)hmac);
}

void
isc_hmac_free(isc_hmac_t *hmac) {
	if (hmac == NULL) {
		return;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)hmac);
}

isc_result_t
isc_hmac_init(isc_hmac_t *hmac, const void *key, const size_t keylen,
	      const isc_md_type_t *md_type) {
	EVP_PKEY *pkey;

	REQUIRE(hmac != NULL);
	REQUIRE(key != NULL);
	REQUIRE(keylen <= INT_MAX);

	if (md_type == NULL) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keylen);
	if (pkey == NULL) {
		ERR_clear_error();
		return (ISC_R_CRYPTOFAILURE);
	}

	if (EVP_DigestSignInit(hmac, NULL, md_type, NULL, pkey) != 1) {
		EVP_PKEY_free(pkey);
		ERR_clear_error();
		return (ISC_R_CRYPTOFAILURE);
	}

	EVP_PKEY_free(pkey);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_hmac_reset(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	if (EVP_MD_CTX_reset(hmac) != 1) {
		ERR_clear_error();
		return (ISC_R_CRYPTOFAILURE);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_hmac_update(isc_hmac_t *hmac, const unsigned char *buf, const size_t len) {
	REQUIRE(hmac != NULL);

	if (buf == NULL || len == 0) {
		return (ISC_R_SUCCESS);
	}

	if (EVP_DigestSignUpdate(hmac, buf, len) != 1) {
		ERR_clear_error();
		return (ISC_R_CRYPTOFAILURE);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_hmac_final(isc_hmac_t *hmac, unsigned char *digest,
	       unsigned int *digestlen) {
	REQUIRE(hmac != NULL);
	REQUIRE(digest != NULL);
	REQUIRE(digestlen != NULL);

	size_t len = *digestlen;

	if (EVP_DigestSignFinal(hmac, digest, &len) != 1) {
		ERR_clear_error();
		return (ISC_R_CRYPTOFAILURE);
	}

	*digestlen = (unsigned int)len;

	return (ISC_R_SUCCESS);
}

const isc_md_type_t *
isc_hmac_get_md_type(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (EVP_MD_CTX_get0_md(hmac));
}

size_t
isc_hmac_get_size(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return ((size_t)EVP_MD_CTX_size(hmac));
}

int
isc_hmac_get_block_size(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);

	return (EVP_MD_CTX_block_size(hmac));
}

isc_result_t
isc_hmac(const isc_md_type_t *type, const void *key, const size_t keylen,
	 const unsigned char *buf, const size_t len, unsigned char *digest,
	 unsigned int *digestlen) {
	isc_result_t res;
	isc_hmac_t *hmac = isc_hmac_new();

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
