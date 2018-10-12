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

#include <stdio.h>

#include <isc/md.h>
#include <isc/util.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "openssl_shim.h"

isc_md_t *
isc_md_new(void) {
	isc_md_t *md = EVP_MD_CTX_new();
	RUNTIME_CHECK(md != NULL);
	return (md);
}

void
isc_md_free(isc_md_t *md) {
	if (ISC_UNLIKELY(md == NULL)) {
		return;
	}
	EVP_MD_CTX_free(md);
}

isc_result_t
isc_md_init(isc_md_t *md, const isc_md_type_t md_type) {
	REQUIRE(md != NULL);

	if (md_type == NULL) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	return (EVP_DigestInit_ex(md, md_type, NULL) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_md_reset(isc_md_t *md) {
	REQUIRE(md != NULL);
	return (EVP_MD_CTX_reset(md) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_md_update(isc_md_t *md, const unsigned char *buf, const size_t len) {
	REQUIRE(md != NULL);

	if (ISC_UNLIKELY(buf == NULL || len == 0)) {
		return (ISC_R_SUCCESS);
	}
	return (EVP_DigestUpdate(md, buf, len) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_md_final(isc_md_t *md, unsigned char *digest, unsigned int *digestlen) {
	REQUIRE(md != NULL);
	REQUIRE(digest != NULL);

	return (EVP_DigestFinal_ex(md, digest, digestlen) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_md_type_t
isc_md_get_md_type(isc_md_t *md) {
	REQUIRE(md != NULL);

	return (EVP_MD_CTX_md(md));
}

int
isc_md_get_size(isc_md_t *md) {
	REQUIRE(md != NULL);

	return (EVP_MD_CTX_size(md));
}

int
isc_md_get_block_size(isc_md_t *md) {
	REQUIRE(md != NULL);

	return (EVP_MD_CTX_block_size(md));
}

int
isc_md_type_get_size(isc_md_type_t md_type) {
	return ((md_type != NULL)
		? EVP_MD_size(md_type)
		: ISC_MAX_MD_SIZE);
}

int
isc_md_type_get_block_size(isc_md_type_t md_type) {
	return ((md_type != NULL)
		? EVP_MD_block_size(md_type)
		: ISC_MAX_BLOCK_SIZE);
}

isc_result_t
isc_md(isc_md_type_t md_type,
       const unsigned char *buf,
       const size_t len,
       unsigned char *digest,
       unsigned int *digestlen) {
	isc_md_t *md;
	isc_result_t res;

	md = isc_md_new();

	res = isc_md_init(md, md_type);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}

	res = isc_md_update(md, buf, len);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}

	res = isc_md_final(md, digest, digestlen);
	if (res != ISC_R_SUCCESS) {
		goto end;
	}
end:
	isc_md_free(md);

	return (res);
}
