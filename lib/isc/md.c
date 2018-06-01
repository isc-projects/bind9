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

#if !HAVE_WORKING_EVP_GET_DIGESTBYNAME
#include <string.h>
#endif

#include <isc/util.h>

#include <isc/md.h>

#include <pk11/site.h>

#include <isc/md.h>

#if HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <isc/once.h>
static isc_once_t isc_md_once = ISC_ONCE_INIT;
static void
isc_md_initialize(void) {
	OpenSSL_add_all_algorithms();
}
#endif

#include "openssl_shim.h"

isc_md_t *isc_md_new(void) {
	return (EVP_MD_CTX_new());
}

void isc_md_free(isc_md_t *md) {
	if (ISC_UNLIKELY(md == NULL)) {
		return;
	}
	EVP_MD_CTX_free(md);
}

isc_result_t
isc_md_init(isc_md_t *md, const isc_md_type_t type) {
	REQUIRE(md != NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RUNTIME_CHECK(isc_once_do(&isc_md_once,
				  isc_md_initialize) == ISC_R_SUCCESS);
#endif

	const EVP_MD *md_type = EVP_get_digestbynid(type);
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
		return ISC_R_SUCCESS;
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

int
isc_md_size(const isc_md_t *md) {
	REQUIRE(md != NULL);
	return (EVP_MD_CTX_size(md));
}

int
isc_md_block_size(const isc_md_t *md) {
	REQUIRE(md != NULL);
	return (EVP_MD_CTX_block_size(md));
}

isc_result_t
isc_md(isc_md_type_t type, const unsigned char *buf, const size_t len, unsigned char *digest, unsigned int *digestlen) {
	isc_md_t *md;
	isc_result_t res;

	if ((md = isc_md_new()) == NULL) {
		return (ISC_R_NOMEMORY);
	}
	if ((res = isc_md_init(md, type)) != ISC_R_SUCCESS) {
		return (res);
	}
	if ((res = isc_md_update(md, buf, len)) != ISC_R_SUCCESS) {
		return (res);
	}
	if ((res = isc_md_final(md, digest, digestlen)) != ISC_R_SUCCESS) {
		return (res);
	}
	isc_md_free(md);

	return (ISC_R_SUCCESS);
}

#elif HAVE_PKCS11 /* HAVE_OPENSSL */

/* XXX */

#endif /* HAVE_PKCS11 */
