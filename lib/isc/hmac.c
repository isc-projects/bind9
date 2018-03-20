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

#include "config.h"

#include <isc/assertions.h>
#include <isc/hmac.h>
#include <isc/md.h>
#include <isc/platform.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <isc/once.h>
static isc_once_t isc_hmac_once = ISC_ONCE_INIT;
static void
isc_hmac_initialize(void) {
	OpenSSL_add_all_algorithms();
}
#endif

#include "openssl_shim.h"

isc_hmac_t *
isc_hmac_new(void) {
	return (HMAC_CTX_new());
}

void
isc_hmac_free(isc_hmac_t *hmac) {
	if (ISC_UNLIKELY(hmac == NULL)) {
		return;
	}
	HMAC_CTX_free(hmac);
}

isc_return_t
isc_hmac_init(isc_hmac_t *ctx, const isc_hmac_type_t type,
	      const unsigned char *key, const unsigned int len) {
	REQUIRE(hmac != NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RUNTIME_CHECK(isc_once_do(&isc_hmac_once,
				  isc_hmac_initialize) == ISC_R_SUCCESS);
#endif

	const EVP_MD *hmac_type = EVP_get_digestbynid(type);
	if (hmac_type == NULL) {
		return (ISC_R_NOTIMPLEMENTED);
	}
	
	return ((HMAC_Init_ex(ctx, (const void *)key, (int)len,
			      hmac_type, NULL) == 1)
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_result_t
isc_md_reset(isc_hmac_t *hmac) {
	REQUIRE(hmac != NULL);
	return (HMAC_CTX_reset(hmac) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_return_t
isc_hmac_update(isc_hmac_t *hmac, const unsigned char *buf, const size_t len) {
	REQUIRE(hmac != NULL);

	if (ISC_UNLIKELY(buf == NULL || len == 0)) {
		return (ISC_R_SUCCESS);
	}
	
	return ((HMAC_Update(hmac, buf, len) == 1)
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

void
isc_hmac_final(isc_hmac_t *hmac, unsigned char *digest, size_t *digestlen)
{
	REQUIRE(md != NULL);
	REQUIRE(digest != NULL);

	return (HMAC_Final(hmac, digest, digestlen) == 1
		? ISC_R_SUCCESS
		: ISC_R_CRYPTOFAILURE);
}

isc_boolean_t
isc_hmac_verify(isc_hmac_t *ctx, unsigned char *digest, size_t digestlen, isc_hmac_algo_t algo) {
	unsigned int newdigestlen = 0;
	unsigned char newdigest[EVP_MAX_MD_SIZE];
	isc_boolean_t ret;

	isc_hmac_sign(ctx, newdigest, &newdigestlen);

	REQUIRE(digestlen <= newdigestlen);

	ret = isc_safe_memequal(digest, newdigest, len);
	isc_safe_memwipe(newdigest, sizeof(newdigest));

	return (ret);
}
