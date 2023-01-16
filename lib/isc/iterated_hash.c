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

#include <stdio.h>

#include <openssl/evp.h>

#include <isc/iterated_hash.h>
#include <isc/md.h>
#include <isc/util.h>

int
isc_iterated_hash(unsigned char *out, const unsigned int hashalg,
		  const int iterations, const unsigned char *salt,
		  const int saltlength, const unsigned char *in,
		  const int inlength) {
	REQUIRE(out != NULL);

	int n = 0;
	size_t len;
	unsigned int outlength = 0;
	const unsigned char *buf;
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();

	RUNTIME_CHECK(ctx != NULL);

	if (hashalg != 1) {
		return (0);
	}

	len = inlength;
	buf = in;
	do {
		if (EVP_DigestInit_ex(ctx, ISC_MD_SHA1, NULL) != 1) {
			goto fail;
		}

		if (EVP_DigestUpdate(ctx, buf, len) != 1) {
			goto fail;
		}

		if (EVP_DigestUpdate(ctx, salt, saltlength) != 1) {
			goto fail;
		}

		if (EVP_DigestFinal_ex(ctx, out, &outlength) != 1) {
			goto fail;
		}

		buf = out;
		len = outlength;
	} while (n++ < iterations);

	EVP_MD_CTX_free(ctx);

	return (outlength);

fail:
	EVP_MD_CTX_free(ctx);
	return (0);
}
