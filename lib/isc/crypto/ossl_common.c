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

#include <isc/crypto.h>
#include <isc/md.h>
#include <isc/ossl_wrap.h>
#include <isc/util.h>

EVP_MD *isc__crypto_md[] = {
	[ISC_MD_UNKNOWN] = NULL, [ISC_MD_MD5] = NULL,	 [ISC_MD_SHA1] = NULL,
	[ISC_MD_SHA224] = NULL,	 [ISC_MD_SHA256] = NULL, [ISC_MD_SHA384] = NULL,
	[ISC_MD_SHA512] = NULL,
};
