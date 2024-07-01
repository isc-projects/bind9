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

#pragma once

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>

/*
 * Limit the size of public exponents.
 */
#ifndef RSA_MAX_PUBEXP_BITS
#define RSA_MAX_PUBEXP_BITS 35
#endif /* ifndef RSA_MAX_PUBEXP_BITS */

#if !HAVE_ERR_GET_ERROR_ALL
unsigned long
ERR_get_error_all(const char **file, int *line, const char **func,
		  const char **data, int *flags);
#endif /* if !HAVE_ERR_GET_ERROR_ALL */

#if !HAVE_EVP_PKEY_EQ
#define EVP_PKEY_eq EVP_PKEY_cmp
#endif
