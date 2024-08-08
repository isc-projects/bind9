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

#include <openssl/evp.h>

#include <isc/types.h>

extern const EVP_MD *isc__crypto_md5;
extern const EVP_MD *isc__crypto_sha1;
extern const EVP_MD *isc__crypto_sha224;
extern const EVP_MD *isc__crypto_sha256;
extern const EVP_MD *isc__crypto_sha384;
extern const EVP_MD *isc__crypto_sha512;

/**
 * Private
 */

void
isc__crypto_setdestroycheck(bool check);

void
isc__crypto_initialize(void);

void
isc__crypto_shutdown(void);
