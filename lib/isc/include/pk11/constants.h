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

#ifndef PK11_CONSTANTS_H
#define PK11_CONSTANTS_H 1

#include <pk11/pk11.h>

/*! \file pk11/constants.h */

/*%
 * Static arrays of data used for key template initialization
 */
static CK_BYTE pk11_ecc_prime256v1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
					 0xce, 0x3d, 0x03, 0x01, 0x07 };
static CK_BYTE pk11_ecc_secp384r1[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};
static CK_BYTE pk11_ecc_ed25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
static CK_BYTE pk11_ecc_ed448[] = { 0x06, 0x03, 0x2b, 0x65, 0x71 };

#endif /* PK11_CONSTANTS_H */
