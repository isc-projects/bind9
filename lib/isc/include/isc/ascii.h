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

#include <stdint.h>

/*
 * ASCII case conversion
 */
extern const uint8_t isc__ascii_tolower[256];
extern const uint8_t isc__ascii_toupper[256];

/*
 * Wrappers so we don't have to cast all over the place like <ctype.h>
 */
#define isc_ascii_tolower(c) isc__ascii_tolower[(uint8_t)(c)]
#define isc_ascii_toupper(c) isc__ascii_toupper[(uint8_t)(c)]

/*
 * Convert a string to lower case in place
 */
static inline void
isc_ascii_strtolower(char *str) {
	for (size_t len = strlen(str); len > 0; len--, str++) {
		*str = isc_ascii_tolower(*str);
	}
}
