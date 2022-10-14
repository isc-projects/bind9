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

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <isc/ascii.h>
#include <isc/entropy.h>
#include <isc/hash.h> /* IWYU pragma: keep */
#include <isc/once.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/siphash.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

static uint8_t isc_hash_key[16];
static uint8_t isc_hash32_key[8];
static bool hash_initialized = false;
static isc_once_t isc_hash_once = ISC_ONCE_INIT;

static void
isc_hash_initialize(void) {
	/*
	 * Set a constant key to help in problem reproduction should
	 * fuzzing find a crash or a hang.
	 */
	uint64_t key[2] = { 0, 1 };
#if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	isc_entropy_get(key, sizeof(key));
#endif /* if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
	memmove(isc_hash_key, key, sizeof(isc_hash_key));
#if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	isc_entropy_get(key, sizeof(key));
#endif /* if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
	memmove(isc_hash32_key, key, sizeof(isc_hash32_key));
	hash_initialized = true;
}

const void *
isc_hash_get_initializer(void) {
	if (!hash_initialized) {
		isc_once_do(&isc_hash_once, isc_hash_initialize);
	}

	return (isc_hash_key);
}

void
isc_hash_set_initializer(const void *initializer) {
	REQUIRE(initializer != NULL);

	/*
	 * Ensure that isc_hash_initialize() is not called after
	 * isc_hash_set_initializer() is called.
	 */
	if (!hash_initialized) {
		isc_once_do(&isc_hash_once, isc_hash_initialize);
	}

	memmove(isc_hash_key, initializer, sizeof(isc_hash_key));
}

uint64_t
isc_hash64(const void *data, const size_t length, const bool case_sensitive) {
	uint64_t hval;

	REQUIRE(length == 0 || data != NULL);

	isc_once_do(&isc_hash_once, isc_hash_initialize);

	isc_siphash24(isc_hash_key, data, length, case_sensitive,
		      (uint8_t *)&hval);

	return (hval);
}

uint32_t
isc_hash32(const void *data, const size_t length, const bool case_sensitive) {
	uint32_t hval;

	REQUIRE(length == 0 || data != NULL);

	isc_once_do(&isc_hash_once, isc_hash_initialize);

	isc_halfsiphash24(isc_hash_key, data, length, case_sensitive,
			  (uint8_t *)&hval);

	return (hval);
}
