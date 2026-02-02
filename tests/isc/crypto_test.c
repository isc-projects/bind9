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
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/crypto.h>
#include <isc/lib.h>
#include <isc/md.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(hkdf) {
	isc_result_t result;
	uint8_t actual[42];

	const uint8_t ikm[22] = { [0 ... 21] = 0x0B };
	const uint8_t salt[13] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	};
	const uint8_t info[10] = {
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9,
	};
	const uint8_t expected[42] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};

	result = isc_crypto_hkdf((isc_region_t){ actual, sizeof(actual) },
				 ISC_MD_SHA256,
				 (isc_constregion_t){ ikm, sizeof(ikm) },
				 (isc_constregion_t){ salt, sizeof(salt) },
				 (isc_constregion_t){ info, sizeof(info) });
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_memory_equal(expected, actual, 42);
}

ISC_RUN_TEST_IMPL(hkdf_expand_label) {
	isc_result_t result;
	uint8_t actual[32];

	/*
	 * Values are taken from RFC 9001 Appendix A.1.
	 */
	const uint8_t secret[32] = {
		0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
		0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
		0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
		0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
	};

	const uint8_t expected[32] = {
		0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
		0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
		0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
		0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
	};

	result = isc_crypto_hkdf_expand_label(
		(isc_region_t){ actual, sizeof(actual) }, ISC_MD_SHA256,
		(isc_constregion_t){ secret, sizeof(secret) },
		(isc_constregion_t){ "client in", sizeof("client in") - 1 });
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_memory_equal(expected, actual, 32);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(hkdf)
ISC_TEST_ENTRY(hkdf_expand_label)
ISC_TEST_LIST_END

ISC_TEST_MAIN
