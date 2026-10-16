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

/*! \file */

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h> /* IWYU pragma: keep */
#include <string.h> /* IWYU pragma: keep */
#include <time.h>   /* IWYU pragma: keep */
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/parseint.h>
#include <isc/util.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(parse_overflow) {
	isc_result_t result;
	uint32_t u32;
	int32_t i32;

	result = isc_parse_uint32(&u32, "123456789012345", 10);
	assert_int_equal(result, ISC_R_RANGE);

	result = isc_parse_uint32(&u32, "12345678901234567890", 10);
	assert_int_equal(result, ISC_R_RANGE);

	result = isc_parse_unsigned_number(&u32, "4294967295", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u32, UINT32_MAX);

	result = isc_parse_unsigned_number(&u32, "4294967296", 10);
	assert_int_equal(result, ISC_R_RANGE);

	result = isc_parse_signed_number(&i32, "-2147483648", 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i32, INT32_MIN);

	result = isc_parse_signed_number(&i32, "-2147483649", 0);
	assert_int_equal(result, ISC_R_RANGE);
}

ISC_RUN_TEST_IMPL(parse_positive) {
	isc_result_t result;
	uint32_t u32;
	uint64_t u64;

	result = isc_parse_uint32(&u32, "1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u32, 1234567890);

	result = isc_parse_uint32(&u32, "+1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u32, 1234567890);

	result = isc_parse_uint64(&u64, "1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u64, 1234567890);

	result = isc_parse_uint64(&u64, "+1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u64, 1234567890);

	result = isc_parse_uint64(&u64, "-1234567890", 10);
	assert_int_equal(result, ISC_R_BADNUMBER);

	result = isc_parse_unsigned_number(&u64, "4294967296", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(u64, 4294967296);
}

ISC_RUN_TEST_IMPL(parse_negative) {
	isc_result_t result;
	int64_t i64;

	result = isc_parse_int64(&i64, "1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, 1234567890);

	result = isc_parse_int64(&i64, "+1234567890", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, 1234567890);

	result = isc_parse_int64(&i64, "-010", 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, -8);

	result = isc_parse_int64(&i64, "-8", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, -8);

	result = isc_parse_int64(&i64, "9223372036854775807", 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, INT64_MAX);

	result = isc_parse_int64(&i64, "-0", 5);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, 0);

	result = isc_parse_int64(&i64, "-000000", 17);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, 0);

	result = isc_parse_int64(&i64, "-9223372036854775807", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, INT64_MIN + 1);

	result = isc_parse_int64(&i64, "-9223372036854775808", 10);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(i64, INT64_MIN);

	result = isc_parse_int64(&i64, "-9223372036854775809", 10);
	assert_int_equal(result, ISC_R_RANGE);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(parse_overflow)
ISC_TEST_ENTRY(parse_positive)
ISC_TEST_ENTRY(parse_negative)

ISC_TEST_LIST_END

ISC_TEST_MAIN
