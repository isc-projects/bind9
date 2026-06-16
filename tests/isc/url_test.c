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
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/mem.h>
#include <isc/url.h>
#include <isc/util.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(parse) {
	isc_result_t result;
	isc_url_parser_t up = { 0 };
	const char *url = NULL;

	/* Test an empty buffer. */
	url = "";
	result = isc_url_parse(url, strlen(url), 0, &up);
	assert_int_equal(ISC_R_RANGE, result);

	/* Test a buffer with a valid URI. */
	url = "http://user:pass@example.com:8080/test?a=b&c=d";
	result = isc_url_parse(url, strlen(url), false, &up);
	assert_int_equal(ISC_R_SUCCESS, result);
	assert_int_equal(0, up.field_data[ISC_UF_SCHEMA].off);
	assert_int_equal(4, up.field_data[ISC_UF_SCHEMA].len);
	assert_int_equal(17, up.field_data[ISC_UF_HOST].off);
	assert_int_equal(11, up.field_data[ISC_UF_HOST].len);
	assert_int_equal(29, up.field_data[ISC_UF_PORT].off);
	assert_int_equal(4, up.field_data[ISC_UF_PORT].len);
	assert_int_equal(33, up.field_data[ISC_UF_PATH].off);
	assert_int_equal(5, up.field_data[ISC_UF_PATH].len);
	assert_int_equal(39, up.field_data[ISC_UF_QUERY].off);
	assert_int_equal(7, up.field_data[ISC_UF_QUERY].len);
	assert_int_equal(0, up.field_data[ISC_UF_FRAGMENT].off);
	assert_int_equal(0, up.field_data[ISC_UF_FRAGMENT].len);
	assert_int_equal(7, up.field_data[ISC_UF_USERINFO].off);
	assert_int_equal(9, up.field_data[ISC_UF_USERINFO].len);

	/* Test a too big buffer. */
	url = "https://localhost/";
	size_t buf_len = UINT16_MAX + 2;
	char *buf = isc_mem_get(mctx, buf_len);
	snprintf(buf, buf_len - 1, "%-65535s", url); /* Pad with spaces */
	buf[buf_len - 1] = '\0'; /* Ensure ending with Null-byte */
	result = isc_url_parse(buf, buf_len - 1, 0, &up);
	isc_mem_put(mctx, buf, buf_len);
	assert_int_equal(ISC_R_RANGE, result);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(parse)

ISC_TEST_LIST_END

ISC_TEST_MAIN
