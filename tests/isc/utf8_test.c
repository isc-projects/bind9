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

#include <ctype.h>
#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/utf8.h>

#include <tests/isc.h>

static void
valid(const char *str) {
	assert_true(isc_utf8_valid((const unsigned char *)str, strlen(str)));
}

static void
invalid(const char *str) {
	assert_false(isc_utf8_valid((const unsigned char *)str, strlen(str)));
}

static void
validbom(const char *str) {
	assert_true(isc_utf8_bom((const unsigned char *)str, strlen(str)));
}

static void
invalidbom(const char *str) {
	assert_false(isc_utf8_bom((const unsigned char *)str, strlen(str)));
}

ISC_RUN_TEST_IMPL(test_utf8_ascii) {
	valid("#1@#'Been a long lonely, lonely, lonely, lonely, lonely time");
}

ISC_RUN_TEST_IMPL(test_utf8_twobytes) {
	/*
	 * 0xC280 -> 1100 0010 1000 0000 (unicode character 0x80, below it's
	 * ASCII, so it would be invalid)
	 *
	 * 0xDFBF -> 1101 1111 1011 1111 (unicode character 0x07FF)
	 */
	invalid("invalid 2-bytes sequence: \xC0\x80 (invalid)");
	valid("2-bytes sequence: \xC2\x80 (begining of the range)");
	valid("2-bytes sequence: \xDF\xBF (end of range)");
	invalid("invalid (second bytes doesn't starts with 10__) \xDF\xFF");
}

ISC_RUN_TEST_IMPL(test_utf8_threebytes) {
	/*
	 * 0x0800 (first valid unicode character holding in 3 bytes in UTF-8) is
	 * 0000 |1000 00|00 0000 which encodes in
	 *
	 * 1110 ____ 10__ ____ 10__ ____
	 * 1110 0000 1010 0000 1000 0000
	 *
	 * So, 0xE0A080
	 *
	 * 0xEFBFBF is 1110 1111 1011 1111 1011 1111 which is the maximum
	 * unicode character encoded in 3-bytes in UTF-8.
	 */

	invalid("invalid 3-bytes sequence: \xE0\x80\x88");
	invalid("invalid 3-bytes sequence: \xE0\x84\x80");
	valid("valid 3-bytes sequence: \xE0\xA0\x80 (min value)");
	valid("valid 3-bytes sequence: \xEF\xBF\xBF (max value)");
	invalid("invalid 3-bytes sequence \xE0\xC1\xC1 (extra bytes does not "
		"start with 10__)");
}

ISC_RUN_TEST_IMPL(test_utf8_utf16_surrogate) {
	/*
	 * Right before the surrogate range.
	 */
	valid("a 3-bytes encoded UTF-8 character \xED\x90\x80 right before the "
	      "surrogate range");

	/*
	 * 0xED 0xA0 0x80 sequence is UTF-8 encoding of 0xD800.
	 */
	invalid("a utf16 \xED\xA0\x80 test");

	/*
	 * Within the surrogate range.
	 */
	invalid("a utf16 \xED\xA0\x88 test");

	/*
	 * 0xED 0xBF 0xBF sequence is UTF-8 encoding of 0xDFFF.
	 */
	invalid("a utf16 \xED\xBF\xBF test");

	/*
	 * Right after the surrogate range.
	 */
	valid("a 3-bytes encoded UTF-8 character \xEE\x80\x80 right after the "
	      "surrogate range");
}

ISC_RUN_TEST_IMPL(test_utf8_fourbytes) {
	/*
	 * 0x010000 (first valid unicode character holding in 4 bytes with
	 * UTF-8) is 0000 00|01 0000 |0000 00|00 0000 which encodes in
	 *
	 * 1111 0___ 10__ ____ 10__ ____ 10__ ____
	 * 1111 0000 1001 0000 1000 0000 1000 0000
	 *
	 * So, 0xF0908080.
	 *
	 * 0x10FFFF (last valid unicode character holding in 4 bytes with UTF-8
	 * is 0001 0000 1111 |1111 11|11 1111 which encodes in

	 * 1111 0___ 10__ ____ 10__ ____ 10__ ____
	 * 1111 0100 1000 1111 1011 1111 1011 1111
	 *
	 * So, 0xF48FBFBF.
	 */

	invalid("invalid 4-bytes sequence: \xF0\x80\x80\x80 (below min)");
	valid("valid 4-bytes sequence: \xF0\x90\x80\x80 (min value)");
	valid("valid 4-bytes sequence: \xF4\x8F\xBF\xBF (max value)");
	invalid("invalid 4-bytes sequence: \xF4\x9F\xBF\xBF(above max)");
	invalid("invalid 4-bytes sequence: \xF0\xC1\xC1\xC1 (extra bytes does "
		"not start with 10__)");
}

ISC_RUN_TEST_IMPL(test_utf8_bom) {
	validbom("\xEF\xBB\xBF");
	validbom("\xEF\xBB\xBF ab");
	validbom("\xEF\xBB\xBF\xF4\x8F\xBF\xBF");
	invalidbom("\xEF\xBB");
	invalidbom("\xEF\xBB\xBE");
	invalidbom("\xEF\xBB\xBE ab");
	invalidbom("\xEF\xBB\xBE\xF4\x8F\xBF\xBF");
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(test_utf8_ascii)
ISC_TEST_ENTRY(test_utf8_twobytes)
ISC_TEST_ENTRY(test_utf8_threebytes)
ISC_TEST_ENTRY(test_utf8_utf16_surrogate)
ISC_TEST_ENTRY(test_utf8_fourbytes)
ISC_TEST_ENTRY(test_utf8_bom)
ISC_TEST_LIST_END

ISC_TEST_MAIN
