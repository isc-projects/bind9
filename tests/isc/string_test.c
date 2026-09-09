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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/string.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(hasprefix) {
	/* matches: exact string and proper prefixes */
	assert_true(isc_string_hasprefix("maxudp=512", "maxudp="));
	assert_true(isc_string_hasprefix("maxudp=", "maxudp="));
	assert_true(isc_string_hasprefix("anything", ""));
	assert_true(isc_string_hasprefix("", ""));

	/* case matters */
	assert_false(isc_string_hasprefix("MAXUDP=512", "maxudp="));

	/* non-matches, including 'str' shorter than 'prefix' */
	assert_false(isc_string_hasprefix("maxcachesize=1", "maxudp"));
	assert_false(isc_string_hasprefix("max", "maxudp="));
	assert_false(isc_string_hasprefix("", "maxudp="));
}

ISC_RUN_TEST_IMPL(casehasprefix) {
	/* matches regardless of case */
	assert_true(isc_string_casehasprefix("ixfr=1234", "ixfr="));
	assert_true(isc_string_casehasprefix("IXFR=1234", "ixfr="));
	assert_true(isc_string_casehasprefix("IxFr=1234", "iXfR="));
	assert_true(isc_string_casehasprefix("anything", ""));

	/* non-matches, including 'str' shorter than 'prefix' */
	assert_false(isc_string_casehasprefix("axfr=1", "ixfr="));
	assert_false(isc_string_casehasprefix("ixfr", "ixfr="));
	assert_false(isc_string_casehasprefix("", "ixfr="));
}

ISC_RUN_TEST_IMPL(stripprefix) {
	const char *str = "maxudp=512";

	/* matches return the remainder after the prefix */
	assert_ptr_equal(isc_string_stripprefix(str, "maxudp="), str + 7);
	assert_string_equal(isc_string_stripprefix(str, "maxudp="), "512");
	assert_string_equal(isc_string_stripprefix(str, ""), str);
	assert_string_equal(isc_string_stripprefix("maxudp=", "maxudp="), "");

	/* case matters */
	assert_null(isc_string_stripprefix("MAXUDP=512", "maxudp="));

	/* non-matches, including 'str' shorter than 'prefix' */
	assert_null(isc_string_stripprefix("maxcachesize=1", "maxudp="));
	assert_null(isc_string_stripprefix("max", "maxudp="));
	assert_null(isc_string_stripprefix("", "maxudp="));
}

ISC_RUN_TEST_IMPL(casestripprefix) {
	const char *str = "IXFR=1234";

	/* matches regardless of case return the remainder */
	assert_ptr_equal(isc_string_casestripprefix(str, "ixfr="), str + 5);
	assert_string_equal(isc_string_casestripprefix(str, "ixfr="), "1234");
	assert_string_equal(isc_string_casestripprefix("IxFr=1", "iXfR="), "1");
	assert_string_equal(isc_string_casestripprefix(str, ""), str);

	/* non-matches, including 'str' shorter than 'prefix' */
	assert_null(isc_string_casestripprefix("axfr=1", "ixfr="));
	assert_null(isc_string_casestripprefix("ixfr", "ixfr="));
	assert_null(isc_string_casestripprefix("", "ixfr="));
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(hasprefix)
ISC_TEST_ENTRY(casehasprefix)
ISC_TEST_ENTRY(stripprefix)
ISC_TEST_ENTRY(casestripprefix)
ISC_TEST_LIST_END

ISC_TEST_MAIN
