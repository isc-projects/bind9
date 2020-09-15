/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <config.h>

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <sched.h> /* IWYU pragma: keep */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/print.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>

/* parse http time stamp */
static void
isc_time_parsehttptimestamp_test(void **state) {
	isc_result_t result;
	isc_time_t t, x;
	char buf[ISC_FORMATHTTPTIMESTAMP_SIZE];

	UNUSED(state);

	setenv("TZ", "America/Los_Angeles", 1);
	result = isc_time_now(&t);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_time_formathttptimestamp(&t, buf, sizeof(buf));
	result = isc_time_parsehttptimestamp(buf, &x);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(isc_time_seconds(&t), isc_time_seconds(&x));
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(isc_time_parsehttptimestamp_test),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
