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
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/print.h>
#include <isc/util.h>

/*
 * Force the prototype for isc_net_ntop to be declared.
 */
#include <isc/platform.h>
#undef ISC_PLATFORM_NEEDNTOP
#define ISC_PLATFORM_NEEDNTOP
#include "../inet_ntop.c"

/* Test isc_net_ntop implementation */
static void
isc_net_ntop_test(void **state) {
	char buf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	int r;
	size_t i;
	unsigned char abuf[16];
	struct {
		int		family;
		const char *	address;
	} testdata[] = {
		{ AF_INET, "0.0.0.0" },
		{ AF_INET, "0.1.0.0" },
		{ AF_INET, "0.0.2.0" },
		{ AF_INET, "0.0.0.3" },
		{ AF_INET, "255.255.255.255" },
		{ AF_INET6, "::" },
		{ AF_INET6, "::1.2.3.4" },
		{ AF_INET6, "::ffff:1.2.3.4" },
		{ AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
	};

	UNUSED(state);

	for (i = 0; i < sizeof(testdata)/sizeof(testdata[0]); i++) {
		r = inet_pton(testdata[i].family, testdata[i].address, abuf);
		assert_int_equal(r, 1);
		isc_net_ntop(testdata[i].family, abuf, buf, sizeof(buf));
		assert_string_equal(buf, testdata[i].address);
	}
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(isc_net_ntop_test),
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
