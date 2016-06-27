/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: driver.c,v 1.11 2007/06/19 23:47:00 tbox Exp $ */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include "driver.h"

#include "testsuite.h"

#define NTESTS (sizeof(tests) / sizeof(test_t))

const char *gettime(void);
const char *test_result_totext(test_result_t);

/*
 * Not thread safe.
 */
const char *
gettime(void) {
	static char now[512];
	time_t t;

	(void)time(&t);

	strftime(now, sizeof(now) - 1,
		 "%A %d %B %H:%M:%S %Y",
		 localtime(&t));

	return (now);
}

const char *
test_result_totext(test_result_t result) {
	const char *s;
	switch (result) {
	case PASSED:
		s = "PASS";
		break;
	case FAILED:
		s = "FAIL";
		break;
	case UNTESTED:
		s = "UNTESTED";
		break;
	case UNKNOWN:
	default:
		s = "UNKNOWN";
		break;
	}

	return (s);
}

int
main(int argc, char **argv) {
	test_t *test;
	test_result_t result;
	unsigned int n_failed;
	unsigned int testno;

	UNUSED(argc);
	UNUSED(argv);

	printf("S:%s:%s\n", SUITENAME, gettime());

	n_failed = 0;
	for (testno = 0; testno < NTESTS; testno++) {
		test = &tests[testno];
		printf("T:%s:%u:A\n", test->tag, testno + 1);
		printf("A:%s\n", test->description);
		result = test->func();
		printf("R:%s\n", test_result_totext(result));
		if (result != PASSED)
			n_failed++;
	}

	printf("E:%s:%s\n", SUITENAME, gettime());

	if (n_failed > 0)
		exit(1);

	return (0);
}

