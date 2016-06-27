/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: driver.h,v 1.8 2007/06/19 23:47:00 tbox Exp $ */

/*
 * PASSED and FAILED mean the particular test passed or failed.
 *
 * UNKNOWN means that for one reason or another, the test process itself
 * failed.  For instance, missing files, error when parsing files or
 * IP addresses, etc.  That is, the test itself is broken, not what is
 * being tested.
 *
 * UNTESTED means the test was unable to be run because a prerequisite test
 * failed, the test is disabled, or the test needs a system component
 * (for instance, Perl) and cannot run.
 */
typedef enum {
	PASSED = 0,
	FAILED = 1,
	UNKNOWN = 2,
	UNTESTED = 3
} test_result_t;

typedef test_result_t (*test_func_t)(void);

typedef struct {
	const char *tag;
	const char *description;
	test_func_t func;
} test_t;

#define TESTDECL(name)	test_result_t name(void)

