/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/platform.h>
#include <isc/util.h>

#include <dst/dst.h>

isc_mem_t *mctx = NULL;
isc_entropy_t *ectx = NULL;
unsigned char buffer[128];

/* isc_entropy_getdata() examples */
static void
isc_entropy_getdata_test(void **state) {
	isc_result_t result;
	unsigned int returned, status;
	const char *randomfile = "testdata/dstrandom/random.data";
	int ret;

	UNUSED(state);

	isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_entropy_create(mctx, &ectx);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_lib_init(mctx, ectx, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

#ifdef ISC_PLATFORM_CRYPTORANDOM
	isc_entropy_usehook(ectx, true);

	returned = 0;
	result = isc_entropy_getdata(ectx, buffer, sizeof(buffer),
				     &returned, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(returned, sizeof(buffer));

	status = isc_entropy_status(ectx);
	assert_int_equal(status, 0);

	isc_entropy_usehook(ectx, false);
#endif

	ret = chdir(TESTS);
	assert_int_equal(ret, 0);

	result = isc_entropy_createfilesource(ectx, randomfile);
	assert_int_equal(result, ISC_R_SUCCESS);

	returned = 0;
	result = isc_entropy_getdata(ectx, buffer, sizeof(buffer),
				     &returned, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(returned, sizeof(buffer));

	status = isc_entropy_status(ectx);
	assert_true(status > 0);

	dst_lib_destroy();
	isc_entropy_detach(&ectx);
	assert_null(ectx);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(isc_entropy_getdata_test),
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
