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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "isctest.h"

#include <isc/buffer.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

ATF_TC(isc_buffer_reserve);
ATF_TC_HEAD(isc_buffer_reserve, tc) {
	atf_tc_set_md_var(tc, "descr", "reserve space in dynamic buffers");
}

ATF_TC_BODY(isc_buffer_reserve, tc) {
	isc_result_t result;
	isc_buffer_t *b;

	result = isc_test_begin(NULL, true, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	b = NULL;
	result = isc_buffer_allocate(mctx, &b, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK_EQ(b->length, 1024);

	/*
	 * 1024 bytes should already be available, so this call does
	 * nothing.
	 */
	result = isc_buffer_reserve(&b, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 1024);

	/*
	 * This call should grow it to 2048 bytes as only 1024 bytes are
	 * available in the buffer.
	 */
	result = isc_buffer_reserve(&b, 1025);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 2048);

	/*
	 * 2048 bytes should already be available, so this call does
	 * nothing.
	 */
	result = isc_buffer_reserve(&b, 2000);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 2048);

	/*
	 * This call should grow it to 4096 bytes as only 2048 bytes are
	 * available in the buffer.
	 */
	result = isc_buffer_reserve(&b, 3000);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 4096);

	/* Consume some of the buffer so we can run the next test. */
	isc_buffer_add(b, 4096);

	/*
	 * This call should fail and leave buffer untouched.
	 */
	result = isc_buffer_reserve(&b, UINT_MAX);
	ATF_CHECK_EQ(result, ISC_R_NOMEMORY);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 4096);

	isc_buffer_free(&b);

	isc_test_end();
}

ATF_TC(isc_buffer_reallocate);
ATF_TC_HEAD(isc_buffer_reallocate, tc) {
	atf_tc_set_md_var(tc, "descr", "reallocate dynamic buffers");
}

ATF_TC_BODY(isc_buffer_reallocate, tc) {
	isc_result_t result;
	isc_buffer_t *b;

	result = isc_test_begin(NULL, true, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	b = NULL;
	result = isc_buffer_allocate(mctx, &b, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 1024);

	result = isc_buffer_reallocate(&b, 512);
	ATF_CHECK_EQ(result, ISC_R_NOSPACE);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 1024);

	result = isc_buffer_reallocate(&b, 1536);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, 1536);

	isc_buffer_free(&b);

	isc_test_end();
}

ATF_TC(isc_buffer_dynamic);
ATF_TC_HEAD(isc_buffer_dynamic, tc) {
	atf_tc_set_md_var(tc, "descr", "dynamic buffer automatic reallocation");
}

ATF_TC_BODY(isc_buffer_dynamic, tc) {
	isc_result_t result;
	isc_buffer_t *b;
	size_t last_length = 10;
	int i;

	result = isc_test_begin(NULL, true, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	b = NULL;
	result = isc_buffer_allocate(mctx, &b, last_length);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(b != NULL);
	ATF_CHECK_EQ(b->length, last_length);

	isc_buffer_setautorealloc(b, true);

	isc_buffer_putuint8(b, 1);

	for (i = 0; i < 1000; i++) {
		isc_buffer_putstr(b, "thisisa24charslongstring");
	}
	ATF_CHECK(b->length-last_length >= 1000*24);
	last_length+=1000*24;

	for (i = 0; i < 10000; i++) {
		isc_buffer_putuint8(b, 1);
	}

	ATF_CHECK(b->length-last_length >= 10000*1);
	last_length += 10000*1;

	for (i = 0; i < 10000; i++) {
		isc_buffer_putuint16(b, 1);
	}

	ATF_CHECK(b->length-last_length >= 10000*2);

	last_length += 10000*2;
	for (i = 0; i < 10000; i++) {
		isc_buffer_putuint24(b, 1);
	}
	ATF_CHECK(b->length-last_length >= 10000*3);

	last_length+=10000*3;

	for (i = 0; i < 10000; i++) {
		isc_buffer_putuint32(b, 1);
	}
	ATF_CHECK(b->length-last_length >= 10000*4);


	isc_buffer_free(&b);

	isc_test_end();
}

ATF_TC(isc_buffer_copyregion);
ATF_TC_HEAD(isc_buffer_copyregion, tc) {
	atf_tc_set_md_var(tc, "descr", "copy a region into a buffer");
}

ATF_TC_BODY(isc_buffer_copyregion, tc) {
	unsigned char data[] = { 0x11, 0x22, 0x33, 0x44 };
	isc_buffer_t *b = NULL;
	isc_result_t result;

	isc_region_t r = {
		.base = data,
		.length = sizeof(data),
	};

	result = isc_test_begin(NULL, true, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = isc_buffer_allocate(mctx, &b, sizeof(data));
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/*
	 * Fill originally allocated buffer space.
	 */
	result = isc_buffer_copyregion(b, &r);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	/*
	 * Appending more data to the buffer should fail.
	 */
	result = isc_buffer_copyregion(b, &r);
	ATF_CHECK_EQ(result, ISC_R_NOSPACE);

	/*
	 * Enable auto reallocation and retry.  Appending should now succeed.
	 */
	isc_buffer_setautorealloc(b, true);
	result = isc_buffer_copyregion(b, &r);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	isc_buffer_free(&b);

	isc_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_buffer_reserve);
	ATF_TP_ADD_TC(tp, isc_buffer_reallocate);
	ATF_TP_ADD_TC(tp, isc_buffer_dynamic);
	ATF_TP_ADD_TC(tp, isc_buffer_copyregion);
	return (atf_no_error());
}
