/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <atf-c.h>

#include "isctest.h"

#include <isc/buffer.h>
#include <isc/result.h>

ATF_TC(isc_buffer_reserve);
ATF_TC_HEAD(isc_buffer_reserve, tc) {
	atf_tc_set_md_var(tc, "descr", "reserve space in dynamic buffers");
}

ATF_TC_BODY(isc_buffer_reserve, tc) {
	isc_result_t result;
	isc_buffer_t *b;

	result = isc_test_begin(NULL, ISC_TRUE);
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
	ATF_CHECK_EQ(b->length, 1024);

	/*
	 * This call should grow it to 2048 bytes as only 1024 bytes are
	 * available in the buffer.
	 */
	result = isc_buffer_reserve(&b, 1025);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_CHECK_EQ(b->length, 2048);

	/*
	 * 2048 bytes should already be available, so this call does
	 * nothing.
	 */
	result = isc_buffer_reserve(&b, 2000);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_CHECK_EQ(b->length, 2048);

	/*
	 * This call should grow it to 4096 bytes as only 2048 bytes are
	 * available in the buffer.
	 */
	result = isc_buffer_reserve(&b, 3000);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_CHECK_EQ(b->length, 4096);

	/* Consume some of the buffer so we can run the next test. */
	isc_buffer_add(b, 4096);

	/*
	 * This call should fail and leave buffer untouched.
	 */
	result = isc_buffer_reserve(&b, UINT_MAX);
	ATF_CHECK_EQ(result, ISC_R_NOMEMORY);

	ATF_CHECK(ISC_BUFFER_VALID(b));
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

	result = isc_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	b = NULL;
	result = isc_buffer_allocate(mctx, &b, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK_EQ(b->length, 1024);

	result = isc_buffer_reallocate(&b, 512);
	ATF_CHECK_EQ(result, ISC_R_NOSPACE);

	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_CHECK_EQ(b->length, 1024);

	result = isc_buffer_reallocate(&b, 1536);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK(ISC_BUFFER_VALID(b));
	ATF_CHECK_EQ(b->length, 1536);

	isc_buffer_free(&b);

	isc_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_buffer_reserve);
	ATF_TP_ADD_TC(tp, isc_buffer_reallocate);
	return (atf_no_error());
}
