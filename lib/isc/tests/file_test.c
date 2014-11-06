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

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <isc/file.h>
#include <isc/result.h>

ATF_TC(isc_file_sanitize);
ATF_TC_HEAD(isc_file_sanitize, tc) {
	atf_tc_set_md_var(tc, "descr", "sanitized filenames");
}

#define NAME "internal"
#define SHA "3bed2cb3a3acf7b6a8ef408420cc682d5520e26976d354254f528c965612054f"
#define TRUNC_SHA "3bed2cb3a3acf7b6"

#define BAD1 "in/internal"
#define BADHASH1 "8bbb97a888791399"

#define BAD2 "Internal"
#define BADHASH2 "2ea1842b445b0c81"

#define F(x) "testdata/file/" x ".test"

ATF_TC_BODY(isc_file_sanitize, tc) {
	isc_result_t result;
	char buf[1024];

	ATF_CHECK(chdir(TESTS) != -1);

	unlink(F(TRUNC_SHA));
	unlink(F(SHA));

	result = isc_file_sanitize("testdata/file", NAME, "test", buf, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(strcmp(buf, F(NAME)) == 0);

	creat(F(TRUNC_SHA), 0644);
	result = isc_file_sanitize("testdata/file", NAME, "test", buf, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(strcmp(buf, F(TRUNC_SHA)) == 0);

	creat(F(SHA), 0644);
	result = isc_file_sanitize("testdata/file", NAME, "test", buf, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(strcmp(buf, F(SHA)) == 0);

	result = isc_file_sanitize("testdata/file", BAD1, "test", buf, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(strcmp(buf, F(BADHASH1)) == 0);

	result = isc_file_sanitize("testdata/file", BAD2, "test", buf, 1024);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(strcmp(buf, F(BADHASH2)) == 0);

	unlink(F(TRUNC_SHA));
	unlink(F(SHA));
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_file_sanitize);
	return (atf_no_error());
}

