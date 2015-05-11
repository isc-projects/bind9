/*
 * Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
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

#include <atf-c.h>

#include <string.h>

#include <isc/result.h>

ATF_TC(isc_result_toid);
ATF_TC_HEAD(isc_result_toid, tc) {
	atf_tc_set_md_var(tc, "descr", "convert result to identifier string");
}
ATF_TC_BODY(isc_result_toid, tc) {
	const char *id;

	id = isc_result_toid(ISC_R_SUCCESS);
	ATF_REQUIRE_STREQ("ISC_R_SUCCESS", id);

	id = isc_result_toid(ISC_R_FAILURE);
	ATF_REQUIRE_STREQ("ISC_R_FAILURE", id);
}

ATF_TC(isc_result_totext);
ATF_TC_HEAD(isc_result_totext, tc) {
	atf_tc_set_md_var(tc, "descr", "convert result to description string");
}
ATF_TC_BODY(isc_result_totext, tc) {
	const char *str;

	str = isc_result_totext(ISC_R_SUCCESS);
	ATF_REQUIRE_STREQ("success", str);

	str = isc_result_totext(ISC_R_FAILURE);
	ATF_REQUIRE_STREQ("failure", str);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_result_toid);
	ATF_TP_ADD_TC(tp, isc_result_totext);

	return (atf_no_error());
}
