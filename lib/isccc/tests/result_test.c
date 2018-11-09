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

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <isc/result.h>
#include <isc/util.h>

#include <isccc/lib.h>
#include <isccc/result.h>

ATF_TC(tables);
ATF_TC_HEAD(tables, tc) {
	atf_tc_set_md_var(tc, "descr", "check tables are populated");
}
ATF_TC_BODY(tables, tc) {
	const char *str;
	isc_result_t result;

	UNUSED(tc);

	isccc_result_register();

	for (result = ISC_RESULTCLASS_ISCCC;
	     result < (ISC_RESULTCLASS_ISCCC + ISCCC_R_NRESULTS);
	     result++) {
		str = isc_result_toid(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_toid(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
				     "(result code text not available)") != 0,
			      "isc_result_toid(%u) returned %s", result, str);

		str = isc_result_totext(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_totext(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
				     "(result code text not available)") != 0,
			      "isc_result_totext(%u) returned %s", result, str);
	}

	str = isc_result_toid(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");

	str = isc_result_totext(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, tables);

	return (atf_no_error());
}
