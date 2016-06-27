/*
 * Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>
#include <stdlib.h>

#include <atf-c.h>

#include <isc/time.h>
#include <isc/result.h>

ATF_TC(isc_time_parsehttptimestamp);
ATF_TC_HEAD(isc_time_parsehttptimestamp, tc) {
	atf_tc_set_md_var(tc, "descr", "parse http time stamp");
}
ATF_TC_BODY(isc_time_parsehttptimestamp, tc) {
	isc_result_t result;
	isc_time_t t, x;
	char buf[ISC_FORMATHTTPTIMESTAMP_SIZE];

	setenv("TZ", "PST8PDT", 1);
	result = isc_time_now(&t);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_time_formathttptimestamp(&t, buf, sizeof(buf));
	result = isc_time_parsehttptimestamp(buf, &x);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(isc_time_seconds(&t), isc_time_seconds(&x));
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_time_parsehttptimestamp);
	return (atf_no_error());
}

