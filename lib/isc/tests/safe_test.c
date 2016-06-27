/*
 * Copyright (C) 2013, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <string.h>

#include <isc/safe.h>
#include <isc/util.h>

ATF_TC(isc_safe_memequal);
ATF_TC_HEAD(isc_safe_memequal, tc) {
	atf_tc_set_md_var(tc, "descr", "safe memequal()");
}
ATF_TC_BODY(isc_safe_memequal, tc) {
	UNUSED(tc);

	ATF_CHECK(isc_safe_memequal("test", "test", 4));
	ATF_CHECK(!isc_safe_memequal("test", "tesc", 4));
	ATF_CHECK(isc_safe_memequal("\x00\x00\x00\x00",
				    "\x00\x00\x00\x00", 4));
	ATF_CHECK(!isc_safe_memequal("\x00\x00\x00\x00",
				     "\x00\x00\x00\x01", 4));
	ATF_CHECK(!isc_safe_memequal("\x00\x00\x00\x02",
				     "\x00\x00\x00\x00", 4));
}

ATF_TC(isc_safe_memcompare);
ATF_TC_HEAD(isc_safe_memcompare, tc) {
	atf_tc_set_md_var(tc, "descr", "safe memcompare()");
}
ATF_TC_BODY(isc_safe_memcompare, tc) {
	UNUSED(tc);

	ATF_CHECK(isc_safe_memcompare("test", "test", 4) == 0);
	ATF_CHECK(isc_safe_memcompare("test", "tesc", 4) > 0);
	ATF_CHECK(isc_safe_memcompare("test", "tesy", 4) < 0);
	ATF_CHECK(isc_safe_memcompare("\x00\x00\x00\x00",
				      "\x00\x00\x00\x00", 4) == 0);
	ATF_CHECK(isc_safe_memcompare("\x00\x00\x00\x00",
				      "\x00\x00\x00\x01", 4) < 0);
	ATF_CHECK(isc_safe_memcompare("\x00\x00\x00\x02",
				      "\x00\x00\x00\x00", 4) > 0);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_safe_memequal);
	ATF_TP_ADD_TC(tp, isc_safe_memcompare);
	return (atf_no_error());
}
