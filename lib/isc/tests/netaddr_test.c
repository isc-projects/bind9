/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <string.h>

#include <isc/netaddr.h>

ATF_TC(isc_netaddr_isnetzero);
ATF_TC_HEAD(isc_netaddr_isnetzero, tc) {
	atf_tc_set_md_var(tc, "descr", "test isc_netaddr_isnetzero");
}
ATF_TC_BODY(isc_netaddr_isnetzero, tc) {
	unsigned int i;
	struct in_addr ina;
	struct {
		const char *address;
		isc_boolean_t expect;
	} tests[] = {
		{ "0.0.0.0", ISC_TRUE },
		{ "0.0.0.1", ISC_TRUE },
		{ "0.0.1.2", ISC_TRUE },
		{ "0.1.2.3", ISC_TRUE },
		{ "10.0.0.0", ISC_FALSE },
		{ "10.9.0.0", ISC_FALSE },
		{ "10.9.8.0", ISC_FALSE },
		{ "10.9.8.7", ISC_FALSE },
		{ "127.0.0.0", ISC_FALSE },
		{ "127.0.0.1", ISC_FALSE }
	};
	isc_boolean_t result;
	isc_netaddr_t netaddr;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		ina.s_addr = inet_addr(tests[i].address);
		isc_netaddr_fromin(&netaddr, &ina);
		result = isc_netaddr_isnetzero(&netaddr);
		ATF_CHECK_EQ_MSG(result, tests[i].expect,
				 "%s", tests[i].address);
	}
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {

	ATF_TP_ADD_TC(tp, isc_netaddr_isnetzero);

	return (atf_no_error());
}
