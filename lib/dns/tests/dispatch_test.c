/*
 * Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <unistd.h>

#include <isc/buffer.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <dns/dispatch.h>
#include <dns/name.h>
#include <dns/view.h>

#include "dnstest.h"

dns_dispatchmgr_t *dispatchmgr = NULL;
dns_dispatchset_t *dset = NULL;

static isc_result_t
make_dispatchset(unsigned int ndisps) {
	isc_result_t result;
	isc_sockaddr_t any;
	unsigned int attrs;
	dns_dispatch_t *disp = NULL;

	result = dns_dispatchmgr_create(mctx, NULL, &dispatchmgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_sockaddr_any(&any);
	attrs = DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_UDP;
	result = dns_dispatch_getudp(dispatchmgr, socketmgr, taskmgr,
				     &any, 512, 6, 1024, 17, 19, attrs,
				     attrs, &disp);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_dispatchset_create(mctx, socketmgr, taskmgr, disp,
					&dset, ndisps);
	dns_dispatch_detach(&disp);

	return (result);
}

static void
teardown(void) {
	if (dset != NULL)
		dns_dispatchset_destroy(&dset);
	if (dispatchmgr != NULL)
		dns_dispatchmgr_destroy(&dispatchmgr);
}

/*
 * Individual unit tests
 */
ATF_TC(dispatchset_create);
ATF_TC_HEAD(dispatchset_create, tc) {
	atf_tc_set_md_var(tc, "descr", "create dispatch set");
}
ATF_TC_BODY(dispatchset_create, tc) {
	isc_result_t result;

	UNUSED(tc);

	result = dns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = make_dispatchset(1);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	teardown();

	result = make_dispatchset(10);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	teardown();

	dns_test_end();
}



ATF_TC(dispatchset_get);
ATF_TC_HEAD(dispatchset_get, tc) {
	atf_tc_set_md_var(tc, "descr", "test dispatch set round-robin");
}
ATF_TC_BODY(dispatchset_get, tc) {
	isc_result_t result;
	dns_dispatch_t *d1, *d2, *d3, *d4, *d5;

	UNUSED(tc);

	result = dns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = make_dispatchset(1);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	ATF_CHECK_EQ(d1, d2);
	ATF_CHECK_EQ(d2, d3);
	ATF_CHECK_EQ(d3, d4);
	ATF_CHECK_EQ(d4, d5);

	teardown();

	result = make_dispatchset(4);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	ATF_CHECK_EQ(d1, d5);
	ATF_CHECK(d1 != d2);
	ATF_CHECK(d2 != d3);
	ATF_CHECK(d3 != d4);
	ATF_CHECK(d4 != d5);

	teardown();
	dns_test_end();
}


/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, dispatchset_create);
	ATF_TP_ADD_TC(tp, dispatchset_get);
	return (atf_no_error());
}

