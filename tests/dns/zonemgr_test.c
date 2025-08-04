/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/name.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <tests/dns.h>

static int
setup_test(void **state) {
	setup_loopmgr(state);
	setup_netmgr(state);

	return 0;
}

static int
teardown_test(void **state) {
	teardown_netmgr(state);
	teardown_loopmgr(state);

	return 0;
}

/* create zone manager */
ISC_LOOP_TEST_IMPL(zonemgr_create) {
	dns_zonemgr_t *myzonemgr = NULL;

	UNUSED(arg);

	dns_zonemgr_create(isc_g_mctx, &myzonemgr);

	dns_zonemgr_shutdown(myzonemgr);
	dns_zonemgr_detach(&myzonemgr);
	assert_null(myzonemgr);

	isc_loopmgr_shutdown();
}

/* manage and release a zone */
ISC_LOOP_TEST_IMPL(zonemgr_managezone) {
	dns_zonemgr_t *myzonemgr = NULL;
	dns_zone_t *zone = NULL;
	isc_result_t result;

	UNUSED(arg);

	dns_zonemgr_create(isc_g_mctx, &myzonemgr);

	result = dns_test_makezone("foo", &zone, NULL, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(dns_zonemgr_getcount(myzonemgr, DNS_ZONESTATE_ANY), 0);

	/* Now it should succeed */
	result = dns_zonemgr_managezone(myzonemgr, zone);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(dns_zonemgr_getcount(myzonemgr, DNS_ZONESTATE_ANY), 1);

	dns_zonemgr_releasezone(myzonemgr, zone);
	dns_zone_detach(&zone);

	assert_int_equal(dns_zonemgr_getcount(myzonemgr, DNS_ZONESTATE_ANY), 0);

	dns_zonemgr_shutdown(myzonemgr);
	dns_zonemgr_detach(&myzonemgr);
	assert_null(myzonemgr);

	isc_loopmgr_shutdown();
}

/* create and release a zone */
ISC_LOOP_TEST_IMPL(zonemgr_createzone) {
	dns_zonemgr_t *myzonemgr = NULL;
	dns_zone_t *zone = NULL;
	isc_result_t result;

	UNUSED(arg);

	dns_zonemgr_create(isc_g_mctx, &myzonemgr);

	result = dns_zonemgr_createzone(myzonemgr, &zone);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(zone);

	result = dns_zonemgr_managezone(myzonemgr, zone);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_zone_detach(&zone);

	dns_zonemgr_shutdown(myzonemgr);
	dns_zonemgr_detach(&myzonemgr);
	assert_null(myzonemgr);

	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(zonemgr_create, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(zonemgr_managezone, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(zonemgr_createzone, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
