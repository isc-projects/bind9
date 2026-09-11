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
#include <dns/zonemgr.h>
#include <dns/zoneproperties.h>

#include <tests/dns.h>

static dns_zonemgr_t *mgr = NULL;

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
	assert_ptr_equal(dns_g_zonemgr, mgr);
	dns_zonemgr_destroy(&mgr);
	assert_null(mgr);
	assert_null(dns_g_zonemgr);

	return 0;
}

/* create zone manager */
ISC_LOOP_TEST_IMPL(zonemgr_create) {
	UNUSED(arg);

	dns_zonemgr_create(isc_g_mctx, &mgr);

	dns_zonemgr_shutdown(mgr);
	assert_ptr_equal(dns_g_zonemgr, mgr);

	isc_loopmgr_shutdown();
}

/* create and release a zone */
ISC_LOOP_TEST_IMPL(zonemgr_createzone) {
	dns_zone_t *zone = NULL;
	isc_result_t result;

	UNUSED(arg);

	dns_zonemgr_create(isc_g_mctx, &mgr);

	result = dns_zonemgr_createzone(mgr, &zone);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(zone);

	assert_non_null(dns_zone_getloop(zone));

	dns_zone_detach(&zone);

	dns_zonemgr_shutdown(mgr);
	assert_ptr_equal(dns_g_zonemgr, mgr);

	isc_loopmgr_shutdown();
}

/* Both raw-zone construction paths must finish cleanup before destruction. */
ISC_LOOP_TEST_IMPL(zonemgr_inline) {
	dns_zone_t *zone = NULL, *raw = NULL;
	UNUSED(arg);
	dns_zonemgr_create(isc_g_mctx, &mgr);

	assert_int_equal(dns_zonemgr_createzone(mgr, &zone), ISC_R_SUCCESS);
	dns_zone_create(&raw, isc_g_mctx, 0);
	assert_int_equal(dns_zone_link(zone, raw), ISC_R_SUCCESS);
	assert_ptr_equal(dns_zone_getloop(zone), dns_zone_getloop(raw));
	dns_zone_detach(&raw);
	dns_zone_detach(&zone);

	assert_int_equal(dns_zonemgr_createzone(mgr, &zone), ISC_R_SUCCESS);
	assert_int_equal(dns_zonemgr_createzone(mgr, &raw), ISC_R_SUCCESS);
	assert_int_equal(dns_zone_link(zone, raw), ISC_R_SUCCESS);
	assert_ptr_equal(dns_zone_getloop(zone), dns_zone_getloop(raw));

	dns_zonemgr_shutdown(mgr);
	/* Shutdown leaves shared services allocated while zones finish cleanup.
	 */
	assert_non_null(dns_g_zonemgr);
	dns_zone_detach(&raw);
	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(zonemgr_create, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(zonemgr_createzone, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(zonemgr_inline, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
