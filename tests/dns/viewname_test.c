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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/log.h>

#include <dns/lib.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

#include <tests/dns.h>

static int
setup_test(void **state) {
	setup_loopmgr(state);
	return 0;
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
	return 0;
}

ISC_LOOP_TEST_IMPL(lifetime) {
	const char *names[] = { "_default", "_bind", "internal" };
	const char *display[] = { "example/IN", "example/IN",
				  "example/IN/internal" };
	FILE *log = tmpfile();
	assert_non_null(log);
	isc_log_createandusechannel(
		isc_logconfig_get(), "viewname", ISC_LOG_TOFILEDESC,
		ISC_LOG_INFO, ISC_LOGDESTINATION_FILE(log), 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		dns_zone_t *zone = NULL, *held = NULL;
		dns_view_t *view = NULL, *replacement = NULL;
		char buf[256], expected[256];
		isc_buffer_t b;

		assert_int_equal(
			dns_test_makezone("example", &zone, NULL, false),
			ISC_R_SUCCESS);
		assert_int_equal(
			dns_test_makeview(names[i], false, false, &view),
			ISC_R_SUCCESS);
		dns_zone_setview(zone, view);
		assert_string_equal(dns__viewname_get(&zone->viewname),
				    names[i]);
		dns_zone_name(zone, buf, sizeof(buf));
		assert_string_equal(buf, display[i]);

		/* Reconfiguration with the same name preserves the allocation.
		 */
		const char *saved = dns__viewname_get(&zone->viewname);
		assert_int_equal(
			dns_test_makeview(names[i], false, false, &replacement),
			ISC_R_SUCCESS);
		dns_zone_setview(zone, replacement);
		assert_ptr_equal(saved, dns__viewname_get(&zone->viewname));
		dns_zone_setviewrevert(zone);
		assert_ptr_equal(saved, dns__viewname_get(&zone->viewname));
		dns_view_detach(&replacement);

		/* A changed name and rollback both update the cached value. */
		assert_int_equal(
			dns_test_makeview("other", false, false, &replacement),
			ISC_R_SUCCESS);
		dns_zone_setview(zone, replacement);
		dns_zone_name(zone, buf, sizeof(buf));
		assert_string_equal(buf, "example/IN/other");
		dns_zone_setviewrevert(zone);
		dns_zone_name(zone, buf, sizeof(buf));
		assert_string_equal(buf, display[i]);
		dns_view_detach(&replacement);

		/* Full names, including built-ins, still expand in filenames.
		 */
		isc_buffer_init(&b, buf, sizeof(buf));
		dns_zone_expandzonefile(
			&b, "$view/$name.db", dns_zone_getorigin(zone),
			dns__viewname_get(&zone->viewname), "primary");
		snprintf(expected, sizeof(expected), "%s/example.db", names[i]);
		assert_string_equal(buf, expected);

		/* An internal reference keeps the zone, but not its view,
		 * alive. */
		dns_zone_iattach(zone, &held);
		dns_zone_detach(&zone);
		assert_null(dns_zone_getview(held));
		dns_view_detach(&view);
		dns_zone_name(held, buf, sizeof(buf));
		assert_string_equal(buf, display[i]);
		dns_zone_log(held, ISC_LOG_INFO, "after shutdown");
		dns_zone_idetach(&held);
	}

	char output[4096];
	assert_int_equal(fflush(log), 0);
	assert_int_equal(fseek(log, 0, SEEK_SET), 0);
	size_t length = fread(output, 1, sizeof(output) - 1, log);
	assert_false(ferror(log));
	output[length] = '\0';
	assert_non_null(strstr(output, "zone example/IN: after shutdown"));
	assert_non_null(
		strstr(output, "zone example/IN/internal: after shutdown"));
	assert_null(strstr(output, "_default"));
	assert_null(strstr(output, "_bind"));
	isc_log_createandusechannel(
		isc_logconfig_get(), "viewname", ISC_LOG_TONULL, ISC_LOG_INFO,
		NULL, 0, ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);
	fclose(log);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(lifetime, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
