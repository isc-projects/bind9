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
#include <isc/work.h>

#include <dns/db.h>
#include <dns/lib.h>
#include <dns/result.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zoneproperties.h>

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

typedef struct {
	dns_view_t *view;
	dns_db_t *db;
	FILE *log;
} verify_test_t;

static isc_result_t
verify_worker(void *arg) {
	verify_test_t *test = arg;
	dns_dbversion_t *version = NULL;
	isc_result_t result;

	/* Exercise both current-version and supplied-version ownership. */
	result = dns_zone_verifydb(test->view, test->db, NULL);
	if (result != DNS_R_VERIFYFAILURE) {
		return ISC_R_FAILURE;
	}
	RETERR(dns_db_newversion(test->db, &version));
	result = dns_zone_verifydb(test->view, test->db, version);
	dns_db_closeversion(test->db, &version, false);
	return result;
}

static void
verify_done(void *arg, isc_result_t result) {
	verify_test_t *test = arg;
	char output[4096];
	size_t length;

	assert_int_equal(result, DNS_R_VERIFYFAILURE);
	assert_int_equal(fflush(test->log), 0);
	assert_int_equal(fseek(test->log, 0, SEEK_SET), 0);
	length = fread(output, 1, sizeof(output) - 1, test->log);
	assert_false(ferror(test->log));
	output[length] = '\0';
	assert_non_null(strstr(output, "zone example/IN/worker-view: Zone "
				       "contains no DNSSEC keys"));
	assert_non_null(strstr(output, "zone example/IN/worker-view: zone "
				       "verification failed:"));

	/* Stop using the temporary stream before closing it. */
	isc_log_createandusechannel(isc_logconfig_get(), "verification",
				    ISC_LOG_TONULL, ISC_LOG_INFO, NULL, 0,
				    ISC_LOGCATEGORY_DEFAULT,
				    ISC_LOGMODULE_DEFAULT);
	fclose(test->log);
	dns_view_weakdetach(&test->view);
	dns_db_detach(&test->db);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(after_shutdown) {
	static verify_test_t test;
	dns_zone_t *zone = NULL;
	dns_view_t *view = NULL;
	UNUSED(arg);

	assert_int_equal(dns_test_makezone("example", &zone, NULL, false),
			 ISC_R_SUCCESS);
	assert_int_equal(dns_test_makeview("worker-view", false, false, &view),
			 ISC_R_SUCCESS);
	dns_zone_setview(zone, view);
	dns_view_initsecroots(view);
	/* Keep the same weak view reference that a transfer owns. */
	dns_view_weakattach(view, &test.view);
	assert_int_equal(dns_db_create(isc_g_mctx, ZONEDB_DEFAULT,
				       dns_zone_getorigin(zone),
				       dns_dbtype_zone, dns_rdataclass_in, 0,
				       NULL, &test.db),
			 ISC_R_SUCCESS);

	/* The unmanaged zone shuts down synchronously on its final detach. */
	dns_zone_detach(&zone);
	dns_view_detach(&view);

	test.log = tmpfile();
	assert_non_null(test.log);
	isc_log_createandusechannel(
		isc_logconfig_get(), "verification", ISC_LOG_TOFILEDESC,
		ISC_LOG_INFO, ISC_LOGDESTINATION_FILE(test.log), 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	isc_work_enqueue(isc_loop(), ISC_WORKLANE_SLOW, verify_worker,
			 verify_done, &test);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(after_shutdown, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
