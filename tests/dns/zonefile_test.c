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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/lib.h>

#include <dns/lib.h>
#include <dns/view.h>

#include <tests/dns.h>

typedef struct {
	const char *input, *expected;
} zonefile_test_params_t;

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

ISC_LOOP_TEST_IMPL(filename) {
	isc_result_t result;
	dns_zone_t *zone = NULL;
	const zonefile_test_params_t tests[] = {
		{ "$name", "example.com" },
		{ "$name.db", "example.com.db" },
		{ "./dir/$name.db", "./dir/example.com.db" },
		{ "$type", "primary" },
		{ "$type-file", "primary-file" },
		{ "./dir/$type", "./dir/primary" },
		{ "./$type/$name.db", "./primary/example.com.db" },
		{ "./$TyPe/$NAmE.db", "./primary/example.com.db" },
		{ "./$name/$type", "./example.com/primary" },
		{ "$name.$type", "example.com.primary" },
		{ "$type$name", "primaryexample.com" },
		{ "$type$type", "primary$type" },
		{ "$name$name", "example.com$name" },
		{ "typename", "typename" },
		{ "$view", "local" },
		{ "./$type/$view-$name.db", "./primary/local-example.com.db" },
		{ "./$view/$type-$name.db", "./local/primary-example.com.db" },
		{ "./$name/$view-$type.db", "./example.com/local-primary.db" },
		{ "", "" },
	};

	dns_view_t *view = NULL;
	result = dns_test_makeview("local", false, false, &view);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* use .COM here to test that the name is correctly downcased */
	result = dns_test_makezone("example.COM", &zone, view, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_zone_setview(zone, view);
	dns_view_detach(&view);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		dns_zone_setfile(zone, tests[i].input, NULL,
				 dns_masterformat_text,
				 &dns_master_style_default);
		assert_string_equal(dns_zone_getfile(zone), tests[i].expected);
	}

	/* test PATH_MAX overrun */
	char longname[PATH_MAX] = { 0 };
	memset(longname, 'x', sizeof(longname) - 1);
	dns_zone_setfile(zone, longname, NULL, dns_masterformat_text,
			 &dns_master_style_default);
	assert_string_equal(dns_zone_getfile(zone), longname);

	/*
	 * overwrite the beginning of the long name with $name. when
	 * it's expanded to the zone name, the resulting string should
	 * still be capped at PATH_MAX characters.
	 */
	memmove(longname, "$name", 5);
	dns_zone_setfile(zone, longname, NULL, dns_masterformat_text,
			 &dns_master_style_default);
	assert_int_equal(strlen(longname), PATH_MAX - 1);
	memmove(longname, "example.com", 11);
	assert_string_equal(dns_zone_getfile(zone), longname);

	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(filename, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
