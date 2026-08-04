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
#include <isc/dir.h> /* Required on GNU/Hurd */
#include <isc/lib.h>

#include <dns/lib.h>
#include <dns/view.h>
#include <dns/zoneproperties.h>

#include <tests/dns.h>

typedef struct {
	const char *name, *view, *type, *input, *expected;
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
	isc_buffer_t b;
	dns_fixedname_t of;
	dns_name_t *origin = dns_fixedname_initname(&of);
	char buf[PATH_MAX];
	const zonefile_test_params_t tests[] = {
		{ "example.COM", "local", "primary", "$name", "example.com" },
		{ "example.COM", "local", "primary", "$name.db",
		  "example.com.db" },
		{ "example.COM", "local", "primary", "./dir/$name.db",
		  "./dir/example.com.db" },
		{ "example.COM", "local", "primary", "%s", "example.com" },
		{ "example.COM", "local", "primary", "%s.db",
		  "example.com.db" },
		{ "example.COM", "local", "primary", "./dir/%s.db",
		  "./dir/example.com.db" },
		{ "example.COM", "local", "primary", "$type", "primary" },
		{ "example.COM", "local", "primary", "$type-file",
		  "primary-file" },
		{ "example.COM", "local", "primary", "./dir/$type",
		  "./dir/primary" },
		{ "example.COM", "local", "secondary", "./dir/$type",
		  "./dir/secondary" },
		{ "example.COM", "local", "primary", "./$type/$name.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "primary", "%t", "primary" },
		{ "example.COM", "local", "primary", "%t-file",
		  "primary-file" },
		{ "example.COM", "local", "primary", "./dir/%t",
		  "./dir/primary" },
		{ "example.COM", "local", "primary", "./%t/%s.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "secondary", "./%t/%s.db",
		  "./secondary/example.com.db" },
		{ "example.COM", "local", "primary", "./$TyPe/$NAmE.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "primary", "./$name/$type",
		  "./example.com/primary" },
		{ "example.COM", "local", "primary", "$name.$type",
		  "example.com.primary" },
		{ "example.COM", "local", "primary", "$type$name",
		  "primaryexample.com" },
		{ "example.COM", "local", "primary", "$type$type",
		  "primary$type" },
		{ "example.COM", "local", "primary", "$name$name",
		  "example.com$name" },
		{ "example.COM", "local", "primary", "typename", "typename" },
		{ "example.COM", "local", "primary", "$view", "local" },
		{ "example.COM", NULL, "primary", "$view", "" },
		{ "example.COM", "local", "primary", "%v", "local" },
		{ "example.COM", "local", "primary", "./$type/$view-$name.db",
		  "./primary/local-example.com.db" },
		{ "example.COM", "local", "primary", "./$view/$type-$name.db",
		  "./local/primary-example.com.db" },
		{ "example.COM", "local", "primary", "./$name/$view-$type.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "local", "primary", "./%s/%v-%t.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "local", "primary", "", "" },
		{ "example.COM", "local", "primary", "$char1", "e" },
		{ "example.COM", "local", "primary", "$char2", "x" },
		{ "example.COM", "local", "primary", "$char3", "a" },
		{ "example.COM", "local", "primary", "%1", "e" },
		{ "example.COM", "local", "primary", "%2", "x" },
		{ "example.COM", "local", "primary", "%3", "a" },
		{ "example.COM", "local", "primary", "$label1", "com" },
		{ "example.COM", "local", "primary", "$label2", "example" },
		{ "example.COM", "local", "primary", "$label3", "." },
		{ "example.COM", "local", "primary", "%z", "com" },
		{ "example.COM", "local", "primary", "%y", "example" },
		{ "example.COM", "local", "primary", "%x", "." },
		{ "example", "local", "primary", "$label1", "example" },
		{ "example", "local", "primary", "$label2", "." },
		{ "example", "local", "primary", "$label3", "." },
		{ "a.b.c.d.e", "local", "primary", "$label1", "e" },
		{ "a.b.c.d.e", "local", "primary", "$label2", "d" },
		{ "a.b.c.d.e", "local", "primary", "$label3", "c" },
		{ "a.b.c", "local", "primary", "$char1", "a" },
		{ "a.b.c", "local", "primary", "$char2", "." },
		{ "a.b.c", "local", "primary", "$char3", "b" },
		{ "a.b.c", "local", "primary", "%1", "a" },
		{ "a.b.c", "local", "primary", "%2", "." },
		{ "a.b.c", "local", "primary", "%3", "b" },
		{ "a", "local", "primary", "%1", "a" },
		{ "a", "local", "primary", "%2", "." },
		{ "a", "local", "primary", "%3", "." },
		{ "a.b.c.d", "local", "primary", "%1$char2%3$label1%x",
		  "a.bdb" }
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		isc_buffer_init(&b, buf, sizeof(buf));
		dns_test_namefromstring(tests[i].name, &of);
		dns_zone_expandzonefile(&b, tests[i].input, origin,
					tests[i].view, tests[i].type);
		assert_string_equal(buf, tests[i].expected);
	}

	/* test PATH_MAX overrun */
	char longname[PATH_MAX] = { 0 };
	memset(longname, 'x', sizeof(longname) - 1);

	/*
	 * overwrite the beginning of the long name with $name. when
	 * it's expanded to the zone name, the resulting string should
	 * still be capped at PATH_MAX characters.
	 */
	memmove(longname, "$name", 5);
	assert_int_equal(strlen(longname), PATH_MAX - 1);

	isc_buffer_init(&b, buf, sizeof(buf));
	dns_test_namefromstring("example.COM", &of);
	dns_zone_expandzonefile(&b, longname, origin, "local", "primary");
	memmove(longname, "example.com", 11);
	assert_string_equal(buf, longname);

	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(filename, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
