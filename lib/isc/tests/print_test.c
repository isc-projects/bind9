/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <config.h>

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/util.h>
#include <isc/types.h>

/*
 * Workout if we need to force the inclusion of print.c so we can test
 * it on all platforms even if we don't include it in libisc.
 */
#include <isc/platform.h>
#if !defined(ISC_PLATFORM_NEEDPRINTF) && \
    !defined(ISC_PLATFORM_NEEDFPRINTF) && \
    !defined(ISC_PLATFORM_NEEDSPRINTF) && \
    !defined(ISC_PLATFORM_NEEDVSNPRINTF)
# define ISC__PRINT_SOURCE
# define ISC_PLATFORM_NEEDPRINTF
# define ISC_PLATFORM_NEEDFPRINTF
# define ISC_PLATFORM_NEEDSPRINTF
# define ISC_PLATFORM_NEEDVSNPRINTF
# include <isc/print.h>
# include "../print.c"
#endif

/* Test snprintf() implementation */
static void
snprintf_test(void **state) {
	char buf[10000];
	uint64_t ll = 8589934592ULL;
	uint64_t nn = 20000000000000ULL;
	uint64_t zz = 10000000000000000000ULL;
	float pi = 3.141;
	int n;
	size_t size;

	UNUSED(state);

	/*
	 * 4294967296 <= 8589934592 < 1000000000^2 to verify fix for
	 * RT#36505.
	 */

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, ll);
	assert_int_equal(n, 10);
	assert_string_equal(buf, "8589934592");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, ll);
	assert_int_equal(n, 10);
	assert_string_equal(buf, "8589934592");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, nn);
	assert_int_equal(n, 14);
	assert_string_equal(buf, "20000000000000");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, nn);
	assert_int_equal(n, 14);
	assert_string_equal(buf, "20000000000000");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, zz);
	assert_int_equal(n, 20);
	assert_string_equal(buf, "10000000000000000000");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRIu64, zz);
	assert_int_equal(n, 20);
	assert_string_equal(buf, "10000000000000000000");

	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%" PRId64, nn);
	assert_int_equal(n, 14);
	assert_string_equal(buf, "20000000000000");

	size = 1000;
	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%zu", size);
	assert_int_equal(n, 4);
	assert_string_equal(buf, "1000");

	size = 1000;
	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%zx", size);
	assert_int_equal(n, 3);
	assert_string_equal(buf, "3e8");

	size = 1000;
	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "%zo", size);
	assert_int_equal(n, 4);
	assert_string_equal(buf, "1750");

	zz = 0xf5f5f5f5f5f5f5f5ULL;
	memset(buf, 0xff, sizeof(buf));
	n = isc_print_snprintf(buf, sizeof(buf), "0x%" PRIx64, zz);
	assert_int_equal(n, 18);
	assert_string_equal(buf, "0xf5f5f5f5f5f5f5f5");

	n = isc_print_snprintf(buf, sizeof(buf), "%.2f", pi);
	assert_int_equal(n, 4);
	assert_string_equal(buf, "3.14");

	/* Similar to the above, but additional characters follows */
	n = isc_print_snprintf(buf, sizeof(buf), "%.2f1592", pi);
	assert_int_equal(n, 8);
	assert_string_equal(buf, "3.141592");

	/* Similar to the above, but with leading spaces */
	n = isc_print_snprintf(buf, sizeof(buf), "% 8.2f1592", pi);
	assert_int_equal(n, 12);
	assert_string_equal(buf, "    3.141592");

	/* Similar to the above, but with trail spaces after the 4 */
	n = isc_print_snprintf(buf, sizeof(buf), "%-8.2f1592", pi);
	assert_int_equal(n, 12);
	assert_string_equal(buf, "3.14    1592");
}

/* Test fprintf implementation */
static void
fprintf_test(void **state) {
	FILE *f;
	int n;
	size_t size;
	char buf[10000];

	UNUSED(state);

	f = fopen("fprintf.test", "w+");
	assert_non_null(f);

	size = 1000;
	n = isc_print_fprintf(f, "%zu", size);
	assert_int_equal(n, 4);

	rewind(f);

	memset(buf, 0, sizeof(buf));
	n = fread(buf, 1, sizeof(buf), f);
	assert_int_equal(n, 4);

	fclose(f);

	assert_string_equal(buf, "1000");

	if ((n > 0) && (!strcmp(buf, "1000"))) {
		unlink("fprintf.test");
	}
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(snprintf_test),
		cmocka_unit_test(fprintf_test),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
