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
#include <unistd.h>

/*
 * As a workaround, include an OpenSSL header file before including cmocka.h,
 * because OpenSSL 3.1.0 uses __attribute__(malloc), conflicting with a
 * redefined malloc in cmocka.h.
 */
#include <openssl/err.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/crypto.h>
#include <isc/file.h>
#include <isc/hex.h>
#include <isc/lib.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/dsdigest.h>
#include <dns/lib.h>

#include <tests/dns.h>

ISC_RUN_TEST_IMPL(dsdigest_format) {
	struct {
		dns_dsdigest_t alg;
		const char *text;
	} totext[] = {
		{ DNS_DSDIGEST_SHA1, "SHA-1" },
		{ DNS_DSDIGEST_SHA256, "SHA-256" },
#if defined(DNS_DSDIGEST_SHA256PRIVATE) &&     \
	defined(DNS_DSDIGEST_SHA384PRIVATE) && \
	defined(DNS_DSDIGEST_SM3PRIVATE)
		{ DNS_DSDIGEST_SHA256PRIVATE, "SHA-256-PRIVATE" },
#endif
		/* Unknown digest fall back to the numeric form. */
		{ 101, "101" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(totext); i++) {
		char algstr[DNS_DSDIGEST_FORMATSIZE];

		dns_dsdigest_format(totext[i].alg, algstr, sizeof(algstr));
		assert_string_equal(algstr, totext[i].text);
	}
}

ISC_RUN_TEST_IMPL(dsdigest_totext) {
	/*
	 * Checks that DNS_DSDIGEST_FORMATSIZE is big enough
	 * by asserting ISC_R_SUCCESS.  Subtract 1 to allow
	 * for terminating NUL added in dns_dsdigest_format.
	 */
	char algstr[DNS_DSDIGEST_FORMATSIZE - 1];
	isc_buffer_t b;
	isc_result_t result;

	/* Assigned range. */
	for (dns_dsdigest_t i = 0; i < DNS_DSDIGEST_MAX; i++) {
		isc_buffer_init(&b, algstr, sizeof(algstr));
		result = dns_dsdigest_totext(i, &b);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/* Maximum possible value. */
	isc_buffer_init(&b, algstr, sizeof(algstr));
	result = dns_dsdigest_totext((dns_dsdigest_t)~0, &b);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dsdigest_format)
ISC_TEST_ENTRY(dsdigest_totext)
ISC_TEST_LIST_END

ISC_TEST_MAIN
