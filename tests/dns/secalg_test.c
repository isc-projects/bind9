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

#include <dns/keyvalues.h>
#include <dns/lib.h>

#include <tests/dns.h>

ISC_RUN_TEST_IMPL(secalg_format) {
	struct {
		dns_secalg_t alg;
		const char *text;
	} totext[] = {
		{ DNS_KEYALG_RSASHA256, "RSASHA256" },
		{ DNS_KEYALG_RSASHA512, "RSASHA512" },
		/* Unknown algorithms fall back to the numeric form. */
		{ 101, "101" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(totext); i++) {
		char algstr[DNS_SECALG_FORMATSIZE];

		dns_secalg_format(totext[i].alg, algstr, sizeof(algstr));
		assert_string_equal(algstr, totext[i].text);
	}
}

ISC_RUN_TEST_IMPL(secalg_totext) {
	/*
	 * Checks that DNS_SECALG_FORMATSIZE is big enough
	 * by asserting ISC_R_SUCCESS.  Subtract 1 to allow
	 * for terminating NUL added in dns_secalg_format.
	 */
	char algstr[DNS_SECALG_FORMATSIZE - 1];
	isc_buffer_t b;
	isc_result_t result;

	/* Assigned range. */
	for (dns_secalg_t i = 0; i < DNS_KEYALG_MAX; i++) {
		isc_buffer_init(&b, algstr, sizeof(algstr));
		result = dns_secalg_totext(i, &b);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/* Maximum possible value. */
	isc_buffer_init(&b, algstr, sizeof(algstr));
	result = dns_secalg_totext((dns_secalg_t)~0, &b);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(secalg_format)
ISC_TEST_ENTRY(secalg_totext)
ISC_TEST_LIST_END

ISC_TEST_MAIN
