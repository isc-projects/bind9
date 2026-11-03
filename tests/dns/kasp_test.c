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

#include <isc/lib.h>
#include <isc/util.h>

#include <dns/kasp.h>
#include <dns/lib.h>

#include <tests/dns.h>

/* Default and clamped RSA key sizes. */
ISC_RUN_TEST_IMPL(kasp_key_size_rsa) {
	struct {
		dst_algorithm_t algorithm;
		int length;
		unsigned int expected;
	} testcases[] = {
		/* No configured length: default to 2048. */
		{ DST_ALG_RSASHA1, -1, 2048 },
		{ DST_ALG_NSEC3RSASHA1, -1, 2048 },
		{ DST_ALG_RSASHA256, -1, 2048 },
		{ DST_ALG_RSASHA512, -1, 2048 },
		{ DST_ALG_RSASHA256PRIVATEOID, -1, 2048 },
		{ DST_ALG_RSASHA512PRIVATEOID, -1, 2048 },
		/* The minimum for all RSA algorithms is 1024. */
		{ DST_ALG_RSASHA1, 512, 1024 },
		{ DST_ALG_NSEC3RSASHA1, 512, 1024 },
		{ DST_ALG_RSASHA256, 512, 1024 },
		{ DST_ALG_RSASHA512, 512, 1024 },
		{ DST_ALG_RSASHA256PRIVATEOID, 512, 1024 },
		{ DST_ALG_RSASHA512PRIVATEOID, 512, 1024 },
		{ DST_ALG_RSASHA256, 1024, 1024 },
		/* Values in range are returned unchanged. */
		{ DST_ALG_RSASHA256, 3072, 3072 },
		{ DST_ALG_RSASHA256, 4096, 4096 },
		/* The maximum is 4096. */
		{ DST_ALG_RSASHA256, 8192, 4096 },
	};
	dns_kasp_t *kasp = NULL;

	dns_kasp_create(isc_g_mctx, "test", &kasp);

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_kasp_key_t *key = NULL;

		dns_kasp_key_create(kasp, &key);
		key->algorithm = testcases[i].algorithm;
		key->length = testcases[i].length;
		assert_int_equal(dns_kasp_key_size(key), testcases[i].expected);
		dns_kasp_key_destroy(key);
	}

	dns_kasp_detach(&kasp);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(kasp_key_size_rsa)
ISC_TEST_LIST_END

ISC_TEST_MAIN
