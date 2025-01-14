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
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/net.h>
#include <isc/timer.h>
#include <isc/tls.h>
#include <isc/util.h>

#include <dns/message.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(ede_enqueue_unlink) {
	dns_edelist_t list;
	dns_ede_t *ede = NULL;
	const char *msg1 = "abcd";
	const char *msg2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"
			   "dabcdabcdadcdabcd";

	ISC_LIST_INIT(list);

	dns_ede_append(mctx, &list, 22, NULL);
	dns_ede_append(mctx, &list, 12, msg1);
	dns_ede_append(mctx, &list, 4, msg2);

	ede = ISC_LIST_HEAD(list);
	assert_non_null(ede);
	assert_int_equal(ede->info_code, 22);
	assert_null(ede->extra_text);

	ede = ISC_LIST_NEXT(ede, link);
	assert_non_null(ede);
	assert_int_equal(ede->info_code, 12);
	assert_string_equal(ede->extra_text, msg1);
	assert_ptr_not_equal(ede->extra_text, msg1);

	/*
	 * Even though we limit the length of an EDE message to 64 bytes,
	 * this is done only at the ns/client.c level (to make sure to cover all
	 * the flows).
	 */
	ede = ISC_LIST_NEXT(ede, link);
	assert_non_null(ede);
	assert_int_equal(ede->info_code, 4);
	assert_string_equal(ede->extra_text, msg2);
	assert_ptr_not_equal(ede->extra_text, msg2);

	dns_ede_unlinkall(mctx, &list);
	assert_true(ISC_LIST_EMPTY(list));
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(ede_enqueue_unlink)

ISC_TEST_LIST_END

ISC_TEST_MAIN
