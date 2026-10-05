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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>

#include <tests/isc.h>

/*
 * dns_message_renderend() invokes dns_compress_rollback(cctx, 0) when a
 * truncated response is re-rendered with TC+OPT/TSIG/SIG(0). The walk
 * must clear every populated slot and leave count == 0 — and crucially
 * must not decrement count for empty slots, which would underflow the
 * uint16_t and lock out subsequent insert_label() calls in the same
 * render via the load-factor guard.
 */
ISC_RUN_TEST_IMPL(rollback_zero_clears_all) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[1024];
	const char *names[] = {
		"www.example.com.",  "mail.example.com.", "ns1.example.com.",
		"ns2.example.com.",  "a.b.c.d.example.",  "x.y.z.example.",
		"foo.bar.baz.test.", "alpha.beta.gamma.",
	};

	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	isc_buffer_add(&buffer, DNS_MESSAGE_HEADERLEN);

	dns_compress_init(&cctx, isc_g_mctx, 0);

	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		dns_fixedname_t fixed;
		dns_name_t *name = dns_fixedname_initname(&fixed);
		assert_int_equal(
			dns_name_fromstring(name, names[i], NULL, 0, NULL),
			ISC_R_SUCCESS);

		assert_int_equal(dns_name_towire(name, &cctx, &buffer),
				 ISC_R_SUCCESS);
	}

	assert_true(cctx.count > 0);

	dns_compress_rollback(&cctx, 0);

	assert_int_equal(cctx.count, 0);
	for (unsigned int i = 0; i <= cctx.mask; i++) {
		assert_int_equal(cctx.set[i].coff, 0);
		assert_int_equal(cctx.set[i].hash, 0);
	}

	dns_compress_invalidate(&cctx);
}

/*
 * Edge case: rollback(0) on a fresh, empty compression context must be
 * a no-op. The pre-fix code decremented count for every empty slot,
 * underflowing uint16_t to ~65535.
 */
ISC_RUN_TEST_IMPL(rollback_zero_on_empty) {
	dns_compress_t cctx;

	dns_compress_init(&cctx, isc_g_mctx, 0);
	assert_int_equal(cctx.count, 0);

	dns_compress_rollback(&cctx, 0);

	assert_int_equal(cctx.count, 0);

	dns_compress_invalidate(&cctx);
}

/*
 * After rollback(0) the table must accept new insertions. Pre-fix, the
 * underflowed count tripped the load-factor guard in insert_label() and
 * silently dropped every subsequent compression entry.
 */
ISC_RUN_TEST_IMPL(rollback_zero_then_reuse) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[1024];
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	isc_buffer_add(&buffer, DNS_MESSAGE_HEADERLEN);

	dns_compress_init(&cctx, isc_g_mctx, 0);

	dns_compress_rollback(&cctx, 0);

	name = dns_fixedname_initname(&fixed);
	assert_int_equal(dns_name_fromstring(name, "after.rollback.test.", NULL,
					     0, NULL),
			 ISC_R_SUCCESS);
	assert_int_equal(dns_name_towire(name, &cctx, &buffer), ISC_R_SUCCESS);
	assert_true(cctx.count > 0);
	assert_true(cctx.count <= cctx.mask + 1U);

	dns_compress_invalidate(&cctx);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(rollback_zero_clears_all)
ISC_TEST_ENTRY(rollback_zero_on_empty)
ISC_TEST_ENTRY(rollback_zero_then_reuse)
ISC_TEST_LIST_END
ISC_TEST_MAIN
