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

/* sched.h must be imported before cmocka to avoid redefinition errors */
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "isc/list.h"

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>

#include <dns/diff.h>
#include <dns/lib.h>

#include <tests/dns.h>

unsigned char data_1[] = "\006name_1";
dns_name_t name_1 = DNS_NAME_INITABSOLUTE(data_1);

unsigned char data_2[] = "\006name_2";
dns_name_t name_2 = DNS_NAME_INITABSOLUTE(data_2);

unsigned char data_3[] = "\006name_3";
dns_name_t name_3 = DNS_NAME_INITABSOLUTE(data_3);

unsigned char data_dup[] = "\006name_1";
dns_name_t name_dup = DNS_NAME_INITABSOLUTE(data_dup);

unsigned char data_nodup[] = "\006name_1";
dns_name_t name_nodup = DNS_NAME_INITABSOLUTE(data_nodup);

static size_t
count_elements(dns_diff_t *diff) {
	size_t count = 0;

	ISC_LIST_FOREACH(diff->tuples, ot, link) {
		++count;
	}

	return count;
}

static void
prepare_rdata_text(dns_rdata_t *rdata, unsigned char *dest, size_t dest_size,
		   const char *text) {
	*rdata = (dns_rdata_t)DNS_RDATA_INIT;
	isc_result_t result = dns_test_rdatafromstring(
		rdata, dns_rdataclass_in, dns_rdatatype_wallet, dest, dest_size,
		text, false);
	INSIST(result == ISC_R_SUCCESS);
}

static void
prepare_rdata(dns_rdata_t *rdata, unsigned char *dest, size_t dest_size) {
	prepare_rdata_text(rdata, dest, dest_size, "cid-example wid-example");
}

static void
append_tuple(dns_diff_t *diff, dns_diffop_t op, const dns_name_t *name,
	     dns_rdata_t *rdata) {
	dns_difftuple_t *tup = NULL;
	dns_difftuple_create(isc_g_mctx, op, name, 1, rdata, &tup);
	dns_diff_append(diff, &tup);
}

ISC_RUN_TEST_IMPL(dns_diff_size) {
	dns_diff_t diff;
	dns_diff_init(isc_g_mctx, &diff);

	assert_true(dns_diff_size(&diff) == 0);

	dns_rdata_t rdatas[5] = { 0 };
	unsigned char bufs[sizeof(rdatas) / sizeof(*rdatas)][128] = { 0 };
	size_t buf_len = sizeof(bufs[0]);

	for (size_t idx = 0; idx < sizeof(rdatas) / sizeof(*rdatas); ++idx) {
		prepare_rdata(&rdatas[idx], bufs[idx], buf_len);
	}

	dns_difftuple_t *tup_1 = NULL, *tup_2 = NULL, *tup_3 = NULL;
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_ADD, &name_1, 1, &rdatas[0],
			     &tup_1);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_2, 1, &rdatas[1],
			     &tup_2);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_3, 1, &rdatas[2],
			     &tup_3);

	dns_difftuple_t *tup_dup = NULL, *tup_nodup = NULL;
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_dup, 1,
			     &rdatas[3], &tup_dup);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_ADD, &name_nodup, 1,
			     &rdatas[4], &tup_nodup);

	dns_diff_append(&diff, &tup_1);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_append(&diff, &tup_2);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_appendminimal(&diff, &tup_dup);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_append(&diff, &tup_3);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_appendminimal(&diff, &tup_nodup);
	assert_true(dns_diff_size(&diff) == 3);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_clear(&diff);
	assert_true(dns_diff_size(&diff) == 0);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_difftuple_t *to_clear[] = { tup_1, tup_2, tup_3, tup_dup,
					tup_nodup };
	size_t to_clear_size = sizeof(to_clear) / sizeof(*to_clear);

	for (size_t idx = 0; idx < to_clear_size; ++idx) {
		if (to_clear[idx] != NULL) {
			dns_difftuple_free(&to_clear[idx]);
		}
	}
}

/*
 * Basic: source entries pass through into diff, and a source entry
 * that matches a pre-existing diff entry with the opposite op cancels
 * it (both are dropped).
 */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_basic) {
	dns_diff_t diff, source;
	dns_rdata_t rdatas[3] = { 0 };
	unsigned char bufs[3][128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);
	for (size_t i = 0; i < 3; i++) {
		prepare_rdata(&rdatas[i], bufs[i], sizeof(bufs[i]));
	}

	/* diff: [ADD name_1] */
	append_tuple(&diff, DNS_DIFFOP_ADD, &name_1, &rdatas[0]);

	/* source: [DEL name_2, DEL name_1 (cancels), DEL name_3] */
	append_tuple(&source, DNS_DIFFOP_DEL, &name_2, &rdatas[1]);
	append_tuple(&source, DNS_DIFFOP_DEL, &name_1, &rdatas[0]);
	append_tuple(&source, DNS_DIFFOP_DEL, &name_3, &rdatas[2]);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&source) == 0);
	assert_true(count_elements(&source) == 0);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* An empty source must leave a non-empty diff untouched. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_empty_source) {
	dns_diff_t diff, source;
	dns_rdata_t rdata = { 0 };
	unsigned char buf[128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);
	prepare_rdata(&rdata, buf, sizeof(buf));

	append_tuple(&diff, DNS_DIFFOP_ADD, &name_1, &rdata);
	append_tuple(&diff, DNS_DIFFOP_DEL, &name_2, &rdata);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	assert_true(dns_diff_size(&source) == 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* Appending into an empty diff must move all source entries over. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_empty_diff) {
	dns_diff_t diff, source;
	dns_rdata_t rdata = { 0 };
	unsigned char buf[128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);
	prepare_rdata(&rdata, buf, sizeof(buf));

	append_tuple(&source, DNS_DIFFOP_ADD, &name_1, &rdata);
	append_tuple(&source, DNS_DIFFOP_DEL, &name_2, &rdata);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	assert_true(dns_diff_size(&source) == 0);
	assert_true(count_elements(&source) == 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* Both empty: no-op. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_both_empty) {
	dns_diff_t diff, source;
	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 0);
	assert_true(dns_diff_size(&source) == 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/*
 * Two entries within 'source' that cancel each other (neither
 * pre-existing in 'diff') must both be dropped.
 */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_source_cancel) {
	dns_diff_t diff, source;
	dns_rdata_t rdatas[2] = { 0 };
	unsigned char bufs[2][128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);
	for (size_t i = 0; i < 2; i++) {
		prepare_rdata(&rdatas[i], bufs[i], sizeof(bufs[i]));
	}

	append_tuple(&source, DNS_DIFFOP_ADD, &name_1, &rdatas[0]);
	append_tuple(&source, DNS_DIFFOP_DEL, &name_1, &rdatas[1]);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 0);
	assert_true(count_elements(&diff) == 0);
	assert_true(dns_diff_size(&source) == 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* A non-minimal destination must be minimized along with the source. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_nonminimal_diff) {
	dns_diff_t diff, source;
	dns_rdata_t rdatas[3] = { 0 };
	unsigned char bufs[3][128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);
	for (size_t i = 0; i < 3; i++) {
		prepare_rdata(&rdatas[i], bufs[i], sizeof(bufs[i]));
	}

	append_tuple(&diff, DNS_DIFFOP_ADD, &name_1, &rdatas[0]);
	append_tuple(&diff, DNS_DIFFOP_DEL, &name_1, &rdatas[1]);
	append_tuple(&source, DNS_DIFFOP_ADD, &name_2, &rdatas[2]);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	assert_true(
		dns_name_caseequal(&ISC_LIST_HEAD(diff.tuples)->name, &name_2));
	assert_true(dns_diff_size(&source) == 0);
	assert_true(count_elements(&source) == 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/*
 * Ordering: original 'diff' entries keep their relative order and
 * appear first; 'source' entries are appended in source order. Uses
 * distinct rdata so nothing cancels.
 */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_order) {
	dns_diff_t diff, source;
	dns_rdata_t rdatas[5] = { 0 };
	unsigned char bufs[5][128] = { 0 };

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);

	prepare_rdata_text(&rdatas[0], bufs[0], sizeof(bufs[0]), "cid-1 wid-1");
	prepare_rdata_text(&rdatas[1], bufs[1], sizeof(bufs[1]), "cid-2 wid-2");
	prepare_rdata_text(&rdatas[2], bufs[2], sizeof(bufs[2]), "cid-3 wid-3");
	prepare_rdata_text(&rdatas[3], bufs[3], sizeof(bufs[3]), "cid-4 wid-4");
	prepare_rdata_text(&rdatas[4], bufs[4], sizeof(bufs[4]), "cid-5 wid-5");

	append_tuple(&diff, DNS_DIFFOP_ADD, &name_1, &rdatas[0]);
	append_tuple(&diff, DNS_DIFFOP_ADD, &name_2, &rdatas[1]);

	append_tuple(&source, DNS_DIFFOP_ADD, &name_3, &rdatas[2]);
	append_tuple(&source, DNS_DIFFOP_DEL, &name_1, &rdatas[3]);
	append_tuple(&source, DNS_DIFFOP_ADD, &name_2, &rdatas[4]);

	dns_diff_appendlistminimal(&diff, &source);

	assert_true(dns_diff_size(&diff) == 5);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	const dns_name_t *expected_names[] = { &name_1, &name_2, &name_3,
					       &name_1, &name_2 };
	dns_diffop_t expected_ops[] = { DNS_DIFFOP_ADD, DNS_DIFFOP_ADD,
					DNS_DIFFOP_ADD, DNS_DIFFOP_DEL,
					DNS_DIFFOP_ADD };
	size_t i = 0;
	ISC_LIST_FOREACH(diff.tuples, t, link) {
		assert_true(dns_name_caseequal(&t->name, expected_names[i]));
		assert_true(t->op == expected_ops[i]);
		i++;
	}
	assert_true(i == 5);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_diff_size)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_basic)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_empty_source)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_empty_diff)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_both_empty)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_source_cancel)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_nonminimal_diff)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_order)
ISC_TEST_LIST_END

ISC_TEST_MAIN
