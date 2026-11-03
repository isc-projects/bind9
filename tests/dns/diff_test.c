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

#define UNIT_TESTING
#include <cmocka.h>

#include <dns/diff.h>

/* isc/list.h must be imported after cmocka to avoid redefinition errors */
#include <isc/list.h>

#include <tests/dns.h>

unsigned char data_1[] = "\006name_1";
unsigned char offsets_1[] = { 0, 7 };
dns_name_t name_1 = DNS_NAME_INITABSOLUTE(data_1, offsets_1);

unsigned char data_2[] = "\006name_2";
unsigned char offsets_2[] = { 0, 7 };
dns_name_t name_2 = DNS_NAME_INITABSOLUTE(data_2, offsets_2);

unsigned char data_3[] = "\006name_3";
unsigned char offsets_3[] = { 0, 7 };
dns_name_t name_3 = DNS_NAME_INITABSOLUTE(data_3, offsets_3);

unsigned char data_dup[] = "\006name_1";
unsigned char offsets_dup[] = { 0, 7 };
dns_name_t name_dup = DNS_NAME_INITABSOLUTE(data_dup, offsets_dup);

unsigned char data_nodup[] = "\006name_1";
unsigned char offsets_nodup[] = { 0, 7 };
dns_name_t name_nodup = DNS_NAME_INITABSOLUTE(data_nodup, offsets_nodup);

static size_t
count_elements(const dns_diff_t *diff) {
	dns_difftuple_t *ot = NULL;
	size_t count = 0;

	for (ot = ISC_LIST_HEAD(diff->tuples); ot != NULL;
	     ot = ISC_LIST_NEXT(ot, link))
	{
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
	isc_result_t result = dns_difftuple_create(mctx, op, name, 1, rdata,
						   &tup);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_diff_append(diff, &tup);
}

ISC_RUN_TEST_IMPL(dns_diff_size) {
	dns_diff_t diff;
	dns_diff_init(mctx, &diff);

	assert_true(dns_diff_size(&diff) == 0);

	dns_rdata_t rdatas[5] = { 0 };
	unsigned char bufs[sizeof(rdatas) / sizeof(*rdatas)][128] = { 0 };
	size_t buf_len = sizeof(bufs[0]);

	for (size_t idx = 0; idx < sizeof(rdatas) / sizeof(*rdatas); ++idx) {
		prepare_rdata(&rdatas[idx], bufs[idx], buf_len);
	}

	dns_difftuple_t *tup_1 = NULL, *tup_2 = NULL, *tup_3 = NULL;
	dns_difftuple_create(mctx, DNS_DIFFOP_ADD, &name_1, 1, &rdatas[0],
			     &tup_1);
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_2, 1, &rdatas[1],
			     &tup_2);
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_3, 1, &rdatas[2],
			     &tup_3);

	dns_difftuple_t *tup_dup = NULL, *tup_nodup = NULL;
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_dup, 1, &rdatas[3],
			     &tup_dup);
	dns_difftuple_create(mctx, DNS_DIFFOP_ADD, &name_nodup, 1, &rdatas[4],
			     &tup_nodup);

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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
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
	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);

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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
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

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);

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
	dns_difftuple_t *t;
	ISC_LIST_FOREACH(diff.tuples, t, link) {
		assert_true(dns_name_caseequal(&t->name, expected_names[i]));
		assert_true(t->op == expected_ops[i]);
		i++;
	}
	assert_true(i == 5);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* Owner case changes must survive minimization. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_ownercase) {
	unsigned char data[] = "\006NAME_1";
	unsigned char offsets[] = { 0, 7 };
	dns_name_t upper = DNS_NAME_INITABSOLUTE(data, offsets);
	dns_diff_t diff, source;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	unsigned char buf[128];
	dns_difftuple_t *tuple;

	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &source);
	prepare_rdata(&rdata, buf, sizeof(buf));
	assert_true(dns_name_equal(&name_1, &upper));
	assert_false(dns_name_caseequal(&name_1, &upper));

	append_tuple(&diff, DNS_DIFFOP_DEL, &name_1, &rdata);
	append_tuple(&source, DNS_DIFFOP_ADD, &upper, &rdata);
	dns_diff_appendlistminimal(&diff, &source);

	assert_int_equal(dns_diff_size(&diff), 2);
	assert_int_equal(dns_diff_size(&source), 0);
	tuple = ISC_LIST_HEAD(diff.tuples);
	assert_int_equal(tuple->op, DNS_DIFFOP_DEL);
	assert_true(dns_name_caseequal(&tuple->name, &name_1));
	tuple = ISC_LIST_NEXT(tuple, link);
	assert_int_equal(tuple->op, DNS_DIFFOP_ADD);
	assert_true(dns_name_caseequal(&tuple->name, &upper));

	/* Reverting the case change cancels each exact spelling. */
	append_tuple(&source, DNS_DIFFOP_DEL, &upper, &rdata);
	append_tuple(&source, DNS_DIFFOP_ADD, &name_1, &rdata);
	dns_diff_appendlistminimal(&diff, &source);
	assert_int_equal(dns_diff_size(&diff), 0);
	assert_int_equal(dns_diff_size(&source), 0);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

/* Hashing must preserve the equality rules of each RDATA type. */
ISC_RUN_TEST_IMPL(dns_diff_appendlistminimal_rdata) {
	const struct {
		dns_rdatatype_t type;
		const char *text[2];
		bool equal;
	} cases[] = {
		{ .type = dns_rdatatype_txt,
		  .text = { "\"Hello\"", "\"hello\"" },
		  .equal = false },
		{ .type = dns_rdatatype_mx,
		  .text = { "10 Mail.Example.", "10 mail.example." },
		  .equal = true },
		/* The preference bytes must not be case-folded either. */
		{ .type = dns_rdatatype_mx,
		  .text = { "65 mail.example.", "97 mail.example." },
		  .equal = false },
		{ .type = dns_rdatatype_soa,
		  .text = { "Ns.Example. Hostmaster.Example. 1 2 3 4 5",
			    "ns.example. hostmaster.example. 1 2 3 4 5" },
		  .equal = true },
		{ .type = dns_rdatatype_rrsig,
		  .text = { "TXT 8 1 300 20300101000000 20260101000000 "
			    "12345 Example. QUFB",
			    "TXT 8 1 300 20300101000000 20260101000000 "
			    "12345 example. QUFB" },
		  .equal = true },
		/* QUFB and YWFh decode to case-distinct signature bytes. */
		{ .type = dns_rdatatype_rrsig,
		  .text = { "TXT 8 1 300 20300101000000 20260101000000 "
			    "12345 example. QUFB",
			    "TXT 8 1 300 20300101000000 20260101000000 "
			    "12345 example. YWFh" },
		  .equal = false },
		/* NSEC's next name is compared case-sensitively. */
		{ .type = dns_rdatatype_nsec,
		  .text = { "Next.Example. A", "next.example. A" },
		  .equal = false },
		/* TKEY has no digest, but its algorithm name ignores case. */
		{ .type = dns_rdatatype_tkey,
		  .text = { "Hmac-Sha256. 0 0 3 NOERROR 0 0",
			    "hmac-sha256. 0 0 3 NOERROR 0 0" },
		  .equal = true },
		{ .type = 65500,
		  .text = { "\\# 1 41", "\\# 1 61" },
		  .equal = false },
		{ .type = 65500, .text = { "\\# 0", "\\# 0" }, .equal = true },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		dns_diff_t diff, source;
		dns_rdata_t rdata[2] = { DNS_RDATA_INIT, DNS_RDATA_INIT };
		unsigned char buf[2][256];
		isc_result_t result;

		dns_diff_init(mctx, &diff);
		dns_diff_init(mctx, &source);
		for (size_t j = 0; j < 2; j++) {
			result = dns_test_rdatafromstring(
				&rdata[j], dns_rdataclass_in, cases[i].type,
				buf[j], sizeof(buf[j]), cases[i].text[j],
				false);
			assert_int_equal(result, ISC_R_SUCCESS);
		}
		assert_true((dns_rdata_compare(&rdata[0], &rdata[1]) == 0) ==
			    cases[i].equal);

		append_tuple(&diff, DNS_DIFFOP_ADD, &name_1, &rdata[0]);
		append_tuple(&source, DNS_DIFFOP_DEL, &name_1, &rdata[1]);
		dns_diff_appendlistminimal(&diff, &source);

		assert_int_equal(dns_diff_size(&diff), cases[i].equal ? 0 : 2);
		assert_int_equal(dns_diff_size(&source), 0);
		dns_diff_clear(&source);
		dns_diff_clear(&diff);
	}
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
ISC_TEST_ENTRY(dns_diff_appendlistminimal_ownercase)
ISC_TEST_ENTRY(dns_diff_appendlistminimal_rdata)
ISC_TEST_LIST_END

ISC_TEST_MAIN
