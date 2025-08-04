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
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/name.h>
#include <dns/qp.h>

#include "qp_p.h"

#include <tests/dns.h>
#include <tests/qp.h>

bool verbose = false;

ISC_RUN_TEST_IMPL(qpkey_name) {
	struct {
		const char *namestr;
		dns_namespace_t space;
		uint8_t key[512];
		size_t len;
	} testcases[] = {
		{
			.namestr = "",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x02 },
			.len = 1,
		},
		{
			.namestr = ".",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x02, 0x02 },
			.len = 2,
		},
		{
			.namestr = "\\000",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x03, 0x03, 0x02 },
			.len = 4,
		},
		{
			.namestr = "\\000\\009",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x03, 0x03, 0x03, 0x0c, 0x02 },
			.len = 6,
		},
		{
			.namestr = "com",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x16, 0x22, 0x20, 0x02 },
			.len = 5,
		},
		{
			.namestr = "com.",
			.space = DNS_DBNAMESPACE_NSEC,
			.key = { 0x08, 0x02, 0x16, 0x22, 0x20, 0x02 },
			.len = 6,
		},
		{
			.namestr = "com.",
			.space = DNS_DBNAMESPACE_NSEC3,
			.key = { 0x09, 0x02, 0x16, 0x22, 0x20, 0x02 },
			.len = 6,
		},
		{
			.namestr = "com.",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x02, 0x16, 0x22, 0x20, 0x02 },
			.len = 6,
		},
		{
			.namestr = "example.com.",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x02, 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b,
				 0x14, 0x20, 0x23, 0x1f, 0x18, 0x02 },
			.len = 14,
		},
		{
			.namestr = "example.com",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b, 0x14,
				 0x20, 0x23, 0x1f, 0x18, 0x02 },
			.len = 13,
		},
		{
			.namestr = "EXAMPLE.COM",
			.space = DNS_DBNAMESPACE_NORMAL,
			.key = { 0x07, 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b, 0x14,
				 0x20, 0x23, 0x1f, 0x18, 0x02 },
			.len = 13,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		size_t len;
		dns_qpkey_t key;
		dns_fixedname_t fn1, fn2;
		dns_name_t *in = NULL, *out = NULL;
		char namebuf[DNS_NAME_FORMATSIZE];
		dns_namespace_t space;

		in = dns_fixedname_initname(&fn1);
		if (testcases[i].len > 1) {
			dns_test_namefromstring(testcases[i].namestr, &fn1);
		}
		len = dns_qpkey_fromname(key, in, testcases[i].space);
		if (verbose) {
			qp_test_printkey(key, len);
		}

		assert_int_equal(testcases[i].len, len);
		assert_memory_equal(testcases[i].key, key, len);

		out = dns_fixedname_initname(&fn2);
		dns_qpkey_toname(key, len, out, &space);
		assert_true(dns_name_equal(in, out));
		assert_int_equal(space, testcases[i].space);
		/* check that 'out' is properly reset by dns_qpkey_toname */
		dns_qpkey_toname(key, len, out, NULL);
		dns_name_format(out, namebuf, sizeof(namebuf));
	}
}

ISC_RUN_TEST_IMPL(qpkey_sort) {
	struct {
		const char *namestr;
		dns_name_t *name;
		dns_fixedname_t fixed;
		dns_namespace_t space;
		size_t len;
		dns_qpkey_t key;
	} testcases[] = {
		{ .namestr = ".", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "\\000.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "\\000.\\000.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "\\000\\009.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "\\007.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "example.com.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "EXAMPLE.COM.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "www.example.com.",
		  .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "exam.com.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "exams.com.", .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "exam\\000.com.",
		  .space = DNS_DBNAMESPACE_NORMAL },
		{ .namestr = "exam.com.", .space = DNS_DBNAMESPACE_NSEC },
		{ .namestr = "exams.com.", .space = DNS_DBNAMESPACE_NSEC },
		{ .namestr = "exam.com.", .space = DNS_DBNAMESPACE_NSEC3 },
		{ .namestr = "exams.com.", .space = DNS_DBNAMESPACE_NSEC3 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_test_namefromstring(testcases[i].namestr,
					&testcases[i].fixed);
		testcases[i].name = dns_fixedname_name(&testcases[i].fixed);
		testcases[i].len = dns_qpkey_fromname(testcases[i].key,
						      testcases[i].name,
						      testcases[i].space);
	}

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(testcases); j++) {
			int namecmp = dns_name_compare(testcases[i].name,
						       testcases[j].name);
			size_t len = ISC_MIN(testcases[i].len,
					     testcases[j].len);
			/* include extra terminating NOBYTE */
			int keycmp = memcmp(testcases[i].key, testcases[j].key,
					    len + 1);
			if (testcases[i].space == testcases[j].space) {
				assert_true((namecmp < 0) == (keycmp < 0));
				assert_true((namecmp == 0) == (keycmp == 0));
				assert_true((namecmp > 0) == (keycmp > 0));
			} else {
				uint8_t di = testcases[i].space;
				uint8_t dj = testcases[j].space;
				assert_true((di < dj) == (keycmp < 0));
				assert_true((di > dj) == (keycmp > 0));
			}
		}
	}
}

#define ITER_ITEMS 100

static void
check_leaf(void *uctx, void *pval, uint32_t ival) {
	uint32_t *items = uctx;
	assert_in_range(ival, 1, ITER_ITEMS - 1);
	assert_ptr_equal(items + ival, pval);
}

static size_t
qpiter_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival) {
	check_leaf(uctx, pval, ival);

	char str[8];
	snprintf(str, sizeof(str), "%03u", ival);

	size_t i = 0;
	while (str[i] != '\0') {
		key[i] = str[i] - '0' + SHIFT_BITMAP;
		i++;
	}
	key[i++] = SHIFT_NOBYTE;

	return i;
}

static void
getname(void *uctx, char *buf, size_t size) {
	strlcpy(buf, "test", size);
	UNUSED(uctx);
	UNUSED(size);
}

const dns_qpmethods_t qpiter_methods = {
	check_leaf,
	check_leaf,
	qpiter_makekey,
	getname,
};

ISC_RUN_TEST_IMPL(qpiter) {
	dns_qp_t *qp = NULL;
	uint32_t item[ITER_ITEMS] = { 0 };
	uint32_t order[ITER_ITEMS] = { 0 };
	dns_qpiter_t qpi;
	int inserted, n;
	uint32_t ival;
	void *pval = NULL;
	isc_result_t result;

	dns_qp_create(isc_g_mctx, &qpiter_methods, item, &qp);
	for (size_t tests = 0; tests < 1234; tests++) {
		ival = isc_random_uniform(ITER_ITEMS - 1) + 1;
		pval = &item[ival];

		item[ival] = ival;

		inserted = n = 0;

		/* randomly insert or remove */
		dns_qpkey_t key;
		size_t len = qpiter_makekey(key, item, pval, ival);
		if (dns_qp_insert(qp, pval, ival) == ISC_R_EXISTS) {
			void *pvald = NULL;
			uint32_t ivald = 0;
			dns_qp_deletekey(qp, key, len, &pvald, &ivald);
			assert_ptr_equal(pval, pvald);
			assert_int_equal(ival, ivald);
			item[ival] = 0;
		}

		/* check that we see only valid items in the correct order */
		uint32_t prev = 0;
		dns_qpiter_init(qp, &qpi);
		while (dns_qpiter_next(&qpi, NULL, &pval, &ival) ==
		       ISC_R_SUCCESS)
		{
			assert_in_range(ival, prev + 1, ITER_ITEMS - 1);
			assert_int_equal(ival, item[ival]);
			assert_ptr_equal(pval, &item[ival]);
			order[inserted++] = ival;
			item[ival] = ~ival;
			prev = ival;
		}

		/* ensure we saw every item */
		for (ival = 0; ival < ITER_ITEMS; ival++) {
			if (item[ival] != 0) {
				assert_int_equal(item[ival], ~ival);
				item[ival] = ival;
			}
		}

		/* now iterate backward and check correctness */
		n = inserted;
		while (dns_qpiter_prev(&qpi, NULL, NULL, &ival) ==
		       ISC_R_SUCCESS)
		{
			--n;

			assert_int_equal(ival, order[n]);

			/* and check current iterator value as well */
			result = dns_qpiter_current(&qpi, NULL, NULL, &ival);
			assert_int_equal(result, ISC_R_SUCCESS);
			assert_int_equal(ival, order[n]);
		}

		assert_int_equal(n, 0);

		/* ...and forward again */
		while (dns_qpiter_next(&qpi, NULL, NULL, &ival) ==
		       ISC_R_SUCCESS)
		{
			assert_int_equal(ival, order[n]);

			/* and check current iterator value as well */
			result = dns_qpiter_current(&qpi, NULL, NULL, &ival);
			assert_int_equal(result, ISC_R_SUCCESS);
			assert_int_equal(ival, order[n]);

			n++;
		}

		assert_int_equal(n, inserted);

		/*
		 * if there are enough items inserted, try going
		 * forward a few steps, then back to the start,
		 * to confirm we can change directions while iterating.
		 */
		if (inserted > 3) {
			assert_int_equal(
				dns_qpiter_next(&qpi, NULL, NULL, &ival),
				ISC_R_SUCCESS);
			assert_int_equal(ival, order[0]);

			assert_int_equal(
				dns_qpiter_next(&qpi, NULL, NULL, &ival),
				ISC_R_SUCCESS);
			assert_int_equal(ival, order[1]);

			assert_int_equal(
				dns_qpiter_prev(&qpi, NULL, NULL, &ival),
				ISC_R_SUCCESS);
			assert_int_equal(ival, order[0]);

			assert_int_equal(
				dns_qpiter_next(&qpi, NULL, NULL, &ival),
				ISC_R_SUCCESS);
			assert_int_equal(ival, order[1]);

			assert_int_equal(
				dns_qpiter_prev(&qpi, NULL, NULL, &ival),
				ISC_R_SUCCESS);
			assert_int_equal(ival, order[0]);

			assert_int_equal(
				dns_qpiter_prev(&qpi, NULL, NULL, &ival),
				ISC_R_NOMORE);
		}
	}

	dns_qp_destroy(&qp);
}

static void
no_op(void *uctx, void *pval, uint32_t ival) {
	UNUSED(uctx);
	UNUSED(pval);
	UNUSED(ival);
}

static size_t
qpkey_fromstring(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival) {
	dns_fixedname_t fixed;
	dns_namespace_t space = ival;

	UNUSED(uctx);
	dns_test_namefromstring(pval, &fixed);
	return dns_qpkey_fromname(key, dns_fixedname_name(&fixed), space);
}

const dns_qpmethods_t string_methods = {
	no_op,
	no_op,
	qpkey_fromstring,
	getname,
};

struct check_partialmatch {
	const char *query;
	isc_result_t result;
	const char *found;
};

static void
check_partialmatch(dns_qp_t *qp, struct check_partialmatch check[],
		   dns_namespace_t space) {
	for (int i = 0; check[i].query != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1, fn2;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_name_t *foundname = dns_fixedname_initname(&fn2);
		void *pval = NULL;

		dns_test_namefromstring(check[i].query, &fn1);
		result = dns_qp_lookup(qp, name, space, foundname, NULL, NULL,
				       &pval, NULL);

#if 0
		fprintf(stderr, "%s%s %s (expected %s) "
			"value \"%s\" (expected \"%s\")\n",
			space == DNS_DBNAMESPACE_NSEC3 ? "NSEC3:" : (space == DNS_DBNAMESPACE_NSEC ? "NSEC:" : ""),
			check[i].query,
			isc_result_totext(result),
			isc_result_totext(check[i].result), (char *)pval,
			check[i].found);
#endif

		assert_int_equal(result, check[i].result);
		if (result == ISC_R_SUCCESS) {
			assert_true(dns_name_equal(name, foundname));
		} else if (result == DNS_R_PARTIALMATCH) {
			/*
			 * there are cases where we may have passed a
			 * query name that was relative to the zone apex,
			 * and gotten back an absolute name from the
			 * partial match. it's also possible for an
			 * absolute query to get a partial match on a
			 * node that had an empty name. in these cases,
			 * sanity checking the relations between name
			 * and foundname can trigger an assertion, so
			 * let's just skip them.
			 */
			if (dns_name_isabsolute(name) ==
			    dns_name_isabsolute(foundname))
			{
				assert_false(dns_name_equal(name, foundname));
				assert_true(
					dns_name_issubdomain(name, foundname));
			}
		}
		if (check[i].found == NULL) {
			assert_null(pval);
		} else {
			assert_string_equal(pval, check[i].found);
		}
	}
}

static void
insert_name(dns_qp_t *qp, const char *str, dns_namespace_t space) {
	isc_result_t result;
	uintptr_t pval = (uintptr_t)str;
	uint32_t ival = (uint32_t)space;
	INSIST((pval & 3) == 0);
	result = dns_qp_insert(qp, (void *)pval, ival);
	assert_int_equal(result, ISC_R_SUCCESS);
}

static void
delete_rootkey(dns_qp_t *qp, dns_namespace_t space) {
	uint8_t d = dns_qp_bits_for_byte[space + 48];
	dns_qpkey_t rootkey = { d, SHIFT_NOBYTE };
	isc_result_t result = dns_qp_deletekey(qp, rootkey, 1, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_RUN_TEST_IMPL(partialmatch) {
	dns_qp_t *qp = NULL;
	int i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);

	/*
	 * Fixed size strings [16] should ensure leaf-compatible alignment.
	 */
	const char insert[][16] = {
		"a.b.",	     "b.",	     "fo.bar.", "foo.bar.",
		"fooo.bar.", "web.foo.bar.", ".",	"",
	};

	/*
	 * omit the root node for now, otherwise we'll get "partial match"
	 * results when we want "not found".
	 */
	while (insert[i][0] != '.') {
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_partialmatch check1[] = {
		{ "a.b.", ISC_R_SUCCESS, "a.b." },
		{ "b.c.", ISC_R_NOTFOUND, NULL },
		{ "bar.", ISC_R_NOTFOUND, NULL },
		{ "f.bar.", ISC_R_NOTFOUND, NULL },
		{ "foo.bar.", ISC_R_SUCCESS, "foo.bar." },
		{ "foooo.bar.", ISC_R_NOTFOUND, NULL },
		{ "w.foo.bar.", DNS_R_PARTIALMATCH, "foo.bar." },
		{ "www.foo.bar.", DNS_R_PARTIALMATCH, "foo.bar." },
		{ "web.foo.bar.", ISC_R_SUCCESS, "web.foo.bar." },
		{ "webby.foo.bar.", DNS_R_PARTIALMATCH, "foo.bar." },
		{ "my.web.foo.bar.", DNS_R_PARTIALMATCH, "web.foo.bar." },
		{ "my.other.foo.bar.", DNS_R_PARTIALMATCH, "foo.bar." },
		{ NULL, 0, NULL },
	};
	check_partialmatch(qp, check1, DNS_DBNAMESPACE_NORMAL);
	check_partialmatch(qp, check1, DNS_DBNAMESPACE_NSEC);
	check_partialmatch(qp, check1, DNS_DBNAMESPACE_NSEC3);

	/* what if the trie contains the root? */
	INSIST(insert[i][0] == '.');
	insert_name(qp, insert[i], DNS_DBNAMESPACE_NORMAL);
	insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC);
	insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC3);
	i++;

	static struct check_partialmatch check2[] = {
		{ "b.c.", DNS_R_PARTIALMATCH, "." },
		{ "bar.", DNS_R_PARTIALMATCH, "." },
		{ "foo.bar.", ISC_R_SUCCESS, "foo.bar." },
		{ "bar", ISC_R_NOTFOUND, NULL },
		{ NULL, 0, NULL },
	};
	check_partialmatch(qp, check2, DNS_DBNAMESPACE_NORMAL);
	check_partialmatch(qp, check2, DNS_DBNAMESPACE_NSEC);
	check_partialmatch(qp, check2, DNS_DBNAMESPACE_NSEC3);

	/*
	 * what if entries in the trie are relative to the zone apex
	 * and there's no root node?
	 */
	delete_rootkey(qp, DNS_DBNAMESPACE_NORMAL);
	delete_rootkey(qp, DNS_DBNAMESPACE_NSEC);
	delete_rootkey(qp, DNS_DBNAMESPACE_NSEC3);

	static struct check_partialmatch check3[] = {
		{ "bar", ISC_R_NOTFOUND, NULL },
		{ "bar.", ISC_R_NOTFOUND, NULL },
		{ NULL, 0, NULL },
	};
	check_partialmatch(qp, check3, DNS_DBNAMESPACE_NORMAL);
	check_partialmatch(qp, check3, DNS_DBNAMESPACE_NSEC);
	check_partialmatch(qp, check3, DNS_DBNAMESPACE_NSEC3);

	dns_qp_destroy(&qp);
}

struct check_qpchain {
	const char *query;
	dns_namespace_t space;
	isc_result_t result;
	unsigned int length;
	const char *names[10];
};

static void
check_qpchainiter(dns_qp_t *qp, struct check_qpchain check[],
		  dns_qpiter_t *iter) {
	for (int i = 0; check[i].query != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_qpchain_t chain;

		dns_qpchain_init(qp, &chain);
		dns_test_namefromstring(check[i].query, &fn1);
		result = dns_qp_lookup(qp, name, check[i].space, NULL, iter,
				       &chain, NULL, NULL);
#if 0
		fprintf(stderr,
			"%s %s (expected %s), "
			"len %d (expected %d)\n",
			check[i].query, isc_result_totext(result),
			isc_result_totext(check[i].result),
			dns_qpchain_length(&chain), check[i].length);
#endif

		assert_int_equal(result, check[i].result);
		assert_int_equal(dns_qpchain_length(&chain), check[i].length);
		for (unsigned int j = 0; j < check[i].length; j++) {
			dns_fixedname_t fn2, fn3;
			dns_name_t *expected = dns_fixedname_initname(&fn2);
			dns_name_t *found = dns_fixedname_initname(&fn3);
			dns_test_namefromstring(check[i].names[j], &fn2);
			dns_qpchain_node(&chain, j, found, NULL, NULL);
#if 0
			char nb[DNS_NAME_FORMATSIZE];
			dns_name_format(found, nb, sizeof(nb));
			fprintf(stderr, "got %s, expected %s\n", nb,
				check[i].names[j]);
#endif
			assert_true(dns_name_equal(found, expected));
		}
	}
}

static void
check_qpchain(dns_qp_t *qp, struct check_qpchain check[]) {
	dns_qpiter_t iter;
	dns_qpiter_init(qp, &iter);
	check_qpchainiter(qp, check, NULL);
	check_qpchainiter(qp, check, &iter);
}

ISC_RUN_TEST_IMPL(qpchain) {
	dns_qp_t *qp = NULL;
	const char insert[][16] = { ".",      "a.",	    "b.",
				    "c.b.a.", "e.d.c.b.a.", "c.b.b.",
				    "c.d.",   "a.b.c.d.",   "a.b.c.d.e.",
				    "b.a.",   "x.k.c.d.",   "" };
	int i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);

	while (insert[i][0] != '\0') {
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_qpchain check1[] = {
		{ "b.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  2,
		  { ".", "b." } },
		{ "b.", DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 2, { ".", "b." } },
		{ "b.", DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS, 2, { ".", "b." } },

		{ "b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "a.", "b.a." } },
		{ "b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "a.", "b.a." } },
		{ "b.a.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "a.", "b.a." } },

		{ "c.", DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 1, { "." } },
		{ "c.", DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 1, { "." } },
		{ "c.", DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 1, { "." } },

		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },

		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },

		{ "b.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },

		{ "z.x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "z.x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "z.x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ NULL, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check1);
	dns_qp_destroy(&qp);

	const char insert2[][16] = { "a.", "d.b.a.", "z.d.b.a.", "" };

	i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);

	while (insert2[i][0] != '\0') {
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_qpchain check2[] = {
		{ "f.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "a." } },
		{ "f.c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "a." } },
		{ "f.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "a." } },
		{ NULL, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check2);
	dns_qp_destroy(&qp);
}

struct check_predecessors {
	const char *query;
	dns_namespace_t space;
	const char *predecessor;
	dns_namespace_t pspace;
	isc_result_t result;
	int remaining;
};

static void
check_predecessors_withchain(dns_qp_t *qp, struct check_predecessors check[],
			     dns_qpchain_t *chain) {
	isc_result_t result;
	dns_fixedname_t fn1, fn2;
	dns_name_t *name = dns_fixedname_initname(&fn1);
	dns_name_t *pred = dns_fixedname_initname(&fn2);
	char *namestr = NULL;
	uint32_t ival;

	for (int i = 0; check[i].query != NULL; i++) {
		dns_qpiter_t it;

		dns_test_namefromstring(check[i].query, &fn1);

		/*
		 * normalize the expected predecessor name, in
		 * case it has escaped characters, so we can compare
		 * apples to apples.
		 */
		dns_fixedname_t fn3;
		dns_name_t *expred = dns_fixedname_initname(&fn3);
		char *predstr = NULL;
		dns_test_namefromstring(check[i].predecessor, &fn3);
		result = dns_name_tostring(expred, &predstr, isc_g_mctx);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_qp_lookup(qp, name, check[i].space, NULL, &it,
				       chain, NULL, NULL);
#if 0
		fprintf(stderr, "%s %s: expected %s got %s\n", check[i].query,
			check[i].space == DNS_DBNAMESPACE_NSEC3
				? "NSEC3"
				: (check[i].space == DNS_DBNAMESPACE_NSEC
					   ? "NSEC"
					   : "NORMAL"),
			isc_result_totext(check[i].result),
			isc_result_totext(result));
#endif
		assert_int_equal(result, check[i].result);

		if (result == ISC_R_SUCCESS) {
			/*
			 * we found an exact match; iterate to find
			 * the predecessor.
			 */
			result = dns_qpiter_prev(&it, pred, NULL, &ival);
			if (result == ISC_R_NOMORE) {
				result = dns_qpiter_prev(&it, pred, NULL,
							 &ival);
			}
		} else {
			/*
			 * we didn't find a match, so the iterator should
			 * already be pointed at the predecessor node.
			 */
			result = dns_qpiter_current(&it, pred, NULL, &ival);
		}
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_name_tostring(pred, &namestr, isc_g_mctx);
#if 0
		fprintf(stderr, "... expected predecessor %s %u got %s %u\n",
			predstr, check[i].pspace, namestr, ival);
#endif
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_string_equal(namestr, predstr);
		assert_int_equal(ival, check[i].pspace);

#if 0
		fprintf(stderr, "%d: remaining names after %s:\n", i, namestr);
#endif
		isc_mem_free(isc_g_mctx, namestr);
		isc_mem_free(isc_g_mctx, predstr);

		int j = 0;
		while (dns_qpiter_next(&it, name, NULL, NULL) == ISC_R_SUCCESS)
		{
#if 0
			result = dns_name_tostring(name, &namestr, isc_g_mctx);
			assert_int_equal(result, ISC_R_SUCCESS);
			fprintf(stderr, "%s%s", j > 0 ? "->" : "", namestr);
			isc_mem_free(isc_g_mctx, namestr);
#endif
			j++;
		}

#if 0
		fprintf(stderr, "\n...expected %d got %d\n", check[i].remaining,
			j);
#endif

		assert_int_equal(j, check[i].remaining);
	}
}

static void
check_predecessors(dns_qp_t *qp, struct check_predecessors check[]) {
	dns_qpchain_t chain;
	dns_qpchain_init(qp, &chain);
	check_predecessors_withchain(qp, check, NULL);
	check_predecessors_withchain(qp, check, &chain);
}

ISC_RUN_TEST_IMPL(predecessors) {
	dns_qp_t *qp = NULL;
	const char insert[][16] = {
		"a.",	  "b.",	      "c.b.a.",	  "e.d.c.b.a.",
		"c.b.b.", "c.d.",     "a.b.c.d.", "a.b.c.d.e.",
		"b.a.",	  "x.k.c.d.", "moog.",	  "mooker.",
		"mooko.", "moon.",    "moops.",	  ""
	};
	int i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);
	while (insert[i][0] != '\0') {
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	/* first check: no root label in the database */
	static struct check_predecessors check1[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, "moops.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ ".", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND, 30 },
		{ ".", DNS_DBNAMESPACE_NSEC3, "moops.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 15 },

		{ "a.", DNS_DBNAMESPACE_NORMAL, "moops.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 0 },
		{ "a.", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 30 },
		{ "a.", DNS_DBNAMESPACE_NSEC3, "moops.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 15 },

		{ "b.a.", DNS_DBNAMESPACE_NORMAL, "a.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 44 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC, "a.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 29 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, "a.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 14 },

		{ "b.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 41 },
		{ "b.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 26 },
		{ "b.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS, 11 },

		{ "aaa.a.", DNS_DBNAMESPACE_NORMAL, "a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 44 },
		{ "aaa.a.", DNS_DBNAMESPACE_NSEC, "a.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 29 },
		{ "aaa.a.", DNS_DBNAMESPACE_NSEC3, "a.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "ddd.a.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 41 },
		{ "ddd.a.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 26 },
		{ "ddd.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 11 },

		{ "d.c.", DNS_DBNAMESPACE_NORMAL, "c.b.b.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 39 },
		{ "d.c.", DNS_DBNAMESPACE_NSEC, "c.b.b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 24 },
		{ "d.c.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 9 },

		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 42 },
		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NSEC, "c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 27 },
		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NSEC3, "c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 12 },

		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "z.y.x.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "z.y.x.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "z.y.x.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "w.c.d.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 36 },
		{ "w.c.d.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "w.c.d.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 36 },
		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "w.k.c.d.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "w.k.c.d.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 22 },
		{ "w.k.c.d.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 7 },

		{ "d.a.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 41 },
		{ "d.a.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 26 },
		{ "d.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 11 },

		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 36 },
		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 21 },
		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 6 },

		{ "b.d.", DNS_DBNAMESPACE_NORMAL, "c.b.b.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 39 },
		{ "b.d.", DNS_DBNAMESPACE_NSEC, "c.b.b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 24 },
		{ "b.d.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 9 },

		{ "mon.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "mon.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "mon.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "moor.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "moor.", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 15 },
		{ "moor.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "mopbop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "mopbop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "mopbop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "moppop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "moppop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "moppop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "mopps.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "mopps.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "mopps.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "mopzop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "mopzop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "mopzop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "mop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "mop.", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 15 },
		{ "mop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "monbop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monbop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monbop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "monpop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monpop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monpop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "monps.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monps.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monps.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "monzop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monzop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monzop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "mon.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "mon.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "mon.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "moop.", DNS_DBNAMESPACE_NORMAL, "moon.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 31 },
		{ "moop.", DNS_DBNAMESPACE_NSEC, "moon.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 16 },
		{ "moop.", DNS_DBNAMESPACE_NSEC3, "moon.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 1 },

		{ "moopser.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 30 },
		{ "moopser.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 15 },
		{ "moopser.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ "monky.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monky.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monky.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "monkey.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monkey.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monkey.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ "monker.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "monker.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 20 },
		{ "monker.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 5 },

		{ NULL, 0, NULL, 0, 0, 0 }
	};

	check_predecessors(qp, check1);

	/* second check: add a root label and try again */
	const char root[16] = ".";
	insert_name(qp, root, DNS_DBNAMESPACE_NORMAL);
	insert_name(qp, root, DNS_DBNAMESPACE_NSEC);
	insert_name(qp, root, DNS_DBNAMESPACE_NSEC3);
	i++;

	static struct check_predecessors check2[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, "moops.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 0 },
		{ ".", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 32 },
		{ ".", DNS_DBNAMESPACE_NSEC3, "moops.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 16 },

		{ "a.", DNS_DBNAMESPACE_NORMAL, ".", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 47 },
		{ "a.", DNS_DBNAMESPACE_NSEC, ".", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 31 },
		{ "a.", DNS_DBNAMESPACE_NSEC3, ".", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 15 },

		{ "b.a.", DNS_DBNAMESPACE_NORMAL, "a.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 46 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC, "a.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 30 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, "a.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 14 },

		{ "b.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 43 },
		{ "b.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 27 },
		{ "b.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS, 11 },

		{ "aaa.a.", DNS_DBNAMESPACE_NORMAL, "a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 46 },
		{ "aaa.a.", DNS_DBNAMESPACE_NSEC, "a.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 30 },
		{ "aaa.a.", DNS_DBNAMESPACE_NSEC3, "a.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "ddd.a.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 43 },
		{ "ddd.a.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 27 },
		{ "ddd.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 11 },

		{ "d.c.", DNS_DBNAMESPACE_NORMAL, "c.b.b.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 41 },
		{ "d.c.", DNS_DBNAMESPACE_NSEC, "c.b.b.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 25 },
		{ "d.c.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 9 },

		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 44 },
		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NSEC, "c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 28 },
		{ "1.2.c.b.a.", DNS_DBNAMESPACE_NSEC3, "c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 12 },

		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "a.b.c.e.f.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "z.y.x.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "z.y.x.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "z.y.x.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "w.c.d.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 38 },
		{ "w.c.d.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 22 },
		{ "w.c.d.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 38 },
		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 22 },
		{ "z.z.z.z.k.c.d.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "w.k.c.d.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 39 },
		{ "w.k.c.d.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 23 },
		{ "w.k.c.d.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 7 },

		{ "d.a.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 43 },
		{ "d.a.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 27 },
		{ "d.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 11 },

		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NORMAL, "x.k.c.d.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 38 },
		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NSEC, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 22 },
		{ "0.b.c.d.e.", DNS_DBNAMESPACE_NSEC3, "x.k.c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "b.d.", DNS_DBNAMESPACE_NORMAL, "c.b.b.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 41 },
		{ "b.d.", DNS_DBNAMESPACE_NSEC, "c.b.b.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 25 },
		{ "b.d.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 9 },

		{ "mon.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "mon.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "mon.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "moor.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "moor.", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 16 },
		{ "moor.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "mopbop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "mopbop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "mopbop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "moppop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "moppop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "moppop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "mopps.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "mopps.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "mopps.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "mopzop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "mopzop.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "mopzop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "mop.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "mop.", DNS_DBNAMESPACE_NSEC, "moops.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 16 },
		{ "mop.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "monbop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monbop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monbop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "monpop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monpop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monpop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "monps.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monps.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monps.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "monzop.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monzop.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monzop.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "mon.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "mon.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "mon.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "moop.", DNS_DBNAMESPACE_NORMAL, "moon.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 33 },
		{ "moop.", DNS_DBNAMESPACE_NSEC, "moon.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 17 },
		{ "moop.", DNS_DBNAMESPACE_NSEC3, "moon.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 1 },

		{ "moopser.", DNS_DBNAMESPACE_NORMAL, "moops.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 32 },
		{ "moopser.", DNS_DBNAMESPACE_NSEC, "moops.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 16 },
		{ "moopser.", DNS_DBNAMESPACE_NSEC3, "moops.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "monky.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monky.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monky.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "monkey.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monkey.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monkey.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "monker.", DNS_DBNAMESPACE_NORMAL, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 37 },
		{ "monker.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 21 },
		{ "monker.", DNS_DBNAMESPACE_NSEC3, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ NULL, 0, NULL, 0, 0, 0 }
	};

	check_predecessors(qp, check2);

	dns_qp_destroy(&qp);
}

/*
 * this is a regression test for an infinite loop that could
 * previously occur in fix_iterator()
 */
ISC_RUN_TEST_IMPL(fixiterator) {
	dns_qp_t *qp = NULL;
	const char insert1[][32] = { "dynamic.",
				     "a.dynamic.",
				     "aaaa.dynamic.",
				     "cdnskey.dynamic.",
				     "cds.dynamic.",
				     "cname.dynamic.",
				     "dname.dynamic.",
				     "dnskey.dynamic.",
				     "ds.dynamic.",
				     "mx.dynamic.",
				     "ns.dynamic.",
				     "nsec.dynamic.",
				     "private-cdnskey.dynamic.",
				     "private-dnskey.dynamic.",
				     "rrsig.dynamic.",
				     "txt.dynamic.",
				     "trailing.",
				     "" };
	int i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);
	while (insert1[i][0] != '\0') {
		insert_name(qp, insert1[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert1[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert1[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_predecessors check1[] = {
		{ "newtext.dynamic.", DNS_DBNAMESPACE_NORMAL, "mx.dynamic.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 41 },
		{ "newtext.dynamic.", DNS_DBNAMESPACE_NSEC, "mx.dynamic.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 24 },
		{ "newtext.dynamic.", DNS_DBNAMESPACE_NSEC3, "mx.dynamic.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 7 },

		{ "nsd.dynamic.", DNS_DBNAMESPACE_NORMAL, "ns.dynamic.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 40 },
		{ "nsd.dynamic.", DNS_DBNAMESPACE_NSEC, "ns.dynamic.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 23 },
		{ "nsd.dynamic.", DNS_DBNAMESPACE_NSEC3, "ns.dynamic.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "nsf.dynamic.", DNS_DBNAMESPACE_NORMAL, "nsec.dynamic.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 39 },
		{ "nsf.dynamic.", DNS_DBNAMESPACE_NSEC, "nsec.dynamic.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 22 },
		{ "nsf.dynamic.", DNS_DBNAMESPACE_NSEC3, "nsec.dynamic.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 5 },

		{ "d.", DNS_DBNAMESPACE_NORMAL, "trailing.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },
		{ "d.", DNS_DBNAMESPACE_NSEC, "trailing.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 34 },
		{ "d.", DNS_DBNAMESPACE_NSEC3, "trailing.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 17 },

		{ "absent.", DNS_DBNAMESPACE_NORMAL, "trailing.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },
		{ "absent.", DNS_DBNAMESPACE_NSEC, "trailing.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 34 },
		{ "absent.", DNS_DBNAMESPACE_NSEC3, "trailing.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 17 },

		{ "nonexistent.", DNS_DBNAMESPACE_NORMAL, "txt.dynamic.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 35 },
		{ "nonexistent.", DNS_DBNAMESPACE_NSEC, "txt.dynamic.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 18 },
		{ "nonexistent.", DNS_DBNAMESPACE_NSEC3, "txt.dynamic.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 1 },

		{ "wayback.", DNS_DBNAMESPACE_NORMAL, "trailing.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 34 },
		{ "wayback.", DNS_DBNAMESPACE_NSEC, "trailing.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 17 },
		{ "wayback.", DNS_DBNAMESPACE_NSEC3, "trailing.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0 },

		{ NULL, 0, NULL, 0, 0, 0 }
	};

	check_predecessors(qp, check1);
	dns_qp_destroy(&qp);

	const char insert2[][64] = { ".", "abb.", "abc.", "" };
	i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);
	while (insert2[i][0] != '\0') {
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert2[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_predecessors check2[] = {
		{ "acb.", DNS_DBNAMESPACE_NORMAL, "abc.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 6 },
		{ "acb.", DNS_DBNAMESPACE_NSEC, "abc.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 3 },
		{ "acb.", DNS_DBNAMESPACE_NSEC3, "abc.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "acc.", DNS_DBNAMESPACE_NORMAL, "abc.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 6 },
		{ "acc.", DNS_DBNAMESPACE_NSEC, "abc.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 3 },
		{ "acc.", DNS_DBNAMESPACE_NSEC3, "abc.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "abbb.", DNS_DBNAMESPACE_NORMAL, "abb.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 7 },
		{ "abbb.", DNS_DBNAMESPACE_NSEC, "abb.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 4 },
		{ "abbb.", DNS_DBNAMESPACE_NSEC3, "abb.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 1 },

		{ "aab.", DNS_DBNAMESPACE_NORMAL, ".", DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH, 8 },
		{ "aab.", DNS_DBNAMESPACE_NSEC, ".", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 5 },
		{ "aab.", DNS_DBNAMESPACE_NSEC3, ".", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 2 },

		{ NULL, 0, NULL, 0, 0, 0 }
	};

	check_predecessors(qp, check2);
	dns_qp_destroy(&qp);

	const char insert3[][64] = { "example.",
				     "key-is-13779.example.",
				     "key-is-14779.example.",
				     "key-not-13779.example.",
				     "key-not-14779.example.",
				     "" };
	i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);
	while (insert3[i][0] != '\0') {
		insert_name(qp, insert3[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert3[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert3[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_predecessors check3[] = {
		{ "key-is-21556.example.", DNS_DBNAMESPACE_NORMAL,
		  "key-is-14779.example.", DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH, 12 },
		{ "key-is-21556.example.", DNS_DBNAMESPACE_NSEC,
		  "key-is-14779.example.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 7 },
		{ "key-is-21556.example.", DNS_DBNAMESPACE_NSEC3,
		  "key-is-14779.example.", DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH, 2 },
		{ NULL, 0, NULL, 0, 0, 0 }
	};

	check_predecessors(qp, check3);
	dns_qp_destroy(&qp);

	const char insert4[][64] = { ".", "\\000.", "\\000.\\000.",
				     "\\000\\009.", "" };
	i = 0;

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);
	while (insert4[i][0] != '\0') {
		insert_name(qp, insert4[i], DNS_DBNAMESPACE_NORMAL);
		insert_name(qp, insert4[i], DNS_DBNAMESPACE_NSEC);
		insert_name(qp, insert4[i], DNS_DBNAMESPACE_NSEC3);
		i++;
	}

	static struct check_predecessors check4[] = {
		{ "\\007.", DNS_DBNAMESPACE_NORMAL, "\\000\\009.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 8 },
		{ "\\007.", DNS_DBNAMESPACE_NSEC, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 4 },
		{ "\\007.", DNS_DBNAMESPACE_NSEC3, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "\\009.", DNS_DBNAMESPACE_NORMAL, "\\000\\009.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 8 },
		{ "\\009.", DNS_DBNAMESPACE_NSEC, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 4 },
		{ "\\009.", DNS_DBNAMESPACE_NSEC3, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "\\045.", DNS_DBNAMESPACE_NORMAL, "\\000\\009.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 8 },
		{ "\\045.", DNS_DBNAMESPACE_NSEC, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 4 },
		{ "\\045.", DNS_DBNAMESPACE_NSEC3, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "\\044.", DNS_DBNAMESPACE_NORMAL, "\\000\\009.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 8 },
		{ "\\044.", DNS_DBNAMESPACE_NSEC, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC, DNS_R_PARTIALMATCH, 4 },
		{ "\\044.", DNS_DBNAMESPACE_NSEC3, "\\000\\009.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "\\000.", DNS_DBNAMESPACE_NORMAL, ".", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 11 },
		{ "\\000.", DNS_DBNAMESPACE_NSEC, ".", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 7 },
		{ "\\000.", DNS_DBNAMESPACE_NSEC3, ".", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 3 },

		{ NULL, 0, NULL, 0, 0, 0 },
	};

	check_predecessors(qp, check4);
	dns_qp_destroy(&qp);
}

struct inserting {
	/* Fixed size strings [32] should ensure leaf-compatible alignment. */
	const char name[32];
	dns_namespace_t space;
	/* Padding */
	uint8_t pad1;
	uint16_t pad2;
};

struct check_delete {
	const char *name;
	dns_namespace_t space;
	isc_result_t result;
};

static void
check_delete(dns_qp_t *qp, struct check_delete check[]) {
	for (int i = 0; check[i].name != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_qpchain_t chain;

		dns_qpchain_init(qp, &chain);
		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_deletename(qp, name, check[i].space, NULL,
					   NULL);
#if 0
		fprintf(stderr, "%s %u %s (expected %s)\n", check[i].name,
			check[i].space, isc_result_totext(result),
			isc_result_totext(check[i].result));
#endif
		assert_int_equal(result, check[i].result);
	}
}

ISC_RUN_TEST_IMPL(qpkey_delete) {
	int i = 0;
	dns_qp_t *qp = NULL;
	static struct inserting insert1[] = {
		{ "a.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "b.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "b.", DNS_DBNAMESPACE_NSEC, 0, 0 },
		{ "b.", DNS_DBNAMESPACE_NSEC3, 0, 0 },
		{ "b.a.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC, 0, 0 },
		{ "c.b.a.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NSEC, 0, 0 },
		{ "c.b.b.", DNS_DBNAMESPACE_NSEC3, 0, 0 },
		{ "c.d.", DNS_DBNAMESPACE_NSEC3, 0, 0 },
		{ "a.b.c.d.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "a.b.c.d.e.", DNS_DBNAMESPACE_NORMAL, 0, 0 },
		{ "", 0, 0, 0 },
	};
	/*
	 * NORMAL:         a.
	 * NORMAL:       b.a.
	 * NORMAL:     c.b.a.
	 * NORMAL: e.d.c.b.a.
	 * NORMAL:         b.
	 * NORMAL:   a.b.c.d.
	 * NORMAL: a.b.c.d.e.
	 *
	 * NSEC:         b.a.
	 * NSEC:   e.d.c.b.a.
	 * NSEC:           b.
	 *
	 * NSEC3:          b.
	 * NSEC3:      c.b.b.
	 * NSEC3:        c.d.
	 */

	dns_qp_create(isc_g_mctx, &string_methods, NULL, &qp);

	while (insert1[i].name[0] != '\0') {
		insert_name(qp, insert1[i].name, insert1[i].space);
		i++;
	}

	/* lookup checks before deleting */
	static struct check_qpchain chain1[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 1, { "a." } },
		{ "a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } }, /* b.a.
			       */
		{ "a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 1, { "b." } },
		{ "b.", DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 1, { "b." } },
		{ "b.", DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS, 1, { "b." } },

		{ "b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  2,
		  { "a.", "b.a." } },
		{ "b.a.", DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 1, { "b.a." } },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { "a.", "b.a.", "c.b.a." } },
		{ "c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "b.a." } },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  4,
		  { "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS,
		  2,
		  { "b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },

		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  1,
		  { "a.b.c.d." } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "c.d." } },

		{ "b.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } }, /* a.b.c.d. */
		{ "b.c.d.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "c.d." } },

		{ "f.b.b.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },
		{ "f.b.b.d.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },
		{ "f.b.b.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },

		{ NULL, 0, 0, 0, { NULL } },
	};
	check_qpchain(qp, chain1);

	static struct check_predecessors pred1[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, "c.d.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ ".", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ ".", DNS_DBNAMESPACE_NSEC3, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },

		{ "a.", DNS_DBNAMESPACE_NORMAL, "c.d.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_SUCCESS, 0 },
		{ "a.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ "a.", DNS_DBNAMESPACE_NSEC3, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },

		{ "b.", DNS_DBNAMESPACE_NORMAL, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 9 },
		{ "b.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 4 },
		{ "b.", DNS_DBNAMESPACE_NSEC3, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS, 3 },

		{ "b.a.", DNS_DBNAMESPACE_NORMAL, "a.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS, 12 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 6 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },

		{ "c.b.a.", DNS_DBNAMESPACE_NORMAL, "b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 11 },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC, "b.a.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 5 },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC3, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },

		{ "c.", DNS_DBNAMESPACE_NORMAL, "b.", DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND, 8 },
		{ "c.", DNS_DBNAMESPACE_NSEC, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },
		{ "c.", DNS_DBNAMESPACE_NSEC3, "c.b.b.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 1 },

		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 10 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NSEC, "b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 5 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NSEC3, "b.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 3 },

		{ "a.b.c.d.", DNS_DBNAMESPACE_NORMAL, "b.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 8 },
		{ "a.b.c.d.", DNS_DBNAMESPACE_NSEC, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },
		{ "a.b.c.d.", DNS_DBNAMESPACE_NSEC3, "c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "b.c.d.", DNS_DBNAMESPACE_NORMAL, "b.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 8 },
		{ "b.c.d.", DNS_DBNAMESPACE_NSEC, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },
		{ "b.c.d.", DNS_DBNAMESPACE_NSEC3, "c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "f.b.b.d.", DNS_DBNAMESPACE_NORMAL, "b.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 8 },
		{ "f.b.b.d.", DNS_DBNAMESPACE_NSEC, "b.", DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND, 3 },
		{ "f.b.b.d.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 1 },

		{ NULL, 0, NULL, 0, 0, 0 },
	};
	check_predecessors(qp, pred1);

	/* delete checks */
	static struct check_delete del1[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ "a.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND },
		{ "a.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS },
		{ "b.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS },
		{ "b.", DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS },
		{ "b.", DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS },
		{ NULL, 0, 0 },
	};
	check_delete(qp, del1);

	/* again */
	static struct check_delete del2[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ "a.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND },
		{ "a.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ "b.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ "b.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND },
		{ "b.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND },
		{ NULL, 0, 0 },
	};
	check_delete(qp, del2);

	/* lookup checks after deleting */
	static struct check_qpchain chain2[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } }, /* c.b.a.
			       */
		{ "a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } }, /* b.a.
			       */
		{ "a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.", DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } }, /* c.b.a. */
		{ "b.a.", DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 1, { "b.a." } },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  1,
		  { "c.b.a." } },
		{ "c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "b.a." } },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NORMAL,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_SUCCESS,
		  2,
		  { "b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },

		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NORMAL,
		  ISC_R_SUCCESS,
		  1,
		  { "a.b.c.d." } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC,
		  ISC_R_NOTFOUND,
		  0,
		  { NULL } },
		{ "a.b.c.d.",
		  DNS_DBNAMESPACE_NSEC3,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "c.d." } },

		{ NULL, 0, 0, 0, { NULL } },
	};
	check_qpchain(qp, chain2);

	static struct check_predecessors pred2[] = {
		{ ".", DNS_DBNAMESPACE_NORMAL, "c.d.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ ".", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 4 },
		{ ".", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },

		{ "a.", DNS_DBNAMESPACE_NORMAL, "c.d.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ "a.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 4 },
		{ "a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },

		{ "b.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ "b.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },
		{ "b.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 }, /* c.b.b. */

		{ "b.a.", DNS_DBNAMESPACE_NORMAL, "c.d.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 0 }, /* c.b.a. */
		{ "b.a.", DNS_DBNAMESPACE_NSEC, "a.b.c.d.e.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 4 },
		{ "b.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },

		{ "c.b.a.", DNS_DBNAMESPACE_NORMAL, "c.d.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_SUCCESS, 0 },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC, "b.a.", DNS_DBNAMESPACE_NSEC,
		  DNS_R_PARTIALMATCH, 3 },
		{ "c.b.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },

		{ "c.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ "c.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },
		{ "c.", DNS_DBNAMESPACE_NSEC3, "c.b.b.", DNS_DBNAMESPACE_NSEC3,
		  ISC_R_NOTFOUND, 1 },

		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, DNS_R_PARTIALMATCH, 6 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NSEC, "b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_SUCCESS, 3 },
		{ "e.d.c.b.a.", DNS_DBNAMESPACE_NSEC3, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },

		{ "a.b.c.d.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_SUCCESS, 6 },
		{ "a.b.c.d.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },
		{ "a.b.c.d.", DNS_DBNAMESPACE_NSEC3, "c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "b.c.d.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ "b.c.d.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },
		{ "b.c.d.", DNS_DBNAMESPACE_NSEC3, "c.d.",
		  DNS_DBNAMESPACE_NSEC3, DNS_R_PARTIALMATCH, 0 },

		{ "f.b.b.d.", DNS_DBNAMESPACE_NORMAL, "c.b.a.",
		  DNS_DBNAMESPACE_NORMAL, ISC_R_NOTFOUND, 6 },
		{ "f.b.b.d.", DNS_DBNAMESPACE_NSEC, "e.d.c.b.a.",
		  DNS_DBNAMESPACE_NSEC, ISC_R_NOTFOUND, 2 },
		{ "f.b.b.d.", DNS_DBNAMESPACE_NSEC3, "c.b.b.",
		  DNS_DBNAMESPACE_NSEC3, ISC_R_NOTFOUND, 1 },

		{ NULL, 0, NULL, 0, 0, 0 },
	};
	check_predecessors(qp, pred2);

	dns_qp_destroy(&qp);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_name)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_ENTRY(qpiter)
ISC_TEST_ENTRY(partialmatch)
ISC_TEST_ENTRY(qpchain)
ISC_TEST_ENTRY(predecessors)
ISC_TEST_ENTRY(fixiterator)
ISC_TEST_ENTRY(qpkey_delete)
ISC_TEST_LIST_END

ISC_TEST_MAIN
