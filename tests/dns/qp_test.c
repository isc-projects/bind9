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

#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/qp.h>

#include "qp_p.h"

#include <tests/dns.h>
#include <tests/qp.h>

ISC_RUN_TEST_IMPL(qpkey_name) {
	struct {
		const char *namestr;
		uint8_t key[512];
		size_t len;
	} testcases[] = {
		{
			.namestr = ".",
			.key = { 0x02, 0x02 },
			.len = 1,
		},
		{
			.namestr = "\\000",
			.key = { 0x03, 0x03, 0x02, 0x02 },
			.len = 3,
		},
		{
			.namestr = "example.com.",
			.key = { 0x02, 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b, 0x14,
				 0x20, 0x23, 0x1f, 0x18, 0x02, 0x02 },
			.len = 13,
		},
		{
			.namestr = "example.com",
			.key = { 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b, 0x14, 0x20,
				 0x23, 0x1f, 0x18, 0x02, 0x02 },
			.len = 12,
		},
		{
			.namestr = "EXAMPLE.COM",
			.key = { 0x16, 0x22, 0x20, 0x02, 0x18, 0x2b, 0x14, 0x20,
				 0x23, 0x1f, 0x18, 0x02, 0x02 },
			.len = 12,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		size_t len;
		dns_qpkey_t key;
		dns_fixedname_t fn1, fn2;
		dns_name_t *in = NULL, *out = NULL;

		dns_test_namefromstring(testcases[i].namestr, &fn1);
		in = dns_fixedname_name(&fn1);
		len = dns_qpkey_fromname(key, in);

		assert_int_equal(testcases[i].len, len);
		assert_memory_equal(testcases[i].key, key, len);

		out = dns_fixedname_initname(&fn2);
		qp_test_keytoname(key, len, out);
		assert_true(dns_name_equal(in, out));
	}
}

ISC_RUN_TEST_IMPL(qpkey_sort) {
	struct {
		const char *namestr;
		dns_name_t *name;
		dns_fixedname_t fixed;
		size_t len;
		dns_qpkey_t key;
	} testcases[] = {
		{ .namestr = "." },
		{ .namestr = "\\000." },
		{ .namestr = "example.com." },
		{ .namestr = "EXAMPLE.COM." },
		{ .namestr = "www.example.com." },
		{ .namestr = "exam.com." },
		{ .namestr = "exams.com." },
		{ .namestr = "exam\\000.com." },
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_test_namefromstring(testcases[i].namestr,
					&testcases[i].fixed);
		testcases[i].name = dns_fixedname_name(&testcases[i].fixed);
		testcases[i].len = dns_qpkey_fromname(testcases[i].key,
						      testcases[i].name);
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
			assert_true((namecmp < 0) == (keycmp < 0));
			assert_true((namecmp == 0) == (keycmp == 0));
			assert_true((namecmp > 0) == (keycmp > 0));
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

	return (i);
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

	dns_qp_create(mctx, &qpiter_methods, item, &qp);
	for (size_t tests = 0; tests < 1234; tests++) {
		uint32_t ival = isc_random_uniform(ITER_ITEMS - 1) + 1;
		void *pval = &item[ival];
		item[ival] = ival;

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
		dns_qpiter_t qpi;
		dns_qpiter_init(qp, &qpi);
		while (dns_qpiter_next(&qpi, &pval, &ival) == ISC_R_SUCCESS) {
			assert_in_range(ival, prev + 1, ITER_ITEMS - 1);
			assert_int_equal(ival, item[ival]);
			assert_ptr_equal(pval, &item[ival]);
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

	UNUSED(uctx);
	UNUSED(ival);
	if (*(char *)pval == '\0') {
		return (0);
	}
	dns_test_namefromstring(pval, &fixed);
	return (dns_qpkey_fromname(key, dns_fixedname_name(&fixed)));
}

const dns_qpmethods_t string_methods = {
	no_op,
	no_op,
	qpkey_fromstring,
	getname,
};

struct check_partialmatch {
	const char *query;
	dns_qpfind_t options;
	isc_result_t result;
	const char *found;
};

static void
check_partialmatch(dns_qp_t *qp, struct check_partialmatch check[]) {
	for (int i = 0; check[i].query != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fixed;
		dns_name_t *name = dns_fixedname_name(&fixed);
		void *pval = NULL;

#if 0
		fprintf(stderr, "%s %u %s %s\n", check[i].query,
			check[i].options, isc_result_totext(check[i].result),
			check[i].found);
#endif
		dns_test_namefromstring(check[i].query, &fixed);
		result = dns_qp_findname_ancestor(qp, name, check[i].options,
						  &pval, NULL);
		assert_int_equal(result, check[i].result);
		if (check[i].found == NULL) {
			assert_null(pval);
		} else {
			assert_string_equal(pval, check[i].found);
		}
	}
}

static void
insert_str(dns_qp_t *qp, const char *str) {
	isc_result_t result;
	uintptr_t pval = (uintptr_t)str;
	INSIST((pval & 3) == 0);
	result = dns_qp_insert(qp, (void *)pval, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_RUN_TEST_IMPL(partialmatch) {
	isc_result_t result;
	dns_qp_t *qp = NULL;

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	/*
	 * Fixed size strings [16] should ensure leaf-compatible alignment.
	 */
	const char insert[][16] = {
		"a.b.",	     "b.",	     "fo.bar.", "foo.bar.",
		"fooo.bar.", "web.foo.bar.", ".",	"",
	};

	int i = 0;
	while (insert[i][0] != '.') {
		insert_str(qp, insert[i++]);
	}

	static struct check_partialmatch check1[] = {
		{ "a.b.", 0, ISC_R_SUCCESS, "a.b." },
		{ "a.b.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH, "b." },
		{ "b.c.", DNS_QPFIND_NOEXACT, ISC_R_NOTFOUND, NULL },
		{ "bar.", 0, ISC_R_NOTFOUND, NULL },
		{ "f.bar.", 0, ISC_R_NOTFOUND, NULL },
		{ "foo.bar.", 0, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", DNS_QPFIND_NOEXACT, ISC_R_NOTFOUND, NULL },
		{ "foooo.bar.", 0, ISC_R_NOTFOUND, NULL },
		{ "w.foo.bar.", 0, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "www.foo.bar.", 0, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "web.foo.bar.", 0, ISC_R_SUCCESS, "web.foo.bar." },
		{ "webby.foo.bar.", 0, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "my.web.foo.bar.", 0, DNS_R_PARTIALMATCH, "web.foo.bar." },
		{ "web.foo.bar.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH,
		  "foo.bar." },
		{ "my.web.foo.bar.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH,
		  "web.foo.bar." },
		{ "my.other.foo.bar.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH,
		  "foo.bar." },
		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check1);

	/* what if the trie contains the root? */
	INSIST(insert[i][0] == '.');
	insert_str(qp, insert[i++]);

	static struct check_partialmatch check2[] = {
		{ "b.c.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH, "." },
		{ "bar.", 0, DNS_R_PARTIALMATCH, "." },
		{ "foo.bar.", 0, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", DNS_QPFIND_NOEXACT, DNS_R_PARTIALMATCH, "." },
		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check2);

	/* what if entries in the trie are relative to the zone apex? */
	dns_qpkey_t rootkey = { SHIFT_NOBYTE };
	result = dns_qp_deletekey(qp, rootkey, 1, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	INSIST(insert[i][0] == '\0');
	insert_str(qp, insert[i++]);
	check_partialmatch(qp, (struct check_partialmatch[]){
				       { "bar", 0, DNS_R_PARTIALMATCH, "" },
				       { "bar.", 0, DNS_R_PARTIALMATCH, "" },
				       { NULL, 0, 0, NULL },
			       });

	dns_qp_destroy(&qp);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_name)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_ENTRY(qpiter)
ISC_TEST_ENTRY(partialmatch)
ISC_TEST_LIST_END

ISC_TEST_MAIN
