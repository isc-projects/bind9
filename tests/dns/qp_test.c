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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/qsbr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
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

static uint32_t
check_leaf(void *uctx, void *pval, uint32_t ival) {
	uint32_t *items = uctx;
	assert_in_range(ival, 1, ITER_ITEMS - 1);
	assert_ptr_equal(items + ival, pval);
	return (1);
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

const struct dns_qpmethods qpiter_methods = {
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
			dns_qp_deletekey(qp, key, len);
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

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_name)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_ENTRY(qpiter)
ISC_TEST_LIST_END

ISC_TEST_MAIN
