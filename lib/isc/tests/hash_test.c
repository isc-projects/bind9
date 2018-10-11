/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/hex.h>
#include <isc/region.h>

#include <isc/crc64.h>
#include <isc/util.h>
#include <isc/print.h>
#include <isc/string.h>

#include <pk11/site.h>

#define TEST_INPUT(x) (x), sizeof(x)-1

typedef struct hash_testcase {
	const char *input;
	size_t input_len;
	const char *result;
	int repeats;
} hash_testcase_t;

/* CRC64 Test */
ATF_TC(isc_crc64);
ATF_TC_HEAD(isc_crc64, tc) {
	atf_tc_set_md_var(tc, "descr", "64-bit cyclic redundancy check");
}
ATF_TC_BODY(isc_crc64, tc) {
	uint64_t crc;
	int i;

	UNUSED(tc);

	hash_testcase_t testcases[] = {
		{
			TEST_INPUT(""),
			"0000000000000000", 1
		},
		{
			TEST_INPUT("a"),
			"CE73F427ACC0A99A", 1
		},
		{
			TEST_INPUT("abc"),
			"048B813AF9F49702", 1
		},
		{
			TEST_INPUT("message digest"),
			"5273F9EA7A357BF4", 1
		},
		{
			TEST_INPUT("abcdefghijklmnopqrstuvwxyz"),
			"59F079F9218BAAA1", 1
		},
		{
			TEST_INPUT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
				   "nopqrstuvwxyz0123456789"),
			"A36DA8F71E78B6FB", 1
		},
		{
			TEST_INPUT("123456789012345678901234567890123456789"
				   "01234567890123456789012345678901234567890"),
			"81E5EB73C8E7874A", 1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	while (testcase->input != NULL && testcase->result != NULL) {
		char str[17];

		isc_crc64_init(&crc);
		for(i = 0; i < testcase->repeats; i++) {
			isc_crc64_update(&crc,
				       (const uint8_t *) testcase->input,
				       testcase->input_len);
		}
		isc_crc64_final(&crc);
		snprintf(str, sizeof(str),
			 "%016" PRIX64, crc);
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
	}
}

ATF_TC(isc_hash_function);
ATF_TC_HEAD(isc_hash_function, tc) {
	atf_tc_set_md_var(tc, "descr", "Hash function test");
}
ATF_TC_BODY(isc_hash_function, tc) {
	unsigned int h1;
	unsigned int h2;

	UNUSED(tc);

	/* Incremental hashing */

	h1 = isc_hash_function(NULL, 0, true, NULL);
	h1 = isc_hash_function("This ", 5, true, &h1);
	h1 = isc_hash_function("is ", 3, true, &h1);
	h1 = isc_hash_function("a long test", 12, true, &h1);

	h2 = isc_hash_function("This is a long test", 20,
			       true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Immutability of hash function */
	h1 = isc_hash_function(NULL, 0, true, NULL);
	h2 = isc_hash_function(NULL, 0, true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Hash function characteristics */
	h1 = isc_hash_function("Hello world", 12, true, NULL);
	h2 = isc_hash_function("Hello world", 12, true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Case */
	h1 = isc_hash_function("Hello world", 12, false, NULL);
	h2 = isc_hash_function("heLLo WorLd", 12, false, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Unequal */
	h1 = isc_hash_function("Hello world", 12, true, NULL);
	h2 = isc_hash_function("heLLo WorLd", 12, true, NULL);

	ATF_CHECK(h1 != h2);
}

ATF_TC(isc_hash_function_reverse);
ATF_TC_HEAD(isc_hash_function_reverse, tc) {
	atf_tc_set_md_var(tc, "descr", "Reverse hash function test");
}
ATF_TC_BODY(isc_hash_function_reverse, tc) {
	unsigned int h1;
	unsigned int h2;

	UNUSED(tc);

	/* Incremental hashing */

	h1 = isc_hash_function_reverse(NULL, 0, true, NULL);
	h1 = isc_hash_function_reverse("\000", 1, true, &h1);
	h1 = isc_hash_function_reverse("\003org", 4, true, &h1);
	h1 = isc_hash_function_reverse("\007example", 8, true, &h1);

	h2 = isc_hash_function_reverse("\007example\003org\000", 13,
				       true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Immutability of hash function */
	h1 = isc_hash_function_reverse(NULL, 0, true, NULL);
	h2 = isc_hash_function_reverse(NULL, 0, true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Hash function characteristics */
	h1 = isc_hash_function_reverse("Hello world", 12, true, NULL);
	h2 = isc_hash_function_reverse("Hello world", 12, true, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Case */
	h1 = isc_hash_function_reverse("Hello world", 12, false, NULL);
	h2 = isc_hash_function_reverse("heLLo WorLd", 12, false, NULL);

	ATF_CHECK_EQ(h1, h2);

	/* Unequal */
	h1 = isc_hash_function_reverse("Hello world", 12, true, NULL);
	h2 = isc_hash_function_reverse("heLLo WorLd", 12, true, NULL);

	ATF_CHECK(h1 != h2);
}

ATF_TC(isc_hash_initializer);
ATF_TC_HEAD(isc_hash_initializer, tc) {
	atf_tc_set_md_var(tc, "descr", "Hash function initializer test");
}
ATF_TC_BODY(isc_hash_initializer, tc) {
	unsigned int h1;
	unsigned int h2;

	UNUSED(tc);

	h1 = isc_hash_function("Hello world", 12, true, NULL);
	h2 = isc_hash_function("Hello world", 12, true, NULL);

	ATF_CHECK_EQ(h1, h2);

	isc_hash_set_initializer(isc_hash_get_initializer());

	/* Hash value must not change */
	h2 = isc_hash_function("Hello world", 12, true, NULL);

	ATF_CHECK_EQ(h1, h2);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	/*
	 * Tests of hash functions, including isc_hash and the
	 * various cryptographic hashes.
	 */

	ATF_TP_ADD_TC(tp, isc_hash_function);
	ATF_TP_ADD_TC(tp, isc_hash_function_reverse);
	ATF_TP_ADD_TC(tp, isc_hash_initializer);
	ATF_TP_ADD_TC(tp, isc_crc64);

	return (atf_no_error());
}
