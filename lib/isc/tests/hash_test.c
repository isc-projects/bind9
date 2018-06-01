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
#include <isc/hmacmd5.h>
#include <isc/hmacsha.h>
#include <isc/md.h>
#include <isc/util.h>
#include <isc/print.h>
#include <isc/string.h>

#include <pk11/site.h>

/*
 * Test data from RFC6234
 */

unsigned char digest[ISC_MAX_MD_SIZE];
unsigned char buffer[1024];
const char *s;
char str[2 * ISC_MAX_MD_SIZE + 3];
unsigned char key[20];

#define TEST_INPUT(x) (x), sizeof(x)-1

static isc_result_t
tohexstr(unsigned char *in, size_t inlen,
	 char *out, const size_t outlen)
{
	isc_buffer_t b;
	isc_region_t r = { .base = in,
			   .length = inlen };

	isc_buffer_init(&b, out, outlen);
	return (isc_hex_totext(&r, 0, "", &b));
}

typedef struct hash_testcase {
	const char *input;
	size_t input_len;
	const char *result;
	int repeats;
} hash_testcase_t;

typedef struct hash_test_key {
	const char *key;
	const int len;
} hash_test_key_t;

/* HMAC-SHA1 test */
ATF_TC(isc_hmacsha1);
ATF_TC_HEAD(isc_hmacsha1, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-SHA1 examples from RFC2104");
}
ATF_TC_BODY(isc_hmacsha1, tc) {
	isc_hmacsha1_t hmacsha1;

	UNUSED(tc);
	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"B617318655057264E28BC0B6FB378C8EF146BE00",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				   "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				   "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"125D7342B9AC11CD91A39AF48AA17B4F63F175D3",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"4C9007F4026250C6BC8414F9BF50C86C2D7235DA",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
#endif
		/* Test 6 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"AA4AE5E15272D00E95705637CE8A3B55ED402112", 1 },
		/* Test 7 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key and "
				   "Larger Than One Block-Size Data"),
			"E8E99D0F45237D786D6BBAA7965C7808BBFF1A91",
			1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
#endif
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 80 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 80 },
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacsha1_init(&hmacsha1, buffer, test_key->len);
		isc_hmacsha1_update(&hmacsha1,
				    (const uint8_t *) testcase->input,
				    testcase->input_len);
		isc_hmacsha1_sign(&hmacsha1, digest, ISC_SHA1_DIGESTLENGTH);
		tohexstr(digest, ISC_SHA1_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}

/* HMAC-SHA224 test */
ATF_TC(isc_hmacsha224);
ATF_TC_HEAD(isc_hmacsha224, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-SHA224 examples from RFC4634");
}
ATF_TC_BODY(isc_hmacsha224, tc) {
	isc_hmacsha224_t hmacsha224;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"896FB1128ABBDF196832107CD49DF33F47B4B1169912BA"
				"4F53684B22",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				   "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				   "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E61480"
				"08FD05E44",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"7FB3CB3588C6C1F6FFA9694D7D6AD2649365B0C1F65D69"
				"D1EC8333EA",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"6C11506874013CAC6A2ABC1BB382627CEC6A90D86EFC01"
				"2DE7AFEC5A",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
#endif
		/* Test 6 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"95E9A0DB962095ADAEBE9B2D6F0DBCE2D499F112F2D2B7"
				"273FA6870E",
			1
		},
		/* Test 7 */
		{
			TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				   "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				   "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				   "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				   "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				   "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				   "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				   "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				   "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				   "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				   "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				   "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				   "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				   "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				   "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				   "\x6d\x2e"),
			"3A854166AC5D9F023F54D517D0B39DBD946770DB9C2B95"
				"C9F6F565D1",
			1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
#endif
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacsha224_init(&hmacsha224, buffer, test_key->len);
		isc_hmacsha224_update(&hmacsha224,
				      (const uint8_t *) testcase->input,
				      testcase->input_len);
		isc_hmacsha224_sign(&hmacsha224, digest, ISC_SHA224_DIGESTLENGTH);
		tohexstr(digest, ISC_SHA224_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}

/* HMAC-SHA256 test */
ATF_TC(isc_hmacsha256);
ATF_TC_HEAD(isc_hmacsha256, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-SHA256 examples from RFC4634");
}
ATF_TC_BODY(isc_hmacsha256, tc) {
	isc_hmacsha256_t hmacsha256;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833D"
				"A726E9376C2E32CFF7",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				   "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				   "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"5BDCC146BF60754E6A042426089575C75A003F089D2739"
				"839DEC58B964EC3843",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"773EA91E36800E46854DB8EBD09181A72959098B3EF8C1"
				"22D9635514CED565FE",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8"
				"077A2E3FF46729665B",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
#endif
		/* Test 6 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5"
				"140546040F0EE37F54",
			1
		},
		/* Test 7 */
		{
			TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				   "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				   "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				   "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				   "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				   "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				   "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				   "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				   "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				   "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				   "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				   "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				   "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				   "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				   "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				   "\x6d\x2e"),
			"9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713"
				"938A7F51535C3A35E2",
			1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
#endif
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacsha256_init(&hmacsha256, buffer, test_key->len);
		isc_hmacsha256_update(&hmacsha256,
				      (const uint8_t *) testcase->input,
				      testcase->input_len);
		isc_hmacsha256_sign(&hmacsha256, digest, ISC_SHA256_DIGESTLENGTH);
		tohexstr(digest, ISC_SHA256_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}

/* HMAC-SHA384 test */
ATF_TC(isc_hmacsha384);
ATF_TC_HEAD(isc_hmacsha384, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-SHA384 examples from RFC4634");
}
ATF_TC_BODY(isc_hmacsha384, tc) {
	isc_hmacsha384_t hmacsha384;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"AFD03944D84895626B0825F4AB46907F15F9DADBE4101E"
				"C682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152"
				"E8B2FA9CB6",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				   "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				   "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B"
				"47E42EC3736322445E8E2240CA5E69E2C78B3239"
				"ECFAB21649",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9F"
				"EBE83EF4E55966144B2A5AB39DC13814B94E3AB6"
				"E101A34F27",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"3E8A69B7783C25851933AB6290AF6CA77A998148085000"
				"9CC5577C6E1F573B4E6801DD23C4A7D679CCF8A3"
				"86C674CFFB",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
#endif
		/* Test 6 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B58"
				"8F3CD11F05033AC4C60C2EF6AB4030FE8296248D"
				"F163F44952",
			1
		},
		/* Test 7 */
		{
			TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				   "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				   "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				   "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				   "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				   "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				   "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				   "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				   "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				   "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				   "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				   "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				   "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				   "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				   "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				   "\x6d\x2e"),
			"6617178E941F020D351E2F254E8FD32C602420FEB0B8FB"
				"9ADCCEBB82461E99C5A678CC31E799176D3860E6"
				"110C46523E",
			1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
#endif
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacsha384_init(&hmacsha384, buffer, test_key->len);
		isc_hmacsha384_update(&hmacsha384,
				      (const uint8_t *) testcase->input,
				      testcase->input_len);
		isc_hmacsha384_sign(&hmacsha384, digest, ISC_SHA384_DIGESTLENGTH);
		tohexstr(digest, ISC_SHA384_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}

/* HMAC-SHA512 test */
ATF_TC(isc_hmacsha512);
ATF_TC_HEAD(isc_hmacsha512, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-SHA512 examples from RFC4634");
}
ATF_TC_BODY(isc_hmacsha512, tc) {
	isc_hmacsha512_t hmacsha512;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2"
				"787AD0B30545E17CDEDAA833B7D6B8A702038B27"
				"4EAEA3F4E4BE9D914EEB61F1702E696C203A126854",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				   "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				   "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831F"
				"D610270CD7EA2505549758BF75C05A994A6D034F"
				"65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A"
				"3655F83E33B2279D39BF3E848279A722C806B485"
				"A47E67C807B946A337BEE8942674278859E13292FB",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B87"
				"2DE76F8050361EE3DBA91CA5C11AA25EB4D67927"
				"5CC5788063A5F19741120C4F2DE2ADEBEB10A298DD",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
#endif
		/* Test 6 */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEE"
				"C1121B013783F8F3526B56D037E05F2598BD0FD2"
				"215D6A1E5295E64F73F63F0AEC8B915A985D786598",
			1
		},
		/* Test 7 */
		{
			TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				   "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				   "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				   "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				   "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				   "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				   "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				   "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				   "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				   "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				   "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				   "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				   "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				   "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				   "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				   "\x6d\x2e"),
			"E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289"
				"865DF5A32D20CDC944B6022CAC3C4982B10D5EEB"
				"55C3E4DE15134676FB6DE0446065C97440FA8C6A58",
			1
		},
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
#endif
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacsha512_init(&hmacsha512, buffer, test_key->len);
		isc_hmacsha512_update(&hmacsha512,
				      (const uint8_t *) testcase->input,
				      testcase->input_len);
		isc_hmacsha512_sign(&hmacsha512, digest, ISC_SHA512_DIGESTLENGTH);
		tohexstr(digest, ISC_SHA512_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}


/* HMAC-MD5 Test */
ATF_TC(isc_hmacmd5);
ATF_TC_HEAD(isc_hmacmd5, tc) {
	atf_tc_set_md_var(tc, "descr", "HMAC-MD5 examples from RFC2104");
}
ATF_TC_BODY(isc_hmacmd5, tc) {
	isc_hmacmd5_t hmacmd5;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
			"9294727A3638BB1C13F48EF8158BFC9D",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79"
				   "\x61\x20\x77\x61\x6e\x74\x20\x66\x6f"
				   "\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
			"750C783E6AB0B503EAA86E310A5DB738", 1
		},
		/* Test 3 */
		{
			TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				   "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
			"56BE34521D144C88DBB8C733F0E8B3F6",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				   "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
			"697EAF0ACA3A3AEA3A75164746FFAA79",
			1
		},
#if 0
		/* Test 5 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test With Truncation"),
			"4C1A03424B55E07FE7F27BE1",
			1
		},
		/* Test 6 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key - "
				   "Hash Key First"),
			"AA4AE5E15272D00E95705637CE8A3B55ED402112",
			1
		 },
		/* Test 7 -- unimplemented optional functionality */
		{
			TEST_INPUT("Test Using Larger Than Block-Size Key and "
				   "Larger Than One Block-Size Data"),
			"E8E99D0F45237D786D6BBAA7965C7808BBFF1A91",
			1
		},
#endif
		{ NULL, 0, NULL, 1 }
	};

	hash_testcase_t *testcase = testcases;

	hash_test_key_t test_keys[] = {
		/* Key 1 */
		{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		  "\x0b\x0b\x0b\x0b\x0b\x0b", 16 },
		/* Key 2 */
		{ "Jefe", 4 },
		/* Key 3 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa", 16 },
		/* Key 4 */
		{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		  "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		  "\x15\x16\x17\x18\x19", 25 },
#if 0
		/* Key 5 */
		{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		  "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20 },
		/* Key 6 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
		/* Key 7 */
		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131 },
#endif
		{ "", 0 }
	};

	hash_test_key_t *test_key = test_keys;

	while (testcase->input != NULL && testcase->result != NULL) {
		memmove(buffer, test_key->key, test_key->len);
		isc_hmacmd5_init(&hmacmd5, buffer, test_key->len);
		isc_hmacmd5_update(&hmacmd5,
				   (const uint8_t *) testcase->input,
				   testcase->input_len);
		isc_hmacmd5_sign(&hmacmd5, digest);
		tohexstr(digest, ISC_MD5_DIGESTLENGTH, str, sizeof(str));
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
		test_key++;
	}
}

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
		isc_crc64_init(&crc);
		for(i = 0; i < testcase->repeats; i++) {
			isc_crc64_update(&crc,
				       (const uint8_t *) testcase->input,
				       testcase->input_len);
		}
		isc_crc64_final(&crc);
		snprintf(str, sizeof(str),
			 "0x%016" PRIX64, crc);
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
	ATF_TP_ADD_TC(tp, isc_hmacmd5);
	ATF_TP_ADD_TC(tp, isc_hmacsha1);
	ATF_TP_ADD_TC(tp, isc_hmacsha224);
	ATF_TP_ADD_TC(tp, isc_hmacsha256);
	ATF_TP_ADD_TC(tp, isc_hmacsha384);
	ATF_TP_ADD_TC(tp, isc_hmacsha512);

	ATF_TP_ADD_TC(tp, isc_crc64);

	return (atf_no_error());
}
