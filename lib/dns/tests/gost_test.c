/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <string.h>

#include <isc/util.h>
#include <isc/string.h>

#include "dnstest.h"

#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)

#include "../dst_gost.h"

/*
 * Test data from Wikipedia GOST (hash function)
 */

unsigned char digest[ISC_GOST_DIGESTLENGTH];
unsigned char buffer[1024];
const char *s;
char str[ISC_GOST_DIGESTLENGTH];
int i = 0;

isc_result_t
tohexstr(unsigned char *d, unsigned int len, char *out);
/*
 * Precondition: a hexadecimal number in *d, the length of that number in len,
 *   and a pointer to a character array to put the output (*out).
 * Postcondition: A String representation of the given hexadecimal number is
 *   placed into the array *out
 *
 * 'out' MUST point to an array of at least len / 2 + 1
 *
 * Return values: ISC_R_SUCCESS if the operation is sucessful
 */

isc_result_t
tohexstr(unsigned char *d, unsigned int len, char *out) {

	out[0]='\0';
	char c_ret[] = "AA";
	unsigned int i;
	strcat(out, "0x");
	for (i = 0; i < len; i++) {
		sprintf(c_ret, "%02X", d[i]);
		strcat(out, c_ret);
	}
	strcat(out, "\0");
	return (ISC_R_SUCCESS);
}


#define TEST_INPUT(x) (x), sizeof(x)-1

typedef struct hash_testcase {
	const char *input;
	size_t input_len;
	const char *result;
	int repeats;
} hash_testcase_t;

ATF_TC(isc_gost);
ATF_TC_HEAD(isc_gost, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "GOST R 34.11-94 examples from Wikipedia");
}
ATF_TC_BODY(isc_gost, tc) {
	isc_gost_t gost;
	isc_result_t result;

	UNUSED(tc);

	/*
	 * These are the various test vectors.  All of these are passed
	 * through the hash function and the results are compared to the
	 * result specified here.
	 */
	hash_testcase_t testcases[] = {
		/* Test 1 */
		{
			TEST_INPUT(""),
			"0x981E5F3CA30C841487830F84FB433E1"
			"3AC1101569B9C13584AC483234CD656C0",
			1
		},
		/* Test 2 */
		{
			TEST_INPUT("a"),
			"0xE74C52DD282183BF37AF0079C9F7805"
			"5715A103F17E3133CEFF1AACF2F403011",
			1
		},
		/* Test 3 */
		{
			TEST_INPUT("abc"),
			"0xB285056DBF18D7392D7677369524DD1"
			"4747459ED8143997E163B2986F92FD42C",
			1
		},
		/* Test 4 */
		{
			TEST_INPUT("message digest"),
			"0xBC6041DD2AA401EBFA6E9886734174F"
			"EBDB4729AA972D60F549AC39B29721BA0",
			1
		},
		/* Test 5 */
		{
			TEST_INPUT("The quick brown fox jumps "
				   "over the lazy dog"),
			"0x9004294A361A508C586FE53D1F1B027"
			"46765E71B765472786E4770D565830A76",
			1
		},
		/* Test 6 */
		{
			TEST_INPUT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
				   "fghijklmnopqrstuvwxyz0123456789"),
			"0x73B70A39497DE53A6E08C67B6D4DB85"
			"3540F03E9389299D9B0156EF7E85D0F61",
			1
		},
		/* Test 7 */
		{
			TEST_INPUT("1234567890123456789012345678901"
				   "2345678901234567890123456789012"
				   "345678901234567890"),
			"0x6BC7B38989B28CF93AE8842BF9D7529"
			"05910A7528A61E5BCE0782DE43E610C90",
			1
		},
		/* Test 8 */
		{
			TEST_INPUT("This is message, length=32 bytes"),
			"0x2CEFC2F7B7BDC514E18EA57FA74FF35"
			"7E7FA17D652C75F69CB1BE7893EDE48EB",
			1
		},
		/* Test 9 */
		{
			TEST_INPUT("Suppose the original message "
				   "has length = 50 bytes"),
			"0xC3730C5CBCCACF915AC292676F21E8B"
			"D4EF75331D9405E5F1A61DC3130A65011",
			1
		},
		/* Test 10 */
		{
			TEST_INPUT("U") /* times 128 */,
			"0x1C4AC7614691BBF427FA2316216BE8F"
			"10D92EDFD37CD1027514C1008F649C4E8",
			128
		},
		/* Test 11 */
		{
			TEST_INPUT("a") /* times 1000000 */,
			"0x8693287AA62F9478F7CB312EC0866B6"
			"C4E4A0F11160441E8F4FFCD2715DD554F",
			1000000
		},
		{ NULL, 0, NULL, 1 }
	};

	result = dns_test_begin(NULL, ISC_FALSE);
	ATF_REQUIRE(result == ISC_R_SUCCESS);

	hash_testcase_t *testcase = testcases;

	while (testcase->input != NULL && testcase->result != NULL) {
		result = isc_gost_init(&gost);
		ATF_REQUIRE(result == ISC_R_SUCCESS);
		for(i = 0; i < testcase->repeats; i++) {
			result = isc_gost_update(&gost,
					(const isc_uint8_t *) testcase->input,
					testcase->input_len);
			ATF_REQUIRE(result == ISC_R_SUCCESS);
		}
		result = isc_gost_final(&gost, digest);
		ATF_REQUIRE(result == ISC_R_SUCCESS);
		tohexstr(digest, ISC_GOST_DIGESTLENGTH, str);
		ATF_CHECK_STREQ(str, testcase->result);

		testcase++;
	}

	dns_test_end();
}
#else
ATF_TC(untested);
ATF_TC_HEAD(untested, tc) {
	atf_tc_set_md_var(tc, "descr", "skipping gost test");
}
ATF_TC_BODY(untested, tc) {
	UNUSED(tc);
	atf_tc_skip("GOST hash not available");
}
#endif
/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)
	ATF_TP_ADD_TC(tp, isc_gost);
#else
	ATF_TP_ADD_TC(tp, untested);
#endif
	return (atf_no_error());
}

