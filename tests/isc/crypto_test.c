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

/*
 * The AEAD test vectors are taken from Project Wycheproof. The vectors are not
 * for checking various cryptographic properties (that is the job of libcrypto
 * and its forks) but as a sanity check for changes in the relevant code.
 *
 * Test vectors do not require a license notice since they are not copyrightable
 * material in the first place. This is also further reinforced by Wycheproof
 * contributors. [1]
 *
 * Last used commit: d544ce0881731f28eaa98e946db430880d216fd5
 *
 * [1]: https://github.com/C2SP/wycheproof/issues/52#issuecomment-394413920
 */

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/crypto.h>
#include <isc/lib.h>
#include <isc/md.h>
#include <isc/types.h>

#include <tests/isc.h>

typedef struct aead_testcase aead_testcase_t;

struct aead_testcase {
	isc_crypto_aead_algorithm_t algorithm;
	const uint8_t key[32];
	const uint8_t nonce[12];
	const uint8_t plaintext[20];
	const uint8_t ciphertext[36];
	const uint8_t additional_data[8];
};


static void
test_aead(const aead_testcase_t *const testcase) {
	uint8_t ciphertext_buf[36], plaintext_buf[20];
	isc_constregion_t nonce, key;
	isc_crypto_aead_t *aead = NULL;
	isc_result_t result;
	size_t outlen;

	const isc_constregion_t aad = {
		.base = testcase->additional_data,
		.length = sizeof(testcase->additional_data),
	};

	isc_region_t actual_ciphertext = {
		.base = ciphertext_buf,
		.length = sizeof(ciphertext_buf),
	};

	isc_region_t actual_plaintext = {
		.base = plaintext_buf,
		.length = sizeof(plaintext_buf),
	};

	nonce.base = testcase->nonce;
	key.base = testcase->key;

	switch (testcase->algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		nonce.length = isc_crypto_aes128gcm_nonce_length;
		key.length = isc_crypto_aes128gcm_key_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		nonce.length = isc_crypto_aes256gcm_nonce_length;
		key.length = isc_crypto_aes256gcm_key_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		nonce.length = isc_crypto_chacha20poly1305_nonce_length;
		key.length = isc_crypto_chacha20poly1305_key_length;
		break;
	default:
		UNREACHABLE();
	}

	result = isc_crypto_aead_create(testcase->algorithm, key,
					ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_crypto_aead_seal(
		aead, nonce,
		(isc_constregion_t){ testcase->plaintext,
				     sizeof(testcase->plaintext) },
		actual_ciphertext, &outlen, (isc_constregion_t){ NULL, 0 });
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(outlen, actual_ciphertext.length);
	assert_memory_not_equal(actual_ciphertext.base, testcase->ciphertext,
				actual_ciphertext.length);

	result = isc_crypto_aead_seal(
		aead, nonce,
		(isc_constregion_t){ testcase->plaintext,
				     sizeof(testcase->plaintext) },
		actual_ciphertext, &outlen,
		(isc_constregion_t){ testcase->additional_data,
				     sizeof(testcase->additional_data) });
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(outlen, actual_ciphertext.length);
	assert_memory_equal(actual_ciphertext.base, testcase->ciphertext,
			    actual_ciphertext.length);
	isc_crypto_aead_destroy(&aead);

	result = isc_crypto_aead_create(testcase->algorithm, key,
					ISC_CRYPTO_AEAD_DIRECTION_OPEN, &aead);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_crypto_aead_open(
		aead, nonce,
		(isc_constregion_t){ (uint8_t *)testcase->ciphertext,
				     sizeof(testcase->ciphertext) },
		actual_plaintext, &outlen, (isc_constregion_t){ NULL, 0 });
	assert_int_not_equal(result, ISC_R_SUCCESS);

	result = isc_crypto_aead_open(
		aead, nonce,
		(isc_constregion_t){ (uint8_t *)testcase->ciphertext,
				     sizeof(testcase->ciphertext) },
		actual_plaintext, &outlen, aad);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_memory_equal(actual_plaintext.base, testcase->plaintext,
			    actual_plaintext.length);
	assert_int_equal(outlen, sizeof(testcase->plaintext));
	isc_crypto_aead_destroy(&aead);
}

ISC_RUN_TEST_IMPL(aead) {
	size_t i;

	static const aead_testcase_t fips_testcases[] = {
		{
			/* tcid : 12 */
			ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
			{ 0xe6, 0x3a, 0x43, 0x21, 0x6c, 0x08, 0x86, 0x72, 0x10,
			  0xe2, 0x48, 0x85, 0x9e, 0xb5, 0xe9, 0x9c },
			{ 0x9c, 0x3a, 0x42, 0x63, 0xd9, 0x83, 0x45, 0x66, 0x58,
			  0xaa, 0xd4, 0xb1 },
			{ 0xb1, 0x4d, 0xa5, 0x6b, 0x04, 0x62, 0xdc,
			  0x05, 0xb8, 0x71, 0xfc, 0x81, 0x52, 0x73,
			  0xff, 0x48, 0x10, 0xf9, 0x2f, 0x4b },
			{ 0xbf, 0x86, 0x46, 0x16, 0xc2, 0x34, 0x75, 0x09, 0xca,
			  0x9b, 0x10, 0x44, 0x63, 0x79, 0xb9, 0xbd, 0xbb, 0x3b,
			  0x8f, 0x64, 0xa9, 0x7d, 0x25, 0xb4, 0x90, 0x39, 0x0b,
			  0x53, 0xc5, 0xdb, 0x91, 0xf6, 0xee, 0x2a, 0x15, 0xb8 },
			{ 0x83, 0x4a, 0xfd, 0xc5, 0xc7, 0x37, 0x18, 0x6b },
		},

		{
			/* tcid: 101 */
			ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM,
			{ 0xcd, 0xcc, 0xfe, 0x3f, 0x46, 0xd7, 0x82, 0xef,
			  0x47, 0xdf, 0x4e, 0x72, 0xf0, 0xc0, 0x2d, 0x9c,
			  0x7f, 0x77, 0x4d, 0xef, 0x97, 0x0d, 0x23, 0x48,
			  0x6f, 0x11, 0xa5, 0x7f, 0x54, 0x24, 0x7f, 0x17 },
			{ 0x37, 0x61, 0x87, 0x89, 0x46, 0x05, 0xa8, 0xd4, 0x5e,
			  0x30, 0xde, 0x51 },
			{ 0xe2, 0x8e, 0x0e, 0x9f, 0x9d, 0x22, 0x46,
			  0x3a, 0xc0, 0xe4, 0x26, 0x39, 0xb5, 0x30,
			  0xf4, 0x21, 0x02, 0xfd, 0xed, 0x75 },
			{ 0xfe, 0xca, 0x44, 0x95, 0x24, 0x47, 0x01, 0x5b, 0x5d,
			  0xf1, 0xf4, 0x56, 0xdf, 0x8c, 0xa4, 0xbb, 0x4e, 0xee,
			  0x2c, 0xe2, 0x08, 0x2e, 0x91, 0x92, 0x4d, 0xee, 0xb7,
			  0x78, 0x80, 0xe1, 0xb1, 0xc8, 0x4f, 0x9b, 0x8d, 0x30 },
			{ 0x95, 0x68, 0x46, 0xa2, 0x09, 0xe0, 0x87, 0xed },

		},
	};

	static const aead_testcase_t non_fips_testcases[] = {
		{
			/* tcid : 43 */
			ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305,
			{ 0xcd, 0xcc, 0xfe, 0x3f, 0x46, 0xd7, 0x82, 0xef,
			  0x47, 0xdf, 0x4e, 0x72, 0xf0, 0xc0, 0x2d, 0x9c,
			  0x7f, 0x77, 0x4d, 0xef, 0x97, 0x0d, 0x23, 0x48,
			  0x6f, 0x11, 0xa5, 0x7f, 0x54, 0x24, 0x7f, 0x17 },
			{ 0x37, 0x61, 0x87, 0x89, 0x46, 0x05, 0xa8, 0xd4, 0x5e,
			  0x30, 0xde, 0x51 },
			{ 0xe2, 0x8e, 0x0e, 0x9f, 0x9d, 0x22, 0x46,
			  0x3a, 0xc0, 0xe4, 0x26, 0x39, 0xb5, 0x30,
			  0xf4, 0x21, 0x02, 0xfd, 0xed, 0x75 },
			{ 0x14, 0xf7, 0x07, 0xc4, 0x46, 0x98, 0x8a, 0x49, 0x03,
			  0x77, 0x5e, 0xc7, 0xac, 0xec, 0x6d, 0xa1, 0x14, 0xd4,
			  0x31, 0x12, 0x98, 0x7d, 0x4b, 0x14, 0x7c, 0x49, 0x0d,
			  0x43, 0xd3, 0x76, 0xa1, 0x98, 0xca, 0xb3, 0x83, 0xf0 },
			{ 0x95, 0x68, 0x46, 0xa2, 0x09, 0xe0, 0x87, 0xed },
		},
	};

	for (i = 0; i < ARRAY_SIZE(fips_testcases); i++) {
		test_aead(&fips_testcases[i]);
	}

	if (isc_crypto_fips_mode()) {
		return;
	}

	for (i = 0; i < ARRAY_SIZE(non_fips_testcases); i++) {
		test_aead(&non_fips_testcases[i]);
	}
}

ISC_RUN_TEST_IMPL(hkdf) {
	isc_result_t result;
	uint8_t actual[42];

	const uint8_t ikm[22] = { [0 ... 21] = 0x0B };
	const uint8_t salt[13] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	};
	const uint8_t info[10] = {
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9,
	};
	const uint8_t expected[42] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};

	result = isc_crypto_hkdf((isc_region_t){ actual, sizeof(actual) },
				 ISC_MD_SHA256,
				 (isc_constregion_t){ ikm, sizeof(ikm) },
				 (isc_constregion_t){ salt, sizeof(salt) },
				 (isc_constregion_t){ info, sizeof(info) });
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_memory_equal(expected, actual, 42);
}

ISC_RUN_TEST_IMPL(hkdf_expand_label) {
	isc_result_t result;
	uint8_t actual[32];

	/*
	 * Values are taken from RFC 9001 Appendix A.1.
	 */
	const uint8_t secret[32] = {
		0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
		0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
		0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
		0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
	};

	const uint8_t expected[32] = {
		0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
		0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
		0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
		0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
	};

	result = isc_crypto_hkdf_expand_label(
		(isc_region_t){ actual, sizeof(actual) }, ISC_MD_SHA256,
		(isc_constregion_t){ secret, sizeof(secret) },
		(isc_constregion_t){ "client in", sizeof("client in") - 1 });
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_memory_equal(expected, actual, 32);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(aead)
ISC_TEST_ENTRY(hkdf)
ISC_TEST_ENTRY(hkdf_expand_label)
ISC_TEST_LIST_END

ISC_TEST_MAIN
