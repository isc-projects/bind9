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

#if HAVE_CMOCKA

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/hash.h>
#include <isc/ht.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include "isctest.h"

/* INCLUDE LAST */

#include "../ht.c"

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

static void
test_ht_full(uint8_t init_bits, uint8_t finish_bits, uintptr_t count) {
	isc_ht_t *ht = NULL;
	isc_result_t result;
	uintptr_t i;

	isc_ht_init(&ht, test_mctx, init_bits);
	assert_non_null(ht);

	for (i = 1; i < count; i++) {
		/*
		 * Note: snprintf() is followed with strlcat()
		 * to ensure we are always filling the 16 byte key.
		 */
		unsigned char key[16];
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_add(ht, key, 16, (void *)i);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_find(ht, key, 16, &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal((void *)i, (uintptr_t)f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_add(ht, key, 16, (void *)i);
		assert_int_equal(result, ISC_R_EXISTS);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		/*
		 * Note: the key size is now strlen(key) which is bigger
		 * then the keys added above.
		 */
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_add(ht, (const unsigned char *)key, strlen(key),
				    (void *)i);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		/*
		 * Note: case of KEY is now in capitals,
		 */
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " KEY of a raw hashtable!!", sizeof(key));
		result = isc_ht_find(ht, key, 16, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		void *f = NULL;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_find(ht, (const unsigned char *)key,
				     strlen(key), &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, (void *)i);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_delete(ht, key, 16);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_ht_find(ht, key, 16, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		/*
		 * Note: upper case KEY.
		 */
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " KEY of a raw hashtable!!", sizeof(key));
		result = isc_ht_add(ht, key, 16, (void *)i);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		void *f = NULL;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_delete(ht, (const unsigned char *)key,
				       strlen(key));
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_ht_find(ht, (const unsigned char *)key,
				     strlen(key), &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		/*
		 * Note: case of KEY is now in capitals,
		 */
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " KEY of a raw hashtable!!", sizeof(key));
		result = isc_ht_find(ht, key, 16, &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal((void *)i, (uintptr_t)f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, " key of a raw hashtable!!", sizeof(key));
		result = isc_ht_find(ht, key, 16, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	assert_int_equal(ht->hashbits[ht->hindex], finish_bits);

	isc_ht_destroy(&ht);
	assert_null(ht);
}

static void
test_ht_iterator(void) {
	isc_ht_t *ht = NULL;
	isc_result_t result;
	isc_ht_iter_t *iter = NULL;
	uintptr_t i;
	uintptr_t count = 6300;
	uint32_t walked;
	unsigned char key[16];
	size_t tksize;

	isc_ht_init(&ht, test_mctx, HT_MIN_BITS);
	assert_non_null(ht);
	for (i = 1; i <= count; i++) {
		/*
		 * Note that the string we're snprintfing is always > 16 bytes
		 * so we are always filling the key.
		 */
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, "key of a raw hashtable!!", sizeof(key));
		result = isc_ht_add(ht, key, 16, (void *)i);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/* We want to iterate while rehashing is in progress */
	assert_true(rehashing_in_progress(ht));

	walked = 0;
	isc_ht_iter_create(ht, &iter);

	for (result = isc_ht_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(iter))
	{
		unsigned char *tkey = NULL;
		void *v = NULL;

		isc_ht_iter_current(iter, &v);
		isc_ht_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);
		i = (uintptr_t)v;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, "key of a raw hashtable!!", sizeof(key));
		assert_memory_equal(key, tkey, 16);
		walked++;
	}
	assert_int_equal(walked, count);
	assert_int_equal(result, ISC_R_NOMORE);

	/* erase odd */
	walked = 0;
	result = isc_ht_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		unsigned char *tkey = NULL;
		void *v = NULL;

		isc_ht_iter_current(iter, &v);
		isc_ht_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);
		i = (uintptr_t)v;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, "key of a raw hashtable!!", sizeof(key));
		assert_memory_equal(key, tkey, 16);
		if ((uintptr_t)v % 2 == 0) {
			result = isc_ht_iter_delcurrent_next(iter);
		} else {
			result = isc_ht_iter_next(iter);
		}
		walked++;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, count);

	/* erase even */
	walked = 0;
	result = isc_ht_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		unsigned char *tkey = NULL;
		void *v = NULL;

		isc_ht_iter_current(iter, &v);
		isc_ht_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);
		i = (uintptr_t)v;
		snprintf((char *)key, sizeof(key), "%u", (unsigned int)i);
		strlcat((char *)key, "key of a raw hashtable!!", sizeof(key));
		assert_memory_equal(key, tkey, 16);
		if ((uintptr_t)v % 2 == 1) {
			result = isc_ht_iter_delcurrent_next(iter);
		} else {
			result = isc_ht_iter_next(iter);
		}
		walked++;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, count / 2);

	walked = 0;
	for (result = isc_ht_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(iter))
	{
		walked++;
	}

	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, 0);

	/* Iterator doesn't progress rehashing */
	assert_true(rehashing_in_progress(ht));

	isc_ht_iter_destroy(&iter);
	assert_null(iter);

	isc_ht_destroy(&ht);
	assert_null(ht);
}

/* 24 bit, 200K elements test, no rehashing */
static void
isc_ht_24(void **state) {
	UNUSED(state);
	test_ht_full(24, 24, 200000);
}

/* 15 bit, 45K elements test, full rehashing */
static void
isc_ht_15(void **state) {
	UNUSED(state);
	test_ht_full(1, 15, 48000);
}

/* 8 bit, 20k elements test, partial rehashing */
static void
isc_ht_8(void **state) {
	UNUSED(state);
	test_ht_full(8, 14, 20000);
}

/* test hashtable iterator */
static void
isc_ht_iterator_test(void **state) {
	UNUSED(state);
	test_ht_iterator();
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(isc_ht_24),
		cmocka_unit_test(isc_ht_15),
		cmocka_unit_test(isc_ht_8),
		cmocka_unit_test(isc_ht_iterator_test),
	};

	return (cmocka_run_group_tests(tests, _setup, _teardown));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
