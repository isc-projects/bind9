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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <tests/isc.h>

/* INCLUDE LAST */

#define mctx __mctx
#include "hashmap.c"
#undef mctx

typedef struct test_node {
	uint32_t hashval;
	char key[64];
} test_node_t;

static void
test_hashmap_full(uint8_t init_bits, uintptr_t count) {
	isc_hashmap_t *hashmap = NULL;
	isc_result_t result;
	test_node_t *nodes, *long_nodes, *upper_nodes;

	nodes = isc_mem_get(mctx, count * sizeof(nodes[0]));
	long_nodes = isc_mem_get(mctx, count * sizeof(nodes[0]));
	upper_nodes = isc_mem_get(mctx, count * sizeof(nodes[0]));

	isc_hashmap_create(mctx, init_bits, ISC_HASHMAP_CASE_SENSITIVE,
			   &hashmap);
	assert_non_null(hashmap);

	/*
	 * Note: snprintf() is followed with strlcat()
	 * to ensure we are always filling the 16 byte key.
	 */
	for (size_t i = 0; i < count; i++) {
		/* short keys */
		snprintf(nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat(nodes[i].key, " key of a raw hashmap!!", 16);

		/* long keys */
		snprintf(long_nodes[i].key, sizeof(long_nodes[i].key), "%u",
			 (unsigned int)i);
		strlcat(long_nodes[i].key, " key of a raw hashmap!!",
			sizeof(long_nodes[i].key));

		/* (some) uppercase keys */
		snprintf(upper_nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat(upper_nodes[i].key, " KEY of a raw hashmap!!", 16);
	}

	/* insert short nodes */
	for (size_t i = 0; i < count; i++) {
		nodes[i].hashval = isc_hashmap_hash(hashmap, nodes[i].key, 16);
		result = isc_hashmap_add(hashmap, &(nodes[i]).hashval,
					 nodes[i].key, 16, &nodes[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/* check if the short nodes were insert */
	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, &(nodes[i]).hashval,
					  nodes[i].key, 16, &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(&nodes[i], f);
	}

	/* check for double inserts */
	for (size_t i = 0; i < count; i++) {
		result = isc_hashmap_add(hashmap, NULL, nodes[i].key, 16,
					 &nodes[i]);
		assert_int_equal(result, ISC_R_EXISTS);
	}

	for (size_t i = 0; i < count; i++) {
		result =
			isc_hashmap_add(hashmap, NULL, long_nodes[i].key,
					strlen((const char *)long_nodes[i].key),
					&long_nodes[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, NULL, upper_nodes[i].key, 16,
					  &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(
			hashmap, NULL, long_nodes[i].key,
			strlen((const char *)long_nodes[i].key), &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, &long_nodes[i]);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_delete(hashmap, &nodes[i].hashval,
					    nodes[i].key, 16);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_hashmap_find(hashmap, NULL, nodes[i].key, 16, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		result = isc_hashmap_add(hashmap, NULL, upper_nodes[i].key, 16,
					 &upper_nodes[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_delete(
			hashmap, NULL, long_nodes[i].key,
			strlen((const char *)long_nodes[i].key));
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_hashmap_find(
			hashmap, NULL, long_nodes[i].key,
			strlen((const char *)long_nodes[i].key), &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, NULL, upper_nodes[i].key, 16,
					  &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, &upper_nodes[i]);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, NULL, nodes[i].key, 16, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	isc_hashmap_destroy(&hashmap);
	assert_null(hashmap);

	isc_mem_put(mctx, nodes, count * sizeof(nodes[0]));
	isc_mem_put(mctx, long_nodes, count * sizeof(nodes[0]));
	isc_mem_put(mctx, upper_nodes, count * sizeof(nodes[0]));
}

static void
test_hashmap_iterator(void) {
	isc_hashmap_t *hashmap = NULL;
	isc_result_t result;
	isc_hashmap_iter_t *iter = NULL;
	size_t count = 7600;
	uint32_t walked;
	size_t tksize;
	test_node_t *nodes;

	nodes = isc_mem_get(mctx, count * sizeof(nodes[0]));

	isc_hashmap_create(mctx, HASHMAP_MIN_BITS, ISC_HASHMAP_CASE_SENSITIVE,
			   &hashmap);
	assert_non_null(hashmap);

	for (size_t i = 0; i < count; i++) {
		/* short keys */
		snprintf(nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat(nodes[i].key, " key of a raw hashmap!!", 16);
	}

	for (size_t i = 0; i < count; i++) {
		result = isc_hashmap_add(hashmap, NULL, nodes[i].key, 16,
					 &nodes[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/* We want to iterate while rehashing is in progress */
	assert_true(rehashing_in_progress(hashmap));

	walked = 0;
	isc_hashmap_iter_create(hashmap, &iter);

	for (result = isc_hashmap_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(iter))
	{
		char key[16] = { 0 };
		ptrdiff_t i;
		const uint8_t *tkey = NULL;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);
		isc_hashmap_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);

		i = v - &nodes[0];

		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);

		assert_memory_equal(key, tkey, 16);

		walked++;
	}
	assert_int_equal(walked, count);
	assert_int_equal(result, ISC_R_NOMORE);

	/* erase odd */
	walked = 0;
	result = isc_hashmap_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		char key[16] = { 0 };
		ptrdiff_t i;
		const uint8_t *tkey = NULL;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);
		isc_hashmap_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);

		i = v - nodes;
		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);
		assert_memory_equal(key, tkey, 16);

		if (i % 2 == 0) {
			result = isc_hashmap_iter_delcurrent_next(iter);
		} else {
			result = isc_hashmap_iter_next(iter);
		}
		walked++;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, count);

	/* erase even */
	walked = 0;
	result = isc_hashmap_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		char key[16] = { 0 };
		ptrdiff_t i;
		const uint8_t *tkey = NULL;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);
		isc_hashmap_iter_currentkey(iter, &tkey, &tksize);
		assert_int_equal(tksize, 16);

		i = v - nodes;
		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);
		assert_memory_equal(key, tkey, 16);

		if (i % 2 == 1) {
			result = isc_hashmap_iter_delcurrent_next(iter);
		} else {
			result = isc_hashmap_iter_next(iter);
		}
		walked++;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, count / 2);

	walked = 0;
	for (result = isc_hashmap_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(iter))
	{
		walked++;
	}

	assert_int_equal(result, ISC_R_NOMORE);
	assert_int_equal(walked, 0);

	/* Iterator doesn't progress rehashing */
	assert_true(rehashing_in_progress(hashmap));

	isc_hashmap_iter_destroy(&iter);
	assert_null(iter);

	isc_hashmap_destroy(&hashmap);
	assert_null(hashmap);

	isc_mem_put(mctx, nodes, count * sizeof(nodes[0]));
}

/* 1 bit, 120 elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_1_120) {
	test_hashmap_full(1, 120);
	return;
}

/* 6 bit, 1000 elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_6_1000) {
	test_hashmap_full(6, 1000);
	return;
}

/* 24 bit, 200K elements test, no rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_24_200000) {
	test_hashmap_full(24, 200000);
	return;
}

/* 15 bit, 45K elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_1_48000) {
	test_hashmap_full(1, 48000);
	return;
}

/* 8 bit, 20k elements test, partial rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_8_20000) {
	test_hashmap_full(8, 20000);
	return;
}

/* test hashmap iterator */

ISC_RUN_TEST_IMPL(isc_hashmap_iterator) {
	test_hashmap_iterator();
	return;
}

ISC_RUN_TEST_IMPL(isc_hashmap_hash_zero_length) {
	isc_hashmap_t *hashmap = NULL;
	uint32_t hashval;
	bool again = false;

again:
	isc_hashmap_create(mctx, 1, ISC_HASHMAP_CASE_SENSITIVE, &hashmap);

	hashval = isc_hashmap_hash(hashmap, "", 0);

	isc_hashmap_destroy(&hashmap);

	if (hashval == 0 && !again) {
		/*
		 * We could be extremely unlock and the siphash could hash the
		 * zero length string to 0, so try one more time.
		 */
		again = true;
		goto again;
	}

	assert_int_not_equal(hashval, 0);
}

ISC_RUN_TEST_IMPL(isc_hashmap_case) {
	isc_result_t result;
	isc_hashmap_t *hashmap = NULL;
	test_node_t lower = { .key = "isc_hashmap_case" };
	test_node_t upper = { .key = "ISC_HASHMAP_CASE" };
	test_node_t mixed = { .key = "IsC_hAsHmAp_CaSe" };
	test_node_t *value;

	isc_hashmap_create(mctx, 1, ISC_HASHMAP_CASE_SENSITIVE, &hashmap);

	result = isc_hashmap_add(hashmap, NULL, lower.key, strlen(lower.key),
				 &lower);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_add(hashmap, NULL, lower.key, strlen(lower.key),
				 &lower);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_add(hashmap, NULL, upper.key, strlen(upper.key),
				 &upper);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_find(hashmap, NULL, mixed.key, strlen(mixed.key),
				  (void *)&value);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_hashmap_destroy(&hashmap);

	isc_hashmap_create(mctx, 1, ISC_HASHMAP_CASE_INSENSITIVE, &hashmap);

	result = isc_hashmap_add(hashmap, NULL, lower.key, strlen(lower.key),
				 &lower);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_add(hashmap, NULL, lower.key, strlen(lower.key),
				 &lower);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_add(hashmap, NULL, upper.key, strlen(upper.key),
				 &upper);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_find(hashmap, NULL, mixed.key, strlen(mixed.key),
				  (void *)&value);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_hashmap_destroy(&hashmap);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_hashmap_hash_zero_length)
ISC_TEST_ENTRY(isc_hashmap_case)
ISC_TEST_ENTRY(isc_hashmap_1_120)
ISC_TEST_ENTRY(isc_hashmap_6_1000)
ISC_TEST_ENTRY(isc_hashmap_24_200000)
ISC_TEST_ENTRY(isc_hashmap_1_48000)
ISC_TEST_ENTRY(isc_hashmap_8_20000)
ISC_TEST_ENTRY(isc_hashmap_iterator)
ISC_TEST_LIST_END

ISC_TEST_MAIN
