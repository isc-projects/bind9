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
#include <isc/symtab.h>
#include <isc/util.h>

#include <tests/isc.h>

#define TEST_NITEMS 10000

static void
undefine(char *key, unsigned int type ISC_ATTR_UNUSED, isc_symvalue_t value,
	 void *arg ISC_ATTR_UNUSED) {
	isc_mem_free(isc_g_mctx, key);
	isc_mem_free(isc_g_mctx, value.as_pointer);
}

ISC_RUN_TEST_IMPL(symtab_define) {
	isc_result_t result;
	isc_symtab_t *symtab = NULL;
	isc_symvalue_t value;
	isc_symvalue_t found;
	isc_symexists_t policy = isc_symexists_reject;
	char str[16], *key;
	snprintf(str, sizeof(str), "%p", "define");
	key = isc_mem_strdup(isc_g_mctx, str);

	isc_symtab_create(isc_g_mctx, undefine, NULL, false, &symtab);
	assert_non_null(symtab);

	value.as_pointer = isc_mem_strdup(isc_g_mctx, key);
	assert_non_null(value.as_pointer);

	result = isc_symtab_define(symtab, key, 1, value, policy);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key, 1, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_string_equal(value.as_pointer, found.as_pointer);

	result = isc_symtab_lookup(symtab, key, 2, NULL);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_symtab_destroy(&symtab);
}

ISC_RUN_TEST_IMPL(symtab_undefine) {
	isc_result_t result;
	isc_symtab_t *symtab = NULL;
	isc_symvalue_t value;
	isc_symexists_t policy = isc_symexists_reject;

	/* We need a separate copy of the key to prevent an use-after-free */
	char str[16], *key, *key_after_undefine;
	snprintf(str, sizeof(str), "%p", "undefine");

	key = isc_mem_strdup(isc_g_mctx, str);
	key_after_undefine = isc_mem_strdup(isc_g_mctx, str);

	isc_symtab_create(isc_g_mctx, undefine, NULL, false, &symtab);
	assert_non_null(symtab);

	value.as_pointer = isc_mem_strdup(isc_g_mctx, key);
	assert_non_null(value.as_pointer);

	result = isc_symtab_define(symtab, key, 1, value, policy);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key_after_undefine, 1, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_undefine(symtab, key, 1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key_after_undefine, 1, NULL);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_symtab_destroy(&symtab);

	/* key will be freed by isc_symtab_undefine, so we don't need to free
	 * it again
	 */
	isc_mem_free(isc_g_mctx, key_after_undefine);
}

ISC_RUN_TEST_IMPL(symtab_replace) {
	isc_result_t result;
	isc_symtab_t *symtab = NULL;
	isc_symvalue_t value1;
	isc_symvalue_t value2;
	isc_symvalue_t found;
	isc_symexists_t policy = isc_symexists_replace;
	char str[16], *key1, *key2;
	snprintf(str, sizeof(str), "%p", "replace");
	key1 = isc_mem_strdup(isc_g_mctx, str);
	key2 = isc_mem_strdup(isc_g_mctx, str);

	isc_symtab_create(isc_g_mctx, undefine, NULL, false, &symtab);
	assert_non_null(symtab);

	value1.as_pointer = isc_mem_strdup(isc_g_mctx, key1);
	assert_non_null(value1.as_pointer);

	value2.as_pointer = isc_mem_strdup(isc_g_mctx, key2);
	assert_non_null(value2.as_pointer);

	result = isc_symtab_define(symtab, key1, 1, value1, policy);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key1, 1, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_string_equal(value1.as_pointer, found.as_pointer);

	result = isc_symtab_define(symtab, key2, 1, value2, policy);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key2, 1, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_string_equal(value2.as_pointer, found.as_pointer);

	result = isc_symtab_undefine(symtab, key2, 1);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_symtab_destroy(&symtab);
}

ISC_RUN_TEST_IMPL(symtab_reject) {
	isc_result_t result;
	isc_symtab_t *symtab = NULL;
	isc_symvalue_t value1;
	isc_symvalue_t value2;
	isc_symvalue_t found;
	isc_symexists_t policy = isc_symexists_reject;
	char str[16], *key1, *key2;
	snprintf(str, sizeof(str), "%p", "reject");
	key1 = isc_mem_strdup(isc_g_mctx, str);
	key2 = isc_mem_strdup(isc_g_mctx, str);

	isc_symtab_create(isc_g_mctx, undefine, NULL, false, &symtab);
	assert_non_null(symtab);

	value1.as_pointer = isc_mem_strdup(isc_g_mctx, key1);
	assert_non_null(value1.as_pointer);

	value2.as_pointer = isc_mem_strdup(isc_g_mctx, key2);
	assert_non_null(value2.as_pointer);

	result = isc_symtab_define(symtab, key1, 1, value1, policy);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_symtab_lookup(symtab, key1, 1, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_string_equal(value1.as_pointer, found.as_pointer);

	result = isc_symtab_define_and_return(symtab, key2, 1, value2, policy,
					      &found);
	assert_int_equal(result, ISC_R_EXISTS);
	assert_string_equal(value1.as_pointer, found.as_pointer);

	result = isc_symtab_lookup(symtab, key2, 1, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_string_equal(value1.as_pointer, found.as_pointer);

	result = isc_symtab_undefine(symtab, key1, 1);
	assert_int_equal(result, ISC_R_SUCCESS);

	undefine(key2, 1, value2, NULL);

	isc_symtab_destroy(&symtab);
}

static bool
peek(char *key ISC_ATTR_UNUSED, unsigned int type,
     isc_symvalue_t value ISC_ATTR_UNUSED, void *arg) {
	bool *seen = arg;
	size_t i = type - 1;

	assert_false(seen[i]);

	seen[i] = true;

	return i % 2;
}

ISC_RUN_TEST_IMPL(symtab_foreach) {
	isc_result_t result;
	isc_symtab_t *symtab = NULL;
	isc_symvalue_t value;
	isc_symexists_t policy = isc_symexists_reject;
	bool seen[TEST_NITEMS] = { 0 };

	isc_symtab_create(isc_g_mctx, undefine, NULL, false, &symtab);

	/* Nothing should be in the table yet */
	assert_non_null(symtab);

	/*
	 * Put TEST_NITEMS entries in the table.
	 */
	for (size_t i = 0; i < TEST_NITEMS; i++) {
		char str[256] = {}, *key;

		snprintf(str, sizeof(str), "%08zx", i);

		key = isc_mem_strdup(isc_g_mctx, str);
		assert_non_null(key);
		value.as_pointer = isc_mem_strdup(isc_g_mctx, str);
		assert_non_null(value.as_pointer);
		result = isc_symtab_define(symtab, key, i + 1, value, policy);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	/*
	 * Retrieve them; this should succeed
	 */
	for (size_t i = 0; i < TEST_NITEMS; i++) {
		char str[256] = {};

		snprintf(str, sizeof(str), "%08zx", i);
		result = isc_symtab_lookup(symtab, str, i + 1, &value);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_string_equal(str, (char *)value.as_pointer);
	}

	/*
	 * Undefine even items them via foreach
	 */
	isc_symtab_foreach(symtab, peek, seen);

	for (size_t i = 0; i < TEST_NITEMS; i++) {
		assert_true(seen[i]);
	}

	/*
	 * Destroy the even ones by hand.
	 */
	for (size_t i = 0; i < TEST_NITEMS; i++) {
		if (i % 2 == 0) {
			char str[256] = {};

			snprintf(str, sizeof(str), "%08zx", i);
			result = isc_symtab_undefine(symtab, str, i + 1);
			assert_int_equal(result, ISC_R_SUCCESS);
		}
	}

	isc_symtab_destroy(&symtab);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(symtab_define)
ISC_TEST_ENTRY(symtab_undefine)
ISC_TEST_ENTRY(symtab_reject)
ISC_TEST_ENTRY(symtab_replace)
ISC_TEST_ENTRY(symtab_foreach)

ISC_TEST_LIST_END

ISC_TEST_MAIN
