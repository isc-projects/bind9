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

#include <config.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <isc/result.h>

#include <dns/tkey.h>

static isc_mem_t *mock_mctx;

void *
__wrap_isc_mem_get(isc_mem_t *mctx __attribute__ ((unused)),
		   size_t size) __attribute__ ((unused));

void *
__wrap_isc_mem_get(isc_mem_t *mctx __attribute__ ((unused)),
		   size_t size)
{
	return (test_malloc(size));
}

void
__wrap_isc_mem_put(isc_mem_t *ctx0 __attribute__ ((unused)),
		   void *ptr,
		   size_t size __attribute__ ((unused))) __attribute__ ((unused));
void
__wrap_isc_mem_put(isc_mem_t *ctx0 __attribute__ ((unused)),
		   void *ptr,
		   size_t size __attribute__ ((unused)))
{
	test_free(ptr);
}

void
__wrap_isc_mem_attach(isc_mem_t *source0, isc_mem_t **targetp) __attribute__ ((unused));
void
__wrap_isc_mem_attach(isc_mem_t *source0, isc_mem_t **targetp) {
	*targetp = source0;
}

static void
__wrap_isc_mem_detach(isc_mem_t **ctxp) __attribute__ ((unused));
static void
__wrap_isc_mem_detach(isc_mem_t **ctxp) {
	*ctxp = NULL;
}

static int
_teardown(void **state) {
	dns_tkeyctx_destroy((dns_tkeyctx_t **)state);
	return (0);
}

static void
dns_tkeyctx_create_test(void **state) {
	assert_int_equal(dns_tkeyctx_create(mock_mctx, (dns_tkeyctx_t **)state), ISC_R_SUCCESS);
}

int main(void) {
	int tkey_tests_result = 0;
	mock_mctx = test_malloc(sizeof(mock_mctx));

	const struct CMUnitTest tkey_tests[] = {
		cmocka_unit_test_teardown(dns_tkeyctx_create_test, _teardown),
	};
	tkey_tests_result = cmocka_run_group_tests(tkey_tests, NULL, NULL);

	test_free(mock_mctx);

	return (tkey_tests_result);
}
