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
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <isc/mem.h>
#include <isc/result.h>

#include <dns/tkey.h>

static isc_mem_t mock_mctx = { 0 };

void *
__wrap_isc__mem_get(isc_mem_t *mctx __attribute__ ((unused)),
		   size_t size) __attribute__ ((unused));

void *
__wrap_isc__mem_get(isc_mem_t *mctx __attribute__ ((unused)),
		   size_t size)
{
	bool has_enough_memory = mock_type(bool);
	if (!has_enough_memory) {
		return (NULL);
	}
	return (malloc(size));
}

void
__wrap_isc__mem_put(isc_mem_t *ctx0 __attribute__ ((unused)),
		   void *ptr,
		   size_t size __attribute__ ((unused))) __attribute__ ((unused));
void
__wrap_isc__mem_put(isc_mem_t *ctx0 __attribute__ ((unused)),
		   void *ptr,
		   size_t size __attribute__ ((unused)))
{
	free(ptr);
}

void
__wrap_isc_mem_attach(isc_mem_t *source0, isc_mem_t **targetp) __attribute__ ((unused));
void
__wrap_isc_mem_attach(isc_mem_t *source0, isc_mem_t **targetp) {
	*targetp = source0;
}

void
__wrap_isc_mem_detach(isc_mem_t **ctxp) __attribute__ ((unused));
void
__wrap_isc_mem_detach(isc_mem_t **ctxp) {
	*ctxp = NULL;
}

static int
_setup(void **state) {
	dns_tkeyctx_t *tctx = NULL;
	will_return(__wrap_isc__mem_get, true);
	if (dns_tkeyctx_create(&mock_mctx, &tctx) != ISC_R_SUCCESS) {
		return (-1);
	}
	*state = tctx;
	return (0);
}

static int
_teardown(void **state) {
	dns_tkeyctx_t *tctx = *state;
	if (tctx != NULL) {
		dns_tkeyctx_destroy(&tctx);
	}
	return (0);
}

static void
dns_tkeyctx_create_test(void **state __attribute__ ((unused))) {
	dns_tkeyctx_t *tctx;

	tctx = NULL;
	will_return(__wrap_isc__mem_get, false);
	assert_int_equal(dns_tkeyctx_create(&mock_mctx, &tctx), ISC_R_NOMEMORY);

	tctx = NULL;
	will_return(__wrap_isc__mem_get, true);
	assert_int_equal(dns_tkeyctx_create(&mock_mctx, &tctx), ISC_R_SUCCESS);
	*state = tctx;
}

static void
dns_tkeyctx_destroy_test(void **state) {
	dns_tkeyctx_t *tctx = *state;
	assert_non_null(tctx);
	dns_tkeyctx_destroy(&tctx);
}

int main(void) {
	int tkey_tests_result = 0;

	const struct CMUnitTest tkey_tests[] = {
		cmocka_unit_test_teardown(dns_tkeyctx_create_test, _teardown),
		/* cmocka_unit_test(dns_tkey_processquery_test), */
		/* cmocka_unit_test(dns_tkey_builddhquery_test), */
		/* cmocka_unit_test(dns_tkey_buildgssquery_test), */
		/* cmocka_unit_test(dns_tkey_builddeletequery_test), */
		/* cmocka_unit_test(dns_tkey_processdhresponse_test), */
		/* cmocka_unit_test(dns_tkey_processgssresponse_test), */
		/* cmocka_unit_test(dns_tkey_processdeleteresponse_test), */
		/* cmocka_unit_test(dns_tkey_gssnegotiate_test), */
		cmocka_unit_test_setup(dns_tkeyctx_destroy_test, _setup),
	};
	tkey_tests_result = cmocka_run_group_tests(tkey_tests, NULL, NULL);

	return (tkey_tests_result);
}
