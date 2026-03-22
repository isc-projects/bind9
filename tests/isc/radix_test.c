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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/radix.h>
#include <isc/result.h>
#include <isc/util.h>

#include <tests/isc.h>

static void
prefix_from_str(const char *str, uint16_t bitlen, isc_prefix_t *pfx) {
	struct in_addr in_addr;
	isc_netaddr_t netaddr;

	in_addr.s_addr = inet_addr(str);
	isc_netaddr_fromin(&netaddr, &in_addr);
	NETADDR_TO_PREFIX_T(&netaddr, *pfx, bitlen);
}

static isc_radix_node_t *
insert_prefix(isc_radix_tree_t *radix, const char *str, uint16_t bitlen,
	      void *data) {
	isc_prefix_t pfx;
	isc_radix_node_t *node = NULL;

	prefix_from_str(str, bitlen, &pfx);

	isc_result_t result = isc_radix_insert(radix, &node, NULL, &pfx);
	assert_int_equal(result, ISC_R_SUCCESS);
	node->data[RADIX_V4] = data;

	return node;
}

ISC_RUN_TEST_IMPL(isc_radix_remove) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 32);

	insert_prefix(radix, "1.1.1.1", 32, (void *)1);
	insert_prefix(radix, "1.0.0.0", 8, (void *)2);
	node = insert_prefix(radix, "1.1.1.0", 24, (void *)3);

	isc_radix_remove(radix, node);

	isc_radix_destroy(radix, NULL);
}

ISC_RUN_TEST_IMPL(isc_radix_search) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 32);

	insert_prefix(radix, "3.3.3.0", 24, (void *)1);
	insert_prefix(radix, "3.3.0.0", 16, (void *)2);

	/*
	 * Search for 3.3.3.3/22 -- should match the /16 entry since
	 * 3.3.3.3 falls within 3.3.0.0/16 and the /24 doesn't cover /22.
	 */
	prefix_from_str("3.3.3.3", 22, &pfx);
	isc_result_t result = isc_radix_search(radix, &node, &pfx);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(node->data[RADIX_V4], (void *)2);

	isc_radix_destroy(radix, NULL);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_radix_remove)
ISC_TEST_ENTRY(isc_radix_search)

ISC_TEST_LIST_END
ISC_TEST_MAIN
