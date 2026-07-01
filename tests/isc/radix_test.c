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
	isc_prefix_from_netaddr(pfx, &netaddr, bitlen);
}

static void
prefix6_from_str(const char *str, uint16_t bitlen, isc_prefix_t *pfx) {
	struct in6_addr in6;
	isc_netaddr_t netaddr;

	assert_int_equal(inet_pton(AF_INET6, str, &in6), 1);
	isc_netaddr_fromin6(&netaddr, &in6);
	isc_prefix_from_netaddr(pfx, &netaddr, bitlen);
}

static isc_radix_node_t *
insert_v4(isc_radix_tree_t *radix, const char *str, uint16_t bitlen,
	  isc_radix_match_t match) {
	isc_prefix_t pfx;
	isc_radix_node_t *node = NULL;

	prefix_from_str(str, bitlen, &pfx);
	isc_radix_insert(radix, &node, NULL, &pfx);
	node->match[RADIX_V4] = match;

	return node;
}

static isc_radix_node_t *
insert_v6(isc_radix_tree_t *radix, const char *str, uint16_t bitlen,
	  isc_radix_match_t match) {
	isc_prefix_t pfx;
	isc_radix_node_t *node = NULL;

	prefix6_from_str(str, bitlen, &pfx);
	isc_radix_insert(radix, &node, NULL, &pfx);
	node->match[RADIX_V6] = match;

	return node;
}

/* Search an empty tree. */
ISC_RUN_TEST_IMPL(radix_search_empty) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	prefix_from_str("10.0.0.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_NOTFOUND);

	isc_radix_destroy(radix);
}

/* Search miss in a populated tree. */
ISC_RUN_TEST_IMPL(radix_search_miss) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);

	prefix_from_str("192.168.1.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_NOTFOUND);

	isc_radix_destroy(radix);
}

/* Exact match: insert only one prefix, search for it exactly. */
ISC_RUN_TEST_IMPL(radix_search_exact) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);

	prefix_from_str("10.1.0.0", 16, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_DENY);

	isc_radix_destroy(radix);
}

/*
 * First-match wins over best-match: even though /16 is more specific,
 * the /8 was inserted first and wins.
 */
ISC_RUN_TEST_IMPL(radix_search_best_match) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);

	/* 10.1.2.3/32 matches both /8 and /16, but /8 was first. */
	prefix_from_str("10.1.2.3", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	isc_radix_destroy(radix);
}

/*
 * First-match semantics: when multiple prefixes match, the one that
 * was inserted first (lowest node_num) wins.
 */
ISC_RUN_TEST_IMPL(radix_first_match) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	/* Insert /8 first, then /16. Both match 10.1.2.3. */
	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);

	/*
	 * Search with /8 bitlen -- both /8 and /16 entries have
	 * prefixes that match within 8 bits, but /8 was inserted
	 * first so it should win.
	 */
	prefix_from_str("10.1.0.0", 8, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	isc_radix_destroy(radix);
}

/* Duplicate insert: same prefix should preserve the first match value. */
ISC_RUN_TEST_IMPL(radix_duplicate_insert) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);

	/* Second insert of same prefix returns the existing node. */
	isc_radix_node_t *dup = NULL;
	prefix_from_str("10.0.0.0", 8, &pfx);
	isc_radix_insert(radix, &dup, NULL, &pfx);
	/* The match value should be unchanged (first insert wins). */
	assert_int_equal(dup->match[RADIX_V4], RADIX_ALLOW);

	prefix_from_str("10.0.0.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	isc_radix_destroy(radix);
}

/* IPv6 prefix insert and search. */
ISC_RUN_TEST_IMPL(radix_ipv6) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v6(radix, "2001:db8::", 32, RADIX_ALLOW);
	insert_v6(radix, "2001:db8:1::", 48, RADIX_DENY);

	/* First-match: /32 was inserted first, so it wins. */
	prefix6_from_str("2001:db8:1::1", 128, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V6], RADIX_ALLOW);

	/* Address outside the prefixes. */
	node = NULL;
	prefix6_from_str("2001:db9::1", 128, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_NOTFOUND);

	isc_radix_destroy(radix);
}

/*
 * Remove a leaf node: the node has no children, so it and its
 * glue parent (if any) should be freed.
 */
ISC_RUN_TEST_IMPL(radix_remove_leaf) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	isc_radix_node_t *leaf = insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);

	isc_radix_remove(radix, leaf);

	/* The /8 should still be findable. */
	prefix_from_str("10.0.0.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	/* The /16 should be gone. */
	node = NULL;
	prefix_from_str("10.1.0.1", 16, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	/* Should match the /8, not the removed /16. */
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	isc_radix_destroy(radix);
}

/*
 * Remove a node with two children: the node is converted to a
 * glue node (prefix cleared) but stays in the tree.
 */
ISC_RUN_TEST_IMPL(radix_remove_internal) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	isc_radix_node_t *mid = insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);
	insert_v4(radix, "10.1.1.0", 24, RADIX_ALLOW);

	/* Remove the /16 which sits between /8 and /24. */
	isc_radix_remove(radix, mid);

	/* The /24 should still be reachable. */
	prefix_from_str("10.1.1.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	/* A search for the /16 range should now fall back to /8. */
	node = NULL;
	prefix_from_str("10.1.2.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_SUCCESS);
	assert_int_equal(node->match[RADIX_V4], RADIX_ALLOW);

	isc_radix_destroy(radix);
}

/* Remove the only node in the tree. */
ISC_RUN_TEST_IMPL(radix_remove_root) {
	isc_radix_tree_t *radix = NULL;
	isc_radix_node_t *node = NULL;
	isc_prefix_t pfx;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	isc_radix_node_t *root = insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	isc_radix_remove(radix, root);

	prefix_from_str("10.0.0.1", 32, &pfx);
	assert_int_equal(isc_radix_search(radix, &node, &pfx), ISC_R_NOTFOUND);

	isc_radix_destroy(radix);
}

/* Test isc_radix_foreach iteration. */
static void
count_nodes(isc_radix_node_t *node, void *arg) {
	UNUSED(node);
	int *count = arg;
	(*count)++;
}

ISC_RUN_TEST_IMPL(radix_foreach) {
	isc_radix_tree_t *radix = NULL;
	int count = 0;

	UNUSED(state);

	isc_radix_create(isc_g_mctx, &radix, 128);

	insert_v4(radix, "10.0.0.0", 8, RADIX_ALLOW);
	insert_v4(radix, "10.1.0.0", 16, RADIX_DENY);
	insert_v4(radix, "192.168.0.0", 16, RADIX_ALLOW);

	isc_radix_foreach(radix, count_nodes, &count);
	assert_int_equal(count, 3);

	isc_radix_destroy(radix);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(radix_search_empty)
ISC_TEST_ENTRY(radix_search_miss)
ISC_TEST_ENTRY(radix_search_exact)
ISC_TEST_ENTRY(radix_search_best_match)
ISC_TEST_ENTRY(radix_first_match)
ISC_TEST_ENTRY(radix_duplicate_insert)
ISC_TEST_ENTRY(radix_ipv6)
ISC_TEST_ENTRY(radix_remove_leaf)
ISC_TEST_ENTRY(radix_remove_internal)
ISC_TEST_ENTRY(radix_remove_root)
ISC_TEST_ENTRY(radix_foreach)

ISC_TEST_LIST_END
ISC_TEST_MAIN
