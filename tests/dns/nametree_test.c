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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/md.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/nametree.h>

#include <dst/dst.h>

#include <tests/dns.h>

dns_nametree_t *nametree = NULL;

/*
 * Test utilities.  In general, these assume input parameters are valid
 * (checking with assert_int_equal, thus aborting if not) and unlikely run time
 * errors (such as memory allocation failure) won't happen.  This helps keep
 * the test code concise.
 */

/* Common setup: create a nametree to test with a few keys */
static void
create_tables(void) {
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_name(&fn);

	dns_nametree_create(mctx, "test", &nametree);

	/* Add a positive node */
	dns_test_namefromstring("example.com.", &fn);
	assert_int_equal(dns_nametree_add(nametree, name, true), ISC_R_SUCCESS);

	/* Add a negative node below it */
	dns_test_namefromstring("negative.example.com.", &fn);
	assert_int_equal(dns_nametree_add(nametree, name, false),
			 ISC_R_SUCCESS);

	/* Add a negative node with no parent */
	dns_test_namefromstring("negative.example.org.", &fn);
	assert_int_equal(dns_nametree_add(nametree, name, false),
			 ISC_R_SUCCESS);
}

static void
destroy_tables(void) {
	if (nametree != NULL) {
		dns_nametree_detach(&nametree);
	}
	rcu_barrier();
}

ISC_RUN_TEST_IMPL(add) {
	dns_ntnode_t *node = NULL;
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_name(&fn);

	create_tables();

	/*
	 * Getting the node for example.com should succeed.
	 */
	dns_test_namefromstring("example.com.", &fn);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_SUCCESS);
	dns_ntnode_detach(&node);

	/*
	 * Try to add the same name.  This should fail.
	 */
	assert_int_equal(dns_nametree_add(nametree, name, false), ISC_R_EXISTS);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_SUCCESS);
	dns_ntnode_detach(&node);

	/*
	 * Try to add a new name.
	 */
	dns_test_namefromstring("newname.com.", &fn);
	assert_int_equal(dns_nametree_add(nametree, name, true), ISC_R_SUCCESS);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_SUCCESS);
	dns_ntnode_detach(&node);

	destroy_tables();
}

ISC_RUN_TEST_IMPL(delete) {
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_name(&fn);

	create_tables();

	/* name doesn't match */
	dns_test_namefromstring("example.org.", &fn);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_NOTFOUND);

	/* subdomain match is the same as no match */
	dns_test_namefromstring("sub.example.org.", &fn);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_NOTFOUND);

	/*
	 * delete requires exact match: this should return SUCCESS on
	 * the first try, then NOTFOUND on the second even though an
	 * ancestor does exist.
	 */
	dns_test_namefromstring("negative.example.com.", &fn);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_SUCCESS);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_NOTFOUND);

	dns_test_namefromstring("negative.example.org.", &fn);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_SUCCESS);
	assert_int_equal(dns_nametree_delete(nametree, name), ISC_R_NOTFOUND);

	destroy_tables();
}

ISC_RUN_TEST_IMPL(find) {
	dns_ntnode_t *node = NULL;
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_name(&fn);

	create_tables();

	/*
	 * dns_nametree_find() requires exact name match.  It matches node
	 * that has a null key, too.
	 */
	dns_test_namefromstring("example.org.", &fn);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_NOTFOUND);
	dns_test_namefromstring("sub.example.com.", &fn);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_NOTFOUND);
	dns_test_namefromstring("example.com.", &fn);
	assert_int_equal(dns_nametree_find(nametree, name, &node),
			 ISC_R_SUCCESS);
	dns_ntnode_detach(&node);

	destroy_tables();
}

ISC_RUN_TEST_IMPL(covered) {
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_name(&fn);
	const char *yesnames[] = { "example.com.", "sub.example.com.", NULL };
	const char *nonames[] = { "whatever.com.", "negative.example.com.",
				  "example.org.", "negative.example.org.",
				  NULL };
	create_tables();

	for (const char **n = yesnames; *n != NULL; n++) {
		dns_test_namefromstring(*n, &fn);
		assert_true(dns_nametree_covered(nametree, name));
	}
	for (const char **n = nonames; *n != NULL; n++) {
		dns_test_namefromstring(*n, &fn);
		assert_false(dns_nametree_covered(nametree, name));
	}

	/* If nametree is NULL, dns_nametree_covered() returns false. */
	dns_test_namefromstring("anyname.example.", &fn);
	assert_false(dns_nametree_covered(NULL, name));

	destroy_tables();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(add)
ISC_TEST_ENTRY(covered)
ISC_TEST_ENTRY(find)
ISC_TEST_ENTRY(delete)
ISC_TEST_LIST_END

ISC_TEST_MAIN
