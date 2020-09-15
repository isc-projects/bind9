/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <config.h>

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <sched.h> /* IWYU pragma: keep */
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/print.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/name.h>
#include <dns/journal.h>

#include "dnstest.h"

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dns_test_begin(NULL, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	dns_test_end();

	return (0);
}

#define	BUFLEN		255
#define	BIGBUFLEN	(64 * 1024)
#define TEST_ORIGIN	"test"

/*
 * Individual unit tests
 */

/* test multiple calls to dns_db_getoriginnode */
static void
getoriginnode_test(void **state) {
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	isc_mem_t *mymctx = NULL;
	isc_result_t result;

	UNUSED(state);

	result = isc_mem_create(0, 0, &mymctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_create(mymctx, "rbt", dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_getoriginnode(db, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_db_detachnode(db, &node);

	result = dns_db_getoriginnode(db, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_db_detachnode(db, &node);

	dns_db_detach(&db);
	isc_mem_detach(&mymctx);
}

/* database class */
static void
class_test(void **state) {
	isc_result_t result;
	dns_db_t *db = NULL;

	UNUSED(state);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_load(db, "testdata/db/data.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(dns_db_class(db), dns_rdataclass_in);

	dns_db_detach(&db);
}

/* database type */
static void
dbtype_test(void **state) {
	isc_result_t result;
	dns_db_t *db = NULL;

	UNUSED(state);

	/* DB has zone semantics */
	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_db_load(db, "testdata/db/data.db");
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(dns_db_iszone(db));
	assert_false(dns_db_iscache(db));
	dns_db_detach(&db);

	/* DB has cache semantics */
	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_db_load(db, "testdata/db/data.db");
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(dns_db_iscache(db));
	assert_false(dns_db_iszone(db));
	dns_db_detach(&db);

}

/* database versions */
static void
version_test(void **state) {
	isc_result_t result;
	dns_fixedname_t fname, ffound;
	dns_name_t *name, *foundname;
	dns_db_t *db = NULL;
	dns_dbversion_t *ver = NULL, *new = NULL;
	dns_dbnode_t *node = NULL;
	dns_rdataset_t rdataset;

	UNUSED(state);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "test.test",
				 "testdata/db/data.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Open current version for reading */
	dns_db_currentversion(db, &ver);
	dns_test_namefromstring("b.test.test", &fname);
	name = dns_fixedname_name(&fname);
	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name , ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &ver, false);

	/* Open new version for writing */
	dns_db_currentversion(db, &ver);
	dns_test_namefromstring("b.test.test", &fname);
	name = dns_fixedname_name(&fname);
	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name , ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_newversion(db, &new);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Delete the rdataset from the new version */
	result = dns_db_deleterdataset(db, node, new, dns_rdatatype_a, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);

	/* This should fail now */
	result = dns_db_find(db, name, new, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	assert_int_equal(result, DNS_R_NXDOMAIN);

	dns_db_closeversion(db, &new, true);

	/* But this should still succeed */
	result = dns_db_find(db, name, ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &ver, false);

	dns_db_detach(&db);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(getoriginnode_test),
		cmocka_unit_test_setup_teardown(class_test,
						_setup, _teardown),
		cmocka_unit_test_setup_teardown(dbtype_test,
						_setup, _teardown),
		cmocka_unit_test_setup_teardown(version_test,
						_setup, _teardown),
	};

	return (cmocka_run_group_tests(tests, dns_test_init, dns_test_final));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
