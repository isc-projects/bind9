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

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <unistd.h>
#include <stdlib.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/name.h>
#include <dns/journal.h>

#include "dnstest.h"

/*
 * Helper functions
 */

#define	BUFLEN		255
#define	BIGBUFLEN	(64 * 1024)
#define TEST_ORIGIN	"test"

/*
 * Individual unit tests
 */

ATF_TC(getoriginnode);
ATF_TC_HEAD(getoriginnode, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test multiple calls to dns_db_getoriginnode");
}
ATF_TC_BODY(getoriginnode, tc) {
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	isc_mem_t *mymctx = NULL;
	isc_result_t result;

	result = isc_mem_create(0, 0, &mymctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = isc_hash_create(mymctx, NULL, 256);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mymctx, "rbt", dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_getoriginnode(db, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	dns_db_detachnode(db, &node);

	result = dns_db_getoriginnode(db, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	dns_db_detachnode(db, &node);

	dns_db_detach(&db);
	isc_mem_detach(&mymctx);
}

ATF_TC(class);
ATF_TC_HEAD(class, tc) {
	atf_tc_set_md_var(tc, "descr", "database class");
}
ATF_TC_BODY(class, tc) {
	isc_result_t result;
	dns_db_t *db = NULL;

	result = dns_test_begin(NULL, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_load(db, "testdata/db/data.db");
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK_EQ(dns_db_class(db), dns_rdataclass_in);

	dns_db_detach(&db);
}

ATF_TC(dbtype);
ATF_TC_HEAD(dbtype, tc) {
	atf_tc_set_md_var(tc, "descr", "database type");
}
ATF_TC_BODY(dbtype, tc) {
	isc_result_t result;
	dns_db_t *db = NULL;

	result = dns_test_begin(NULL, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* DB has zone semantics */
	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	result = dns_db_load(db, "testdata/db/data.db");
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(dns_db_iszone(db));
	ATF_CHECK(!dns_db_iscache(db));
	dns_db_detach(&db);

	/* DB has cache semantics */
	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	result = dns_db_load(db, "testdata/db/data.db");
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(dns_db_iscache(db));
	ATF_CHECK(!dns_db_iszone(db));
	dns_db_detach(&db);

	dns_test_end();
}

ATF_TC(version);
ATF_TC_HEAD(version, tc) {
	atf_tc_set_md_var(tc, "descr", "database versions");
}
ATF_TC_BODY(version, tc) {
	isc_result_t result;
	dns_fixedname_t fname, ffound;
	dns_name_t *name, *foundname;
	dns_db_t *db = NULL;
	dns_dbversion_t *ver = NULL, *new = NULL;
	dns_dbnode_t *node = NULL;
	dns_rdataset_t rdataset;

	result = dns_test_begin(NULL, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "test.test",
				 "testdata/db/data.db");
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Open current version for reading */
	dns_db_currentversion(db, &ver);
	dns_test_namefromstring("b.test.test", &fname);
	name = dns_fixedname_name(&fname);
	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name , ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &ver, ISC_FALSE);

	/* Open new version for writing */
	dns_db_currentversion(db, &ver);
	dns_test_namefromstring("b.test.test", &fname);
	name = dns_fixedname_name(&fname);
	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name , ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_newversion(db, &new);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Delete the rdataset from the new verison */
	result = dns_db_deleterdataset(db, node, new, dns_rdatatype_a, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);

	/* This should fail now */
	result = dns_db_find(db, name, new, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NXDOMAIN);

	dns_db_closeversion(db, &new, ISC_TRUE);

	/* But this should still succeed */
	result = dns_db_find(db, name, ver, dns_rdatatype_a, 0, 0, &node,
			     foundname, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	dns_rdataset_disassociate(&rdataset);
	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &ver, ISC_FALSE);

	dns_db_detach(&db);
	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, getoriginnode);
	ATF_TP_ADD_TC(tp, class);
	ATF_TP_ADD_TC(tp, dbtype);
	ATF_TP_ADD_TC(tp, version);

	return (atf_no_error());
}
