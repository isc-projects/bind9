/*
 * Copyright (C) 2013, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

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

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, getoriginnode);
	return (atf_no_error());
}
