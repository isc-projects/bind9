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

#include <stdio.h>
#include <unistd.h>

#include <isc/print.h>

#include <dns/acl.h>
#include "dnstest.h"

/*
 * Helper functions
 */

#define	BUFLEN		255
#define	BIGBUFLEN	(70 * 1024)
#define TEST_ORIGIN	"test"

ATF_TC(dns_acl_isinsecure);
ATF_TC_HEAD(dns_acl_isinsecure, tc) {
	atf_tc_set_md_var(tc, "descr", "test that dns_acl_isinsecure works");
}
ATF_TC_BODY(dns_acl_isinsecure, tc) {
	isc_result_t result;
	dns_acl_t *any = NULL;
	dns_acl_t *none = NULL;
	dns_acl_t *notnone = NULL;
	dns_acl_t *notany = NULL;

	UNUSED(tc);

	result = dns_test_begin(NULL, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_any(mctx, &any);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_none(mctx, &none);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notnone);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notany);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notnone, none, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notany, any, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK(dns_acl_isinsecure(any));		/* any; */
	ATF_CHECK(!dns_acl_isinsecure(none));		/* none; */
	ATF_CHECK(!dns_acl_isinsecure(notany));		/* !any; */
	ATF_CHECK(!dns_acl_isinsecure(notnone));	/* !none; */

	dns_acl_detach(&any);
	dns_acl_detach(&none);
	dns_acl_detach(&notany);
	dns_acl_detach(&notnone);

	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, dns_acl_isinsecure);
	return (atf_no_error());
}
