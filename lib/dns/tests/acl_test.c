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

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <isc/print.h>
#include <isc/string.h>

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
#ifdef HAVE_GEOIP
	dns_acl_t *geoip = NULL;
	dns_acl_t *notgeoip = NULL;
	dns_aclelement_t *de;
#endif

	UNUSED(tc);

	result = dns_test_begin(NULL, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_any(mctx, &any);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_none(mctx, &none);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notnone);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notany);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notnone, none, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notany, any, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

#ifdef HAVE_GEOIP
	result = dns_acl_create(mctx, 1, &geoip);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	de = geoip->elements;
	ATF_REQUIRE(de != NULL);
	strlcpy(de->geoip_elem.as_string, "AU",
		sizeof(de->geoip_elem.as_string));
	de->geoip_elem.subtype = dns_geoip_country_code;
	de->type = dns_aclelementtype_geoip;
	de->negative = false;
	ATF_REQUIRE(geoip->length < geoip->alloc);
	geoip->node_count++;
	de->node_num = geoip->node_count;
	geoip->length++;

	result = dns_acl_create(mctx, 1, &notgeoip);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notgeoip, geoip, false);
#endif

	ATF_CHECK(dns_acl_isinsecure(any));		/* any; */
	ATF_CHECK(!dns_acl_isinsecure(none));		/* none; */
	ATF_CHECK(!dns_acl_isinsecure(notany));		/* !any; */
	ATF_CHECK(!dns_acl_isinsecure(notnone));	/* !none; */

#ifdef HAVE_GEOIP
	ATF_CHECK(dns_acl_isinsecure(geoip));		/* geoip; */
	ATF_CHECK(!dns_acl_isinsecure(notgeoip));	/* !geoip; */
#endif

	dns_acl_detach(&any);
	dns_acl_detach(&none);
	dns_acl_detach(&notany);
	dns_acl_detach(&notnone);
#ifdef HAVE_GEOIP
	dns_acl_detach(&geoip);
	dns_acl_detach(&notgeoip);
#endif

	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, dns_acl_isinsecure);
	return (atf_no_error());
}
