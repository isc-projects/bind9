/*
 * Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <unistd.h>

#include <isc/event.h>
#include <isc/print.h>
#include <isc/task.h>

#include <dns/acl.h>
#include <dns/rcode.h>
#include <dns/view.h>

#include <ns/client.h>
#include <ns/notify.h>

#include "nstest.h"

static dns_zone_t *zone = NULL;
static dns_view_t *view = NULL;

/*
 * Helper functions
 */
static void
setup_zone(const char *zonename, const char *filename) {
	isc_result_t result;
	dns_db_t *db = NULL;

	result = ns_test_makezone(zonename, &zone, NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	result = ns_test_setupzonemgr();
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	result = ns_test_managezone(zone);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	view = dns_zone_getview(zone);
	ATF_REQUIRE(view->zonetable != NULL);
	view->nocookieudp = 512;

	dns_zone_setfile(zone, filename);
	result = dns_zone_load(zone);
	ATF_REQUIRE(result == ISC_R_SUCCESS);

	/* The zone should now be loaded; test it */
	result = dns_zone_getdb(zone, &db);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	ATF_CHECK(db != NULL);
	if (db != NULL) {
		dns_db_detach(&db);
	}
}

static void
cleanup_zone() {
	ns_test_releasezone(zone);
	ns_test_closezonemgr();

	dns_zone_detach(&zone);
	dns_view_detach(&view);
}

static void
check_response(isc_buffer_t *buf) {
	isc_result_t result;
	dns_message_t *message = NULL;
	char rcodebuf[20];
	isc_buffer_t b;

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, buf, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_buffer_init(&b, rcodebuf, sizeof(rcodebuf));
	result = dns_rcode_totext(message->rcode, &b);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	ATF_CHECK_EQ(message->rcode, dns_rcode_noerror);

	dns_message_destroy(&message);
}

ATF_TC(notify_start);
ATF_TC_HEAD(notify_start, tc) {
	atf_tc_set_md_var(tc, "descr", "notify start");
}
ATF_TC_BODY(notify_start, tc) {
	isc_result_t result;
	ns_client_t *client = NULL;
	dns_message_t *nmsg = NULL;
	unsigned char ndata[4096];
	isc_buffer_t nbuf;
	size_t nsize;

	UNUSED(tc);

	result = ns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = ns_test_getclient(NULL, ISC_FALSE, &client);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	setup_zone("example.com", "testdata/notify/zone1.db");

	/*
	 * Create a NOTIFY message by parsing a file in testdata.
	 * (XXX: use better message mocking method when available.)
	 */

	result = ns_test_getdata("testdata/notify/notify1.msg",
				  ndata, sizeof(ndata), &nsize);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_init(&nbuf, ndata, nsize);
	isc_buffer_add(&nbuf, nsize);

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &nmsg);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(nmsg, &nbuf, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/*
	 * Set up client object with this message and test the NOTIFY
	 * handler.
	 */
	dns_view_attach(view, &client->view);
	if (client->message != NULL) {
		dns_message_destroy(&client->message);
	}
	client->message = nmsg;
	nmsg = NULL;
	client->sendcb = check_response;
	ns_notify_start(client);

	/*
	 * Clean up
	 */
	cleanup_zone();

	ns_client_detach(&client);

	ns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, notify_start);
	return (atf_no_error());
}
