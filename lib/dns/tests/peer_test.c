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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/util.h>

#include <dns/peer.h>

#include <dns/test.h>

/* Test DSCP set/get functions */
ISC_RUN_TEST_IMPL(dscp) {
	isc_result_t result;
	isc_netaddr_t netaddr;
	struct in_addr ina;
	dns_peer_t *peer = NULL;
	isc_dscp_t dscp;

	/*
	 * Create peer structure for the loopback address.
	 */
	ina.s_addr = INADDR_LOOPBACK;
	isc_netaddr_fromin(&netaddr, &ina);
	result = dns_peer_new(mctx, &netaddr, &peer);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * All should be not set on creation.
	 * 'dscp' should remain unchanged.
	 */
	dscp = 100;
	result = dns_peer_getquerydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	result = dns_peer_getnotifydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	result = dns_peer_gettransferdscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	/*
	 * Test that setting query dscp does not affect the other
	 * dscp values.  'dscp' should remain unchanged until
	 * dns_peer_getquerydscp is called.
	 */
	dscp = 100;
	result = dns_peer_setquerydscp(peer, 1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_peer_getnotifydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	result = dns_peer_gettransferdscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	result = dns_peer_getquerydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 1);

	/*
	 * Test that setting notify dscp does not affect the other
	 * dscp values.  'dscp' should remain unchanged until
	 * dns_peer_getquerydscp is called then should change again
	 * on dns_peer_getnotifydscp.
	 */
	dscp = 100;
	result = dns_peer_setnotifydscp(peer, 2);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_peer_gettransferdscp(peer, &dscp);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(dscp, 100);

	result = dns_peer_getquerydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 1);

	result = dns_peer_getnotifydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 2);

	/*
	 * Test that setting notify dscp does not affect the other
	 * dscp values.  Check that appropriate values are returned.
	 */
	dscp = 100;
	result = dns_peer_settransferdscp(peer, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_peer_getquerydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 1);

	result = dns_peer_getnotifydscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 2);

	result = dns_peer_gettransferdscp(peer, &dscp);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dscp, 3);

	dns_peer_detach(&peer);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(dscp)

ISC_TEST_LIST_END

ISC_TEST_MAIN
