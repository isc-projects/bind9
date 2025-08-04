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
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/lib.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/unreachcache.h>

#include <tests/dns.h>

#define EXPIRE_MIN_S	  5
#define EXPIRE_MAX_S	  10
#define BACKOFF_ELGIBLE_S 5

ISC_LOOP_TEST_IMPL(basic) {
	dns_unreachcache_t *uc = NULL;
	struct in_addr localhost4 = { 0 };
	isc_sockaddr_t src_addrv4 = { 0 }, dst_addrv4 = { 0 },
		       src_addrv6 = { 0 }, dst_addrv6 = { 0 };
	const uint16_t src_port = 1234;
	const uint16_t dst_port = 5678;
	isc_result_t result;

	isc_sockaddr_fromin(&src_addrv4, &localhost4, src_port);
	isc_sockaddr_fromin(&dst_addrv4, &localhost4, dst_port);
	isc_sockaddr_fromin6(&src_addrv6, &in6addr_loopback, src_port);
	isc_sockaddr_fromin6(&dst_addrv6, &in6addr_loopback, dst_port);

	uc = dns_unreachcache_new(isc_g_mctx, EXPIRE_MIN_S, EXPIRE_MAX_S,
				  BACKOFF_ELGIBLE_S);
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);
	dns_unreachcache_add(uc, &dst_addrv6, &src_addrv6);

	/* Added but unconfirmed (at least another add required to confirm). */
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_NOTFOUND);
	result = dns_unreachcache_find(uc, &dst_addrv6, &src_addrv6);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* Confirmed. */
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);
	dns_unreachcache_add(uc, &dst_addrv6, &src_addrv6);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_unreachcache_find(uc, &dst_addrv6, &src_addrv6);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Removal. */
	dns_unreachcache_remove(uc, &dst_addrv6, &src_addrv6);
	result = dns_unreachcache_find(uc, &dst_addrv6, &src_addrv6);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* Swapped addresses, should be not found. */
	result = dns_unreachcache_find(uc, &src_addrv4, &dst_addrv4);
	assert_int_equal(result, ISC_R_NOTFOUND);
	result = dns_unreachcache_find(uc, &src_addrv6, &dst_addrv6);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_unreachcache_destroy(&uc);

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(expire) {
	dns_unreachcache_t *uc = NULL;
	struct in_addr localhost4 = { 0 };
	isc_sockaddr_t src_addrv4 = { 0 }, dst_addrv4 = { 0 };
	const uint16_t src_port = 1234;
	const uint16_t dst_port = 5678;
	isc_result_t result;

	isc_sockaddr_fromin(&src_addrv4, &localhost4, src_port);
	isc_sockaddr_fromin(&dst_addrv4, &localhost4, dst_port);

	uc = dns_unreachcache_new(isc_g_mctx, EXPIRE_MIN_S, EXPIRE_MAX_S,
				  BACKOFF_ELGIBLE_S);
	/* Two adds to "confirm" the addition. */
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);

	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);

	sleep(1);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);

	sleep(EXPIRE_MIN_S);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * Because of the exponentatl backoff, the new quick addition after the
	 * previous expiration should expire in 2 x EXPIRE_MIN_S seconds.
	 */
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);

	sleep(1);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);

	sleep(EXPIRE_MIN_S);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);

	sleep(EXPIRE_MIN_S);
	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_unreachcache_destroy(&uc);

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(flush) {
	dns_unreachcache_t *uc = NULL;
	struct in_addr localhost4 = { 0 };
	isc_sockaddr_t src_addrv4 = { 0 }, dst_addrv4 = { 0 };
	const uint16_t src_port = 1234;
	const uint16_t dst_port = 5678;
	isc_result_t result;

	isc_sockaddr_fromin(&src_addrv4, &localhost4, src_port);
	isc_sockaddr_fromin(&dst_addrv4, &localhost4, dst_port);

	uc = dns_unreachcache_new(isc_g_mctx, EXPIRE_MIN_S, EXPIRE_MAX_S,
				  BACKOFF_ELGIBLE_S);
	/* Two adds to "confirm" the addition. */
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);
	dns_unreachcache_add(uc, &dst_addrv4, &src_addrv4);

	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_unreachcache_flush(uc);

	result = dns_unreachcache_find(uc, &dst_addrv4, &src_addrv4);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_unreachcache_destroy(&uc);

	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(basic, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(expire, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(flush, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
