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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/acl.h>

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
#define	BIGBUFLEN	(70 * 1024)
#define TEST_ORIGIN	"test"

/* test that dns_acl_isinsecure works */
static void
dns_acl_isinsecure_test(void **state) {
	isc_result_t result;
	unsigned int pass;
	struct {
		bool first;
		bool second;
	} ecs[] = {
		{ false, false },
		{ true, true },
		{ true, false },
		{ false, true }
	};

	dns_acl_t *any = NULL;
	dns_acl_t *none = NULL;
	dns_acl_t *notnone = NULL;
	dns_acl_t *notany = NULL;
#if defined(HAVE_GEOIP) || defined(HAVE_GEOIP2)
	dns_acl_t *geoip = NULL;
	dns_acl_t *notgeoip = NULL;
	dns_aclelement_t *de;
#endif /* HAVE_GEOIP || HAVE_GEOIP2 */
	dns_acl_t *pos4pos6 = NULL;
	dns_acl_t *notpos4pos6 = NULL;
	dns_acl_t *neg4pos6 = NULL;
	dns_acl_t *notneg4pos6 = NULL;
	dns_acl_t *pos4neg6 = NULL;
	dns_acl_t *notpos4neg6 = NULL;
	dns_acl_t *neg4neg6 = NULL;
	dns_acl_t *notneg4neg6 = NULL;

	dns_acl_t *loop4 = NULL;
	dns_acl_t *notloop4 = NULL;

	dns_acl_t *loop6 = NULL;
	dns_acl_t *notloop6 = NULL;

	dns_acl_t *loop4pos6 = NULL;
	dns_acl_t *notloop4pos6 = NULL;
	dns_acl_t *loop4neg6 = NULL;
	dns_acl_t *notloop4neg6 = NULL;

	struct in_addr inaddr;
	isc_netaddr_t addr;

	UNUSED(state);

	result = dns_acl_any(mctx, &any);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_none(mctx, &none);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notnone);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_create(mctx, 1, &notany);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notnone, none, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notany, any, false);
	assert_int_equal(result, ISC_R_SUCCESS);

#if defined(HAVE_GEOIP) || defined(HAVE_GEOIP2)
	result = dns_acl_create(mctx, 1, &geoip);
	assert_int_equal(result, ISC_R_SUCCESS);

	de = geoip->elements;
	assert_non_null(de);
	strlcpy(de->geoip_elem.as_string, "AU",
		sizeof(de->geoip_elem.as_string));
	de->geoip_elem.subtype = dns_geoip_country_code;
	de->type = dns_aclelementtype_geoip;
	de->negative = false;
	assert_true(geoip->length < geoip->alloc);
	dns_acl_node_count(geoip)++;
	de->node_num = dns_acl_node_count(geoip);
	geoip->length++;

	result = dns_acl_create(mctx, 1, &notgeoip);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notgeoip, geoip, false);
	assert_int_equal(result, ISC_R_SUCCESS);
#endif /* HAVE_GEOIP || HAVE_GEOIP2 */

	assert_true(dns_acl_isinsecure(any));		/* any; */
	assert_false(dns_acl_isinsecure(none));		/* none; */
	assert_false(dns_acl_isinsecure(notany));	/* !any; */
	assert_false(dns_acl_isinsecure(notnone));	/* !none; */

#if defined(HAVE_GEOIP) || defined(HAVE_GEOIP2)
	assert_true(dns_acl_isinsecure(geoip));		/* geoip; */
	assert_false(dns_acl_isinsecure(notgeoip));	/* !geoip; */
#endif /* HAVE_GEOIP || HAVE_GEOIP2 */

	dns_acl_detach(&any);
	dns_acl_detach(&none);
	dns_acl_detach(&notany);
	dns_acl_detach(&notnone);
#if defined(HAVE_GEOIP) || defined(HAVE_GEOIP2)
	dns_acl_detach(&geoip);
	dns_acl_detach(&notgeoip);
#endif /* HAVE_GEOIP || HAVE_GEOIP2 */

	for (pass = 0; pass < sizeof(ecs)/sizeof(ecs[0]); pass++) {
		result = dns_acl_create(mctx, 1, &pos4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notpos4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &neg4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notneg4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &pos4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notpos4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &neg4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notneg4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x0a000000);	/* 10.0.0.0 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(pos4pos6->iptable, &addr, 8,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* 0a00:: */
		result = dns_iptable_addprefix2(pos4pos6->iptable, &addr, 8,
						true, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notpos4pos6, pos4pos6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x0a000000);	/* !10.0.0.0/8 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(neg4pos6->iptable, &addr, 8,
						false, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* 0a00::/8 */
		result = dns_iptable_addprefix2(neg4pos6->iptable, &addr, 8,
						true, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notneg4pos6, neg4pos6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x0a000000);	/* 10.0.0.0/8 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(pos4neg6->iptable, &addr, 8,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* !0a00::/8 */
		result = dns_iptable_addprefix2(pos4neg6->iptable, &addr, 8,
						false, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notpos4neg6, pos4neg6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x0a000000);	/* !10.0.0.0/8 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(neg4neg6->iptable, &addr, 8,
						false, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* !0a00::/8 */
		result = dns_iptable_addprefix2(neg4neg6->iptable, &addr, 8,
						false, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notneg4neg6, neg4neg6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		assert_true(dns_acl_isinsecure(pos4pos6));
		assert_false(dns_acl_isinsecure(notpos4pos6));
		assert_true(dns_acl_isinsecure(neg4pos6));
		assert_false(dns_acl_isinsecure(notneg4pos6));
		assert_true(dns_acl_isinsecure(pos4neg6));
		assert_false(dns_acl_isinsecure(notpos4neg6));
		assert_false(dns_acl_isinsecure(neg4neg6));
		assert_false(dns_acl_isinsecure(notneg4neg6));

		dns_acl_detach(&pos4pos6);
		dns_acl_detach(&notpos4pos6);
		dns_acl_detach(&neg4pos6);
		dns_acl_detach(&notneg4pos6);
		dns_acl_detach(&pos4neg6);
		dns_acl_detach(&notpos4neg6);
		dns_acl_detach(&neg4neg6);
		dns_acl_detach(&notneg4neg6);

		result = dns_acl_create(mctx, 1, &loop4);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notloop4);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &loop6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notloop6);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(loop4->iptable, &addr, 32,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notloop4, loop4, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_netaddr_fromin6(&addr, &in6addr_loopback);	/* ::1 */
		result = dns_iptable_addprefix2(loop6->iptable, &addr, 128,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notloop6, loop6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		if (!ecs[pass].first) {
			assert_false(dns_acl_isinsecure(loop4));
			assert_false(dns_acl_isinsecure(notloop4));
			assert_false(dns_acl_isinsecure(loop6));
			assert_false(dns_acl_isinsecure(notloop6));
		} else if (ecs[pass].first) {
			assert_true(dns_acl_isinsecure(loop4));
			assert_false(dns_acl_isinsecure(notloop4));
			assert_true(dns_acl_isinsecure(loop6));
			assert_false(dns_acl_isinsecure(notloop6));
		}

		dns_acl_detach(&loop4);
		dns_acl_detach(&notloop4);
		dns_acl_detach(&loop6);
		dns_acl_detach(&notloop6);

		result = dns_acl_create(mctx, 1, &loop4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notloop4pos6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &loop4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_create(mctx, 1, &notloop4neg6);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(loop4pos6->iptable, &addr, 32,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* f700:0001::/32 */
		result = dns_iptable_addprefix2(loop4pos6->iptable, &addr, 32,
						true, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notloop4pos6, loop4pos6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		inaddr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
		isc_netaddr_fromin(&addr, &inaddr);
		result = dns_iptable_addprefix2(loop4neg6->iptable, &addr, 32,
						true, ecs[pass].first);
		assert_int_equal(result, ISC_R_SUCCESS);

		addr.family = AF_INET6;			/* !f700:0001::/32 */
		result = dns_iptable_addprefix2(loop4neg6->iptable, &addr, 32,
						false, ecs[pass].second);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_acl_merge(notloop4neg6, loop4neg6, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		if (!ecs[pass].first && !ecs[pass].second) {
			assert_true(dns_acl_isinsecure(loop4pos6));
			assert_false(dns_acl_isinsecure(notloop4pos6));
			assert_false(dns_acl_isinsecure(loop4neg6));
			assert_false(dns_acl_isinsecure(notloop4neg6));
		} else if (ecs[pass].first && !ecs[pass].second) {
			assert_true(dns_acl_isinsecure(loop4pos6));
			assert_false(dns_acl_isinsecure(notloop4pos6));
			assert_true(dns_acl_isinsecure(loop4neg6));
			assert_false(dns_acl_isinsecure(notloop4neg6));
		} else if (!ecs[pass].first && ecs[pass].second) {
			assert_true(dns_acl_isinsecure(loop4pos6));
			assert_false(dns_acl_isinsecure(notloop4pos6));
			assert_false(dns_acl_isinsecure(loop4neg6));
			assert_false(dns_acl_isinsecure(notloop4neg6));
		} else {
			assert_true(dns_acl_isinsecure(loop4pos6));
			assert_false(dns_acl_isinsecure(notloop4pos6));
			assert_true(dns_acl_isinsecure(loop4neg6));
			assert_false(dns_acl_isinsecure(notloop4neg6));
		}

		dns_acl_detach(&loop4pos6);
		dns_acl_detach(&notloop4pos6);
		dns_acl_detach(&loop4neg6);
		dns_acl_detach(&notloop4neg6);
	}
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(dns_acl_isinsecure_test,
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
