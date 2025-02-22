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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/transport.h>

#include <tests/dns.h>

ISC_RUN_TEST_IMPL(dns_transport_totext) {
	dns_transport_t *udp = NULL, *tcp = NULL;
	dns_transport_t *tls = NULL, *http = NULL;
	dns_transport_list_t *tlist = NULL;

	tlist = dns_transport_list_new(mctx);
	udp = dns_transport_new(dns_rootname, DNS_TRANSPORT_UDP, tlist);
	tcp = dns_transport_new(dns_rootname, DNS_TRANSPORT_TCP, tlist);
	tls = dns_transport_new(dns_rootname, DNS_TRANSPORT_TLS, tlist);
	http = dns_transport_new(dns_rootname, DNS_TRANSPORT_HTTP, tlist);

	assert_string_equal(dns_transport_totext(dns_transport_get_type(udp)),
			    "udp");
	assert_string_equal(dns_transport_totext(dns_transport_get_type(tcp)),
			    "tcp");
	assert_string_equal(dns_transport_totext(dns_transport_get_type(tls)),
			    "tls");
	assert_string_equal(dns_transport_totext(dns_transport_get_type(http)),
			    "https");

	dns_transport_list_detach(&tlist);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_transport_totext)
ISC_TEST_LIST_END

ISC_TEST_MAIN
