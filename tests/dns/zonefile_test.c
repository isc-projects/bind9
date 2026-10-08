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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/dir.h> /* Required on GNU/Hurd */
#include <isc/lib.h>

#include <dns/lib.h>
#include <dns/view.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

#include <tests/dns.h>

typedef struct {
	const char *name, *view, *type, *input, *expected;
} zonefile_test_params_t;

static int
setup_test(void **state) {
	setup_loopmgr(state);
	return 0;
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
	return 0;
}

ISC_LOOP_TEST_IMPL(filename) {
	isc_buffer_t b;
	dns_fixedname_t of;
	dns_name_t *origin = dns_fixedname_initname(&of);
	char buf[PATH_MAX];
	const zonefile_test_params_t tests[] = {
		{ "example.COM", "local", "primary", "$name", "example.com" },
		{ "example.COM", "local", "primary", "$name.db",
		  "example.com.db" },
		{ "example.COM", "local", "primary", "./dir/$name.db",
		  "./dir/example.com.db" },
		{ "example.COM", "local", "primary", "%s", "example.com" },
		{ "example.COM", "local", "primary", "%s.db",
		  "example.com.db" },
		{ "example.COM", "local", "primary", "./dir/%s.db",
		  "./dir/example.com.db" },
		{ "example.COM", "local", "primary", "$type", "primary" },
		{ "example.COM", "local", "primary", "$type-file",
		  "primary-file" },
		{ "example.COM", "local", "primary", "./dir/$type",
		  "./dir/primary" },
		{ "example.COM", "local", "secondary", "./dir/$type",
		  "./dir/secondary" },
		{ "example.COM", "local", "primary", "./$type/$name.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "primary", "%t", "primary" },
		{ "example.COM", "local", "primary", "%t-file",
		  "primary-file" },
		{ "example.COM", "local", "primary", "./dir/%t",
		  "./dir/primary" },
		{ "example.COM", "local", "primary", "./%t/%s.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "secondary", "./%t/%s.db",
		  "./secondary/example.com.db" },
		{ "example.COM", "local", "primary", "./$TyPe/$NAmE.db",
		  "./primary/example.com.db" },
		{ "example.COM", "local", "primary", "./$name/$type",
		  "./example.com/primary" },
		{ "example.COM", "local", "primary", "$name.$type",
		  "example.com.primary" },
		{ "example.COM", "local", "primary", "$type$name",
		  "primaryexample.com" },
		{ "example.COM", "local", "primary", "$type$type",
		  "primary$type" },
		{ "example.COM", "local", "primary", "$name$name",
		  "example.com$name" },
		{ "example.COM", "local", "primary", "typename", "typename" },
		{ "example.COM", "local", "primary", "$view", "local" },
		{ "example.COM", NULL, "primary", "$view", "" },
		{ "example.COM", "local", "primary", "%v", "local" },
		{ "example.COM", "local", "primary", "./$type/$view-$name.db",
		  "./primary/local-example.com.db" },
		{ "example.COM", "local", "primary", "./$view/$type-$name.db",
		  "./local/primary-example.com.db" },
		{ "example.COM", "local", "primary", "./$name/$view-$type.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "local", "primary", "./%s/%v-%t.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "local", "primary", "", "" },
		{ "example.COM", "local", "primary", "$char1", "e" },
		{ "example.COM", "local", "primary", "$char2", "x" },
		{ "example.COM", "local", "primary", "$char3", "a" },
		{ "example.COM", "local", "primary", "%1", "e" },
		{ "example.COM", "local", "primary", "%2", "x" },
		{ "example.COM", "local", "primary", "%3", "a" },
		{ "example.COM", "local", "primary", "$label1", "com" },
		{ "example.COM", "local", "primary", "$label2", "example" },
		{ "example.COM", "local", "primary", "$label3", "." },
		{ "example.COM", "local", "primary", "%z", "com" },
		{ "example.COM", "local", "primary", "%y", "example" },
		{ "example.COM", "local", "primary", "%x", "." },
		{ "example", "local", "primary", "$label1", "example" },
		{ "example", "local", "primary", "$label2", "." },
		{ "example", "local", "primary", "$label3", "." },
		{ "a.b.c.d.e", "local", "primary", "$label1", "e" },
		{ "a.b.c.d.e", "local", "primary", "$label2", "d" },
		{ "a.b.c.d.e", "local", "primary", "$label3", "c" },
		{ "a.b.c", "local", "primary", "$char1", "a" },
		{ "a.b.c", "local", "primary", "$char2", "." },
		{ "a.b.c", "local", "primary", "$char3", "b" },
		{ "a.b.c", "local", "primary", "%1", "a" },
		{ "a.b.c", "local", "primary", "%2", "." },
		{ "a.b.c", "local", "primary", "%3", "b" },
		{ "a", "local", "primary", "%1", "a" },
		{ "a", "local", "primary", "%2", "." },
		{ "a", "local", "primary", "%3", "." },
		{ "a.b.c.d", "local", "primary", "%1$char2%3$label1%x",
		  "a.bdb" }
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		isc_buffer_init(&b, buf, sizeof(buf));
		dns_test_namefromstring(tests[i].name, &of);
		dns_zone_expandzonefile(&b, tests[i].input, origin,
					tests[i].view, tests[i].type);
		assert_string_equal(buf, tests[i].expected);
	}

	/* test PATH_MAX overrun */
	char longname[PATH_MAX] = { 0 };
	memset(longname, 'x', sizeof(longname) - 1);

	/*
	 * overwrite the beginning of the long name with $name. when
	 * it's expanded to the zone name, the resulting string should
	 * still be capped at PATH_MAX characters.
	 */
	memmove(longname, "$name", 5);
	assert_int_equal(strlen(longname), PATH_MAX - 1);

	isc_buffer_init(&b, buf, sizeof(buf));
	dns_test_namefromstring("example.COM", &of);
	dns_zone_expandzonefile(&b, longname, origin, "local", "primary");
	memmove(longname, "example.com", 11);
	assert_string_equal(buf, longname);

	isc_loopmgr_shutdown();
}

static unsigned int check_calls[4];

static bool
check_mx(dns_zone_t *zone ISC_ATTR_UNUSED,
	 const dns_name_t *name ISC_ATTR_UNUSED,
	 const dns_name_t *owner ISC_ATTR_UNUSED) {
	check_calls[0]++;
	return true;
}

static bool
check_srv(dns_zone_t *zone ISC_ATTR_UNUSED,
	  const dns_name_t *name ISC_ATTR_UNUSED,
	  const dns_name_t *owner ISC_ATTR_UNUSED) {
	check_calls[1]++;
	return true;
}

static bool
check_ns(dns_zone_t *zone ISC_ATTR_UNUSED,
	 const dns_name_t *name ISC_ATTR_UNUSED,
	 const dns_name_t *owner ISC_ATTR_UNUSED,
	 dns_rdataset_t *a ISC_ATTR_UNUSED,
	 dns_rdataset_t *aaaa ISC_ATTR_UNUSED) {
	check_calls[2]++;
	return true;
}

static bool
check_servedby(dns_zone_t *zone ISC_ATTR_UNUSED,
	       dns_rdatatype_t type ISC_ATTR_UNUSED,
	       const dns_name_t *name ISC_ATTR_UNUSED) {
	check_calls[3]++;
	return true;
}

static bool
check_self(dns_view_t *view ISC_ATTR_UNUSED, dns_tsigkey_t *key ISC_ATTR_UNUSED,
	   const isc_sockaddr_t *src ISC_ATTR_UNUSED,
	   const isc_sockaddr_t *dst ISC_ATTR_UNUSED,
	   dns_rdataclass_t rdclass ISC_ATTR_UNUSED, void *arg) {
	return *(bool *)arg;
}

static void
free_object(isc_mem_t *mctx ISC_ATTR_UNUSED, void **object) {
	(*(unsigned int *)*object)++;
	*object = NULL;
}

ISC_LOOP_TEST_IMPL(callbacks) {
	static const dns_zone_ops_t ops = {
		.checkmx = check_mx,
		.checksrv = check_srv,
		.checkns = check_ns,
		.checkisservedby = check_servedby,
		.isself = check_self,
		.plugins_free = free_object,
		.hooktable_free = free_object,
	};
	static const char contents[] =
		"$TTL 300\n"
		"@ IN SOA ns.example.net. hostmaster 1 3600 600 86400 300\n"
		"@ IN NS ns.example.net.\n"
		"@ IN A 192.0.2.1\n"
		"@ IN MX 10 mail.example.net.\n"
		"_test._tcp IN SRV 0 0 443 srv.example.net.\n"
		"child IN NS ns.example.net.\n";
	UNUSED(arg);

	/* All eight combinations share one table; toggles must be independent.
	 */
	for (unsigned int mask = 0; mask < 8; mask++) {
		dns_zone_t *zone = NULL;
		dns_isselffunc_t isself = NULL;
		void *isselfarg = NULL;
		bool self = true;
		unsigned int freed = 0;
		FILE *stream = tmpfile();
		assert_non_null(stream);
		assert_true(fputs(contents, stream) >= 0);
		rewind(stream);
		assert_int_equal(
			dns_test_makezone("example", &zone, NULL, false),
			ISC_R_SUCCESS);
		dns__zone_getisself(zone, &isself, &isselfarg);
		assert_null(isself);
		dns_zone_setops(zone, &ops);
		dns_zone_setcheckmx(zone, true);
		dns_zone_setchecksrv(zone, true);
		dns_zone_setcheckns(zone, true);
		dns_zone_setcheckmx(zone, (mask & 1) != 0);
		dns_zone_setchecksrv(zone, (mask & 2) != 0);
		dns_zone_setcheckns(zone, (mask & 4) != 0);
		dns_zone_setisself(zone, true, &self);
		dns__zone_getisself(zone, &isself, &isselfarg);
		assert_ptr_equal(isselfarg, &self);
		assert_true(isself(NULL, NULL, NULL, NULL, dns_rdataclass_in,
				   isselfarg));
		dns_zone_setisself(zone, false, NULL);
		isselfarg = NULL;
		dns__zone_getisself(zone, &isself, &isselfarg);
		assert_null(isself);
		assert_null(isselfarg);

		dns_zone_setoption(zone, DNS_ZONEOPT_CHECKINTEGRITY, true);
		dns_zone_setstream(zone, stream, dns_masterformat_text,
				   &dns_master_style_default);
		memset(check_calls, 0, sizeof(check_calls));
		assert_int_equal(dns_zone_load(zone, false), ISC_R_SUCCESS);
		assert_int_equal(check_calls[0] != 0, (mask & 1) != 0);
		assert_int_equal(check_calls[1] != 0, (mask & 2) != 0);
		assert_int_equal(check_calls[2] != 0, (mask & 4) != 0);
		assert_int_equal(check_calls[3] != 0, (mask & 4) != 0);

		dns_zone_sethooktable(zone, &freed);
		dns_zone_setplugins(zone, &freed);
		dns_zone_unloadplugins(zone);
		assert_int_equal(freed, 2);
		dns_zone_unloadplugins(zone);
		assert_int_equal(freed, 2);
		dns_zone_setops(zone, &ops);
		dns_zone_sethooktable(zone, &freed);
		dns_zone_setplugins(zone, &freed);
		dns_zone_detach(&zone);
		assert_int_equal(freed, 4);
		fclose(stream);
	}
	isc_loopmgr_shutdown();
}

static void
assert_endpoint_equal(const isc_sockaddr_t *actual,
		      const isc_sockaddr_t *expected) {
	assert_true(isc_sockaddr_equal(actual, expected));
	assert_int_equal(actual->length, expected->length);
	assert_false(ISC_LINK_LINKED(actual, link));
	if (isc_sockaddr_pf(expected) == PF_INET6) {
		assert_int_equal(actual->type.sin6.sin6_flowinfo,
				 expected->type.sin6.sin6_flowinfo);
	}
}

ISC_LOOP_TEST_IMPL(addresses) {
	dns_zone_t *zone = NULL;
	isc_sockaddr_t addr4, addr6, actual, snapshot;
	struct in_addr in;
	struct in6_addr in6;
	const char *ipv6[] = { "2001:db8::1234", "fe80::1",
			       "::ffff:192.0.2.1" };
	const uint32_t scopes[] = { 0, 42, UINT32_MAX };
	UNUSED(arg);

	assert_int_equal(dns_test_makezone("example", &zone, NULL, false),
			 ISC_R_SUCCESS);

	/* Newly created zones retain the wildcard defaults of both families. */
	isc_sockaddr_any(&addr4);
	isc_sockaddr_any6(&addr6);
	dns_zone_getxfrsource4(zone, &actual);
	assert_endpoint_equal(&actual, &addr4);
	dns_zone_getparentalsrc4(zone, &actual);
	assert_endpoint_equal(&actual, &addr4);
	dns_zone_getxfrsource6(zone, &actual);
	assert_endpoint_equal(&actual, &addr6);
	dns_zone_getparentalsrc6(zone, &actual);
	assert_endpoint_equal(&actual, &addr6);
	dns_zone_setprimaries(zone, &addr4, NULL, NULL, NULL, 1);
	dns_zone_getsourceaddr(zone, &actual);
	assert_int_equal(actual.type.sa.sa_family, AF_UNSPEC);
	assert_int_equal(actual.length, 0);

	assert_int_equal(inet_pton(AF_INET, "192.0.2.123", &in), 1);
	for (size_t i = 0; i < ARRAY_SIZE(ipv6); i++) {
		assert_int_equal(inet_pton(AF_INET6, ipv6[i], &in6), 1);
		isc_sockaddr_fromin(&addr4, &in, 0);
		isc_sockaddr_fromin6(&addr6, &in6, 0);
		addr6.type.sin6.sin6_scope_id = scopes[i];

		dns_zone_setxfrsource4(zone, &addr4);
		dns_zone_setparentalsrc4(zone, &addr4);
		dns_zone_setxfrsource6(zone, &addr6);
		dns_zone_setparentalsrc6(zone, &addr6);
		dns_zone_getxfrsource4(zone, &actual);
		assert_endpoint_equal(&actual, &addr4);
		dns_zone_getparentalsrc4(zone, &actual);
		assert_endpoint_equal(&actual, &addr4);
		dns_zone_getxfrsource6(zone, &actual);
		assert_endpoint_equal(&actual, &addr6);
		dns_zone_getparentalsrc6(zone, &actual);
		assert_endpoint_equal(&actual, &addr6);

		/* Source snapshots preserve overrides across configuration
		 * changes. */
		zone->sourceaddr = zone_addr_fromsockaddr(&addr6);
		dns_zone_getsourceaddr(zone, &snapshot);
		assert_endpoint_equal(&snapshot, &addr6);
		isc_sockaddr_any6(&actual);
		dns_zone_setxfrsource6(zone, &actual);
		dns_zone_getsourceaddr(zone, &actual);
		assert_endpoint_equal(&actual, &snapshot);

		/* Replacing IPv6 with IPv4 must also replace the address
		 * family. */
		zone->sourceaddr = zone_addr_fromsockaddr(&addr4);
		dns_zone_getsourceaddr(zone, &snapshot);
		assert_endpoint_equal(&snapshot, &addr4);
		isc_sockaddr_any(&actual);
		dns_zone_setxfrsource4(zone, &actual);
		dns_zone_getsourceaddr(zone, &actual);
		assert_endpoint_equal(&actual, &snapshot);
	}

	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(notify_addresses) {
	dns_zone_t *zone = NULL;
	isc_sockaddr_t addr4, addr6, actual;
	struct in_addr in;
	struct in6_addr in6;
	const dns_rdatatype_t types[] = { dns_rdatatype_soa,
					  dns_rdatatype_cds };
	UNUSED(arg);

	assert_int_equal(dns_test_makezone("example", &zone, NULL, false),
			 ISC_R_SUCCESS);
	isc_sockaddr_any(&addr4);
	isc_sockaddr_any6(&addr6);
	for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
		dns_notifyctx_t *ctx = dns__zone_getnotifyctx(zone, types[i]);
		actual = zone_addr4_tosockaddr(&ctx->notifysrc4);
		assert_endpoint_equal(&actual, &addr4);
		actual = zone_addr6_tosockaddr(&ctx->notifysrc6);
		assert_endpoint_equal(&actual, &addr6);
	}

	/* Both contexts keep independent IPv4 and scoped IPv6 sources. */
	for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
		assert_int_equal(inet_pton(AF_INET,
					   i == 0 ? "192.0.2.1" : "192.0.2.2",
					   &in),
				 1);
		assert_int_equal(inet_pton(AF_INET6, "fe80::1", &in6), 1);
		isc_sockaddr_fromin(&addr4, &in, 0);
		isc_sockaddr_fromin6(&addr6, &in6, 0);
		addr6.type.sin6.sin6_scope_id = i == 0 ? 42 : UINT32_MAX;
		dns_zone_setnotifysrc4(zone, types[i], &addr4);
		dns_zone_setnotifysrc6(zone, types[i], &addr6);
	}
	for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
		dns_notifyctx_t *ctx = dns__zone_getnotifyctx(zone, types[i]);
		assert_int_equal(inet_pton(AF_INET,
					   i == 0 ? "192.0.2.1" : "192.0.2.2",
					   &in),
				 1);
		isc_sockaddr_fromin(&addr4, &in, 0);
		addr6.type.sin6.sin6_scope_id = i == 0 ? 42 : UINT32_MAX;
		actual = zone_addr4_tosockaddr(&ctx->notifysrc4);
		assert_endpoint_equal(&actual, &addr4);
		actual = zone_addr6_tosockaddr(&ctx->notifysrc6);
		assert_endpoint_equal(&actual, &addr6);
	}
	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(filename, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(callbacks, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(addresses, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(notify_addresses, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
