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
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

/*
 * Mock isc_stdtime_now() as it makes testing easier (to compare
 * generated/expected deleg data).
 */
static uint32_t stdtime_now = 100;

static uint32_t
isc_stdtime_now(void) {
	return stdtime_now;
}

#include <isc/lib.h>
#include <isc/list.h>
#include <isc/loop.h>
#include <isc/netaddr.h>
#include <isc/stdtime.h>
#include <isc/urcu.h>

#include <dns/deleg.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>

/*
 * Because of the mock above.
 */
#include "../dns/deleg.c"

#include <tests/isc.h>

/*
 * cleanuptests adds NENTRIES address entries to a delegset; each is an
 * isc_netaddrlink_t whose size depends on sizeof(void *) via ISC_LINK.
 * Express memory expectations in terms of that struct so the test works
 * on both 32-bit and 64-bit targets.
 */
#define NENTRIES       99999
#define ENTRIES_MEM(n) ((size_t)(n) * sizeof(isc_netaddrlink_t))

static void
shutdownloop(ISC_ATTR_UNUSED void *arg) {
	isc_loopmgr_shutdown();
}

static void
shutdowntest(dns_delegdb_t **dbp) {
	dns_delegdb_detach(dbp);
	shutdownloop(NULL);
}

static void
rundelegtest(isc_job_cb testcb) {
	isc_loopmgr_create(isc_g_mctx, 1);

	isc_loop_setup(isc_loop_main(), testcb, NULL);
	isc_loopmgr_run();

	isc_loopmgr_destroy();
}

static void
addnamedeleg(const char *addrstr, dns_delegset_t *delegset, dns_deleg_t *deleg,
	     void (*fn)(dns_delegset_t *, dns_deleg_t *, const dns_name_t *)) {
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);

	dns_name_fromstring(name, addrstr, NULL, 0, NULL);
	fn(delegset, deleg, name);
}

static void
addipdeleg(unsigned int af, const char *addrstr, dns_delegset_t *delegset,
	   dns_deleg_t *deleg) {
	isc_netaddr_t addr = { .family = af };

	assert_true(af == AF_INET || af == AF_INET6);
	assert_int_equal(inet_pton(af, addrstr, &addr.type), 1);
	dns_delegset_addaddr(delegset, deleg, &addr);
}

static void
writedb(dns_delegdb_t *db, const char *zonecutstr, dns_ttl_t expire,
	dns_delegset_t **delegsetp, bool expectsuccess) {
	dns_fixedname_t fzonecut;
	dns_name_t *zonecut = dns_fixedname_initname(&fzonecut);
	isc_result_t result;

	dns_name_fromstring(zonecut, zonecutstr, NULL, 0, NULL);
	result = dns_delegset_insert(db, zonecut, expire, *delegsetp);

	dns_delegset_detach(delegsetp);
	assert_null(*delegsetp);

	if (expectsuccess) {
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		assert_int_equal(result, ISC_R_EXISTS);
	}
}

static isc_result_t
lookupdb(dns_delegdb_t *db, const char *namestr, isc_stdtime_t now,
	 unsigned int options, const char *expectedzcstr,
	 dns_delegset_t **delegsetp) {
	isc_result_t result;
	dns_fixedname_t fname, fexpectedzc, fzonecut;
	dns_name_t *name = dns_fixedname_initname(&fname),
		   *expectedzc = dns_fixedname_initname(&fexpectedzc),
		   *zonecut = dns_fixedname_initname(&fzonecut);

	if (expectedzcstr != NULL) {
		dns_name_fromstring(expectedzc, expectedzcstr, NULL, 0, NULL);
	}
	dns_name_fromstring(name, namestr, NULL, 0, NULL);
	result = dns_delegdb_lookup(db, name, now, options, zonecut, NULL,
				    delegsetp);

	if (result == ISC_R_SUCCESS) {
		assert_non_null(*delegsetp);
		assert_non_null(expectedzcstr);
		assert_true(dns_name_equal(zonecut, expectedzc));
	} else {
		assert_null(*delegsetp);
	}

	return result;
}

static void
dumpdb(dns_delegdb_t *db, bool expired, const char *expected) {
	constexpr char *filename = "delegdb-dump-test.db";
	char buffer[1024 * 4] = { 0 };
	FILE *fp = fopen(filename, "w+");

	REQUIRE(fp != NULL);
	dns_delegdb_dump(db, expired, fp);

	fp = freopen(filename, "r", fp);
	REQUIRE(fp != NULL);
	REQUIRE(fread(buffer, sizeof(buffer) - 1, 1, fp) == 0);

	if (expected != NULL) {
		assert_string_equal(expected, buffer);
	}

	REQUIRE(fclose(fp) == 0);
	REQUIRE(unlink(filename) == 0);
}

static void
basictests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();

	dns_delegdb_create(&db);
	assert_non_null(db);

	/*
	 * A non expired delegation for foo. zonecut
	 */
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.foo.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_GLUES, &deleg);
	addipdeleg(AF_INET, "1.2.3.4", delegset, deleg);
	addipdeleg(AF_INET6, "1111:2222:3333::4444", delegset, deleg);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_NAMES, &deleg);
	assert_non_null(deleg);
	addnamedeleg("ns.example.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;
	writedb(db, "foo.", 30, &delegset, true);

	result = lookupdb(db, "baz.bar.gee.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.foo.", 0, 0, "foo.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	/*
	 * A non expired delegation for bar.foo. zonecut
	 */
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_NAMES, &deleg);
	addnamedeleg("ns.bar.foo.", delegset, deleg, dns_delegset_addns);
	addnamedeleg("ns2.bar.foo.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_GLUES, &deleg);
	addipdeleg(AF_INET, "8.9.10.11", delegset, deleg);
	addipdeleg(AF_INET, "9.9.10.12", delegset, deleg);
	addipdeleg(AF_INET6, "ACDC::ACDC", delegset, deleg);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "ABBA::ABBA", delegset, deleg);
	addipdeleg(AF_INET, "13.14.15.16", delegset, deleg);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_PARAMS, &deleg);
	addnamedeleg("delegns.gee.", delegset, deleg,
		     dns_delegset_adddelegparam);
	addnamedeleg("delegns2.gee.", delegset, deleg,
		     dns_delegset_adddelegparam);
	deleg = NULL;

	writedb(db, "bar.foo.", 25, &delegset, true);

	result = lookupdb(db, "baz.bar.gee.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.foo.", 0, 0, "bar.foo.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	/*
	 * A expired delegation for bar.stuff. zonecut
	 */
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_GLUES, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	deleg = NULL;

	writedb(db, "bar.stuff.", 10, &delegset, true);
	deleg = NULL;

	result = lookupdb(db, "baz.bar.stuff.", now + 10, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * But, if we ask for a date before its expiration, it is visible. And
	 * it is possible to dump it as well. But of course the dump when
	 * expired won't get anythig.
	 */
	result = lookupdb(db, "baz.bar.stuff.", now + 9, 0, "bar.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	/*
	 * A non expired delegation for bar.stuff. zonecut replace the expired
	 * one. Move the time forward 10 to make the entry expired.
	 */
	stdtime_now += 10;
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_GLUES, &deleg);
	addipdeleg(AF_INET6, "1111::3333", delegset, deleg);
	deleg = NULL;

	writedb(db, "bar.stuff.", 2, &delegset, true);

	/*
	 * Attempt to override bar.stuff. even though the existing delegation is
	 * not expired. This will be rejected.
	 */
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("wontbeindb.bar.stuff.", delegset, deleg,
		     dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "acdc::acdc", delegset, deleg);
	deleg = NULL;

	writedb(db, "bar.stuff.", 2, &delegset, false);
	deleg = NULL;

	result = lookupdb(db, "stuff.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "idonotknowthis.at.all.stuff.", 0, 0, "",
			  &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.stuff.", 0, 0, "bar.stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	char expected_dbdump[] =
		"foo. 20 DELEG server-name=ns.foo.\n"
		"foo. 20 DELEG server-ipv4=1.2.3.4 "
		"server-ipv6=1111:2222:3333::4444\n"
		"foo. 20 DELEG server-name=ns.example.\n"
		"bar.foo. 15 DELEG server-name=ns.bar.foo.,ns2.bar.foo.\n"
		"bar.foo. 15 DELEG server-ipv4=8.9.10.11,9.9.10.12 "
		"server-ipv6=acdc::acdc\n"
		"bar.foo. 15 DELEG server-ipv4=13.14.15.16 "
		"server-ipv6=abba::abba\n"
		"bar.foo. 15 DELEG "
		"include-delegparam=delegns.gee.,delegns2.gee.\n"
		"bar.stuff. 2 DELEG server-name=ns.bar.stuff.\n"
		"bar.stuff. 2 DELEG server-ipv6=1111::3333\n";
	dumpdb(db, false, expected_dbdump);

	/*
	 * Dump in the "future", everything is seen as expired
	 */
	stdtime_now += 300;
	dumpdb(db, false, "");

	/*
	 * Bump if we ask to dump expired entries, they'll be there (with TTL 0)
	 */
	char expected_expired_dbdump[] =
		"foo. 0 DELEG server-name=ns.foo.\n"
		"foo. 0 DELEG server-ipv4=1.2.3.4 "
		"server-ipv6=1111:2222:3333::4444\n"
		"foo. 0 DELEG server-name=ns.example.\n"
		"bar.foo. 0 DELEG server-name=ns.bar.foo.,ns2.bar.foo.\n"
		"bar.foo. 0 DELEG server-ipv4=8.9.10.11,9.9.10.12 "
		"server-ipv6=acdc::acdc\n"
		"bar.foo. 0 DELEG server-ipv4=13.14.15.16 "
		"server-ipv6=abba::abba\n"
		"bar.foo. 0 DELEG "
		"include-delegparam=delegns.gee.,delegns2.gee.\n"
		"bar.stuff. 0 DELEG server-name=ns.bar.stuff.\n"
		"bar.stuff. 0 DELEG server-ipv6=1111::3333\n";
	dumpdb(db, true, expected_expired_dbdump);

	shutdowntest(&db);
}

static void
ttltests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_buffer_t b;
	char bdata[2048];

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_delegdb_create(&db);
	assert_non_null(db);

	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	deleg = NULL;

	writedb(db, "bar.stuff.", 0, &delegset, true);
	deleg = NULL;

	/*
	 * This is possible because delegdb internally forces TTL of 1 if the
	 * caller TTL is 0, in the case of the minttl config is disabled.
	 */
	result = lookupdb(db, "baz.bar.stuff.", now, 0, "bar.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	result = lookupdb(db, "baz.bar.stuff.", now + 1, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_delegdb_setconfig(db, &(dns_delegdb_config_t){ .minttl = 60 });
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.gee.bar.stuff.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "3333::2222", delegset, deleg);
	deleg = NULL;

	writedb(db, "gee.bar.stuff.", 2, &delegset, true);
	deleg = NULL;

	result = lookupdb(db, "gee.bar.stuff.", now + 59, 0, "gee.bar.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	result = lookupdb(db, "gee.bar.stuff.", now + 61, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_delegdb_setconfig(db, &(dns_delegdb_config_t){ .maxttl = 160 });
	dns_delegset_allocset(db, &delegset);

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns.gee.", delegset, deleg, dns_delegset_addns);
	deleg = NULL;

	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "4444::2222", delegset, deleg);
	deleg = NULL;

	writedb(db, "gee.", 200, &delegset, true);
	deleg = NULL;

	result = lookupdb(db, "gee.", now + 159, 0, "gee.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	result = lookupdb(db, "gee.", now + 200, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	shutdowntest(&db);
}

static void
noexacttests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_buffer_t b;
	char bdata[2048];

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_delegdb_create(&db);
	assert_non_null(db);

	struct {
		const char *name;
		const char *expected;
		const char *noexactexpected;
		isc_result_t noexactresult;
		dns_ttl_t ttl;
	} zonecuts[] = {
		/*
		 * "stuff." has no proper ancestor in the trie, so a
		 * NOEXACT lookup must return NOTFOUND rather than the
		 * exact match itself.
		 */
		{ "stuff.", "stuff.", NULL, ISC_R_NOTFOUND, 30 },
		{ "foo.stuff.", "foo.stuff.", "stuff.", ISC_R_SUCCESS, 30 },
		{ "expired.foo.stuff.", "foo.stuff.", "foo.stuff.",
		  ISC_R_SUCCESS, 1 },
		{ "bar.expired.foo.stuff.", "bar.expired.foo.stuff.",
		  "foo.stuff.", ISC_R_SUCCESS, 30 },
		{ "baz.bar.expired.foo.stuff.", "baz.bar.expired.foo.stuff.",
		  "bar.expired.foo.stuff.", ISC_R_SUCCESS, 30 }
	};

	for (size_t i = 0; i < ARRAY_SIZE(zonecuts); i++) {
		dns_delegset_allocset(db, &delegset);
		dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_NS_GLUES,
					&deleg);
		addipdeleg(AF_INET6, "1111::1111", delegset, deleg);
		writedb(db, zonecuts[i].name, zonecuts[i].ttl, &delegset, true);
		deleg = NULL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(zonecuts); i++) {
		result = lookupdb(db, zonecuts[i].name, now + 1, 0,
				  zonecuts[i].expected, &delegset);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_delegset_detach(&delegset);

		result = lookupdb(db, zonecuts[i].name, now + 1,
				  DNS_DBFIND_ABOVE, zonecuts[i].noexactexpected,
				  &delegset);
		assert_int_equal(result, zonecuts[i].noexactresult);
		if (result == ISC_R_SUCCESS) {
			dns_delegset_detach(&delegset);
		}
	}

	result = lookupdb(db, "gee.expired.foo.stuff.", now + 1, 0,
			  "foo.stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	shutdowntest(&db);
}

static void
deletetests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);

	dns_delegdb_create(&db);
	assert_non_null(db);

	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "stuff.", 10, &delegset, true);
	deleg = NULL;

	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "baz.stuff.", 10, &delegset, true);
	deleg = NULL;

	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "bar.baz.stuff.", 10, &delegset, true);
	deleg = NULL;

	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "foo.bar.baz.stuff.", 10, &delegset, true);
	deleg = NULL;

	dns_name_fromstring(name, "foo.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);
	result = dns_delegdb_delete(db, name, true);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "gee.foo.bar.stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "foo.bar.baz.stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_name_fromstring(name, "foo.bar.baz.stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "baz.stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "bar.baz.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	dns_name_fromstring(name, "stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_name_fromstring(name, "stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "bar.baz.stuff.", NULL, 0, NULL);
	result = dns_delegdb_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "bar.baz.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * Let's add stuff. back and query bar.baz.stuff. again. Because the
	 * node is NULL, it should go up until it finds stuff.
	 */
	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "stuff.", 10, &delegset, true);
	deleg = NULL;

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	shutdowntest(&db);
}

static void
cleanuptests(ISC_ATTR_UNUSED void *arg) {
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now;
	isc_result_t result;

	/*
	 * hiwater is 4375000 = 5000000 - (5000000 >> 3)
	 * lowater is 3750000 = 5000000 - (5000000 >> 2)
	 */
	dns_delegdb_config_t config = { .dbsize = 5000000 };

	dns_delegdb_create(&db);
	assert_non_null(db);

	now = isc_stdtime_now();

	dns_delegdb_setconfig(db, &config);

	/*
	 * A valid record
	 */
	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "baz.", 300, &delegset, true);
	deleg = NULL;

	/*
	 * An expired record
	 */
	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);

	assert_int_in_range(isc_mem_inuse(db->mctx), 500, 2000);

	for (size_t i = 0; i < NENTRIES; i++) {
		addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	}

	assert_int_in_range(isc_mem_inuse(db->mctx), ENTRIES_MEM(NENTRIES),
			    ENTRIES_MEM(NENTRIES) + 100000);

	writedb(db, "stuff.", 10, &delegset, true);
	deleg = NULL;
	stdtime_now += 10;

	/*
	 * A non expired record
	 */
	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);

	for (size_t i = 0; i < NENTRIES; i++) {
		addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	}

	/*
	 * The zonecut is not added yet but the delegset being huge (allocated
	 * with DB mem context) overmem conditions will be detected, and the
	 * expired node will be removed
	 */
	assert_int_in_range(isc_mem_inuse(db->mctx), ENTRIES_MEM(2 * NENTRIES),
			    ENTRIES_MEM(2 * NENTRIES) + 100000);
	writedb(db, "bar.", 30, &delegset, true);
	deleg = NULL;

	/*
	 * stuff. internal node (and delegset) is now removed.  Node
	 * destruction runs synchronously inside the QP-trie chunk reclamation,
	 * so rcu_barrier() is enough: once it returns, the evicted nodes have
	 * been detached and freed.
	 */
	rcu_barrier();

	assert_int_in_range(isc_mem_inuse(db->mctx), ENTRIES_MEM(NENTRIES),
			    ENTRIES_MEM(NENTRIES) + 100000);

	/*
	 * bar. is there
	 */
	result = lookupdb(db, "bar.", now, 0, "bar.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	/*
	 * Add yet another non expired record. But LRU will have to get
	 * rid of it because we're hitting the hiwater mark again.
	 */
	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_ADDRESSES,
				&deleg);

	for (size_t i = 0; i < NENTRIES; i++) {
		addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	}
	assert_int_in_range(isc_mem_inuse(db->mctx), ENTRIES_MEM(2 * NENTRIES),
			    ENTRIES_MEM(2 * NENTRIES) + 100000);
	writedb(db, "baz.", 30, &delegset, true);
	deleg = NULL;

	/*
	 * Re-adding baz. hit the hiwater mark and evicted bar.; wait for the
	 * reclamation to free it before checking memory and final state.
	 */
	rcu_barrier();

	assert_int_in_range(isc_mem_inuse(db->mctx), ENTRIES_MEM(2 * NENTRIES),
			    ENTRIES_MEM(2 * NENTRIES) + 100000);

	/*
	 * baz. is there, but bar. is gone, as it has been
	 * removed (even if it wasn't expired.)
	 */
	result = lookupdb(db, "baz.", now, 0, "baz.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	result = lookupdb(db, "bar.", now, 0, "bar.", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	shutdowntest(&db);
}

static void
longnametests(ISC_ATTR_UNUSED void *arg) {
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;

	dns_delegdb_create(&db);
	assert_non_null(db);

	dns_delegset_allocset(db, &delegset);
	dns_delegset_allocdeleg(delegset, DNS_DELEGTYPE_DELEG_NAMES, &deleg);
	addnamedeleg("ns."
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037."
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037."
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		     "\037\037\037\037\037.",
		     delegset, deleg, dns_delegset_addns);
	writedb(db,
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037."
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037."
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037\037\037\037\037\037\037\037\037\037"
		"\037\037\037\037\037.",
		10, &delegset, true);

	/*
	 * `dns_name_totext()` doesn't seems to apply the master zone escape
	 * format, so the actual output wouldn't be the same. But the point of
	 * the test is that we can run the dump code without overflow (with
	 * address sanatizer enabled).
	 */
	dumpdb(db, false, NULL);

	shutdowntest(&db);
}

ISC_RUN_TEST_IMPL(dns_deleg_basictests) { rundelegtest(basictests); }
ISC_RUN_TEST_IMPL(dns_deleg_ttltests) { rundelegtest(ttltests); }
ISC_RUN_TEST_IMPL(dns_deleg_noexacttests) { rundelegtest(noexacttests); }
ISC_RUN_TEST_IMPL(dns_deleg_deletetests) { rundelegtest(deletetests); }
ISC_RUN_TEST_IMPL(dns_deleg_cleanuptests) { rundelegtest(cleanuptests); }
ISC_RUN_TEST_IMPL(dns_deleg_longnametests) { rundelegtest(longnametests); }

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_deleg_basictests)
ISC_TEST_ENTRY(dns_deleg_ttltests)
ISC_TEST_ENTRY(dns_deleg_noexacttests)
ISC_TEST_ENTRY(dns_deleg_deletetests)
ISC_TEST_ENTRY(dns_deleg_cleanuptests)
ISC_TEST_ENTRY(dns_deleg_longnametests)
ISC_TEST_LIST_END

ISC_TEST_MAIN
