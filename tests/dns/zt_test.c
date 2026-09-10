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
#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/sockaddr.h>
#include <isc/timer.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/forward.h>
#include <dns/keytable.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zoneproperties.h>
#include <dns/zt.h>

#include <tests/dns.h>

static dns_db_t *db = NULL;
static FILE *zonefile, *origfile;
static dns_view_t *view = NULL;

static int
teardown_test(void **state) {
	teardown_managers(state);
	dns_test_destroyzonemgr();
	return 0;
}

static isc_result_t
count_zone(dns_zone_t *zone, void *uap) {
	int *nzones = (int *)uap;

	UNUSED(zone);

	*nzones += 1;
	return ISC_R_SUCCESS;
}

/* Covering lookups return the closest origin without attaching a zone. */
ISC_LOOP_TEST_IMPL(covers) {
	dns_fixedname_t qname, found, expected;
	dns_name_t *name = dns_fixedname_initname(&qname);
	dns_name_t *foundname = dns_fixedname_initname(&found);
	dns_name_t *expectedname = dns_fixedname_initname(&expected);
	dns_zone_t *zones[2] = { NULL, NULL };
	dns_zt_t *zt = NULL;
	const struct {
		const char *name;
		const char *origin;
		isc_result_t result;
	} cases[] = {
		{ "example.", "example.", ISC_R_SUCCESS },
		{ "child.example.", "child.example.", ISC_R_SUCCESS },
		{ "www.child.example.", "child.example.", DNS_R_PARTIALMATCH },
		{ "sibling.example.", "example.", DNS_R_PARTIALMATCH },
		{ "unrelated.", ".", ISC_R_NOTFOUND },
		{ ".", ".", ISC_R_NOTFOUND },
	};

	assert_int_equal(dns_test_makeview("view", false, false, &view),
			 ISC_R_SUCCESS);
	dns_zt_create(view->mctx, view, &zt);
	dns_test_namefromstring("example.", &qname);
	dns_name_copy(dns_rootname, foundname);
	assert_int_equal(dns_zt_covers(zt, name, foundname), ISC_R_NOTFOUND);
	assert_true(dns_name_isroot(foundname));
	assert_false(dns_zt_contains(zt, name));

	assert_int_equal(dns_test_makezone("example", &zones[0], NULL, false),
			 ISC_R_SUCCESS);
	assert_int_equal(
		dns_test_makezone("child.example", &zones[1], NULL, false),
		ISC_R_SUCCESS);
	for (size_t i = 0; i < ARRAY_SIZE(zones); i++) {
		assert_int_equal(dns_zt_mount(zt, zones[i]), ISC_R_SUCCESS);
	}

	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		dns_test_namefromstring(cases[i].name, &qname);
		dns_test_namefromstring(cases[i].origin, &expected);
		dns_name_copy(dns_rootname, foundname);
		assert_int_equal(dns_zt_covers(zt, name, foundname),
				 cases[i].result);
		assert_true(dns_name_equal(foundname, expectedname));
		assert_int_equal(dns_zt_contains(zt, name),
				 cases[i].result == ISC_R_SUCCESS);
	}

	/* The copied origin remains valid after removing its zone. */
	dns_test_namefromstring("www.child.example.", &qname);
	assert_int_equal(dns_zt_covers(zt, name, foundname),
			 DNS_R_PARTIALMATCH);
	assert_int_equal(dns_zt_unmount(zt, zones[1]), ISC_R_SUCCESS);
	dns_zone_detach(&zones[1]);
	dns_test_namefromstring("child.example.", &expected);
	assert_true(dns_name_equal(foundname, expectedname));
	assert_int_equal(dns_zt_covers(zt, name, foundname),
			 DNS_R_PARTIALMATCH);
	assert_true(dns_name_equal(foundname, dns_zone_getorigin(zones[0])));

	assert_int_equal(dns_zt_unmount(zt, zones[0]), ISC_R_SUCCESS);
	dns_zone_detach(&zones[0]);
	dns_zt_detach(&zt);
	dns_view_detach(&view);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(sfd_forward_only_deepest) {
	dns_fixedname_t child, found, parent, qname;
	dns_name_t *childname = dns_fixedname_initname(&child);
	dns_name_t *name = dns_fixedname_initname(&qname);
	dns_name_t *namespace = dns_fixedname_initname(&found);
	dns_name_t *parentname = dns_fixedname_initname(&parent);
	isc_sockaddrlist_t addrs;
	isc_result_t result;
	dns_fwdpolicy_t policy = dns_fwdpolicy_none;

	result = dns_test_makeview("view", false, false, &view);
	assert_int_equal(result, ISC_R_SUCCESS);

	ISC_LIST_INIT(addrs);

	dns_test_namefromstring("example.", &parent);
	dns_test_namefromstring("child.example.", &child);

	result = dns_fwdtable_add(view->fwdtable, parentname, &addrs,
				  dns_fwdpolicy_only);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_fwdtable_add(view->fwdtable, childname, &addrs,
				  dns_fwdpolicy_first);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_fwdtable_covers(view->fwdtable, parentname, namespace,
				     &policy);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(dns_name_equal(namespace, parentname));
	assert_int_equal(policy, dns_fwdpolicy_only);

	result = dns_fwdtable_covers(view->fwdtable, childname, namespace,
				     &policy);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(dns_name_equal(namespace, childname));
	assert_int_equal(policy, dns_fwdpolicy_first);

	dns_test_namefromstring("unrelated.", &qname);
	result = dns_fwdtable_covers(view->fwdtable, name, namespace, &policy);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_true(dns_name_equal(namespace, childname));
	assert_int_equal(policy, dns_fwdpolicy_first);

	dns_test_namefromstring("www.child.example.", &qname);
	result = dns_fwdtable_covers(view->fwdtable, name, namespace, &policy);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_true(dns_name_equal(namespace, childname));
	assert_int_equal(policy, dns_fwdpolicy_first);
	assert_int_equal(dns_fwdtable_covers(view->fwdtable, name, NULL, NULL),
			 DNS_R_PARTIALMATCH);
	policy = dns_fwdpolicy_none;
	assert_int_equal(
		dns_fwdtable_covers(view->fwdtable, name, NULL, &policy),
		DNS_R_PARTIALMATCH);
	assert_int_equal(policy, dns_fwdpolicy_first);
	assert_int_equal(
		dns_fwdtable_covers(view->fwdtable, name, namespace, NULL),
		DNS_R_PARTIALMATCH);
	assert_true(dns_name_equal(namespace, childname));

	dns_view_sfd_find(view, name, namespace);
	assert_true(dns_name_equal(namespace, parentname));

	dns_view_detach(&view);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(sfd_secroots_boundary) {
	dns_fixedname_t anchor, found, qname;
	dns_name_t *anchorname = dns_fixedname_initname(&anchor);
	dns_name_t *name = dns_fixedname_initname(&qname);
	dns_name_t *namespace = dns_fixedname_initname(&found);
	dns_keytable_t *secroots = NULL;
	isc_result_t result;

	result = dns_test_makeview("view", false, false, &view);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_view_initsecroots(view);
	result = dns_view_getsecroots(view, &secroots);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_test_namefromstring("secure.example.", &anchor);
	result = dns_keytable_marksecure(secroots, anchorname);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_keytable_detach(&secroots);

	dns_test_namefromstring("www.secure.example.", &qname);
	dns_view_sfd_find(view, name, namespace);
	assert_true(dns_name_equal(namespace, anchorname));

	dns_view_detach(&view);
	isc_loopmgr_shutdown();
}

/* apply a function to a zone table */
ISC_LOOP_TEST_IMPL(apply) {
	isc_result_t result;
	dns_zone_t *zone = NULL;
	dns_zt_t *zt = NULL;
	int nzones = 0;

	result = dns_test_makezone("foo", &zone, NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	view = dns_zone_getview(zone);
	rcu_read_lock();
	zt = rcu_dereference(view->zonetable);
	rcu_read_unlock();

	assert_non_null(zt);

	assert_int_equal(nzones, 0);
	result = dns_view_apply(view, false, NULL, count_zone, &nzones);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(nzones, 1);

	/* The view was left attached in dns_test_makezone() */
	dns_view_detach(&view);
	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

static isc_result_t
load_done_last(void *uap) {
	dns_zone_t *zone = uap;
	isc_result_t result;

	/* The zone should now be loaded; test it */
	result = dns_zone_getdb(zone, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_non_null(db);
	if (db != NULL) {
		dns_db_detach(&db);
	}

	dns_test_closezonemgr();

	dns_zone_detach(&zone);
	dns_view_detach(&view);

	isc_loopmgr_shutdown();

	return ISC_R_SUCCESS;
}

static isc_result_t
load_done_new_only(void *uap) {
	dns_zone_t *zone = uap;
	isc_result_t result;

	/* The zone should now be loaded; test it */
	result = dns_zone_getdb(zone, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_db_detach(&db);

	dns_zone_asyncload(zone, true, load_done_last, zone);

	return ISC_R_SUCCESS;
}

static isc_result_t
load_done_first(void *uap) {
	dns_zone_t *zone = uap;
	isc_result_t result;

	/* The zone should now be loaded; test it */
	result = dns_zone_getdb(zone, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_db_detach(&db);

	/*
	 * Add something to zone file, reload zone with newonly - it should
	 * not be reloaded.
	 */
	fprintf(zonefile, "\nb in b 1.2.3.4\n");
	fflush(zonefile);
	fclose(zonefile);

	dns_zone_asyncload(zone, true, load_done_new_only, zone);

	return ISC_R_SUCCESS;
}

/* asynchronous zone load */
ISC_LOOP_TEST_IMPL(asyncload_zone) {
	dns_test_setupzonemgr();
	isc_result_t result;
	int n;
	dns_zone_t *zone = NULL;
	dns_zt_t *zt = NULL;
	char buf[4096];

	result = dns_test_makezone("foo", &zone, NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	view = dns_zone_getview(zone);
	rcu_read_lock();
	zt = rcu_dereference(view->zonetable);
	rcu_read_unlock();
	assert_non_null(zt);

	assert_false(dns__zone_loadpending(zone));
	zonefile = fopen("./zone.data", "wb");
	assert_non_null(zonefile);
	origfile = fopen(TESTS_DIR "/testdata/zt/zone1.db", "r+b");
	assert_non_null(origfile);
	n = fread(buf, 1, 4096, origfile);
	fclose(origfile);
	fwrite(buf, 1, n, zonefile);
	fflush(zonefile);

	dns_zone_setfile(zone, "./zone.data", NULL, dns_masterformat_text,
			 &dns_master_style_default);

	dns_zone_asyncload(zone, false, load_done_first, zone);
}

dns_zone_t *zone1 = NULL, *zone2 = NULL, *zone3 = NULL;

static isc_result_t
all_done(void *arg ISC_ATTR_UNUSED) {
	isc_result_t result;

	/* Both zones should now be loaded; test them */
	result = dns_zone_getdb(zone1, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(db);
	if (db != NULL) {
		dns_db_detach(&db);
	}

	result = dns_zone_getdb(zone2, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(db);
	if (db != NULL) {
		dns_db_detach(&db);
	}

	dns_test_closezonemgr();

	dns_zone_detach(&zone1);
	dns_zone_detach(&zone2);
	dns_zone_detach(&zone3);
	dns_view_detach(&view);

	isc_loopmgr_shutdown();
	return ISC_R_SUCCESS;
}

/* asynchronous zone table load */
ISC_LOOP_TEST_IMPL(asyncload_zt) {
	isc_result_t result;
	dns_zt_t *zt = NULL;
	atomic_bool done;

	dns_test_setupzonemgr();
	atomic_init(&done, false);

	result = dns_test_makezone("foo", &zone1, NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_zone_setfile(zone1, TESTS_DIR "/testdata/zt/zone1.db", NULL,
			 dns_masterformat_text, &dns_master_style_default);
	view = dns_zone_getview(zone1);

	result = dns_test_makezone("bar", &zone2, view, false);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_zone_setfile(zone2, TESTS_DIR "/testdata/zt/zone1.db", NULL,
			 dns_masterformat_text, &dns_master_style_default);

	/* This one will fail to load */
	result = dns_test_makezone("fake", &zone3, view, false);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_zone_setfile(zone3, TESTS_DIR "/testdata/zt/nonexistent.db", NULL,
			 dns_masterformat_text, &dns_master_style_default);

	rcu_read_lock();
	zt = rcu_dereference(view->zonetable);
	rcu_read_unlock();
	assert_non_null(zt);

	assert_false(dns__zone_loadpending(zone1));
	assert_false(dns__zone_loadpending(zone2));
	assert_false(atomic_load(&done));

	rcu_read_lock();
	zt = rcu_dereference(view->zonetable);
	dns_zt_asyncload(zt, false, all_done, NULL);
	rcu_read_unlock();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(covers, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(sfd_forward_only_deepest, setup_managers, teardown_test)
ISC_TEST_ENTRY_CUSTOM(sfd_secroots_boundary, setup_managers, teardown_test)
ISC_TEST_ENTRY_CUSTOM(apply, setup_managers, teardown_test)
ISC_TEST_ENTRY_CUSTOM(asyncload_zone, setup_managers, teardown_test)
ISC_TEST_ENTRY_CUSTOM(asyncload_zt, setup_managers, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
