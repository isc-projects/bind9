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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#define KEEP_BEFORE

/* Include the main file */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include "qpcache.c"
#pragma GCC diagnostic pop

#include <tests/dns.h>

/* Set to true (or use -v option) for verbose output */
static bool verbose = false;

/*
 * Add to a cache DB 'db' an rdataset of type 'rtype' at a name
 * <idx>.example.com. The rdataset would contain one data, and rdata_len is
 * its length. 'rtype' is supposed to be some private type whose data can be
 * arbitrary (and it doesn't matter in this test).
 */
static void
overmempurge_addrdataset(dns_db_t *db, isc_stdtime_t now, int idx,
			 dns_rdatatype_t rtype, size_t rdata_len,
			 bool longname) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_fixedname_t fname;
	dns_name_t *name;
	char namebuf[DNS_NAME_FORMATSIZE];
	unsigned char rdatabuf[65535] = { 0 }; /* large enough for any valid
						  RDATA */

	REQUIRE(rdata_len <= sizeof(rdatabuf));

	if (longname) {
		/*
		 * Build a longest possible name (in wire format) that would
		 * result in a new rbt node with the long name data.
		 */
		snprintf(namebuf, sizeof(namebuf),
			 "%010d.%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef01.",
			 idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx,
			 idx, idx, idx, idx, idx);
	} else {
		snprintf(namebuf, sizeof(namebuf), "%d.example.com.", idx);
	}
	dns_test_namefromstring(namebuf, &fname);
	name = dns_fixedname_name(&fname);

	result = dns_db_findnode(db, name, true, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(node);

	dns_rdata_init(&rdata);
	rdata.length = rdata_len;
	rdata.data = rdatabuf;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = rtype;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = rtype;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_db_detachnode(&node);
}

static void
cleanup_all_deadnodes(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcache_ref(qpdb);
	for (uint16_t locknum = 0; locknum < qpdb->buckets_count; locknum++) {
		cleanup_deadnodes(qpdb, locknum);
	}
	qpcache_unref(qpdb);
}

/*
 * Add to cache DB 'db' an rdataset of type 'rtype' at 'name', with the single
 * rdata parsed from the text 'rdatastr'. The rdataset is given TTL 'ttl'
 * relative to 'now', so passing a 'now' in the past makes the entry expired
 * (and, with serve-stale enabled, stale).
 */
static void
servestale_addrdataset(dns_db_t *db, const dns_name_t *name, isc_stdtime_t now,
		       dns_rdatatype_t rtype, const char *rdatastr,
		       dns_ttl_t ttl, dns_trust_t trust) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	unsigned char rdatabuf[1024];

	dns_rdata_init(&rdata);
	result = dns_test_rdatafromstring(&rdata, dns_rdataclass_in, rtype,
					  rdatabuf, sizeof(rdatabuf), rdatastr,
					  false);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = rtype;
	rdatalist.ttl = ttl;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);
	rdataset.trust = trust;

	result = dns_db_findnode(db, name, true, &node);
	assert_true(result == ISC_R_SUCCESS || result == DNS_R_CNAME);
	assert_non_null(node);

	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_db_detachnode(&node);
}

/*
 * Create a cache DB with serve-stale enabled and bind 'name' to a freshly
 * initialized name pointing into 'fname'.
 */
static dns_db_t *
servestale_setup(isc_mem_t *mctx, dns_fixedname_t *fname, dns_name_t **namep) {
	isc_result_t result;
	dns_db_t *db = NULL;

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Keep expired entries for a day as a last-resort fallback. */
	dns_db_setservestalettl(db, 86400);

	dns_test_namefromstring("example.com.", fname);
	*namep = dns_fixedname_name(fname);

	return db;
}

/*
 * Regression test for the find loop accepting a stale CNAME as a final answer
 * and stopping early even though a fresh record of the requested type exists
 * at the same node.
 *
 * A stale CNAME that expired two hours ago (but is still inside the stale
 * window) is added first and a fresh non-priority type is (HINFO) added last
 * last, so the stale CNAME sits at the head of the node's type list and is
 * visited first by the find loop. With serve-stale enabled, the search must
 * skip the stale CNAME and return the fresh HINFO rather than the stale CNAME.
 */
ISC_LOOP_TEST_IMPL(servestale_fresh_over_stale_cname) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname, ffound;
	dns_name_t *name = NULL, *foundname = NULL;
	dns_rdataset_t rdataset;

	isc_mem_create("test", &mctx);
	db = servestale_setup(mctx, &fname, &name);

	servestale_addrdataset(db, name, now - 7200, dns_rdatatype_cname,
			       "target.example.com.", 3600, dns_trust_answer);
	servestale_addrdataset(db, name, now, dns_rdatatype_hinfo,
			       "CRAY-1 NEXUS", 3600, dns_trust_answer);

	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name, NULL, dns_rdatatype_hinfo,
			     DNS_DBFIND_STALEOK, now, foundname, &rdataset,
			     NULL);

	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdataset.type, dns_rdatatype_hinfo);
	assert_false(rdataset.attributes.stale);

	dns_rdataset_disassociate(&rdataset);
	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

/*
 * Same regression, but for a stale record of the requested type masking a
 * fresh CNAME. A fresh CNAME is added first and a stale A is added last; the
 * stale A is visited first and must not short-circuit the search. The fresh
 * CNAME has to win, returning DNS_R_CNAME instead of the stale A.
 */
ISC_LOOP_TEST_IMPL(servestale_fresh_cname_over_stale_type) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname, ffound;
	dns_name_t *name = NULL, *foundname = NULL;
	dns_rdataset_t rdataset;

	isc_mem_create("test", &mctx);
	db = servestale_setup(mctx, &fname, &name);

	servestale_addrdataset(db, name, now, dns_rdatatype_cname,
			       "target.example.com.", 3600, dns_trust_answer);
	servestale_addrdataset(db, name, now - 7200, dns_rdatatype_a,
			       "10.53.0.1", 3600, dns_trust_answer);

	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name, NULL, dns_rdatatype_a,
			     DNS_DBFIND_STALEOK, now, foundname, &rdataset,
			     NULL);

	assert_int_equal(result, DNS_R_CNAME);
	assert_int_equal(rdataset.type, dns_rdatatype_cname);
	assert_false(rdataset.attributes.stale);

	dns_rdataset_disassociate(&rdataset);
	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

static const char *
precedence_rdata(dns_rdatatype_t type) {
	switch (type) {
	case dns_rdatatype_cname:
		return "target.example.com.";
	case dns_rdatatype_a:
		return "10.53.0.1";
	case dns_rdatatype_ns:
		return "ns.example.com.";
	case dns_rdatatype_ds:
		return "12345 13 2 "
		       "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184C"
		       "F"
		       "C41A5766";
	default:
		UNREACHABLE();
	}
}

/* 'age' is measured from insertion; dns_rdatatype_none skips an RRset. */
static void
check_cname_precedence(isc_mem_t *mctx, dns_rdatatype_t type1,
		       isc_stdtime_t age1, dns_rdatatype_t type2,
		       isc_stdtime_t age2, dns_rdatatype_t qtype,
		       isc_result_t expected, dns_rdatatype_t expected_type,
		       bool expected_stale) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname, ffound;
	dns_name_t *name = NULL, *foundname = NULL;
	dns_rdataset_t rdataset;

	db = servestale_setup(mctx, &fname, &name);

	if (type1 != dns_rdatatype_none) {
		servestale_addrdataset(db, name, now - age1, type1,
				       precedence_rdata(type1), 3600,
				       dns_trust_answer);
	}
	if (type2 != dns_rdatatype_none) {
		servestale_addrdataset(db, name, now - age2, type2,
				       precedence_rdata(type2), 3600,
				       dns_trust_answer);
	}

	foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_init(&rdataset);
	result = dns_db_find(db, name, NULL, qtype, DNS_DBFIND_STALEOK, now,
			     foundname, &rdataset, NULL);

	assert_int_equal(result, expected);
	if (dns_rdataset_isassociated(&rdataset)) {
		assert_int_equal(rdataset.type, expected_type);
		assert_true(rdataset.attributes.stale == expected_stale);
		dns_rdataset_disassociate(&rdataset);
	} else {
		assert_int_equal(expected_type, dns_rdatatype_none);
	}

	dns_db_detach(&db);
}

/* Check CNAME precedence for both insertion orders. */
ISC_LOOP_TEST_IMPL(cname_precedence) {
	isc_mem_t *mctx = NULL;
	const dns_rdatatype_t cname = dns_rdatatype_cname;
	const dns_rdatatype_t a = dns_rdatatype_a;
	const dns_rdatatype_t ns = dns_rdatatype_ns;
	const dns_rdatatype_t ds = dns_rdatatype_ds;
	const dns_rdatatype_t txt = dns_rdatatype_txt;
	const dns_rdatatype_t none = dns_rdatatype_none;
	const isc_stdtime_t fresh = 0;
	const isc_stdtime_t stale = 7200; /* expired an hour ago */

	struct {
		const dns_rdatatype_t type1;
		const isc_stdtime_t rank1;
		const dns_rdatatype_t type2;
		const isc_stdtime_t rank2;
		const dns_rdatatype_t qtype;
		const isc_result_t expected_result;
		const dns_rdatatype_t expected_type;
		const bool expected_stale;
		const bool one_direction;
	} testcases[] = {
		/* Both fresh: the requested type wins over the alias. */
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = a,
			.rank2 = fresh,
			.qtype = a,
			.expected_result = ISC_R_SUCCESS,
			.expected_type = a,
			.expected_stale = false,
		},
		/* Fresh beats stale, in both directions and either order. */
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = a,
			.rank2 = fresh,
			.qtype = a,
			.expected_result = ISC_R_SUCCESS,
			.expected_type = a,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = a,
			.rank2 = stale,
			.qtype = a,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
		/* Both stale: the requested type wins. */
		{
			.type1 = a,
			.rank1 = stale,
			.type2 = cname,
			.rank2 = stale,
			.qtype = a,
			.expected_result = ISC_R_SUCCESS,
			.expected_type = a,
			.expected_stale = true,
		},
		/* Queried type is not in cache, expect CNAME. */
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = a,
			.rank2 = fresh,
			.qtype = txt,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = a,
			.rank2 = stale,
			.qtype = txt,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = a,
			.rank2 = fresh,
			.qtype = txt,
			.expected_result = ISC_R_NOTFOUND,
			.expected_type = none,
			.expected_stale = false,
			.one_direction = true,
		},
		{
			.type1 = a,
			.rank1 = fresh,
			.type2 = cname,
			.rank2 = stale,
			.qtype = txt,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = stale,
			.one_direction = true,
		},
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = a,
			.rank2 = stale,
			.qtype = txt,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = true,
		},
		/* A lone CNAME answers ordinary types, including NS, but not
		   DS. */
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = none,
			.rank2 = 0,
			.qtype = a,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = none,
			.rank2 = 0,
			.qtype = ns,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = none,
			.rank2 = 0,
			.qtype = ds,
			.expected_result = ISC_R_NOTFOUND,
			.expected_type = none,
			.expected_stale = false,
		},
		/* A lone stale CNAME answers ordinary types, including NS, but
		   not DS. */
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = none,
			.rank2 = 0,
			.qtype = a,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = true,
		},
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = none,
			.rank2 = 0,
			.qtype = ns,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = true,
		},
		{
			.type1 = cname,
			.rank1 = stale,
			.type2 = none,
			.rank2 = 0,
			.qtype = ds,
			.expected_result = ISC_R_NOTFOUND,
			.expected_type = none,
			.expected_stale = false,
		},
		/* Delegation data beside a CNAME is found by its own type. */
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = ds,
			.rank2 = fresh,
			.qtype = ds,
			.expected_result = ISC_R_SUCCESS,
			.expected_type = ds,
			.expected_stale = false,
		},
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = ns,
			.rank2 = fresh,
			.qtype = ns,
			.expected_result = ISC_R_SUCCESS,
			.expected_type = ns,
			.expected_stale = false,
		},
		/* DS does not hide a CNAME from ordinary queries. */
		{
			.type1 = cname,
			.rank1 = fresh,
			.type2 = ds,
			.rank2 = fresh,
			.qtype = a,
			.expected_result = DNS_R_CNAME,
			.expected_type = cname,
			.expected_stale = false,
		},
	};

	isc_mem_create("test", &mctx);

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		const dns_rdatatype_t type1 = testcases[i].type1;
		const isc_stdtime_t rank1 = testcases[i].rank1;
		const dns_rdatatype_t type2 = testcases[i].type2;
		const isc_stdtime_t rank2 = testcases[i].rank2;
		const dns_rdatatype_t qtype = testcases[i].qtype;
		const isc_result_t expected_result =
			testcases[i].expected_result;
		const dns_rdatatype_t expected_type =
			testcases[i].expected_type;
		const bool expected_stale = testcases[i].expected_stale;
		const bool one_direction = testcases[i].one_direction;

		/*
		 * A fresh RRset cached after a stale one retires it; with
		 * 'purged' set, that insertion order is expected to find
		 * nothing for the query.
		 */
		check_cname_precedence(mctx, type1, rank1, type2, rank2, qtype,
				       expected_result, expected_type,
				       expected_stale);
		if (!one_direction) {
			check_cname_precedence(mctx, type2, rank2, type1, rank1,
					       qtype, expected_result,
					       expected_type, expected_stale);
		}
	}

	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(allrdatasets_expiredok_skips_deleted_header) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	dns_rdatasetiter_t *iterator = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname;
	dns_name_t *name = NULL;

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_test_namefromstring("deleted.example.com.", &fname);
	name = dns_fixedname_name(&fname);

	servestale_addrdataset(db, name, now, dns_rdatatype_a, "10.53.0.1",
			       3600, dns_trust_answer);

	result = dns_db_findnode(db, name, false, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(node);

	result = dns_db_deleterdataset(db, node, NULL, dns_rdatatype_a, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_allrdatasets(db, node, NULL, DNS_DB_EXPIREDOK, now,
				     &iterator);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_rdatasetiter_first(iterator);
	assert_int_equal(result, ISC_R_NOMORE);

	dns_rdatasetiter_destroy(&iterator);
	dns_db_detachnode(&node);
	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(overmempurge_bigrdata) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	size_t i = 0;

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx, hiwater, lowater);

	/*
	 * Add a lot of data entries sufficient to push the context
	 * above the hi_water mark.
	 */
	while (isc_mem_inuse(mctx) < hiwater) {
		overmempurge_addrdataset(db, now, i, 50053, 0, true);
		i++;
	}
	assert_true(isc_mem_inuse(mctx) >= hiwater);
	assert_true(isc_mem_inuse(mctx) < maxcache);

	/*
	 * Then try to add the same number of entries, each has very large data.
	 * Probabilistic LRU cleaning should keep the total cache size from
	 * exceeding the 'hiwater' mark too much. So we should be able to
	 * assume the cache size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054,
					 DNS_RDATA_MAXLENGTH - 2, false);
		cleanup_all_deadnodes(db);
		if (verbose) {
			print_message("# inuse: %zd max: %zd\n",
				      isc_mem_inuse(mctx), maxcache);
		}
		assert_true(isc_mem_inuse(mctx) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(overmempurge_longname) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	size_t i = 0;

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx, hiwater, lowater);

	/*
	 * Add a lot of data entries sufficient to push the context
	 * above the hi_water mark.
	 */
	while (isc_mem_inuse(mctx) < hiwater) {
		overmempurge_addrdataset(db, now, i, 50053, 0, true);
		i++;
	}
	assert_true(isc_mem_inuse(mctx) >= hiwater);
	assert_true(isc_mem_inuse(mctx) < maxcache);

	/*
	 * Then try to add the same number of entries, each has very long name.
	 * Probabilistic LRU cleaning should keep the total cache size from
	 * exceeding the 'hiwater' mark too much. So we should be able to
	 * assume the cache size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054, 0, true);
		cleanup_all_deadnodes(db);
		if (verbose) {
			print_message("# inuse: %zd max: %zd\n",
				      isc_mem_inuse(mctx), maxcache);
		}
		assert_true(isc_mem_inuse(mctx) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(overmempurge_bigrdata, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(overmempurge_longname, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(allrdatasets_expiredok_skips_deleted_header,
		      setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(servestale_fresh_over_stale_cname, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(servestale_fresh_cname_over_stale_type, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(cname_precedence, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
