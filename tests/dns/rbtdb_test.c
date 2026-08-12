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

#include <isc/util.h>

#include <dns/rbt.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#define KEEP_BEFORE

/* Include the main file */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include "rbtdb.c"
#pragma GCC diagnostic pop

#include <tests/dns.h>

const char *ownercase_vectors[12][2] = {
	{
		"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz",
		"aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz",
	},
	{
		"aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz",
		"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ",
	},
	{
		"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ",
		"aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz",
	},
	{
		"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ",
		"aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz",
	},
	{
		"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVxXyYzZ",
		"aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvxxyyzz",
	},
	{
		"WwW.ExAmPlE.OrG",
		"wWw.eXaMpLe.oRg",
	},
	{
		"_SIP.tcp.example.org",
		"_sip.TCP.example.org",
	},
	{
		"bind-USERS.lists.example.org",
		"bind-users.lists.example.org",
	},
	{
		"a0123456789.example.org",
		"A0123456789.example.org",
	},
	{
		"\\000.example.org",
		"\\000.example.org",
	},
	{
		"wWw.\\000.isc.org",
		"www.\\000.isc.org",
	},
	{
		"\255.example.org",
		"\255.example.ORG",
	}
};

static bool
ownercase_test_one(const char *str1, const char *str2) {
	isc_result_t result;
	rbtdb_nodelock_t node_locks[1];
	dns_rbtdb_t rbtdb = { .node_locks = node_locks };
	dns_rbtnode_t rbtnode = { .locknum = 0 };
	rdatasetheader_t header = { 0 };
	unsigned char *raw = (unsigned char *)(&header) + sizeof(header);
	dns_rdataset_t rdataset = {
		.magic = DNS_RDATASET_MAGIC,
		.private1 = &rbtdb,
		.private2 = &rbtnode,
		.private3 = raw,
		.methods = &rdataset_methods,
	};

	isc_buffer_t b;
	dns_fixedname_t fname1, fname2;
	dns_name_t *name1, *name2;

	memset(node_locks, 0, sizeof(node_locks));
	/* Minimal initialization of the mock objects */
	NODE_INITLOCK(&rbtdb.node_locks[0].lock);

	name1 = dns_fixedname_initname(&fname1);
	isc_buffer_constinit(&b, str1, strlen(str1));
	isc_buffer_add(&b, strlen(str1));
	result = dns_name_fromtext(name1, &b, dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	name2 = dns_fixedname_initname(&fname2);
	isc_buffer_constinit(&b, str2, strlen(str2));
	isc_buffer_add(&b, strlen(str2));
	result = dns_name_fromtext(name2, &b, dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Store the case from name1 */
	dns_rdataset_setownercase(&rdataset, name1);

	assert_true(CASESET(&header));

	/* Retrieve the case to name2 */
	dns_rdataset_getownercase(&rdataset, name2);

	NODE_DESTROYLOCK(&rbtdb.node_locks[0].lock);

	return dns_name_caseequal(name1, name2);
}

ISC_RUN_TEST_IMPL(ownercase) {
	UNUSED(state);

	for (size_t n = 0; n < ARRAY_SIZE(ownercase_vectors); n++) {
		assert_true(ownercase_test_one(ownercase_vectors[n][0],
					       ownercase_vectors[n][1]));
	}

	assert_false(ownercase_test_one("W.example.org", "\\000.example.org"));

	/* Ö and ö in ISO Latin 1 */
	assert_false(ownercase_test_one("\\216", "\\246"));
}

ISC_RUN_TEST_IMPL(setownercase) {
	isc_result_t result;
	rbtdb_nodelock_t node_locks[1];
	dns_rbtdb_t rbtdb = { .node_locks = node_locks };
	dns_rbtnode_t rbtnode = { .locknum = 0 };
	rdatasetheader_t header = { 0 };
	unsigned char *raw = (unsigned char *)(&header) + sizeof(header);
	dns_rdataset_t rdataset = {
		.magic = DNS_RDATASET_MAGIC,
		.private1 = &rbtdb,
		.private2 = &rbtnode,
		.private3 = raw,
		.methods = &rdataset_methods,
	};
	const char *str1 =
		"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	isc_buffer_t b;
	dns_fixedname_t fname1, fname2;
	dns_name_t *name1, *name2;

	UNUSED(state);

	/* Minimal initialization of the mock objects */
	memset(node_locks, 0, sizeof(node_locks));
	NODE_INITLOCK(&rbtdb.node_locks[0].lock);

	name1 = dns_fixedname_initname(&fname1);
	isc_buffer_constinit(&b, str1, strlen(str1));
	isc_buffer_add(&b, strlen(str1));
	result = dns_name_fromtext(name1, &b, dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	name2 = dns_fixedname_initname(&fname2);
	isc_buffer_constinit(&b, str1, strlen(str1));
	isc_buffer_add(&b, strlen(str1));
	result = dns_name_fromtext(name2, &b, dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_false(CASESET(&header));

	/* Retrieve the case to name2 */
	dns_rdataset_getownercase(&rdataset, name2);

	NODE_DESTROYLOCK(&rbtdb.node_locks[0].lock);

	assert_true(dns_name_caseequal(name1, name2));
}

static void
make_rdatalist(dns_rdatalist_t *rdatalist, dns_rdataset_t *rdataset,
	       dns_rdata_t *rdata, dns_rdatatype_t type, dns_rdatatype_t covers,
	       unsigned char *data, size_t length) {
	dns_rdata_init(rdata);
	rdata->data = data;
	rdata->length = length;
	rdata->rdclass = dns_rdataclass_in;
	rdata->type = type;

	dns_rdatalist_init(rdatalist);
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->type = type;
	rdatalist->covers = covers;
	rdatalist->ttl = 60;
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);

	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);
	rdataset->trust = dns_trust_answer;
}

/*
 * No operation water() callback. We need it to cause overmem condition, but
 * nothing has to be done in the callback.
 */
static void
overmempurge_water(void *arg, int mark) {
	UNUSED(arg);
	UNUSED(mark);
}

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

	dns_db_detachnode(db, &node);
}

ISC_RUN_TEST_IMPL(overmempurge_bigrdata) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx2 = NULL;
	isc_stdtime_t now;
	size_t i;

	isc_stdtime_get(&now);
	isc_mem_create(&mctx2);

	result = dns_db_create(mctx2, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx2, overmempurge_water, NULL, hiwater, lowater);

	/*
	 * Add cache entries with minimum size of data until 'overmem'
	 * condition is triggered.
	 * This should eventually happen, but we also limit the number of
	 * iteration to avoid an infinite loop in case something gets wrong.
	 */
	for (i = 0; !isc_mem_isovermem(mctx2) && i < (maxcache / 10); i++) {
		overmempurge_addrdataset(db, now, i, 50053, 0, false);
	}

	/*
	 * Then try to add the same number of entries, each has very large data.
	 * 'overmem purge' should keep the total cache size from not exceeding
	 * the 'hiwater' mark too much. So we should be able to assume the
	 * cache size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054,
					 DNS_RDATA_MAXLENGTH - 8, false);
		assert_true(isc_mem_inuse(mctx2) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_destroy(&mctx2);
}

ISC_RUN_TEST_IMPL(overmempurge_longname) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx2 = NULL;
	isc_stdtime_t now;
	size_t i;

	isc_stdtime_get(&now);
	isc_mem_create(&mctx2);

	result = dns_db_create(mctx2, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx2, overmempurge_water, NULL, hiwater, lowater);

	/*
	 * Add cache entries with minimum size of data until 'overmem'
	 * condition is triggered.
	 * This should eventually happen, but we also limit the number of
	 * iteration to avoid an infinite loop in case something gets wrong.
	 */
	for (i = 0; !isc_mem_isovermem(mctx2) && i < (maxcache / 10); i++) {
		overmempurge_addrdataset(db, now, i, 50053, 0, false);
	}

	/*
	 * Then try to add the same number of entries, each has very large data.
	 * 'overmem purge' should keep the total cache size from not exceeding
	 * the 'hiwater' mark too much. So we should be able to assume the
	 * cache size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054, 0, true);
		assert_true(isc_mem_inuse(mctx2) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_destroy(&mctx2);
}

/*
 * A noqname-encloser proof rdataset is a view into memory owned by
 * the header of its parent rdataset.  Expiring the replacement must not
 * reclaim the stale parent while a proof view or one of its clones remains
 * associated.
 */
ISC_RUN_TEST_IMPL(proof_rdataset_survives_expiration_cleanup) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_rbtdb_t *rbtdb = NULL;
	isc_mem_t *dbmctx = NULL;
	isc_stdtime_t now;
	dns_fixedname_t fname, fproof, ffound;
	dns_name_t *name = NULL, *proofname = NULL;
	dns_dbnode_t *node = NULL;
	dns_rbtnode_t *rbtnode = NULL;
	rdatasetheader_t *oldheader = NULL, *newheader = NULL;
	dns_rdatalist_t oldlist, newlist, nseclist, siglist;
	dns_rdataset_t oldset, newset, nsecset, sigset;
	dns_rdataset_t oldbound, newbound;
	dns_rdataset_t noqname, noqnamesig, noqnameclone;
	dns_rdata_t oldrdata, newrdata, nsecrdata, sigrdata;
	unsigned char olddata[] = { 192, 0, 2, 1 };
	unsigned char newdata[] = { 192, 0, 2, 2 };
	unsigned char nsecdata[] = { 0 };
	unsigned char sigdata[] = { 0 };

	UNUSED(state);

	isc_stdtime_get(&now);
	isc_mem_create(&dbmctx);
	result = dns_db_create(dbmctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	rbtdb = (dns_rbtdb_t *)db;

	dns_test_namefromstring("proof.example.", &fname);
	name = dns_fixedname_name(&fname);
	dns_test_namefromstring("nsec.example.", &fproof);
	proofname = dns_fixedname_name(&fproof);

	make_rdatalist(&oldlist, &oldset, &oldrdata, dns_rdatatype_a, 0,
		       olddata, sizeof(olddata));
	make_rdatalist(&newlist, &newset, &newrdata, dns_rdatatype_a, 0,
		       newdata, sizeof(newdata));
	make_rdatalist(&nseclist, &nsecset, &nsecrdata, dns_rdatatype_nsec, 0,
		       nsecdata, sizeof(nsecdata));
	make_rdatalist(&siglist, &sigset, &sigrdata, dns_rdatatype_rrsig,
		       dns_rdatatype_nsec, sigdata, sizeof(sigdata));

	ISC_LIST_APPEND(proofname->list, &nsecset, link);
	ISC_LIST_APPEND(proofname->list, &sigset, link);
	result = dns_rdataset_addnoqname(&oldset, proofname);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_db_findnode(db, name, true, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	rbtnode = (dns_rbtnode_t *)node;

	dns_rdataset_init(&oldbound);
	result = dns_db_addrdataset(db, node, NULL, now, &oldset, 0, &oldbound);
	assert_int_equal(result, ISC_R_SUCCESS);
	oldheader = (rdatasetheader_t *)oldbound.private3 - 1;

	dns_rdataset_init(&noqname);
	dns_rdataset_init(&noqnamesig);
	result = dns_rdataset_getnoqname(&oldbound,
					 dns_fixedname_initname(&ffound),
					 &noqname, &noqnamesig);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(noqname.private6, oldheader);
	assert_ptr_equal(noqnamesig.private6, oldheader);

	dns_rdataset_init(&noqnameclone);
	dns_rdataset_clone(&noqname, &noqnameclone);
	assert_ptr_equal(noqnameclone.private6, oldheader);

	/* Leave only the cache and proof views holding the old header. */
	dns_rdataset_disassociate(&oldbound);
	assert_int_equal(isc_refcount_current(&oldheader->references), 4);

	dns_rdataset_init(&newbound);
	result = dns_db_addrdataset(db, node, NULL, now, &newset, 0, &newbound);
	assert_int_equal(result, ISC_R_SUCCESS);
	newheader = (rdatasetheader_t *)newbound.private3 - 1;
	assert_ptr_equal(newheader->down, oldheader);
	assert_int_equal(isc_refcount_current(&oldheader->references), 3);

	/* RBTDB reclaims stale headers immediately when the top is expired. */
	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	expire_header(rbtdb, newheader, false, expire_ttl);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);
	assert_ptr_equal(newheader->down, oldheader);
	assert_int_equal(dns_rdataset_count(&noqname), 1);
	assert_int_equal(dns_rdataset_count(&noqnamesig), 1);
	assert_int_equal(dns_rdataset_count(&noqnameclone), 1);

	dns_rdataset_disassociate(&noqnameclone);
	dns_rdataset_disassociate(&noqname);
	dns_rdataset_disassociate(&noqnamesig);
	assert_int_equal(isc_refcount_current(&oldheader->references), 0);

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	clean_stale_headers(rbtdb, rbtdb->common.mctx, newheader);
	assert_null(newheader->down);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);

	dns_rdataset_disassociate(&newbound);
	dns_db_detachnode(db, &node);
	dns_db_detach(&db);
	isc_mem_detach(&dbmctx);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(ownercase)
ISC_TEST_ENTRY(setownercase)
ISC_TEST_ENTRY(overmempurge_bigrdata)
ISC_TEST_ENTRY(overmempurge_longname)
ISC_TEST_ENTRY(proof_rdataset_survives_expiration_cleanup)
ISC_TEST_LIST_END

ISC_TEST_MAIN
