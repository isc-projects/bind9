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
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>

#include "rbtdb_p.h"

#define ANCIENT(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ANCIENT) != 0)

#include <tests/dns.h>
#include <tests/isc.h>

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
 * Add to cache DB 'db' an rdataset of type 'rtype' at 'name', with the single
 * rdata parsed from the text 'rdatastr', TTL 'ttl' relative to 'now' and
 * trust 'trust'.
 */
static void
cache_addrdataset(dns_db_t *db, const dns_name_t *name, isc_stdtime_t now,
		  dns_rdatatype_t rtype, const char *rdatastr, dns_ttl_t ttl,
		  dns_trust_t trust) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset, added;
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
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(node);

	dns_rdataset_init(&added);
	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, &added);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_rdataset_disassociate(&added);
	dns_db_detachnode(db, &node);
}

/*
 * Regression test for the secure-data check in dns__rbtdb_add() binding an
 * ancient header. A validated RRset whose TTL passed more than RBTDB_VIRTUAL
 * seconds ago is marked ancient during a lookup: its reference count drops
 * to zero, but it stays linked in the node as long as the node itself is
 * referenced. Caching an unvalidated negative entry covering all types at
 * that node then walks the node's headers looking for secure data to
 * protect; binding the ancient header would trip the reference counting
 * INSIST in dns__rbtdb_bindrdataset(). The ancient header must be skipped
 * and the negative entry cached.
 */
ISC_LOOP_TEST_IMPL(ncache_add_over_ancient_secure) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *dbmctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_stdtime_t future = now + 3600 + RBTDB_VIRTUAL + 2;
	dns_fixedname_t fname;
	dns_name_t *name = NULL;
	dns_dbnode_t *node = NULL;
	dns_slabheader_t *header = NULL;
	dns_rdatalist_t ncrdatalist;
	dns_rdataset_t ncrdataset, rdataset, added;

	isc_mem_create(&dbmctx);

	result = dns_db_create(dbmctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_test_namefromstring("example.com.", &fname);
	name = dns_fixedname_name(&fname);

	cache_addrdataset(db, name, now, dns_rdatatype_a, "10.53.0.1", 3600,
			  dns_trust_secure);

	/*
	 * Hold the node and look the type up again after both the TTL and
	 * the RBTDB_VIRTUAL grace period have passed: the expired RRset can
	 * no longer be found, and the node reference keeps its dead header
	 * linked.
	 */
	result = dns_db_findnode(db, name, false, &node);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, NULL, dns_rdatatype_a, 0, future,
				     &rdataset, NULL);
	assert_int_equal(result, ISC_R_NOTFOUND);

	header = ((dns_rbtnode_t *)node)->data;
	assert_non_null(header);
	assert_true(header->trust >= dns_trust_secure);

	/*
	 * The lookup marks the expired header ancient only when it can
	 * upgrade the node lock; with the pthread rwlock implementation
	 * the upgrade never succeeds, so mark the header directly (a
	 * no-op when the lookup already did it).
	 */
	dns__rbtdb_mark_ancient(header);
	assert_true(ANCIENT(header));
	assert_int_equal(isc_refcount_current(&header->references), 0);

	/*
	 * Cache an unvalidated NXDOMAIN covering all types, shaped the way
	 * dns_ncache_add() builds it.
	 */
	dns_rdatalist_init(&ncrdatalist);
	ncrdatalist.rdclass = dns_rdataclass_in;
	ncrdatalist.covers = dns_rdatatype_any;
	ncrdatalist.ttl = 60;

	dns_rdataset_init(&ncrdataset);
	dns_rdatalist_tordataset(&ncrdatalist, &ncrdataset);
	ncrdataset.trust = dns_trust_pending_answer;
	ncrdataset.attributes |= DNS_RDATASETATTR_NEGATIVE |
				 DNS_RDATASETATTR_NXDOMAIN;

	dns_rdataset_init(&added);
	result = dns_db_addrdataset(db, node, NULL, future, &ncrdataset, 0,
				    &added);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true((added.attributes & DNS_RDATASETATTR_NEGATIVE) != 0);
	assert_true((added.attributes & DNS_RDATASETATTR_NXDOMAIN) != 0);

	dns_rdataset_disassociate(&added);
	dns_db_detachnode(db, &node);
	dns_db_detach(&db);
	isc_mem_detach(&dbmctx);
	isc_loopmgr_shutdown(loopmgr);
}

/*
 * A noqname or closest-encloser proof rdataset is a view into memory owned by
 * the slabheader of its parent rdataset.  Expiring the replacement must not
 * reclaim the stale parent while a proof view or one of its clones remains
 * associated.
 */
ISC_LOOP_TEST_IMPL(proof_rdataset_survives_expiration_cleanup) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *dbmctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname, fproof, ffound;
	dns_name_t *name = NULL, *proofname = NULL;
	dns_dbnode_t *node = NULL;
	dns_slabheader_t *oldheader = NULL, *newheader = NULL;
	dns_rdatalist_t oldlist, newlist, nseclist, siglist;
	dns_rdataset_t oldset, newset, nsecset, sigset;
	dns_rdataset_t oldbound, newbound;
	dns_rdataset_t noqname, noqnamesig, noqnameclone;
	dns_rdata_t oldrdata, newrdata, nsecrdata, sigrdata;
	unsigned char olddata[] = { 192, 0, 2, 1 };
	unsigned char newdata[] = { 192, 0, 2, 2 };
	unsigned char nsecdata[] = { 0 };
	unsigned char sigdata[] = { 0 };

	isc_mem_create(&dbmctx);
	result = dns_db_create(dbmctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

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

	dns_rdataset_init(&oldbound);
	result = dns_db_addrdataset(db, node, NULL, now, &oldset, 0, &oldbound);
	assert_int_equal(result, ISC_R_SUCCESS);
	oldheader = dns_slabheader_fromrdataset(&oldbound);

	dns_rdataset_init(&noqname);
	dns_rdataset_init(&noqnamesig);
	result = dns_rdataset_getnoqname(&oldbound,
					 dns_fixedname_initname(&ffound),
					 &noqname, &noqnamesig);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(noqname.proof.header, oldheader);
	assert_ptr_equal(noqnamesig.proof.header, oldheader);

	dns_rdataset_init(&noqnameclone);
	dns_rdataset_clone(&noqname, &noqnameclone);
	assert_ptr_equal(noqnameclone.proof.header, oldheader);

	/* Leave only the cache and proof views holding the old header. */
	dns_rdataset_disassociate(&oldbound);
	assert_int_equal(isc_refcount_current(&oldheader->references), 4);

	dns_rdataset_init(&newbound);
	result = dns_db_addrdataset(db, node, NULL, now, &newset, 0, &newbound);
	assert_int_equal(result, ISC_R_SUCCESS);
	newheader = dns_slabheader_fromrdataset(&newbound);
	assert_ptr_equal(newheader->down, oldheader);
	assert_int_equal(isc_refcount_current(&oldheader->references), 3);

	/* RBTDB reclaims stale headers immediately when the top is expired. */
	dns_db_expiredata(db, node, newheader);
	assert_ptr_equal(newheader->down, oldheader);
	assert_int_equal(dns_rdataset_count(&noqname), 1);
	assert_int_equal(dns_rdataset_count(&noqnamesig), 1);
	assert_int_equal(dns_rdataset_count(&noqnameclone), 1);

	dns_rdataset_disassociate(&noqnameclone);
	dns_rdataset_disassociate(&noqname);
	dns_rdataset_disassociate(&noqnamesig);
	assert_int_equal(isc_refcount_current(&oldheader->references), 0);

	dns_db_locknode(db, node, isc_rwlocktype_write);
	dns__rbtdb_clean_stale_headers(newheader);
	assert_null(newheader->down);
	dns_db_unlocknode(db, node, isc_rwlocktype_write);

	dns_rdataset_disassociate(&newbound);
	dns_db_detachnode(db, &node);
	dns_db_detach(&db);
	isc_mem_detach(&dbmctx);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(ncache_add_over_ancient_secure, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(proof_rdataset_survives_expiration_cleanup,
		      setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
