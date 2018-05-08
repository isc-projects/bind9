/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <dns/dnssec.h>
#include <dns/zone.h>

#include "../zone_p.h"

#include "dnstest.h"

/*%
 * Structure defining a dns__zone_update_sigs() test.
 */
typedef struct {
	const char *description;	/* test description */
	const zonechange_t *changes;	/* array of "raw" zone changes */
	size_t rrsigs_added;		/* expected added RRSIG count */
	size_t non_rrsigs_added;	/* expected added non-RRSIG count */
	size_t rrsigs_deleted;		/* expected deleted RRSIG count */
	size_t non_rrsigs_deleted;	/* expected deleted non-RRSIG count */
} update_sigs_test_params_t;

/*%
 * Perform a single dns__zone_update_sigs() test defined in 'test'.  All other
 * arguments are expected to remain constant between subsequent invocations of
 * this function.
 */
static void
update_sigs_test(const update_sigs_test_params_t *test, dns_zone_t *zone,
		 dns_db_t *db, dst_key_t *zone_keys[], unsigned int nkeys,
		 isc_stdtime_t now)
{
	size_t rrsigs_deleted = 0, non_rrsigs_deleted = 0;
	size_t rrsigs_added = 0, non_rrsigs_added = 0;
	dns_dbversion_t *version = NULL;
	dns_diff_t raw_diff, zone_diff;
	dns_difftuple_t *tuple;
	isc_result_t result;

	dns__zonediff_t zonediff = {
		.diff = &zone_diff,
		.offline = ISC_FALSE,
	};

	REQUIRE(test != NULL);
	REQUIRE(test->description != NULL);
	REQUIRE(test->changes != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(db != NULL);
	REQUIRE(zone_keys != NULL);

	/*
	 * Create a new version of the zone's database.
	 */
	result = dns_db_newversion(db, &version);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/*
	 * Create a diff representing the supplied changes.
	 */
	result = dns_test_diff_fromchanges(&raw_diff, test->changes);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/*
	 * Apply the "raw" diff to the new version of the zone's database as
	 * this is what dns__zone_update_sigs() expects to happen before it is
	 * called.
	 */
	dns_diff_apply(&raw_diff, db, version);

	/*
	 * Initialize the structure dns__zone_update_sigs() will modify.
	 */
	dns_diff_init(mctx, &zone_diff);

	/*
	 * Check whether dns__zone_update_sigs() behaves as expected.
	 */
	result = dns__zone_update_sigs(&raw_diff, db, version, zone_keys,
				       nkeys, zone, now - 3600, now + 3600, 0,
				       now, ISC_TRUE, ISC_FALSE, &zonediff);

	ATF_CHECK_EQ_MSG(result, ISC_R_SUCCESS,
			 "test \"%s\": expected success, got %s",
			 test->description, isc_result_totext(result));
	ATF_CHECK_MSG(ISC_LIST_EMPTY(raw_diff.tuples),
		      "test \"%s\": raw diff was not emptied",
		      test->description);
	ATF_CHECK_MSG(!ISC_LIST_EMPTY(zone_diff.tuples),
		      "test \"%s\": zone diff was not created",
		      test->description);

	for (tuple = ISC_LIST_HEAD(zone_diff.tuples);
	     tuple != NULL;
	     tuple = ISC_LIST_NEXT(tuple, link))
	{
		switch (tuple->op) {
		case DNS_DIFFOP_ADD:
		case DNS_DIFFOP_ADDRESIGN:
			switch (tuple->rdata.type) {
			case dns_rdatatype_rrsig:
				rrsigs_added++;
				break;
			default:
				non_rrsigs_added++;
				break;
			}
			break;
		case DNS_DIFFOP_DEL:
		case DNS_DIFFOP_DELRESIGN:
			switch (tuple->rdata.type) {
			case dns_rdatatype_rrsig:
				rrsigs_deleted++;
				break;
			default:
				non_rrsigs_deleted++;
				break;
			}
			break;
		default:
			ATF_REQUIRE(0);
			break;
		}
	}

	ATF_CHECK_EQ_MSG(rrsigs_added, test->rrsigs_added,
			 "test \"%s\": "
			 "RRSIG RRs added: %zu, expected: %zu",
			 test->description,
			 rrsigs_added, test->rrsigs_added);
	ATF_CHECK_EQ_MSG(non_rrsigs_added, test->non_rrsigs_added,
			 "test \"%s\": "
			 "non-RRSIG RRs added: %zu, expected: %zu",
			 test->description,
			 non_rrsigs_added, test->non_rrsigs_added);
	ATF_CHECK_EQ_MSG(rrsigs_deleted, test->rrsigs_deleted,
			 "test \"%s\": "
			 "RRSIG RRs deleted: %zu, expected: %zu",
			 test->description,
			 rrsigs_deleted, test->rrsigs_deleted);
	ATF_CHECK_EQ_MSG(non_rrsigs_deleted, test->non_rrsigs_deleted,
			 "test \"%s\": "
			 "non-RRSIG RRs deleted: %zu, expected: %zu",
			 test->description,
			 non_rrsigs_deleted, test->non_rrsigs_deleted);

	/*
	 * Apply changes to zone database contents and clean up.
	 */
	dns_db_closeversion(db, &version, ISC_TRUE);
	dns_diff_clear(&zone_diff);
	dns_diff_clear(&raw_diff);
}

ATF_TC(update_sigs);
ATF_TC_HEAD(update_sigs, tc) {
	atf_tc_set_md_var(tc, "descr", "dns__zone_update_sigs() tests");
}
ATF_TC_BODY(update_sigs, tc) {
	dst_key_t *zone_keys[DNS_MAXZONEKEYS];
	dns_zone_t *zone = NULL;
	dns_db_t *db = NULL;
	isc_result_t result;
	unsigned int nkeys;
	isc_stdtime_t now;
	size_t i;

	result = dns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/*
	 * Prepare a zone along with its signing keys.
	 */

	result = dns_test_makezone("example", &zone, NULL, ISC_FALSE);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "example",
				 "testdata/master/master18.data");
	ATF_REQUIRE_EQ(result, DNS_R_SEENINCLUDE);

	result = dns_zone_setkeydirectory(zone, "testkeys");
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_stdtime_get(&now);
	result = dns__zone_find_keys(zone, db, NULL, now, mctx,
				     DNS_MAXZONEKEYS, zone_keys, &nkeys);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(nkeys, 2);

	/*
	 * Define the tests to be run.  Note that changes to zone database
	 * contents introduced by each test are preserved between tests.
	 */

	const zonechange_t changes_add[] = {
		{
			.op = DNS_DIFFOP_ADD,
			.owner = "foo.example",
			.ttl = 300,
			.type = "TXT",
			.rdata = "foo"
		},
		{
			.op = DNS_DIFFOP_ADD,
			.owner = "bar.example",
			.ttl = 300,
			.type = "TXT",
			.rdata = "bar"
		},
		ZONECHANGE_SENTINEL,
	};
	const update_sigs_test_params_t test_add = {
		.description = "add new RRsets",
		.changes = changes_add,
		.rrsigs_added = 2,
		.non_rrsigs_added = 2,
		.rrsigs_deleted = 0,
		.non_rrsigs_deleted = 0,
	};

	const zonechange_t changes_append[] = {
		{ DNS_DIFFOP_ADD, "foo.example", 300, "TXT", "foo1" },
		{ DNS_DIFFOP_ADD, "foo.example", 300, "TXT", "foo2" },
		ZONECHANGE_SENTINEL,
	};
	const update_sigs_test_params_t test_append = {
		.description = "append multiple RRs to an existing RRset",
		.changes = changes_append,
		.rrsigs_added = 1,
		.non_rrsigs_added = 2,
		.rrsigs_deleted = 1,
		.non_rrsigs_deleted = 0,
	};

	const zonechange_t changes_replace[] = {
		{ DNS_DIFFOP_DEL, "bar.example", 300, "TXT", "bar" },
		{ DNS_DIFFOP_ADD, "bar.example", 300, "TXT", "rab" },
		ZONECHANGE_SENTINEL,
	};
	const update_sigs_test_params_t test_replace = {
		.description = "replace an existing RRset",
		.changes = changes_replace,
		.rrsigs_added = 1,
		.non_rrsigs_added = 1,
		.rrsigs_deleted = 1,
		.non_rrsigs_deleted = 1,
	};

	const zonechange_t changes_delete[] = {
		{ DNS_DIFFOP_DEL, "bar.example", 300, "TXT", "rab" },
		ZONECHANGE_SENTINEL,
	};
	const update_sigs_test_params_t test_delete = {
		.description = "delete an existing RRset",
		.changes = changes_delete,
		.rrsigs_added = 0,
		.non_rrsigs_added = 0,
		.rrsigs_deleted = 1,
		.non_rrsigs_deleted = 1,
	};

	const zonechange_t changes_mixed[] = {
		{ DNS_DIFFOP_ADD, "baz.example", 300, "TXT", "baz1" },
		{ DNS_DIFFOP_ADD, "baz.example", 300, "A", "127.0.0.1" },
		{ DNS_DIFFOP_ADD, "baz.example", 300, "TXT", "baz2" },
		{ DNS_DIFFOP_ADD, "baz.example", 300, "AAAA", "::1" },
		ZONECHANGE_SENTINEL,
	};
	const update_sigs_test_params_t test_mixed = {
		.description = "add different RRsets with common owner name",
		.changes = changes_mixed,
		.rrsigs_added = 3,
		.non_rrsigs_added = 4,
		.rrsigs_deleted = 0,
		.non_rrsigs_deleted = 0,
	};

	const update_sigs_test_params_t *tests[] = {
		&test_add,
		&test_append,
		&test_replace,
		&test_delete,
		&test_mixed,
	};

	/*
	 * Run tests.
	 */
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		update_sigs_test(tests[i], zone, db, zone_keys, nkeys, now);
	}

	/*
	 * Clean up.
	 */
	for (i = 0; i < nkeys; i++) {
		dst_key_free(&zone_keys[i]);
	}
	dns_db_detach(&db);
	dns_zone_detach(&zone);

	dns_test_end();
}

ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, update_sigs);

	return (atf_no_error());
}
