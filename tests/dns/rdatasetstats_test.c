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

#include <isc/lib.h>
#include <isc/stats.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/stats.h>

#include <tests/dns.h>

/*
 * Each rdataset statistics counter is keyed on an RRtype plus a few
 * attribute bits.  The interesting combinations are the cross product of
 *
 *   - positive RRset / NXRRSET (NODATA) / NXDOMAIN, and
 *   - active / stale,
 *
 * and the property under test is that every combination maps to its own
 * counter (no aliasing) and round-trips through dns_rdatasetstats_dump().
 *
 * The helpers below drive the counters from the active to the stale state;
 * the verify callback then dumps *every* counter (ISC_STATSDUMP_VERBOSE) and
 * asserts that exactly the counters in the expected state hold 1 and all
 * others hold 0.  An aliasing bug shows up as a counter holding 2 (two
 * states folded onto one slot) or 0 (a state that landed on the wrong slot).
 */

/* A type that does not fit in 8 bits and folds onto the 'other' counter. */
#define OTHERTYPE ((dns_rdatatype_t)1000)

static void
incr(dns_stats_t *stats, dns_rdatatype_t type, unsigned int attr) {
	dns_rdatasetstats_increment(stats,
				    DNS_RDATASTATSTYPE_VALUE(type, attr));
}

static void
decr(dns_stats_t *stats, dns_rdatatype_t type, unsigned int attr) {
	dns_rdatasetstats_decrement(stats,
				    DNS_RDATASTATSTYPE_VALUE(type, attr));
}

/* Set the active positive and active NXRRSET counters for 'type'. */
static void
set_active(dns_stats_t *stats, dns_rdatatype_t type) {
	incr(stats, type, 0);
	incr(stats, type, DNS_RDATASTATSTYPE_ATTR_NXRRSET);
}

/* Set the active NXDOMAIN counter. */
static void
set_active_nxdomain(dns_stats_t *stats) {
	incr(stats, 0, DNS_RDATASTATSTYPE_ATTR_NXDOMAIN);
}

/* Move the positive and NXRRSET counters for 'type' from active to stale. */
static void
mark_stale(dns_stats_t *stats, dns_rdatatype_t type) {
	unsigned int nx = DNS_RDATASTATSTYPE_ATTR_NXRRSET;
	unsigned int stale = DNS_RDATASTATSTYPE_ATTR_STALE;

	decr(stats, type, 0);
	incr(stats, type, stale);
	decr(stats, type, nx);
	incr(stats, type, nx | stale);
}

/* Move the NXDOMAIN counter from active to stale. */
static void
mark_stale_nxdomain(dns_stats_t *stats) {
	unsigned int nxd = DNS_RDATASTATSTYPE_ATTR_NXDOMAIN;
	unsigned int stale = DNS_RDATASTATSTYPE_ATTR_STALE;

	decr(stats, 0, nxd);
	incr(stats, 0, nxd | stale);
}

/*
 * Assert that a counter holds 1 exactly when its staleness matches the
 * expected state passed via 'arg' (0 for active, DNS_RDATASTATSTYPE_ATTR_STALE
 * for stale), and 0 otherwise.
 */
static void
verify_counters(dns_rdatastatstype_t which, uint64_t value, void *arg) {
	unsigned int attributes = DNS_RDATASTATSTYPE_ATTR(which);
	unsigned int expected = *(unsigned int *)arg;

	if ((attributes & DNS_RDATASTATSTYPE_ATTR_STALE) == expected) {
		assert_int_equal(value, 1);
	} else {
		assert_int_equal(value, 0);
	}
}

/*
 * Populate every counter active, verify, transition all to stale, verify.
 */
ISC_RUN_TEST_IMPL(active_stale) {
	unsigned int active = 0;
	unsigned int stale = DNS_RDATASTATSTYPE_ATTR_STALE;
	dns_stats_t *stats = NULL;

	UNUSED(state);

	dns_rdatasetstats_create(isc_g_mctx, &stats);

	/*
	 * The first 255 RRtypes, a type that folds onto the 'other' counter,
	 * and an NXDOMAIN.  Setting 'other' (type 0) matters: the verify pass
	 * checks every slot, so each active slot must be populated.
	 */
	for (unsigned int i = 1; i <= 255; i++) {
		set_active(stats, (dns_rdatatype_t)i);
	}
	set_active(stats, OTHERTYPE);
	set_active_nxdomain(stats);

	dns_rdatasetstats_dump(stats, verify_counters, &active,
			       ISC_STATSDUMP_VERBOSE);

	for (unsigned int i = 1; i <= 255; i++) {
		mark_stale(stats, (dns_rdatatype_t)i);
	}
	mark_stale(stats, OTHERTYPE);
	mark_stale_nxdomain(stats);

	dns_rdatasetstats_dump(stats, verify_counters, &stale,
			       ISC_STATSDUMP_VERBOSE);

	dns_stats_detach(&stats);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(active_stale)
ISC_TEST_LIST_END

ISC_TEST_MAIN
