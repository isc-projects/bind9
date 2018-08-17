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

#include <inttypes.h>
#include <string.h>

#include <ck_pr.h>

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/stats.h>
#include <isc/util.h>

#define ISC_STATS_MAGIC			ISC_MAGIC('S', 't', 'a', 't')
#define ISC_STATS_VALID(x)		ISC_MAGIC_VALID(x, ISC_STATS_MAGIC)

typedef uint64_t isc_stat_t;

struct isc_stats {
	unsigned int	magic;
	isc_mem_t	*mctx;
	int		ncounters;

	unsigned int	references;

	isc_stat_t	*counters;
};

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	ck_pr_inc_uint(&stats->references);

	*statsp = stats;
}

void
isc_stats_detach(isc_stats_t **statsp) {
	REQUIRE(statsp != NULL && ISC_STATS_VALID(*statsp));

	isc_stats_t *stats = *statsp;

	ck_pr_dec_uint(&stats->references);
	ck_pr_fence_atomic_load();

	if (ck_pr_load_uint((const unsigned int *)&stats->references) == 0) {
		isc_mem_put(stats->mctx, stats->counters,
			    sizeof(isc_stat_t) * stats->ncounters);
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
	}

	*statsp = NULL;
}

int
isc_stats_ncounters(isc_stats_t *stats) {
	REQUIRE(ISC_STATS_VALID(stats));

	return (stats->ncounters);
}

isc_result_t
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_stats_t *stats;

	stats = isc_mem_get(mctx, sizeof(*stats));
	if (stats == NULL) {
		goto cleanup;
	}

	stats->counters = isc_mem_get(mctx, sizeof(isc_stat_t) * ncounters);
	if (stats->counters == NULL) {
		goto cleanup;
	}

	ck_pr_store_uint(&stats->references, 1);

	memset(stats->counters, 0, sizeof(isc_stat_t) * ncounters);
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->magic = ISC_STATS_MAGIC;

	*statsp = stats;

	return (ISC_R_SUCCESS);

cleanup:
	if (stats != NULL) {
		isc_mem_put(mctx, stats, sizeof(*stats));
	}

	return (ISC_R_NOMEMORY);
}

void
isc_stats_increment(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	ck_pr_inc_64(&stats->counters[counter]);
}

void
isc_stats_decrement(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	ck_pr_dec_64(&stats->counters[counter]);
}

void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn,
	       void *arg, unsigned int options)
{
	REQUIRE(ISC_STATS_VALID(stats));

	bool verbose = (options & ISC_STATSDUMP_VERBOSE);

	for (int i = 0; i < stats->ncounters; i++) {
		if (!verbose && stats->counters[i] == 0) {
			continue;
		}
		dump_fn((isc_statscounter_t)i,
			ck_pr_load_64((const uint64_t *)stats->counters[i]),
			arg);
	}
}

void
isc_stats_set(isc_stats_t *stats, uint64_t val,
	      isc_statscounter_t counter)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	ck_pr_store_64(&stats->counters[counter], val);
}
