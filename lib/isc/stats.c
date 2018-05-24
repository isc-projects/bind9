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

#include <string.h>

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/stats.h>
#include <isc/util.h>

#ifdef ISC_PLATFORM_USETHREADS
#include <stdatomic.h>
#endif

#define ISC_STATS_MAGIC			ISC_MAGIC('S', 't', 'a', 't')
#define ISC_STATS_VALID(x)		ISC_MAGIC_VALID(x, ISC_STATS_MAGIC)

/*%
 * `ISC_STATS_LOCKCOUNTERS` indicates if the complete set of statistics
 * counters have to be locked before update, so that an instantaneous
 * snapshot of them can be dumped.
 */
#define ISC_STATS_LOCKCOUNTERS 0

#ifdef ISC_PLATFORM_USETHREADS
typedef atomic_int_fast64_t isc_stat_t;
#else
typedef isc_int64_t isc_stat_t;
#endif

struct isc_stats {
	/*% Unlocked */
	unsigned int	magic;
	isc_mem_t	*mctx;
	int		ncounters;

	isc_refcount_t	references;

	isc_stat_t	*counters;

	/*%
	 * We don't want to lock the counters while we are dumping, so we first
	 * copy the current counter values into a local array.  This buffer
	 * will be used as the copy destination.  It's allocated on creation
	 * of the stats structure so that the dump operation won't fail due
	 * to memory allocation failure.
	 * XXX: this approach is weird for non-threaded build because the
	 * additional memory and the copy overhead could be avoided.  We prefer
	 * simplicity here, however, under the assumption that this function
	 * should be only rarely called.
	 */
	isc_uint64_t	*copiedcounters;
};

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_refcount_increment(&stats->references);

	*statsp = stats;
}

void
isc_stats_detach(isc_stats_t **statsp) {
	isc_stats_t *stats;
	int_fast32_t refcount;

	REQUIRE(statsp != NULL && ISC_STATS_VALID(*statsp));

	stats = *statsp;
	*statsp = NULL;

	refcount = isc_refcount_decrement(&stats->references);

	if (refcount == 1) {
		isc_mem_put(stats->mctx, stats->copiedcounters,
			    sizeof(isc_stat_t) * stats->ncounters);
		isc_mem_put(stats->mctx, stats->counters,
			    sizeof(isc_stat_t) * stats->ncounters);
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
		return;
	}
}

int
isc_stats_ncounters(isc_stats_t *stats) {
	REQUIRE(ISC_STATS_VALID(stats));

	return (stats->ncounters);
}

isc_result_t
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters) {
	isc_stats_t *stats;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(statsp != NULL && *statsp == NULL);

	stats = isc_mem_get(mctx, sizeof(*stats));
	if (stats == NULL)
		return (ISC_R_NOMEMORY);

	stats->counters = isc_mem_get(mctx, sizeof(isc_stat_t) * ncounters);
	if (stats->counters == NULL) {
		result = ISC_R_NOMEMORY;
		goto clean_stats;
	}

	stats->copiedcounters = isc_mem_get(mctx,
					    sizeof(isc_uint64_t) * ncounters);
	if (stats->copiedcounters == NULL) {
		result = ISC_R_NOMEMORY;
		goto clean_counters;
	}

	isc_refcount_init(&stats->references, 1);
	memset(stats->counters, 0, sizeof(isc_stat_t) * ncounters);
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->magic = ISC_STATS_MAGIC;

	*statsp = stats;

	return (result);

clean_counters:
	isc_mem_put(mctx, stats->counters, sizeof(isc_stat_t) * ncounters);

clean_stats:
	isc_mem_put(mctx, stats, sizeof(*stats));

	return (result);
}

void
isc_stats_increment(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);
#ifdef ISC_PLATFORM_USETHREADS
	atomic_fetch_add_explicit(&stats->counters[counter], 1,
				  memory_order_release);
#else /* ISC_PLATFORM_USETHREADS */
	stats->counters[counter]++;
#endif /* ISC_PLATFORM_USETHREADS */
}

void
isc_stats_decrement(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

#ifdef ISC_PLATFORM_USETHREADS
	atomic_fetch_sub_explicit(&stats->counters[counter], 1,
				  memory_order_release);
#else /* ISC_PLATFORM_USETHREADS */
	stats->counters[counter]--;
#endif /* ISC_PLATFORM_USETHREADS */
}

void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn,
	       void *arg, unsigned int options)
{
	int i;

	REQUIRE(ISC_STATS_VALID(stats));

#ifdef ISC_PLATFORM_USETHREADS
	for (i = 0; i < stats->ncounters; i++) {
		stats->copiedcounters[i] =
			atomic_load_explicit(&stats->counters[i],
					     memory_order_acquire);
	}

	for (i = 0; i < stats->ncounters; i++) {
		if ((options & ISC_STATSDUMP_VERBOSE) == 0 &&
		    stats->copiedcounters[i] == 0)
				continue;
		dump_fn((isc_statscounter_t)i, stats->copiedcounters[i], arg);
	}
#else /* ISC_PLATFORM_USETHREADS */
	for (i = 0; i < stats->ncounters; i++) {
		if ((options & ISC_STATSDUMP_VERBOSE) == 0 &&
		    stats->counters[i] == 0)
				continue;
		dump_fn((isc_statscounter_t)i, stats->counters[i], arg);
	}
#endif /* ISC_PLATFORM_USETHREADS */
}

void
isc_stats_set(isc_stats_t *stats, isc_uint64_t val,
	      isc_statscounter_t counter)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

#ifdef ISC_PLATFORM_USETHREADS
	atomic_store_explicit(&stats->counters[counter], val,
			      memory_order_release);
#else /* ISC_PLATFORM_USETHREADS */
	stats->counters[counter] = val;
#endif /* ISC_PLATFORM_USETHREADS */
}
