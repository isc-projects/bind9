/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <inttypes.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/stats.h>
#include <isc/util.h>

#if defined(ISC_PLATFORM_HAVESTDATOMIC)
#if defined(__cplusplus)
#include <isc/stdatomic.h>
#else
#include <stdatomic.h>
#endif
#endif

#define ISC_STATS_MAGIC			ISC_MAGIC('S', 't', 'a', 't')
#define ISC_STATS_VALID(x)		ISC_MAGIC_VALID(x, ISC_STATS_MAGIC)

#if defined(ISC_PLATFORM_HAVESTDATOMIC)
/*%
 * Just use stdatomics
 */
#elif defined(ISC_PLATFORM_HAVEXADDQ) && defined(ISC_PLATFORM_HAVEATOMICSTOREQ)
/*%
 * Local macro confirming presence of 64-bit
 * increment and store operations, just to make
 * the later macros simpler
 */
# define ISC_STATS_HAVEATOMICQ 1
#else

/*%
 * Only lock the counters if 64-bit atomic operations are
 * not available but cheap atomic lock operations are.
 * On a modern 64-bit system this should never be the case.
 *
 * Normal locks are too expensive to be used whenever a counter
 * is updated.
 */
# if ISC_RWLOCK_USEATOMIC
#  define ISC_STATS_LOCKCOUNTERS 1
# endif /* ISC_RWLOCK_USEATOMIC */

/*%
 * If 64-bit atomic operations are not available but
 * 32-bit operations are then split the counter into two,
 * using the atomic operations to try to ensure that any carry
 * from the low word is correctly carried into the high word.
 *
 * Otherwise, just rely on standard 64-bit data types
 * and operations
 */
# if defined(ISC_PLATFORM_HAVEXADD)
#  define ISC_STATS_USEMULTIFIELDS 1
# endif /* ISC_PLATFORM_HAVEXADD */
#endif /* ISC_PLATFORM_HAVESTDATOMIC */

#if ISC_STATS_LOCKCOUNTERS
# define MAYBE_RWLOCK(a, b) isc_rwlock_lock(a, b);
# define MAYBE_RWUNLOCK(a, b) isc_rwlock_unlock(a, b)
#else
# define MAYBE_RWLOCK(a, b)
# define MAYBE_RWUNLOCK(a, b)
#endif

#if ISC_PLATFORM_HAVESTDATOMIC
typedef atomic_uint_fast64_t isc_stat_t;
#elif ISC_STATS_HAVEATOMICQ
typedef uint64_t isc_stat_t;
#elif ISC_STATS_USEMULTIFIELDS
typedef struct {
	uint32_t hi;
	uint32_t lo;
} isc_stat_t;
#else
typedef uint64_t isc_stat_t;
#endif

struct isc_stats {
	/*% Unlocked */
	unsigned int	magic;
	isc_mem_t	*mctx;
	int		ncounters;

	isc_mutex_t	lock;
	unsigned int	references; /* locked by lock */

	/*%
	 * Locked by counterlock or unlocked if efficient rwlock is not
	 * available.
	 */
#if ISC_STATS_LOCKCOUNTERS
	isc_rwlock_t	counterlock;
#endif
	isc_stat_t	*counters;
};

static isc_result_t
create_stats(isc_mem_t *mctx, int ncounters, isc_stats_t **statsp) {
	isc_stats_t *stats;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(statsp != NULL && *statsp == NULL);

	stats = isc_mem_get(mctx, sizeof(*stats));
	if (stats == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&stats->lock);
	if (result != ISC_R_SUCCESS)
		goto clean_stats;

	stats->counters = isc_mem_get(mctx, sizeof(isc_stat_t) * ncounters);
	if (stats->counters == NULL) {
		result = ISC_R_NOMEMORY;
		goto clean_mutex;
	}

#if ISC_STATS_LOCKCOUNTERS
	result = isc_rwlock_init(&stats->counterlock, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto clean_counters;
#endif

	stats->references = 1;
	memset(stats->counters, 0, sizeof(isc_stat_t) * ncounters);
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->magic = ISC_STATS_MAGIC;

	*statsp = stats;

	return (result);

#if ISC_STATS_LOCKCOUNTERS
clean_counters:
	isc_mem_put(mctx, stats->counters, sizeof(isc_stat_t) * ncounters);
#endif

clean_mutex:
	DESTROYLOCK(&stats->lock);

clean_stats:
	isc_mem_put(mctx, stats, sizeof(*stats));

	return (result);
}

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	LOCK(&stats->lock);
	stats->references++;
	UNLOCK(&stats->lock);

	*statsp = stats;
}

void
isc_stats_detach(isc_stats_t **statsp) {
	isc_stats_t *stats;

	REQUIRE(statsp != NULL && ISC_STATS_VALID(*statsp));

	stats = *statsp;
	*statsp = NULL;

	LOCK(&stats->lock);
	stats->references--;

	if (stats->references == 0) {
		isc_mem_put(stats->mctx, stats->counters,
			    sizeof(isc_stat_t) * stats->ncounters);
		UNLOCK(&stats->lock);
		DESTROYLOCK(&stats->lock);
#if ISC_STATS_LOCKCOUNTERS
		isc_rwlock_destroy(&stats->counterlock);
#endif
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
		return;
	}

	UNLOCK(&stats->lock);
}

int
isc_stats_ncounters(isc_stats_t *stats) {
	REQUIRE(ISC_STATS_VALID(stats));

	return (stats->ncounters);
}

/*
 * Inline the code if we can use atomic operations.
 */
#if defined(ISC_PLATFORM_HAVESTDATOMIC) || defined(ISC_STATS_HAVEATOMICQ) || \
    defined(ISC_STATS_USEMULTIFIELDS)
static inline void
incrementcounter(isc_stats_t *stats, int counter) {
#if ISC_PLATFORM_HAVESTDATOMIC
	(void)atomic_fetch_add_explicit(&stats->counters[counter], 1,
					memory_order_relaxed);
#elif ISC_STATS_HAVEATOMICQ
	isc_atomic_xaddq((int64_t *)&stats->counters[counter], 1);
#elif ISC_STATS_USEMULTIFIELDS
	int32_t prev = isc_atomic_xadd((int32_t *)&stats->counters[counter].lo, 1);
	/*
	 * If the lower 32-bit field overflows, increment the higher field.
	 * Note that it's *theoretically* possible that the lower field
	 * overlaps again before the higher field is incremented.  It doesn't
	 * matter, however, because we don't read the value until
	 * isc_stats_copy() is called where the whole process is protected
	 * by the write (exclusive) lock.
	 */
	if (prev == (int32_t)0xffffffff) {
		isc_atomic_xadd((int32_t *)&stats->counters[counter].hi, 1);
	}
#endif
}

static inline void
decrementcounter(isc_stats_t *stats, int counter) {
#if ISC_PLATFORM_HAVESTDATOMIC
	(void)atomic_fetch_sub_explicit(&stats->counters[counter], 1,
					memory_order_relaxed);
#elif ISC_STATS_HAVEATOMICQ
	(void)isc_atomic_xaddq((int64_t *)&stats->counters[counter], -1);
#elif ISC_STATS_USEMULTIFIELDS
	int32_t prev =
		isc_atomic_xadd((int32_t *)&stats->counters[counter].lo, -1);
	if (prev == 0) {
		(void)isc_atomic_xadd((int32_t *)&stats->counters[counter].hi,
				      -1);
	}
#endif
}

static inline uint64_t
getcounter(isc_stats_t *stats, const int counter) {
#if ISC_PLATFORM_HAVESTDATOMIC
	return(atomic_load_explicit(&stats->counters[counter],
				    memory_order_relaxed));
#elif ISC_STATS_HAVEATOMICQ
	/* use xaddq(..., 0) as an atomic load */
	return((uint64_t)isc_atomic_xaddq((int64_t *)&stats->counters[counter],
					  0));
#else
	uint64_t curr_value;
	curr_value = ((uint64_t)stats->counters[counter].hi << 32) |
			stats->counters[counter].lo;
	return (curr_value);
#endif
}

static inline void
setcounter(isc_stats_t *stats,
	   const isc_statscounter_t counter,
	   const uint64_t value)
{
#if ISC_PLATFORM_HAVESTDATOMIC
	atomic_store_explicit(&stats->counters[counter], value,
			      memory_order_relaxed);
#elif ISC_STATS_HAVEATOMICQ
	isc_atomic_storeq((int64_t *)&stats->counters[counter], value);
#else
# if ISC_STATS_USEMULTIFIELDS
	isc_atomic_store((int32_t *)&stats->counters[counter].hi,
			 (uint32_t)((value >> 32) & 0xffffffff));
	isc_atomic_store((int32_t *)&stats->counters[counter].lo,
			 (uint32_t)(value & 0xffffffff));
# endif
#endif
}
#else
ISC_NO_SANITIZE_THREAD static ISC_NO_SANITIZE_INLINE void
incrementcounter(isc_stats_t *stats, int counter) {
	stats->counters[counter]++;
}

ISC_NO_SANITIZE_THREAD static ISC_NO_SANITIZE_INLINE void
decrementcounter(isc_stats_t *stats, int counter) {
	stats->counters[counter]--;
}

ISC_NO_SANITIZE_THREAD static ISC_NO_SANITIZE_INLINE uint64_t
getcounter(isc_stats_t *stats, const int counter) {
	return (stats->counters[counter]);
}

ISC_NO_SANITIZE_THREAD static ISC_NO_SANITIZE_INLINE void
setcounter(isc_stats_t *stats,
	   const isc_statscounter_t counter,
	   const uint64_t value)
{
	stats->counters[counter] = value;
}
#endif

static void
copy_counters(isc_stats_t *stats, uint64_t *counters) {
	/*
	 * We use a "write" lock before "reading" the statistics counters as
	 * an exclusive lock.
	 */
	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_write);
	for (isc_statscounter_t counter = 0;
	     counter < stats->ncounters;
	     counter++)
	{
		counters[counter] = getcounter(stats, counter);
	}
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_write);
}

isc_result_t
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	return (create_stats(mctx, ncounters, statsp));
}

void
isc_stats_increment(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	/*
	 * We use a "read" lock to prevent other threads from reading the
	 * counter while we "writing" a counter field.  The write access itself
	 * is protected by the atomic operation.
	 */
	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_read);
	incrementcounter(stats, (int)counter);
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_read);
}

void
isc_stats_decrement(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_read);
	decrementcounter(stats, (int)counter);
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_read);
}

void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn,
	       void *arg, unsigned int options)
{
	REQUIRE(ISC_STATS_VALID(stats));

	uint64_t *counters;
	bool verbose = ((options & ISC_STATSDUMP_VERBOSE) != 0);

	counters = isc_mem_get(stats->mctx,
			       sizeof(uint64_t) * stats->ncounters);

	copy_counters(stats, counters);

	for (isc_statscounter_t counter = 0;
	     counter < stats->ncounters;
	     counter++)
	{
		if (!verbose && counters[counter] == 0)
		{
			continue;
		}
		dump_fn(counter, counters[counter], arg);
	}

	isc_mem_put(stats->mctx,
		    counters, sizeof(isc_stat_t) * stats->ncounters);
}

void
isc_stats_set(isc_stats_t *stats, uint64_t val,
	      isc_statscounter_t counter)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	/*
	 * We use a "write" lock before "reading" the statistics counters as
	 * an exclusive lock.
	 */
	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_write);
	setcounter(stats, counter, val);
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_write);
}

void
isc_stats_update_if_greater(isc_stats_t *stats,
				 isc_statscounter_t counter,
				 uint64_t value)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

#if ISC_PLATFORM_HAVESTDATOMIC
	uint64_t curr_value = atomic_load_explicit(&stats->counters[counter],
						   memory_order_relaxed);
	do {
		if (curr_value >= value) {
			break;
		}

	} while (!atomic_compare_exchange_strong(&stats->counters[counter],
						 &curr_value,
						 value));
#else
	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_write);
	uint64_t curr_value = getcounter(stats, counter);
	if (curr_value < value) {
		setcounter(stats, counter, value);
	}
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_write);
#endif
}

uint64_t
isc_stats_get_counter(isc_stats_t *stats, isc_statscounter_t counter)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	MAYBE_RWLOCK(&stats->counterlock, isc_rwlocktype_read);
	uint64_t curr_value = getcounter(stats, counter);
	MAYBE_RWUNLOCK(&stats->counterlock, isc_rwlocktype_read);

	return (curr_value);
}
