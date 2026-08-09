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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/stats.h>
#include <isc/statsmulti.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <tests/isc.h>

/* test stats */
ISC_RUN_TEST_IMPL(isc_stats_basic) {
	isc_stats_t *stats = NULL;

	isc_stats_create(isc_g_mctx, &stats, 4);
	assert_int_equal(isc_stats_ncounters(stats), 4);

	/* Default all 0. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		assert_int_equal(isc_stats_get_counter(stats, i), 0);
	}

	/* Test increment. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		isc_stats_increment(stats, i);
		assert_int_equal(isc_stats_get_counter(stats, i), 1);
		isc_stats_increment(stats, i);
		assert_int_equal(isc_stats_get_counter(stats, i), 2);
	}

	/* Test decrement. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		isc_stats_decrement(stats, i);
		assert_int_equal(isc_stats_get_counter(stats, i), 1);
		isc_stats_decrement(stats, i);
		assert_int_equal(isc_stats_get_counter(stats, i), 0);
	}

	/* Test set. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		isc_stats_set(stats, i, i);
		assert_int_equal(isc_stats_get_counter(stats, i), i);
	}

	/* Test update if greater. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		isc_stats_update_if_greater(stats, i, i);
		assert_int_equal(isc_stats_get_counter(stats, i), i);
		isc_stats_update_if_greater(stats, i, i + 1);
		assert_int_equal(isc_stats_get_counter(stats, i), i + 1);
	}

	/* Counter values can be retrieved. */
	for (int i = 0; i < isc_stats_ncounters(stats); i++) {
		assert_int_equal(isc_stats_get_counter(stats, i), i + 1);
	}

	isc_stats_detach(&stats);
}

/* test statsmulti */
ISC_RUN_TEST_IMPL(isc_statsmulti_basic) {
	isc_statsmulti_t *stats = NULL;

	/* Create with 3 additive counters */
	isc_statsmulti_create(isc_g_mctx, &stats, 3);

	/* Test increment on additive counters */
	for (int i = 0; i < 3; i++) {
		isc_statsmulti_increment(stats, i);
		assert_int_equal(isc_statsmulti_get_counter(stats, i), 1);
		isc_statsmulti_increment(stats, i);
		assert_int_equal(isc_statsmulti_get_counter(stats, i), 2);
	}

	/* Test decrement on additive counters */
	for (int i = 0; i < 3; i++) {
		isc_statsmulti_decrement(stats, i);
		assert_int_equal(isc_statsmulti_get_counter(stats, i), 1);
		isc_statsmulti_decrement(stats, i);
		assert_int_equal(isc_statsmulti_get_counter(stats, i), 0);
	}

	/* Test clear */
	isc_statsmulti_increment(stats, 0);
	isc_statsmulti_increment(stats, 1);
	isc_statsmulti_clear(stats);
	for (int i = 0; i < 3; i++) {
		assert_int_equal(isc_statsmulti_get_counter(stats, i), 0);
	}

	isc_statsmulti_detach(&stats);
}

/* test statsmulti with multiple threads */
static isc_statsmulti_t *mt_stats = NULL;
static atomic_uint_fast32_t mt_workers_completed = 0;
static int mt_counter_id = 0; /* Global counter ID */

#define MT_INCREMENTS_PER_THREAD 100000

static void
mt_increment_worker(void *arg ISC_ATTR_UNUSED) {
	/* Do exactly 100,000 increments */
	for (int i = 0; i < MT_INCREMENTS_PER_THREAD; i++) {
		isc_statsmulti_increment(mt_stats, mt_counter_id);
	}

	/* Signal completion and check if we're the last one */
	uint32_t completed = atomic_fetch_add(&mt_workers_completed, 1) + 1;
	if (completed == isc_loopmgr_nloops()) {
		/* Last worker shuts down the loop manager */
		isc_loopmgr_shutdown();
	}
}

static void
mt_setup_workers(void *arg ISC_ATTR_UNUSED) {
	/* Start workers on each loop */
	for (size_t i = 0; i < isc_loopmgr_nloops(); i++) {
		isc_async_run(isc_loop_get(i), mt_increment_worker, NULL);
	}
}

ISC_RUN_TEST_IMPL(isc_statsmulti_multithread) {
	atomic_store(&mt_workers_completed, 0);

	/* Create stats with 1 additive counter */
	isc_statsmulti_create(isc_g_mctx, &mt_stats, 1);

	isc_loop_setup(isc_loop_main(), mt_setup_workers, NULL);
	isc_loopmgr_run();

	/* Check results - should be exactly threads * increments per thread */
	uint64_t actual_count = isc_statsmulti_get_counter(mt_stats, 0);
	uint64_t expected_total = (uint64_t)isc_loopmgr_nloops() *
				  MT_INCREMENTS_PER_THREAD;

	/* Verify no increments were lost */
	assert_int_equal(actual_count, expected_total);
	assert_true(actual_count > 0);

	/* Verify all workers completed */
	assert_int_equal(atomic_load(&mt_workers_completed),
			 isc_loopmgr_nloops());

	/* Cleanup */
	isc_statsmulti_detach(&mt_stats);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_stats_basic)
ISC_TEST_ENTRY(isc_statsmulti_basic)
ISC_TEST_ENTRY_CUSTOM(isc_statsmulti_multithread, setup_loopmgr,
		      teardown_loopmgr)

ISC_TEST_LIST_END

ISC_TEST_MAIN
