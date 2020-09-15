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

#include <config.h>

#if HAVE_CMOCKA

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <sched.h>
#include <inttypes.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>

#include "isctest.h"

#define TASKS 32
#define ITERATIONS 1000
#define COUNTS_PER_ITERATION 1000
#define INCREMENT_64 (int64_t)0x0000000010000000
#define EXPECTED_COUNT_32 (TASKS * ITERATIONS * COUNTS_PER_ITERATION)
#define EXPECTED_COUNT_64 (TASKS * ITERATIONS * COUNTS_PER_ITERATION * INCREMENT_64)

typedef struct {
	uint32_t iteration;
} counter_t;

counter_t counters[TASKS];

#if defined(ISC_PLATFORM_HAVEXADD) || \
    defined(ISC_PLATFORM_HAVEXADDQ) || \
    defined(ISC_PLATFORM_HAVEATOMICSTORE) || \
    defined(ISC_PLATFORM_HAVEATOMICSTOREQ)
static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}
#endif

#if defined(ISC_PLATFORM_HAVEXADD)
static int32_t counter_32;

static void
do_xadd(isc_task_t *task, isc_event_t *ev) {
	counter_t *state = (counter_t *)ev->ev_arg;
	int i;

	for (i = 0 ; i < COUNTS_PER_ITERATION ; i++) {
		isc_atomic_xadd(&counter_32, 1);
	}

	state->iteration++;
	if (state->iteration < ITERATIONS) {
		isc_task_send(task, &ev);
	} else {
		isc_event_free(&ev);
	}
}

/* Atomic XADD */
static void
atomic_xadd(void **state) {
	isc_task_t *tasks[TASKS];
	isc_event_t *event = NULL;
	int i;

	UNUSED(state);

	memset(counters, 0, sizeof(counters));
	counter_32 = 0;

	/*
	 * Create our tasks, and allocate an event to get the counters going.
	 */
	for (i = 0 ; i < TASKS ; i++) {
		tasks[i] = NULL;
		assert_int_equal(isc_task_create(taskmgr, 0, &tasks[i]),
				 ISC_R_SUCCESS);
		event = isc_event_allocate(mctx, NULL, 1000, do_xadd,
					   &counters[i],
					   sizeof(struct isc_event));
		assert_non_null(event);
		isc_task_sendanddetach(&tasks[i], &event);
	}

	isc_test_end();

	assert_int_equal(counter_32, EXPECTED_COUNT_32);
	counter_32 = 0;
}
#endif

#if defined(ISC_PLATFORM_HAVEXADDQ)
static int64_t counter_64;

static void
do_xaddq(isc_task_t *task, isc_event_t *ev) {
	counter_t *state = (counter_t *)ev->ev_arg;
	int i;

	for (i = 0 ; i < COUNTS_PER_ITERATION ; i++) {
		isc_atomic_xaddq(&counter_64, INCREMENT_64);
	}

	state->iteration++;
	if (state->iteration < ITERATIONS) {
		isc_task_send(task, &ev);
	} else {
		isc_event_free(&ev);
	}
}

/* Atomic XADDQ */
static void
atomic_xaddq(void **state) {
	isc_task_t *tasks[TASKS];
	isc_event_t *event = NULL;
	int i;

	UNUSED(state);

	memset(counters, 0, sizeof(counters));
	counter_64 = 0;

	/*
	 * Create our tasks, and allocate an event to get the counters going.
	 */
	for (i = 0 ; i < TASKS ; i++) {
		tasks[i] = NULL;
		assert_int_equal(isc_task_create(taskmgr, 0, &tasks[i]),
				 ISC_R_SUCCESS);
		event = isc_event_allocate(mctx, NULL, 1000, do_xaddq,
					   &counters[i],
					   sizeof(struct isc_event));
		assert_non_null(event);
		isc_task_sendanddetach(&tasks[i], &event);
	}

	isc_test_end();

	assert_int_equal(counter_64, EXPECTED_COUNT_64);
	counter_32 = 0;
}
#endif

#if defined(ISC_PLATFORM_HAVEATOMICSTORE)
static int32_t store_32;

static void
do_store(isc_task_t *task, isc_event_t *ev) {
	counter_t *state = (counter_t *)ev->ev_arg;
	int i;
	uint32_t r;
	uint32_t val;

	r = random() % 256;
	val = (r << 24) | (r << 16) | (r << 8) | r;

	for (i = 0 ; i < COUNTS_PER_ITERATION ; i++) {
		isc_atomic_store(&store_32, val);
	}

	state->iteration++;
	if (state->iteration < ITERATIONS) {
		isc_task_send(task, &ev);
	} else {
		isc_event_free(&ev);
	}
}

/* Atomic STORE */
static void
atomic_store(void **state) {
	isc_task_t *tasks[TASKS];
	isc_event_t *event = NULL;
	uint32_t val;
	uint32_t r;
	int i;

	UNUSED(state);

	memset(counters, 0, sizeof(counters));
	store_32 = 0;

	/*
	 * Create our tasks, and allocate an event to get the counters
	 * going.
	 */
	for (i = 0 ; i < TASKS ; i++) {
		tasks[i] = NULL;
		assert_int_equal(isc_task_create(taskmgr, 0, &tasks[i]),
				 ISC_R_SUCCESS);
		event = isc_event_allocate(mctx, NULL, 1000, do_store,
					   &counters[i],
					   sizeof(struct isc_event));
		assert_non_null(event);
		isc_task_sendanddetach(&tasks[i], &event);
	}

	isc_test_end();

	r = store_32 & 0xff;
	val = (r << 24) | (r << 16) | (r << 8) | r;

	assert_int_equal((uint32_t) store_32, val);
	store_32 = 0;
}
#endif

#if defined(ISC_PLATFORM_HAVEATOMICSTOREQ)
static int64_t store_64;

static void
do_storeq(isc_task_t *task, isc_event_t *ev) {
	counter_t *state = (counter_t *)ev->ev_arg;
	int i;
	uint8_t r;
	uint64_t val;

	r = random() % 256;
	val = (((uint64_t) r << 24) |
	       ((uint64_t) r << 16) |
	       ((uint64_t) r << 8) |
	       (uint64_t) r);
	val |= ((uint64_t) val << 32);

	for (i = 0 ; i < COUNTS_PER_ITERATION ; i++) {
		isc_atomic_storeq(&store_64, val);
	}

	state->iteration++;
	if (state->iteration < ITERATIONS) {
		isc_task_send(task, &ev);
	} else {
		isc_event_free(&ev);
	}
}

/* Atomic STOREQ */
static void
atomic_storeq(void **state) {
	isc_task_t *tasks[TASKS];
	isc_event_t *event = NULL;
	uint64_t val;
	uint32_t r;
	int i;

	UNUSED(state);

	memset(counters, 0, sizeof(counters));
	store_64 = 0;

	/*
	 * Create our tasks, and allocate an event to get the counters
	 * going.
	 */
	for (i = 0 ; i < TASKS ; i++) {
		tasks[i] = NULL;
		assert_int_equal(isc_task_create(taskmgr, 0, &tasks[i]),
				 ISC_R_SUCCESS);
		event = isc_event_allocate(mctx, NULL, 1000, do_storeq,
					   &counters[i],
					   sizeof(struct isc_event));
		assert_non_null(event);
		isc_task_sendanddetach(&tasks[i], &event);
	}

	isc_test_end();

	r = store_64 & 0xff;
	val = (((uint64_t) r << 24) |
	       ((uint64_t) r << 16) |
	       ((uint64_t) r << 8) |
	       (uint64_t) r);
	val |= ((uint64_t) val << 32);

	assert_int_equal((uint64_t) store_64, val);
	store_64 = 0;
}
#endif

int
main(void) {
#if defined(ISC_PLATFORM_HAVEXADD) || \
    defined(ISC_PLATFORM_HAVEXADDQ) || \
    defined(ISC_PLATFORM_HAVEATOMICSTORE) || \
    defined(ISC_PLATFORM_HAVEATOMICSTOREQ)
	const struct CMUnitTest tests[] = {
#if defined(ISC_PLATFORM_HAVEXADD)
		cmocka_unit_test_setup(atomic_xadd, _setup),
#endif
#if defined(ISC_PLATFORM_HAVEXADDQ)
		cmocka_unit_test_setup(atomic_xaddq, _setup),
#endif
#ifdef ISC_PLATFORM_HAVEATOMICSTORE
		cmocka_unit_test_setup(atomic_store, _setup),
#endif
#if defined(ISC_PLATFORM_HAVEATOMICSTOREQ)
		cmocka_unit_test_setup(atomic_storeq, _setup),
#endif
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
#else
	print_message("1..0 # Skipped: atomic operations not available\n");
#endif
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
