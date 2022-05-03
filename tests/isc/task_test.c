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

#include <isc/atomic.h>
#include <isc/cmocka.h>
#include <isc/commandline.h>
#include <isc/condition.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>
#include <isc/uv.h>

#include <tests/isc.h>

/* Set to true (or use -v option) for verbose output */
static bool verbose = false;

static isc_mutex_t lock;
static isc_condition_t cv;

atomic_int_fast32_t counter;
static int active[10];
static atomic_bool done;

static int
_setup(void **state) {
	isc_mutex_init(&lock);
	isc_condition_init(&cv);

	workers = 0;
	setup_managers(state);

	return (0);
}

static int
_setup2(void **state) {
	isc_mutex_init(&lock);
	isc_condition_init(&cv);

	/* Two worker threads */
	workers = 2;
	setup_managers(state);

	return (0);
}

static int
_setup4(void **state) {
	isc_mutex_init(&lock);
	isc_condition_init(&cv);

	/* Four worker threads */
	workers = 4;
	setup_managers(state);

	return (0);
}

static int
_teardown(void **state) {
	teardown_managers(state);

	isc_condition_destroy(&cv);
	isc_mutex_destroy(&lock);

	return (0);
}

static void
set(isc_task_t *task, isc_event_t *event) {
	atomic_int_fast32_t *value = (atomic_int_fast32_t *)event->ev_arg;

	UNUSED(task);

	isc_event_free(&event);
	atomic_store(value, atomic_fetch_add(&counter, 1));
}

#include <isc/thread.h>

/* Create a task */
ISC_RUN_TEST_IMPL(create_task) {
	isc_result_t result;
	isc_task_t *task = NULL;

	UNUSED(state);

	result = isc_task_create(taskmgr, 0, &task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_task_detach(&task);
	assert_null(task);
}

/* Process events */
ISC_RUN_TEST_IMPL(all_events) {
	isc_result_t result;
	isc_task_t *task = NULL;
	isc_event_t *event = NULL;
	atomic_int_fast32_t a, b;
	int i = 0;

	UNUSED(state);

	atomic_init(&counter, 1);
	atomic_init(&a, 0);
	atomic_init(&b, 0);

	result = isc_task_create(taskmgr, 0, &task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* First event */
	event = isc_event_allocate(mctx, task, ISC_TASKEVENT_TEST, set, &a,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(atomic_load(&a), 0);
	isc_task_send(task, &event);

	event = isc_event_allocate(mctx, task, ISC_TASKEVENT_TEST, set, &b,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(atomic_load(&b), 0);
	isc_task_send(task, &event);

	while ((atomic_load(&a) == 0 || atomic_load(&b) == 0) && i++ < 5000) {
		uv_sleep(1);
	}

	assert_int_not_equal(atomic_load(&a), 0);
	assert_int_not_equal(atomic_load(&b), 0);

	isc_task_detach(&task);
	assert_null(task);
}

/*
 * Basic task functions:
 */
static void
basic_cb(isc_task_t *task, isc_event_t *event) {
	int i, j;

	UNUSED(task);

	j = 0;
	for (i = 0; i < 1000000; i++) {
		j += 100;
	}

	UNUSED(j);

	if (verbose) {
		print_message("# task %s\n", (char *)event->ev_arg);
	}

	isc_event_free(&event);
}

static void
basic_tick(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	if (verbose) {
		print_message("# %s\n", (char *)event->ev_arg);
	}

	isc_event_free(&event);
}

static char one[] = "1";
static char two[] = "2";
static char three[] = "3";
static char four[] = "4";
static char tick[] = "tick";
static char tock[] = "tock";

ISC_RUN_TEST_IMPL(basic) {
	isc_result_t result;
	isc_task_t *task1 = NULL;
	isc_task_t *task2 = NULL;
	isc_task_t *task3 = NULL;
	isc_task_t *task4 = NULL;
	isc_event_t *event = NULL;
	isc_timer_t *ti1 = NULL;
	isc_timer_t *ti2 = NULL;
	isc_interval_t interval;
	char *testarray[] = { one, one, one,   one,  one, one,	 one,  one,
			      one, two, three, four, two, three, four, NULL };
	int i;

	UNUSED(state);

	result = isc_task_create(taskmgr, 0, &task1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, 0, &task2, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, 0, &task3, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, 0, &task4, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_interval_set(&interval, 1, 0);
	isc_timer_create(timermgr, task1, basic_tick, tick, &ti1);
	result = isc_timer_reset(ti1, isc_timertype_ticker, &interval, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	ti2 = NULL;
	isc_interval_set(&interval, 1, 0);
	isc_timer_create(timermgr, task2, basic_tick, tock, &ti2);
	result = isc_timer_reset(ti2, isc_timertype_ticker, &interval, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	sleep(2);

	for (i = 0; testarray[i] != NULL; i++) {
		/*
		 * Note:  (void *)1 is used as a sender here, since some
		 * compilers don't like casting a function pointer to a
		 * (void *).
		 *
		 * In a real use, it is more likely the sender would be a
		 * structure (socket, timer, task, etc) but this is just a
		 * test program.
		 */
		event = isc_event_allocate(mctx, (void *)1, 1, basic_cb,
					   testarray[i], sizeof(*event));
		assert_non_null(event);
		isc_task_send(task1, &event);
	}

	isc_task_detach(&task1);
	isc_task_detach(&task2);
	isc_task_detach(&task3);
	isc_task_detach(&task4);

	sleep(10);
	isc_timer_destroy(&ti1);
	isc_timer_destroy(&ti2);
}

/*
 * Exclusive mode test:
 * When one task enters exclusive mode, all other active
 * tasks complete first.
 */
static int
spin(int n) {
	int i;
	int r = 0;
	for (i = 0; i < n; i++) {
		r += i;
		if (r > 1000000) {
			r = 0;
		}
	}
	return (r);
}

static void
exclusive_cb(isc_task_t *task, isc_event_t *event) {
	int taskno = *(int *)(event->ev_arg);

	if (verbose) {
		print_message("# task enter %d\n", taskno);
	}

	/* task chosen from the middle of the range */
	if (taskno == 6) {
		isc_result_t result;
		int i;

		result = isc_task_beginexclusive(task);
		assert_int_equal(result, ISC_R_SUCCESS);

		for (i = 0; i < 10; i++) {
			assert_int_equal(active[i], 0);
		}

		isc_task_endexclusive(task);
		atomic_store(&done, true);
	} else {
		active[taskno]++;
		(void)spin(10000000);
		active[taskno]--;
	}

	if (verbose) {
		print_message("# task exit %d\n", taskno);
	}

	if (atomic_load(&done)) {
		isc_mem_put(event->ev_destroy_arg, event->ev_arg, sizeof(int));
		isc_event_free(&event);
		atomic_fetch_sub(&counter, 1);
	} else {
		isc_task_send(task, &event);
	}
}

ISC_RUN_TEST_IMPL(task_exclusive) {
	isc_task_t *tasks[10];
	isc_result_t result;
	int i;

	UNUSED(state);

	atomic_init(&counter, 0);

	for (i = 0; i < 10; i++) {
		isc_event_t *event = NULL;
		int *v;

		tasks[i] = NULL;

		if (i == 6) {
			/* task chosen from the middle of the range */
			result = isc_task_create(taskmgr, 0, &tasks[i], 0);
			assert_int_equal(result, ISC_R_SUCCESS);

			isc_taskmgr_setexcltask(taskmgr, tasks[6]);
		} else {
			result = isc_task_create(taskmgr, 0, &tasks[i], 0);
			assert_int_equal(result, ISC_R_SUCCESS);
		}

		v = isc_mem_get(mctx, sizeof *v);
		assert_non_null(v);

		*v = i;

		event = isc_event_allocate(mctx, NULL, 1, exclusive_cb, v,
					   sizeof(*event));
		assert_non_null(event);

		isc_task_send(tasks[i], &event);
		atomic_fetch_add(&counter, 1);
	}

	for (i = 0; i < 10; i++) {
		isc_task_detach(&tasks[i]);
	}

	while (atomic_load(&counter) > 0) {
		uv_sleep(1);
	}
}

/*
 * Max tasks test:
 * The task system can create and execute many tasks. Tests with 10000.
 */

static void
maxtask_cb(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	uintptr_t ntasks = (uintptr_t)event->ev_arg;

	if (ntasks-- > 0) {
		task = NULL;

		event->ev_arg = (void *)ntasks;

		/*
		 * Create a new task and forward the message.
		 */
		result = isc_task_create(taskmgr, 0, &task, 0);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_task_send(task, &event);
		isc_task_detach(&task);
	} else {
		isc_event_free(&event);

		LOCK(&lock);
		atomic_store(&done, true);
		SIGNAL(&cv);
		UNLOCK(&lock);
	}
}

ISC_RUN_TEST_IMPL(manytasks) {
	isc_event_t *event = NULL;
	uintptr_t ntasks = 2; /* 0000; */

	UNUSED(state);

	if (verbose) {
		print_message("# Testing with %lu tasks\n",
			      (unsigned long)ntasks);
	}

	atomic_init(&done, false);

	event = isc_event_allocate(mctx, NULL, 1, maxtask_cb, (void *)ntasks,
				   sizeof(*event));
	assert_non_null(event);

	LOCK(&lock);
	maxtask_cb(NULL, event);
	while (!atomic_load(&done)) {
		WAIT(&cv, &lock);
	}
	UNLOCK(&lock);
}

/*
 * Helper for the purge tests below:
 */

#define SENDERCNT 3
#define TYPECNT	  4
#define TAGCNT	  5
#define NEVENTS	  (SENDERCNT * TYPECNT * TAGCNT)

static int eventcnt;

atomic_bool started;

/*
 * Helpers for purge event tests
 */
static void
pge_event1(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	LOCK(&lock);
	while (!atomic_load(&started)) {
		WAIT(&cv, &lock);
	}
	UNLOCK(&lock);

	LOCK(&lock);
	atomic_store(&done, true);
	SIGNAL(&cv);
	UNLOCK(&lock);

	isc_event_free(&event);
}

static void
pge_event2(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	++eventcnt;
	isc_event_free(&event);
}

static void
try_purgeevent(void) {
	isc_result_t result;
	isc_task_t *task = NULL;
	bool purged;
	isc_event_t *event1 = NULL;
	isc_event_t *event2 = NULL;
	isc_event_t *event2_clone = NULL;
	isc_time_t now;
	isc_interval_t interval;

	atomic_init(&started, false);
	atomic_init(&done, false);
	eventcnt = 0;

	result = isc_task_create(taskmgr, 0, &task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Block the task on cv.
	 */
	event1 = isc_event_allocate(mctx, (void *)1, (isc_eventtype_t)1,
				    pge_event1, NULL, sizeof(*event1));
	assert_non_null(event1);
	isc_task_send(task, &event1);

	event2 = isc_event_allocate(mctx, (void *)1, (isc_eventtype_t)1,
				    pge_event2, NULL, sizeof(*event2));
	assert_non_null(event2);

	event2_clone = event2;

	isc_task_send(task, &event2);

	purged = isc_task_purgeevent(task, event2_clone);

	assert_true(purged);

	/*
	 * Unblock the task, allowing event processing.
	 */
	LOCK(&lock);
	atomic_store(&started, true);
	SIGNAL(&cv);

	isc_interval_set(&interval, 5, 0);

	/*
	 * Wait for shutdown processing to complete.
	 */
	while (!atomic_load(&done)) {
		result = isc_time_nowplusinterval(&now, &interval);
		assert_int_equal(result, ISC_R_SUCCESS);

		WAITUNTIL(&cv, &lock, &now);
	}
	UNLOCK(&lock);

	isc_task_detach(&task);
}

/*
 * Purge event test:
 * When the event is marked as purgeable, a call to
 * isc_task_purgeevent(task, event) purges the event 'event' from the
 * task's queue and returns true.
 */

ISC_RUN_TEST_IMPL(purgeevent) {
	UNUSED(state);

	try_purgeevent();
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(manytasks, _setup4, _teardown)
ISC_TEST_ENTRY_CUSTOM(all_events, _setup, _teardown)
ISC_TEST_ENTRY_CUSTOM(basic, _setup2, _teardown)
ISC_TEST_ENTRY_CUSTOM(create_task, _setup, _teardown)
ISC_TEST_ENTRY_CUSTOM(purgeevent, _setup2, _teardown)
ISC_TEST_ENTRY_CUSTOM(task_exclusive, _setup4, _teardown)

ISC_TEST_LIST_END

ISC_TEST_MAIN
