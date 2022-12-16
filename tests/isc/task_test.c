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
#include <isc/event.h>
#include <isc/job.h>
#include <isc/loop.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>
#include <isc/work.h>

#include <tests/isc.h>

static atomic_int_fast32_t counter;
static int active[10];
static atomic_bool done = false;

atomic_int_fast32_t set_a, set_b;

static void
set(isc_task_t *task, isc_event_t *event) {
	atomic_int_fast32_t *value = (atomic_int_fast32_t *)event->ev_arg;

	UNUSED(task);

	isc_event_free(&event);
	atomic_store(value, atomic_fetch_add(&counter, 1));

	if ((atomic_load(&set_a) != 0 && atomic_load(&set_b) != 0)) {
		isc_loopmgr_shutdown(loopmgr);
	}
}

#include <isc/thread.h>

ISC_LOOP_TEST_IMPL(create_task) {
	isc_result_t result;
	isc_task_t *task = NULL;

	result = isc_task_create(taskmgr, &task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_task_detach(&task);
	assert_null(task);

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_SETUP_IMPL(all_events) {
	atomic_init(&set_a, 0);
	atomic_init(&set_b, 0);
}

ISC_LOOP_TEARDOWN_IMPL(all_events) {
	assert_int_not_equal(atomic_load(&set_a), 0);
	assert_int_not_equal(atomic_load(&set_b), 0);
}

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(all_events) {
	isc_result_t result;
	isc_task_t *task = NULL;
	isc_event_t *event = NULL;

	atomic_init(&counter, 1);

	result = isc_task_create(taskmgr, &task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* First event */
	event = isc_event_allocate(mctx, task, ISC_TASKEVENT_TEST, set, &set_a,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(atomic_load(&set_a), 0);
	isc_task_send(task, &event);

	event = isc_event_allocate(mctx, task, ISC_TASKEVENT_TEST, set, &set_b,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(atomic_load(&set_b), 0);
	isc_task_send(task, &event);

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
	isc_event_free(&event);
}

static void
basic_tick(void *arg __attribute__((__unused__))) {
	/* no-op */
}

static char one[] = "1";
static char two[] = "2";
static char three[] = "3";
static char four[] = "4";
static char tick[] = "tick";
static char tock[] = "tock";

isc_task_t *task1 = NULL;
isc_task_t *task2 = NULL;
isc_task_t *task3 = NULL;
isc_task_t *task4 = NULL;
isc_timer_t *ti1 = NULL;
isc_timer_t *ti2 = NULL;

static void
basic_work(void *arg __attribute__((__unused__))) {
	char *testarray[] = { one, one, one,   one,  one, one,	 one,  one,
			      one, two, three, four, two, three, four, NULL };
	sleep(2);

	for (size_t i = 0; testarray[i] != NULL; i++) {
		/*
		 * Note:  (void *)1 is used as a sender here, since some
		 * compilers don't like casting a function pointer to a
		 * (void *).
		 *
		 * In a real use, it is more likely the sender would be a
		 * structure (socket, timer, task, etc) but this is just a
		 * test program.
		 */
		isc_event_t *event = isc_event_allocate(mctx, &task1, 1,
							basic_cb, testarray[i],
							sizeof(*event));
		assert_non_null(event);
		isc_task_send(task1, &event);
	}
}

static void
basic_after_work(void *arg) {
	UNUSED(arg);

	sleep(5);

	isc_task_detach(&task1);
	isc_task_detach(&task2);
	isc_task_detach(&task3);
	isc_task_detach(&task4);

	sleep(5);

	isc_timer_destroy(&ti1);
	isc_timer_destroy(&ti2);

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(basic) {
	isc_result_t result;
	isc_interval_t interval;

	UNUSED(arg);

	result = isc_task_create(taskmgr, &task1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, &task2, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, &task3, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_task_create(taskmgr, &task4, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_interval_set(&interval, 1, 0);
	isc_timer_create(mainloop, basic_tick, tick, &ti1);
	isc_timer_start(ti1, isc_timertype_ticker, &interval);

	isc_interval_set(&interval, 1, 0);
	isc_timer_create(mainloop, basic_tick, tock, &ti2);
	isc_timer_start(ti2, isc_timertype_ticker, &interval);

	isc_work_enqueue(mainloop, basic_work, basic_after_work, NULL);
}

/*
 * Exclusive mode test:
 * When one task enters exclusive mode, all other active
 * tasks complete first.
 */

static void
exclusive_cb(isc_task_t *task, isc_event_t *event) {
	int taskno = *(int *)(event->ev_arg);

	/* task chosen from the middle of the range */
	if (taskno == 6) {
		int i;

		isc_task_beginexclusive(task);

		for (i = 0; i < 10; i++) {
			assert_int_equal(active[i], 0);
		}

		isc_task_endexclusive(task);
		atomic_store(&done, true);
	} else {
		active[taskno]++;
		isc_thread_yield();
		active[taskno]--;
	}

	if (atomic_load(&done)) {
		isc_mem_put(event->ev_destroy_arg, event->ev_arg, sizeof(int));
		isc_event_free(&event);
		atomic_fetch_sub(&counter, 1);
		isc_loopmgr_shutdown(loopmgr);
	} else {
		isc_task_send(task, &event);
	}
}

isc_task_t *tasks[10] = { NULL };

ISC_LOOP_SETUP_IMPL(task_exclusive) {
	isc_result_t result;

	atomic_init(&counter, 0);
	atomic_init(&done, false);

	for (size_t i = 0; i < 10; i++) {
		uint32_t tid = i % isc_loopmgr_nloops(loopmgr);

		if (i == 6) {
			/* task chosen from the middle of the range */
			tid = 0;
			result = isc_task_create(taskmgr, &tasks[i], tid);
			assert_int_equal(result, ISC_R_SUCCESS);

			isc_taskmgr_setexcltask(taskmgr, tasks[i]);
		} else {
			result = isc_task_create(taskmgr, &tasks[i], tid);
			assert_int_equal(result, ISC_R_SUCCESS);
		}
	}
}

ISC_LOOP_TEST_SETUP_IMPL(task_exclusive) {
	UNUSED(arg);

	for (size_t i = 0; i < 10; i++) {
		isc_event_t *event = NULL;
		int *v;

		v = isc_mem_get(mctx, sizeof *v);
		assert_non_null(v);

		*v = i;

		event = isc_event_allocate(mctx, NULL, 1, exclusive_cb, v,
					   sizeof(*event));
		assert_non_null(event);

		isc_task_send(tasks[i], &event);
		atomic_fetch_add(&counter, 1);
		isc_task_detach(&tasks[i]);
	}
}

static void
maxtask_cb(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	uintptr_t ntasks = (uintptr_t)event->ev_arg;

	if (event->ev_arg != NULL) {
		isc_task_t *newtask = NULL;

		event->ev_arg = (void *)(ntasks - 1);

		/*
		 * Create a new task and forward the message.
		 */
		result = isc_task_create(taskmgr, &newtask, 0);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_task_send(newtask, &event);
	} else {
		isc_event_free(&event);
		isc_loopmgr_shutdown(loopmgr);
	}

	if (task != NULL) {
		isc_task_detach(&task);
	}
}

ISC_LOOP_TEST_IMPL(manytasks) {
	isc_event_t *event = NULL;
	uintptr_t ntasks = 10000;

	UNUSED(arg);

	event = isc_event_allocate(mctx, (void *)1, 1, maxtask_cb,
				   (void *)ntasks, sizeof(*event));
	assert_non_null(event);

	maxtask_cb(NULL, event);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(manytasks, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(all_events, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(basic, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(create_task, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(task_exclusive, setup_managers, teardown_managers)

ISC_TEST_LIST_END

ISC_TEST_MAIN
