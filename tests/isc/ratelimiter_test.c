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

#include <isc/event.h>
#include <isc/job.h>
#include <isc/loop.h>
#include <isc/ratelimiter.h>
#include <isc/task.h>
#include <isc/time.h>

#include "ratelimiter.c"

#include <tests/isc.h>

isc_ratelimiter_t *rl = NULL;

ISC_LOOP_TEST_IMPL(ratelimiter_create) {
	rl = NULL;
	expect_assert_failure(isc_ratelimiter_create(NULL, &rl));
	expect_assert_failure(isc_ratelimiter_create(mainloop, NULL));
	rl = (isc_ratelimiter_t *)&rl;
	expect_assert_failure(isc_ratelimiter_create(mainloop, &rl));

	rl = NULL;
	isc_ratelimiter_create(mainloop, &rl);
	isc_ratelimiter_shutdown(rl);

	isc_ratelimiter_detach(&rl);

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(ratelimiter_shutdown) {
	rl = NULL;

	expect_assert_failure(isc_ratelimiter_shutdown(NULL));
	expect_assert_failure(isc_ratelimiter_shutdown(rl));

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(ratelimiter_detach) {
	rl = NULL;

	expect_assert_failure(isc_ratelimiter_detach(NULL));
	expect_assert_failure(isc_ratelimiter_detach(&rl));

	isc_loopmgr_shutdown(loopmgr);
}

static int ticks = 0;
static isc_task_t *rl_task = NULL;
static isc_time_t start_time;
static isc_time_t tick_time;

static void
tick(isc_task_t *task, isc_event_t *event) {
	assert_ptr_equal(task, rl_task);
	isc_event_free(&event);

	ticks++;

	assert_int_equal(isc_time_now(&tick_time), ISC_R_SUCCESS);

	isc_loopmgr_shutdown(loopmgr);

	isc_task_detach(&rl_task);
	isc_ratelimiter_shutdown(rl);
	isc_ratelimiter_detach(&rl);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_common) {
	isc_result_t result = isc_task_create(taskmgr, &rl_task, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	rl = NULL;
	isc_time_set(&tick_time, 0, 0);
	assert_int_equal(isc_time_now(&start_time), ISC_R_SUCCESS);
	isc_ratelimiter_create(mainloop, &rl);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_enqueue) {
	ticks = 0;
	setup_loop_ratelimiter_common(arg);
}

ISC_LOOP_TEARDOWN_IMPL(ratelimiter_enqueue) { assert_int_equal(ticks, 1); }

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(ratelimiter_enqueue) {
	isc_result_t result;
	isc_event_t *event = NULL;

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	result = isc_ratelimiter_enqueue(rl, rl_task, &event);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_enqueue_shutdown) {
	ticks = 0;
	setup_loop_ratelimiter_common(arg);
}

ISC_LOOP_TEARDOWN_IMPL(ratelimiter_enqueue_shutdown) {
	assert_int_equal(ticks, 1);
}

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(ratelimiter_enqueue_shutdown) {
	isc_event_t *event = NULL;

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	expect_assert_failure(isc_ratelimiter_enqueue(NULL, rl_task, &event));
	expect_assert_failure(isc_ratelimiter_enqueue(rl, NULL, &event));
	expect_assert_failure(isc_ratelimiter_enqueue(rl, rl_task, NULL));
	expect_assert_failure(
		isc_ratelimiter_enqueue(rl, rl_task, &(isc_event_t *){ NULL }));

	assert_int_equal(isc_ratelimiter_enqueue(rl, rl_task, &event),
			 ISC_R_SUCCESS);

	isc_ratelimiter_shutdown(rl);

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(isc_ratelimiter_enqueue(rl, rl_task, &event),
			 ISC_R_SHUTTINGDOWN);

	isc_event_free(&event);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_dequeue) {
	ticks = 0;
	setup_loop_ratelimiter_common(arg);
}

ISC_LOOP_TEARDOWN_IMPL(ratelimiter_dequeue) { /* */
	assert_int_equal(ticks, 1);
}

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(ratelimiter_dequeue) {
	isc_event_t *event = NULL;

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);
	assert_int_equal(
		isc_ratelimiter_enqueue(rl, rl_task, &(isc_event_t *){ event }),
		ISC_R_SUCCESS);
	assert_int_equal(isc_ratelimiter_dequeue(rl, event), ISC_R_SUCCESS);
	isc_event_free(&event);
	assert_null(event);

	/* This event didn't get scheduled */
	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);
	assert_int_equal(isc_ratelimiter_dequeue(rl, event), ISC_R_NOTFOUND);
	assert_int_equal(isc_ratelimiter_enqueue(rl, rl_task, &event),
			 ISC_R_SUCCESS);
	assert_null(event);
}

static isc_time_t tock_time;

static void
tock(isc_task_t *task, isc_event_t *event) {
	assert_ptr_equal(task, rl_task);
	isc_event_free(&event);

	ticks++;
	assert_int_equal(isc_time_now(&tock_time), ISC_R_SUCCESS);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_pertick_interval) {
	ticks = 0;
	isc_time_set(&tock_time, 0, 0);
	setup_loop_ratelimiter_common(arg);
}

ISC_LOOP_TEARDOWN_IMPL(ratelimiter_pertick_interval) {
	uint64_t t = isc_time_microdiff(&tick_time, &tock_time);
	assert_int_equal(ticks, 2);
	assert_true(t >= 1000000);

	t = isc_time_microdiff(&tock_time, &start_time);
	assert_true(t < 1000000);
}

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(ratelimiter_pertick_interval) {
	isc_event_t *event = NULL;
	isc_interval_t interval;

	isc_interval_set(&interval, 1, NS_PER_SEC / 10);

	expect_assert_failure(isc_ratelimiter_setinterval(NULL, &interval));
	expect_assert_failure(isc_ratelimiter_setinterval(rl, NULL));
	expect_assert_failure(isc_ratelimiter_setpertic(NULL, 1));
	expect_assert_failure(isc_ratelimiter_setpertic(rl, 0));
	expect_assert_failure(isc_ratelimiter_setpushpop(NULL, false));

	isc_ratelimiter_setinterval(rl, &interval);
	isc_ratelimiter_setpertic(rl, 1);
	isc_ratelimiter_setpushpop(rl, false);

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tock, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(isc_ratelimiter_enqueue(rl, rl_task, &event),
			 ISC_R_SUCCESS);

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(isc_ratelimiter_enqueue(rl, rl_task, &event),
			 ISC_R_SUCCESS);
}

ISC_LOOP_SETUP_IMPL(ratelimiter_pushpop) {
	ticks = 0;
	isc_time_set(&tock_time, 0, 0);
	setup_loop_ratelimiter_common(arg);
}

ISC_LOOP_TEARDOWN_IMPL(ratelimiter_pushpop) {
	uint64_t t = isc_time_microdiff(&tock_time, &tick_time);
	assert_int_equal(ticks, 2);
	assert_true(t < 1000000);
}

ISC_LOOP_TEST_SETUP_TEARDOWN_IMPL(ratelimiter_pushpop) {
	isc_event_t *event = NULL;
	isc_interval_t interval;

	isc_interval_set(&interval, 1, NS_PER_SEC / 10);

	isc_ratelimiter_setinterval(rl, &interval);
	isc_ratelimiter_setpertic(rl, 2);
	isc_ratelimiter_setpushpop(rl, true);

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tick, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(
		isc_ratelimiter_enqueue(rl, rl_task, &(isc_event_t *){ event }),
		ISC_R_SUCCESS);

	event = isc_event_allocate(mctx, NULL, ISC_TASKEVENT_TEST, tock, NULL,
				   sizeof(isc_event_t));
	assert_non_null(event);

	assert_int_equal(
		isc_ratelimiter_enqueue(rl, rl_task, &(isc_event_t *){ event }),
		ISC_R_SUCCESS);
}

static int
setup_test(void **state) {
	int r;

	r = setup_loopmgr(state);
	if (r != 0) {
		return (r);
	}
	r = setup_taskmgr(state);
	if (r != 0) {
		return (r);
	}

	return (0);
}

static int
teardown_test(void **state) {
	int r;

	r = teardown_taskmgr(state);
	if (r != 0) {
		return (r);
	}
	r = teardown_loopmgr(state);
	if (r != 0) {
		return (r);
	}

	return (0);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(ratelimiter_create, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_shutdown, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_detach, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_enqueue, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_enqueue_shutdown, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_dequeue, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_pertick_interval, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(ratelimiter_pushpop, setup_test, teardown_test)

ISC_TEST_LIST_END

ISC_TEST_MAIN
