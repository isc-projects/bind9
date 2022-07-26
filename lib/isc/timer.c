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

/*! \file */

#include <stdbool.h>

#include <isc/async.h>
#include <isc/condition.h>
#include <isc/heap.h>
#include <isc/job.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "loop_p.h"

#define TIMER_MAGIC    ISC_MAGIC('T', 'I', 'M', 'R')
#define VALID_TIMER(t) ISC_MAGIC_VALID(t, TIMER_MAGIC)

struct isc_timer {
	unsigned int magic;
	isc_refcount_t references;
	isc_loop_t *loop;
	uv_timer_t timer;
	isc_job_cb cb;
	void *cbarg;

	/*
	 * We are locking the values here for now, but this needs to go away
	 * when the timers are pinned to the respective loops.
	 */
	isc_mutex_t lock;
	uint64_t timeout;
	uint64_t repeat;
};

static void
isc__timer_detach(isc_timer_t **timerp);

void
isc_timer_create(isc_loop_t *loop, isc_job_cb cb, void *cbarg,
		 isc_timer_t **timerp) {
	int r;
	isc_timer_t *timer = NULL;
	isc_loopmgr_t *loopmgr = NULL;

	REQUIRE(cb != NULL);
	REQUIRE(timerp != NULL && *timerp == NULL);

	REQUIRE(VALID_LOOP(loop));

	loopmgr = loop->loopmgr;

	REQUIRE(VALID_LOOPMGR(loopmgr));

	REQUIRE(loop == isc_loop_current(loopmgr) ||
		!atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused) > 0);

	timer = isc_mem_get(loop->mctx, sizeof(*timer));
	*timer = (isc_timer_t){
		.cb = cb,
		.cbarg = cbarg,
	};

	isc_loop_attach(loop, &timer->loop);

	isc_refcount_init(&timer->references, 1);

	isc_mutex_init(&timer->lock);

	timer->magic = TIMER_MAGIC;

	r = uv_timer_init(&timer->loop->loop, &timer->timer);
	UV_RUNTIME_CHECK(uv_timer_init, r);
	uv_handle_set_data(&timer->timer, timer);

	*timerp = timer;
}

static void
isc__timer_stop(void *arg) {
	isc_timer_t *timer = (isc_timer_t *)arg;
	uv_timer_stop(&timer->timer);
	isc__timer_detach(&timer);
}

void
isc_timer_stop(isc_timer_t *timer) {
	REQUIRE(VALID_TIMER(timer));

	isc_refcount_increment(&timer->references);
	if (timer->loop == isc_loop_current(timer->loop->loopmgr)) {
		isc__timer_stop(timer);
	} else {
		isc_async_run(timer->loop, isc__timer_stop, timer);
	}
}

static void
timer_cb(uv_timer_t *handle) {
	isc_timer_t *timer = uv_handle_get_data(handle);

	REQUIRE(VALID_TIMER(timer));

	timer->cb(timer->cbarg);
}

static void
isc__timer_start(void *arg) {
	isc_timer_t *timer = (isc_timer_t *)arg;

	LOCK(&timer->lock);
	int r = uv_timer_start(&timer->timer, timer_cb, timer->timeout,
			       timer->repeat);
	UV_RUNTIME_CHECK(uv_timer_start, r);
	UNLOCK(&timer->lock);

	isc__timer_detach(&timer);
}

void
isc_timer_start(isc_timer_t *timer, isc_timertype_t type,
		const isc_interval_t *interval) {
	isc_loopmgr_t *loopmgr = NULL;
	isc_loop_t *loop = NULL;

	REQUIRE(VALID_TIMER(timer));
	REQUIRE(type == isc_timertype_ticker || type == isc_timertype_once);

	loop = timer->loop;

	REQUIRE(VALID_LOOP(loop));

	loopmgr = loop->loopmgr;

	REQUIRE(VALID_LOOPMGR(loopmgr));

	LOCK(&timer->lock);
	switch (type) {
	case isc_timertype_once:
		timer->timeout = isc_interval_ms(interval);
		timer->repeat = 0;
		break;
	case isc_timertype_ticker:
		timer->timeout = timer->repeat = isc_interval_ms(interval);
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK(&timer->lock);

	isc_refcount_increment(&timer->references);
	if (timer->loop == isc_loop_current(timer->loop->loopmgr)) {
		isc__timer_start(timer);
	} else {
		isc_async_run(timer->loop, isc__timer_start, timer);
	}
}

static void
timer_destroy(uv_handle_t *handle) {
	isc_timer_t *timer = uv_handle_get_data(handle);
	isc_loop_t *loop;

	REQUIRE(VALID_TIMER(timer));

	loop = timer->loop;

	isc_refcount_destroy(&timer->references);
	isc_mutex_destroy(&timer->lock);

	isc_mem_put(loop->mctx, timer, sizeof(*timer));

	isc_loop_detach(&loop);
}

static void
isc__timer_destroy(void *arg) {
	isc_timer_t *timer = (isc_timer_t *)arg;

	uv_timer_stop(&timer->timer);
	uv_close(&timer->timer, timer_destroy);
}

static void
isc__timer_detach(isc_timer_t **timerp) {
	isc_timer_t *timer = NULL;

	REQUIRE(timerp != NULL && VALID_TIMER(*timerp));

	timer = *timerp;
	*timerp = NULL;

	if (isc_refcount_decrement(&timer->references) == 1) {
		if (timer->loop == isc_loop_current(timer->loop->loopmgr)) {
			isc__timer_destroy(timer);
		} else {
			isc_async_run(timer->loop, isc__timer_destroy, timer);
		}
	}
}

void
isc_timer_destroy(isc_timer_t **timerp) {
	isc__timer_detach(timerp);
}
