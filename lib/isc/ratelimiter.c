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

#include <inttypes.h>
#include <stdbool.h>

#include <isc/async.h>
#include <isc/event.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/ratelimiter.h>
#include <isc/refcount.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

typedef enum {
	isc_ratelimiter_ratelimited = 0,
	isc_ratelimiter_idle = 1,
	isc_ratelimiter_shuttingdown = 2
} isc_ratelimiter_state_t;

#define RATELIMITER_MAGIC     ISC_MAGIC('R', 't', 'L', 'm')
#define VALID_RATELIMITER(rl) ISC_MAGIC_VALID(rl, RATELIMITER_MAGIC)

struct isc_ratelimiter {
	int magic;
	isc_mem_t *mctx;
	isc_loop_t *loop;
	isc_refcount_t references;
	isc_mutex_t lock;
	isc_timer_t *timer;
	isc_interval_t interval;
	uint32_t pertic;
	bool pushpop;
	isc_ratelimiter_state_t state;
	ISC_LIST(isc_event_t) pending;
};

static void
isc__ratelimiter_tick(void *arg);

static void
isc__ratelimiter_start(void *arg);

static void
isc__ratelimiter_doshutdown(void *arg);

void
isc_ratelimiter_create(isc_loop_t *loop, isc_ratelimiter_t **rlp) {
	isc_ratelimiter_t *rl = NULL;
	isc_mem_t *mctx;

	REQUIRE(loop != NULL);
	REQUIRE(rlp != NULL && *rlp == NULL);

	mctx = isc_loop_getmctx(loop);

	rl = isc_mem_get(mctx, sizeof(*rl));
	*rl = (isc_ratelimiter_t){
		.pertic = 1,
		.state = isc_ratelimiter_idle,
		.magic = RATELIMITER_MAGIC,
	};

	isc_mem_attach(mctx, &rl->mctx);
	isc_loop_attach(loop, &rl->loop);
	isc_refcount_init(&rl->references, 1);
	isc_interval_set(&rl->interval, 0, 0);
	ISC_LIST_INIT(rl->pending);

	isc_timer_create(rl->loop, isc__ratelimiter_tick, rl, &rl->timer);

	isc_mutex_init(&rl->lock);

	*rlp = rl;
}

void
isc_ratelimiter_setinterval(isc_ratelimiter_t *rl, isc_interval_t *interval) {
	REQUIRE(VALID_RATELIMITER(rl));
	REQUIRE(interval != NULL);

	LOCK(&rl->lock);
	rl->interval = *interval;
	/* The interval will be adjusted on the next tick */
	UNLOCK(&rl->lock);
}

void
isc_ratelimiter_setpertic(isc_ratelimiter_t *rl, uint32_t pertic) {
	REQUIRE(VALID_RATELIMITER(rl));
	REQUIRE(pertic > 0);

	LOCK(&rl->lock);
	rl->pertic = pertic;
	UNLOCK(&rl->lock);
}

void
isc_ratelimiter_setpushpop(isc_ratelimiter_t *rl, bool pushpop) {
	REQUIRE(VALID_RATELIMITER(rl));

	LOCK(&rl->lock);
	rl->pushpop = pushpop;
	UNLOCK(&rl->lock);
}

static void
isc__ratelimiter_start(void *arg) {
	isc_ratelimiter_t *rl = arg;
	isc_interval_t interval;

	REQUIRE(VALID_RATELIMITER(rl));

	LOCK(&rl->lock);
	switch (rl->state) {
	case isc_ratelimiter_ratelimited:
		/* The first tick happens immediately */
		isc_interval_set(&interval, 0, 0);
		isc_timer_start(rl->timer, isc_timertype_once, &interval);
		break;
	case isc_ratelimiter_shuttingdown:
		/* The ratelimiter is shutting down */
		break;
	case isc_ratelimiter_idle:
		/*
		 * This could happen if we are changing the interval on the
		 * ratelimiter, but all the events were processed and the timer
		 * was stopped before the new interval could be applied.
		 */
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK(&rl->lock);
	isc_ratelimiter_detach(&rl);
}

isc_result_t
isc_ratelimiter_enqueue(isc_ratelimiter_t *rl, isc_task_t *task,
			isc_event_t **eventp) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_event_t *event;

	REQUIRE(VALID_RATELIMITER(rl));
	REQUIRE(task != NULL);
	REQUIRE(eventp != NULL && *eventp != NULL);
	event = *eventp;
	REQUIRE(event->ev_sender == NULL);

	LOCK(&rl->lock);
	switch (rl->state) {
	case isc_ratelimiter_shuttingdown:
		result = ISC_R_SHUTTINGDOWN;
		break;
	case isc_ratelimiter_idle:
		/* Start the ratelimiter */
		isc_ratelimiter_ref(rl);
		isc_async_run(rl->loop, isc__ratelimiter_start, rl);
		rl->state = isc_ratelimiter_ratelimited;
		FALLTHROUGH;
	case isc_ratelimiter_ratelimited:
		event->ev_sender = task;
		*eventp = NULL;
		if (rl->pushpop) {
			ISC_LIST_PREPEND(rl->pending, event, ev_ratelink);
		} else {
			ISC_LIST_APPEND(rl->pending, event, ev_ratelink);
		}
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK(&rl->lock);
	return (result);
}

isc_result_t
isc_ratelimiter_dequeue(isc_ratelimiter_t *rl, isc_event_t *event) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(rl != NULL);
	REQUIRE(event != NULL);

	LOCK(&rl->lock);
	if (ISC_LINK_LINKED(event, ev_ratelink)) {
		ISC_LIST_UNLINK(rl->pending, event, ev_ratelink);
		event->ev_sender = NULL;
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&rl->lock);

	return (result);
}

static void
isc__ratelimiter_tick(void *arg) {
	isc_ratelimiter_t *rl = (isc_ratelimiter_t *)arg;
	isc_event_t *event;
	uint32_t pertic;
	ISC_LIST(isc_event_t) pending;

	REQUIRE(VALID_RATELIMITER(rl));

	ISC_LIST_INIT(pending);

	LOCK(&rl->lock);

	REQUIRE(rl->timer != NULL);

	if (rl->state == isc_ratelimiter_shuttingdown) {
		INSIST(EMPTY(rl->pending));
		goto unlock;
	}

	pertic = rl->pertic;
	while (pertic != 0) {
		event = ISC_LIST_HEAD(rl->pending);
		if (event != NULL) {
			/* There is work to do.  Let's do it after unlocking. */
			ISC_LIST_UNLINK(rl->pending, event, ev_ratelink);
			ISC_LIST_APPEND(pending, event, ev_ratelink);
		} else {
			/*
			 * We processed all the scheduled work, but there's a
			 * room for at least one more event (we haven't consumed
			 * all of the "pertick"), so we can stop the ratelimiter
			 * now, and don't worry about isc_ratelimiter_enqueue()
			 * sending an extra event immediately.
			 */
			rl->state = isc_ratelimiter_idle;
			break;
		}
		pertic--;
	}

	if (rl->state != isc_ratelimiter_idle) {
		/* Reschedule the timer */
		isc_timer_start(rl->timer, isc_timertype_once, &rl->interval);
	}
unlock:
	UNLOCK(&rl->lock);

	while ((event = ISC_LIST_HEAD(pending)) != NULL) {
		ISC_LIST_UNLINK(pending, event, ev_ratelink);
		isc_task_send(event->ev_sender, &event);
	}
}

void
isc__ratelimiter_doshutdown(void *arg) {
	isc_ratelimiter_t *rl = arg;

	REQUIRE(VALID_RATELIMITER(rl));

	LOCK(&rl->lock);
	INSIST(rl->state == isc_ratelimiter_shuttingdown);
	INSIST(EMPTY(rl->pending));

	isc_timer_stop(rl->timer);
	isc_timer_destroy(&rl->timer);
	isc_loop_detach(&rl->loop);
	UNLOCK(&rl->lock);
	isc_ratelimiter_detach(&rl);
}

void
isc_ratelimiter_shutdown(isc_ratelimiter_t *rl) {
	isc_event_t *event;
	ISC_LIST(isc_event_t) pending;

	REQUIRE(VALID_RATELIMITER(rl));

	ISC_LIST_INIT(pending);

	LOCK(&rl->lock);
	if (rl->state != isc_ratelimiter_shuttingdown) {
		rl->state = isc_ratelimiter_shuttingdown;
		ISC_LIST_MOVE(pending, rl->pending);
		isc_ratelimiter_ref(rl);
		isc_async_run(rl->loop, isc__ratelimiter_doshutdown, rl);
	}
	UNLOCK(&rl->lock);

	while ((event = ISC_LIST_HEAD(pending)) != NULL) {
		ISC_LIST_UNLINK(pending, event, ev_ratelink);
		event->ev_attributes |= ISC_EVENTATTR_CANCELED;
		isc_task_send(event->ev_sender, &event);
	}
}

static void
ratelimiter_destroy(isc_ratelimiter_t *rl) {
	isc_refcount_destroy(&rl->references);

	LOCK(&rl->lock);
	REQUIRE(rl->state == isc_ratelimiter_shuttingdown);
	UNLOCK(&rl->lock);

	isc_mutex_destroy(&rl->lock);
	isc_mem_putanddetach(&rl->mctx, rl, sizeof(*rl));
}

ISC_REFCOUNT_IMPL(isc_ratelimiter, ratelimiter_destroy);
