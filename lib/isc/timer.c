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

#include <isc/app.h>
#include <isc/condition.h>
#include <isc/heap.h>
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

#include "timer_p.h"

#ifdef ISC_TIMER_TRACE
#define XTRACE(s)      fprintf(stderr, "%s\n", (s))
#define XTRACEID(s, t) fprintf(stderr, "%s %p\n", (s), (t))
#define XTRACETIME(s, d) \
	fprintf(stderr, "%s %u.%09u\n", (s), (d).seconds, (d).nanoseconds)
#define XTRACETIME2(s, d, n)                                      \
	fprintf(stderr, "%s %u.%09u %u.%09u\n", (s), (d).seconds, \
		(d).nanoseconds, (n).seconds, (n).nanoseconds)
#define XTRACETIMER(s, t, d)                                      \
	fprintf(stderr, "%s %p %u.%09u\n", (s), (t), (d).seconds, \
		(d).nanoseconds)
#else /* ifdef ISC_TIMER_TRACE */
#define XTRACE(s)
#define XTRACEID(s, t)
#define XTRACETIME(s, d)
#define XTRACETIME2(s, d, n)
#define XTRACETIMER(s, t, d)
#endif /* ISC_TIMER_TRACE */

#define TIMER_MAGIC    ISC_MAGIC('T', 'I', 'M', 'R')
#define VALID_TIMER(t) ISC_MAGIC_VALID(t, TIMER_MAGIC)

struct isc_timer {
	/*! Not locked. */
	unsigned int magic;
	isc_timermgr_t *manager;
	isc_mutex_t lock;
	/*! Locked by timer lock. */
	isc_time_t idle;
	ISC_LIST(isc_timerevent_t) active;
	/*! Locked by manager lock. */
	isc_timertype_t type;
	isc_interval_t interval;
	isc_task_t *task;
	isc_taskaction_t action;
	void *arg;
	unsigned int index;
	isc_time_t due;
	LINK(isc_timer_t) link;
};

#define TIMER_MANAGER_MAGIC ISC_MAGIC('T', 'I', 'M', 'M')
#define VALID_MANAGER(m)    ISC_MAGIC_VALID(m, TIMER_MANAGER_MAGIC)

struct isc_timermgr {
	/* Not locked. */
	unsigned int magic;
	isc_mem_t *mctx;
	isc_mutex_t lock;
	/* Locked by manager lock. */
	bool done;
	LIST(isc_timer_t) timers;
	unsigned int nscheduled;
	isc_time_t due;
	isc_condition_t wakeup;
	isc_thread_t thread;
	isc_heap_t *heap;
};

static isc_result_t
schedule(isc_timer_t *timer, isc_time_t *now, bool signal_ok) {
	isc_timermgr_t *manager;
	isc_time_t due;
	isc_result_t result = ISC_R_SUCCESS;

	/*!
	 * Note: the caller must ensure locking.
	 */

	manager = timer->manager;

	/*
	 * Compute the new due time.
	 */
	switch (timer->type) {
	case isc_timertype_ticker:
		result = isc_time_add(now, &timer->interval, &due);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		break;
	case isc_timertype_once:
		due = timer->idle;
		break;
	default:
		UNREACHABLE();
	}

	/*
	 * Schedule the timer.
	 */

	if (timer->index > 0) {
		/*
		 * Already scheduled.
		 */
		int cmp = isc_time_compare(&due, &timer->due);
		timer->due = due;
		switch (cmp) {
		case -1:
			isc_heap_increased(manager->heap, timer->index);
			break;
		case 1:
			isc_heap_decreased(manager->heap, timer->index);
			break;
		case 0:
			/* Nothing to do. */
			break;
		}
	} else {
		timer->due = due;
		isc_heap_insert(manager->heap, timer);
		manager->nscheduled++;
	}

	XTRACETIMER("schedule", timer, due);

	/*
	 * If this timer is at the head of the queue, we need to ensure
	 * that we won't miss it if it has a more recent due time than
	 * the current "next" timer.  We do this either by waking up the
	 * run thread, or explicitly setting the value in the manager.
	 */

	if (timer->index == 1 && signal_ok) {
		XTRACE("signal (schedule)");
		SIGNAL(&manager->wakeup);
	}

	return (result);
}

static void
deschedule(isc_timer_t *timer) {
	isc_timermgr_t *manager;

	/*
	 * The caller must ensure locking.
	 */

	manager = timer->manager;
	if (timer->index > 0) {
		bool need_wakeup = false;
		if (timer->index == 1) {
			need_wakeup = true;
		}
		isc_heap_delete(manager->heap, timer->index);
		timer->index = 0;
		INSIST(manager->nscheduled > 0);
		manager->nscheduled--;
		if (need_wakeup) {
			XTRACE("signal (deschedule)");
			SIGNAL(&manager->wakeup);
		}
	}
}

static void
timerevent_unlink(isc_timer_t *timer, isc_timerevent_t *event) {
	REQUIRE(ISC_LINK_LINKED(event, ev_timerlink));
	ISC_LIST_UNLINK(timer->active, event, ev_timerlink);
}

static void
timerevent_destroy(isc_event_t *event0) {
	isc_timer_t *timer = event0->ev_destroy_arg;
	isc_timerevent_t *event = (isc_timerevent_t *)event0;

	LOCK(&timer->lock);
	if (ISC_LINK_LINKED(event, ev_timerlink)) {
		/* The event was unlinked via timer_purge() */
		timerevent_unlink(timer, event);
	}
	UNLOCK(&timer->lock);

	isc_mem_put(timer->manager->mctx, event, event0->ev_size);
}

static void
timer_purge(isc_timer_t *timer) {
	isc_timerevent_t *event = NULL;

	while ((event = ISC_LIST_HEAD(timer->active)) != NULL) {
		timerevent_unlink(timer, event);
		UNLOCK(&timer->lock);
		(void)isc_task_purgeevent(timer->task, (isc_event_t *)event);
		LOCK(&timer->lock);
	}
}

void
isc_timer_create(isc_timermgr_t *manager, isc_task_t *task,
		 isc_taskaction_t action, void *arg, isc_timer_t **timerp) {
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	isc_timer_t *timer;
	isc_time_t now;

	REQUIRE(timerp != NULL && *timerp == NULL);

	/*
	 * Get current time.
	 */
	TIME_NOW(&now);

	timer = isc_mem_get(manager->mctx, sizeof(*timer));
	*timer = (isc_timer_t){
		.manager = manager,
		.type = isc_timertype_inactive,
		.interval = *isc_interval_zero,
		.action = action,
		.arg = arg,
	};

	isc_time_settoepoch(&timer->idle);

	isc_task_attach(task, &timer->task);

	isc_mutex_init(&timer->lock);
	ISC_LINK_INIT(timer, link);

	ISC_LIST_INIT(timer->active);

	timer->magic = TIMER_MAGIC;

	/*
	 * Note we don't have to lock the timer like we normally would because
	 * there are no external references to it yet.
	 */

	*timerp = timer;

	LOCK(&manager->lock);
	APPEND(manager->timers, timer, link);
	UNLOCK(&manager->lock);
}

isc_result_t
isc_timer_reset(isc_timer_t *timer, isc_timertype_t type,
		const isc_interval_t *interval, bool purge) {
	isc_time_t now;
	isc_timermgr_t *manager;
	isc_result_t result;

	/*
	 * Change the timer's type, expires, and interval values to the given
	 * values.  If 'purge' is true, any pending events from this timer
	 * are purged from its task's event queue.
	 */

	REQUIRE(VALID_TIMER(timer));
	manager = timer->manager;
	REQUIRE(VALID_MANAGER(manager));

	if (interval == NULL) {
		interval = isc_interval_zero;
	}
	REQUIRE(type == isc_timertype_inactive ||
		!isc_interval_iszero(interval));

	/*
	 * Get current time.
	 */
	if (type != isc_timertype_inactive) {
		TIME_NOW(&now);
	} else {
		/*
		 * We don't have to do this, but it keeps the compiler from
		 * complaining about "now" possibly being used without being
		 * set, even though it will never actually happen.
		 */
		isc_time_settoepoch(&now);
	}

	LOCK(&manager->lock);
	LOCK(&timer->lock);

	if (purge) {
		timer_purge(timer);
	}
	timer->type = type;
	timer->interval = *interval;
	if (type == isc_timertype_once && !isc_interval_iszero(interval)) {
		result = isc_time_add(&now, interval, &timer->idle);
	} else {
		isc_time_settoepoch(&timer->idle);
		result = ISC_R_SUCCESS;
	}

	if (result == ISC_R_SUCCESS) {
		if (type == isc_timertype_inactive) {
			deschedule(timer);
			result = ISC_R_SUCCESS;
		} else {
			result = schedule(timer, &now, true);
		}
	}

	UNLOCK(&timer->lock);
	UNLOCK(&manager->lock);

	return (result);
}

isc_timertype_t
isc_timer_gettype(isc_timer_t *timer) {
	isc_timertype_t t;

	REQUIRE(VALID_TIMER(timer));

	LOCK(&timer->lock);
	t = timer->type;
	UNLOCK(&timer->lock);

	return (t);
}

void
isc_timer_destroy(isc_timer_t **timerp) {
	isc_timer_t *timer = NULL;
	isc_timermgr_t *manager = NULL;

	REQUIRE(timerp != NULL && VALID_TIMER(*timerp));

	timer = *timerp;
	*timerp = NULL;

	manager = timer->manager;

	LOCK(&manager->lock);

	LOCK(&timer->lock);
	timer_purge(timer);
	deschedule(timer);
	UNLOCK(&timer->lock);

	UNLINK(manager->timers, timer, link);

	UNLOCK(&manager->lock);

	isc_task_detach(&timer->task);
	isc_mutex_destroy(&timer->lock);
	timer->magic = 0;
	isc_mem_put(manager->mctx, timer, sizeof(*timer));
}

static void
post_event(isc_timermgr_t *manager, isc_timer_t *timer, isc_eventtype_t type) {
	isc_timerevent_t *event;
	XTRACEID("posting", timer);

	event = (isc_timerevent_t *)isc_event_allocate(
		manager->mctx, timer, type, timer->action, timer->arg,
		sizeof(*event));

	ISC_LINK_INIT(event, ev_timerlink);
	((isc_event_t *)event)->ev_destroy = timerevent_destroy;
	((isc_event_t *)event)->ev_destroy_arg = timer;

	event->due = timer->due;

	LOCK(&timer->lock);
	ISC_LIST_APPEND(timer->active, event, ev_timerlink);
	UNLOCK(&timer->lock);

	isc_task_send(timer->task, ISC_EVENT_PTR(&event));
}

static void
dispatch(isc_timermgr_t *manager, isc_time_t *now) {
	bool need_schedule;
	isc_eventtype_t type = 0;
	isc_timer_t *timer;
	isc_result_t result;

	/*!
	 * The caller must be holding the manager lock.
	 */

	while (manager->nscheduled > 0) {
		timer = isc_heap_element(manager->heap, 1);
		INSIST(timer != NULL && timer->type != isc_timertype_inactive);

		if (isc_time_compare(now, &timer->due) < 0) {
			manager->due = timer->due;
			break;
		}

		switch (timer->type) {
		case isc_timertype_ticker:
			type = ISC_TIMEREVENT_TICK;
			post_event(manager, timer, type);
			need_schedule = true;
			break;
		case isc_timertype_once:
			type = ISC_TIMEREVENT_ONCE;
			post_event(manager, timer, type);
			need_schedule = false;
			break;
		default:
			UNREACHABLE();
		}

		timer->index = 0;
		isc_heap_delete(manager->heap, 1);
		manager->nscheduled--;

		if (need_schedule) {
			result = schedule(timer, now, false);
			if (result != ISC_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__, "%s: %u",
						 "couldn't schedule "
						 "timer",
						 result);
			}
		}
	}
}

static isc_threadresult_t
run(void *uap) {
	isc_timermgr_t *manager = uap;
	isc_time_t now;
	isc_result_t result;

	LOCK(&manager->lock);
	while (!manager->done) {
		TIME_NOW(&now);

		XTRACETIME("running", now);

		dispatch(manager, &now);

		if (manager->nscheduled > 0) {
			XTRACETIME2("waituntil", manager->due, now);
			result = WAITUNTIL(&manager->wakeup, &manager->lock,
					   &manager->due);
			INSIST(result == ISC_R_SUCCESS ||
			       result == ISC_R_TIMEDOUT);
		} else {
			XTRACETIME("wait", now);
			WAIT(&manager->wakeup, &manager->lock);
		}
		XTRACE("wakeup");
	}
	UNLOCK(&manager->lock);

	return ((isc_threadresult_t)0);
}

static bool
sooner(void *v1, void *v2) {
	isc_timer_t *t1, *t2;

	t1 = v1;
	t2 = v2;
	REQUIRE(VALID_TIMER(t1));
	REQUIRE(VALID_TIMER(t2));

	if (isc_time_compare(&t1->due, &t2->due) < 0) {
		return (true);
	}
	return (false);
}

static void
set_index(void *what, unsigned int index) {
	isc_timer_t *timer;

	REQUIRE(VALID_TIMER(what));
	timer = what;

	timer->index = index;
}

isc_result_t
isc__timermgr_create(isc_mem_t *mctx, isc_timermgr_t **managerp) {
	isc_timermgr_t *manager;

	/*
	 * Create a timer manager.
	 */

	REQUIRE(managerp != NULL && *managerp == NULL);

	manager = isc_mem_get(mctx, sizeof(*manager));

	manager->magic = TIMER_MANAGER_MAGIC;
	manager->mctx = NULL;
	manager->done = false;
	INIT_LIST(manager->timers);
	manager->nscheduled = 0;
	isc_time_settoepoch(&manager->due);
	manager->heap = NULL;
	isc_heap_create(mctx, sooner, set_index, 0, &manager->heap);
	isc_mutex_init(&manager->lock);
	isc_mem_attach(mctx, &manager->mctx);
	isc_condition_init(&manager->wakeup);
	isc_thread_create(run, manager, &manager->thread);
	isc_thread_setname(manager->thread, "isc-timer");

	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
isc__timermgr_destroy(isc_timermgr_t **managerp) {
	isc_timermgr_t *manager;

	/*
	 * Destroy a timer manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);

	REQUIRE(EMPTY(manager->timers));
	manager->done = true;

	XTRACE("signal (destroy)");
	SIGNAL(&manager->wakeup);

	UNLOCK(&manager->lock);

	/*
	 * Wait for thread to exit.
	 */
	isc_thread_join(manager->thread, NULL);

	/*
	 * Clean up.
	 */
	isc_condition_destroy(&manager->wakeup);
	isc_mutex_destroy(&manager->lock);
	isc_heap_destroy(&manager->heap);
	manager->magic = 0;
	isc_mem_putanddetach(&manager->mctx, manager, sizeof(*manager));

	*managerp = NULL;
}
