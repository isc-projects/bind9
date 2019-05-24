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

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <process.h>

#include <isc/app.h>
#include <isc/atomic.h>
#include <isc/condition.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/platform.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/thread.h>

/*%
 * For BIND9 internal applications built with threads, we use a single app
 * context and let multiple worker, I/O, timer threads do actual jobs.
 */

static isc_thread_t	blockedthread;
static atomic_bool	is_running;

#define APPCTX_MAGIC		ISC_MAGIC('A', 'p', 'c', 'x')
#define VALID_APPCTX(c)		ISC_MAGIC_VALID(c, APPCTX_MAGIC)

/* Events to wait for */

#define NUM_EVENTS 2

enum {
	RELOAD_EVENT,
	SHUTDOWN_EVENT
};

struct isc_appctx {
	unsigned int		magic;
	isc_mem_t		*mctx;
	isc_eventlist_t		on_run;
	isc_mutex_t		lock;
	atomic_bool		shutdown_requested;
	atomic_bool		running;
	/*
	 * We assume that 'want_shutdown' can be read and written atomically.
	 */
	atomic_bool		want_shutdown;
	/*
	 * We assume that 'want_reload' can be read and written atomically.
	 */
	atomic_bool		want_reload;

	atomic_bool		blocked;

	HANDLE			hEvents[NUM_EVENTS];
};

static isc_appctx_t isc_g_appctx;

/*
 * We need to remember which thread is the main thread...
 */
static isc_thread_t	main_thread;

isc_result_t
isc_app_ctxstart(isc_appctx_t *ctx) {

	REQUIRE(VALID_APPCTX(ctx));

	/*
	 * Start an ISC library application.
	 */

	main_thread = GetCurrentThread();

	isc_mutex_init(&ctx->lock);

	atomic_init(&ctx->shutdown_requested, false);
	atomic_init(&ctx->running, false);
	atomic_init(&ctx->want_shutdown, false);
	atomic_init(&ctx->want_reload, false);
	atomic_init(&ctx->blocked, false);

	/* Create the reload event in a non-signaled state */
	ctx->hEvents[RELOAD_EVENT] = CreateEvent(NULL, FALSE, FALSE, NULL);

	/* Create the shutdown event in a non-signaled state */
	ctx->hEvents[SHUTDOWN_EVENT] = CreateEvent(NULL, FALSE, FALSE, NULL);

	ISC_LIST_INIT(ctx->on_run);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_start(void) {
	isc_g_appctx.magic = APPCTX_MAGIC;
	isc_g_appctx.mctx = NULL;
	/* The remaining members will be initialized in ctxstart() */

	return (isc_app_ctxstart(&isc_g_appctx));
}

isc_result_t
isc_app_onrun(isc_mem_t *mctx, isc_task_t *task, isc_taskaction_t action,
	       void *arg)
{
	return (isc_app_ctxonrun(&isc_g_appctx, mctx, task, action, arg));
}

isc_result_t
isc_app_ctxonrun(isc_appctx_t *ctx, isc_mem_t *mctx, isc_task_t *task,
		  isc_taskaction_t action, void *arg)
{
	isc_event_t *event;
	isc_task_t *cloned_task = NULL;
	isc_result_t result;

	if (atomic_load_acquire(&ctx->running)) {
		return (ISC_R_ALREADYRUNNING);
	}

	/*
	 * Note that we store the task to which we're going to send the event
	 * in the event's "sender" field.
	 */
	isc_task_attach(task, &cloned_task);
	event = isc_event_allocate(mctx, cloned_task, ISC_APPEVENT_SHUTDOWN,
				   action, arg, sizeof(*event));
	if (event == NULL) {
		return (ISC_R_NOMEMORY);
	}

	LOCK(&ctx->lock);
	ISC_LINK_INIT(event, ev_link);
	ISC_LIST_APPEND(ctx->on_run, event, ev_link);
	UNLOCK(&ctx->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_ctxrun(isc_appctx_t *ctx) {
	bool exp_true = true;
	bool exp_false = false;
	isc_event_t *event, *next_event;
	isc_task_t *task;
	HANDLE *pHandles = NULL;
	DWORD  dwWaitResult;

	REQUIRE(VALID_APPCTX(ctx));

	REQUIRE(main_thread == GetCurrentThread());

	LOCK(&ctx->lock);
	if (atomic_compare_exchange_weak(&ctx->running, &exp_false, true)) {
		/*
		 * Post any on-run events (in FIFO order).
		 */
		for (event = ISC_LIST_HEAD(ctx->on_run);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, ev_link);
			ISC_LIST_UNLINK(ctx->on_run, event, ev_link);
			task = event->ev_sender;
			event->ev_sender = NULL;
			isc_task_sendanddetach(&task, &event);
		}
	}
	UNLOCK(&ctx->lock);

	/*
	 * There is no danger if isc_app_shutdown() is called before we wait
	 * for events.
	 */

	while (atomic_load_acquire(&ctx->want_shutdown) == false) {
		dwWaitResult = WaitForMultipleObjects(NUM_EVENTS, ctx->hEvents,
						      FALSE, INFINITE);

		/* See why we returned */

		if (WaitSucceeded(dwWaitResult, NUM_EVENTS)) {
			/*
			 * The return was due to one of the events
			 * being signaled
			 */
			switch (WaitSucceededIndex(dwWaitResult)) {
			case RELOAD_EVENT:
				atomic_store_release(&ctx->want_reload, true);

				break;

			case SHUTDOWN_EVENT:
				atomic_store_release(&ctx->want_shutdown, true);
				break;
			}
		}

		exp_true = true;
		if (atomic_compare_exchange_weak(&ctx->want_reload,
						 &exp_true, false))
		{
			return (ISC_R_RELOAD);
		}

		if (atomic_load_acquire(&ctx->want_shutdown) &&
		    atomic_load_acquire(&ctx->blocked)) {
			exit(-1);
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_run(void) {
	bool exp_false = false;
	isc_result_t result;

	REQUIRE(atomic_compare_exchange_weak(&is_running, &exp_false, true));
	result = isc_app_ctxrun(&isc_g_appctx);
	atomic_store_release(&is_running, false);

	return (result);
}

bool
isc_app_isrunning() {
	return (is_running);
}

void
isc_app_ctxshutdown(isc_appctx_t *ctx) {
	bool exp_false = false;

	REQUIRE(VALID_APPCTX(ctx));
	REQUIRE(atomic_load_acquire(&ctx->running));

	/*
	 * If ctx->shutdown_requested == true, we are already shutting
	 * down and we want to just bail out.
	 */
	if (atomic_compare_exchange_weak(&ctx->shutdown_requested,
					 &exp_false, true))
	{
		SetEvent(ctx->hEvents[SHUTDOWN_EVENT]);
	}
}

void
isc_app_shutdown(void) {
	isc_app_ctxshutdown(&isc_g_appctx);
}

void
isc_app_ctxsuspend(isc_appctx_t *ctx) {

	REQUIRE(VALID_APPCTX(ctx));
	REQUIRE(atomic_load(&ctx->running));

	/*
	 * Don't send the reload signal if we're shutting down.
	 */
	if (atomic_load_acquire(&ctx->shutdown_requested) == false) {
		SetEvent(ctx->hEvents[RELOAD_EVENT]);
	}
}

void
isc_app_reload(void) {
	isc_app_ctxsuspend(&isc_g_appctx);
}

void
isc_app_ctxfinish(isc_appctx_t *ctx) {
	REQUIRE(VALID_APPCTX(ctx));

	isc_mutex_destroy(&ctx->lock);
}

void
isc_app_finish(void) {
	isc_app_ctxfinish(&isc_g_appctx);
}

void
isc_app_block(void) {
	bool exp_false = false;

	REQUIRE(atomic_load_acquire(&isc_g_appctx.running));
	REQUIRE(atomic_compare_exchange_weak(&isc_g_appctx.blocked,
					     &exp_false, true));

	blockedthread = GetCurrentThread();
}

void
isc_app_unblock(void) {
	bool exp_true = true;

	REQUIRE(atomic_load_acquire(&isc_g_appctx.running));
	REQUIRE(atomic_compare_exchange_weak(&isc_g_appctx.blocked,
					     &exp_true, false));
	REQUIRE(blockedthread == GetCurrentThread());
}

isc_result_t
isc_appctx_create(isc_mem_t *mctx, isc_appctx_t **ctxp) {
	isc_appctx_t *ctx;

	REQUIRE(mctx != NULL);
	REQUIRE(ctxp != NULL && *ctxp == NULL);

	ctx = isc_mem_get(mctx, sizeof(*ctx));

	ctx->magic = APPCTX_MAGIC;

	ctx->mctx = NULL;
	isc_mem_attach(mctx, &ctx->mctx);

	*ctxp = ctx;

	return (ISC_R_SUCCESS);
}

void
isc_appctx_destroy(isc_appctx_t **ctxp) {
	isc_appctx_t *ctx;

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	*ctxp = NULL;
	REQUIRE(VALID_APPCTX(ctx));

	isc_mem_putanddetach(&ctx->mctx, ctx, sizeof(*ctx));
}
