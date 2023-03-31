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

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/barrier.h>
#include <isc/condition.h>
#include <isc/job.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/qsbr.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/signal.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>
#include <isc/work.h>

#include "async_p.h"
#include "job_p.h"
#include "loop_p.h"

/**
 * Private
 */

static void
ignore_signal(int sig, void (*handler)(int)) {
	struct sigaction sa = { .sa_handler = handler };

	if (sigfillset(&sa.sa_mask) != 0 || sigaction(sig, &sa, NULL) < 0) {
		FATAL_SYSERROR(errno, "ignore_signal(%d)", sig);
	}
}

void
isc_loopmgr_shutdown(isc_loopmgr_t *loopmgr) {
	if (!atomic_compare_exchange_strong(&loopmgr->shuttingdown,
					    &(bool){ false }, true))
	{
		return;
	}

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		int r;

		r = uv_async_send(&loop->shutdown_trigger);
		UV_RUNTIME_CHECK(uv_async_send, r);
	}
}

static void
isc__loopmgr_signal(void *arg, int signum) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		isc_loopmgr_shutdown(loopmgr);
		break;
	default:
		UNREACHABLE();
	}
}

static void
pause_loop(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;

	rcu_thread_offline();

	loop->paused = true;
	(void)isc_barrier_wait(&loopmgr->pausing);
}

static void
resume_loop(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;

	(void)isc_barrier_wait(&loopmgr->resuming);
	loop->paused = false;

	rcu_thread_online();
}

static void
pauseresume_cb(uv_async_t *handle) {
	isc_loop_t *loop = uv_handle_get_data(handle);

	pause_loop(loop);
	resume_loop(loop);
}

#define XX(uc, lc)                                                         \
	case UV_##uc:                                                      \
		fprintf(stderr, "%s, %s: dangling %p: %p.type = %s\n",     \
			__func__, (char *)arg, handle->loop, handle, #lc); \
		break;

static void
loop_walk_cb(uv_handle_t *handle, void *arg) {
	if (uv_is_closing(handle)) {
		return;
	}

	switch (handle->type) {
		UV_HANDLE_TYPE_MAP(XX)
	default:
		fprintf(stderr, "%s, %s: dangling %p: %p.type = %s\n", __func__,
			(char *)arg, &handle->loop, handle, "unknown");
	}
}

static void
shutdown_trigger_close_cb(uv_handle_t *handle) {
	isc_loop_t *loop = uv_handle_get_data(handle);

	isc_loop_detach(&loop);
}

static void
destroy_cb(uv_async_t *handle) {
	isc_loop_t *loop = uv_handle_get_data(handle);

	/* Again, the first close callback here is called last */
	uv_close(&loop->async_trigger, isc__async_close);
	uv_close(&loop->run_trigger, isc__job_close);
	uv_close(&loop->destroy_trigger, NULL);
	uv_close(&loop->pause_trigger, NULL);
	uv_close(&loop->wakeup_trigger, NULL);
	uv_close(&loop->quiescent, NULL);

	uv_walk(&loop->loop, loop_walk_cb, (char *)"destroy_cb");
}

static void
shutdown_cb(uv_async_t *handle) {
	isc_job_t *job = NULL;
	isc_loop_t *loop = uv_handle_get_data(handle);
	isc_loopmgr_t *loopmgr = loop->loopmgr;

	loop->shuttingdown = true;

	/* Make sure, we can't be called again */
	uv_close(&loop->shutdown_trigger, shutdown_trigger_close_cb);

	if (DEFAULT_LOOP(loopmgr) == CURRENT_LOOP(loopmgr)) {
		/* Stop the signal handlers */
		isc_signal_stop(loopmgr->sigterm);
		isc_signal_stop(loopmgr->sigint);

		/* Free the signal handlers */
		isc_signal_destroy(&loopmgr->sigterm);
		isc_signal_destroy(&loopmgr->sigint);
	}

	job = ISC_LIST_TAIL(loop->teardown_jobs);
	while (job != NULL) {
		isc_job_t *prev = ISC_LIST_PREV(job, link);
		ISC_LIST_UNLINK(loop->teardown_jobs, job, link);

		job->cb(job->cbarg);

		isc_mem_put(loop->mctx, job, sizeof(*job));

		job = prev;
	}
}

static void
wakeup_cb(uv_async_t *handle) {
	/* we only woke up to make the loop take a spin */
	UNUSED(handle);
}

static void
loop_init(isc_loop_t *loop, isc_loopmgr_t *loopmgr, uint32_t tid) {
	*loop = (isc_loop_t){
		.tid = tid,
		.loopmgr = loopmgr,
		.async_jobs = ISC_ASTACK_INITIALIZER,
		.run_jobs = ISC_LIST_INITIALIZER,
		.setup_jobs = ISC_LIST_INITIALIZER,
		.teardown_jobs = ISC_LIST_INITIALIZER,
	};

	int r = uv_loop_init(&loop->loop);
	UV_RUNTIME_CHECK(uv_loop_init, r);

	r = uv_async_init(&loop->loop, &loop->pause_trigger, pauseresume_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data(&loop->pause_trigger, loop);

	r = uv_async_init(&loop->loop, &loop->shutdown_trigger, shutdown_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data(&loop->shutdown_trigger, loop);

	r = uv_async_init(&loop->loop, &loop->async_trigger, isc__async_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data(&loop->async_trigger, loop);

	r = uv_idle_init(&loop->loop, &loop->run_trigger);
	UV_RUNTIME_CHECK(uv_idle_init, r);
	uv_handle_set_data(&loop->run_trigger, loop);

	r = uv_async_init(&loop->loop, &loop->destroy_trigger, destroy_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data(&loop->destroy_trigger, loop);

	r = uv_async_init(&loop->loop, &loop->wakeup_trigger, wakeup_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);

	r = uv_prepare_init(&loop->loop, &loop->quiescent);
	UV_RUNTIME_CHECK(uv_prepare_init, r);
	uv_handle_set_data(&loop->quiescent, loop);

	char name[16];
	snprintf(name, sizeof(name), "loop-%08" PRIx32, tid);
	isc_mem_create(&loop->mctx);
	isc_mem_setname(loop->mctx, name);

	isc_refcount_init(&loop->references, 1);

	loop->magic = LOOP_MAGIC;
}

static void
setup_jobs_cb(void *arg) {
	isc_loop_t *loop = arg;
	isc_job_t *job = ISC_LIST_HEAD(loop->setup_jobs);

	while (job != NULL) {
		isc_job_t *next = ISC_LIST_NEXT(job, link);
		ISC_LIST_UNLINK(loop->setup_jobs, job, link);

		job->cb(job->cbarg);

		isc_mem_put(loop->mctx, job, sizeof(*job));

		job = next;
	}
}

static void
quiescent_cb(uv_prepare_t *handle) {
	isc__qsbr_quiescent_cb(handle);

#if defined(RCU_QSBR)
	/* safe memory reclamation */
	rcu_quiescent_state();

	/* mark the thread offline when polling */
	rcu_thread_offline();
#else
	INSIST(!rcu_read_ongoing());
#endif
}

static void
loop_close(isc_loop_t *loop) {
	int r = uv_loop_close(&loop->loop);
	UV_RUNTIME_CHECK(uv_loop_close, r);

	INSIST(ISC_ASTACK_EMPTY(loop->async_jobs));
	INSIST(ISC_LIST_EMPTY(loop->run_jobs));

	loop->magic = 0;

	isc_mem_detach(&loop->mctx);
}

static void *
loop_thread(void *arg) {
	isc_loop_t *loop = (isc_loop_t *)arg;

	/* Initialize the thread_local variable */

	isc__tid_init(loop->tid);

	int r = uv_prepare_start(&loop->quiescent, quiescent_cb);
	UV_RUNTIME_CHECK(uv_prepare_start, r);

	isc_barrier_wait(&loop->loopmgr->starting);

	isc_async_run(loop, setup_jobs_cb, loop);

	r = uv_run(&loop->loop, UV_RUN_DEFAULT);
	UV_RUNTIME_CHECK(uv_run, r);

	isc_barrier_wait(&loop->loopmgr->stopping);

	return (NULL);
}

void
isc_loop_nosetup(isc_loop_t *loop, isc_job_t *job) {
	ISC_LIST_DEQUEUE(loop->setup_jobs, job, link);
}

void
isc_loop_noteardown(isc_loop_t *loop, isc_job_t *job) {
	ISC_LIST_DEQUEUE(loop->teardown_jobs, job, link);
}

/**
 * Public
 */

static void
threadpool_initialize(uint32_t workers) {
	char buf[11];
	int r = uv_os_getenv("UV_THREADPOOL_SIZE", buf,
			     &(size_t){ sizeof(buf) });
	if (r == UV_ENOENT) {
		snprintf(buf, sizeof(buf), "%" PRIu32, workers);
		uv_os_setenv("UV_THREADPOOL_SIZE", buf);
	}
}

static void
loop_destroy(isc_loop_t *loop) {
	int r = uv_async_send(&loop->destroy_trigger);
	UV_RUNTIME_CHECK(uv_async_send, r);
}

#if ISC_LOOP_TRACE
ISC_REFCOUNT_TRACE_IMPL(isc_loop, loop_destroy)
#else
ISC_REFCOUNT_IMPL(isc_loop, loop_destroy);
#endif

void
isc_loopmgr_create(isc_mem_t *mctx, uint32_t nloops, isc_loopmgr_t **loopmgrp) {
	isc_loopmgr_t *loopmgr = NULL;

	REQUIRE(loopmgrp != NULL && *loopmgrp == NULL);
	REQUIRE(nloops > 0);

	threadpool_initialize(nloops);
	isc__tid_initcount(nloops);

	loopmgr = isc_mem_get(mctx, sizeof(*loopmgr));
	*loopmgr = (isc_loopmgr_t){
		.nloops = nloops,
		.qsbr = ISC_QSBR_INITIALIZER(nloops),
	};

	isc_mem_attach(mctx, &loopmgr->mctx);

	isc_barrier_init(&loopmgr->pausing, loopmgr->nloops);
	isc_barrier_init(&loopmgr->resuming, loopmgr->nloops);
	isc_barrier_init(&loopmgr->starting, loopmgr->nloops);
	isc_barrier_init(&loopmgr->stopping, loopmgr->nloops);

	loopmgr->loops = isc_mem_get(
		loopmgr->mctx, loopmgr->nloops * sizeof(loopmgr->loops[0]));
	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		loop_init(loop, loopmgr, i);
	}

	loopmgr->sigint = isc_signal_new(loopmgr, isc__loopmgr_signal, loopmgr,
					 SIGINT);
	loopmgr->sigterm = isc_signal_new(loopmgr, isc__loopmgr_signal, loopmgr,
					  SIGTERM);

	isc_signal_start(loopmgr->sigint);
	isc_signal_start(loopmgr->sigterm);

	loopmgr->magic = LOOPMGR_MAGIC;

	*loopmgrp = loopmgr;
}

isc_job_t *
isc_loop_setup(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	REQUIRE(VALID_LOOP(loop));
	REQUIRE(cb != NULL);

	isc_loopmgr_t *loopmgr = loop->loopmgr;
	isc_job_t *job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.cb = cb,
		.cbarg = cbarg,
		.link = ISC_LINK_INITIALIZER,
	};

	REQUIRE(loop->tid == isc_tid() || !atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	ISC_LIST_APPEND(loop->setup_jobs, job, link);

	return (job);
}

isc_job_t *
isc_loop_teardown(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	REQUIRE(VALID_LOOP(loop));

	isc_loopmgr_t *loopmgr = loop->loopmgr;
	isc_job_t *job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.cb = cb,
		.cbarg = cbarg,
		.link = ISC_LINK_INITIALIZER,
	};

	REQUIRE(loop->tid == isc_tid() || !atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	ISC_LIST_APPEND(loop->teardown_jobs, job, link);

	return (job);
}

void
isc_loopmgr_setup(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(!atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		(void)isc_loop_setup(loop, cb, cbarg);
	}
}

void
isc_loopmgr_teardown(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(!atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		(void)isc_loop_teardown(loop, cb, cbarg);
	}
}

void
isc_loopmgr_run(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->running,
						     &(bool){ false }, true));

	/*
	 * Always ignore SIGPIPE.
	 */
	ignore_signal(SIGPIPE, SIG_IGN);

	/*
	 * The thread 0 is this one.
	 */
	for (size_t i = 1; i < loopmgr->nloops; i++) {
		char name[32];
		isc_loop_t *loop = &loopmgr->loops[i];

		isc_thread_create(loop_thread, loop, &loop->thread);

		snprintf(name, sizeof(name), "isc-loop-%04zu", i);
		isc_thread_setname(loop->thread, name);
	}

	isc_thread_main(loop_thread, &loopmgr->loops[0]);
}

void
isc_loopmgr_wakeup(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		/* Skip current loop */
		if (i == isc_tid()) {
			continue;
		}

		uv_async_send(&loop->wakeup_trigger);
	}
}

void
isc_loopmgr_pause(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "loop exclusive mode: starting");
	}

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		/* Skip current loop */
		if (i == isc_tid()) {
			continue;
		}

		uv_async_send(&loop->pause_trigger);
	}

	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->paused,
						     &(bool){ false }, true));
	pause_loop(CURRENT_LOOP(loopmgr));

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "loop exclusive mode: started");
	}
}

void
isc_loopmgr_resume(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "loop exclusive mode: ending");
	}

	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->paused,
						     &(bool){ true }, false));
	resume_loop(CURRENT_LOOP(loopmgr));

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "loop exclusive mode: ended");
	}
}

void
isc_loopmgr_destroy(isc_loopmgr_t **loopmgrp) {
	isc_loopmgr_t *loopmgr = NULL;

	REQUIRE(loopmgrp != NULL);
	REQUIRE(VALID_LOOPMGR(*loopmgrp));

	loopmgr = *loopmgrp;
	*loopmgrp = NULL;

	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->running,
						     &(bool){ true }, false));

	/* First wait for all loops to finish */
	for (size_t i = 1; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		isc_thread_join(loop->thread, NULL);
	}

	loopmgr->magic = 0;

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		loop_close(loop);
	}
	isc_mem_put(loopmgr->mctx, loopmgr->loops,
		    loopmgr->nloops * sizeof(loopmgr->loops[0]));

	isc_barrier_destroy(&loopmgr->starting);
	isc_barrier_destroy(&loopmgr->stopping);
	isc_barrier_destroy(&loopmgr->resuming);
	isc_barrier_destroy(&loopmgr->pausing);

	isc_mem_putanddetach(&loopmgr->mctx, loopmgr, sizeof(*loopmgr));
}

uint32_t
isc_loopmgr_nloops(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	return (loopmgr->nloops);
}

isc_mem_t *
isc_loop_getmctx(isc_loop_t *loop) {
	REQUIRE(VALID_LOOP(loop));

	return (loop->mctx);
}

isc_loop_t *
isc_loop_main(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	return (DEFAULT_LOOP(loopmgr));
}

isc_loop_t *
isc_loop_current(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	return (CURRENT_LOOP(loopmgr));
}

isc_loop_t *
isc_loop_get(isc_loopmgr_t *loopmgr, uint32_t tid) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(tid < loopmgr->nloops);

	return (LOOP(loopmgr, tid));
}

void
isc_loopmgr_blocking(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	isc_signal_stop(loopmgr->sigterm);
	isc_signal_stop(loopmgr->sigint);
}

void
isc_loopmgr_nonblocking(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	isc_signal_start(loopmgr->sigint);
	isc_signal_start(loopmgr->sigterm);
}

isc_loopmgr_t *
isc_loop_getloopmgr(isc_loop_t *loop) {
	REQUIRE(VALID_LOOP(loop));

	return (loop->loopmgr);
}
