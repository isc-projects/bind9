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

#include <isc/atomic.h>
#include <isc/barrier.h>
#include <isc/condition.h>
#include <isc/job.h>
#include <isc/list.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/signal.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>
#include <isc/work.h>

#include "job_p.h"
#include "loop_p.h"

#define JOB_MAGIC    ISC_MAGIC('J', 'O', 'B', ' ')
#define VALID_JOB(t) ISC_MAGIC_VALID(t, JOB_MAGIC)

/*
 * Private: static
 */

static void
isc__job_close_cb(uv_handle_t *handle) {
	isc_job_t *job = uv_handle_get_data(handle);
	isc_loop_t *loop = job->loop;

	REQUIRE(loop == isc_loop_current(job->loop->loopmgr));

	isc_mem_put(loop->mctx, job, sizeof(*job));

	isc_loop_detach(&loop);
}

static void
isc__job_destroy(isc_job_t *job) {
	REQUIRE(VALID_JOB(job));
	REQUIRE(job->loop == isc_loop_current(job->loop->loopmgr));

	job->magic = 0;

	uv_close(&job->idle, isc__job_close_cb);
}

static void
isc__job_cb(uv_idle_t *idle) {
	isc_job_t *job = uv_handle_get_data(idle);
	int r;

	REQUIRE(job->loop == isc_loop_current(job->loop->loopmgr));

	job->cb(job->cbarg);

	r = uv_idle_stop(idle);
	UV_RUNTIME_CHECK(uv_idle_stop, r);

	isc__job_destroy(job);
}

/*
 * Public: #include <isc/job.h>
 */

void
isc_job_run(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	isc_loop_t *loop = isc_loop_current(loopmgr);
	isc_job_t *job = isc__job_new(loop, cb, cbarg);
	isc__job_init(loop, job);
	isc__job_run(job);
}

/*
 * Protected: #include <job_p.h>
 */

isc_job_t *
isc__job_new(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	isc_job_t *job = NULL;

	REQUIRE(VALID_LOOP(loop));
	REQUIRE(cb != NULL);

	job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.magic = JOB_MAGIC,
		.cb = cb,
		.cbarg = cbarg,
	};

	isc_loop_attach(loop, &job->loop);

	ISC_LINK_INIT(job, link);

	return (job);
}

void
isc__job_init(isc_loop_t *loop, isc_job_t *job) {
	int r = uv_idle_init(&loop->loop, &job->idle);
	UV_RUNTIME_CHECK(uv_idle_init, r);
	uv_handle_set_data(&job->idle, job);
}

void
isc__job_run(isc_job_t *job) {
	int r;

	REQUIRE(VALID_JOB(job));
	REQUIRE(job->loop == isc_loop_current(job->loop->loopmgr));

	r = uv_idle_start(&job->idle, isc__job_cb);
	UV_RUNTIME_CHECK(uv_idle_start, r);
}
