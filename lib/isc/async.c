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
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/signal.h>
#include <isc/stack.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>
#include <isc/work.h>

#include "async_p.h"
#include "job_p.h"
#include "loop_p.h"

void
isc_async_run(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	REQUIRE(VALID_LOOP(loop));
	REQUIRE(cb != NULL);

	isc_job_t *job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.link = ISC_LINK_INITIALIZER,
		.cb = cb,
		.cbarg = cbarg,
	};

	/*
	 * Now send the half-initialized job to the loop queue.
	 */
	ISC_ASTACK_PUSH(loop->async_jobs, job, link);

	int r = uv_async_send(&loop->async_trigger);
	UV_RUNTIME_CHECK(uv_async_send, r);
}

void
isc__async_cb(uv_async_t *handle) {
	isc_loop_t *loop = uv_handle_get_data(handle);

	REQUIRE(VALID_LOOP(loop));

	ISC_STACK(isc_job_t) drain = ISC_ASTACK_TO_STACK(loop->async_jobs);
	ISC_LIST(isc_job_t) jobs = ISC_LIST_INITIALIZER;

	isc_job_t *job = ISC_STACK_POP(drain, link);
	isc_job_t *next = NULL;
	while (job != NULL) {
		ISC_LIST_PREPEND(jobs, job, link);

		job = ISC_STACK_POP(drain, link);
	}

	for (job = ISC_LIST_HEAD(jobs),
	    next = (job ? ISC_LIST_NEXT(job, link) : NULL);
	     job != NULL;
	     job = next, next = (job ? ISC_LIST_NEXT(job, link) : NULL))
	{
		job->cb(job->cbarg);

		isc_mem_put(loop->mctx, job, sizeof(*job));
	}
}

void
isc__async_close(uv_handle_t *handle) {
	isc_loop_t *loop = uv_handle_get_data(handle);

	isc__async_cb(&loop->async_trigger);
}
