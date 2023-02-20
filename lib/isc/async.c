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

#include "job_p.h"
#include "loop_p.h"

void
isc_async_run(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	int r;
	isc_job_t *job = NULL;

	REQUIRE(VALID_LOOP(loop));
	REQUIRE(cb != NULL);

	job = isc__job_new(loop, cb, cbarg);

	/*
	 * Now send the half-initialized job to the loop queue.
	 *
	 * The ISC_ASTACK_PUSH is counterintuitive here, but uv_idle
	 * drains its queue backwards, so if there's more than one event
	 * to be processed then they need to be in reverse order.
	 */
	ISC_ASTACK_PUSH(loop->queue_jobs, job, link);

	r = uv_async_send(&loop->queue_trigger);
	UV_RUNTIME_CHECK(uv_async_send, r);
}
