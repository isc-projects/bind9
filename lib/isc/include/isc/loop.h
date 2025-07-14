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

#pragma once

#include <inttypes.h>

#include <urcu/compiler.h>
#include <urcu/system.h>

#include <isc/job.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/types.h>

typedef void (*isc_job_cb)(void *);

/* Add -DISC_LOOP_TRACE=1 to CFLAGS for detailed reference tracing */

/*%<
 * Returns the current running loop.
 */

extern thread_local isc_loop_t *isc__loop_local;

static inline isc_loop_t *
isc_loop(void) {
	return isc__loop_local;
}

void
isc_loopmgr_create(isc_mem_t *mctx, uint32_t nloops);
/*%<
 * Create a loop manager supporting 'nloops' loops.
 *
 * Requires:
 *\li	'nloops' is greater than 0.
 */

void
isc_loopmgr_destroy(void);
/*%<
 * Destroy the loop manager.
 */

void
isc_loopmgr_shutdown(void);
/*%<
 * Request shutdown of the loop manager.
 *
 * This will stop all signal handlers and send shutdown events to
 * all active loops. As a final action on shutting down, each loop
 * will run the function (or functions) set by isc_loopmgr_teardown()
 * or isc_loop_teardown().
 */

void
isc_loopmgr_run(void);
/*%<
 * Run the loops in loop manager. Each loop will start by running the
 * function (or functions) set by isc_loopmgr_setup() or isc_loop_setup().
 */

void
isc_loopmgr_pause(void);
/*%<
 * Send pause events to all running loops in loop manager except the
 * current one. This can only be called from a running loop.
 * All the paused loops will wait until isc_loopmgr_resume() is
 * run in the calling loop before continuing.
 *
 * Requires:
 *\li	We are in a running loop.
 */

bool
isc_loopmgr_paused(void);
/*%<
 * Returns true if the loopmgr has been paused and not yet resumed.
 *
 * Requires:
 *\li	We are in a running loop.
 */

void
isc_loopmgr_resume(void);
/*%<
 * Send resume events to all paused loops in loop manager. This can
 * only be called by a running loop (which must therefore be the
 * loop that called isc_loopmgr_pause()).
 *
 * Requires:
 *\li	We are in a running loop.
 */

uint32_t
isc_loopmgr_nloops(void);

isc_job_t *
isc_loop_setup(isc_loop_t *loop, isc_job_cb cb, void *cbarg);
isc_job_t *
isc_loop_teardown(isc_loop_t *loop, isc_job_cb cb, void *cbarg);
/*%<
 * Schedule actions to be run when starting, and when shutting down,
 * one of the loops in a loop manager.
 *
 * Requires:
 *\li	'loop' is a valid loop.
 *\li	The loop manager associated with 'loop' is paused or has not
 *	yet been started.
 */

void
isc_loopmgr_setup(isc_job_cb cb, void *cbarg);
void
isc_loopmgr_teardown(isc_job_cb cb, void *cbarg);
/*%<
 * Schedule actions to be run when starting, and when shutting down,
 * *all* of the loops in loopmgr.
 *
 * This is the same as running isc_loop_setup() or
 * isc_loop_teardown() on each of the loops in turn.
 *
 * Requires:
 *\li	loopmgr is paused or has not yet been started.
 */

isc_mem_t *
isc_loop_getmctx(isc_loop_t *loop);
/*%<
 * Return a pointer to the a memory context that was created for
 * 'loop' when it was initialized.
 *
 * Requires:
 *\li	'loop' is a valid loop.
 */

isc_loop_t *
isc_loop_main(void);
/*%<
 * Returns the main loop for the loop manager (which is 'loops[0]',
 * regardless of how many loops there are).
 */

isc_loop_t *
isc_loop_get(isc_tid_t tid);
/*%<
 * Return the loop object associated with the 'tid' threadid
 *
 * Requires:
 *\li   'tid' is smaller than number of initialized loops
 */

#if ISC_LOOP_TRACE
#define isc_loop_ref(ptr)   isc_loop__ref(ptr, __func__, __FILE__, __LINE__)
#define isc_loop_unref(ptr) isc_loop__unref(ptr, __func__, __FILE__, __LINE__)
#define isc_loop_attach(ptr, ptrp) \
	isc_loop__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define isc_loop_detach(ptrp) \
	isc_loop__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(isc_loop);
#else
ISC_REFCOUNT_DECL(isc_loop);
#endif
/*%<
 * Reference counting functions for isc_loop
 */

void
isc_loopmgr_blocking(void);
void
isc_loopmgr_nonblocking(void);
/*%<
 * isc_loopmgr_blocking() stops the SIGINT and SIGTERM signal handlers
 * during blocking operations, for example while waiting for user
 * interaction; isc_loopmgr_nonblocking() restarts them.
 */

isc_time_t
isc_loop_now(isc_loop_t *loop);
/*%<
 * Returns the start time of the current loop tick.
 *
 * Requires:
 *
 * \li 'loop' is a valid loop.
 */

bool
isc_loop_shuttingdown(isc_loop_t *loop);
/*%<
 * Returns whether the loop is shutting down.
 *
 * Requires:
 *
 * \li 'loop' is a valid loop and the loop tid matches the current tid.
 */

isc_loop_t *
isc_loop_helper(isc_loop_t *loop);
/*%<
 * Returns the helper thread corresponding to the thread ID for 'loop'.
 *
 * Requires:
 *
 * \li 'loop' is a valid loop.
 */
