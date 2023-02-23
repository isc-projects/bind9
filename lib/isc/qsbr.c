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

#include <isc/atomic.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/qsbr.h>
#include <isc/stack.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/types.h>
#include <isc/uv.h>

#include "loop_p.h"

#define MAX_GRACE_PERIOD_NS 53 * NS_PER_MS

#if 0
#define TRACE(fmt, ...)                                                       \
	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, \
		      ISC_LOG_DEBUG(7), "%s:%u:%s():t%u: " fmt, __FILE__,     \
		      __LINE__, __func__, isc_tid(), ##__VA_ARGS__)
#else
#define TRACE(...)
#endif

static ISC_STACK(isc_qsbr_registered_t) qsbreclaimers = ISC_STACK_INITIALIZER;

static void
reclaim_cb(void *arg);
static void
reclaimed_cb(void *arg);

/**********************************************************************/

/*
 * 3,2,1,3,2,1,...
 */
static isc_qsbr_phase_t
change_phase(isc_qsbr_phase_t phase) {
	return (--phase > 0 ? phase : ISC_QSBR_PHASE_MAX);
}

/*
 * For marking or checking that a phase has cleanup work to do.
 */
static unsigned int
active_bit(isc_qsbr_phase_t phase) {
	return (1 << phase);
}

/*
 * Extract the global phase from the grace period state.
 */
static isc_qsbr_phase_t
global_phase(isc_qsbr_t *qsbr, memory_order m_o) {
	uint32_t grace = atomic_load_explicit(&qsbr->grace, m_o);
	return (ISC_QSBR_GRACE_PHASE(grace));
}

/*
 * Record that the current thread has passed the barrier.
 * Returns true if more threads still need to pass.
 *
 * ATOMIC: acquire-release, to ensure that this is not reordered wrt
 * read-only accesses to lock-free data structures. This implements the
 * ordering requirements of a quiescent state.
 */
static bool
fuzzy_barrier_not_yet(isc_qsbr_t *qsbr) {
	uint32_t grace = atomic_fetch_sub_acq_rel(&qsbr->grace,
						  ISC_QSBR_ONE_THREAD);
	uint32_t threads = ISC_QSBR_GRACE_THREADS(grace);
	return (threads > 1);
}

/*
 * Ungracefully drive all cleanup work to completion.
 *
 * ATOMIC: everything is relaxed, because we assume that concurrent
 * readers have already finished. `reclaim_cb()` uses the `activated`
 * flags to ensure it is OK that threads will race to complete the
 * cleanup.
 */
static void
qsbr_shutdown(isc_loopmgr_t *loopmgr) {
	isc_qsbr_t *qsbr = &loopmgr->qsbr;
	isc_qsbr_phase_t phase = global_phase(qsbr, memory_order_relaxed);
	uint32_t threads = isc_loopmgr_nloops(loopmgr);
	uint32_t grace;

	while (atomic_load_relaxed(&qsbr->activated) != 0) {
		reclaim_cb(loopmgr);
		phase = change_phase(phase);
		grace = ISC_QSBR_GRACE(threads, phase);
		atomic_store_relaxed(&qsbr->grace, grace);
	}
}

/*
 * On a quiet server that does not have enough network traffic to keep
 * all its threads spinning, grace periods might extend indefinitely.
 * So check if we have been waiting an unreasonably long time since
 * the last phase change. If so, send a no-op async request to every
 * thread to make them all cycle through a quiescent state.
 */
static void
maybe_wakeup(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;
	isc_qsbr_t *qsbr = &loopmgr->qsbr;

	/*
	 * ATOMIC: relaxed is OK here because we don't use any values guarded
	 * by the `activated` flags.
	 */
	if (atomic_load_relaxed(&qsbr->activated) == 0) {
		return;
	}
	if (loop->shuttingdown) {
		qsbr_shutdown(loopmgr);
		return;
	}

	/*
	 * ATOMIC: relaxed, because the `transition_time` doesn't guard any
	 * other values, just the isc_loopmgr_wakeup() call below.
	 */
	atomic_uint_fast64_t *qsbr_ttp = &qsbr->transition_time;
	isc_nanosecs_t now = isc_time_monotonic();
	isc_nanosecs_t start = atomic_load_relaxed(qsbr_ttp);
	if (now < start + MAX_GRACE_PERIOD_NS) {
		return;
	}

	/*
	 * To stop other threads from also invoking `isc_loopmgr_wakeup()`,
	 * we try to push the timer into the future (expecting that it will
	 * not trigger again), and quit if someone else got there first.
	 * ATOMIC: relaxed, as before; strong, because there is no retry loop.
	 */
	if (!atomic_compare_exchange_strong_relaxed(qsbr_ttp, &start, now)) {
		return;
	}

	TRACE("long grace period of %llu ns, waking up other threads",
	      (unsigned long long)(now - start));

	isc_loopmgr_wakeup(loopmgr);
}

/*
 * Callers use the fuzzy barrier to ensure only one thread can enter
 * this function at a time.
 *
 * Phase transitions happen at roughly the same frequency that IO
 * event loops cycle, limited by the slowest loop in each cycle.
 */
static void
phase_transition(isc_loop_t *loop, isc_qsbr_phase_t current_phase) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;
	isc_qsbr_t *qsbr = &loopmgr->qsbr;

	if (loop->shuttingdown) {
		qsbr_shutdown(loopmgr);
		return;
	}

	/*
	 * After we change phase, threads will be in either the `current_phase`
	 * or the `next_phase`. We will reclaim memory from the `third_phase`.
	 *
	 * ATOMIC: relaxed is OK here because the necessary synchronization
	 * happens in `reclaim_cb()`.
	 */
	isc_qsbr_phase_t next_phase = change_phase(current_phase);
	isc_qsbr_phase_t third_phase = change_phase(next_phase);
	bool activated = atomic_load_relaxed(&qsbr->activated) &
			 active_bit(third_phase);

	/*
	 * Reset the wakeup timer, and log the length of the grace period.
	 * ATOMIC: relaxed, per the commentary in `maybe_wakeup()`.
	 */
	atomic_uint_fast64_t *qsbr_tt = &qsbr->transition_time;
	isc_nanosecs_t now = isc_time_monotonic();
	isc_nanosecs_t start = atomic_exchange_relaxed(qsbr_tt, now);
	TRACE("phase %u -> %u after grace period of %f ms", current_phase,
	      next_phase, (double)(now - start) / NS_PER_MS);
	UNUSED(start); /* ifndef TRACE() */

	/*
	 * Work out the threads counter for this grace period.
	 *
	 * We need to add one for any reclamation worker thread, to
	 * prevent us from changing phase before the work is done. If
	 * we change too early, any newly detached objects will be
	 * marked with the same phase as the running reclaimer, which
	 * might lead to them being free()d too soon.
	 */
	uint32_t threads = isc_loopmgr_nloops(loopmgr) + (activated ? 1 : 0);

	/*
	 * Start the new grace period.
	 *
	 * ATOMIC: release, to pair with the load-acquire in `reclaim_cb()`
	 * which is spawned in a separate worker thread.
	 */
	uint32_t grace = ISC_QSBR_GRACE(threads, next_phase);
	atomic_store_release(&qsbr->grace, grace);

	if (activated) {
		isc_work_enqueue(loop, reclaim_cb, reclaimed_cb, loopmgr);
	}
}

/*
 * This function is called once per cycle of each IO event loop by the
 * `uv_prepare` callback below.
 */
void
isc__qsbr_quiescent_state(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;
	isc_qsbr_t *qsbr = &loopmgr->qsbr;

	/*
	 * ATOMIC: relaxed. If we are in phase then we don't need to
	 * synchronize; if we are not then this thread's presence in
	 * the thread counter will prevent the phase from changing
	 * before we get to the fuzzy barrier.
	 */
	isc_qsbr_phase_t phase = global_phase(qsbr, memory_order_relaxed);
	if (loop->qsbr_phase == phase) {
		maybe_wakeup(loop);
		return;
	}

	/*
	 * Enter the current phase and count us out of the previous phase.
	 */
	loop->qsbr_phase = phase;
	if (fuzzy_barrier_not_yet(qsbr)) {
		maybe_wakeup(loop);
		return;
	}

	/*
	 * We were the last thread to enter the current phase so the
	 * grace period is up. No other thread can reach this point.
	 */
	phase_transition(loop, phase);
}

void
isc__qsbr_quiescent_cb(uv_prepare_t *handle) {
	isc_loop_t *loop = uv_handle_get_data((uv_handle_t *)handle);
	isc__qsbr_quiescent_state(loop);
}

static void
reclaimed_cb(void *arg) {
	/* we are back on a loop thread */
	isc_loopmgr_t *loopmgr = arg;
	isc_qsbr_t *qsbr = &loopmgr->qsbr;
	isc_loop_t *loop = CURRENT_LOOP(loopmgr);

	/*
	 * Remove the reclaimers from the thread count, so that the
	 * next grace period can start.
	 */
	if (fuzzy_barrier_not_yet(qsbr)) {
		return;
	}

	/*
	 * The reclaimers were the last thread to be counted out: every
	 * other thread already passed through a quiescent state.
	 *
	 * We expect loop->qsbr_phase == global_phase() at this point,
	 * except during shutdown when the phase shifts rapidly. Also,
	 * the current loop might not have received the shutdown
	 * message yet, so it seems easiest to omit the assertion.
	 *
	 * ATOMIC: relaxed, the fuzzy barrier already synchronized.
	 */
	TRACE("reclaimers overran");
	phase_transition(loop, global_phase(qsbr, memory_order_relaxed));
}

static void
reclaim_cb(void *arg) {
	/* we are on a work thread not a loop thread */
	isc_loopmgr_t *loopmgr = arg;
	isc_qsbr_t *qsbr = &loopmgr->qsbr;

	/*
	 * The global phase has just been bumped by a `phase_transition()`
	 * and it cannot change again until the grace period is up, which
	 * cannot happen until we have finished working.
	 *
	 * ATOMIC: acquire, to pair with the release in `phase_transition()`.
	 *
	 * The phase we are to clean up is 2 before the current phase,
	 * which is the same as the one after the current phase (mod 3).
	 */
	isc_qsbr_phase_t cur_phase = global_phase(qsbr, memory_order_acquire);
	isc_qsbr_phase_t third_phase = change_phase(cur_phase);
	unsigned int third_bit = active_bit(third_phase);

	/*
	 * If any reclaimers need to be called again later, they can use
	 * `isc_qsbr_activate()`, so we need to clear the bit first.
	 *
	 * ATOMIC: acquire, so that `isc_qsbr_activate()` happens before
	 * the callbacks are invoked.
	 */
	uint32_t activated = atomic_fetch_and_explicit(
		&qsbr->activated, ~third_bit, memory_order_acquire);

	/* this can happen when we are racing to clean up on shutdown */
	if ((activated & third_bit) == 0) {
		return;
	}

	isc_qsbr_registered_t *reclaimer = ISC_STACK_TOP(qsbreclaimers);
	while (reclaimer != NULL) {
		reclaimer->func(third_phase);
		reclaimer = ISC_SLINK_NEXT(reclaimer, link);
	}
}

void
isc__qsbr_register(isc_qsbr_registered_t *reclaimer) {
	REQUIRE(reclaimer->func != NULL);
	ISC_STACK_PUSH(qsbreclaimers, reclaimer, link);
}

/*
 * ATOMIC: This function needs to ensure that the global phase is read
 * after a write has committed. Acquire/release ordering is not sufficient
 * for ordering between separate atomics (the data structure's root pointer
 * and the global phase), so it must be sequentially consistent.
 *
 * In general, the phases up to and including the next phase transition
 * look like:
 *
 * 1. local phase
 * 2. global phase
 * 3. next phase
 * 1. third phase
 *
 * i.e. some threads are still one behind the global phase, on the same
 * phase that will be cleaned up immediately after the phase transition.
 *
 * This function is called just after a write commits. It's likely that
 * some threads on the global phase (2) are using a version of the data
 * structure from before the write, and they can continue using it while
 * the straggler threads (1) catch up and cause a phase transition.
 *
 * The writer can be one of the straggler threads. If it incorrectly marks
 * cleanup work with its local phase (1), memory will be reclaimed
 * immediately after the next phase transition (when the third phase is
 * also 1), which could be almost immediately when the writer returns to
 * the event loop. This will cause a use-after-free for existing readers
 * (in phase 2).
 *
 * More straightforwardly, we need to be able to queue up reclaim work from
 * a thread that isn't running a loop, which also means this function has
 * to return the global phase.
 */
isc_qsbr_phase_t
isc_qsbr_phase(isc_loopmgr_t *loopmgr) {
	isc_qsbr_t *qsbr = &loopmgr->qsbr;
	return (global_phase(qsbr, memory_order_seq_cst));
}

void
isc_qsbr_activate(isc_loopmgr_t *loopmgr, isc_qsbr_phase_t phase) {
	/*
	 * ATOMIC: release ordering ensures that writing the cleanup lists
	 * happens before the callback is invoked from a worker thread.
	 */
	atomic_fetch_or_release(&loopmgr->qsbr.activated, active_bit(phase));
}
