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

#include <isc/atomic.h>
#include <isc/stack.h>
#include <isc/types.h>
#include <isc/uv.h>

/*
 * Quiescent state based reclamation
 * =================================
 *
 * QSBR is a safe memory reclamation algorithm for lock-free data
 * structures such as a qp-trie.
 *
 * When an object is unlinked from a lock-free data structure, it
 * cannot be free()d immediately, because there can still be readers
 * accessing the object via an old version of the data structure. SMR
 * algorithms determine when it is safe to reclaim memory after it has
 * been unlinked.
 *
 * With QSBR, reading a data structure is wait-free. All that is
 * required is an atomic load to get the data structure's current
 * root; there is no need to explicitly mark any read-side critical
 * section.
 *
 * QSBR is used by RCU (read-copy-update) in the Linux kernel. BIND's
 * implementation also uses some ideas from EBR (epoch-based reclamation).
 * The following summary is based on the overview in the paper
 * "performance of memory reclamation for lockless synchronization",
 * (http://csng.cs.toronto.edu/publication_files/0000/0159/jpdc07.pdf).
 *
 * Aside: This QSBR implementation is somewhat different from the one
 * in liburcu, described in the paper "user-level implementations of
 * read-copy update", (https://www.efficios.com/publications/), which
 * contains the amusing comment:
 *
 *	BIND, a major domain-name server used for Internet domain-name
 *	resolution, is facing scalability issues. Since domain names
 *	are read often but rarely updated, using user-level RCU might
 *	be beneficial.
 *
 * A "quiescent state" is a point when a thread is not accessing any
 * lock-free data structure. After passing through a quiescent state,
 * a thread can no longer access versions of a data structure that
 * were replaced before that point. In BIND, we use a point in the
 * event loop (a uv_prepare_t callback) to identify a quiescent state.
 *
 * Aside: a prepare handle runs its callbacks before the loop sleeps,
 * which reduces reclaim latency (unlike a check handle) and it does
 * not affect timeout calculations (unlike an idle handle).
 *
 * A "grace period" is any time interval such that after the end of
 * the grace period, all objects removed before the start of the grace
 * period can safely be reclaimed. Different SMR algorithms detect
 * grace periods with varying degrees of tightness or looseness.
 *
 * QSBR uses quiescent states to detect grace periods: a grace period
 * is a time interval in which every thread passes through a quiescent
 * state. (This is a safe over-estimate.) A "fuzzy barrier" is used to
 * find out when all threads have passed through a quiescent state.
 *
 * NOTE: In BIND this means that code which is not running in an event
 * loop thread (such as an isc_work / uv_work_t callback) must use
 * locking (not lock-free) data structure accessors.
 *
 * Because a quiescent state happens once per event loop, a grace
 * period takes roughly the same amount of time as the slowest event
 * loop in each cycle.
 *
 * Similar to the paper linked above, this QSBR implementation uses a
 * variant of the EBR fuzzy barrier. Like EBR, each grace period is
 * numbered with a "phase", which cycles round 1,2,3,1,2,3,... (Phases
 * are called epochs in EBR, but I think "phase" is a better metaphor.)
 * When entering the fuzzy barrier, each thread updates its local phase
 * to match the global phase, keeping a global count of the number of
 * threads still to pass. When this count reaches zero, it is the end of
 * the grace period; the global phase is updated and reclamation is
 * triggered.
 *
 * Note that threads are usually slightly out-of-phase wrt the global
 * grace period. At any particular point in time, there will be some
 * threads in the current global phase, and some in the previous
 * global phase. EBR has three phases because that is the minimum
 * number that leaves one phase unoccupied by readers. Any objects that
 * were detached from the data structure in the third phase can be
 * reclaimed after the start of the current phase, because a grace
 * period (the previous phase) has elapsed since the objects were
 * detached.
 *
 * A phase number can be used by a lock-free data structure (such as a
 * qp-trie) to record when an object was detached. QSBR calls the data
 * structure's reclaimer function, passing a phase number indicating
 * that objects detached in that phase can now be reclaimed
 *
 * In general, there will be several (maybe many) write operations
 * during a grace period. The lock-free data structures that use QSBR
 * will collect their reclamation work from all these writes into a
 * batch per phase, i.e. per grace period.
 *
 * There is some example code in `doc/dev/qsbr.md`, with pointers to
 * less terse introductions to QSBR and other overview material.
 */

#define ISC_QSBR_PHASE_BITS 2

typedef unsigned int isc_qsbr_phase_t;
/*%<
 * A grace period phase number. It can be stored in a bitfield of size
 * ISC_QSBR_PHASE_BITS. You can use zero to indicate "no phase".
 * (Don't assume the maximum is three: We might want to increase the
 * number of phases so that there is more than one unoccupied phase.
 * This would allow concurrent reclamation of objects released in
 * multiple unoccupied phases.)
 */

typedef void
isc_qsbreclaimer_t(isc_qsbr_phase_t phase);
/*%<
 * The type of memory reclaimer callback functions.
 *
 * The `phase` identifies which objects are to be reclaimed.
 *
 * An isc_qsbreclaimer_t can call isc_qsbr_activate() if it could not
 * reclaim everything and needs to be called again.
 */

typedef struct isc_qsbr_registered {
	ISC_SLINK(struct isc_qsbr_registered) link;
	isc_qsbreclaimer_t *func;
} isc_qsbr_registered_t;
/*%<
 * Each reclaimer callback has a static `isc_qsbr_registered_t` object
 * so that QSBR can find it.
 */

void
isc__qsbr_register(isc_qsbr_registered_t *reg);
/*%<
 * Requires:
 * \li	reclaimer->link is not linked
 * \li	reclaimer->func is not NULL
 */

#define isc_qsbr_register(cb)                                 \
	do {                                                  \
		static isc_qsbr_registered_t registration = { \
			.link = ISC_SLINK_INITIALIZER,        \
			.func = cb,                           \
		};                                            \
		isc__qsbr_register(&registration);            \
	} while (0)
/*%<
 * Register a callback function with QSBR. This macro should be used
 * inside an `ISC_CONSTRUCTOR` function. There should be one callback
 * for eack lock-free data structure implementation, which is able to
 * reclaim all the unused memory across all instances of its data
 * structure.
 */

isc_qsbr_phase_t
isc_qsbr_phase(isc_loopmgr_t *loopmgr);
/*%<
 * Get the current phase, to use for marking detached objects.
 *
 * To commit a write that requires cleanup, the ordering must be:
 *
 * - Use atomic_store_release() to commit the data structure's new
 *   root pointer; release ordering ensures that the interior changes
 *   are written before the root pointer.
 *
 * - Call isc_qsbr_phase() to get the phase to be used for marking
 *   objects to reclaim. This must happen after the commit, to ensure
 *   there is at least one grace period between commit and cleanup.
 *
 * - Pass the same phase to isc_qsbr_activate() so that the reclaimer
 *   will be called after a grace period has passed.
 */

void
isc_qsbr_activate(isc_loopmgr_t *loopmgr, isc_qsbr_phase_t phase);
/*%<
 * Tell QSBR that objects have been detached and will need reclaiming
 * after a grace period.
 */

/***********************************************************************
 *
 *  private parts
 */

/*
 * Accessors and constructors for the `grace` variable.
 * It contains two bit fields:
 *
 *   - the global phase in the lower ISC_QSBR_PHASE_BITS
 *
 *   - a thread counter in the upper bits
 */

#define ISC_QSBR_ONE_THREAD (1 << ISC_QSBR_PHASE_BITS)
#define ISC_QSBR_PHASE_MAX  (ISC_QSBR_ONE_THREAD - 1)

#define ISC_QSBR_GRACE_PHASE(grace)   (grace & ISC_QSBR_PHASE_MAX)
#define ISC_QSBR_GRACE_THREADS(grace) (grace >> ISC_QSBR_PHASE_BITS)
#define ISC_QSBR_GRACE(threads, phase) \
	((threads << ISC_QSBR_PHASE_BITS) | phase)

typedef struct isc_qsbr {
	/*
	 * The `grace` variable keeps track of the current grace period.
	 * When the phase changes, the thread counter is set to the number of
	 * threads that need to observe the new phase before the grace period
	 * can end.
	 *
	 * The thread counter is an add-on to the usual EBR fuzzy barrier.
	 * Counting threads through the barrier adds multi-thread update
	 * contention, and in EBR the fuzzy barrier runs frequently enough
	 * (on every access) that it's important to minimize its cost. With
	 * QSBR, the fuzzy barrier runs less frequently (roughly, per loop,
	 * instead of per-callback) so contention is less of a concern. The
	 * thread counter helps to reduce reclaim latency, because unlike EBR
	 * we don't probabilistically check, we know deterministically when
	 * all threads have changed phase.
	 */
	atomic_uint_fast32_t grace;

	/*
	 * A flag for each phase indicating that there will be work to
	 * do, so we don't invoke the reclaim machinery unnecessarily.
	 * Set by `isc_qsbr_activate()` and cleared before the reclaimer
	 * functions are invoked (so they can re-set their flag if
	 * necessary).
	 */
	atomic_uint_fast32_t activated;

	/*
	 * The time of the last phase transition (isc_nanosecs_t). Used
	 * to ensure that grace periods do not last forever. We use
	 * `isc_time_monotonic()` because we need the same time in all
	 * threads. (`uv_now()` is different in different threads.)
	 */
	atomic_uint_fast64_t transition_time;

} isc_qsbr_t;

/*
 * When we start there is no worker thread yet, so the thread
 * count is equal to the number of loops. The global phase starts
 * off at one (it must always be nonzero).
 */
#define ISC_QSBR_INITIALIZER(nloops)                     \
	(isc_qsbr_t) {                                   \
		.grace = ISC_QSBR_GRACE(nloops, 1),      \
		.transition_time = isc_time_monotonic(), \
	}

/*
 * For use by tests that need to explicitly drive QSBR phase transitions.
 */
void
isc__qsbr_quiescent_state(isc_loop_t *loop);

/*
 * Used by the loopmgr
 */
void
isc__qsbr_quiescent_cb(uv_prepare_t *handle);
void
isc__qsbr_destroy(isc_loopmgr_t *loopmgr);
