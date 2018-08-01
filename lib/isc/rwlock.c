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


/*! \file */

#include <config.h>

#include <stddef.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/msgs.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#define RWLOCK_MAGIC		ISC_MAGIC('R', 'W', 'L', 'k')
#define VALID_RWLOCK(rwl)	ISC_MAGIC_VALID(rwl, RWLOCK_MAGIC)

#ifdef ISC_PLATFORM_USETHREADS

#ifndef RWLOCK_DEFAULT_READ_QUOTA
#define RWLOCK_DEFAULT_READ_QUOTA 4
#endif

#ifndef RWLOCK_DEFAULT_WRITE_QUOTA
#define RWLOCK_DEFAULT_WRITE_QUOTA 4
#endif

#ifndef RWLOCK_MAX_ADAPTIVE_COUNT
#define RWLOCK_MAX_ADAPTIVE_COUNT 100
#endif

static isc_result_t
isc__rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

#ifdef ISC_RWLOCK_TRACE
#include <stdio.h>		/* Required for fprintf/stderr. */
#include <isc/thread.h>		/* Required for isc_thread_self(). */

static void
print_lock(const char *operation, isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	fprintf(stderr,
		isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
			       ISC_MSG_PRINTLOCK2,
			       "rwlock %p thread %lu %s(%s): "
			       "write_requests=%u, write_completions=%u, "
			       "cnt_and_flag=0x%x, readers_waiting=%u, "
			       "write_granted=%u, write_quota=%u\n"),
		rwl, isc_thread_self(), operation,
		(type == isc_rwlocktype_read ?
		 isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				ISC_MSG_READ, "read") :
		 isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				ISC_MSG_WRITE, "write")),
		rwl->write_requests, rwl->write_completions,
		rwl->cnt_and_flag, rwl->readers_waiting,
		rwl->write_granted, rwl->write_quota);
}
#endif /* ISC_RWLOCK_TRACE */

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota)
{
	isc_result_t result;

	REQUIRE(rwl != NULL);

	/*
	 * In case there's trouble initializing, we zero magic now.  If all
	 * goes well, we'll set it to RWLOCK_MAGIC.
	 */
	rwl->magic = 0;

	rwl->spins = 0;
	rwl->write_requests = 0;
	rwl->write_completions = 0;
	rwl->cnt_and_flag = 0;
	rwl->readers_waiting = 0;
	rwl->write_granted = 0;
	if (read_quota != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "read quota is not supported");
	}
	if (write_quota == 0)
		write_quota = RWLOCK_DEFAULT_WRITE_QUOTA;
	rwl->write_quota = write_quota;

	result = isc_mutex_init(&rwl->lock);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_condition_init(&rwl->readable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(readable) %s: %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"),
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto destroy_lock;
	}
	result = isc_condition_init(&rwl->writeable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(writeable) %s: %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"),
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto destroy_rcond;
	}

	rwl->magic = RWLOCK_MAGIC;

	return (ISC_R_SUCCESS);

  destroy_rcond:
	(void)isc_condition_destroy(&rwl->readable);
  destroy_lock:
	DESTROYLOCK(&rwl->lock);

	return (result);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	REQUIRE(rwl->write_requests == rwl->write_completions &&
		rwl->cnt_and_flag == 0 && rwl->readers_waiting == 0);

	rwl->magic = 0;
	(void)isc_condition_destroy(&rwl->readable);
	(void)isc_condition_destroy(&rwl->writeable);
	DESTROYLOCK(&rwl->lock);
}

/*
 * When some architecture-dependent atomic operations are available,
 * rwlock can be more efficient than the generic algorithm defined below.
 * The basic algorithm is described in the following URL:
 *   http://www.cs.rochester.edu/u/scott/synchronization/pseudocode/rw.html
 *
 * The key is to use the following integer variables modified atomically:
 *   write_requests, write_completions, and cnt_and_flag.
 *
 * write_requests and write_completions act as a waiting queue for writers
 * in order to ensure the FIFO order.  Both variables begin with the initial
 * value of 0.  When a new writer tries to get a write lock, it increments
 * write_requests and gets the previous value of the variable as a "ticket".
 * When write_completions reaches the ticket number, the new writer can start
 * writing.  When the writer completes its work, it increments
 * write_completions so that another new writer can start working.  If the
 * write_requests is not equal to write_completions, it means a writer is now
 * working or waiting.  In this case, a new readers cannot start reading, or
 * in other words, this algorithm basically prefers writers.
 *
 * cnt_and_flag is a "lock" shared by all readers and writers.  This integer
 * variable is a kind of structure with two members: writer_flag (1 bit) and
 * reader_count (31 bits).  The writer_flag shows whether a writer is working,
 * and the reader_count shows the number of readers currently working or almost
 * ready for working.  A writer who has the current "ticket" tries to get the
 * lock by exclusively setting the writer_flag to 1, provided that the whole
 * 32-bit is 0 (meaning no readers or writers working).  On the other hand,
 * a new reader tries to increment the "reader_count" field provided that
 * the writer_flag is 0 (meaning there is no writer working).
 *
 * If some of the above operations fail, the reader or the writer sleeps
 * until the related condition changes.  When a working reader or writer
 * completes its work, some readers or writers are sleeping, and the condition
 * that suspended the reader or writer has changed, it wakes up the sleeping
 * readers or writers.
 *
 * As already noted, this algorithm basically prefers writers.  In order to
 * prevent readers from starving, however, the algorithm also introduces the
 * "writer quota" (Q).  When Q consecutive writers have completed their work,
 * suspending readers, the last writer will wake up the readers, even if a new
 * writer is waiting.
 *
 * Implementation specific note: due to the combination of atomic operations
 * and a mutex lock, ordering between the atomic operation and locks can be
 * very sensitive in some cases.  In particular, it is generally very important
 * to check the atomic variable that requires a reader or writer to sleep after
 * locking the mutex and before actually sleeping; otherwise, it could be very
 * likely to cause a deadlock.  For example, assume "var" is a variable
 * atomically modified, then the corresponding code would be:
 *	if (var == need_sleep) {
 *		LOCK(lock);
 *		if (var == need_sleep)
 *			WAIT(cond, lock);
 *		UNLOCK(lock);
 *	}
 * The second check is important, since "var" is protected by the atomic
 * operation, not by the mutex, and can be changed just before sleeping.
 * (The first "if" could be omitted, but this is also important in order to
 * make the code efficient by avoiding the use of the mutex unless it is
 * really necessary.)
 */

#define WRITER_ACTIVE	0x1
#define READER_INCR	0x2

static isc_result_t
isc__rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_int32_t cntflag;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_PRELOCK, "prelock"), rwl, type);
#endif

	if (type == isc_rwlocktype_read) {
		if (rwl->write_requests != rwl->write_completions) {
			/* there is a waiting or active writer */
			LOCK(&rwl->lock);
			if (rwl->write_requests != rwl->write_completions) {
				rwl->readers_waiting++;
				WAIT(&rwl->readable, &rwl->lock);
				rwl->readers_waiting--;
			}
			UNLOCK(&rwl->lock);
		}

		cntflag = atomic_fetch_add_explicit(&rwl->cnt_and_flag,
						    READER_INCR,
						    memory_order_relaxed);
		POST(cntflag);
		while (1) {
			if ((rwl->cnt_and_flag & WRITER_ACTIVE) == 0)
				break;

			/* A writer is still working */
			LOCK(&rwl->lock);
			rwl->readers_waiting++;
			if ((rwl->cnt_and_flag & WRITER_ACTIVE) != 0)
				WAIT(&rwl->readable, &rwl->lock);
			rwl->readers_waiting--;
			UNLOCK(&rwl->lock);

			/*
			 * Typically, the reader should be able to get a lock
			 * at this stage:
			 *   (1) there should have been no pending writer when
			 *       the reader was trying to increment the
			 *       counter; otherwise, the writer should be in
			 *       the waiting queue, preventing the reader from
			 *       proceeding to this point.
			 *   (2) once the reader increments the counter, no
			 *       more writer can get a lock.
			 * Still, it is possible another writer can work at
			 * this point, e.g. in the following scenario:
			 *   A previous writer unlocks the writer lock.
			 *   This reader proceeds to point (1).
			 *   A new writer appears, and gets a new lock before
			 *   the reader increments the counter.
			 *   The reader then increments the counter.
			 *   The previous writer notices there is a waiting
			 *   reader who is almost ready, and wakes it up.
			 * So, the reader needs to confirm whether it can now
			 * read explicitly (thus we loop).  Note that this is
			 * not an infinite process, since the reader has
			 * incremented the counter at this point.
			 */
		}

		/*
		 * If we are temporarily preferred to writers due to the writer
		 * quota, reset the condition (race among readers doesn't
		 * matter).
		 */
		rwl->write_granted = 0;
	} else {
		isc_int32_t prev_writer;

		/* enter the waiting queue, and wait for our turn */
		prev_writer = atomic_fetch_add_explicit(&rwl->write_requests, 1,
							memory_order_relaxed);
		while (rwl->write_completions != prev_writer) {
			LOCK(&rwl->lock);
			if (rwl->write_completions != prev_writer) {
				WAIT(&rwl->writeable, &rwl->lock);
				UNLOCK(&rwl->lock);
				continue;
			}
			UNLOCK(&rwl->lock);
			break;
		}

		while (1) {
			int_fast32_t cntflag2 = 0;
			atomic_compare_exchange_strong_explicit
				(&rwl->cnt_and_flag, &cntflag2, WRITER_ACTIVE,
				 memory_order_relaxed, memory_order_relaxed);

			if (cntflag2 == 0)
				break;

			/* Another active reader or writer is working. */
			LOCK(&rwl->lock);
			if (rwl->cnt_and_flag != 0)
				WAIT(&rwl->writeable, &rwl->lock);
			UNLOCK(&rwl->lock);
		}

		INSIST((rwl->cnt_and_flag & WRITER_ACTIVE) != 0);
		rwl->write_granted++;
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_POSTLOCK, "postlock"), rwl, type);
#endif

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_int32_t cnt = 0;
	isc_int32_t max_cnt = rwl->spins * 2 + 10;
	isc_result_t result = ISC_R_SUCCESS;

	if (max_cnt > RWLOCK_MAX_ADAPTIVE_COUNT)
		max_cnt = RWLOCK_MAX_ADAPTIVE_COUNT;

	do {
		if (cnt++ >= max_cnt) {
			result = isc__rwlock_lock(rwl, type);
			break;
		}
#ifdef ISC_PLATFORM_BUSYWAITNOP
		ISC_PLATFORM_BUSYWAITNOP;
#endif
	} while (isc_rwlock_trylock(rwl, type) != ISC_R_SUCCESS);

	rwl->spins += (cnt - rwl->spins) / 8;

	return (result);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_int32_t cntflag;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_PRELOCK, "prelock"), rwl, type);
#endif

	if (type == isc_rwlocktype_read) {
		/* If a writer is waiting or working, we fail. */
		if (rwl->write_requests != rwl->write_completions)
			return (ISC_R_LOCKBUSY);

		/* Otherwise, be ready for reading. */
		cntflag = atomic_fetch_add_explicit(&rwl->cnt_and_flag,
						    READER_INCR,
						    memory_order_relaxed);
		if ((cntflag & WRITER_ACTIVE) != 0) {
			/*
			 * A writer is working.  We lose, and cancel the read
			 * request.
			 */
			cntflag = atomic_fetch_sub_explicit
				(&rwl->cnt_and_flag, READER_INCR,
				 memory_order_relaxed);
			/*
			 * If no other readers are waiting and we've suspended
			 * new writers in this short period, wake them up.
			 */
			if (cntflag == READER_INCR &&
			    rwl->write_completions != rwl->write_requests) {
				LOCK(&rwl->lock);
				BROADCAST(&rwl->writeable);
				UNLOCK(&rwl->lock);
			}

			return (ISC_R_LOCKBUSY);
		}
	} else {
		/* Try locking without entering the waiting queue. */
		int_fast32_t zero = 0;
		if (!atomic_compare_exchange_strong_explicit
		    (&rwl->cnt_and_flag, &zero, WRITER_ACTIVE,
		     memory_order_relaxed, memory_order_relaxed))
			return (ISC_R_LOCKBUSY);

		/*
		 * XXXJT: jump into the queue, possibly breaking the writer
		 * order.
		 */
		atomic_fetch_sub_explicit(&rwl->write_completions, 1,
					  memory_order_relaxed);

		rwl->write_granted++;
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_POSTLOCK, "postlock"), rwl, type);
#endif

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	{
		int_fast32_t reader_incr = READER_INCR;

		/* Try to acquire write access. */
		atomic_compare_exchange_strong_explicit
			(&rwl->cnt_and_flag, &reader_incr, WRITER_ACTIVE,
			 memory_order_relaxed, memory_order_relaxed);
		/*
		 * There must have been no writer, and there must have
		 * been at least one reader.
		 */
		INSIST((reader_incr & WRITER_ACTIVE) == 0 &&
		       (reader_incr & ~WRITER_ACTIVE) != 0);

		if (reader_incr == READER_INCR) {
			/*
			 * We are the only reader and have been upgraded.
			 * Now jump into the head of the writer waiting queue.
			 */
			atomic_fetch_sub_explicit(&rwl->write_completions, 1,
						  memory_order_relaxed);
		} else
			return (ISC_R_LOCKBUSY);

	}

	return (ISC_R_SUCCESS);
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	isc_int32_t prev_readers;

	REQUIRE(VALID_RWLOCK(rwl));

	{
		/* Become an active reader. */
		prev_readers = atomic_fetch_add_explicit(&rwl->cnt_and_flag,
							 READER_INCR,
							 memory_order_relaxed);
		/* We must have been a writer. */
		INSIST((prev_readers & WRITER_ACTIVE) != 0);

		/* Complete write */
		atomic_fetch_sub_explicit(&rwl->cnt_and_flag, WRITER_ACTIVE,
					  memory_order_relaxed);
		atomic_fetch_add_explicit(&rwl->write_completions, 1,
					  memory_order_relaxed);
	}

	/* Resume other readers */
	LOCK(&rwl->lock);
	if (rwl->readers_waiting > 0)
		BROADCAST(&rwl->readable);
	UNLOCK(&rwl->lock);
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_int32_t prev_cnt;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_PREUNLOCK, "preunlock"), rwl, type);
#endif

	if (type == isc_rwlocktype_read) {
		prev_cnt = atomic_fetch_sub_explicit(&rwl->cnt_and_flag,
						     READER_INCR,
						     memory_order_relaxed);
		/*
		 * If we're the last reader and any writers are waiting, wake
		 * them up.  We need to wake up all of them to ensure the
		 * FIFO order.
		 */
		if (prev_cnt == READER_INCR &&
		    rwl->write_completions != rwl->write_requests) {
			LOCK(&rwl->lock);
			BROADCAST(&rwl->writeable);
			UNLOCK(&rwl->lock);
		}
	} else {
		isc_boolean_t wakeup_writers = ISC_TRUE;

		/*
		 * Reset the flag, and (implicitly) tell other writers
		 * we are done.
		 */
		atomic_fetch_sub_explicit(&rwl->cnt_and_flag, WRITER_ACTIVE,
					  memory_order_relaxed);
		atomic_fetch_add_explicit(&rwl->write_completions, 1,
					  memory_order_relaxed);

		if (rwl->write_granted >= rwl->write_quota ||
		    rwl->write_requests == rwl->write_completions ||
		    (rwl->cnt_and_flag & ~WRITER_ACTIVE) != 0) {
			/*
			 * We have passed the write quota, no writer is
			 * waiting, or some readers are almost ready, pending
			 * possible writers.  Note that the last case can
			 * happen even if write_requests != write_completions
			 * (which means a new writer in the queue), so we need
			 * to catch the case explicitly.
			 */
			LOCK(&rwl->lock);
			if (rwl->readers_waiting > 0) {
				wakeup_writers = ISC_FALSE;
				BROADCAST(&rwl->readable);
			}
			UNLOCK(&rwl->lock);
		}

		if (rwl->write_requests != rwl->write_completions &&
		    wakeup_writers) {
			LOCK(&rwl->lock);
			BROADCAST(&rwl->writeable);
			UNLOCK(&rwl->lock);
		}
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock(isc_msgcat_get(isc_msgcat, ISC_MSGSET_RWLOCK,
				  ISC_MSG_POSTUNLOCK, "postunlock"),
		   rwl, type);
#endif

	return (ISC_R_SUCCESS);
}

#else /* ISC_PLATFORM_USETHREADS */

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota)
{
	REQUIRE(rwl != NULL);

	UNUSED(read_quota);
	UNUSED(write_quota);

	rwl->type = isc_rwlocktype_read;
	rwl->active = 0;
	rwl->magic = RWLOCK_MAGIC;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	if (type == isc_rwlocktype_read) {
		if (rwl->type != isc_rwlocktype_read && rwl->active != 0)
			return (ISC_R_LOCKBUSY);
		rwl->type = isc_rwlocktype_read;
		rwl->active++;
	} else {
		if (rwl->active != 0)
			return (ISC_R_LOCKBUSY);
		rwl->type = isc_rwlocktype_write;
		rwl->active = 1;
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	return (isc_rwlock_lock(rwl, type));
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_RWLOCK(rwl));
	REQUIRE(rwl->type == isc_rwlocktype_read);
	REQUIRE(rwl->active != 0);

	/* If we are the only reader then succeed. */
	if (rwl->active == 1)
		rwl->type = isc_rwlocktype_write;
	else
		result = ISC_R_LOCKBUSY;
	return (result);
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {

	REQUIRE(VALID_RWLOCK(rwl));
	REQUIRE(rwl->type == isc_rwlocktype_write);
	REQUIRE(rwl->active == 1);

	rwl->type = isc_rwlocktype_read;
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));
	REQUIRE(rwl->type == type);

	UNUSED(type);

	INSIST(rwl->active > 0);
	rwl->active--;

	return (ISC_R_SUCCESS);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	REQUIRE(rwl != NULL);
	REQUIRE(rwl->active == 0);
	rwl->magic = 0;
}

#endif /* ISC_PLATFORM_USETHREADS */
