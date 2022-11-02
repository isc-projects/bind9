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
#include <stdlib.h>

/*! \file isc/rwlock.h */

#include <isc/atomic.h>
#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/types.h>
#include <isc/util.h>

ISC_LANG_BEGINDECLS

typedef enum {
	isc_rwlocktype_none = 0,
	isc_rwlocktype_read,
	isc_rwlocktype_write
} isc_rwlocktype_t;

#if USE_PTHREAD_RWLOCK
#include <pthread.h>

/*
 * We use macros instead of static inline functions so that the exact code
 * location can be reported when PTHREADS_RUNTIME_CHECK() fails or when mutrace
 * reports lock contention.
 */

#if ISC_TRACK_PTHREADS_OBJECTS

typedef pthread_rwlock_t *isc_rwlock_t;
typedef pthread_rwlock_t  isc__rwlock_t;

#define isc_rwlock_init(rwl, rq, wq)            \
	{                                       \
		*rwl = malloc(sizeof(**rwl));   \
		isc__rwlock_init(*rwl, rq, wq); \
	}
#define isc_rwlock_lock(rwl, type)    isc__rwlock_lock(*rwl, type)
#define isc_rwlock_trylock(rwl, type) isc__rwlock_trylock(*rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(*rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc__rwlock_tryupgrade(*rwl)
#define isc_rwlock_destroy(rwl)            \
	{                                  \
		isc__rwlock_destroy(*rwl); \
		free(*rwl);                \
	}

#else /* ISC_TRACK_PTHREADS_OBJECTS */

typedef pthread_rwlock_t isc_rwlock_t;
typedef pthread_rwlock_t isc__rwlock_t;

#define isc_rwlock_init(rwl, rq, wq)  isc__rwlock_init(rwl, rq, wq)
#define isc_rwlock_lock(rwl, type)    isc__rwlock_lock(rwl, type)
#define isc_rwlock_trylock(rwl, type) isc__rwlock_trylock(rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc__rwlock_tryupgrade(rwl)
#define isc_rwlock_destroy(rwl)	      isc__rwlock_destroy(rwl)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__rwlock_init(rwl, read_quota, write_quote)             \
	{                                                          \
		int _ret = pthread_rwlock_init(rwl, NULL);         \
		PTHREADS_RUNTIME_CHECK(pthread_rwlock_init, _ret); \
	}

#define isc__rwlock_lock(rwl, type)                                          \
	{                                                                    \
		int _ret;                                                    \
		switch (type) {                                              \
		case isc_rwlocktype_read:                                    \
			_ret = pthread_rwlock_rdlock(rwl);                   \
			PTHREADS_RUNTIME_CHECK(pthread_rwlock_rdlock, _ret); \
			break;                                               \
		case isc_rwlocktype_write:                                   \
			_ret = pthread_rwlock_wrlock(rwl);                   \
			PTHREADS_RUNTIME_CHECK(pthread_rwlock_rwlock, _ret); \
			break;                                               \
		default:                                                     \
			UNREACHABLE();                                       \
		}                                                            \
	}

#define isc__rwlock_trylock(rwl, type)                                   \
	({                                                               \
		int	     _ret = 0;                                   \
		isc_result_t _res = ISC_R_UNSET;                         \
                                                                         \
		switch (type) {                                          \
		case isc_rwlocktype_read:                                \
			_ret = pthread_rwlock_tryrdlock(rwl);            \
			break;                                           \
		case isc_rwlocktype_write:                               \
			_ret = pthread_rwlock_trywrlock(rwl);            \
			break;                                           \
		default:                                                 \
			UNREACHABLE();                                   \
		}                                                        \
                                                                         \
		switch (_ret) {                                          \
		case 0:                                                  \
			_res = ISC_R_SUCCESS;                            \
			break;                                           \
		case EBUSY:                                              \
		case EAGAIN:                                             \
			_res = ISC_R_LOCKBUSY;                           \
			break;                                           \
		default:                                                 \
			switch (type) {                                  \
			case isc_rwlocktype_read:                        \
				PTHREADS_RUNTIME_CHECK(                  \
					pthread_rwlock_tryrdlock, _ret); \
				break;                                   \
			case isc_rwlocktype_write:                       \
				PTHREADS_RUNTIME_CHECK(                  \
					pthread_rwlock_trywrlock, _ret); \
				break;                                   \
			default:                                         \
				UNREACHABLE();                           \
			}                                                \
			UNREACHABLE();                                   \
		}                                                        \
		_res;                                                    \
	})

#define isc__rwlock_unlock(rwl, type)                                \
	{                                                            \
		int _ret = pthread_rwlock_unlock(rwl);               \
		PTHREADS_RUNTIME_CHECK(pthread_rwlock_rwlock, _ret); \
	}

#define isc__rwlock_tryupgrade(rwl) \
	({                          \
		UNUSED(rwl);        \
		ISC_R_LOCKBUSY;     \
	})

#define isc__rwlock_destroy(rwl)                                      \
	{                                                             \
		int _ret = pthread_rwlock_destroy(rwl);               \
		PTHREADS_RUNTIME_CHECK(pthread_rwlock_destroy, _ret); \
	}

#else /* USE_PTHREAD_RWLOCK */

struct isc_rwlock {
	/* Unlocked. */
	unsigned int	    magic;
	isc_mutex_t	    lock;
	atomic_int_fast32_t spins;

	/*
	 * When some atomic instructions with hardware assistance are
	 * available, rwlock will use those so that concurrent readers do not
	 * interfere with each other through mutex as long as no writers
	 * appear, massively reducing the lock overhead in the typical case.
	 *
	 * The basic algorithm of this approach is the "simple
	 * writer-preference lock" shown in the following URL:
	 * http://www.cs.rochester.edu/u/scott/synchronization/pseudocode/rw.html
	 * but our implementation does not rely on the spin lock unlike the
	 * original algorithm to be more portable as a user space application.
	 */

	/* Read or modified atomically. */
	atomic_int_fast32_t write_requests;
	atomic_int_fast32_t write_completions;
	atomic_int_fast32_t cnt_and_flag;

	/* Locked by lock. */
	isc_condition_t readable;
	isc_condition_t writeable;
	unsigned int	readers_waiting;

	/* Locked by rwlock itself. */
	atomic_uint_fast32_t write_granted;

	/* Unlocked. */
	unsigned int write_quota;
};

typedef struct isc_rwlock isc_rwlock_t;
typedef struct isc_rwlock isc__rwlock_t;

#define isc_rwlock_init(rwl, rq, wq)  isc__rwlock_init(rwl, rq, wq)
#define isc_rwlock_lock(rwl, type)    isc__rwlock_lock(rwl, type)
#define isc_rwlock_trylock(rwl, type) isc__rwlock_trylock(rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc__rwlock_tryupgrade(rwl)
#define isc_rwlock_destroy(rwl)	      isc__rwlock_destroy(rwl)

void
isc__rwlock_init(isc__rwlock_t *rwl, unsigned int read_quota,
		 unsigned int write_quota);

void
isc__rwlock_lock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc__rwlock_trylock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

void
isc__rwlock_unlock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc__rwlock_tryupgrade(isc__rwlock_t *rwl);

void
isc__rwlock_destroy(isc__rwlock_t *rwl);

#endif /* USE_PTHREAD_RWLOCK */

ISC_LANG_ENDDECLS
