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

struct isc_rwlock {
	pthread_rwlock_t rwlock;
	atomic_bool	 downgrade;
};

#if ISC_TRACK_PTHREADS_OBJECTS

typedef struct isc_rwlock *isc_rwlock_t;
typedef struct isc_rwlock  isc__rwlock_t;

#define isc_rwlock_init(rwl, rq, wq)            \
	{                                       \
		*rwl = malloc(sizeof(**rwl));   \
		isc__rwlock_init(*rwl, rq, wq); \
	}
#define isc_rwlock_lock(rwl, type)    isc__rwlock_lock(*rwl, type)
#define isc_rwlock_trylock(rwl, type) isc___rwlock_trylock(*rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(*rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc___rwlock_tryupgrade(*rwl)
#define isc_rwlock_downgrade(rwl)     isc__rwlock_downgrade(*rwl)
#define isc_rwlock_destroy(rwl)             \
	{                                   \
		isc___rwlock_destroy(*rwl); \
		free(*rwl);                 \
	}

#else /* ISC_TRACK_PTHREADS_OBJECTS */

typedef struct isc_rwlock isc_rwlock_t;
typedef struct isc_rwlock isc__rwlock_t;

#define isc_rwlock_init(rwl, rq, wq)  isc__rwlock_init(rwl, rq, wq)
#define isc_rwlock_lock(rwl, type)    isc__rwlock_lock(rwl, type)
#define isc_rwlock_trylock(rwl, type) isc___rwlock_trylock(rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc___rwlock_tryupgrade(rwl)
#define isc_rwlock_downgrade(rwl)     isc__rwlock_downgrade(rwl)
#define isc_rwlock_destroy(rwl)	      isc__rwlock_destroy(rwl)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

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
#define isc_rwlock_trylock(rwl, type) isc___rwlock_trylock(rwl, type)
#define isc_rwlock_unlock(rwl, type)  isc__rwlock_unlock(rwl, type)
#define isc_rwlock_tryupgrade(rwl)    isc___rwlock_tryupgrade(rwl)
#define isc_rwlock_downgrade(rwl)     isc__rwlock_downgrade(rwl)
#define isc_rwlock_destroy(rwl)	      isc__rwlock_destroy(rwl)

#endif /* USE_PTHREAD_RWLOCK */

#define isc__rwlock_init(rwl, rq, wq)                      \
	{                                                  \
		int _ret = isc___rwlock_init(rwl, rq, wq); \
		ERRNO_CHECK(isc___rwlock_init, _ret);      \
	}

#define isc__rwlock_lock(rwl, type)                      \
	{                                                \
		int _ret = isc___rwlock_lock(rwl, type); \
		ERRNO_CHECK(isc___rwlock_lock, _ret);    \
	}

#define isc__rwlock_unlock(rwl, type)                      \
	{                                                  \
		int _ret = isc___rwlock_unlock(rwl, type); \
		ERRNO_CHECK(isc___rwlock_unlock, _ret);    \
	}

#define isc__rwlock_downgrade(rwl)                         \
	{                                                  \
		int _ret = isc___rwlock_downgrade(rwl);    \
		ERRNO_CHECK(isc___rwlock_downgrade, _ret); \
	}

#define isc__rwlock_destroy(rwl)                         \
	{                                                \
		int _ret = isc___rwlock_destroy(rwl);    \
		ERRNO_CHECK(isc___rwlock_destroy, _ret); \
	}

int
isc___rwlock_init(isc__rwlock_t *rwl, unsigned int read_quota,
		  unsigned int write_quota);

int
isc___rwlock_lock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc___rwlock_trylock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

int
isc___rwlock_unlock(isc__rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc___rwlock_tryupgrade(isc__rwlock_t *rwl);

int
isc___rwlock_downgrade(isc__rwlock_t *rwl);

int
isc___rwlock_destroy(isc__rwlock_t *rwl);

ISC_LANG_ENDDECLS
