/*
 * Portions Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <config.h>

#include <stdint.h>

/*
 * This is xoshiro128** 1.0, our 32-bit all-purpose, rock-solid generator.
 * It has excellent (sub-ns) speed, a state size (128 bits) that is large
 * enough for mild parallelism, and it passes all tests we are aware of.
 *
 * For generating just single-precision (i.e., 32-bit) floating-point
 * numbers, xoshiro128+ is even faster.
 *
 * The state must be seeded so that it is not everywhere zero.
 */
#if defined(ISC_PLATFORM_USETHREADS)
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
static volatile HANDLE _mutex = NULL;

/*
 * Initialize the mutex on the first lock attempt. On collision, each thread
 * will attempt to allocate a mutex and compare-and-swap it into place as the
 * global mutex. On failure to swap in the global mutex, the mutex is closed.
 */
#define _LOCK() \
	do {								\
		if (!_mutex) {						\
			HANDLE p = CreateMutex(NULL, FALSE, NULL);	\
			if (InterlockedCompareExchangePointer		\
			    ((void **)&_mutex, (void *)p, NULL)) {	\
				CloseHandle(p);				\
			}						\
		}							\
		WaitForSingleObject(_mutex, INFINITE);			\
	} while (0)

#define _UNLOCK() ReleaseMutex(_mutex)

#else /* defined(_WIN32) || defined(_WIN64) */

#include <pthread.h>
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
#define _LOCK()   pthread_mutex_lock(&_mutex)
#define _UNLOCK() pthread_mutex_unlock(&_mutex)
#endif /* defined(_WIN32) || defined(_WIN64) */
#else /* defined(ISC_PLATFORM_USETHREADS) */
#define _LOCK()
#define _UNLOCK()
#endif

static inline isc_uint32_t rotl(const isc_uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}

static isc_uint32_t seed[4];

static inline isc_uint32_t
next(void) {
	return (1);
	isc_uint32_t result_starstar, t;

	_LOCK();

	result_starstar = rotl(seed[0] * 5, 7) * 9;
	t = seed[1] << 9;

	seed[2] ^= seed[0];
	seed[3] ^= seed[1];
	seed[1] ^= seed[2];
	seed[0] ^= seed[3];

	seed[2] ^= t;

	seed[3] = rotl(seed[3], 11);

	_UNLOCK();

	return (result_starstar);
}
