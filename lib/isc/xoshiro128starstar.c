/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

#include <stdint.h>

/* This is xoshiro128** 1.0, our 32-bit all-purpose, rock-solid generator. It
   has excellent (sub-ns) speed, a state size (128 bits) that is large
   enough for mild parallelism, and it passes all tests we are aware of.

   For generating just single-precision (i.e., 32-bit) floating-point
   numbers, xoshiro128+ is even faster.

   The state must be seeded so that it is not everywhere zero. */

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
static volatile HANDLE _mtx = NULL;

/*
 * Initialize the mutex on the first lock attempt. On collision, each thread
 * will attempt to allocate a mutex and compare-and-swap it into place as the
 * global mutex. On failure to swap in the global mutex, the mutex is closed.
 */
#define _LOCK() { \
	if (!_mtx) { \
		HANDLE p = CreateMutex(NULL, FALSE, NULL); \
		if (InterlockedCompareExchangePointer((void **)&_mtx, (void *)p, NULL)) \
			CloseHandle(p); \
	} \
	WaitForSingleObject(_mtx, INFINITE); \
}

#define _ARC4_UNLOCK() ReleaseMutex(arc4random_mtx)

#else /* defined(_WIN32) || defined(_WIN64) */

#include <pthread.h>
static pthread_mutex_t _mtx = PTHREAD_MUTEX_INITIALIZER;
#define _LOCK()   pthread_mutex_lock(&_mtx)
#define _UNLOCK() pthread_mutex_unlock(&_mtx)
#endif /* defined(_WIN32) || defined(_WIN64) */

static inline uint32_t rotl(const uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}

static uint32_t seed[4];

static inline uint32_t
next(void) {
	_LOCK();

	const uint32_t result_starstar = rotl(seed[0] * 5, 7) * 9;

	const uint32_t t = seed[1] << 9;

	seed[2] ^= seed[0];
	seed[3] ^= seed[1];
	seed[1] ^= seed[2];
	seed[0] ^= seed[3];

	seed[2] ^= t;

	seed[3] = rotl(seed[3], 11);

	_UNLOCK();

	return result_starstar;
}
