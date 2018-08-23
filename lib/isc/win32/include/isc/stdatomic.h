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

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <stddef.h>
#include <stdint.h>
#include <windows.h>

typedef intptr_t atomic_int_fast32_t;
typedef intptr_t atomic_uint_fast32_t;
typedef intptr_t atomic_int_fast64_t;
typedef intptr_t atomic_uint_fast64_t;

#define atomic_init(obj, desired)		\
	(*(obj) = (desired))

#define atomic_store(obj, desired)	 	\
	do {					\
		*(obj) = (desired);		\
		MemoryBarrier();		\
	} while (0)

#define atomic_load(obj)			\
	(MemoryBarrier(), *(obj))

static inline bool
atomic_compare_exchange_strong(intptr_t *obj, intptr_t *expected, intptr_t desired) {
	intptr_t old = *expected;
	*expected = (intptr_t)InterlockedCompareExchangePointer(
		(PVOID *)obj, (PVOID)desired, (PVOID)old);
	return (*expected == old);
}

#define atomic_compare_exchange_weak(obj, expected, desired) \
	atomic_compare_exchange_strong(obj, expected, desired)

#ifdef _WIN64
#define atomic_fetch_add(obj, arg) \
	InterlockedExchangeAdd64(obj, arg)

#define atomic_fetch_sub(obj, arg) \
	InterlockedExchangeAdd64(obj, -(arg))
#else /* _WIN64 */
#define atomic_fetch_add(obj, arg) \
	InterlockedExchangeAdd(obj, arg)

#define atomic_fetch_sub(obj, arg) \
	InterlockedExchangeAdd(obj, -(arg))
#endif /* _WIN64 */

#define atomic_store_explicit(obj, desired, order)	\
	atomic_store(obj, desired)
#define atomic_load_explicit(obj, order)		\
	atomic_load(obj)
#define atomic_fetch_add_explicit(obj, arg, order)	\
	atomic_fetch_add(obj, arg)
#define atomic_fetch_sub_explicit(obj, arg, order)	\
	atomic_fetch_sub(obj, arg)
#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_strong(obj, expected, desired)
#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_weak(obj, expected, desired)
