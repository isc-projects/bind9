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

#if !defined(_WIN32)

#if HAVE_STDATOMIC_H
#include <stdatomic.h>
#else /* HAVE_STDATOMIC_H */
#include <isc/stdatomic.h>
#endif /* HAVE_STDATOMIC_H */

#else /* !defined(_WIN32) */

/* Windows implementation */

#define WIN32_LEAN_AND_MEAN
#include <stddef.h>
#include <stdint.h>
#include <windows.h>

typedef intptr_t atomic_bool;
typedef intptr_t atomic_char;
typedef intptr_t atomic_schar;
typedef intptr_t atomic_uchar;
typedef intptr_t atomic_short;
typedef intptr_t atomic_uschor;
typedef intptr_t atomic_int;
typedef intptr_t atomic_uint;
typedef intptr_t atomic_long;
typedef intptr_t atomic_ulong;
typedef intptr_t atomic_llong;
typedef intptr_t atomic_ullong;
typedef intptr_t atomic_char16_t;
typedef intptr_t atomic_char32_t;
typedef intptr_t atomic_wchar_t;
typedef intptr_t atomic_int_least8_t;
typedef intptr_t atomic_uint_least8_t;
typedef intptr_t atomic_int_least16_t;
typedef intptr_t atomic_uint_least16_t;
typedef intptr_t atomic_int_least32_t;
typedef intptr_t atomic_uint_least32_t;
typedef intptr_t atomic_int_least64_t;
typedef intptr_t atomic_uint_least64_t;
typedef intptr_t atomic_int_fast8_t;
typedef intptr_t atomic_uint_fast8_t;
typedef intptr_t atomic_int_fast16_t;
typedef intptr_t atomic_uint_fast16_t;
typedef intptr_t atomic_int_fast32_t;
typedef intptr_t atomic_uint_fast32_t;
typedef intptr_t atomic_int_fast64_t;
typedef intptr_t atomic_uint_fast64_t;
typedef intptr_t atomic_intptr_t;
typedef intptr_t atomic_uintptr_t;
typedef intptr_t atomic_size_t;
typedef intptr_t atomic_ptrdiff_t;
typedef intptr_t atomic_intmax_t;
typedef intptr_t atomic_uintmax_t;

#define atomic_init(obj, desired)		\
	do {					\
		*(obj) = (desired);		\
	} while(0)

#define atomic_store(obj, desired)	 	\
	do {					\
		*(obj) = (desired);		\
		MemoryBarrier();		\
	} while (0)

#define atomic_load(obj)			\
	(MemoryBarrier(), *(obj))

#define atomic_exchange(obj, desired)	\
	InterlockedExchangePointer(obj, desired)

static inline bool
atomic_compare_exchange_strong(intptr_t *obj, intptr_t *expected, intptr_t desired) {  \
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

#define atomic_fetch_or(obj, arg) \
	InterlockedOr64(obj, arg)

#define atomic_fetch_xor(obj, arg) \
	InterlockedXor64(obj, arg)

#define atomic_fetch_and(obj, arg) \
	InterlockedAnd64(obj, arg)
#else /* _WIN64 */
#define atomic_fetch_add(obj, arg) \
	InterlockedExchangeAdd(obj, arg)

#define atomic_fetch_sub(obj, arg) \
	InterlockedExchangeAdd(obj, -(arg))

#define atomic_fetch_or(obj, arg) \
	InterlockedOr(obj, arg)

#define atomic_fetch_xor(obj, arg) \
	InterlockedXor(obj, arg)

#define atomic_fetch_and(obj, arg) \
	InterlockedAnd(obj, arg)
#endif /* _WIN64 */

#define atomic_store_explicit(obj, desired, order)	\
	atomic_store(obj, desired)
#define atomic_load_explicit(obj, order)		\
	atomic_load(obj)
#define atomic_exchange_explicit(obj, desired, order)	\
	atomic_exchange(obj,desired)
#define atomic_fetch_add_explicit(obj, arg, order)	\
	atomic_fetch_add(obj, arg)
#define atomic_fetch_sub_explicit(obj, arg, order)	\
	atomic_fetch_sub(obj, arg)
#define atomic_fetch_or_explicit(obj, arg, order)	\
	atomic_fetch_or(obj, arg)
#define atomic_fetch_and_explicit(obj, arg, order)	\
	atomic_fetch_and(obj, arg)
#define atomic_fetch_xor_explicit(obj, arg, order)	\
	atomic_fetch_and_xor(obj, arg)
#define atomic_fetch_nand_explicit(obj, arg)		\
	atomic_fetch_and_nand(obj, arg)
#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_strong(obj, expected, desired)
#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_weak(obj, expected, desired)

#endif /* !defined(_WIN32) */
