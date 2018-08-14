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

#if !HAVE_STDATOMIC_H
#include <stdbool.h>
#include <inttypes.h>

typedef bool atomic_bool;
typedef char atomic_char;
typedef signed char atomic_schar;
typedef unsigned char atomic_uchar;
typedef short atomic_short;
typedef unsigned short atomic_uschor;
typedef int atomic_int;
typedef unsigned int atomic_uint;
typedef long atomic_long;
typedef unsigned long atomic_ulong;
typedef long long atomic_llong;
typedef unsigned long long atomic_ullong;
typedef uint_least16_t atomic_char16_t;
typedef uint_least32_t atomic_char32_t;
typedef int_least8_t atomic_int_least8_t;
typedef uint_least8_t atomic_uint_least8_t;
typedef int_least16_t atomic_int_least16_t;
typedef uint_least16_t atomic_uint_least16_t;
typedef int_least32_t atomic_int_least32_t;
typedef uint_least32_t atomic_uint_least32_t;
typedef int_least64_t atomic_int_least64_t;
typedef uint_least64_t atomic_uint_least64_t;
typedef int_fast8_t atomic_int_fast8_t;
typedef uint_fast8_t atomic_uint_fast8_t;
typedef int_fast16_t atomic_int_fast16_t;
typedef uint_fast16_t atomic_uint_fast16_t;
typedef int_fast32_t atomic_int_fast32_t;
typedef uint_fast32_t atomic_uint_fast32_t;
typedef int_fast64_t atomic_int_fast64_t;
typedef uint_fast64_t atomic_uint_fast64_t;
typedef intptr_t atomic_intptr_t;
typedef uintptr_t atomic_uintptr_t;
typedef size_t atomic_size_t;
typedef intmax_t atomic_intmax_t;
typedef uintmax_t atomic_uintmax_t;
#endif

#if HAVE_STDATOMIC_H

#include <stdatomic.h>

#elif HAVE___ATOMIC

enum memory_order {
	memory_order_relaxed = __ATOMIC_RELAXED,
	memory_order_consume = __ATOMIC_CONSUME,
	memory_order_acquire = __ATOMIC_ACQUIRE,
	memory_order_release = __ATOMIC_RELEASE,
	memory_order_acq_rel = __ATOMIC_ACQ_REL,
	memory_order_seq_cst = __ATOMIC_SEQ_CST
};

#define atomic_init(obj, desired)			\
	__atomic_store_n(obj, desired, __ATOMIC_SEQ_CST)

#define atomic_store(obj, desired)			\
	__atomic_store_n(obj, desired, __ATOMIC_SEQ_CST)

#define atomic_store_explicit(obj, desired, order)	\
	__atomic_store_n(obj, desired, order)

#define atomic_load(obj)				\
	__atomic_load_n(obj, __ATOMIC_SEQ_CST)

#define atomic_load_explicit(obj, order)		\
	__atomic_load_n(obj, order)

#define atomic_fetch_add(obj, arg)			\
	__atomic_fetch_add(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_add_explicit(obj, arg, order)	\
	__atomic_fetch_add(obj, arg, order)

#define atomic_fetch_sub(obj, arg)			\
	__atomic_fetch_sub(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_sub_explicit(obj, arg, order)	\
	__atomic_fetch_sub(obj, arg, order)

#define atomic_fetch_or(obj, arg)			\
	__atomic_fetch_or(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_or_explicit(obj, arg, order)	\
	__atomic_fetch_or(obj, arg, order)

#define atomic_fetch_and(obj, arg)			\
	__atomic_fetch_and(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_and_explicit(obj, arg, order)	\
	__atomic_fetch_and(obj, arg, order)

#define atomic_fetch_xor(obj, arg)			\
	__atomic_fetch_xor(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_xor_explicit(obj, arg, order)	\
	__atomic_fetch_xor(obj, arg, order)

#define atomic_fetch_nand(obj, arg)			\
	__atomic_fetch_nand(obj, arg, __ATOMIC_SEQ_CST)

#define atomic_fetch_nand_explicit(obj, arg, order)	\
	__atomic_fetch_nand(obj, arg, order)

#define atomic_compare_exchange_strong(obj, expected, desired)		\
	__atomic_compare_exchange_n(obj, expected, desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
	__atomic_compare_exchange_n(obj, expected, desired, false, succ, fail)

#define atomic_compare_exchange_weak(obj, expected, desired)		\
	__atomic_compare_exchange_n(obj, expected, desired, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
	__atomic_compare_exchange_n(obj, expected, desired, true, succ, fail)

#else

enum memory_order {
	memory_order_relaxed = 0,
	memory_order_consume = 0,
	memory_order_acquire = 0,
	memory_order_release = 0,
	memory_order_acq_rel = 0,
	memory_order_seq_cst = 0
};

#define atomic_init(obj, desired)			\
	(*obj = desired)

#define atomic_store(obj, desired)			\
	(*obj = desired)

#define atomic_load(obj) \
	(*obj)

#define atomic_fetch_add(obj, arg)			\
	__sync_fetch_and_add(obj, arg)

#define atomic_fetch_sub(obj, arg)			\
	__sync_fetch_and_sub(obj, arg)

#define atomic_fetch_or(obj, arg)			\
	__sync_fetch_and_or(obj, arg)

#define atomic_fetch_and(obj, arg)			\
	__sync_fetch_and_and(obj, arg)

#define atomic_fetch_xor(obj, arg)			\
	__sync_fetch_and_xor(obj, arg)

#define atomic_fetch_nand(obj, arg)			\
	__sync_fetch_and_nand(obj, arg)

#define atomic_compare_exchange_strong(obj, expected, desired)			\
	__sync_val_compare_and_swap(obj, *expected, desired)

#define atomic_compare_exchange_weak(obj, expected, desired)			\
	__sync_val_compare_and_swap(obj, *expected, desired)

#endif

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

static inline int
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

#endif /* !defined(_WIN32) */

#if defined(_WIN32) || (!HAVE_STDATOMIC_H && !HAVE___ATOMIC)

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

#endif /* defined(_WIN32) || HAVE_NO__ATOMIC */
