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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#ifndef __ATOMIC_RELAXED
#define __ATOMIC_RELAXED        0
#endif
#ifndef __ATOMIC_CONSUME
#define __ATOMIC_CONSUME        1
#endif
#ifndef __ATOMIC_ACQUIRE
#define __ATOMIC_ACQUIRE        2
#endif
#ifndef __ATOMIC_RELEASE
#define __ATOMIC_RELEASE        3
#endif
#ifndef __ATOMIC_ACQ_REL
#define __ATOMIC_ACQ_REL        4
#endif
#ifndef __ATOMIC_SEQ_CST
#define __ATOMIC_SEQ_CST        5
#endif

enum memory_order {
	memory_order_relaxed = __ATOMIC_RELAXED,
	memory_order_consume = __ATOMIC_CONSUME,
	memory_order_acquire = __ATOMIC_ACQUIRE,
	memory_order_release = __ATOMIC_RELEASE,
	memory_order_acq_rel = __ATOMIC_ACQ_REL,
	memory_order_seq_cst = __ATOMIC_SEQ_CST
};

typedef enum memory_order memory_order;

typedef volatile int_fast32_t atomic_int_fast32_t;
typedef volatile uint_fast32_t atomic_uint_fast32_t;
typedef volatile int_fast64_t atomic_int_fast64_t;
typedef volatile uint_fast64_t atomic_uint_fast64_t;

#define atomic_init(obj, desired)		\
	(*(obj) = (desired))

#define atomic_store_explicit32(obj, desired, order) {	\
	switch (order) {				\
	case memory_order_acquire: InterlockedExchangeAcquire(obj, desired); break; \
	case memory_order_relaxed: InterlockedExchangeNoFence(obj, desired); break; \
	default: InterlockedExchange(obj, desired); break; \
	}

#define atomic_store_explicit64(obj, desired, order) {	\
	switch (order) {				\
	case memory_order_acquire: InterlockedExchangeAcquire64(obj, desired); break; \
	case memory_order_relaxed: InterlockedExchangeNoFence64(obj, desired); break; \
	default: InterlockedExchange64(obj, desired); break; \
	}

#define atomic_store_explicit(obj, desired, order) 			\
	switch (sizeof(*obj)) {						\
	case 4: atomic_store_explicit32(obj, desired, order); break;	\
	case 8: atomic_store_explicit64(obj, desired, order); break;	\
	default: INSIST(0);						\
	}

#define atomic_store(obj, desired) \
	atomic_store(obj, desider, memory_order_seq_cst)

#define atomic_load_explicit32(obj, order) {		\
	((order == memory_order_relaxed) ?		\
	InterlockedOrNoFence(obj, 0) :			\
	(order == memory_order_acquire) ?		\
	InterlockedOrAcquire(obj, 0) :			\
	(order == memory_order_release) ?		\
	InterlockedOrRelease(obj, 0) :			\
	InterlockedOr(obj, 0))

#define atomic_load_explicit64(obj, order) {		\
	((order == memory_order_relaxed) ?		\
	InterlockedOrNoFence64(obj, 0) :		\
	(order == memory_order_acquire) ?		\
	InterlockedOrAcquire64(obj, 0) :		\
	(order == memory_order_release) ?		\
	InterlockedOrRelease64(obj, 0) :		\
	InterlockedOr64(obj, 0))

#define atomic_load_explicit(obj, order)		\
	((sizeof(*obj) == 8) ?				\
	atomic_load_explicit64(obj, order) :		\
	sizeof(*obj == 4) ?				\
	atomic_load_explicit32(obj, order) :		\
	INSIST(0))

#define atomic_load(obj)				\
	atomic_load_explicit(obj, memory_order_seq_cst)

#define atomic_fetch_add_explicit32(obj, arg, order)	\
	((order == memory_order_relaxed) ?		\
	InterlockedExchangeAddNoFence(obj, arg) :	\
	(order == memory_order_acquire) ?		\
	InterlockedExchangeAddAcquire(obj, arg) :	\
	(order == memory_order_release) ?		\
	InterlockedExchangeAddRelease(obj, arg) :	\
	InterlockedExchange(obj, arg))

#define atomic_fetch_add_explicit32(obj, arg, order)	\
	((order == memory_order_relaxed) ?		\
	InterlockedExchangeAddNoFence64(obj, arg) :	\
	(order == memory_order_acquire) ?		\
	InterlockedExchangeAddAcquire64(obj, arg) :	\
	(order == memory_order_release) ?		\
	InterlockedExchangeAddRelease64(obj, arg) :	\
	InterlockedExchange64(obj, arg))

#define atomic_fetch_add_explicit(obj, arg, order)	\
	((sizeof(*obj) == 8) ?				\
	atomic_fetch_add_explicit64(obj, arg, order) :	\
	(sizeof(*obj) == 4) ?				\
	atomic_fetch_add_explicit32(obj, arg, order) :	\
	 INSIST(0))

#define atomic_fetch_add(obj, arg)			\
	atomic_fetch_add_explicit(obj, arg, memory_order_seq_cst)

#define atomic_fetch_sub_explicit(obj, arg, order)	\
	atomic_fetch_add_explicit(obj, -arg, order)

#define atomic_fetch_sub(obj, arg)			\
	atomic_fetch_sub_explicit(obj, arg, memory_order_seq_cst)

static inline bool
atomic_compare_exchange_strong32(atomic_int_fast32_t *obj, int32_t *expected, int32_t desired, memory_order succ, memory_order fail) {
	bool __r;
	intptr_t __v;
	REQUIRE(succ == fail);
	switch (succ) {
	case memory_order_relaxed:
		__v = InterlockedCompareExchangeNoFence(obj, desired, *expected);
		break;
	case memory_order_acquire:
		__v = InterlockedCompareExchangeAcquire(obj, desired, *expected);
		break;
	case memory_order_release:
		__v = InterlockedCompareExchangeRelease(obj, desired, *expected);
		break;
	default:
		__v = InterlockedCompareExchange(obj, desired, *expected);
		break;
	}
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

static inline bool
atomic_compare_exchange_strong64(atomic_int_fast64_t *obj, int64_t *expected, int64_t desired, memory_order succ, memory_order fail) {
	bool __r;
	intptr_t __v;
	REQUIRE(succ == fail);
	switch (succ) {
	case memory_order_relaxed:
		__v = InterlockedCompareExchangeNoFence64(obj, desired, *expected);
		break;
	case memory_order_acquire:
		__v = InterlockedCompareExchangeAcquire64(obj, desired, *expected);
		break;
	case memory_order_release:
		__v = InterlockedCompareExchangeRelease64(obj, desired, *expected);
		break;
	default:
		__v = InterlockedCompareExchange64(obj, desired, *expected);
		break;
	}
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
	((sizeof(*obj) == 8) ?						\
	atomic_compare_exchange_strong_explicit64(obj, expected, desired, succ, fail) : \
	(sizeof(*obj) == 4) ?						\
	atomic_compare_exchange_strong_explicit32(obj, expected, desired, succ, fail) : \
	 INSIST(0))

#define atomic_compare_exchange_strong(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_strong_explicit(obj, expected, desired, memory_order_cst_seq, memory_order_cst_seq)

#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail)

#define atomic_compare_exchange_weak(obj, expected, desired, succ, fail) \
	atomic_compare_exchange_weak_explicit(obj, expected, desired, memory_order_cst_seq, memory_order_cst_seq)
