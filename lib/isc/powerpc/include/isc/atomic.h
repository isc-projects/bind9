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


#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <inttypes.h>

#include <isc/platform.h>
#include <isc/types.h>

/*!\file
 * static inline int32_t
 * isc_atomic_xadd(int32_t *p, int32_t val);
 *
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 *
 * static inline void
 * isc_atomic_store(void *p, int32_t val);
 *
 * This routine atomically stores the value 'val' in 'p'.
 *
 * static inline int32_t
 * isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val);
 *
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */

#if defined(ISC_PLATFORM_USEGCCASM) || defined(ISC_PLATFORM_USEMACASM)
static inline int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	int32_t orig;

	__asm__ volatile (
#ifdef ISC_PLATFORM_USEMACASM
		"1:"
		"lwarx r6, 0, %1\n"
		"mr %0, r6\n"
		"add r6, r6, %2\n"
		"stwcx. r6, 0, %1\n"
		"bne- 1b\n"
		"sync"
#else
		"1:"
		"lwarx 6, 0, %1\n"
		"mr %0, 6\n"
		"add 6, 6, %2\n"
		"stwcx. 6, 0, %1\n"
		"bne- 1b\n"
		"sync"
#endif
		: "=&r"(orig)
		: "r"(p), "r"(val)
		: "r6", "memory"
		);

	return (orig);
}

static inline void
isc_atomic_store(void *p, int32_t val) {
	__asm__ volatile (
#ifdef ISC_PLATFORM_USEMACASM
		"1:"
		"lwarx r6, 0, %0\n"
		"lwz r6, %1\n"
		"stwcx. r6, 0, %0\n"
		"bne- 1b\n"
		"sync"
#else
		"1:"
		"lwarx 6, 0, %0\n"
		"lwz 6, %1\n"
		"stwcx. 6, 0, %0\n"
		"bne- 1b\n"
		"sync"
#endif
		:
		: "r"(p), "m"(val)
		: "r6", "memory"
		);
}

static inline int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	int32_t orig;

	__asm__ volatile (
#ifdef ISC_PLATFORM_USEMACASM
		"1:"
		"lwarx r6, 0, %1\n"
		"mr %0,r6\n"
		"cmpw r6, %2\n"
		"bne 2f\n"
		"mr r6, %3\n"
		"stwcx. r6, 0, %1\n"
		"bne- 1b\n"
		"2:\n"
		"sync"
#else
		"1:"
		"lwarx 6, 0, %1\n"
		"mr %0,6\n"
		"cmpw 6, %2\n"
		"bne 2f\n"
		"mr 6, %3\n"
		"stwcx. 6, 0, %1\n"
		"bne- 1b\n"
		"2:\n"
		"sync"
#endif
		: "=&r" (orig)
		: "r"(p), "r"(cmpval), "r"(val)
		: "r6", "memory"
		);

	return (orig);
}

#else

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif
#endif /* ISC_ATOMIC_H */
