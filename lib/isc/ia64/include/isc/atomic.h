/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <inttypes.h>

#include <isc/platform.h>
#include <isc/types.h>

#ifdef ISC_PLATFORM_USEGCCASM
/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 *
 * Open issue: can 'fetchadd' make the code faster for some particular values
 * (e.g., 1 and -1)?
 */
static inline int32_t
#ifdef __GNUC__
__attribute__ ((unused))
#endif
isc_atomic_xadd(int32_t *p, int32_t val)
{
	int32_t prev, swapped;

	for (prev = *(volatile int32_t *)p; ; prev = swapped) {
		swapped = prev + val;
		__asm__ volatile(
			"mov ar.ccv=%2;;"
			"cmpxchg4.acq %0=%4,%3,ar.ccv"
			: "=r" (swapped), "=m" (*p)
			: "r" (prev), "r" (swapped), "m" (*p)
			: "memory");
		if (swapped == prev)
			break;
	}

	return (prev);
}

/*
 * This routine atomically stores the value 'val' in 'p'.
 */
static inline void
#ifdef __GNUC__
__attribute__ ((unused))
#endif
isc_atomic_store(int32_t *p, int32_t val)
{
	__asm__ volatile(
		"st4.rel %0=%1"
		: "=m" (*p)
		: "r" (val)
		: "memory"
		);
}

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
static inline int32_t
#ifdef __GNUC__
__attribute__ ((unused))
#endif
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val)
{
	int32_t ret;

	__asm__ volatile(
		"mov ar.ccv=%2;;"
		"cmpxchg4.acq %0=%4,%3,ar.ccv"
		: "=r" (ret), "=m" (*p)
		: "r" (cmpval), "r" (val), "m" (*p)
		: "memory");

	return (ret);
}
#else /* !ISC_PLATFORM_USEGCCASM */

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif
#endif /* ISC_ATOMIC_H */
