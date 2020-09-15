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

/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 */
#ifdef ISC_PLATFORM_HAVEXADD
static __inline int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	return (int32_t) _InterlockedExchangeAdd((long *)p, (long)val);
}
#endif

#ifdef ISC_PLATFORM_HAVEXADDQ
static __inline int64_t
isc_atomic_xaddq(int64_t *p, int64_t val) {
	return (int64_t) _InterlockedExchangeAdd64((__int64 *)p,
						       (__int64) val);
}
#endif

/*
 * This routine atomically stores the value 'val' in 'p' (32-bit version).
 */
#ifdef ISC_PLATFORM_HAVEATOMICSTORE
static __inline void
isc_atomic_store(int32_t *p, int32_t val) {
	(void) _InterlockedExchange((long *)p, (long)val);
}
#endif

/*
 * This routine atomically stores the value 'val' in 'p' (64-bit version).
 */
#ifdef ISC_PLATFORM_HAVEATOMICSTOREQ
static __inline void
isc_atomic_storeq(int64_t *p, int64_t val) {
	(void) _InterlockedExchange64((__int64 *)p, (__int64)val);
}
#endif

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
#ifdef ISC_PLATFORM_HAVECMPXCHG
static __inline int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	/* beware: swap arguments */
	return (int32_t) _InterlockedCompareExchange((long *)p,
							 (long)val,
							 (long)cmpval);
}
#endif

#endif /* ISC_ATOMIC_H */
