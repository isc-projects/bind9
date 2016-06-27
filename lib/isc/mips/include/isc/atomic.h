/*
 * Copyright (C) 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: atomic.h,v 1.3 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <isc/platform.h>
#include <isc/types.h>

#ifdef ISC_PLATFORM_USEGCCASM
/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 */
static inline isc_int32_t
isc_atomic_xadd(isc_int32_t *p, int val) {
	isc_int32_t orig;

	/* add is a cheat, since MIPS has no mov instruction */
	__asm__ volatile (
	    "1:"
	    "ll $3, %1\n"
	    "add %0, $0, $3\n"
	    "add $3, $3, %2\n"
	    "sc $3, %1\n"
	    "beq $3, 0, 1b"
	    : "=&r"(orig)
	    : "m"(*p), "r"(val)
	    : "memory", "$3"
		);

	return (orig);
}

/*
 * This routine atomically stores the value 'val' in 'p'.
 */
static inline void
isc_atomic_store(isc_int32_t *p, isc_int32_t val) {
	__asm__ volatile (
	    "1:"
	    "ll $3, %0\n"
	    "add $3, $0, %1\n"
	    "sc $3, %0\n"
	    "beq $3, 0, 1b"
	    :
	    : "m"(*p), "r"(val)
	    : "memory", "$3"
		);
}

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
static inline isc_int32_t
isc_atomic_cmpxchg(isc_int32_t *p, int cmpval, int val) {
	isc_int32_t orig;

	__asm__ volatile(
	    "1:"
	    "ll $3, %1\n"
	    "add %0, $0, $3\n"
	    "bne $3, %2, 2f\n"
	    "add $3, $0, %3\n"
	    "sc $3, %1\n"
	    "beq $3, 0, 1b\n"
	    "2:"
	    : "=&r"(orig)
	    : "m"(*p), "r"(cmpval), "r"(val)
	    : "memory", "$3"
		);

	return (orig);
}

#else /* !ISC_PLATFORM_USEGCCASM */

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif
#endif /* ISC_ATOMIC_H */
