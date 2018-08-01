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


#ifndef ISC_REFCOUNT_H
#define ISC_REFCOUNT_H 1

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/lang.h>
#include <isc/mutex.h>
#include <isc/platform.h>
#include <isc/types.h>

#include <stdatomic.h>

/*! \file isc/refcount.h
 * \brief Implements a locked reference counter.
 *
 * These functions may actually be
 * implemented using macros, and implementations of these macros are below.
 * The isc_refcount_t type should not be accessed directly, as its contents
 * depend on the implementation.
 */

ISC_LANG_BEGINDECLS

/*
 * Function prototypes
 */

/*
 * void
 * isc_refcount_init(isc_refcount_t *ref, unsigned int n);
 *
 * Initialize the reference counter.  There will be 'n' initial references.
 *
 * Requires:
 *	ref != NULL
 */

/*
 * void
 * isc_refcount_destroy(isc_refcount_t *ref);
 *
 * Destroys a reference counter.
 *
 * Requires:
 *	ref != NULL
 *	The number of references is 0.
 */

/*
 * void
 * isc_refcount_increment(isc_refcount_t *ref, unsigned int *targetp);
 * isc_refcount_increment0(isc_refcount_t *ref, unsigned int *targetp);
 *
 * Increments the reference count, returning the new value in targetp if it's
 * not NULL.  The reference counter typically begins with the initial counter
 * of 1, and will be destroyed once the counter reaches 0.  Thus,
 * isc_refcount_increment() additionally requires the previous counter be
 * larger than 0 so that an error which violates the usage can be easily
 * caught.  isc_refcount_increment0() does not have this restriction.
 *
 * Requires:
 *	ref != NULL.
 */

/*
 * void
 * isc_refcount_decrement(isc_refcount_t *ref, unsigned int *targetp);
 *
 * Decrements the reference count,  returning the new value in targetp if it's
 * not NULL.
 *
 * Requires:
 *	ref != NULL.
 */


/*
 * Sample implementations
 */

typedef atomic_int_fast32_t isc_refcount_t;

#define isc_refcount_init(rp, n) atomic_init(rp, n)

#define isc_refcount_current(rp)					\
	((unsigned int)(atomic_load_explicit(rp,			\
					     memory_order_acquire)))

#define isc_refcount_destroy(rp)				\
	do {							\
		atomic_thread_fence(memory_order_acquire);	\
		ISC_REQUIRE(isc_refcount_current(rp) == 0);	\
	} while (0)

#define isc_refcount_increment0(rp, tp)				\
	do {							\
		unsigned int *_tmp = (unsigned int *)(tp);	\
		isc_int32_t prev;				\
		prev = atomic_fetch_add_explicit		\
			(rp, 1, memory_order_relaxed); \
		if (_tmp != NULL)				\
			*_tmp = prev + 1;			\
	} while (0)

#define isc_refcount_increment(rp, tp)				\
	do {							\
		unsigned int *_tmp = (unsigned int *)(tp);	\
		isc_int32_t prev;				\
		prev = atomic_fetch_add_explicit		\
			(rp, 1, memory_order_relaxed); \
		ISC_REQUIRE(prev > 0);				\
		if (_tmp != NULL)				\
			*_tmp = prev + 1;			\
	} while (0)

#define isc_refcount_decrement(rp, tp)				\
	do {							\
		unsigned int *_tmp = (unsigned int *)(tp);	\
		isc_int32_t prev;				\
		prev = atomic_fetch_sub_explicit		\
			(rp, 1, memory_order_release); \
		ISC_REQUIRE(prev > 0);				\
		if (_tmp != NULL)				\
			*_tmp = prev - 1;			\
	} while (0)

ISC_LANG_ENDDECLS

#endif /* ISC_REFCOUNT_H */
