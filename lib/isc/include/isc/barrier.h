/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/util.h>

#if __SANITIZE_THREAD__

#include <pthread.h>

#define isc_barrier_t pthread_barrier_t

#define isc_barrier_init(barrier, count) \
	pthread_barrier_init(barrier, NULL, count)
#define isc_barrier_destroy(barrier) pthread_barrier_destroy(barrier)
#define isc_barrier_wait(barrier)    pthread_barrier_wait(barrier)

#else /* __SANITIZE_THREAD__ */

#include <isc/uv.h>

#if ISC_TRACK_PTHREADS_OBJECTS

typedef uv_barrier_t *isc_barrier_t;

#define isc_barrier_init(bp, count)            \
	{                                      \
		*bp = malloc(sizeof(**bp));    \
		isc__barrier_init(*bp, count); \
	}
#define isc_barrier_wait(bp) isc__barrier_wait(*bp)
#define isc_barrier_destroy(bp)            \
	{                                  \
		isc__barrier_destroy(*bp); \
		free(*bp);                 \
	}

#else /* ISC_TRACK_PTHREADS_OBJECTS */

typedef uv_barrier_t isc_barrier_t;

#define isc_barrier_init(bp, count) isc__barrier_init(bp, count)
#define isc_barrier_wait(bp)	    isc__barrier_wait(bp)
#define isc_barrier_destroy(bp)	    isc__barrier_destroy(bp)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__barrier_init(bp, count)                     \
	{                                                \
		int _ret = uv_barrier_init(bp, count);   \
		UV_RUNTIME_CHECK(uv_barrier_init, _ret); \
	}

#define isc__barrier_wait(bp) uv_barrier_wait(bp)

#define isc__barrier_destroy(bp) uv_barrier_destroy(bp)

#endif /* __SANITIZE_THREAD__ */
