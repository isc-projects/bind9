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

/*! \file */

#if defined(HAVE_SCHED_H)
#include <sched.h>
#endif /* if defined(HAVE_SCHED_H) */

#if defined(HAVE_CPUSET_H)
#include <sys/cpuset.h>
#include <sys/param.h>
#endif /* if defined(HAVE_CPUSET_H) */

#if defined(HAVE_SYS_PROCSET_H)
#include <sys/processor.h>
#include <sys/procset.h>
#include <sys/types.h>
#endif /* if defined(HAVE_SYS_PROCSET_H) */

#include <stdlib.h>

#include <isc/iterated_hash.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "random_p.h"

#ifndef THREAD_MINSTACKSIZE
#define THREAD_MINSTACKSIZE (1024U * 1024)
#endif /* ifndef THREAD_MINSTACKSIZE */

/*
 * We can't use isc_mem API here, because it's called too early and the
 * isc_mem_debugging flags can be changed later causing mismatch between flags
 * used for isc_mem_get() and isc_mem_put().
 */

struct thread_wrap {
	isc_threadfunc_t func;
	isc_threadarg_t arg;
	isc_threadresult_t result;
	void *jemalloc_enforce_init;
};

static isc_threadresult_t
thread_run(isc_threadarg_t arg) {
	struct thread_wrap *wrap = arg;

	/*
	 * Ensure every thread starts with a malloc() call to prevent memory
	 * bloat caused by a jemalloc quirk.  While this dummy allocation is
	 * not used for anything, free() must not be immediately called for it
	 * so that an optimizing compiler does not strip away such a pair of
	 * malloc() + free() calls altogether, as it would foil the fix.
	 */
	wrap->jemalloc_enforce_init = malloc(8);

	/* Re-seed the random number generator in each thread. */
	isc__random_initialize();

	/* Get a thread-local digest context. */
	isc__iterated_hash_initialize();

	/* Run the main function */
	wrap->result = wrap->func(wrap->arg);

	/* Cleanup */
	isc__iterated_hash_shutdown();

	/* Return the wrapper struct for jemalloc cleanup */
	return (wrap);
}

void
isc_thread_create(isc_threadfunc_t func, isc_threadarg_t arg,
		  isc_thread_t *thread) {
	pthread_attr_t attr;
	struct thread_wrap *wrap = malloc(sizeof(*wrap));
	RUNTIME_CHECK(wrap != NULL);

	*wrap = (struct thread_wrap){
		.func = func,
		.arg = arg,
	};

#if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	size_t stacksize;
#endif /* if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	* defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE) */
	int ret;

	pthread_attr_init(&attr);

#if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	ret = pthread_attr_getstacksize(&attr, &stacksize);
	PTHREADS_RUNTIME_CHECK(pthread_attr_getstacksize, ret);

	if (stacksize < THREAD_MINSTACKSIZE) {
		ret = pthread_attr_setstacksize(&attr, THREAD_MINSTACKSIZE);
		PTHREADS_RUNTIME_CHECK(pthread_attr_setstacksize, ret);
	}
#endif /* if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	* defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE) */

	ret = pthread_create(thread, &attr, thread_run, wrap);
	PTHREADS_RUNTIME_CHECK(pthread_create, ret);

	pthread_attr_destroy(&attr);

	return;
}

void
isc_thread_join(isc_thread_t thread, isc_threadresult_t *result) {
	void *wrap_v;
	int ret = pthread_join(thread, &wrap_v);

	PTHREADS_RUNTIME_CHECK(pthread_join, ret);

	struct thread_wrap *wrap = wrap_v;
	if (result != NULL) {
		*result = wrap->result;
	}
	free(wrap->jemalloc_enforce_init);
	free(wrap);
}

void
isc_thread_setname(isc_thread_t thread, const char *name) {
#if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__)
	/*
	 * macOS has pthread_setname_np but only works on the
	 * current thread so it's not used here
	 */
#if defined(__NetBSD__)
	(void)pthread_setname_np(thread, name, NULL);
#else  /* if defined(__NetBSD__) */
	(void)pthread_setname_np(thread, name);
#endif /* if defined(__NetBSD__) */
#elif defined(HAVE_PTHREAD_SET_NAME_NP)
	(void)pthread_set_name_np(thread, name);
#else  /* if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__) */
	UNUSED(thread);
	UNUSED(name);
#endif /* if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__) */
}

void
isc_thread_yield(void) {
#if defined(HAVE_SCHED_YIELD)
	sched_yield();
#elif defined(HAVE_PTHREAD_YIELD)
	pthread_yield();
#elif defined(HAVE_PTHREAD_YIELD_NP)
	pthread_yield_np();
#endif /* if defined(HAVE_SCHED_YIELD) */
}
