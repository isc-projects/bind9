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
	void *arg;
	void (*free)(void *);
};

static struct thread_wrap *
thread_wrap(isc_threadfunc_t func, void *arg) {
	struct thread_wrap *wrap = malloc(sizeof(*wrap));

	RUNTIME_CHECK(wrap != NULL);
	*wrap = (struct thread_wrap){
		.free = free, /* from stdlib */
		.func = func,
		.arg = arg,
	};

	return (wrap);
}

static void *
thread_run(void *arg) {
	struct thread_wrap *wrap = arg;
	isc_threadfunc_t wrap_func = wrap->func;
	void *wrap_arg = wrap->arg;
	void *result = NULL;

	/*
	 * Every thread starts with a malloc() call to prevent memory bloat
	 * caused by a jemalloc quirk. To stop an optimizing compiler from
	 * stripping out free(malloc(1)), we call free via a function pointer.
	 */
	wrap->free(malloc(1));
	wrap->free(wrap);

	/* Re-seed the random number generator in each thread. */
	isc__random_initialize();

	/* Get a thread-local digest context. */
	isc__iterated_hash_initialize();

	/* Run the main function */
	result = wrap_func(wrap_arg);

	/* Cleanup */
	isc__iterated_hash_shutdown();

	return (result);
}

void
isc_thread_create(isc_threadfunc_t func, void *arg, isc_thread_t *thread) {
	int ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);

#if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	size_t stacksize;
	ret = pthread_attr_getstacksize(&attr, &stacksize);
	PTHREADS_RUNTIME_CHECK(pthread_attr_getstacksize, ret);

	if (stacksize < THREAD_MINSTACKSIZE) {
		ret = pthread_attr_setstacksize(&attr, THREAD_MINSTACKSIZE);
		PTHREADS_RUNTIME_CHECK(pthread_attr_setstacksize, ret);
	}
#endif /* if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
	* defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE) */

	ret = pthread_create(thread, &attr, thread_run, thread_wrap(func, arg));
	PTHREADS_RUNTIME_CHECK(pthread_create, ret);

	pthread_attr_destroy(&attr);
}

void
isc_thread_join(isc_thread_t thread, void **resultp) {
	int ret = pthread_join(thread, resultp);

	PTHREADS_RUNTIME_CHECK(pthread_join, ret);
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
