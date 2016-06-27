/*
 * Copyright (C) 2000, 2001, 2003-2005, 2007, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: thread.c,v 1.17 2007/06/19 23:47:18 tbox Exp $ */

/*! \file */

#include <config.h>

#if defined(HAVE_SCHED_H)
#include <sched.h>
#endif

#include <isc/thread.h>
#include <isc/util.h>

#ifndef THREAD_MINSTACKSIZE
#define THREAD_MINSTACKSIZE		(1024U * 1024)
#endif

isc_result_t
isc_thread_create(isc_threadfunc_t func, isc_threadarg_t arg,
		  isc_thread_t *thread)
{
	pthread_attr_t attr;
	size_t stacksize;
	int ret;

	pthread_attr_init(&attr);

#if defined(HAVE_PTHREAD_ATTR_GETSTACKSIZE) && \
    defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	ret = pthread_attr_getstacksize(&attr, &stacksize);
	if (ret != 0)
		return (ISC_R_UNEXPECTED);

	if (stacksize < THREAD_MINSTACKSIZE) {
		ret = pthread_attr_setstacksize(&attr, THREAD_MINSTACKSIZE);
		if (ret != 0)
			return (ISC_R_UNEXPECTED);
	}
#endif

#if defined(PTHREAD_SCOPE_SYSTEM) && defined(NEED_PTHREAD_SCOPE_SYSTEM)
	ret = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	if (ret != 0)
		return (ISC_R_UNEXPECTED);
#endif

	ret = pthread_create(thread, &attr, func, arg);
	if (ret != 0)
		return (ISC_R_UNEXPECTED);

	pthread_attr_destroy(&attr);

	return (ISC_R_SUCCESS);
}

void
isc_thread_setconcurrency(unsigned int level) {
#if defined(CALL_PTHREAD_SETCONCURRENCY)
	(void)pthread_setconcurrency(level);
#else
	UNUSED(level);
#endif
}

void
isc_thread_yield(void) {
#if defined(HAVE_SCHED_YIELD)
	sched_yield();
#elif defined( HAVE_PTHREAD_YIELD)
	pthread_yield();
#elif defined( HAVE_PTHREAD_YIELD_NP)
	pthread_yield_np();
#endif
}
