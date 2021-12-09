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

/*! \file */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

#if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK)

static bool errcheck_initialized = false;
static pthread_mutexattr_t errcheck;
static isc_once_t once_errcheck = ISC_ONCE_INIT;

static void
initialize_errcheck(void) {
	RUNTIME_CHECK(pthread_mutexattr_init(&errcheck) == 0);
	RUNTIME_CHECK(pthread_mutexattr_settype(&errcheck,
						PTHREAD_MUTEX_ERRORCHECK) == 0);
	errcheck_initialized = true;
}

void
isc_mutex_init_errcheck(isc_mutex_t *mp) {
	isc_result_t result;
	int err;

	result = isc_once_do(&once_errcheck, initialize_errcheck);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	err = pthread_mutex_init(mp, &errcheck);
	if (err != 0) {
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}
}
#endif /* if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK) */

#if ISC_MUTEX_DEBUG && defined(__NetBSD__) && defined(PTHREAD_MUTEX_ERRORCHECK)
pthread_mutexattr_t isc__mutex_attrs = {
	PTHREAD_MUTEX_ERRORCHECK, /* m_type */
	0			  /* m_flags, which appears to be unused. */
};
#endif /* if ISC_MUTEX_DEBUG && defined(__NetBSD__) && \
	* defined(PTHREAD_MUTEX_ERRORCHECK) */

#if !(ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK))

#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
static bool attr_initialized = false;
static pthread_mutexattr_t attr;
static isc_once_t once_attr = ISC_ONCE_INIT;
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */

#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
static void
initialize_attr(void) {
	RUNTIME_CHECK(pthread_mutexattr_init(&attr) == 0);
	RUNTIME_CHECK(pthread_mutexattr_settype(
			      &attr, PTHREAD_MUTEX_ADAPTIVE_NP) == 0);
	attr_initialized = true;
}
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */

void
isc__mutex_init(isc_mutex_t *mp, const char *file, unsigned int line) {
	int err;

#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
	isc_result_t result = ISC_R_SUCCESS;
	result = isc_once_do(&once_attr, initialize_attr);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	err = pthread_mutex_init(mp, &attr);
#else  /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
	err = pthread_mutex_init(mp, ISC__MUTEX_ATTRS);
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
	if (err != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}
}
#endif /* if !(ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK)) */
