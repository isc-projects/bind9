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

#pragma once

/*! \file */

#include <pthread.h>
#include <stdio.h>

#include <isc/lang.h>
#include <isc/result.h> /* for ISC_R_ codes */

ISC_LANG_BEGINDECLS

/*!
 * Supply mutex attributes that enable deadlock detection
 * (helpful when debugging).  This is system dependent and
 * currently only supported on NetBSD.
 */
#if ISC_MUTEX_DEBUG && defined(__NetBSD__) && defined(PTHREAD_MUTEX_ERRORCHECK)
extern pthread_mutexattr_t isc__mutex_attrs;
#define ISC__MUTEX_ATTRS &isc__mutex_attrs
#else /* if ISC_MUTEX_DEBUG && defined(__NetBSD__) && \
       * defined(PTHREAD_MUTEX_ERRORCHECK) */
#define ISC__MUTEX_ATTRS NULL
#endif /* if ISC_MUTEX_DEBUG && defined(__NetBSD__) && \
	* defined(PTHREAD_MUTEX_ERRORCHECK) */

/* XXX We could do fancier error handling... */

typedef pthread_mutex_t isc_mutex_t;

#if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK)
#define isc_mutex_init(mp) isc_mutex_init_errcheck((mp))
#else /* if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK) */
#define isc_mutex_init(mp) isc__mutex_init((mp), __FILE__, __LINE__)
void
isc__mutex_init(isc_mutex_t *mp, const char *file, unsigned int line);
#endif /* if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK) */

#define isc_mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_LOCKBUSY)

#define isc_mutex_destroy(mp) RUNTIME_CHECK(pthread_mutex_destroy((mp)) == 0)

void
isc_mutex_init_errcheck(isc_mutex_t *mp);

ISC_LANG_ENDDECLS
