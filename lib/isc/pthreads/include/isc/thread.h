/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: thread.h,v 1.26 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_THREAD_H
#define ISC_THREAD_H 1

/*! \file */

#include <pthread.h>

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

typedef pthread_t isc_thread_t;
typedef void * isc_threadresult_t;
typedef void * isc_threadarg_t;
typedef isc_threadresult_t (*isc_threadfunc_t)(isc_threadarg_t);
typedef pthread_key_t isc_thread_key_t;

isc_result_t
isc_thread_create(isc_threadfunc_t, isc_threadarg_t, isc_thread_t *);

void
isc_thread_setconcurrency(unsigned int level);

void
isc_thread_yield(void);

/* XXX We could do fancier error handling... */

#define isc_thread_join(t, rp) \
	((pthread_join((t), (rp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_self \
	(unsigned long)pthread_self

#define isc_thread_key_create pthread_key_create
#define isc_thread_key_getspecific pthread_getspecific
#define isc_thread_key_setspecific pthread_setspecific
#define isc_thread_key_delete pthread_key_delete

ISC_LANG_ENDDECLS

#endif /* ISC_THREAD_H */
