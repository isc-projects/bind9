/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2013, 2016, 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: thread.h,v 1.6 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_THREAD_H
#define ISC_THREAD_H 1

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

/* Placeholder types (they are not accessed) */

typedef void * isc_thread_t;
typedef void * isc_threadresult_t;
typedef void * isc_threadarg_t;
typedef void * isc_threadfunc_t;
typedef void * isc_thread_key_t;

void
isc_thread_setconcurrency(unsigned int level);

void
isc_thread_setname(isc_thread_t thread, const char *name);

#define isc_thread_self() ((unsigned long)0)
#define isc_thread_yield() ((void)0)

ISC_LANG_ENDDECLS

#endif /* ISC_THREAD_H */
