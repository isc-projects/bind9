/*
 * Copyright (C) 1999-2001, 2004, 2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: once.h,v 1.9 2007/06/19 23:47:20 tbox Exp $ */

#ifndef ISC_ONCE_H
#define ISC_ONCE_H 1

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

typedef struct {
	int status;
	int counter;
} isc_once_t;

#define ISC_ONCE_INIT_NEEDED 0
#define ISC_ONCE_INIT_DONE 1

#define ISC_ONCE_INIT { ISC_ONCE_INIT_NEEDED, 1 }

isc_result_t
isc_once_do(isc_once_t *controller, void(*function)(void));

ISC_LANG_ENDDECLS

#endif /* ISC_ONCE_H */
