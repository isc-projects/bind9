/*
 * Copyright (C) 2003-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: stdlib.h,v 1.8 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_STDLIB_H
#define ISC_STDLIB_H 1

/*! \file isc/stdlib.h */

#include <stdlib.h>

#include <isc/lang.h>
#include <isc/platform.h>

#ifdef ISC_PLATFORM_NEEDSTRTOUL
#define strtoul isc_strtoul
#endif

ISC_LANG_BEGINDECLS

unsigned long isc_strtoul(const char *, char **, int);

ISC_LANG_ENDDECLS

#endif
