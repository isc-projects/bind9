/*
 * Copyright (C) 2003-2007, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef LWRES_STDLIB_H
#define LWRES_STDLIB_H 1

/*! \file lwres/stdlib.h */

#include <stdlib.h>

#include <lwres/lang.h>
#include <lwres/platform.h>

#ifdef LWRES_PLATFORM_NEEDSTRTOUL
#define strtoul lwres_strtoul
#endif

LWRES_LANG_BEGINDECLS

unsigned long lwres_strtoul(const char *, char **, int);

LWRES_LANG_ENDDECLS

#endif
