/*
 * Copyright (C) 1998-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: version.c,v 1.7 2007/06/19 23:47:19 tbox Exp $ */

#include <versions.h>

#include <isc/version.h>

LIBISC_EXTERNAL_DATA const char isc_version[] = VERSION;

LIBISC_EXTERNAL_DATA const unsigned int isc_libinterface = LIBINTERFACE;
LIBISC_EXTERNAL_DATA const unsigned int isc_librevision = LIBREVISION;
LIBISC_EXTERNAL_DATA const unsigned int isc_libage = LIBAGE;
