/*
 * Copyright (C) 1998-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: version.c,v 1.6 2007/06/19 23:47:23 tbox Exp $ */

#include <versions.h>

#include <lwres/version.h>

LIBLWRES_EXTERNAL_DATA const char lwres_version[] = VERSION;

LIBLWRES_EXTERNAL_DATA const unsigned int lwres_libinterface = LIBINTERFACE;
LIBLWRES_EXTERNAL_DATA const unsigned int lwres_librevision = LIBREVISION;
LIBLWRES_EXTERNAL_DATA const unsigned int lwres_libage = LIBAGE;
