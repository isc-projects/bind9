/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: version.c,v 1.5 2007/06/19 23:47:16 tbox Exp $ */

#include <versions.h>

#include <bind9/version.h>

LIBBIND9_EXTERNAL_DATA const char bind9_version[] = VERSION;

LIBBIND9_EXTERNAL_DATA const unsigned int bind9_libinterface = LIBINTERFACE;
LIBBIND9_EXTERNAL_DATA const unsigned int bind9_librevision = LIBREVISION;
LIBBIND9_EXTERNAL_DATA const unsigned int bind9_libage = LIBAGE;
