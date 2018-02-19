/*
 * Copyright (C) 1998-2001, 2004, 2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: version.c,v 1.6 2007/06/19 23:47:22 tbox Exp $ */

#include <versions.h>

#include <isccfg/version.h>

LIBISCCFG_EXTERNAL_DATA const char cfg_version[] = VERSION;

LIBISCCFG_EXTERNAL_DATA const unsigned int cfg_libinterface = LIBINTERFACE;
LIBISCCFG_EXTERNAL_DATA const unsigned int cfg_librevision = LIBREVISION;
LIBISCCFG_EXTERNAL_DATA const unsigned int cfg_libage = LIBAGE;

