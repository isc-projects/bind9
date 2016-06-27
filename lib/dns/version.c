/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2012, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: version.c,v 1.15.1234.1 2012/02/11 22:37:57 each Exp $ */

/*! \file */

#include <dns/version.h>

const char dns_version[] = VERSION;
const char dns_major[] = MAJOR;
const char dns_mapapi[] = MAPAPI;

const unsigned int dns_libinterface = LIBINTERFACE;
const unsigned int dns_librevision = LIBREVISION;
const unsigned int dns_libage = LIBAGE;
