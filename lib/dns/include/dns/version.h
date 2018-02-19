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

/* $Id: version.h,v 1.9.1234.1 2012/02/11 22:37:57 each Exp $ */

/*! \file dns/version.h */

#include <isc/platform.h>

LIBDNS_EXTERNAL_DATA extern const char dns_version[];
LIBDNS_EXTERNAL_DATA extern const char dns_major[];
LIBDNS_EXTERNAL_DATA extern const char dns_mapapi[];

LIBDNS_EXTERNAL_DATA extern const unsigned int dns_libinterface;
LIBDNS_EXTERNAL_DATA extern const unsigned int dns_librevision;
LIBDNS_EXTERNAL_DATA extern const unsigned int dns_libage;
