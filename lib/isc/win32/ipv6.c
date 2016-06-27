/*
 * Copyright (C) 1999-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ipv6.c,v 1.8 2007/06/19 23:47:19 tbox Exp $ */

#include <isc/net.h>
#include <isc/platform.h>

LIBISC_EXTERNAL_DATA const struct in6_addr isc_in6addr_any =
	IN6ADDR_ANY_INIT;

LIBISC_EXTERNAL_DATA const struct in6_addr isc_in6addr_loopback =
	IN6ADDR_LOOPBACK_INIT;
