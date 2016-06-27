/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: testsuite.h,v 1.7 2007/06/19 23:47:00 tbox Exp $ */

#define SUITENAME "net"

TESTDECL(netaddr_multicast);
TESTDECL(sockaddr_multicast);

static test_t tests[] = {
	{ "isc_netaddr_ismulticast",
	  "Checking to see if multicast addresses are detected properly",
	  netaddr_multicast },
	{ "isc_sockaddr_ismulticast",
	  "Checking to see if multicast addresses are detected properly",
	  sockaddr_multicast },

};
