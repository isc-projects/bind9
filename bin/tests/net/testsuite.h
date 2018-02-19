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
