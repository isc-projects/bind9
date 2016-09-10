/*
 * Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/print.h>
#include <isc/util.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

#ifndef MAXHOSTNAMELEN
#ifdef HOST_NAME_MAX
#define MAXHOSTNAMELEN HOST_NAME_MAX
#else
#define MAXHOSTNAMELEN 256
#endif
#endif

int
main(void) {
	char hostname[MAXHOSTNAMELEN];
	int n;
#ifdef WIN32
	/* From lwres InitSocket() */
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 0);
	err = WSAStartup( wVersionRequested, &wsaData );
	if (err != 0) {
		fprintf(stderr, "WSAStartup() failed: %d\n", err);
		exit(1);
	}
#endif

	n = gethostname(hostname, sizeof(hostname));
	if (n == -1) {
		perror("gethostname");
		exit(1);
	}
	fprintf(stdout, "%s\n", hostname);
#ifdef WIN32
	WSACleanup();
#endif
	return (0);
}
