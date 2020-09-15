/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdio.h>
#include <isc/print.h>
#include <lwres/platform.h>
#include <Winsock2.h>

void
InitSockets(void) {
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 0);

	err = WSAStartup( wVersionRequested, &wsaData );
	if (err != 0) {
		fprintf(stderr, "WSAStartup() failed: %d\n", err);
		exit(1);
	}
}

void
DestroySockets(void) {
	WSACleanup();
}
