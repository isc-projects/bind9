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

#ifndef MAXHOSTNAMELEN
#ifdef HOST_NAME_MAX
#define MAXHOSTNAMELEN HOST_NAME_MAX
#else
#define MAXHOSTNAMELEN 256
#endif
#endif

int
main(int argc, char **argv) {
	char hostname[MAXHOSTNAMELEN];
	int n;

	UNUSED(argc);
	UNUSED(argv);

	n = gethostname(hostname, sizeof(hostname));
	if (n == -1) {
		perror("gethostname");
		exit(1);
	}
	fprintf(stdout, "%s\n", hostname);
	return (0);
}
