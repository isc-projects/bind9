/*
 * Copyright (C) 2011-2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */


#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define USAGE "usage: nsip | nsdname\n"

int
main(int argc, char **argv)
{
	if (argc != 2) {
		fputs(USAGE, stderr);
		return (1);
	}

	if (!strcasecmp(argv[1], "nsip")) {
#ifdef ENABLE_RPZ_NSIP
		return (0);
#else
		return (1);
#endif
	}

	if (!strcasecmp(argv[1], "nsdname")) {
#ifdef ENABLE_RPZ_NSDNAME
		return (0);
#else
		return (1);
#endif
	}

	fputs(USAGE, stderr);
	return (1);
}
