/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdio.h>

#include <isc/commandline.h>
#include <isc/mem.h>

#include "dnssectool.h"

const char *program = "dnssec-ksr";

/*
 * Infrastructure
 */
static isc_log_t *lctx = NULL;
static isc_mem_t *mctx = NULL;

static void
usage(int ret) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s options [options]\n", program);
	fprintf(stderr, "Version: %s\n", PACKAGE_VERSION);
	fprintf(stderr, "Options:\n"
			"    -h: print usage and exit\n"
			"    -v <level>: set verbosity level\n"
			"    -V: print version information\n");
	exit(ret);
}

int
main(int argc, char *argv[]) {
	int ch;
	char *endp;

	isc_mem_create(&mctx);

	isc_commandline_errprint = false;

#define OPTIONS "hv:V"
	while ((ch = isc_commandline_parse(argc, argv, OPTIONS)) != -1) {
		switch (ch) {
		case 'h':
			usage(0);
			break;
		case 'V':
			version(program);
			break;
		case 'v':
			verbose = strtoul(isc_commandline_argument, &endp, 0);
			if (*endp != '\0') {
				fatal("-v must be followed by a number");
			}
			break;
		default:
			usage(1);
			break;
		}
	}
	argv += isc_commandline_index;
	argc -= isc_commandline_index;

	if (argc != 0) {
		usage(1);
	}

	setup_logging(mctx, &lctx);

	vbprintf(verbose, "KSR: Hello, world.\n");

	exit(0);
}
