/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/print.h>
#include <isc/util.h>

#ifndef MAXHOSTNAMELEN
#ifdef HOST_NAME_MAX
#define MAXHOSTNAMELEN HOST_NAME_MAX
#else
#define MAXHOSTNAMELEN 256
#endif
#endif

static void
usage() {
	fprintf(stderr, "usage: feature-test <arg>\n");
	fprintf(stderr, "args:\n");
	fprintf(stderr, "	--allow-filter-aaaa\n");
	fprintf(stderr, "	--edns-version\n");
	fprintf(stderr, "	--gethostname\n");
	fprintf(stderr, "	--gssapi\n");
	fprintf(stderr, "	--have-dlopen\n");
	fprintf(stderr, "	--have-geoip\n");
	fprintf(stderr, "	--have-libxml2\n");
	fprintf(stderr, "	--rpz-nsip\n");
	fprintf(stderr, "	--rpz-nsdname\n");
	fprintf(stderr, "	--with-idn\n");
}

int
main(int argc, char **argv) {
	
	if (argc != 2) {
		usage();
		return (1);
	}

	if (strcmp(argv[1], "--allow-filter-aaaa") == 0) {
#ifdef ALLOW_FILTER_AAAA
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--edns-version") == 0) {
#ifdef DNS_EDNS_VERSION
		printf("%d\n", DNS_EDNS_VERSION);
#else
		printf("0\n");
#endif
		return (0);
	}

	if (strcmp(argv[1], "--gethostname") == 0) {
		char hostname[MAXHOSTNAMELEN];
		int n;
		n = gethostname(hostname, sizeof(hostname));
		if (n == -1) {
			perror("gethostname");
			return(1);
		}
		fprintf(stdout, "%s\n", hostname);
		return (0);
	}

	if (strcmp(argv[1], "--gssapi") == 0) {
#if defined(GSSAPI)
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-dlopen") == 0) {	
#if defined(HAVE_DLOPEN) && defined(ISC_DLZ_DLOPEN)
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-geoip") == 0) {	
#ifdef HAVE_GEOIP
		return (0);
#else
		return (1);
#endif
	}

        if (strcmp(argv[1], "--have-libxml2") == 0) {
#ifdef HAVE_LIBXML2
		return (0);
#else
		return (1);
#endif
	}

        if (strcmp(argv[1], "--rpz-nsip") == 0) {
#ifdef ENABLE_RPZ_NSIP
                return (0);
#else
                return (1);
#endif
        }

        if (strcmp(argv[1], "--rpz-nsdname") == 0) {
#ifdef ENABLE_RPZ_NSDNAME
                return (0);
#else
                return (1);
#endif
        }

	if (strcmp(argv[1], "--with-idn") == 0) {
#ifdef WITH_IDN
		return (0);
#else
		return (1);
#endif
	}

	fprintf(stderr, "unknown arg: %s\n", argv[1]);
	usage();
	return (1);
}
