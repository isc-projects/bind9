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

/*! \file */
#include <config.h>

#include <stdio.h>

#include <isc/net.h>
#include <isc/print.h>

#include <lwres/netdb.h>

static void
print_he(struct hostent *he, int error, const char *fun, const char *name) {
	char **c;
	int i;

	if (he != NULL) {
		 printf("%s(%s):\n", fun, name);
		 printf("\tname = %s\n", he->h_name);
		 printf("\taddrtype = %d\n", he->h_addrtype);
		 printf("\tlength = %d\n", he->h_length);
		 c = he->h_aliases;
		 i = 1;
		 while (*c != NULL) {
			printf("\talias[%d] = %s\n", i, *c);
			i++;
			c++;
		 }
		 c = he->h_addr_list;
		 i = 1;
		 while (*c != NULL) {
			char buf[128];
			inet_ntop(he->h_addrtype, *c, buf, sizeof(buf));
			printf("\taddress[%d] = %s\n", i, buf);
			c++;
			i++;
		}
	} else {
		printf("%s(%s): error = %d (%s)\n", fun, name, error,
		       hstrerror(error));
	}
}

int
main(int argc, char **argv) {
	struct hostent *he;
	int error;

	(void)argc;

	while (argv[1] != NULL) {
		he = gethostbyname(argv[1]);
		print_he(he, h_errno, "gethostbyname", argv[1]);

		he = getipnodebyname(argv[1], AF_INET6, AI_DEFAULT|AI_ALL,
				     &error);
		print_he(he, error, "getipnodebyname", argv[1]);
		if (he != NULL)
			freehostent(he);

		he = getipnodebyname(argv[1], AF_INET6, AI_DEFAULT,
				     &error);
		print_he(he, error, "getipnodebyname", argv[1]);
		if (he != NULL)
			freehostent(he);
		argv++;
	}
	return (0);
}
