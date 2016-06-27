/*
 * Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>
#include <stdio.h>

#include <isc/print.h>
#include <isc/util.h>
#include <dns/edns.h>

int
main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);
	printf("%d\n", DNS_EDNS_VERSION);
	return (0);
}
