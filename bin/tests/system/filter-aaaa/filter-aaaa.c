/*
 * Copyright (C) 2010-2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: filter-aaaa.c,v 1.4 2011/07/28 23:47:58 tbox Exp $ */

#include <config.h>
#include <isc/util.h>

int
main(int argc, char **argv) {

	UNUSED(argc);
	UNUSED(argv);

#ifdef ALLOW_FILTER_AAAA
	return (0);
#else
	return (1);
#endif
}
