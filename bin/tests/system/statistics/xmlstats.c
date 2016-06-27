/*
 * Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>
#include <isc/util.h>

int
main(int argc, char **argv) {

	UNUSED(argc);
	UNUSED(argv);

#ifdef HAVE_LIBXML2
	return (0);
#else
	return (1);
#endif
}
