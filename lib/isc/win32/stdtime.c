/*
 * Copyright (C) 1999-2001, 2004, 2007, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: stdtime.c,v 1.12 2007/06/19 23:47:19 tbox Exp $ */

#include <config.h>

#include <time.h>

#include <isc/assertions.h>
#include <isc/stdtime.h>
#include <isc/util.h>

void
isc_stdtime_get(isc_stdtime_t *t) {
	/*
	 * Set 't' to the number of seconds past 00:00:00 UTC, January 1, 1970.
	 */

	REQUIRE(t != NULL);

	(void)_time32(t);
}
