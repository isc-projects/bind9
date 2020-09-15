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

#include <stdbool.h>
#include <stddef.h>	/* NULL */
#include <stdlib.h>	/* NULL */
#include <syslog.h>

#include <sys/time.h>

#include <isc/stdtime.h>
#include <isc/util.h>

void
isc_stdtime_get(isc_stdtime_t *t) {
	struct timeval tv;

	/*
	 * Set 't' to the number of seconds since 00:00:00 UTC, January 1,
	 * 1970.
	 */

	REQUIRE(t != NULL);

	RUNTIME_CHECK(gettimeofday(&tv, NULL) != -1);

	*t = (unsigned int)tv.tv_sec;
}
