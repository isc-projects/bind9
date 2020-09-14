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

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif /* HAVE_BACKTRACE */

#include <isc/backtrace.h>
#include <isc/result.h>
#include <isc/util.h>

#ifdef HAVE_BACKTRACE
isc_result_t
isc_backtrace_gettrace(void **addrs, int maxaddrs, int *nframes) {
	/*
	 * Validate the arguments: intentionally avoid using REQUIRE().
	 * See notes in backtrace.h.
	 */
	if (addrs == NULL || nframes == NULL) {
		return (ISC_R_FAILURE);
	}

	/*
	 * backtrace(3) includes this function itself in the address array,
	 * which should be eliminated from the returned sequence.
	 */
	int n = backtrace(addrs, maxaddrs);
	if (n < 2) {
		return (ISC_R_NOTFOUND);
	}
	n--;
	memmove(addrs, &addrs[1], sizeof(addrs[0]) * n);
	*nframes = n;
	return (ISC_R_SUCCESS);
}

#else  /* HAVE_BACKTRACE */
isc_result_t
isc_backtrace_gettrace(void **addrs, int maxaddrs, int *nframes) {
	UNUSED(addrs);
	UNUSED(maxaddrs);
	UNUSED(nframes);

	return (ISC_R_NOTIMPLEMENTED);
}
#endif /* HAVE_BACKTRACE */
