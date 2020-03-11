/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdio.h>
#include <string.h>

#include <isc/backtrace.h>
#include <isc/print.h>
#include <isc/result.h>

static int
func3() {
	void *tracebuf[16];
	int nframes;
	isc_result_t result;

	result = isc_backtrace_gettrace(tracebuf, 16, &nframes);
	if (result != ISC_R_SUCCESS) {
		printf("isc_backtrace_gettrace failed: %s\n",
		       isc_result_totext(result));
		return (1);
	}

	if (nframes < 4) {
		printf("Unexpected result:\n");
		printf("  # of frames: %d (expected: at least 4)\n", nframes);
		return (1);
	}

	return (0);
}

static int
func2() {
	return (func3());
}

static int
func1() {
	return (func2());
}

int
main() {
	return (func1());
}
