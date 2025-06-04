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

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/util.h>

/**
 * Private
 */
thread_local isc_tid_t isc__tid_local = ISC_TID_UNKNOWN;

/*
 * Zero is a better nonsense value in this case than ISC_TID_UNKNOWN;
 * avoids things like trying to allocate 32GB of per-thread counters.
 */
static isc_tid_t tid_count = 0;

/**
 * Protected
 */

void
isc__tid_init(isc_tid_t tid) {
	REQUIRE(isc__tid_local == ISC_TID_UNKNOWN || isc__tid_local == tid);
	REQUIRE(tid < ISC_TID_MAX);
	isc__tid_local = tid;
}

void
isc__tid_initcount(isc_tid_t count) {
	REQUIRE(tid_count == 0 || tid_count == count);
	REQUIRE(tid_count < ISC_TID_MAX);
	tid_count = count;
}

/**
 * Public
 */

isc_tid_t
isc_tid_count(void) {
	return tid_count;
}
