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

#pragma once

#include <inttypes.h>

#include <isc/thread.h>

typedef int32_t isc_tid_t;

#define PRItid PRId32

#define ISC_TID_UNKNOWN (isc_tid_t) - 1

#ifndef ISC_TID_MAX
#define ISC_TID_MAX 512
#endif /* ISC_TID_MAX */

isc_tid_t
isc_tid_count(void);
/*%<
 * Returns the number of threads.
 */

extern thread_local isc_tid_t isc__tid_local;

static inline isc_tid_t
isc_tid(void) {
	return isc__tid_local;
}
/*%<
 * Returns the thread ID of the currently-running loop.
 */

/* Private */

void
isc__tid_init(isc_tid_t tid);

void
isc__tid_initcount(isc_tid_t count);
