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

#include <isc/lang.h>
#include <isc/tid.h>
#include <isc/util.h>

/**
 * Private
 */

#define ISC_TID_UNKNOWN UINT32_MAX

static thread_local uint32_t isc__tid_v = ISC_TID_UNKNOWN;

/**
 * Protected
 */

void
isc__tid_init(uint32_t tid) {
	REQUIRE(isc__tid_v == ISC_TID_UNKNOWN || isc__tid_v == tid);

	isc__tid_v = tid;
}

/**
 * Public
 */

uint32_t
isc_tid(void) {
	return (isc__tid_v);
}
