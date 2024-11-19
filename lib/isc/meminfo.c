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

#include <inttypes.h>

#include <isc/meminfo.h>
#include <isc/uv.h>

uint64_t
isc_meminfo_totalphys(void) {
	uint64_t tmem = uv_get_total_memory();
#if UV_VERSION_HEX >= UV_VERSION(1, 29, 0)
	uint64_t cmem = uv_get_constrained_memory();
	if (cmem > 0 && cmem < tmem) {
		return cmem;
	}
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 29, 0) */
	return tmem;
}
