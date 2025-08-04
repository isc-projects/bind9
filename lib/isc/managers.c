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

#include <isc/loop.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/rwlock.h>

void
isc_managers_create(uint32_t workers) {
	isc_loopmgr_create(isc_g_mctx, workers);
	isc_netmgr_create(isc_g_mctx);
	isc_rwlock_setworkers(workers);
}

void
isc_managers_destroy(void) {
	/*
	 * The sequence of operations here is important:
	 */
	isc_netmgr_destroy();
	isc_loopmgr_destroy();
}
