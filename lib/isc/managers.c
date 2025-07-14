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
#include <isc/rwlock.h>
#include <isc/util.h>
#include <isc/uv.h>

void
isc_managers_create(isc_mem_t **mctxp, uint32_t workers, isc_nm_t **netmgrp) {
	REQUIRE(mctxp != NULL && *mctxp == NULL);
	isc_mem_create("managers", mctxp);
	INSIST(*mctxp != NULL);

	isc_loopmgr_create(*mctxp, workers);

	REQUIRE(netmgrp != NULL && *netmgrp == NULL);
	isc_netmgr_create(*mctxp, netmgrp);
	INSIST(*netmgrp != NULL);

	isc_rwlock_setworkers(workers);
}

void
isc_managers_destroy(isc_mem_t **mctxp, isc_nm_t **netmgrp) {
	REQUIRE(mctxp != NULL && *mctxp != NULL);
	REQUIRE(netmgrp != NULL && *netmgrp != NULL);

	/*
	 * The sequence of operations here is important:
	 */

	isc_nm_detach(netmgrp);
	isc_loopmgr_destroy();
	isc_mem_detach(mctxp);
}
