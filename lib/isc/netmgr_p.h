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

#pragma once

#include <isc/mem.h>
#include <isc/result.h>

void
isc__netmgr_create(isc_mem_t *mctx, uint32_t workers, isc_nm_t **netgmrp);
/*%<
 * Creates a new network manager with 'workers' worker threads,
 * and starts it running.
 */

void
isc__netmgr_destroy(isc_nm_t **netmgrp);
/*%<
 * Destroy is working the same way as isc_nm_detach, but it actively waits
 * for all other references to be gone.
 */
