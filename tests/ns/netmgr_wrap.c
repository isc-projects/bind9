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

/*! \file */

#include <isc/atomic.h>
#include <isc/netmgr.h>
#include <isc/util.h>

#include <dns/view.h>

#include <ns/client.h>

void
ns_client_error(ns_client_t *client ISC_ATTR_UNUSED,
		isc_result_t result ISC_ATTR_UNUSED) {
	return;
}
