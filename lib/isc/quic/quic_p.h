
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

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>

#include <isc/quic.h>
#include <isc/types.h>

struct isc_quic_conn {
	uint32_t magic;
	isc_refcount_t references;
	isc_quic_router_t *router;

	const isc_quic_conn_callbacks_t *cb;
	void *cbarg;

	/* isc_mem_t resides inside `mem.user_data` */
	ngtcp2_mem mem;
};
