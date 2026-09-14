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

#include <isc/net.h>

/*
 * Embedded endpoints need neither socket-address list links nor a length.
 * Configured source addresses have port zero and no IPv6 flow information.
 * Preserve the IPv6 scope ID for interface-scoped addresses.
 * The all-zero IPv4/IPv6 representations are wildcard addresses.
 */
typedef struct {
	struct in_addr address;
} zone_addr4_t;

typedef struct {
	struct in6_addr address;
	uint32_t	scope;
} zone_addr6_t;

typedef struct {
	union {
		zone_addr4_t in;
		zone_addr6_t in6;
	} type;
	sa_family_t family;
} zone_addr_t;
