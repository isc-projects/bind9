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

#include <isc/endian.h>

#include <dns/rdataslab.h>

#define CASEFULLYLOWER(header)                         \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_CASEFULLYLOWER) != 0)
#define CASESET(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_CASESET) != 0)
#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) == 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_IGNORE) != 0)
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NEGATIVE) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NXDOMAIN) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_OPTOUT) != 0)
#define PREFETCH(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_PREFETCH) != 0)
#define RESIGN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_RESIGN) != 0)
#define STALE(header)                                  \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE) != 0)
#define STALE_WINDOW(header)                           \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE_WINDOW) != 0)
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STATCOUNT) != 0)
#define ZEROTTL(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ZEROTTL) != 0)

#define peek_uint16(buffer) ISC_U8TO16_BE(buffer)
#define get_uint16(buffer)                            \
	({                                            \
		uint16_t __ret = peek_uint16(buffer); \
		buffer += sizeof(uint16_t);           \
		__ret;                                \
	})
#define put_uint16(buffer, val)               \
	{                                     \
		ISC_U16TO8_BE(buffer, val);   \
		(buffer) += sizeof(uint16_t); \
	}
