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

/*****
***** Module Info
*****/

/*! \file dns/unreachcache.h
 * \brief
 * Defines dns_unreachcache_t, the "unreachable cache" object.
 *
 * Notes:
 *\li 	An unreachable cache object is a hash table of
 *	isc_sockaddr_t/isc_sockaddr_t tuples, indicating whether a given tuple
 *	is known to be "unreachable" in some sense (e.g. an unresponsive primary
 *	server). This is currently used by the secondary servers for the
 *	"unreachable cache".
 *
 * Reliability:
 *
 * Resources:
 *
 * Security:
 *
 * Standards:
 */

/***
 ***	Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>

#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/stdtime.h>

#include <dns/types.h>

/***
 ***	Functions
 ***/

dns_unreachcache_t *
dns_unreachcache_new(isc_mem_t *mctx, const uint16_t expire_min_s,
		     const uint16_t expire_max_s,
		     const uint16_t backoff_eligible_s);
/*%
 * Allocate and initialize an unreachable cache. A newly entered entry expires
 * in 'expire_min_s' seconds, a duplicate entry refreshes the expire timer.
 * However, after expiring, if the same entry is added again in less that the
 * 'backoff_eligible_s' time, then the next expire happens in a double amount of
 * time of the previous expiration, but no more than in 'expire_max_s' seconds.
 *
 * Requires:
 * \li	mctx != NULL
 * \li	expire_min_s > 0
 * \li  expire_min_s <= expire_max_s
 */

void
dns_unreachcache_destroy(dns_unreachcache_t **ucp);
/*%
 * Flush and then free unreachcache in 'ucp'. '*ucp' is set to NULL on return.
 *
 * Requires:
 * \li	'*ucp' to be a valid unreachcache
 */

void
dns_unreachcache_add(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
		     const isc_sockaddr_t *local);
/*%
 * Adds an unreachcache entry to the unreachcache 'uc' for addresses 'remote'
 * and 'local'. If an entry already exists, then it is refreshed. See also
 * the documentation of the dns_unreachcache_new() function.
 *
 * Requires:
 * \li	uc to be a valid unreachcache.
 * \li	remote != NULL
 * \li	local != NULL
 */

isc_result_t
dns_unreachcache_find(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
		      const isc_sockaddr_t *local);
/*%
 * Returns ISC_R_SUCCESS if a record is found in the unreachcache 'uc' matching
 * 'remote' and 'local', with an expiration date later than 'now'. Returns
 * ISC_R_NOTFOUND otherwise.
 *
 * Requires:
 * \li	uc to be a valid unreachcache.
 * \li	remote != NULL
 * \li	local != NULL
 */

void
dns_unreachcache_remove(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
			const isc_sockaddr_t *local);
/*%
 * Removes a record that is found in the unreachcache 'uc' matching 'remote' and
 * 'local', if it exists.
 *
 * Requires:
 * \li	uc to be a valid unreachcache.
 * \li	remote != NULL
 * \li	local != NULL
 * \li	now != NULL
 */

void
dns_unreachcache_flush(dns_unreachcache_t *uc);
/*%
 * Flush the entire unreachable cache.
 *
 * Requires:
 * \li	uc to be a valid unreachcache
 */
