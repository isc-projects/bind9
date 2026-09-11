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

/*! \file dns/zonemgr.h */

#include <dns/zone.h>

/*
 * Process-wide shared zone services owned by the runtime. Borrowed by zones
 * and DynDB modules; valid until the runtime calls dns_zonemgr_destroy().
 */
extern dns_zonemgr_t *dns_g_zonemgr;

void
dns_zonemgr_create(isc_mem_t *mctx, dns_zonemgr_t **zmgrp);
/*%<
 * Create the process-wide zone manager. Only one may exist at a time.
 * The caller owns its lifetime and must destroy it after all loops drain.
 *
 * Requires:
 *\li	'mctx' to be a valid memory context.
 *\li	'zmgrp'	to point to a NULL pointer.
 */

isc_result_t
dns_zonemgr_createzone(dns_zonemgr_t *zmgr, dns_zone_t **zonep);
/*%<
 *	Allocate a new zone using a memory context from the
 *	zone manager's memory context pool, attached to an existing event loop.
 *	The runtime must keep the manager alive until zone cleanup finishes.
 *
 * Require:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'zonep' != NULL and '*zonep' == NULL.
 */

void
dns_zonemgr_resumexfrs(dns_zonemgr_t *zmgr);
/*%<
 * Retry transfers waiting for quota after a configuration change.
 * Zone timer maintenance is scheduled separately by the view owner.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_shutdown(dns_zonemgr_t *zmgr);
/*%<
 *	Stop zone services while the event loops are running. The manager
 * remains allocated until dns_zonemgr_destroy() is called after the loops
 * drain.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_destroy(dns_zonemgr_t **zmgrp);
/*%<
 * Destroy the process-wide zone manager and clear '*zmgrp' and dns_g_zonemgr.
 *
 * The runtime must first shut down the manager and all DynDB instances, then
 * drain all zone activity by waiting for isc_loopmgr_run() to return. Zones
 * and DynDB instances borrow the manager and must not outlive it.
 */

void
dns_zonemgr_settransfersin(dns_zonemgr_t *zmgr, uint32_t value);
/*%<
 *	Set the maximum number of simultaneous transfers in allowed by
 *	the zone manager.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

uint32_t
dns_zonemgr_gettransfersin(dns_zonemgr_t *zmgr);
/*%<
 *	Return the maximum number of simultaneous transfers in allowed.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_settransfersperns(dns_zonemgr_t *zmgr, uint32_t value);
/*%<
 *	Set the number of zone transfers allowed per nameserver.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

uint32_t
dns_zonemgr_gettransfersperns(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of transfers allowed per nameserver.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_setcheckdsrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of parental DS queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setnotifyrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setstartupnotifyrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of startup NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setserialqueryrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of SOA queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

unsigned int
dns_zonemgr_getnotifyrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getstartupnotifyrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of startup NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getserialqueryrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of SOA queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getcount(dns_zonemgr_t *zmgr, dns_zonestate_t state);
/*%<
 *	Returns the number of zones in the specified state.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'state' is DNS_ZONESTATE_XFERRUNNING or DNS_ZONESTATE_XFERDEFERRED.
 */

void
dns_zonemgr_set_tlsctx_cache(dns_zonemgr_t	*zmgr,
			     isc_tlsctx_cache_t *tlsctx_cache);
/*%<
 *	Set the TLS client context cache used for zone transfers via
 *	encrypted transports (e.g. XoT).
 *
 * Requires:
 *\li	'zmgr' is a valid zone manager.
 *\li	'tlsctx_cache' is a valid TLS context cache.
 */
