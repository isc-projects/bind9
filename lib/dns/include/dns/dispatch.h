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

#include <isc/netmgr.h>

/*****
***** Module Info
*****/

/*! \file dns/dispatch.h
 * \brief
 * DNS Dispatch Management
 *	Shared UDP and single-use TCP dispatches for queries and responses.
 *
 * MP:
 *
 *\li	All locking is performed internally to each dispatch.
 *	Restrictions apply to dns_dispatch_done().
 *
 * Reliability:
 *
 * Resources:
 *
 * Security:
 *
 *\li	Depends on the isc_socket_t and dns_message_t for prevention of
 *	buffer overruns.
 *
 * Standards:
 *
 *\li	None.
 */

/***
 *** Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/lang.h>
#include <isc/mutex.h>
#include <isc/netmgr.h>
#include <isc/socket.h>
#include <isc/types.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

/*%
 * This is a set of one or more dispatches which can be retrieved
 * round-robin fashion.
 */
struct dns_dispatchset {
	isc_mem_t *	 mctx;
	dns_dispatch_t **dispatches;
	int		 ndisp;
	int		 cur;
	isc_mutex_t	 lock;
};

/*
 */
#define DNS_DISPATCHOPT_FIXEDID 0x00000001U

isc_result_t
dns_dispatchmgr_create(isc_mem_t *mctx, isc_nm_t *nm, dns_dispatchmgr_t **mgrp);
/*%<
 * Creates a new dispatchmgr object, and sets the available ports
 * to the default range (1024-65535).
 *
 * Requires:
 *\li	'mctx' be a valid memory context.
 *
 *\li	'nm' is a valid network manager.

 *\li	mgrp != NULL && *mgrp == NULL
 *
 * Returns:
 *\li	ISC_R_SUCCESS	-- all ok
 *
 *\li	anything else	-- failure
 */

void
dns_dispatchmgr_attach(dns_dispatchmgr_t *mgr, dns_dispatchmgr_t **mgrp);
/*%<
 * Attach to a dispatch manger.
 *
 * Requires:
 *\li	 is valid.
 *
 *\li	mgrp != NULL && *mgrp == NULL
 */

void
dns_dispatchmgr_detach(dns_dispatchmgr_t **mgrp);
/*%<
 * Detach from the dispatch manager, and destroy it if no references
 * remain.
 *
 * Requires:
 *\li	mgrp != NULL && *mgrp is a valid dispatchmgr.
 */

void
dns_dispatchmgr_setblackhole(dns_dispatchmgr_t *mgr, dns_acl_t *blackhole);
/*%<
 * Sets the dispatcher's "blackhole list," a list of addresses that will
 * be ignored by all dispatchers created by the dispatchmgr.
 *
 * Requires:
 * \li	mgrp is a valid dispatchmgr
 * \li	blackhole is a valid acl
 */

dns_acl_t *
dns_dispatchmgr_getblackhole(dns_dispatchmgr_t *mgr);
/*%<
 * Gets a pointer to the dispatcher's current blackhole list,
 * without incrementing its reference count.
 *
 * Requires:
 *\li	mgr is a valid dispatchmgr
 * Returns:
 *\li	A pointer to the current blackhole list, or NULL.
 */

isc_result_t
dns_dispatchmgr_setavailports(dns_dispatchmgr_t *mgr, isc_portset_t *v4portset,
			      isc_portset_t *v6portset);
/*%<
 * Sets a list of UDP ports that can be used for outgoing UDP messages.
 *
 * Requires:
 *\li	mgr is a valid dispatchmgr
 *\li	v4portset is NULL or a valid port set
 *\li	v6portset is NULL or a valid port set
 */

void
dns_dispatchmgr_setstats(dns_dispatchmgr_t *mgr, isc_stats_t *stats);
/*%<
 * Sets statistics counter for the dispatchmgr.  This function is expected to
 * be called only on zone creation (when necessary).
 * Once installed, it cannot be removed or replaced.  Also, there is no
 * interface to get the installed stats from the zone; the caller must keep the
 * stats to reference (e.g. dump) it later.
 *
 * Requires:
 *\li	mgr is a valid dispatchmgr with no managed dispatch.
 *\li	stats is a valid statistics supporting resolver statistics counters
 *	(see dns/stats.h).
 */

isc_result_t
dns_dispatch_createudp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		       dns_dispatch_t **dispp);
/*%<
 * Create a new UDP dispatch.
 *
 * Requires:
 *\li	All pointer parameters be valid for their respective types.
 *
 *\li	dispp != NULL && *disp == NULL
 *
 * Returns:
 *\li	ISC_R_SUCCESS	-- success.
 *
 *\li	Anything else	-- failure.
 */

isc_result_t
dns_dispatch_createtcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		       const isc_sockaddr_t *destaddr, isc_dscp_t dscp,
		       dns_dispatch_t **dispp);
/*%<
 * Create a new dns_dispatch and attach it to the provided isc_socket_t.
 *
 * Requires:
 *
 *\li	mgr is a valid dispatch manager.
 *
 *\li	sock is a valid.
 *
 * Returns:
 *\li	ISC_R_SUCCESS	-- success.
 *
 *\li	Anything else	-- failure.
 */

void
dns_dispatch_attach(dns_dispatch_t *disp, dns_dispatch_t **dispp);
/*%<
 * Attach to a dispatch handle.
 *
 * Requires:
 *\li	disp is valid.
 *
 *\li	dispp != NULL && *dispp == NULL
 */

void
dns_dispatch_detach(dns_dispatch_t **dispp);
/*%<
 * Detaches from the dispatch.
 *
 * Requires:
 *\li	dispp != NULL and *dispp be a valid dispatch.
 */

isc_result_t
dns_dispatch_connect(dns_dispentry_t *resp);
/*%<
 * Connect to the remote server configured in 'resp' and run the
 * connect callback that was set up via dns_dispatch_add().
 *
 * Requires:
 *\li	'resp' is valid.
 */

void
dns_dispatch_send(dns_dispentry_t *resp, isc_region_t *r, isc_dscp_t dscp);
/*%<
 * Send region 'r' using the socket in 'resp', then run the specified
 * callback.
 *
 * Requires:
 *\li	'resp' is valid.
 */

void
dns_dispatch_resume(dns_dispentry_t *resp, uint16_t timeout);
/*%<
 * Reset the read timeout in the socket associated with 'resp' and
 * continue reading.
 *
 * Requires:
 *\li	'resp' is valid.
 */

isc_result_t
dns_dispatch_gettcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *destaddr,
		    const isc_sockaddr_t *localaddr, bool *connected,
		    dns_dispatch_t **dispp);
/*
 * Attempt to connect to a existing TCP connection (connection completed
 * if connected == NULL).
 */

typedef void (*dispatch_cb_t)(isc_result_t eresult, isc_region_t *region,
			      void *cbarg);

isc_result_t
dns_dispatch_add(dns_dispatch_t *disp, unsigned int options,
		 unsigned int timeout, const isc_sockaddr_t *dest,
		 dispatch_cb_t connected, dispatch_cb_t sent,
		 dispatch_cb_t response, void *arg, dns_messageid_t *idp,
		 dns_dispentry_t **resp);
/*%<
 * Add a response entry for this dispatch.
 *
 * "*idp" is filled in with the assigned message ID, and *resp is filled in
 * with the dispatch entry object.
 *
 * The 'connected' and 'sent' callbacks are run to inform the caller when
 * the connect and send functions are complete. The 'timedout' callback
 * is run to inform the caller that a read has timed out; it may optionally
 * reset the read timer. The 'response' callback is run for recv results
 * (response packets, timeouts, or cancellations).
 *
 * All the callback functions are sent 'arg' as a parameter.
 *
 * Requires:
 *\li	"idp" be non-NULL.
 *
 *\li	"response" and "arg" be set as appropriate.
 *
 *\li	"dest" be non-NULL and valid.
 *
 *\li	"resp" be non-NULL and *resp be NULL
 *
 * Ensures:
 *
 *\li	&lt;id, dest> is a unique tuple.  That means incoming messages
 *	are identifiable.
 *
 * Returns:
 *
 *\li	ISC_R_SUCCESS		-- all is well.
 *\li	ISC_R_NOMEMORY		-- memory could not be allocated.
 *\li	ISC_R_NOMORE		-- no more message ids can be allocated
 *				   for this destination.
 */

void
dns_dispatch_done(dns_dispentry_t **respp);
/*%<
 * Disconnects a dispatch response entry from its dispatch and shuts it
 * down. This is called when the dispatch is complete; use
 * dns_dispatch_cancel() if it is still pending.
 *
 * Requires:
 *\li	"resp" != NULL and "*resp" contain a value previously allocated
 *	by dns_dispatch_add();
 */

void
dns_dispatch_cancel(dns_dispentry_t **respp);
/*%<
 * Cancel all pending connects and reads in a dispatch entry,
 * then call dns_dispatch_done(). This is used when the caller
 * cancels a dispatch response before it has completed.
 *
 * Requires:
 *\li	"resp" != NULL and "*resp" contain a value previously allocated
 *	by dns_dispatch_add();
 */

isc_result_t
dns_dispatch_getlocaladdress(dns_dispatch_t *disp, isc_sockaddr_t *addrp);
/*%<
 * Return the local address for this dispatch.
 * This currently only works for dispatches using UDP sockets.
 *
 * Requires:
 *\li	disp is valid.
 *\li	addrp to be non NULL.
 *
 * Returns:
 *\li	ISC_R_SUCCESS
 *\li	ISC_R_NOTIMPLEMENTED
 */

isc_result_t
dns_dispentry_getlocaladdress(dns_dispentry_t *resp, isc_sockaddr_t *addrp);
/*%<
 * Return the local address for this dispatch entry.
 *
 * Requires:
 *\li	resp is valid.
 *\li	addrp to be non NULL.
 *
 * Returns:
 *\li	ISC_R_SUCCESS
 *\li	ISC_R_NOTIMPLEMENTED
 */

dns_dispatch_t *
dns_dispatchset_get(dns_dispatchset_t *dset);
/*%<
 * Retrieve the next dispatch from dispatch set 'dset', and increment
 * the round-robin counter.
 *
 * Requires:
 *\li	dset != NULL
 */

isc_result_t
dns_dispatchset_create(isc_mem_t *mctx, dns_dispatch_t *source,
		       dns_dispatchset_t **dsetp, int n);
/*%<
 * Given a valid dispatch 'source', create a dispatch set containing
 * 'n' UDP dispatches, with the remainder filled out by clones of the
 * source.
 *
 * Requires:
 *\li	source is a valid UDP dispatcher
 *\li	dsetp != NULL, *dsetp == NULL
 */

void
dns_dispatchset_destroy(dns_dispatchset_t **dsetp);
/*%<
 * Dereference all the dispatches in '*dsetp', free the dispatchset
 * memory, and set *dsetp to NULL.
 *
 * Requires:
 *\li	dset is valid
 */

isc_result_t
dns_dispatch_getnext(dns_dispentry_t *resp);
/*%<
 * Trigger the sending of the next item off the dispatch queue if present.
 *
 * Requires:
 *\li	resp is valid
 */

ISC_LANG_ENDDECLS
