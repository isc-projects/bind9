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

#include <isc/netmgr.h>

#ifndef DNS_DISPATCH_H
#define DNS_DISPATCH_H 1

/*****
***** Module Info
*****/

/*! \file dns/dispatch.h
 * \brief
 * DNS Dispatch Management
 * 	Shared UDP and single-use TCP dispatches for queries and responses.
 *
 * MP:
 *
 *\li     	All locking is performed internally to each dispatch.
 * 	Restrictions apply to dns_dispatch_removeresponse().
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

/*@{*/
/*%
 * Attributes for added dispatchers.
 *
 * Values with the mask 0xffff0000 are application defined.
 * Values with the mask 0x0000ffff are library defined.
 *
 * Insane values (like setting both TCP and UDP) are not caught.  Don't
 * do that.
 *
 * _PRIVATE
 *	The dispatcher cannot be shared.
 *
 * _TCP, _UDP
 *	The dispatcher is a TCP or UDP socket.
 *
 * _IPV4, _IPV6
 *	The dispatcher uses an IPv4 or IPv6 socket.
 */
#define DNS_DISPATCHATTR_PRIVATE   0x00000001U
#define DNS_DISPATCHATTR_TCP	   0x00000002U
#define DNS_DISPATCHATTR_UDP	   0x00000004U
#define DNS_DISPATCHATTR_IPV4	   0x00000008U
#define DNS_DISPATCHATTR_IPV6	   0x00000010U
#define DNS_DISPATCHATTR_CONNECTED 0x00000080U
/*@}*/

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
 *\li 	mgr is a valid dispatchmgr
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
		       unsigned int attributes, dns_dispatch_t **dispp);
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
		       const isc_sockaddr_t *destaddr, unsigned int attributes,
		       isc_dscp_t dscp, dns_dispatch_t **dispp);
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
 * connect callback that was set up via dns_dispatch_addresponse().
 *
 * Requires:
 *\li	'resp' is valid.
 */

void
dns_dispatch_cancel(dns_dispentry_t *resp);
/*%<
 * Cancel pending connects in 'resp', by setting a flag so that
 * a read is not started when the connect handler runs.
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

isc_result_t
dns_dispatch_gettcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *destaddr,
		    const isc_sockaddr_t *localaddr, bool *connected,
		    dns_dispatch_t **dispp);
/*
 * Attempt to connect to a existing TCP connection (connection completed
 * if connected == NULL).
 */

isc_result_t
dns_dispatch_addresponse(dns_dispatch_t *disp, unsigned int options,
			 unsigned int timeout, const isc_sockaddr_t *dest,
			 isc_nm_cb_t connected, isc_nm_cb_t sent,
			 isc_nm_recv_cb_t response, isc_nm_cb_t timedout,
			 void *arg, dns_messageid_t *idp,
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
dns_dispatch_removeresponse(dns_dispentry_t **resp);
/*%<
 * Stops the flow of responses for the provided id and destination.
 *
 * Requires:
 *\li	"resp" != NULL and "*resp" contain a value previously allocated
 *	by dns_dispatch_addresponse();
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

unsigned int
dns_dispatch_getattributes(dns_dispatch_t *disp);
/*%<
 * Return the attributes (DNS_DISPATCHATTR_xxx) of this dispatch.  Only the
 * non-changeable attributes are expected to be referenced by the caller.
 *
 * Requires:
 *\li	disp is valid.
 */

void
dns_dispatch_changeattributes(dns_dispatch_t *disp, unsigned int attributes,
			      unsigned int mask);
/*%<
 * Set the bits described by "mask" to the corresponding values in
 * "attributes".
 *
 * That is:
 *
 * \code
 *	new = (old & ~mask) | (attributes & mask)
 * \endcode
 *
 * This function has a side effect when #DNS_DISPATCHATTR_NOLISTEN changes.
 * When the flag becomes off, the dispatch will start receiving on the
 * corresponding socket.  When the flag becomes on, receive events on the
 * corresponding socket will be canceled.
 *
 * Requires:
 *\li	disp is valid.
 *
 *\li	attributes are reasonable for the dispatch.  That is, setting the UDP
 *	attribute on a TCP socket isn't reasonable.
 */

dns_dispatch_t *
dns_dispatchset_get(dns_dispatchset_t *dset);
/*%<
 * Retrieve the next dispatch from dispatch set 'dset', and increment
 * the round-robin counter.
 *
 * Requires:
 *\li 	dset != NULL
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
 *\li 	source is a valid UDP dispatcher
 *\li 	dsetp != NULL, *dsetp == NULL
 */

void
dns_dispatchset_destroy(dns_dispatchset_t **dsetp);
/*%<
 * Dereference all the dispatches in '*dsetp', free the dispatchset
 * memory, and set *dsetp to NULL.
 *
 * Requires:
 *\li 	dset is valid
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

#endif /* DNS_DISPATCH_H */
