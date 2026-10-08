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

/*! \file dns/notify.h */

#include <isc/sockaddr.h>

#include <dns/name.h>
#include <dns/types.h>
#include <dns/zoneaddr.h>

#define NOTIFY_MAGIC		 ISC_MAGIC('N', 't', 'f', 'y')
#define DNS_NOTIFY_VALID(notify) ISC_MAGIC_VALID(notify, NOTIFY_MAGIC)

/*%
 * Hold notify contxt.
 */
struct dns_notifyctx {
	dns_acl_t *notify_acl;

	dns_rdatatype_t type;

	dns_notifylist_t notifies;

	/* Configuration data. */
	dns_notifytype_t notifytype;
	uint32_t	 notifydefer;
	uint32_t	 notifydelay;
	zone_addr4_t	 notifysrc4;
	zone_addr6_t	 notifysrc6;
};

/*%
 * Hold notify state.
 */
struct dns_notify {
	unsigned int	 magic;
	unsigned int	 flags;
	isc_mem_t	*mctx;
	dns_zone_t	*zone;
	dns_adbfind_t	*find;
	dns_request_t	*request;
	dns_name_t	 ns;
	dns_rdatatype_t	 type;
	in_port_t	 port;
	isc_sockaddr_t	 src;
	isc_sockaddr_t	 dst;
	dns_tsigkey_t	*key;
	dns_transport_t *transport;
	ISC_LINK(dns_notify_t) link;
	isc_rlevent_t *rlevent;
};

typedef enum dns_notify_flags {
	DNS_NOTIFY_NOSOA = 1 << 0,
	DNS_NOTIFY_STARTUP = 1 << 1,
	DNS_NOTIFY_TCP = 1 << 2,
} dns_notify_flags_t;

void
dns_notifyctx_init(dns_notifyctx_t *nctx, dns_rdatatype_t type);
/*%
 *	Initializes a notify context for the RRtype 'type'.
 *
 *	Requires:
 *		'nctx' is not NULL.
 *
 */

void
dns_notify_create(isc_mem_t *mctx, dns_rdatatype_t type, in_port_t port,
		  unsigned int flags, dns_notify_t **notifyp);
/*%<
 *	Create a notify structure to maintain state.
 *
 *	Requires:
 *		'mctx' is not NULL.
 *		'notifyp' is not NULL and '*notifyp' is NULL.
 */

void
dns_notify_destroy(dns_notify_t *notify, bool zone_locked);
/*%<
 *	Destroy a notify structure. If 'zone_locked' is true, the attached
 *	zone is already locked.
 *
 *	Requires:
 *		'notify' is a valid notify.
 */

bool
dns_notify_isqueued(dns_notifyctx_t *nctx, dns_rdatatype_t type, in_port_t port,
		    unsigned int flags, dns_name_t *name, isc_sockaddr_t *addr,
		    dns_tsigkey_t *key, dns_transport_t *transport);
/*%<
 *	Check if we already have a notify queued matching name, type,
 *	destination address and port, TSIG key, and transport. Will
 *	requeue on the normal notify ratelimiter if the notify was
 *	enqueued on the startup ratelimiter and this is not a startup
 *	notify.
 *
 *      Requires:
 *		'nctx' is not NULL
 *
 *      Returns:
 *		true if the notify matching the parameters is already enqueued
 *		false otherwise
 */

isc_result_t
dns_notify_queue(dns_notify_t *notify, bool startup);
/*%<
 *      Queue notify.
 *
 *      Requires:
 *              'notify' is a valid notify.
 */

void
dns_notify_find_address(dns_notify_t *notify);
/*%<
 *	Find corresponding addresses for name server to send notify to.
 *	Does a lookup into the ADB, then sends a notify to the found
 *	addresses.
 *
 *	Requires:
 *		'notify' is a valid notify.
 */

void
dns_notify_cancel(dns_notifyctx_t *nctx);
/*%<
 *	Cancel all notifies. The corresponding zone must be locked.
 *
 *	Requires:
 *		'nctx' is not NULL
 */
