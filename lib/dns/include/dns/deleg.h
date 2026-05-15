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

#include <isc/refcount.h>
#include <isc/stdtime.h>

#include <dns/types.h>

/*
 * A `dns_deleg_t` object represents either:
 *
 * - a DELEG-based delegation with `server-ipv4=` and/or `server-ipv6=`
 *   (DNS_DELEGTYPE_DELEG_ADDRESS)
 *
 * - a DELEG-based delegation with `server-name=` (DNS_DELEGTYPE_DELEG_NAMES)
 *
 * - a DELEG-based delegation with `include-delegparam=`
 *   (DNS_DELEGTYPE_DELEG_PARAMS)
 *
 * - an NS-based delegation with glues (DNS_DELEGTYPE_NS_GLUES)
 *
 * - an NS-based delegation with no glues (DNS_DELEGTYPE_NS_NAMES)
 *
 * This object must be allocated using `dns_deleg_allocdeleg()`.
 */

typedef enum {
	DNS_DELEGTYPE_UNDEFINED,
	DNS_DELEGTYPE_DELEG_ADDRESSES,
	DNS_DELEGTYPE_DELEG_NAMES,
	DNS_DELEGTYPE_DELEG_PARAMS,
	DNS_DELEGTYPE_NS_GLUES,
	DNS_DELEGTYPE_NS_NAMES
} dns_deleg_type_t;

struct dns_deleg {
	isc_netaddrlist_t addresses;
	dns_namelist_t	  names;
	dns_deleg_type_t  type;
	ISC_LINK(dns_deleg_t) link;
};

/*
 * A delegation set. Once it's added to the delegation DB, it gets a
 * read-only object thus doesn't require any locking nor copying when the
 * caller gets it.
 *
 * The TTL is common to all the DELEG RR for the same zonecut
 * https://datatracker.ietf.org/doc/html/rfc2181#section-5.2
 *
 * When the delegation is NS-based, the TTL is the lowest TTL of the referral
 * (either of the NS, A or AAAA glues).
 *
 * If a zone contains NS and DELEG delegations, this delegation must only
 * store the DELEG ones. (This is resolver responsibility to ensure that.)
 */
struct dns_delegset {
	unsigned int   magic;
	isc_mem_t     *mctx;
	isc_refcount_t references;

	dns_deleglist_t delegs;
	isc_stdtime_t	expires;

	/*
	 * Used only when a delegation is built from a local zone.
	 */
	bool staticstub;
};
ISC_REFCOUNT_DECL(dns_delegset);

#define DNS_DELEGSET_MAGIC ISC_MAGIC('D', 'e', 'G', 's')
#define DNS_DELEGSET_VALID(delegset) \
	ISC_MAGIC_VALID(delegset, DNS_DELEGSET_MAGIC)

typedef struct dns_delegdb dns_delegdb_t;

/*
 * Allocate and initialize the delegation database. `db` is attached to the
 * caller.
 */
void
dns_delegdb_create(dns_delegdb_t **delegdbp);

/*
 * Attach a delegation DB from an existing view to another view. Used when
 * reloading the server and the delegation DB is reused.
 */
void
dns_delegdb_reuse(dns_view_t *oldview, dns_view_t *newview);

/*
 * Shutdown the delegation database. Must be called from any view shutting down
 * which either created a delegdb or reused a delegdb.
 */
void
dns_delegdb_shutdown(dns_delegdb_t *delegdb);

/*
 * Lookup for delegations of a given name in the DB. If found, the zonecut is
 * written and the delegation set is attached to the caller, so it must be
 * detached once the caller is done with it. Even though `delegset` is not
 * const (for convenience with ISC_LIST_FOREACH macros, _attach, _detach
 * functions, etc.) the `delegset` _is_ a read-only object, and must not be
 * modified.
 *
 * If only the zonecut is needed from the caller, `delegset` can be NULL, it
 * won't be attached.
 *
 * The zonecut must be a initialized and attached to a buffer.
 *
 * If `now` is 0, the actual expiration time is `isc_stdtime_now()`.
 */
isc_result_t
dns_delegdb_lookup(dns_delegdb_t *db, const dns_name_t *name, isc_stdtime_t now,
		   unsigned int options, dns_name_t *zonecut,
		   dns_name_t *deepestzonecut, dns_delegset_t **delegset);

/*
 * Allocate and attach to the caller a new empty delegation set, but do not
 * attach it in the DB yet, so the following API can be used to set its
 * various properties.
 *
 * Because all those API calls (dns_deleg_alloc* and dns_deleg_add*) use
 * the internal delegdb memory context, it _might_ in some circumstances
 * allocate above its hiwater mark without reclaiming memory. The flow
 * reclaiming memory is then run when adding the delegset into the database
 * (dns_deleg_writeanddetach()).
 *
 * This could be changed to run through those API calls also if needed.
 */
void
dns_delegset_allocset(dns_delegdb_t *db, dns_delegset_t **delegsetp);

/*
 * Allocate a new deleg struct and insert it into the delegation set. Can't
 * be used on delegation set already attached in the DB.
 */
void
dns_delegset_allocdeleg(dns_delegset_t *delegset, dns_deleg_type_t type,
			dns_deleg_t **delegp);
/*
 * Free the deleg struct and remove it from the delegation set. Can't
 * be used on delegation set already attached in the DB.
 */
void
dns_delegset_freedeleg(dns_delegset_t *delegset, dns_deleg_t **delegp);

/*
 * Add a new IP into a delegation. Can't be used on a delegation from a
 * delegation set already attached in the DB.
 */
void
dns_delegset_addaddr(dns_delegset_t *delegset, dns_deleg_t *deleg,
		     const isc_netaddr_t *addr);

/*
 * Add a new DELEGPARAM name into a delegation. Can't be used on a delegation
 * from a delegation set already attached in the DB.
 */
void
dns_delegset_adddelegparam(dns_delegset_t *delegset, dns_deleg_t *deleg,
			   const dns_name_t *name);

/*
 * Add a new nameserver name into a delegation. Can't be used on a delegation
 * from a delegation set already attached in the DB.
 */
void
dns_delegset_addns(dns_delegset_t *delegset, dns_deleg_t *deleg,
		   const dns_name_t *name);

/*
 * Add a delegation set into the DB for the given zonecut and a time to live. If
 * a delegation already exists and is not expired, ISC_R_EXISTS is returned and
 * the DB is not altered.
 *
 * This function also cleanup least recently used delegation is the database in
 * an overmemory conditions (See dns_deleg_setsize()).
 *
 * TODO: once DELEG is supported, attempting to add a delegation from NS
 * where a delegation from DELEG already exists would be rejected too.
 */
isc_result_t
dns_delegset_insert(dns_delegdb_t *db, const dns_name_t *zonecut, dns_ttl_t ttl,
		    dns_delegset_t *delegset);

/*
 * Dump the database in a textual format for a given name. If `expired` is
 * false, only the non expired entries are shown. All entries are shown
 * otherwise.
 */
void
dns_delegdb_dump(dns_delegdb_t *db, bool expired, FILE *fp);

/*
 * Convert an NS rdataset into a delegset containing a single delegation
 * (with possibly multiple nameserver). The allocated delegset is using the
 * main memory context, thus, is not expected to be added into the deleg DB
 * (which accepts only delegset allocated using `dns_deleg_alloc*()` APIs.
 */
void
dns_delegset_fromnsrdataset(isc_mem_t *mctx, dns_rdataset_t *rdataset,
			    dns_delegset_t **delegsetp);

/*
 * Delete a delegation matching a name. If `tree` is true, this will also
 * delete all names below `name`.
 */
isc_result_t
dns_delegdb_delete(dns_delegdb_t *db, const dns_name_t *name, bool tree);

/*
 * Defines the size of the delegation cache. Whenever the effective cache
 * size comes close to this size, least recently used cache entries are
 * discarded. Value `0` means there is no limitation.
 */
void
dns_delegdb_setsize(dns_delegdb_t *db, size_t size);

ISC_REFCOUNT_DECL(dns_delegdb);
