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

#include <isc/async.h>
#include <isc/random.h>
#include <isc/ratelimiter.h>

#include <dns/peer.h>
#include <dns/stats.h>
#include <dns/unreachcache.h>
#include <dns/zone.h>
#include <dns/zonemgr.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

static void
zonemgr_free(dns_zonemgr_t *zmgr);

/***
 ***	Zone manager.
 ***/

static void
setrl(isc_ratelimiter_t *rl, unsigned int *rate, unsigned int value) {
	isc_interval_t interval;
	uint32_t s, ns;
	uint32_t pertic;

	if (value == 0) {
		value = 1;
	}

	if (value == 1) {
		s = 1;
		ns = 0;
		pertic = 1;
	} else if (value <= 10) {
		s = 0;
		ns = 1000000000 / value;
		pertic = 1;
	} else {
		s = 0;
		ns = (1000000000 / value) * 10;
		pertic = 10;
	}

	isc_interval_set(&interval, s, ns);

	isc_ratelimiter_setinterval(rl, &interval);
	isc_ratelimiter_setpertic(rl, pertic);

	*rate = value;
}

void
dns_zonemgr_create(isc_mem_t *mctx, dns_zonemgr_t **zmgrp) {
	dns_zonemgr_t *zmgr = NULL;
	isc_loop_t *loop = isc_loop();

	REQUIRE(mctx != NULL);
	REQUIRE(zmgrp != NULL && *zmgrp == NULL);

	zmgr = isc_mem_get(mctx, sizeof(*zmgr));

	*zmgr = (dns_zonemgr_t){
		.workers = isc_loopmgr_nloops(),
		.transfersin = 10,
		.transfersperns = 2,
	};

	isc_refcount_init(&zmgr->refs, 1);
	isc_mem_attach(mctx, &zmgr->mctx);

	ISC_LIST_INIT(zmgr->zones);
	ISC_LIST_INIT(zmgr->waiting_for_xfrin);
	ISC_LIST_INIT(zmgr->xfrin_in_progress);
	isc_rwlock_init(&zmgr->rwlock);

	isc_ratelimiter_create(loop, &zmgr->checkdsrl);
	isc_ratelimiter_create(loop, &zmgr->notifyrl);
	isc_ratelimiter_create(loop, &zmgr->refreshrl);
	isc_ratelimiter_create(loop, &zmgr->startupnotifyrl);
	isc_ratelimiter_create(loop, &zmgr->startuprefreshrl);

	zmgr->mctxpool = isc_mem_cget(zmgr->mctx, zmgr->workers,
				      sizeof(zmgr->mctxpool[0]));
	for (size_t i = 0; i < zmgr->workers; i++) {
		isc_mem_create("zonemgr-mctxpool", &zmgr->mctxpool[i]);
	}

	/* Default to 20 refresh queries / notifies / checkds per second. */
	setrl(zmgr->checkdsrl, &zmgr->checkdsrate, 20);
	setrl(zmgr->notifyrl, &zmgr->notifyrate, 20);
	setrl(zmgr->startupnotifyrl, &zmgr->startupnotifyrate, 20);
	setrl(zmgr->refreshrl, &zmgr->serialqueryrate, 20);
	setrl(zmgr->startuprefreshrl, &zmgr->startupserialqueryrate, 20);
	isc_ratelimiter_setpushpop(zmgr->startupnotifyrl, true);
	isc_ratelimiter_setpushpop(zmgr->startuprefreshrl, true);

	zmgr->tlsctx_cache = NULL;
	isc_rwlock_init(&zmgr->tlsctx_cache_rwlock);

	zmgr->magic = ZONEMGR_MAGIC;

	*zmgrp = zmgr;
}

isc_result_t
dns_zonemgr_createzone(dns_zonemgr_t *zmgr, dns_zone_t **zonep) {
	isc_mem_t *mctx = NULL;
	dns_zone_t *zone = NULL;
	isc_tid_t tid;

	REQUIRE(DNS_ZONEMGR_VALID(zmgr));
	REQUIRE(zonep != NULL && *zonep == NULL);

	if (zmgr->mctxpool == NULL) {
		return ISC_R_FAILURE;
	}

	tid = isc_random_uniform(zmgr->workers);

	mctx = zmgr->mctxpool[tid];
	if (mctx == NULL) {
		return ISC_R_FAILURE;
	}

	dns_zone_create(&zone, mctx, tid);

	*zonep = zone;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_zonemgr_managezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK_ZONE(zone);
	REQUIRE(zone->timer == NULL);
	REQUIRE(zone->zmgr == NULL);

	isc_loop_t *loop = isc_loop_get(zone->tid);
	isc_loop_attach(loop, &zone->loop);

	ISC_LIST_APPEND(zmgr->zones, zone, link);
	zone->zmgr = zmgr;

	isc_refcount_increment(&zmgr->refs);

	UNLOCK_ZONE(zone);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	return ISC_R_SUCCESS;
}

void
dns_zonemgr_releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));
	REQUIRE(zone->zmgr == zmgr);

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK_ZONE(zone);

	ISC_LIST_UNLINK(zmgr->zones, zone, link);

	if (zone->timer != NULL) {
		isc_refcount_decrement(&zone->irefs);
		isc_timer_destroy(&zone->timer);
	}

	isc_loop_detach(&zone->loop);

	/* Detach below, outside of the write lock. */
	zone->zmgr = NULL;

	UNLOCK_ZONE(zone);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);

	dns_zonemgr_detach(&zmgr);
}

void
dns_zonemgr_attach(dns_zonemgr_t *source, dns_zonemgr_t **target) {
	REQUIRE(DNS_ZONEMGR_VALID(source));
	REQUIRE(target != NULL && *target == NULL);

	isc_refcount_increment(&source->refs);

	*target = source;
}

void
dns_zonemgr_detach(dns_zonemgr_t **zmgrp) {
	dns_zonemgr_t *zmgr;

	REQUIRE(zmgrp != NULL);
	zmgr = *zmgrp;
	*zmgrp = NULL;
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	if (isc_refcount_decrement(&zmgr->refs) == 1) {
		zonemgr_free(zmgr);
	}
}

isc_result_t
dns_zonemgr_forcemaint(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_read);
	ISC_LIST_FOREACH(zmgr->zones, zone, link) {
		LOCK_ZONE(zone);
		dns__zone_settimer(zone, isc_time_now());
		UNLOCK_ZONE(zone);
	}
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_read);

	/*
	 * Recent configuration changes may have increased the
	 * amount of available transfers quota.  Make sure any
	 * transfers currently blocked on quota get started if
	 * possible.
	 */
	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	dns__zonemgr_resume_xfrs(zmgr, true);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	return ISC_R_SUCCESS;
}

void
dns_zonemgr_shutdown(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	isc_ratelimiter_shutdown(zmgr->checkdsrl);
	isc_ratelimiter_shutdown(zmgr->notifyrl);
	isc_ratelimiter_shutdown(zmgr->refreshrl);
	isc_ratelimiter_shutdown(zmgr->startupnotifyrl);
	isc_ratelimiter_shutdown(zmgr->startuprefreshrl);

	for (size_t i = 0; i < zmgr->workers; i++) {
		isc_mem_detach(&zmgr->mctxpool[i]);
	}

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_read);
	ISC_LIST_FOREACH(zmgr->zones, zone, link) {
		LOCK_ZONE(zone);
		dns__zone_forward_cancel(zone);
		UNLOCK_ZONE(zone);
	}
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_read);
}

static void
zonemgr_free(dns_zonemgr_t *zmgr) {
	REQUIRE(ISC_LIST_EMPTY(zmgr->zones));

	zmgr->magic = 0;

	isc_refcount_destroy(&zmgr->refs);
	isc_ratelimiter_detach(&zmgr->checkdsrl);
	isc_ratelimiter_detach(&zmgr->notifyrl);
	isc_ratelimiter_detach(&zmgr->refreshrl);
	isc_ratelimiter_detach(&zmgr->startupnotifyrl);
	isc_ratelimiter_detach(&zmgr->startuprefreshrl);

	isc_mem_cput(zmgr->mctx, zmgr->mctxpool, zmgr->workers,
		     sizeof(zmgr->mctxpool[0]));

	isc_rwlock_destroy(&zmgr->rwlock);
	isc_rwlock_destroy(&zmgr->tlsctx_cache_rwlock);

	if (zmgr->tlsctx_cache != NULL) {
		isc_tlsctx_cache_detach(&zmgr->tlsctx_cache);
	}
	isc_mem_putanddetach(&zmgr->mctx, zmgr, sizeof(*zmgr));
}

void
dns_zonemgr_settransfersin(dns_zonemgr_t *zmgr, uint32_t value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	zmgr->transfersin = value;
}

uint32_t
dns_zonemgr_gettransfersin(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return zmgr->transfersin;
}

void
dns_zonemgr_settransfersperns(dns_zonemgr_t *zmgr, uint32_t value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	zmgr->transfersperns = value;
}

uint32_t
dns_zonemgr_gettransfersperns(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return zmgr->transfersperns;
}

/*
 * Try to start a new incoming zone transfer to fill a quota
 * slot that was just vacated.
 *
 * Requires:
 *	The zone manager is locked by the caller.
 */
void
dns__zonemgr_resume_xfrs(dns_zonemgr_t *zmgr, bool multi) {
	ISC_LIST_FOREACH(zmgr->waiting_for_xfrin, zone, statelink) {
		isc_result_t result;
		result = dns__zonemgr_start_xfrin_ifquota(zmgr, zone);
		if (result == ISC_R_SUCCESS) {
			if (multi) {
				continue;
			}
			/*
			 * We successfully filled the slot.  We're done.
			 */
			break;
		} else if (result == ISC_R_QUOTA) {
			/*
			 * Not enough quota.  This is probably the per-server
			 * quota, because we usually get called when a unit of
			 * global quota has just been freed.  Try the next
			 * zone, it may succeed if it uses another primary.
			 */
			continue;
		} else {
			dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN,
				      ISC_LOG_DEBUG(1),
				      "starting zone transfer: %s",
				      isc_result_totext(result));
			break;
		}
	}
}

/*
 * This event callback is called when a zone has received
 * any necessary zone transfer quota.  This is the time
 * to go ahead and start the transfer.
 */
static void
got_transfer_quota(void *arg) {
	dns_zone_t *zone = (dns_zone_t *)arg;
	isc_result_t result = ISC_R_SUCCESS;
	dns_peer_t *peer = NULL;
	char primary[ISC_SOCKADDR_FORMATSIZE];
	char source[ISC_SOCKADDR_FORMATSIZE];
	dns_rdatatype_t xfrtype;
	uint32_t ixfr_maxdiffs = 0;
	isc_netaddr_t primaryip;
	isc_sockaddr_t primaryaddr;
	isc_sockaddr_t sourceaddr;
	dns_transport_type_t soa_transport_type = DNS_TRANSPORT_NONE;
	const char *soa_before = "";
	bool loaded;
	isc_tlsctx_cache_t *zmgr_tlsctx_cache = NULL;
	dns_xfrin_t *xfr = NULL;

	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING)) {
		dns__zone_xfrdone(zone, NULL, ISC_R_CANCELED);
		return;
	}

	primaryaddr = dns_remote_curraddr(&zone->primaries);
	isc_sockaddr_format(&primaryaddr, primary, sizeof(primary));
	if (dns_unreachcache_find(zone->view->unreachcache, &primaryaddr,
				  &zone->sourceaddr) == ISC_R_SUCCESS)
	{
		isc_sockaddr_format(&zone->sourceaddr, source, sizeof(source));
		dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_INFO,
			      "got_transfer_quota: skipping zone transfer as "
			      "primary %s (source %s) is unreachable (cached)",
			      primary, source);
		dns__zone_xfrdone(zone, NULL, ISC_R_CANCELED);
		return;
	}

	isc_netaddr_fromsockaddr(&primaryip, &primaryaddr);
	(void)dns_peerlist_peerbyaddr(zone->view->peers, &primaryip, &peer);

	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_SOABEFOREAXFR)) {
		soa_before = "SOA before ";
	}
	/*
	 * Decide whether we should request IXFR or AXFR.
	 */
	ZONEDB_LOCK(&zone->dblock, isc_rwlocktype_read);
	loaded = (zone->db != NULL);
	ZONEDB_UNLOCK(&zone->dblock, isc_rwlocktype_read);

	if (!loaded) {
		dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_DEBUG(1),
			      "no database exists yet, requesting AXFR of "
			      "initial version from %s",
			      primary);
		xfrtype = dns_rdatatype_axfr;
	} else if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_FORCEXFER)) {
		dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_DEBUG(1),
			      "forced reload, requesting AXFR of "
			      "initial version from %s",
			      primary);
		xfrtype = dns_rdatatype_axfr;
	} else if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NOIXFR)) {
		dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_DEBUG(1),
			      "retrying with AXFR from %s due to "
			      "previous IXFR failure",
			      primary);
		xfrtype = dns_rdatatype_axfr;
		LOCK_ZONE(zone);
		DNS_ZONE_CLRFLAG(zone, DNS_ZONEFLG_NOIXFR);
		UNLOCK_ZONE(zone);
	} else {
		bool use_ixfr = true;

		if (peer != NULL) {
			result = dns_peer_getrequestixfr(peer, &use_ixfr);
		}
		if (peer == NULL || result != ISC_R_SUCCESS) {
			use_ixfr = zone->requestixfr;
		}
		if (peer != NULL) {
			result = dns_peer_getrequestixfrmaxdiffs(
				peer, &ixfr_maxdiffs);
		}
		if (peer == NULL || result != ISC_R_SUCCESS) {
			ixfr_maxdiffs = zone->requestixfr_maxdiffs;
		}
		if (!use_ixfr) {
			dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN,
				      ISC_LOG_DEBUG(1),
				      "IXFR disabled, "
				      "requesting %sAXFR from %s",
				      soa_before, primary);
			if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_SOABEFOREAXFR)) {
				xfrtype = dns_rdatatype_soa;
			} else {
				xfrtype = dns_rdatatype_axfr;
			}
		} else {
			dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN,
				      ISC_LOG_DEBUG(1),
				      "requesting IXFR from %s", primary);
			xfrtype = dns_rdatatype_ixfr;
		}
	}

	/*
	 * Determine if we should attempt to sign the request with TSIG.
	 */
	result = ISC_R_NOTFOUND;

	/*
	 * First, look for a tsig key in the primaries statement, then
	 * try for a server key.
	 */
	if (dns_remote_keyname(&zone->primaries) != NULL) {
		dns_view_t *view = dns_zone_getview(zone);
		dns_name_t *keyname = dns_remote_keyname(&zone->primaries);
		result = dns_view_gettsig(view, keyname, &zone->tsigkey);
	}
	if (result != ISC_R_SUCCESS) {
		INSIST(zone->tsigkey == NULL);
		result = dns_view_getpeertsig(zone->view, &primaryip,
					      &zone->tsigkey);
	}
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_ERROR,
			      "could not get TSIG key for zone transfer: %s",
			      isc_result_totext(result));
	}

	/*
	 * Get the TLS transport for the primary, if configured.
	 */
	if (dns_remote_tlsname(&zone->primaries) != NULL) {
		dns_view_t *view = dns_zone_getview(zone);
		dns_name_t *tlsname = dns_remote_tlsname(&zone->primaries);
		result = dns_view_gettransport(view, DNS_TRANSPORT_TLS, tlsname,
					       &zone->transport);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
			dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN,
				      ISC_LOG_ERROR,
				      "could not get TLS configuration for "
				      "zone transfer: %s",
				      isc_result_totext(result));
		}
	}

	if (xfrtype != dns_rdatatype_soa) {
		/*
		 * If 'xfrtype' is dns_rdatatype_soa, then the SOA query will be
		 * performed by xfrin, otherwise, the SOA request performed by
		 * soa_query() was successful and we should inform the xfrin
		 * about the transport type used for that query, so that the
		 * information can be presented in the statistics channel.
		 */
		soa_transport_type = dns_zone_getrequesttransporttype(zone);
	}

	LOCK_ZONE(zone);
	sourceaddr = zone->sourceaddr;
	UNLOCK_ZONE(zone);

	INSIST(isc_sockaddr_pf(&primaryaddr) == isc_sockaddr_pf(&sourceaddr));

	dns__zonemgr_tlsctx_attach(zone->zmgr, &zmgr_tlsctx_cache);

	dns_xfrin_create(zone, xfrtype, ixfr_maxdiffs, &primaryaddr,
			 &sourceaddr, zone->tsigkey, soa_transport_type,
			 zone->transport, zmgr_tlsctx_cache, zone->mctx, &xfr);
	INSIST(xfr != NULL);

	isc_tlsctx_cache_detach(&zmgr_tlsctx_cache);

	LOCK_ZONE(zone);
	if (zone->xfr != NULL) {
		dns_xfrin_detach(&zone->xfr);
	}
	dns_xfrin_attach(xfr, &zone->xfr);
	UNLOCK_ZONE(zone);

	dns_xfrin_detach(&xfr);

	/*
	 * Any failure in this function is handled like a failed
	 * zone transfer.  This ensures that we get removed from
	 * zmgr->xfrin_in_progress.
	 */
	result = dns_xfrin_start(zone->xfr, dns__zone_xfrdone);
	if (result != ISC_R_SUCCESS) {
		dns__zone_xfrdone(zone, NULL, result);
		return;
	}

	LOCK_ZONE(zone);
	if (xfrtype == dns_rdatatype_axfr) {
		if (isc_sockaddr_pf(&primaryaddr) == PF_INET) {
			dns__zone_stats_increment(
				zone, dns_zonestatscounter_axfrreqv4);
		} else {
			dns__zone_stats_increment(
				zone, dns_zonestatscounter_axfrreqv6);
		}
	} else if (xfrtype == dns_rdatatype_ixfr) {
		if (isc_sockaddr_pf(&primaryaddr) == PF_INET) {
			dns__zone_stats_increment(
				zone, dns_zonestatscounter_ixfrreqv4);
		} else {
			dns__zone_stats_increment(
				zone, dns_zonestatscounter_ixfrreqv6);
		}
	}
	UNLOCK_ZONE(zone);
}

/*
 * Try to start an incoming zone transfer for 'zone', quota permitting.
 *
 * Requires:
 *	The zone manager is locked by the caller.
 *
 * Returns:
 *	ISC_R_SUCCESS	There was enough quota and we attempted to
 *			start a transfer.  dns__zone_xfrdone() has been or will
 *			be called.
 *	ISC_R_QUOTA	Not enough quota.
 *	Others		Failure.
 */
isc_result_t
dns__zonemgr_start_xfrin_ifquota(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	dns_peer_t *peer = NULL;
	isc_netaddr_t primaryip;
	isc_sockaddr_t curraddr;
	uint32_t nxfrsin, nxfrsperns;
	uint32_t maxtransfersin, maxtransfersperns;

	/*
	 * If we are exiting just pretend we got quota so the zone will
	 * be cleaned up in the zone's loop context.
	 */
	LOCK_ZONE(zone);
	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING)) {
		UNLOCK_ZONE(zone);
		goto gotquota;
	}

	/*
	 * Find any configured information about the server we'd
	 * like to transfer this zone from.
	 */
	curraddr = dns_remote_curraddr(&zone->primaries);
	isc_netaddr_fromsockaddr(&primaryip, &curraddr);
	(void)dns_peerlist_peerbyaddr(zone->view->peers, &primaryip, &peer);
	UNLOCK_ZONE(zone);

	/*
	 * Determine the total maximum number of simultaneous
	 * transfers allowed, and the maximum for this specific
	 * primary.
	 */
	maxtransfersin = zmgr->transfersin;
	maxtransfersperns = zmgr->transfersperns;
	if (peer != NULL) {
		(void)dns_peer_gettransfers(peer, &maxtransfersperns);
	}

	/*
	 * Count the total number of transfers that are in progress,
	 * and the number of transfers in progress from this primary.
	 * We linearly scan a list of all transfers; if this turns
	 * out to be too slow, we could hash on the primary address.
	 */
	nxfrsin = nxfrsperns = 0;
	ISC_LIST_FOREACH(zmgr->xfrin_in_progress, x, statelink) {
		isc_netaddr_t xip;
		isc_sockaddr_t xaddr;

		LOCK_ZONE(x);
		xaddr = dns_remote_curraddr(&x->primaries);
		isc_netaddr_fromsockaddr(&xip, &xaddr);
		UNLOCK_ZONE(x);

		nxfrsin++;
		if (isc_netaddr_equal(&xip, &primaryip)) {
			nxfrsperns++;
		}
	}

	/* Enforce quota. */
	if (nxfrsin >= maxtransfersin) {
		return ISC_R_QUOTA;
	}

	if (nxfrsperns >= maxtransfersperns) {
		return ISC_R_QUOTA;
	}

gotquota:
	/*
	 * We have sufficient quota.  Move the zone to the "xfrin_in_progress"
	 * list and start the actual transfer asynchronously.
	 */
	LOCK_ZONE(zone);
	INSIST(zone->statelist == &zmgr->waiting_for_xfrin);
	ISC_LIST_UNLINK(zmgr->waiting_for_xfrin, zone, statelink);
	ISC_LIST_APPEND(zmgr->xfrin_in_progress, zone, statelink);
	zone->statelist = &zmgr->xfrin_in_progress;
	isc_async_run(zone->loop, got_transfer_quota, zone);
	dns_zone_logc(zone, DNS_LOGCATEGORY_XFER_IN, ISC_LOG_INFO,
		      "Transfer started.");
	UNLOCK_ZONE(zone);

	return ISC_R_SUCCESS;
}

void
dns_zonemgr_setcheckdsrate(dns_zonemgr_t *zmgr, unsigned int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	setrl(zmgr->checkdsrl, &zmgr->checkdsrate, value);
}

void
dns_zonemgr_setnotifyrate(dns_zonemgr_t *zmgr, unsigned int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	setrl(zmgr->notifyrl, &zmgr->notifyrate, value);
}

void
dns_zonemgr_setstartupnotifyrate(dns_zonemgr_t *zmgr, unsigned int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	setrl(zmgr->startupnotifyrl, &zmgr->startupnotifyrate, value);
}

void
dns_zonemgr_setkeystores(dns_zonemgr_t *zmgr, dns_keystorelist_t *keystores) {
	zmgr->keystores = keystores;
}

void
dns_zonemgr_setserialqueryrate(dns_zonemgr_t *zmgr, unsigned int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	setrl(zmgr->refreshrl, &zmgr->serialqueryrate, value);
	/* XXXMPA separate out once we have the code to support this. */
	setrl(zmgr->startuprefreshrl, &zmgr->startupserialqueryrate, value);
}

unsigned int
dns_zonemgr_getnotifyrate(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return zmgr->notifyrate;
}

void
dns__zonemgr_getnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	*prl = zmgr->notifyrl;
}

unsigned int
dns_zonemgr_getstartupnotifyrate(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return zmgr->startupnotifyrate;
}

void
dns__zonemgr_getstartupnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	*prl = zmgr->startupnotifyrl;
}

unsigned int
dns_zonemgr_getserialqueryrate(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return zmgr->serialqueryrate;
}

unsigned int
dns_zonemgr_getcount(dns_zonemgr_t *zmgr, dns_zonestate_t state) {
	unsigned int count = 0;

	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_read);
	switch (state) {
	case DNS_ZONESTATE_XFERRUNNING:
		ISC_LIST_FOREACH(zmgr->xfrin_in_progress, zone, statelink) {
			count++;
		}
		break;
	case DNS_ZONESTATE_XFERDEFERRED:
		ISC_LIST_FOREACH(zmgr->waiting_for_xfrin, zone, statelink) {
			count++;
		}
		break;
	case DNS_ZONESTATE_XFERFIRSTREFRESH:
		ISC_LIST_FOREACH(zmgr->zones, zone, link) {
			if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_FIRSTREFRESH)) {
				count++;
			}
		}
		break;
	case DNS_ZONESTATE_SOAQUERY:
		ISC_LIST_FOREACH(zmgr->zones, zone, link) {
			if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_REFRESH)) {
				count++;
			}
		}
		break;
	case DNS_ZONESTATE_ANY:
		ISC_LIST_FOREACH(zmgr->zones, zone, link) {
			dns_view_t *view = zone->view;
			if (view != NULL && strcmp(view->name, "_bind") == 0) {
				continue;
			}
			count++;
		}
		break;
	case DNS_ZONESTATE_AUTOMATIC:
		ISC_LIST_FOREACH(zmgr->zones, zone, link) {
			dns_view_t *view = zone->view;
			if (view != NULL && strcmp(view->name, "_bind") == 0) {
				continue;
			}
			if (zone->automatic) {
				count++;
			}
		}
		break;
	default:
		UNREACHABLE();
	}

	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_read);

	return count;
}

isc_result_t
dns_zonemgr_next_zone(dns_zone_t *zone, dns_zone_t **next) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(next != NULL && *next == NULL);

	*next = ISC_LIST_NEXT(zone, link);
	if (*next == NULL) {
		return ISC_R_NOMORE;
	} else {
		return ISC_R_SUCCESS;
	}
}

isc_result_t
dns_zonemgr_first_zone(dns_zonemgr_t *zmgr, dns_zone_t **first) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));
	REQUIRE(first != NULL && *first == NULL);

	*first = ISC_LIST_HEAD(zmgr->zones);
	if (*first == NULL) {
		return ISC_R_NOMORE;
	} else {
		return ISC_R_SUCCESS;
	}
}
