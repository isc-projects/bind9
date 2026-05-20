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

#include <isc/netmgr.h>
#include <isc/ratelimiter.h>
#include <isc/result.h>

#include <dns/adb.h>
#include <dns/notify.h>
#include <dns/peer.h>
#include <dns/rcode.h>
#include <dns/rdatalist.h>
#include <dns/request.h>
#include <dns/stats.h>
#include <dns/tsig.h>
#include <dns/zone.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

static void
notify_log(dns_notify_t *notify, int level, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	dns_zone_logv(notify->zone, DNS_LOGCATEGORY_NOTIFY, level, NULL, fmt,
		      ap);
	va_end(ap);
}

void
dns_notifyctx_init(dns_notifyctx_t *nctx, dns_rdatatype_t type) {
	dns_notifyctx_t ctx = {
		.type = type,
		.notifytype = dns_notifytype_yes,
		.notifydelay = 5,
		.notifies = ISC_LIST_INITIALIZER,
	};
	isc_sockaddr_any(&ctx.notifysrc4);
	isc_sockaddr_any6(&ctx.notifysrc6);

	*nctx = ctx;
}

void
dns_notify_create(isc_mem_t *mctx, dns_rdatatype_t type, in_port_t port,
		  unsigned int flags, dns_notify_t **notifyp) {
	dns_notify_t *notify;

	REQUIRE(notifyp != NULL && *notifyp == NULL);

	notify = isc_mem_get(mctx, sizeof(*notify));
	*notify = (dns_notify_t){
		.flags = flags,
		.port = port,
		.type = type,
	};

	isc_mem_attach(mctx, &notify->mctx);
	isc_sockaddr_any(&notify->src);
	isc_sockaddr_any(&notify->dst);
	dns_name_init(&notify->ns);
	ISC_LINK_INIT(notify, link);
	notify->magic = NOTIFY_MAGIC;
	*notifyp = notify;
}

void
dns_notify_destroy(dns_notify_t *notify, bool locked) {
	REQUIRE(DNS_NOTIFY_VALID(notify));

	isc_mem_t *mctx;
	dns_notifyctx_t *nctx;

	if (notify->zone != NULL) {
		if (!locked) {
			dns__zone_lock(notify->zone);
		}
		REQUIRE(dns__zone_locked(notify->zone));
		nctx = dns__zone_getnotifyctx(notify->zone, notify->type);
		if (ISC_LINK_LINKED(notify, link)) {
			ISC_LIST_UNLINK(nctx->notifies, notify, link);
		}
		if (!locked) {
			dns__zone_unlock(notify->zone);
		}
		if (locked) {
			dns__zone_idetach_locked(&notify->zone);
		} else {
			dns_zone_idetach(&notify->zone);
		}
	}
	if (notify->find != NULL) {
		dns_adb_destroyfind(&notify->find);
	}
	if (notify->request != NULL) {
		dns_request_destroy(&notify->request);
	}
	if (dns_name_dynamic(&notify->ns)) {
		dns_name_free(&notify->ns, notify->mctx);
	}
	if (notify->key != NULL) {
		dns_tsigkey_detach(&notify->key);
	}
	if (notify->transport != NULL) {
		dns_transport_detach(&notify->transport);
	}
	mctx = notify->mctx;
	isc_mem_put(notify->mctx, notify, sizeof(*notify));
	isc_mem_detach(&mctx);
}

static void
notify_done(void *arg) {
	dns_request_t *request = (dns_request_t *)arg;
	dns_notify_t *notify = dns_request_getarg(request);
	isc_result_t result;
	dns_message_t *message = NULL;
	isc_buffer_t buf;
	char rcode[128];
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];

	REQUIRE(DNS_NOTIFY_VALID(notify));

	isc_buffer_init(&buf, rcode, sizeof(rcode));
	isc_sockaddr_format(&notify->dst, addrbuf, sizeof(addrbuf));

	dns_rdatatype_format(notify->type, typebuf, sizeof(typebuf));

	/* WMM: This is changing the mctx from zone to notify. */
	dns_message_create(notify->mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE,
			   &message);

	result = dns_request_getresult(request);
	if (result != ISC_R_SUCCESS) {
		goto fail;
	}

	result = dns_request_getresponse(request, message,
					 DNS_MESSAGEPARSE_PRESERVEORDER);
	if (result != ISC_R_SUCCESS) {
		goto fail;
	}

	result = dns_rcode_totext(message->rcode, &buf);
	if (result == ISC_R_SUCCESS) {
		notify_log(notify, ISC_LOG_DEBUG(3),
			   "notify(%s) response from %s: %.*s", typebuf,
			   addrbuf, (int)buf.used, rcode);
	}
fail:
	dns_message_detach(&message);

	if (result == ISC_R_SUCCESS) {
		notify_log(notify, ISC_LOG_DEBUG(1),
			   "notify(%s) to %s successful", typebuf, addrbuf);
	} else if (result == ISC_R_SHUTTINGDOWN || result == ISC_R_CANCELED) {
		/* just destroy the notify */
	} else if ((notify->flags & DNS_NOTIFY_TCP) == 0) {
		notify_log(notify, ISC_LOG_NOTICE,
			   "notify(%s) to %s failed: %s: retrying over TCP",
			   typebuf, addrbuf, isc_result_totext(result));
		notify->flags |= DNS_NOTIFY_TCP;
		dns_request_destroy(&notify->request);
		dns_notify_queue(notify, notify->flags & DNS_NOTIFY_STARTUP);
		return;
	} else if (result == ISC_R_TIMEDOUT) {
		notify_log(notify, ISC_LOG_WARNING,
			   "notify(%s) to %s failed: %s: retries exceeded",
			   typebuf, addrbuf, isc_result_totext(result));
	} else {
		notify_log(notify, ISC_LOG_WARNING,
			   "notify(%s) to %s failed: %s", typebuf, addrbuf,
			   isc_result_totext(result));
	}
	dns_notify_destroy(notify, false);
}

static isc_result_t
notify_createmessage(dns_notify_t *notify, dns_message_t **messagep) {
	dns_db_t *zonedb = NULL;
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	dns_message_t *message = NULL;
	dns_rdataset_t rdataset;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	dns_name_t *tempname = NULL;
	dns_rdata_t *temprdata = NULL;
	dns_rdatalist_t *temprdatalist = NULL;
	dns_rdataset_t *temprdataset = NULL;

	isc_result_t result;
	isc_region_t r;
	isc_buffer_t *b = NULL;

	REQUIRE(DNS_NOTIFY_VALID(notify));
	REQUIRE(messagep != NULL && *messagep == NULL);

	/* WMM: This is changing the mctx from zone to notify. */
	dns_message_create(notify->mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER,
			   &message);

	message->opcode = dns_opcode_notify;
	message->flags |= DNS_MESSAGEFLAG_AA;
	message->rdclass = dns_zone_getclass(notify->zone);

	dns_message_gettempname(message, &tempname);
	dns_message_gettemprdataset(message, &temprdataset);

	/*
	 * Make question.
	 */
	dns_name_clone(dns_zone_getorigin(notify->zone), tempname);
	dns_rdataset_makequestion(temprdataset, dns_zone_getclass(notify->zone),
				  dns_rdatatype_soa);
	ISC_LIST_APPEND(tempname->list, temprdataset, link);
	dns_message_addname(message, tempname, DNS_SECTION_QUESTION);
	tempname = NULL;
	temprdataset = NULL;

	if ((notify->flags & DNS_NOTIFY_NOSOA) != 0) {
		goto done;
	}

	dns_message_gettempname(message, &tempname);
	dns_message_gettemprdata(message, &temprdata);
	dns_message_gettemprdataset(message, &temprdataset);
	dns_message_gettemprdatalist(message, &temprdatalist);

	result = dns_zone_getdb(notify->zone, &zonedb);
	INSIST(result == ISC_R_SUCCESS);
	INSIST(zonedb != NULL); /* XXXJT: is this assumption correct? */

	dns_name_clone(dns_zone_getorigin(notify->zone), tempname);
	dns_db_currentversion(zonedb, &version);
	result = dns_db_findnode(zonedb, tempname, false, &node);
	if (result != ISC_R_SUCCESS) {
		goto soa_cleanup;
	}

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(zonedb, node, version, dns_rdatatype_soa,
				     dns_rdatatype_none, 0, &rdataset, NULL);
	if (result != ISC_R_SUCCESS) {
		goto soa_cleanup;
	}
	result = dns_rdataset_first(&rdataset);
	if (result != ISC_R_SUCCESS) {
		goto soa_cleanup;
	}
	dns_rdataset_current(&rdataset, &rdata);
	dns_rdata_toregion(&rdata, &r);
	/* WMM: This is changing the mctx from zone to notify. */
	isc_buffer_allocate(notify->mctx, &b, r.length);
	isc_buffer_putmem(b, r.base, r.length);
	isc_buffer_usedregion(b, &r);
	dns_rdata_fromregion(temprdata, rdata.rdclass, rdata.type, &r);
	dns_message_takebuffer(message, &b);
	result = dns_rdataset_next(&rdataset);
	dns_rdataset_disassociate(&rdataset);
	if (result != ISC_R_NOMORE) {
		goto soa_cleanup;
	}
	temprdatalist->rdclass = rdata.rdclass;
	temprdatalist->type = rdata.type;
	temprdatalist->ttl = rdataset.ttl;
	ISC_LIST_APPEND(temprdatalist->rdata, temprdata, link);

	dns_rdatalist_tordataset(temprdatalist, temprdataset);

	ISC_LIST_APPEND(tempname->list, temprdataset, link);
	dns_message_addname(message, tempname, DNS_SECTION_ANSWER);
	temprdatalist = NULL;
	temprdataset = NULL;
	temprdata = NULL;
	tempname = NULL;

soa_cleanup:
	if (node != NULL) {
		dns_db_detachnode(&node);
	}
	if (version != NULL) {
		dns_db_closeversion(zonedb, &version, false);
	}
	if (zonedb != NULL) {
		dns_db_detach(&zonedb);
	}
	if (tempname != NULL) {
		dns_message_puttempname(message, &tempname);
	}
	if (temprdata != NULL) {
		dns_message_puttemprdata(message, &temprdata);
	}
	if (temprdataset != NULL) {
		dns_message_puttemprdataset(message, &temprdataset);
	}
	if (temprdatalist != NULL) {
		dns_message_puttemprdatalist(message, &temprdatalist);
	}

done:
	*messagep = message;
	return ISC_R_SUCCESS;
}

static void
notify_send_toaddr(void *arg) {
	dns_notify_t *notify = (dns_notify_t *)arg;
	dns_notifyctx_t *notifyctx = NULL;
	isc_result_t result;
	dns_db_t *zonedb = NULL;
	dns_view_t *view = NULL;
	isc_loop_t *loop = NULL;
	dns_zonemgr_t *zmgr = NULL;
	dns_message_t *message = NULL;
	isc_netaddr_t dstip;
	dns_tsigkey_t *key = NULL;
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];
	isc_sockaddr_t src;
	unsigned int options;
	bool have_notifysource = false;
	isc_tlsctx_cache_t *zmgr_tlsctx_cache = NULL;

	REQUIRE(DNS_NOTIFY_VALID(notify));

	dns__zone_lock(notify->zone);

	notifyctx = dns__zone_getnotifyctx(notify->zone, notify->type);
	zmgr = dns_zone_getmgr(notify->zone);
	view = dns_zone_getview(notify->zone);
	loop = dns_zone_getloop(notify->zone);
	result = dns_zone_getdb(notify->zone, &zonedb);

	isc_sockaddr_format(&notify->dst, addrbuf, sizeof(addrbuf));

	dns_rdatatype_format(notify->type, typebuf, sizeof(typebuf));

	if (!dns__zone_loaded(notify->zone) || notify->rlevent->canceled ||
	    dns__zone_exiting(notify->zone) || zmgr == NULL || view == NULL ||
	    view->requestmgr == NULL || loop == NULL || zonedb == NULL ||
	    result != ISC_R_SUCCESS)
	{
		result = ISC_R_CANCELED;
		goto cleanup;
	}

	/*
	 * The raw IPv4 address should also exist.  Don't send to the
	 * mapped form.
	 */
	if (isc_sockaddr_pf(&notify->dst) == PF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&notify->dst.type.sin6.sin6_addr))
	{
		notify_log(notify, ISC_LOG_DEBUG(3),
			   "notify(%s): ignoring IPv6 mapped IPV4 address: %s",
			   typebuf, addrbuf);
		result = ISC_R_CANCELED;
		goto cleanup;
	}

	CHECK(notify_createmessage(notify, &message));

	if (notify->key != NULL) {
		/* Transfer ownership of key */
		key = notify->key;
		notify->key = NULL;
	} else {
		isc_netaddr_fromsockaddr(&dstip, &notify->dst);
		result = dns_view_getpeertsig(view, &dstip, &key);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
			notify_log(notify, ISC_LOG_ERROR,
				   "NOTIFY(%s) to %s not sent. "
				   "Peer TSIG key lookup failure.",
				   typebuf, addrbuf);
			goto cleanup_message;
		}
	}

	if (key != NULL) {
		char namebuf[DNS_NAME_FORMATSIZE];

		dns_name_format(key->name, namebuf, sizeof(namebuf));
		notify_log(notify, ISC_LOG_INFO,
			   "sending notify(%s) to %s : TSIG (%s)", typebuf,
			   addrbuf, namebuf);
	} else {
		notify_log(notify, ISC_LOG_INFO, "sending notify(%s) to %s",
			   typebuf, addrbuf);
	}
	options = 0;
	if (view->peers != NULL) {
		dns_peer_t *peer = NULL;
		bool usetcp = false;
		result = dns_peerlist_peerbyaddr(view->peers, &dstip, &peer);
		if (result == ISC_R_SUCCESS) {
			result = dns_peer_getnotifysource(peer, &src);
			if (result == ISC_R_SUCCESS) {
				have_notifysource = true;
			}
			result = dns_peer_getforcetcp(peer, &usetcp);
			if (result == ISC_R_SUCCESS && usetcp) {
				options |= DNS_FETCHOPT_TCP;
			}
		}
	}
	switch (isc_sockaddr_pf(&notify->dst)) {
	case PF_INET:
		if (!have_notifysource) {
			isc_sockaddr_t any;
			isc_sockaddr_any(&any);

			src = notify->src;
			if (isc_sockaddr_equal(&src, &any)) {
				src = notifyctx->notifysrc4;
			}
		}
		break;
	case PF_INET6:
		if (!have_notifysource) {
			isc_sockaddr_t any;
			isc_sockaddr_any6(&any);

			src = notify->src;
			if (isc_sockaddr_equal(&src, &any)) {
				src = notifyctx->notifysrc6;
			}
		}
		break;
	default:
		result = ISC_R_NOTIMPLEMENTED;
		goto cleanup_key;
	}

again:
	if ((notify->flags & DNS_NOTIFY_TCP) != 0) {
		options |= DNS_REQUESTOPT_TCP;
	}

	dns__zonemgr_tlsctx_attach(zmgr, &zmgr_tlsctx_cache);

	const unsigned int connect_timeout = isc_nm_getinitialtimeout() /
					     MS_PER_SEC;
	result = dns_request_create(
		view->requestmgr, message, &src, &notify->dst,
		notify->transport, zmgr_tlsctx_cache, options, key,
		connect_timeout, TCP_REQUEST_TIMEOUT, UDP_REQUEST_TIMEOUT,
		UDP_REQUEST_RETRIES, loop, notify_done, notify,
		&notify->request);

	isc_tlsctx_cache_detach(&zmgr_tlsctx_cache);

	switch (result) {
	case ISC_R_SUCCESS:
		if (isc_sockaddr_pf(&notify->dst) == AF_INET) {
			dns__zone_stats_increment(
				notify->zone, dns_zonestatscounter_notifyoutv4);
		} else {
			dns__zone_stats_increment(
				notify->zone, dns_zonestatscounter_notifyoutv6);
		}
		break;
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
	case ISC_R_ADDRNOTAVAIL:
	case DNS_R_BLACKHOLED:
	case ISC_R_FAMILYNOSUPPORT:
		notify_log(notify, ISC_LOG_NOTICE,
			   "notify(%s) to %s failed: %s", typebuf, addrbuf,
			   isc_result_totext(result));
		break;
	default:
		if ((notify->flags & DNS_NOTIFY_TCP) == 0) {
			notify_log(notify, ISC_LOG_NOTICE,
				   "notify(%s) to %s failed: %s: retrying over "
				   "TCP",
				   typebuf, addrbuf, isc_result_totext(result));
			notify->flags |= DNS_NOTIFY_TCP;
			goto again;
		}
	}

cleanup_key:
	if (key != NULL) {
		dns_tsigkey_detach(&key);
	}
cleanup_message:
	dns_message_detach(&message);
cleanup:
	dns__zone_unlock(notify->zone);

	if (zonedb != NULL) {
		dns_db_detach(&zonedb);
	}

	if (notify->rlevent != NULL) {
		isc_rlevent_free(&notify->rlevent);
	}

	if (result != ISC_R_SUCCESS) {
		isc_sockaddr_format(&notify->dst, addrbuf, sizeof(addrbuf));
		notify_log(notify, ISC_LOG_WARNING,
			   "notify(%s) to %s failed: %s", typebuf, addrbuf,
			   isc_result_totext(result));
		dns_notify_destroy(notify, false);
	}
}

static isc_result_t
notify_queue(dns_notify_t *notify, bool startup, bool dequeue) {
	REQUIRE(DNS_NOTIFY_VALID(notify));

	isc_loop_t *loop = dns_zone_getloop(notify->zone);
	dns_zonemgr_t *zmgr = dns_zone_getmgr(notify->zone);
	isc_ratelimiter_t *notifyrl = NULL;
	isc_ratelimiter_t *startupnotifyrl = NULL;

	INSIST(loop != NULL);
	INSIST(zmgr != NULL);

	dns__zonemgr_getnotifyrl(zmgr, &notifyrl);
	dns__zonemgr_getstartupnotifyrl(zmgr, &startupnotifyrl);

	if (dequeue) {
		return isc_ratelimiter_dequeue(
			startup ? startupnotifyrl : notifyrl, &notify->rlevent);
	}

	return isc_ratelimiter_enqueue(startup ? startupnotifyrl : notifyrl,
				       loop, notify_send_toaddr, notify,
				       &notify->rlevent);
}

isc_result_t
dns_notify_queue(dns_notify_t *notify, bool startup) {
	return notify_queue(notify, startup, false);
}

bool
dns_notify_isqueued(dns_notifyctx_t *nctx, dns_rdatatype_t type, in_port_t port,
		    unsigned int flags, dns_name_t *name, isc_sockaddr_t *addr,
		    dns_tsigkey_t *key, dns_transport_t *transport) {
	dns_notify_t *notify = NULL;
	isc_result_t result;

	REQUIRE(nctx != NULL);

	ISC_LIST_FOREACH(nctx->notifies, n, link) {
		if (n->request != NULL) {
			continue;
		}
		if (n->type != type) {
			continue;
		}
		if ((name != NULL && dns_name_dynamic(&n->ns) &&
		     dns_name_equal(name, &n->ns)) ||
		    (addr != NULL && isc_sockaddr_equal(addr, &n->dst) &&
		     n->port == port && n->key == key &&
		     n->transport == transport))
		{
			notify = n;
			goto requeue;
		}
	}
	return false;
requeue:
	/*
	 * If we are enqueued on the startup ratelimiter and this is
	 * not a startup notify, re-enqueue on the normal notify
	 * ratelimiter.
	 */
	if (notify->rlevent != NULL && (flags & DNS_NOTIFY_STARTUP) == 0 &&
	    (notify->flags & DNS_NOTIFY_STARTUP) != 0)
	{
		result = notify_queue(notify, true, true);
		if (result != ISC_R_SUCCESS) {
			return true;
		}

		notify->flags &= ~DNS_NOTIFY_STARTUP;
		result = notify_queue(notify, false, false);
		if (result != ISC_R_SUCCESS) {
			return false;
		}
	}

	return true;
}

static bool
notify_isself(dns_notify_t *notify, isc_sockaddr_t *dst) {
	dns_tsigkey_t *key = NULL;
	isc_sockaddr_t src;
	isc_sockaddr_t any;
	bool isself;
	isc_netaddr_t dstaddr;
	isc_result_t result;
	dns_notifyctx_t *notifyctx = NULL;
	dns_view_t *view = NULL;
	dns_isselffunc_t isselffunc;
	void *isselfarg = NULL;

	notifyctx = dns__zone_getnotifyctx(notify->zone, notify->type);
	view = dns_zone_getview(notify->zone);
	dns__zone_getisself(notify->zone, &isselffunc, &isselfarg);
	if (view == NULL || isselffunc == NULL) {
		return false;
	}

	switch (isc_sockaddr_pf(dst)) {
	case PF_INET:
		src = notifyctx->notifysrc4;
		isc_sockaddr_any(&any);
		break;
	case PF_INET6:
		src = notifyctx->notifysrc6;
		isc_sockaddr_any6(&any);
		break;
	default:
		return false;
	}

	/*
	 * When sending from any the kernel will assign a source address
	 * that matches the destination address.
	 */
	if (isc_sockaddr_eqaddr(&any, &src)) {
		src = *dst;
	}

	isc_netaddr_fromsockaddr(&dstaddr, dst);
	result = dns_view_getpeertsig(view, &dstaddr, &key);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		return false;
	}
	isself = (isselffunc)(view, key, &src, dst,
			      dns_zone_getclass(notify->zone), isselfarg);
	if (key != NULL) {
		dns_tsigkey_detach(&key);
	}
	return isself;
}

static void
notify_send(dns_notify_t *notify) {
	isc_sockaddr_t dst;
	isc_result_t result;
	dns_notify_t *newnotify = NULL;
	dns_notifyctx_t *notifyctx = NULL;
	unsigned int flags;
	bool startup;

	/*
	 * Zone lock held by caller.
	 */
	REQUIRE(DNS_NOTIFY_VALID(notify));
	REQUIRE(dns__zone_locked(notify->zone));
	if (dns__zone_exiting(notify->zone)) {
		return;
	}
	notifyctx = dns__zone_getnotifyctx(notify->zone, notify->type);

	ISC_LIST_FOREACH(notify->find->list, ai, publink) {
		dst = ai->sockaddr;
		if (dns_notify_isqueued(notifyctx, notify->type, notify->port,
					notify->flags, NULL, &dst, NULL, NULL))
		{
			continue;
		}
		if (notify_isself(notify, &dst)) {
			continue;
		}
		newnotify = NULL;
		flags = notify->flags & DNS_NOTIFY_NOSOA;
		dns_notify_create(notify->mctx, notify->type, notify->port,
				  flags, &newnotify);
		dns__zone_iattach_locked(notify->zone, &newnotify->zone);
		ISC_LIST_APPEND(notifyctx->notifies, newnotify, link);
		newnotify->dst = dst;
		if (isc_sockaddr_pf(&dst) == AF_INET6) {
			isc_sockaddr_any6(&newnotify->src);
		}
		startup = ((notify->flags & DNS_NOTIFY_STARTUP) != 0);
		CHECK(dns_notify_queue(newnotify, startup));
		newnotify = NULL;
	}

cleanup:
	if (newnotify != NULL) {
		dns_notify_destroy(newnotify, true);
	}
}

/*
 * XXXAG should check for DNS_ZONEFLG_EXITING
 */
static void
process_notify_adb_event(void *arg) {
	dns_adbfind_t *find = (dns_adbfind_t *)arg;
	dns_notify_t *notify = (dns_notify_t *)find->cbarg;
	dns_adbstatus_t astat = find->status;

	REQUIRE(DNS_NOTIFY_VALID(notify));
	REQUIRE(find == notify->find);

	switch (astat) {
	case DNS_ADB_MOREADDRESSES:
		dns_adb_destroyfind(&notify->find);
		dns_notify_find_address(notify);
		return;

	case DNS_ADB_NOMOREADDRESSES:
		dns__zone_lock(notify->zone);
		notify_send(notify);
		dns__zone_unlock(notify->zone);
		break;

	default:
		break;
	}

	dns_notify_destroy(notify, false);
}

void
dns_notify_find_address(dns_notify_t *notify) {
	isc_result_t result;
	unsigned int options;
	dns_adb_t *adb = NULL;
	dns_view_t *view = NULL;
	isc_loop_t *loop = NULL;

	REQUIRE(DNS_NOTIFY_VALID(notify));

	options = DNS_ADBFIND_WANTEVENT;
	if (isc_net_probeipv4() != ISC_R_DISABLED) {
		options |= DNS_ADBFIND_INET;
	}
	if (isc_net_probeipv6() != ISC_R_DISABLED) {
		options |= DNS_ADBFIND_INET6;
	}

	loop = dns_zone_getloop(notify->zone);
	view = dns_zone_getview(notify->zone);
	dns_view_getadb(view, &adb);
	if (loop == NULL || view == NULL || adb == NULL) {
		goto destroy;
	}

	result = dns_adb_createfind(
		adb, loop, process_notify_adb_event, notify, &notify->ns,
		options, 0, notify->port, 0, NULL, NULL, NULL,
		view->max_delegation_servers, &notify->find, NULL);
	dns_adb_detach(&adb);

	/* Something failed? */
	if (result != ISC_R_SUCCESS) {
		goto destroy;
	}

	/* More addresses pending? */
	if ((notify->find->options & DNS_ADBFIND_WANTEVENT) != 0) {
		return;
	}

	/* We have as many addresses as we can get. */
	dns__zone_lock(notify->zone);
	notify_send(notify);
	dns__zone_unlock(notify->zone);
destroy:
	dns_notify_destroy(notify, false);
}

void
dns_notify_cancel(dns_notifyctx_t *nctx) {
	ISC_LIST_FOREACH(nctx->notifies, notify, link) {
		INSIST(dns__zone_locked(notify->zone));
		if (notify->find != NULL) {
			dns_adb_cancelfind(notify->find);
		}
		if (notify->request != NULL) {
			dns_request_cancel(notify->request);
		}
	}
}
