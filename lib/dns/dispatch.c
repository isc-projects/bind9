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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/netmgr.h>
#include <isc/portset.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/dispatch.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/stats.h>
#include <dns/types.h>

typedef ISC_LIST(dns_dispentry_t) dns_displist_t;

typedef struct dns_qid {
	unsigned int magic;
	isc_mutex_t lock;
	unsigned int qid_nbuckets;  /*%< hash table size */
	unsigned int qid_increment; /*%< id increment on collision */
	dns_displist_t *qid_table;  /*%< the table itself */
} dns_qid_t;

struct dns_dispatchmgr {
	/* Unlocked. */
	unsigned int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	dns_acl_t *blackhole;
	isc_stats_t *stats;
	isc_nm_t *nm;

	/* Locked by "lock". */
	isc_mutex_t lock;
	unsigned int state;
	ISC_LIST(dns_dispatch_t) list;

	dns_qid_t *qid;

	in_port_t *v4ports;    /*%< available ports for IPv4 */
	unsigned int nv4ports; /*%< # of available ports for IPv4 */
	in_port_t *v6ports;    /*%< available ports for IPv4 */
	unsigned int nv6ports; /*%< # of available ports for IPv4 */
};

#define MGR_SHUTTINGDOWN       0x00000001U
#define MGR_IS_SHUTTINGDOWN(l) (((l)->state & MGR_SHUTTINGDOWN) != 0)

struct dns_dispentry {
	unsigned int magic;
	isc_refcount_t references;
	dns_dispatch_t *disp;
	isc_nmhandle_t *handle; /*%< netmgr handle for UDP connection */
	unsigned int bucket;
	unsigned int retries;
	unsigned int timeout;
	isc_time_t start;
	isc_sockaddr_t local;
	isc_sockaddr_t peer;
	in_port_t port;
	dns_messageid_t id;
	dispatch_cb_t connected;
	dispatch_cb_t sent;
	dispatch_cb_t response;
	void *arg;
	bool canceled;
	ISC_LINK(dns_dispentry_t) link;
	ISC_LINK(dns_dispentry_t) alink;
	ISC_LINK(dns_dispentry_t) plink;
	ISC_LINK(dns_dispentry_t) rlink;
};

/*%
 * Fixed UDP buffer size.
 */
#ifndef DNS_DISPATCH_UDPBUFSIZE
#define DNS_DISPATCH_UDPBUFSIZE 4096
#endif /* ifndef DNS_DISPATCH_UDPBUFSIZE */

typedef enum {
	DNS_DISPATCHSTATE_NONE = 0UL,
	DNS_DISPATCHSTATE_CONNECTING,
	DNS_DISPATCHSTATE_CONNECTED
} dns_dispatchstate_t;

struct dns_dispatch {
	/* Unlocked. */
	unsigned int magic;	/*%< magic */
	dns_dispatchmgr_t *mgr; /*%< dispatch manager */
	isc_nmhandle_t *handle; /*%< netmgr handle for TCP connection */
	isc_sockaddr_t local;	/*%< local address */
	in_port_t localport;	/*%< local UDP port */
	isc_sockaddr_t peer;	/*%< peer address (TCP) */

	/*% Locked by mgr->lock. */
	ISC_LINK(dns_dispatch_t) link;

	/* Locked by "lock". */
	isc_mutex_t lock; /*%< locks all below */
	isc_socktype_t socktype;
	atomic_uint_fast32_t state;
	isc_refcount_t references;
	unsigned int shutdown_out : 1;

	dns_displist_t pending;
	dns_displist_t active;
	unsigned int nsockets;

	unsigned int requests;	 /*%< how many requests we have */
	unsigned int tcpbuffers; /*%< allocated buffers */
};

#define QID_MAGIC    ISC_MAGIC('Q', 'i', 'd', ' ')
#define VALID_QID(e) ISC_MAGIC_VALID((e), QID_MAGIC)

#define RESPONSE_MAGIC	  ISC_MAGIC('D', 'r', 's', 'p')
#define VALID_RESPONSE(e) ISC_MAGIC_VALID((e), RESPONSE_MAGIC)

#define DISPSOCK_MAGIC	  ISC_MAGIC('D', 's', 'o', 'c')
#define VALID_DISPSOCK(e) ISC_MAGIC_VALID((e), DISPSOCK_MAGIC)

#define DISPATCH_MAGIC	  ISC_MAGIC('D', 'i', 's', 'p')
#define VALID_DISPATCH(e) ISC_MAGIC_VALID((e), DISPATCH_MAGIC)

#define DNS_DISPATCHMGR_MAGIC ISC_MAGIC('D', 'M', 'g', 'r')
#define VALID_DISPATCHMGR(e)  ISC_MAGIC_VALID((e), DNS_DISPATCHMGR_MAGIC)

/*%
 * Quota to control the number of UDP dispatch sockets.  If a dispatch has
 * more than the quota of sockets, new queries will purge oldest ones, so
 * that a massive number of outstanding queries won't prevent subsequent
 * queries (especially if the older ones take longer time and result in
 * timeout).
 */
#ifndef DNS_DISPATCH_SOCKSQUOTA
#define DNS_DISPATCH_SOCKSQUOTA 3072
#endif /* ifndef DNS_DISPATCH_SOCKSQUOTA */

/*%
 * Quota to control the number of concurrent requests that can be handled
 * by each TCP dispatch. (UDP dispatches do not currently support socket
 * sharing.)
 */
#ifndef DNS_DISPATCH_MAXREQUESTS
#define DNS_DISPATCH_MAXREQUESTS 32768
#endif /* ifndef DNS_DISPATCH_MAXREQUESTS */

/*%
 * Number of buckets in the QID hash table, and the value to
 * increment the QID by when attempting to avoid collisions.
 * The number of buckets should be prime, and the increment
 * should be the next higher prime number.
 */
#ifndef DNS_QID_BUCKETS
#define DNS_QID_BUCKETS 16411
#endif /* ifndef DNS_QID_BUCKETS */
#ifndef DNS_QID_INCREMENT
#define DNS_QID_INCREMENT 16433
#endif /* ifndef DNS_QID_INCREMENT */

/*
 * Statics.
 */
static void
dispatchmgr_destroy(dns_dispatchmgr_t *mgr);

static dns_dispentry_t *
entry_search(dns_qid_t *, const isc_sockaddr_t *, dns_messageid_t, in_port_t,
	     unsigned int);
static void
udp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg);
static void
tcp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg);
static uint32_t
dns_hash(dns_qid_t *, const isc_sockaddr_t *, dns_messageid_t, in_port_t);
static void
dispatch_free(dns_dispatch_t **dispp);
static isc_result_t
dispatch_createudp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		   dns_dispatch_t **dispp);
static void
qid_allocate(dns_dispatchmgr_t *mgr, dns_qid_t **qidp);
static void
qid_destroy(isc_mem_t *mctx, dns_qid_t **qidp);
static void
startrecv(isc_nmhandle_t *handle, dns_dispatch_t *disp, dns_dispentry_t *resp);
void
dispatch_getnext(dns_dispatch_t *disp, dns_dispentry_t *resp, int32_t timeout);

#define LVL(x) ISC_LOG_DEBUG(x)

static void
mgr_log(dns_dispatchmgr_t *mgr, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);

static void
mgr_log(dns_dispatchmgr_t *mgr, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(dns_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DISPATCH,
		      DNS_LOGMODULE_DISPATCH, level, "dispatchmgr %p: %s", mgr,
		      msgbuf);
}

static inline void
inc_stats(dns_dispatchmgr_t *mgr, isc_statscounter_t counter) {
	if (mgr->stats != NULL) {
		isc_stats_increment(mgr->stats, counter);
	}
}

static inline void
dec_stats(dns_dispatchmgr_t *mgr, isc_statscounter_t counter) {
	if (mgr->stats != NULL) {
		isc_stats_decrement(mgr->stats, counter);
	}
}

static void
dispatch_log(dns_dispatch_t *disp, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);

static void
dispatch_log(dns_dispatch_t *disp, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(dns_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DISPATCH,
		      DNS_LOGMODULE_DISPATCH, level, "dispatch %p: %s", disp,
		      msgbuf);
}

/*
 * Return a hash of the destination and message id.
 */
static uint32_t
dns_hash(dns_qid_t *qid, const isc_sockaddr_t *dest, dns_messageid_t id,
	 in_port_t port) {
	uint32_t ret;

	ret = isc_sockaddr_hash(dest, true);
	ret ^= ((uint32_t)id << 16) | port;
	ret %= qid->qid_nbuckets;

	INSIST(ret < qid->qid_nbuckets);

	return (ret);
}

/*%
 * Choose a random port number for a dispatch entry.
 * The caller must hold the disp->lock
 */
static isc_result_t
setup_socket(dns_dispatch_t *disp, dns_dispentry_t *resp,
	     const isc_sockaddr_t *dest, in_port_t *portp) {
	dns_dispatchmgr_t *mgr = disp->mgr;
	unsigned int nports;
	in_port_t *ports = NULL;
	in_port_t port;

	if (resp->retries++ > 5) {
		return (ISC_R_FAILURE);
	}

	if (isc_sockaddr_pf(&disp->local) == AF_INET) {
		nports = mgr->nv4ports;
		ports = mgr->v4ports;
	} else {
		nports = mgr->nv6ports;
		ports = mgr->v6ports;
	}
	if (nports == 0) {
		return (ISC_R_ADDRNOTAVAIL);
	}

	disp->nsockets++;

	resp->local = disp->local;
	resp->peer = *dest;

	port = ports[isc_random_uniform(nports)];
	isc_sockaddr_setport(&resp->local, port);
	resp->port = port;

	*portp = port;

	return (ISC_R_SUCCESS);
}

/*%
 * Deactivate the socket for a dispatch entry.
 * The dispatch must be locked.
 */
static void
deactivate_dispentry(dns_dispatch_t *disp, dns_dispentry_t *resp) {
	if (ISC_LINK_LINKED(resp, alink)) {
		ISC_LIST_UNLINK(disp->active, resp, alink);
	}

	if (resp->handle != NULL) {
		INSIST(disp->socktype == isc_socktype_udp);

		isc_nm_cancelread(resp->handle);
		isc_nmhandle_detach(&resp->handle);
	}

	disp->nsockets--;
}

/*
 * Find an entry for query ID 'id', socket address 'dest', and port number
 * 'port'.
 * Return NULL if no such entry exists.
 */
static dns_dispentry_t *
entry_search(dns_qid_t *qid, const isc_sockaddr_t *dest, dns_messageid_t id,
	     in_port_t port, unsigned int bucket) {
	dns_dispentry_t *res = NULL;

	REQUIRE(VALID_QID(qid));
	REQUIRE(bucket < qid->qid_nbuckets);

	res = ISC_LIST_HEAD(qid->qid_table[bucket]);

	while (res != NULL) {
		if (res->id == id && isc_sockaddr_equal(dest, &res->peer) &&
		    res->port == port) {
			return (res);
		}
		res = ISC_LIST_NEXT(res, link);
	}

	return (NULL);
}

static void
dispentry_attach(dns_dispentry_t *resp, dns_dispentry_t **respp) {
	REQUIRE(VALID_RESPONSE(resp));
	REQUIRE(respp != NULL && *respp == NULL);

	isc_refcount_increment(&resp->references);

	*respp = resp;
}

static void
dispentry_destroy(dns_dispentry_t *resp) {
	dns_dispatch_t *disp = resp->disp;

	resp->magic = 0;

	if (ISC_LINK_LINKED(resp, plink)) {
		ISC_LIST_UNLINK(disp->pending, resp, plink);
	}

	INSIST(!ISC_LINK_LINKED(resp, alink));
	INSIST(!ISC_LINK_LINKED(resp, rlink));

	if (resp->handle != NULL) {
		isc_nmhandle_detach(&resp->handle);
	}

	isc_refcount_destroy(&resp->references);

	isc_mem_put(disp->mgr->mctx, resp, sizeof(*resp));

	dns_dispatch_detach(&disp);
}

static void
dispentry_detach(dns_dispentry_t **respp) {
	dns_dispentry_t *resp = NULL;
	uint_fast32_t ref;

	REQUIRE(respp != NULL && VALID_RESPONSE(*respp));

	resp = *respp;
	*respp = NULL;

	ref = isc_refcount_decrement(&resp->references);
	if (ref == 1) {
		dispentry_destroy(resp);
	}
}

/*
 * How long in milliseconds has it been since this dispentry
 * started reading? (Only used for UDP, to adjust the timeout
 * downward when running getnext.)
 */
static unsigned int
dispentry_runtime(dns_dispentry_t *resp) {
	isc_time_t now;

	if (isc_time_isepoch(&resp->start)) {
		return (0);
	}

	TIME_NOW(&now);
	return (isc_time_microdiff(&now, &resp->start) / 1000);
}

/*
 * General flow:
 *
 * If I/O result == CANCELED or error, free the buffer.
 *
 * If query, free the buffer, restart.
 *
 * If response:
 *	Allocate event, fill in details.
 *		If cannot allocate, free buffer, restart.
 *	find target.  If not found, free buffer, restart.
 *	if event queue is not empty, queue.  else, send.
 *	restart.
 */
static void
udp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg) {
	dns_dispentry_t *resp = (dns_dispentry_t *)arg;
	dns_dispatch_t *disp = NULL;
	dns_messageid_t id;
	isc_result_t dres;
	isc_buffer_t source;
	unsigned int flags;
	isc_sockaddr_t peer;
	isc_netaddr_t netaddr;
	int match, timeout;
	dispatch_cb_t response = NULL;

	REQUIRE(VALID_RESPONSE(resp));
	REQUIRE(VALID_DISPATCH(resp->disp));

	disp = resp->disp;

	LOCK(&disp->lock);

	dispatch_log(disp, LVL(90), "UDP response %p:%s:requests %d", resp,
		     isc_result_totext(eresult), disp->requests);

	/*
	 * The resp may have been deactivated by shutdown; if
	 * so, we can skip the response callback.
	 */
	if (ISC_LINK_LINKED(resp, alink)) {
		response = resp->response;
	}

	if (eresult != ISC_R_SUCCESS) {
		/*
		 * This is most likely a network error on a connected
		 * socket, a timeout, or the query has been canceled.
		 * It makes no sense to check the address or parse the
		 * packet, but we can return the error to the caller.
		 */
		goto done;
	}

	INSIST(ISC_LINK_LINKED(resp, alink));

	peer = isc_nmhandle_peeraddr(handle);
	isc_netaddr_fromsockaddr(&netaddr, &peer);

	/*
	 * If this is from a blackholed address, drop it.
	 */
	if (disp->mgr->blackhole != NULL &&
	    dns_acl_match(&netaddr, NULL, disp->mgr->blackhole, NULL, &match,
			  NULL) == ISC_R_SUCCESS &&
	    match > 0)
	{
		if (isc_log_wouldlog(dns_lctx, LVL(10))) {
			char netaddrstr[ISC_NETADDR_FORMATSIZE];
			isc_netaddr_format(&netaddr, netaddrstr,
					   sizeof(netaddrstr));
			dispatch_log(disp, LVL(10), "blackholed packet from %s",
				     netaddrstr);
		}
		goto next;
	}

	/*
	 * Peek into the buffer to see what we can see.
	 */
	id = resp->id;
	isc_buffer_init(&source, region->base, region->length);
	isc_buffer_add(&source, region->length);
	dres = dns_message_peekheader(&source, &id, &flags);
	if (dres != ISC_R_SUCCESS) {
		dispatch_log(disp, LVL(10), "got garbage packet");
		goto next;
	}

	dispatch_log(disp, LVL(92),
		     "got valid DNS message header, /QR %c, id %u",
		     (((flags & DNS_MESSAGEFLAG_QR) != 0) ? '1' : '0'), id);

	/*
	 * Look at the message flags.  If it's a query, ignore it.
	 */
	if ((flags & DNS_MESSAGEFLAG_QR) == 0) {
		goto next;
	}

	/*
	 * The QID and the address must match the expected ones.
	 */
	if (resp->id != id || !isc_sockaddr_equal(&peer, &resp->peer)) {
		dispatch_log(disp, LVL(90), "response doesn't match");
		inc_stats(disp->mgr, dns_resstatscounter_mismatch);
		goto next;
	}

	/*
	 * We have the right resp, so call the caller back.
	 */
	goto done;

next:
	/*
	 * This is the wrong response. Don't call the caller back
	 * but keep listening.
	 */
	response = NULL;

	timeout = resp->timeout - dispentry_runtime(resp);
	if (timeout <= 0) {
		eresult = ISC_R_TIMEDOUT;
		goto done;
	}
	dispatch_getnext(disp, resp, resp->timeout - dispentry_runtime(resp));

done:
	UNLOCK(&disp->lock);

	if (response != NULL) {
		response(eresult, region, resp->arg);
	}

	dispentry_detach(&resp);
}

/*
 * General flow:
 *
 * If I/O result == CANCELED, EOF, or error, notify everyone as the
 * various queues drain.
 *
 * If query, restart.
 *
 * If response:
 *	Allocate event, fill in details.
 *		If cannot allocate, restart.
 *	find target.  If not found, restart.
 *	if event queue is not empty, queue.  else, send.
 *	restart.
 */
static void
tcp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg) {
	dns_dispatch_t *disp = (dns_dispatch_t *)arg;
	dns_dispentry_t *resp = NULL, *next = NULL;
	dns_messageid_t id;
	isc_result_t dres;
	unsigned int flags;
	unsigned int bucket;
	dns_qid_t *qid = NULL;
	int level;
	char buf[ISC_SOCKADDR_FORMATSIZE];
	isc_buffer_t source;
	isc_sockaddr_t peer;
	dns_displist_t resps;

	REQUIRE(VALID_DISPATCH(disp));

	qid = disp->mgr->qid;

	LOCK(&disp->lock);

	dispatch_log(disp, LVL(90), "TCP read:%s:requests %d, buffers %d",
		     isc_result_totext(eresult), disp->requests,
		     disp->tcpbuffers);

	peer = isc_nmhandle_peeraddr(handle);
	ISC_LIST_INIT(resps);

	switch (eresult) {
	case ISC_R_SUCCESS:
		/* got our answer */
		break;

	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
	case ISC_R_EOF:
		dispatch_log(disp, LVL(90), "shutting down: %s",
			     isc_result_totext(eresult));
		/*
		 * If there are any active responses, shut them all down.
		 */
		for (resp = ISC_LIST_HEAD(disp->active); resp != NULL;
		     resp = next) {
			next = ISC_LIST_NEXT(resp, alink);
			dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
			ISC_LIST_UNLINK(disp->active, resp, alink);
			ISC_LIST_APPEND(resps, resp, rlink);
		}
		goto done;

	case ISC_R_TIMEDOUT:
		/*
		 * Time out the oldest response in the active queue,
		 * and move it to the end. (We don't remove it from the
		 * active queue immediately, though, because the callback
		 * might decide to keep waiting and leave it active.)
		 */
		resp = ISC_LIST_HEAD(disp->active);
		if (resp != NULL) {
			dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
			ISC_LIST_UNLINK(disp->active, resp, alink);
			ISC_LIST_APPEND(disp->active, resp, alink);
		}
		goto done;

	default:
		if (eresult == ISC_R_CONNECTIONRESET) {
			level = ISC_LOG_INFO;
		} else {
			level = ISC_LOG_ERROR;
		}

		isc_sockaddr_format(&peer, buf, sizeof(buf));
		dispatch_log(disp, level,
			     "shutting down due to TCP "
			     "receive error: %s: %s",
			     buf, isc_result_totext(eresult));
		goto done;
	}

	dispatch_log(disp, LVL(90), "success, length == %d, addr = %p",
		     region->length, region->base);

	/*
	 * Peek into the buffer to see what we can see.
	 */
	isc_buffer_init(&source, region->base, region->length);
	isc_buffer_add(&source, region->length);
	dres = dns_message_peekheader(&source, &id, &flags);
	if (dres != ISC_R_SUCCESS) {
		dispatch_log(disp, LVL(10), "got garbage packet");
		goto next;
	}

	dispatch_log(disp, LVL(92),
		     "got valid DNS message header, /QR %c, id %u",
		     (((flags & DNS_MESSAGEFLAG_QR) != 0) ? '1' : '0'), id);

	/*
	 * Look at the message flags.  If it's a query, ignore it
	 * and keep reading.
	 */
	if ((flags & DNS_MESSAGEFLAG_QR) == 0) {
		/*
		 * Query.
		 */
		goto next;
	}

	/*
	 * We have a valid response; find the associated dispentry object
	 * and call the caller back.
	 */
	bucket = dns_hash(qid, &peer, id, disp->localport);
	LOCK(&qid->lock);
	resp = entry_search(qid, &peer, id, disp->localport, bucket);
	if (resp != NULL) {
		dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
	}
	dispatch_log(disp, LVL(90), "search for response in bucket %d: %s",
		     bucket, (resp == NULL ? "not found" : "found"));
	UNLOCK(&qid->lock);

next:
	dispatch_getnext(disp, NULL, -1);

done:
	UNLOCK(&disp->lock);

	if (resp != NULL) {
		/* We got a matching response, or timed out */
		resp->response(eresult, region, resp->arg);
		dispentry_detach(&resp);
	} else {
		/* We're being shut down; cancel all outstanding resps */
		for (resp = ISC_LIST_HEAD(resps); resp != NULL; resp = next) {
			next = ISC_LIST_NEXT(resp, rlink);
			ISC_LIST_UNLINK(resps, resp, rlink);
			resp->response(ISC_R_SHUTTINGDOWN, region, resp->arg);
			dispentry_detach(&resp);
		}
	}

	dns_dispatch_detach(&disp);
}

/*%
 * Create a temporary port list to set the initial default set of dispatch
 * ports: [1024, 65535].  This is almost meaningless as the application will
 * normally set the ports explicitly, but is provided to fill some minor corner
 * cases.
 */
static void
create_default_portset(isc_mem_t *mctx, isc_portset_t **portsetp) {
	isc_portset_create(mctx, portsetp);
	isc_portset_addrange(*portsetp, 1024, 65535);
}

static isc_result_t
setavailports(dns_dispatchmgr_t *mgr, isc_portset_t *v4portset,
	      isc_portset_t *v6portset) {
	in_port_t *v4ports, *v6ports, p = 0;
	unsigned int nv4ports, nv6ports, i4 = 0, i6 = 0;

	nv4ports = isc_portset_nports(v4portset);
	nv6ports = isc_portset_nports(v6portset);

	v4ports = NULL;
	if (nv4ports != 0) {
		v4ports = isc_mem_get(mgr->mctx, sizeof(in_port_t) * nv4ports);
	}
	v6ports = NULL;
	if (nv6ports != 0) {
		v6ports = isc_mem_get(mgr->mctx, sizeof(in_port_t) * nv6ports);
	}

	do {
		if (isc_portset_isset(v4portset, p)) {
			INSIST(i4 < nv4ports);
			v4ports[i4++] = p;
		}
		if (isc_portset_isset(v6portset, p)) {
			INSIST(i6 < nv6ports);
			v6ports[i6++] = p;
		}
	} while (p++ < 65535);
	INSIST(i4 == nv4ports && i6 == nv6ports);

	if (mgr->v4ports != NULL) {
		isc_mem_put(mgr->mctx, mgr->v4ports,
			    mgr->nv4ports * sizeof(in_port_t));
	}
	mgr->v4ports = v4ports;
	mgr->nv4ports = nv4ports;

	if (mgr->v6ports != NULL) {
		isc_mem_put(mgr->mctx, mgr->v6ports,
			    mgr->nv6ports * sizeof(in_port_t));
	}
	mgr->v6ports = v6ports;
	mgr->nv6ports = nv6ports;

	return (ISC_R_SUCCESS);
}

/*
 * Publics.
 */

isc_result_t
dns_dispatchmgr_create(isc_mem_t *mctx, isc_nm_t *nm,
		       dns_dispatchmgr_t **mgrp) {
	dns_dispatchmgr_t *mgr = NULL;
	isc_portset_t *v4portset = NULL;
	isc_portset_t *v6portset = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(mgrp != NULL && *mgrp == NULL);

	mgr = isc_mem_get(mctx, sizeof(dns_dispatchmgr_t));
	*mgr = (dns_dispatchmgr_t){ .magic = 0 };

	isc_refcount_init(&mgr->references, 1);

	isc_mem_attach(mctx, &mgr->mctx);
	isc_nm_attach(nm, &mgr->nm);

	isc_mutex_init(&mgr->lock);

	ISC_LIST_INIT(mgr->list);

	create_default_portset(mctx, &v4portset);
	create_default_portset(mctx, &v6portset);

	setavailports(mgr, v4portset, v6portset);

	isc_portset_destroy(mctx, &v4portset);
	isc_portset_destroy(mctx, &v6portset);

	qid_allocate(mgr, &mgr->qid);
	mgr->magic = DNS_DISPATCHMGR_MAGIC;

	*mgrp = mgr;
	return (ISC_R_SUCCESS);
}

void
dns_dispatchmgr_attach(dns_dispatchmgr_t *mgr, dns_dispatchmgr_t **mgrp) {
	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(mgrp != NULL && *mgrp == NULL);

	isc_refcount_increment(&mgr->references);

	*mgrp = mgr;
}

void
dns_dispatchmgr_detach(dns_dispatchmgr_t **mgrp) {
	dns_dispatchmgr_t *mgr = NULL;
	uint_fast32_t ref;

	REQUIRE(mgrp != NULL && VALID_DISPATCHMGR(*mgrp));

	mgr = *mgrp;
	*mgrp = NULL;

	ref = isc_refcount_decrement(&mgr->references);
	if (ref == 1) {
		dispatchmgr_destroy(mgr);
	}
}

void
dns_dispatchmgr_setblackhole(dns_dispatchmgr_t *mgr, dns_acl_t *blackhole) {
	REQUIRE(VALID_DISPATCHMGR(mgr));
	if (mgr->blackhole != NULL) {
		dns_acl_detach(&mgr->blackhole);
	}
	dns_acl_attach(blackhole, &mgr->blackhole);
}

dns_acl_t *
dns_dispatchmgr_getblackhole(dns_dispatchmgr_t *mgr) {
	REQUIRE(VALID_DISPATCHMGR(mgr));
	return (mgr->blackhole);
}

isc_result_t
dns_dispatchmgr_setavailports(dns_dispatchmgr_t *mgr, isc_portset_t *v4portset,
			      isc_portset_t *v6portset) {
	REQUIRE(VALID_DISPATCHMGR(mgr));
	return (setavailports(mgr, v4portset, v6portset));
}

static void
dispatchmgr_destroy(dns_dispatchmgr_t *mgr) {
	REQUIRE(VALID_DISPATCHMGR(mgr));

	isc_refcount_destroy(&mgr->references);

	mgr->magic = 0;
	isc_mutex_destroy(&mgr->lock);
	mgr->state = 0;

	qid_destroy(mgr->mctx, &mgr->qid);

	if (mgr->blackhole != NULL) {
		dns_acl_detach(&mgr->blackhole);
	}

	if (mgr->stats != NULL) {
		isc_stats_detach(&mgr->stats);
	}

	if (mgr->v4ports != NULL) {
		isc_mem_put(mgr->mctx, mgr->v4ports,
			    mgr->nv4ports * sizeof(in_port_t));
	}
	if (mgr->v6ports != NULL) {
		isc_mem_put(mgr->mctx, mgr->v6ports,
			    mgr->nv6ports * sizeof(in_port_t));
	}

	isc_nm_detach(&mgr->nm);

	isc_mem_putanddetach(&mgr->mctx, mgr, sizeof(dns_dispatchmgr_t));
}

void
dns_dispatchmgr_setstats(dns_dispatchmgr_t *mgr, isc_stats_t *stats) {
	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(ISC_LIST_EMPTY(mgr->list));
	REQUIRE(mgr->stats == NULL);

	isc_stats_attach(stats, &mgr->stats);
}

static void
qid_allocate(dns_dispatchmgr_t *mgr, dns_qid_t **qidp) {
	dns_qid_t *qid = NULL;
	unsigned int i;

	REQUIRE(qidp != NULL && *qidp == NULL);

	qid = isc_mem_get(mgr->mctx, sizeof(*qid));
	*qid = (dns_qid_t){ .qid_nbuckets = DNS_QID_BUCKETS,
			    .qid_increment = DNS_QID_INCREMENT };

	qid->qid_table = isc_mem_get(mgr->mctx,
				     DNS_QID_BUCKETS * sizeof(dns_displist_t));
	for (i = 0; i < qid->qid_nbuckets; i++) {
		ISC_LIST_INIT(qid->qid_table[i]);
	}

	isc_mutex_init(&qid->lock);
	qid->magic = QID_MAGIC;
	*qidp = qid;
}

static void
qid_destroy(isc_mem_t *mctx, dns_qid_t **qidp) {
	dns_qid_t *qid = NULL;

	REQUIRE(qidp != NULL);
	qid = *qidp;
	*qidp = NULL;

	REQUIRE(VALID_QID(qid));

	qid->magic = 0;
	isc_mem_put(mctx, qid->qid_table,
		    qid->qid_nbuckets * sizeof(dns_displist_t));
	isc_mutex_destroy(&qid->lock);
	isc_mem_put(mctx, qid, sizeof(*qid));
}

/*
 * Allocate and set important limits.
 */
static void
dispatch_allocate(dns_dispatchmgr_t *mgr, isc_socktype_t type,
		  dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(dispp != NULL && *dispp == NULL);

	/*
	 * Set up the dispatcher, mostly.  Don't bother setting some of
	 * the options that are controlled by tcp vs. udp, etc.
	 */

	disp = isc_mem_get(mgr->mctx, sizeof(*disp));
	*disp = (dns_dispatch_t){ .socktype = type };

	dns_dispatchmgr_attach(mgr, &disp->mgr);
	isc_refcount_init(&disp->references, 1);
	ISC_LINK_INIT(disp, link);
	ISC_LIST_INIT(disp->active);
	ISC_LIST_INIT(disp->pending);

	isc_mutex_init(&disp->lock);

	disp->magic = DISPATCH_MAGIC;

	*dispp = disp;
}

/*
 * MUST be unlocked, and not used by anything.
 */
static void
dispatch_free(dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;
	dns_dispatchmgr_t *mgr = NULL;

	REQUIRE(VALID_DISPATCH(*dispp));
	disp = *dispp;
	*dispp = NULL;

	disp->magic = 0;

	mgr = disp->mgr;
	REQUIRE(VALID_DISPATCHMGR(mgr));

	INSIST(disp->requests == 0);
	INSIST(ISC_LIST_EMPTY(disp->active));

	isc_mutex_destroy(&disp->lock);

	isc_mem_put(mgr->mctx, disp, sizeof(*disp));
}

isc_result_t
dns_dispatch_createtcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		       const isc_sockaddr_t *destaddr, isc_dscp_t dscp,
		       dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(destaddr != NULL);

	UNUSED(dscp);

	LOCK(&mgr->lock);

	dispatch_allocate(mgr, isc_socktype_tcp, &disp);

	disp->peer = *destaddr;

	if (localaddr != NULL) {
		disp->local = *localaddr;
	} else {
		int pf;
		pf = isc_sockaddr_pf(destaddr);
		isc_sockaddr_anyofpf(&disp->local, pf);
		isc_sockaddr_setport(&disp->local, 0);
	}

	/*
	 * Append it to the dispatcher list.
	 */

	/* FIXME: There should be a lookup hashtable here */
	ISC_LIST_APPEND(mgr->list, disp, link);
	UNLOCK(&mgr->lock);

	mgr_log(mgr, LVL(90), "dns_dispatch_createtcp: created TCP dispatch %p",
		disp);
	*dispp = disp;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_dispatch_gettcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *destaddr,
		    const isc_sockaddr_t *localaddr, bool *connected,
		    dns_dispatch_t **dispp) {
	dns_dispatch_t *disp_connected = NULL;
	dns_dispatch_t *disp_fallback = NULL;
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(destaddr != NULL);
	REQUIRE(connected != NULL);
	REQUIRE(dispp != NULL && *dispp == NULL);

	LOCK(&mgr->lock);

	for (dns_dispatch_t *disp = ISC_LIST_HEAD(mgr->list); disp != NULL;
	     disp = ISC_LIST_NEXT(disp, link))
	{
		isc_sockaddr_t sockname;
		isc_sockaddr_t peeraddr;

		LOCK(&disp->lock);

		if (disp->handle != NULL) {
			sockname = isc_nmhandle_localaddr(disp->handle);
			peeraddr = isc_nmhandle_peeraddr(disp->handle);
		} else {
			sockname = disp->local;
			peeraddr = disp->peer;
		}

		/*
		 * The conditions match:
		 * 1. socktype is TCP
		 * 2. destination address is same
		 * 3. local address is either NULL or same
		 */
		if (disp->socktype == isc_socktype_tcp &&
		    isc_sockaddr_equal(destaddr, &peeraddr) &&
		    (localaddr == NULL ||
		     isc_sockaddr_eqaddr(localaddr, &sockname)))
		{
			if (atomic_load(&disp->state) ==
			    DNS_DISPATCHSTATE_CONNECTED) {
				/* We found connected dispatch */
				disp_connected = disp;
				UNLOCK(&disp->lock);
				break;
			}

			/* We found "a" dispatch, store it for later */
			if (disp_fallback == NULL) {
				disp_fallback = disp;
			}

			UNLOCK(&disp->lock);
			continue;
		}

		UNLOCK(&disp->lock);
	}

	if (disp_connected != NULL) {
		/* We found connected dispatch */
		INSIST(disp_connected->handle != NULL);

		*connected = true;
		dns_dispatch_attach(disp_connected, dispp);

		result = ISC_R_SUCCESS;
	} else if (disp_fallback != NULL) {
		/* We found matching dispatch */
		*connected = false;

		dns_dispatch_attach(disp_fallback, dispp);

		result = ISC_R_SUCCESS;
	}

	UNLOCK(&mgr->lock);

	return (result);
}

isc_result_t
dns_dispatch_createudp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		       dns_dispatch_t **dispp) {
	isc_result_t result;
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(localaddr != NULL);
	REQUIRE(dispp != NULL && *dispp == NULL);

	LOCK(&mgr->lock);
	result = dispatch_createudp(mgr, localaddr, &disp);
	if (result == ISC_R_SUCCESS) {
		*dispp = disp;
	}
	UNLOCK(&mgr->lock);

	return (result);
}

static isc_result_t
dispatch_createudp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *localaddr,
		   dns_dispatch_t **dispp) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_dispatch_t *disp = NULL;
	isc_sockaddr_t sa_any;

	dispatch_allocate(mgr, isc_socktype_udp, &disp);

	/*
	 * Check whether this address/port is available locally.
	 */
	isc_sockaddr_anyofpf(&sa_any, isc_sockaddr_pf(localaddr));
	if (!isc_sockaddr_eqaddr(&sa_any, localaddr)) {
		result = isc_nm_checkaddr(localaddr, isc_socktype_udp);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
	}

	if (isc_log_wouldlog(dns_lctx, 90)) {
		char addrbuf[ISC_SOCKADDR_FORMATSIZE];

		isc_sockaddr_format(localaddr, addrbuf,
				    ISC_SOCKADDR_FORMATSIZE);
		mgr_log(mgr, LVL(90),
			"dispatch_createudp: created UDP dispatch for %s",
			addrbuf);
	}

	disp->local = *localaddr;

	/*
	 * Append it to the dispatcher list.
	 */
	ISC_LIST_APPEND(mgr->list, disp, link);

	mgr_log(mgr, LVL(90), "created UDP dispatcher %p", disp);

	*dispp = disp;

	return (result);

	/*
	 * Error returns.
	 */
cleanup:
	dispatch_free(&disp);

	return (result);
}

static void
dispatch_destroy(dns_dispatch_t *disp) {
	dns_dispatchmgr_t *mgr = disp->mgr;

	LOCK(&mgr->lock);
	ISC_LIST_UNLINK(mgr->list, disp, link);
	UNLOCK(&mgr->lock);

	dispatch_log(disp, LVL(90), "shutting down; detaching from handle %p",
		     disp->handle);

	if (disp->handle != NULL) {
		isc_nmhandle_detach(&disp->handle);
	}

	dispatch_free(&disp);

	/*
	 * Because dispatch uses mgr->mctx, we must detach after freeing
	 * dispatch, not before.
	 */
	dns_dispatchmgr_detach(&mgr);
}

void
dns_dispatch_attach(dns_dispatch_t *disp, dns_dispatch_t **dispp) {
	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(dispp != NULL && *dispp == NULL);

	isc_refcount_increment(&disp->references);

	*dispp = disp;
}

void
dns_dispatch_detach(dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;
	uint_fast32_t ref;

	REQUIRE(dispp != NULL && VALID_DISPATCH(*dispp));

	disp = *dispp;
	*dispp = NULL;

	ref = isc_refcount_decrement(&disp->references);
	dispatch_log(disp, LVL(90), "detach: refcount %" PRIuFAST32, ref - 1);
	if (ref == 1) {
		LOCK(&disp->lock);
		INSIST(ISC_LIST_EMPTY(disp->pending));
		INSIST(ISC_LIST_EMPTY(disp->active));
		UNLOCK(&disp->lock);

		dispatch_destroy(disp);
	}
}

isc_result_t
dns_dispatch_add(dns_dispatch_t *disp, unsigned int options,
		 unsigned int timeout, const isc_sockaddr_t *dest,
		 dispatch_cb_t connected, dispatch_cb_t sent,
		 dispatch_cb_t response, void *arg, dns_messageid_t *idp,
		 dns_dispentry_t **resp) {
	dns_dispentry_t *res = NULL;
	dns_qid_t *qid = NULL;
	in_port_t localport = 0;
	dns_messageid_t id;
	unsigned int bucket;
	bool ok = false;
	int i = 0;
	dispatch_cb_t oldest_response = NULL;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(dest != NULL);
	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(idp != NULL);
	REQUIRE(disp->socktype == isc_socktype_tcp ||
		disp->socktype == isc_socktype_udp);

	LOCK(&disp->lock);

	if (disp->requests >= DNS_DISPATCH_MAXREQUESTS) {
		UNLOCK(&disp->lock);
		return (ISC_R_QUOTA);
	}

	qid = disp->mgr->qid;

	if (disp->socktype == isc_socktype_udp &&
	    disp->nsockets > DNS_DISPATCH_SOCKSQUOTA)
	{
		dns_dispentry_t *oldest = NULL;

		/*
		 * Kill oldest outstanding query if the number of sockets
		 * exceeds the quota to keep the room for new queries.
		 */
		oldest = ISC_LIST_HEAD(disp->active);
		if (oldest != NULL) {
			oldest_response = oldest->response;
			inc_stats(disp->mgr, dns_resstatscounter_dispabort);
		}
	}

	res = isc_mem_get(disp->mgr->mctx, sizeof(*res));

	*res = (dns_dispentry_t){ .port = localport,
				  .timeout = timeout,
				  .peer = *dest,
				  .connected = connected,
				  .sent = sent,
				  .response = response,
				  .arg = arg };

	isc_refcount_init(&res->references, 1);

	ISC_LINK_INIT(res, link);
	ISC_LINK_INIT(res, alink);
	ISC_LINK_INIT(res, plink);
	ISC_LINK_INIT(res, rlink);

	if (disp->socktype == isc_socktype_udp) {
		isc_result_t result = setup_socket(disp, res, dest, &localport);
		if (result != ISC_R_SUCCESS) {
			isc_mem_put(disp->mgr->mctx, res, sizeof(*res));
			UNLOCK(&disp->lock);
			inc_stats(disp->mgr, dns_resstatscounter_dispsockfail);
			return (result);
		}
	}

	/*
	 * Try somewhat hard to find a unique ID. Start with
	 * a random number unless DNS_DISPATCHOPT_FIXEDID is set,
	 * in which case we start with the ID passed in via *idp.
	 */
	if ((options & DNS_DISPATCHOPT_FIXEDID) != 0) {
		id = *idp;
	} else {
		id = (dns_messageid_t)isc_random16();
	}

	LOCK(&qid->lock);
	do {
		dns_dispentry_t *entry = NULL;
		bucket = dns_hash(qid, dest, id, localport);
		entry = entry_search(qid, dest, id, localport, bucket);
		if (entry == NULL) {
			ok = true;
			break;
		}
		id += qid->qid_increment;
		id &= 0x0000ffff;
	} while (i++ < 64);
	UNLOCK(&qid->lock);

	if (!ok) {
		isc_mem_put(disp->mgr->mctx, res, sizeof(*res));
		UNLOCK(&disp->lock);
		return (ISC_R_NOMORE);
	}

	dns_dispatch_attach(disp, &res->disp);

	res->id = id;
	res->bucket = bucket;
	res->magic = RESPONSE_MAGIC;

	disp->requests++;

	LOCK(&qid->lock);
	ISC_LIST_APPEND(qid->qid_table[bucket], res, link);
	UNLOCK(&qid->lock);

	inc_stats(disp->mgr, (disp->socktype == isc_socktype_udp)
				     ? dns_resstatscounter_disprequdp
				     : dns_resstatscounter_dispreqtcp);

	ISC_LIST_APPEND(disp->active, res, alink);

	UNLOCK(&disp->lock);

	if (oldest_response != NULL) {
		oldest_response(ISC_R_CANCELED, NULL, res->arg);
	}

	*idp = id;
	*resp = res;

	return (ISC_R_SUCCESS);
}

void
dispatch_getnext(dns_dispatch_t *disp, dns_dispentry_t *resp, int32_t timeout) {
	REQUIRE(timeout <= UINT16_MAX);

	switch (disp->socktype) {
	case isc_socktype_udp:
		dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
		if (timeout > 0) {
			isc_nmhandle_settimeout(resp->handle, timeout);
		}
		isc_nm_read(resp->handle, udp_recv, resp);
		break;

	case isc_socktype_tcp:
		dns_dispatch_attach(disp, &(dns_dispatch_t *){ NULL });
		if (timeout > 0) {
			isc_nmhandle_settimeout(disp->handle, timeout);
		}
		isc_nm_read(disp->handle, tcp_recv, disp);
		break;

	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
dns_dispatch_getnext(dns_dispentry_t *resp) {
	dns_dispatch_t *disp = NULL;
	int32_t timeout;

	REQUIRE(VALID_RESPONSE(resp));

	disp = resp->disp;

	REQUIRE(VALID_DISPATCH(disp));

	if (disp->socktype == isc_socktype_udp) {
		timeout = resp->timeout - dispentry_runtime(resp);
		if (timeout <= 0) {
			return (ISC_R_TIMEDOUT);
		}
	} else {
		timeout = -1;
	}

	LOCK(&disp->lock);
	dispatch_getnext(disp, resp, timeout);
	UNLOCK(&disp->lock);
	return (ISC_R_SUCCESS);
}

void
dns_dispatch_cancel(dns_dispentry_t **respp) {
	dns_dispentry_t *resp = NULL;

	REQUIRE(respp != NULL);

	resp = *respp;
	*respp = NULL;

	REQUIRE(VALID_RESPONSE(resp));

	resp->canceled = true;

	/* Connected UDP. */
	if (resp->handle != NULL) {
		isc_nm_cancelread(resp->handle);
		goto done;
	}

	/* TCP pending connection. */
	if (ISC_LINK_LINKED(resp, plink)) {
		dns_dispentry_t *copy = resp;

		ISC_LIST_UNLINK(resp->disp->pending, resp, plink);
		if (resp->connected != NULL) {
			resp->connected(ISC_R_CANCELED, NULL, resp->arg);
		}

		/*
		 * We need to detach twice if we were pending
		 * connection - once to take the place of the
		 * detach in tcp_connected() or udp_connected()
		 * that we won't reach, and again later in
		 * dns_dispatch_done().
		 */
		dispentry_detach(&copy);
		goto done;
	}

	/*
	 * Connected TCP, or unconnected UDP.
	 *
	 * If TCP, we don't want to cancel the dispatch
	 * unless this is the last resp waiting.
	 */
	if (ISC_LINK_LINKED(resp, alink)) {
		ISC_LIST_UNLINK(resp->disp->active, resp, alink);
		if (ISC_LIST_EMPTY(resp->disp->active) &&
		    resp->disp->handle != NULL) {
			isc_nm_cancelread(resp->disp->handle);
		} else if (resp->response != NULL) {
			resp->response(ISC_R_CANCELED, NULL, resp->arg);
		}
	}

done:
	dns_dispatch_done(&resp);
}

void
dns_dispatch_done(dns_dispentry_t **respp) {
	dns_dispatchmgr_t *mgr = NULL;
	dns_dispatch_t *disp = NULL;
	dns_dispentry_t *resp = NULL;
	dns_qid_t *qid = NULL;

	REQUIRE(respp != NULL);

	resp = *respp;

	REQUIRE(VALID_RESPONSE(resp));

	disp = resp->disp;

	REQUIRE(VALID_DISPATCH(disp));

	mgr = disp->mgr;

	REQUIRE(VALID_DISPATCHMGR(mgr));

	qid = mgr->qid;

	LOCK(&disp->lock);
	INSIST(disp->requests > 0);
	disp->requests--;

	dec_stats(disp->mgr, (disp->socktype == isc_socktype_udp)
				     ? dns_resstatscounter_disprequdp
				     : dns_resstatscounter_dispreqtcp);

	deactivate_dispentry(disp, resp);

	LOCK(&qid->lock);
	ISC_LIST_UNLINK(qid->qid_table[resp->bucket], resp, link);
	UNLOCK(&qid->lock);
	UNLOCK(&disp->lock);

	dispentry_detach(respp);
}

/*
 * disp must be locked.
 */
static void
startrecv(isc_nmhandle_t *handle, dns_dispatch_t *disp, dns_dispentry_t *resp) {
	switch (disp->socktype) {
	case isc_socktype_udp:
		REQUIRE(resp != NULL && resp->handle == NULL);

		TIME_NOW(&resp->start);
		isc_nmhandle_attach(handle, &resp->handle);
		dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
		isc_nm_read(resp->handle, udp_recv, resp);
		break;

	case isc_socktype_tcp:
		REQUIRE(disp != NULL);
		LOCK(&disp->lock);
		REQUIRE(disp->handle == NULL);

		isc_nmhandle_attach(handle, &disp->handle);
		dns_dispatch_attach(disp, &(dns_dispatch_t *){ NULL });
		isc_nm_read(disp->handle, tcp_recv, disp);
		UNLOCK(&disp->lock);

		break;

	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

static void
tcp_connected(isc_nmhandle_t *handle, isc_result_t eresult, void *arg) {
	dns_dispatch_t *disp = (dns_dispatch_t *)arg;
	dns_dispentry_t *resp = NULL, *next = NULL;
	dns_displist_t resps;

	dispatch_log(disp, LVL(90), "TCP connected (%p): %s", disp,
		     isc_result_totext(eresult));

	ISC_LIST_INIT(resps);

	if (MGR_IS_SHUTTINGDOWN(disp->mgr)) {
		eresult = ISC_R_SHUTTINGDOWN;
	}

	if (eresult == ISC_R_SUCCESS) {
		REQUIRE(atomic_compare_exchange_strong(
			&disp->state,
			&(uint_fast32_t){ DNS_DISPATCHSTATE_CONNECTING },
			DNS_DISPATCHSTATE_CONNECTED));
		startrecv(handle, disp, NULL);
	}

	/*
	 * If there are pending responses, call the connect
	 * callbacks for all of them.
	 */
	LOCK(&disp->lock);
	for (resp = ISC_LIST_HEAD(disp->pending); resp != NULL; resp = next) {
		next = ISC_LIST_NEXT(resp, plink);
		ISC_LIST_UNLINK(disp->pending, resp, plink);
		ISC_LIST_APPEND(resps, resp, plink);
	}
	UNLOCK(&disp->lock);

	for (resp = ISC_LIST_HEAD(resps); resp != NULL; resp = next) {
		next = ISC_LIST_NEXT(resp, plink);
		ISC_LIST_UNLINK(resps, resp, plink);

		if (resp->connected != NULL) {
			resp->connected(eresult, NULL, resp->arg);
		}
		dispentry_detach(&resp);
	}

	dns_dispatch_detach(&disp);
}

static void
udp_connected(isc_nmhandle_t *handle, isc_result_t eresult, void *arg) {
	dns_dispentry_t *resp = (dns_dispentry_t *)arg;
	dns_dispatch_t *disp = resp->disp;

	dispatch_log(disp, LVL(90), "UDP connected (%p): %s", resp,
		     isc_result_totext(eresult));

	if (MGR_IS_SHUTTINGDOWN(disp->mgr)) {
		eresult = ISC_R_SHUTTINGDOWN;
	}

	if (eresult == ISC_R_SUCCESS && resp->canceled) {
		eresult = ISC_R_CANCELED;
	} else if (eresult == ISC_R_SUCCESS) {
		startrecv(handle, disp, resp);
	} else if (eresult == ISC_R_ADDRINUSE) {
		in_port_t localport = 0;
		isc_result_t result;

		/* probably a port collision; try a different one */
		disp->nsockets--;
		result = setup_socket(disp, resp, &resp->peer, &localport);
		if (result == ISC_R_SUCCESS) {
			dns_dispatch_connect(resp);
			goto detach;
		}
	}

	if (resp->connected != NULL) {
		resp->connected(eresult, NULL, resp->arg);
	}

detach:
	dispentry_detach(&resp);
}

isc_result_t
dns_dispatch_connect(dns_dispentry_t *resp) {
	dns_dispatch_t *disp = NULL;
	uint_fast32_t state = DNS_DISPATCHSTATE_NONE;

	REQUIRE(VALID_RESPONSE(resp));

	disp = resp->disp;

	/* This will be detached once we've connected. */
	dispentry_attach(resp, &(dns_dispentry_t *){ NULL });

	switch (disp->socktype) {
	case isc_socktype_tcp:
		/*
		 * Check whether the dispatch is already connecting
		 * or connected.
		 */
		atomic_compare_exchange_strong(&disp->state,
					       (uint_fast32_t *)&state,
					       DNS_DISPATCHSTATE_CONNECTING);
		switch (state) {
		case DNS_DISPATCHSTATE_NONE:
			/* First connection, continue with connecting */
			LOCK(&disp->lock);
			INSIST(ISC_LIST_EMPTY(disp->pending));
			ISC_LIST_APPEND(disp->pending, resp, plink);
			UNLOCK(&disp->lock);
			dns_dispatch_attach(disp, &(dns_dispatch_t *){ NULL });
			isc_nm_tcpdnsconnect(disp->mgr->nm, &disp->local,
					     &disp->peer, tcp_connected, disp,
					     resp->timeout, 0);
			break;

		case DNS_DISPATCHSTATE_CONNECTING:
			/* Connection pending; add resp to the list */
			LOCK(&disp->lock);
			ISC_LIST_APPEND(disp->pending, resp, plink);
			UNLOCK(&disp->lock);
			break;

		case DNS_DISPATCHSTATE_CONNECTED:
			/* We are already connected; call the connected cb */
			if (resp->connected != NULL) {
				resp->connected(ISC_R_SUCCESS, NULL, resp->arg);
			}
			dispentry_detach(&resp);
			break;

		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}

		break;

	case isc_socktype_udp:
		isc_nm_udpconnect(disp->mgr->nm, &resp->local, &resp->peer,
				  udp_connected, resp, resp->timeout, 0);
		break;

	default:
		return (ISC_R_NOTIMPLEMENTED);
	}

	return (ISC_R_SUCCESS);
}

static void
send_done(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	dns_dispentry_t *resp = (dns_dispentry_t *)cbarg;

	REQUIRE(VALID_RESPONSE(resp));

	resp->sent(result, NULL, resp->arg);

	if (result != ISC_R_SUCCESS) {
		isc_nm_cancelread(handle);
	}

	dispentry_detach(&resp);
}

void
dns_dispatch_resume(dns_dispentry_t *resp, uint16_t timeout) {
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_RESPONSE(resp));

	disp = resp->disp;

	REQUIRE(VALID_DISPATCH(disp));

	dispatch_getnext(disp, resp, timeout);
}

void
dns_dispatch_send(dns_dispentry_t *resp, isc_region_t *r, isc_dscp_t dscp) {
	isc_nmhandle_t *handle = NULL;

	REQUIRE(VALID_RESPONSE(resp));

	UNUSED(dscp);

#if 0
	/* XXX: no DSCP support */
	if (dscp == -1) {
		sendevent->attributes &= ~ISC_SOCKEVENTATTR_DSCP;
		sendevent->dscp = 0;
	} else {
		sendevent->attributes |= ISC_SOCKEVENTATTR_DSCP;
		sendevent->dscp = dscp;
		if (tcp) {
			isc_socket_dscp(sock, dscp);
		}
	}
#endif

	if (resp->disp->socktype == isc_socktype_tcp) {
		handle = resp->disp->handle;
	} else {
		handle = resp->handle;
	}

	dispentry_attach(resp, &(dns_dispentry_t *){ NULL });
	isc_nm_send(handle, r, send_done, resp);
}

isc_result_t
dns_dispatch_getlocaladdress(dns_dispatch_t *disp, isc_sockaddr_t *addrp) {
	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(addrp != NULL);

	if (disp->socktype == isc_socktype_udp) {
		*addrp = disp->local;
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
dns_dispentry_getlocaladdress(dns_dispentry_t *resp, isc_sockaddr_t *addrp) {
	REQUIRE(VALID_RESPONSE(resp));
	REQUIRE(addrp != NULL);

	if (resp->disp->socktype == isc_socktype_tcp) {
		*addrp = resp->disp->local;
		return (ISC_R_SUCCESS);
	}

	if (resp->handle != NULL) {
		*addrp = isc_nmhandle_localaddr(resp->handle);
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_NOTIMPLEMENTED);
}

dns_dispatch_t *
dns_dispatchset_get(dns_dispatchset_t *dset) {
	dns_dispatch_t *disp = NULL;

	/* check that dispatch set is configured */
	if (dset == NULL || dset->ndisp == 0) {
		return (NULL);
	}

	LOCK(&dset->lock);
	disp = dset->dispatches[dset->cur];
	dset->cur++;
	if (dset->cur == dset->ndisp) {
		dset->cur = 0;
	}
	UNLOCK(&dset->lock);

	return (disp);
}

isc_result_t
dns_dispatchset_create(isc_mem_t *mctx, dns_dispatch_t *source,
		       dns_dispatchset_t **dsetp, int n) {
	isc_result_t result;
	dns_dispatchset_t *dset = NULL;
	dns_dispatchmgr_t *mgr = NULL;
	int i, j;

	REQUIRE(VALID_DISPATCH(source));
	REQUIRE(source->socktype == isc_socktype_udp);
	REQUIRE(dsetp != NULL && *dsetp == NULL);

	mgr = source->mgr;

	dset = isc_mem_get(mctx, sizeof(dns_dispatchset_t));
	*dset = (dns_dispatchset_t){ .ndisp = n };

	isc_mutex_init(&dset->lock);

	dset->dispatches = isc_mem_get(mctx, sizeof(dns_dispatch_t *) * n);

	isc_mem_attach(mctx, &dset->mctx);

	dset->dispatches[0] = NULL;
	dns_dispatch_attach(source, &dset->dispatches[0]);

	LOCK(&mgr->lock);
	for (i = 1; i < n; i++) {
		dset->dispatches[i] = NULL;
		result = dispatch_createudp(mgr, &source->local,
					    &dset->dispatches[i]);
		if (result != ISC_R_SUCCESS) {
			goto fail;
		}
	}

	UNLOCK(&mgr->lock);
	*dsetp = dset;

	return (ISC_R_SUCCESS);

fail:
	UNLOCK(&mgr->lock);

	for (j = 0; j < i; j++) {
		dns_dispatch_detach(&(dset->dispatches[j]));
	}
	isc_mem_put(mctx, dset->dispatches, sizeof(dns_dispatch_t *) * n);
	if (dset->mctx == mctx) {
		isc_mem_detach(&dset->mctx);
	}

	isc_mutex_destroy(&dset->lock);
	isc_mem_put(mctx, dset, sizeof(dns_dispatchset_t));
	return (result);
}

void
dns_dispatchset_destroy(dns_dispatchset_t **dsetp) {
	dns_dispatchset_t *dset = NULL;
	int i;

	REQUIRE(dsetp != NULL && *dsetp != NULL);

	dset = *dsetp;
	*dsetp = NULL;
	for (i = 0; i < dset->ndisp; i++) {
		dns_dispatch_detach(&(dset->dispatches[i]));
	}
	isc_mem_put(dset->mctx, dset->dispatches,
		    sizeof(dns_dispatch_t *) * dset->ndisp);
	isc_mutex_destroy(&dset->lock);
	isc_mem_putanddetach(&dset->mctx, dset, sizeof(dns_dispatchset_t));
}
