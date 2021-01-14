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

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/netmgr.h>
#include <isc/portset.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/stats.h>
#include <dns/types.h>

typedef ISC_LIST(dns_dispentry_t) dns_displist_t;

typedef struct dispsocket dispsocket_t;

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
	isc_mem_t *mctx;
	dns_acl_t *blackhole;
	isc_stats_t *stats;
	isc_nm_t *nm;

	/* Locked by "lock". */
	isc_mutex_t lock;
	unsigned int state;
	ISC_LIST(dns_dispatch_t) list;

	/* locked by buffer_lock */
	dns_qid_t *qid;
	isc_mutex_t buffer_lock;
	unsigned int buffers;

	isc_refcount_t irefs;

	in_port_t *v4ports;    /*%< available ports for IPv4 */
	unsigned int nv4ports; /*%< # of available ports for IPv4 */
	in_port_t *v6ports;    /*%< available ports for IPv4 */
	unsigned int nv6ports; /*%< # of available ports for IPv4 */
};

#define MGR_SHUTTINGDOWN       0x00000001U
#define MGR_IS_SHUTTINGDOWN(l) (((l)->state & MGR_SHUTTINGDOWN) != 0)

struct dns_dispentry {
	unsigned int magic;
	dns_dispatch_t *disp;
	dns_messageid_t id;
	in_port_t port;
	unsigned int bucket;
	unsigned int timeout;
	isc_sockaddr_t peer;
	isc_task_t *task;
	isc_nm_cb_t connected;
	isc_nm_cb_t sent;
	isc_taskaction_t action;
	isc_taskaction_t timeout_action;
	void *arg;
	bool item_out;
	dispsocket_t *dispsocket;
	ISC_LIST(dns_dispatchevent_t) items;
	ISC_LINK(dns_dispentry_t) link;
};

/*%
 * Fixed UDP buffer size.
 */
#ifndef DNS_DISPATCH_UDPBUFSIZE
#define DNS_DISPATCH_UDPBUFSIZE 4096
#endif /* ifndef DNS_DISPATCH_UDPBUFSIZE */

struct dispsocket {
	unsigned int magic;
	isc_nmhandle_t *handle;
	dns_dispatch_t *disp;
	isc_sockaddr_t local;
	isc_sockaddr_t peer;
	dns_dispentry_t *resp;
	in_port_t port;
	ISC_LINK(dispsocket_t) link;
};

struct dns_dispatch {
	/* Unlocked. */
	unsigned int magic;	/*%< magic */
	dns_dispatchmgr_t *mgr; /*%< dispatch manager */
	isc_task_t *task;
	isc_nmhandle_t *handle; /*%< netmgr handle for TCP connection */
	isc_sockaddr_t local;	/*%< local address */
	in_port_t localport;	/*%< local UDP port */
	isc_sockaddr_t peer;	/*%< peer address (TCP) */
	isc_event_t *ctlevent;

	isc_mem_t *sepool; /*%< pool for socket events */

	/*% Locked by mgr->lock. */
	ISC_LINK(dns_dispatch_t) link;

	/* Locked by "lock". */
	isc_mutex_t lock; /*%< locks all below */
	isc_socktype_t socktype;
	unsigned int attributes;
	isc_refcount_t refcount;
	dns_dispatchevent_t *failsafe_ev; /*%< failsafe cancel event */
	unsigned int shutting_down : 1, shutdown_out : 1, recv_pending : 1;
	isc_result_t shutdown_why;
	ISC_LIST(dispsocket_t) activesockets;
	ISC_LIST(dispsocket_t) inactivesockets;
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
 * Maximum number of dispatch sockets that can be pooled for reuse.  The
 * appropriate value may vary, but experiments have shown a busy caching server
 * may need more than 1000 sockets concurrently opened.  The maximum allowable
 * number of dispatch sockets (per manager) will be set to the double of this
 * value.
 */
#ifndef DNS_DISPATCH_POOLSOCKS
#define DNS_DISPATCH_POOLSOCKS 2048
#endif /* ifndef DNS_DISPATCH_POOLSOCKS */

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
 * Number of buffers available for all dispatches in the buffer
 * memory pool.
 */
#ifndef DNS_DISPATCH_MAXBUFFERS
#define DNS_DISPATCH_MAXBUFFERS 37268
#endif /* ifndef DNS_DISPATCH_MAXBUFFERS */

/*%
 * Number of dispatch sockets available for all dispatches in the
 * socket memory pool.
 */
#ifndef DNS_DISPATCH_MAXSOCKETS
#define DNS_DISPATCH_MAXSOCKETS 32768
#endif /* ifndef DNS_DISPATCH_MAXSOCKETS */

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
static dns_dispentry_t *
entry_search(dns_qid_t *, const isc_sockaddr_t *, dns_messageid_t, in_port_t,
	     unsigned int);
static bool
destroy_disp_ok(dns_dispatch_t *);
static void
destroy_disp(isc_task_t *task, isc_event_t *event);
static void
destroy_dispsocket(dns_dispatch_t *, dispsocket_t **);
static void
deactivate_dispsocket(dns_dispatch_t *, dispsocket_t *);
static void
udp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg);
static void
tcp_recv(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	 void *arg);
static uint32_t
dns_hash(dns_qid_t *, const isc_sockaddr_t *, dns_messageid_t, in_port_t);
static inline void
free_devent(dns_dispatch_t *disp, dns_dispatchevent_t *ev);
static inline dns_dispatchevent_t *
allocate_devent(dns_dispatch_t *disp);
static void
do_cancel(dns_dispatch_t *disp);
static dns_dispentry_t *
linear_first(dns_qid_t *disp);
static dns_dispentry_t *
linear_next(dns_qid_t *disp, dns_dispentry_t *resp);
static void
dispatch_free(dns_dispatch_t **dispp);
static isc_result_t
dispatch_createudp(dns_dispatchmgr_t *mgr, isc_taskmgr_t *taskmgr,
		   const isc_sockaddr_t *localaddr, unsigned int attributes,
		   dns_dispatch_t **dispp);
static bool
destroy_mgr_ok(dns_dispatchmgr_t *mgr);
static void
destroy_mgr(dns_dispatchmgr_t **mgrp);
static void
qid_allocate(dns_dispatchmgr_t *mgr, dns_qid_t **qidp);
static void
qid_destroy(isc_mem_t *mctx, dns_qid_t **qidp);
static isc_nmhandle_t *
gethandle(dns_dispatch_t *disp);
static isc_nmhandle_t *
getentryhandle(dns_dispentry_t *resp);
static void
startrecv(dns_dispatch_t *disp, dispsocket_t *dispsocket);

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

static void
request_log(dns_dispatch_t *disp, dns_dispentry_t *resp, int level,
	    const char *fmt, ...) ISC_FORMAT_PRINTF(4, 5);

static void
request_log(dns_dispatch_t *disp, dns_dispentry_t *resp, int level,
	    const char *fmt, ...) {
	char msgbuf[2048];
	char peerbuf[256];
	va_list ap;

	if (!isc_log_wouldlog(dns_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	if (VALID_RESPONSE(resp)) {
		isc_sockaddr_format(&resp->peer, peerbuf, sizeof(peerbuf));
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DISPATCH,
			      DNS_LOGMODULE_DISPATCH, level,
			      "dispatch %p response %p %s: %s", disp, resp,
			      peerbuf, msgbuf);
	} else {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DISPATCH,
			      DNS_LOGMODULE_DISPATCH, level,
			      "dispatch %p req/resp %p: %s", disp, resp,
			      msgbuf);
	}
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

/*
 * Find the first entry in 'qid'.  Returns NULL if there are no entries.
 */
static dns_dispentry_t *
linear_first(dns_qid_t *qid) {
	dns_dispentry_t *ret = NULL;
	unsigned int bucket = 0;

	while (bucket < qid->qid_nbuckets) {
		ret = ISC_LIST_HEAD(qid->qid_table[bucket]);
		if (ret != NULL) {
			return (ret);
		}
		bucket++;
	}

	return (NULL);
}

/*
 * Find the next entry after 'resp' in 'qid'.  Return NULL if there are
 * no more entries.
 */
static dns_dispentry_t *
linear_next(dns_qid_t *qid, dns_dispentry_t *resp) {
	dns_dispentry_t *ret = NULL;
	unsigned int bucket;

	ret = ISC_LIST_NEXT(resp, link);
	if (ret != NULL) {
		return (ret);
	}

	bucket = resp->bucket + 1;
	while (bucket < qid->qid_nbuckets) {
		ret = ISC_LIST_HEAD(qid->qid_table[bucket]);
		if (ret != NULL) {
			return (ret);
		}
		bucket++;
	}

	return (NULL);
}

/*
 * The dispatch must be locked.
 */
static bool
destroy_disp_ok(dns_dispatch_t *disp) {
	if (isc_refcount_current(&disp->refcount) != 0) {
		return (false);
	}

	if (disp->recv_pending != 0) {
		return (false);
	}

	if (!ISC_LIST_EMPTY(disp->activesockets)) {
		return (false);
	}

	if (disp->shutting_down == 0) {
		return (false);
	}

	return (true);
}

/*
 * Called when refcount reaches 0 (and safe to destroy).
 *
 * The dispatcher must be locked.
 * The manager must not be locked.
 */
static void
destroy_disp(isc_task_t *task, isc_event_t *event) {
	dns_dispatch_t *disp = NULL;
	dns_dispatchmgr_t *mgr = NULL;
	bool killmgr;
	dispsocket_t *dispsocket = NULL;

	INSIST(event->ev_type == DNS_EVENT_DISPATCHCONTROL);

	UNUSED(task);

	disp = event->ev_arg;
	mgr = disp->mgr;

	LOCK(&mgr->lock);
	ISC_LIST_UNLINK(mgr->list, disp, link);

	dispatch_log(disp, LVL(90), "shutting down; detaching from handle %p",
		     disp->handle);

	if (disp->sepool != NULL) {
		isc_mem_destroy(&disp->sepool);
	}

	if (disp->handle != NULL) {
		isc_nmhandle_detach(&disp->handle);
	}
	while ((dispsocket = ISC_LIST_HEAD(disp->inactivesockets)) != NULL) {
		ISC_LIST_UNLINK(disp->inactivesockets, dispsocket, link);
		destroy_dispsocket(disp, &dispsocket);
	}
	isc_task_detach(&disp->task);
	isc_event_free(&event);

	dispatch_free(&disp);

	killmgr = destroy_mgr_ok(mgr);
	UNLOCK(&mgr->lock);
	if (killmgr) {
		destroy_mgr(&mgr);
	}
}

/*%
 * Make a new socket for a single dispatch with a random port number.
 * The caller must hold the disp->lock
 */
static isc_result_t
get_dispsocket(dns_dispatch_t *disp, const isc_sockaddr_t *dest,
	       dispsocket_t **dispsockp, in_port_t *portp) {
	dns_dispatchmgr_t *mgr = disp->mgr;
	in_port_t port;
	dispsocket_t *dispsock = NULL;
	unsigned int nports;
	in_port_t *ports = NULL;

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

	dispsock = ISC_LIST_HEAD(disp->inactivesockets);
	if (dispsock != NULL) {
		ISC_LIST_UNLINK(disp->inactivesockets, dispsock, link);
	} else {
		dispsock = isc_mem_get(mgr->mctx, sizeof(*dispsock));
		disp->nsockets++;

		*dispsock = (dispsocket_t){ .disp = disp };
		ISC_LINK_INIT(dispsock, link);
		dispsock->magic = DISPSOCK_MAGIC;
	}

	dispsock->local = disp->local;
	dispsock->peer = *dest;

	/* Pick a random UDP port */
	port = ports[isc_random_uniform(nports)];
	isc_sockaddr_setport(&dispsock->local, port);
	dispsock->port = port;

	*dispsockp = dispsock;
	*portp = port;

	return (ISC_R_SUCCESS);
}

/*%
 * Destroy a dedicated dispatch socket.
 * The dispatch must be locked.
 */
static void
destroy_dispsocket(dns_dispatch_t *disp, dispsocket_t **dispsockp) {
	dispsocket_t *dispsock = NULL;

	REQUIRE(dispsockp != NULL && *dispsockp != NULL);

	dispsock = *dispsockp;
	*dispsockp = NULL;

	REQUIRE(!ISC_LINK_LINKED(dispsock, link));

	disp->nsockets--;
	dispsock->magic = 0;
	if (dispsock->handle != NULL) {
		isc_nm_cancelread(dispsock->handle);
		isc_nmhandle_detach(&dispsock->handle);
	}

	isc_mem_put(disp->mgr->mctx, dispsock, sizeof(*dispsock));
}

/*%
 * Deactivate a dedicated dispatch socket.  Move it to the inactive list for
 * future reuse unless the total number of sockets are exceeding the maximum.
 * The dispatch must be locked.
 */
static void
deactivate_dispsocket(dns_dispatch_t *disp, dispsocket_t *dispsock) {
	ISC_LIST_UNLINK(disp->activesockets, dispsock, link);
	if (dispsock->resp != NULL) {
		INSIST(dispsock->resp->dispsocket == dispsock);
		dispsock->resp->dispsocket = NULL;
		dispsock->resp = NULL;
	}

	if (disp->nsockets > DNS_DISPATCH_POOLSOCKS) {
		destroy_dispsocket(disp, &dispsock);
	} else {
		if (dispsock->handle != NULL) {
			isc_nm_cancelread(dispsock->handle);
			isc_nmhandle_detach(&dispsock->handle);
		}

		ISC_LIST_APPEND(disp->inactivesockets, dispsock, link);
	}
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
free_buffer(dns_dispatch_t *disp, void *buf, unsigned int len) {
	REQUIRE(buf != NULL && len != 0);

	switch (disp->socktype) {
	case isc_socktype_tcp:
		INSIST(disp->tcpbuffers > 0);
		disp->tcpbuffers--;
		isc_mem_put(disp->mgr->mctx, buf, len);
		break;
	case isc_socktype_udp:
		LOCK(&disp->mgr->buffer_lock);
		INSIST(disp->mgr->buffers > 0);
		INSIST(len == DNS_DISPATCH_UDPBUFSIZE);
		disp->mgr->buffers--;
		UNLOCK(&disp->mgr->buffer_lock);
		isc_mem_put(disp->mgr->mctx, buf, len);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

static void *
allocate_udp_buffer(dns_dispatch_t *disp) {
	LOCK(&disp->mgr->buffer_lock);
	if (disp->mgr->buffers >= DNS_DISPATCH_MAXBUFFERS) {
		UNLOCK(&disp->mgr->buffer_lock);
		return (NULL);
	}
	disp->mgr->buffers++;
	UNLOCK(&disp->mgr->buffer_lock);

	return (isc_mem_get(disp->mgr->mctx, DNS_DISPATCH_UDPBUFSIZE));
}

static inline void
free_devent(dns_dispatch_t *disp, dns_dispatchevent_t *ev) {
	if (disp->failsafe_ev == ev) {
		INSIST(disp->shutdown_out == 1);
		disp->shutdown_out = 0;

		return;
	}

	if (ev->region.base != NULL) {
		free_buffer(disp, ev->region.base, ev->region.length);
		ev->region.base = NULL;
		ev->region.length = 0;
	}

	isc_refcount_decrement(&disp->mgr->irefs);
	isc_mem_put(disp->mgr->mctx, ev, sizeof(*ev));
}

static inline dns_dispatchevent_t *
allocate_devent(dns_dispatch_t *disp) {
	dns_dispatchevent_t *ev = NULL;

	ev = isc_mem_get(disp->mgr->mctx, sizeof(*ev));
	isc_refcount_increment0(&disp->mgr->irefs);

	*ev = (dns_dispatchevent_t){ 0 };
	ISC_EVENT_INIT(ev, sizeof(*ev), 0, NULL, 0, NULL, NULL, NULL, NULL,
		       NULL);
	return (ev);
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
	dispsocket_t *dispsock = (dispsocket_t *)arg;
	dns_dispatch_t *disp = NULL;
	dns_messageid_t id;
	isc_result_t dres;
	isc_buffer_t source;
	unsigned int flags;
	dns_dispentry_t *resp = NULL;
	dns_dispatchevent_t *rev = NULL;
	bool killit;
	bool queue_response;
	dns_dispatchmgr_t *mgr = NULL;
	isc_sockaddr_t peer;
	isc_netaddr_t netaddr;
	isc_taskaction_t action;
	int match;

	REQUIRE(VALID_DISPSOCK(dispsock));

	disp = dispsock->disp;

	LOCK(&disp->lock);

	mgr = disp->mgr;

	LOCK(&disp->mgr->buffer_lock);
	dispatch_log(disp, LVL(90), "got packet: requests %d, recvs %d",
		     disp->requests, disp->recv_pending);
	UNLOCK(&disp->mgr->buffer_lock);

	if (eresult == ISC_R_CANCELED || dispsock->resp == NULL) {
		/*
		 * dispsock->resp can be NULL if this transaction was canceled
		 * just after receiving a response. So we can just move on.
		 */
		dispsock = NULL;
	}

	if (disp->shutting_down == 1) {
		/*
		 * This dispatcher is shutting down.
		 */
		killit = destroy_disp_ok(disp);
		UNLOCK(&disp->lock);
		if (killit) {
			isc_task_send(disp->task, &disp->ctlevent);
		}

		return;
	}

	if (dispsock == NULL) {
		UNLOCK(&disp->lock);
		return;
	}

	resp = dispsock->resp;
	id = resp->id;

	peer = isc_nmhandle_peeraddr(handle);
	isc_netaddr_fromsockaddr(&netaddr, &peer);

	if (eresult != ISC_R_SUCCESS) {
		/*
		 * This is most likely either a timeout or a network
		 * error on a connected socket.  It makes no sense to
		 * check the address or parse the packet, but it
		 * will help to return the error to the caller.
		 */
		goto sendevent;
	}

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
	 * Look at flags.  If query, drop it. If response,
	 * look to see where it goes.
	 */
	if ((flags & DNS_MESSAGEFLAG_QR) == 0) {
		/* query */
		goto next;
	}

	/*
	 * The QID and the address must match the expected ones.
	 */
	if (resp->id != id || !isc_sockaddr_equal(&peer, &resp->peer)) {
		dispatch_log(disp, LVL(90), "response doesn't match");
		inc_stats(mgr, dns_resstatscounter_mismatch);
		goto next;
	}

sendevent:
	rev = allocate_devent(disp);
	queue_response = resp->item_out;

	/*
	 * At this point, rev contains the event we want to fill in, and
	 * resp contains the information on the place to send it to.
	 * Send the event off.
	 */
	rev->result = eresult;
	resp->item_out = true;
	if (region != NULL) {
		rev->region.base = allocate_udp_buffer(disp);
		rev->region.length = DNS_DISPATCH_UDPBUFSIZE;
		memmove(rev->region.base, region->base, region->length);
		isc_buffer_init(&rev->buffer, rev->region.base,
				rev->region.length);
		isc_buffer_add(&rev->buffer, rev->region.length);
	}

	rev->result = eresult;
	if (queue_response) {
		ISC_LIST_APPEND(resp->items, rev, ev_link);
	} else {
		ISC_EVENT_INIT(rev, sizeof(*rev), 0, NULL, DNS_EVENT_DISPATCH,
			       action, resp->arg, resp, NULL, NULL);
		request_log(disp, resp, LVL(90),
			    "[a] Sent event %p buffer %p len %d to task %p",
			    rev, rev->buffer.base, rev->buffer.length,
			    resp->task);
		isc_task_send(resp->task, ISC_EVENT_PTR(&rev));
	}

	UNLOCK(&disp->lock);
	return;

next:
	UNLOCK(&disp->lock);
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
	dns_messageid_t id;
	isc_result_t dres;
	unsigned int flags;
	dns_dispentry_t *resp = NULL;
	dns_dispatchevent_t *rev = NULL;
	unsigned int bucket;
	bool killit;
	bool queue_response;
	dns_qid_t *qid = NULL;
	int level;
	char buf[ISC_SOCKADDR_FORMATSIZE];
	isc_buffer_t source;
	isc_sockaddr_t peer;
	isc_taskaction_t action;

	REQUIRE(VALID_DISPATCH(disp));

	qid = disp->mgr->qid;

	LOCK(&disp->lock);

	dispatch_log(disp, LVL(90),
		     "got TCP packet: requests %d, buffers %d, recvs %d",
		     disp->requests, disp->tcpbuffers, disp->recv_pending);

	INSIST(disp->recv_pending != 0);
	disp->recv_pending = 0;

	if (isc_refcount_current(&disp->refcount) == 0) {
		/*
		 * This dispatcher is shutting down.  Force cancellation.
		 */
		eresult = ISC_R_CANCELED;
	}

	peer = isc_nmhandle_peeraddr(handle);
	isc_nmhandle_detach(&handle);

	if (eresult != ISC_R_SUCCESS) {
		disp->shutdown_why = eresult;

		switch (eresult) {
		case ISC_R_CANCELED:
			break;

		case ISC_R_EOF:
			dispatch_log(disp, LVL(90), "shutting down on EOF");
			do_cancel(disp);
			break;

		case ISC_R_CONNECTIONRESET:
			level = ISC_LOG_INFO;
			goto logit;

		case ISC_R_TIMEDOUT:
			id = 0; /* XXX this is broken */
			goto sendevent;

		default:
			level = ISC_LOG_ERROR;
		logit:
			isc_sockaddr_format(&peer, buf, sizeof(buf));
			dispatch_log(disp, level,
				     "shutting down due to TCP "
				     "receive error: %s: %s",
				     buf, isc_result_totext(eresult));
			do_cancel(disp);
			break;
		}

		disp->shutting_down = 1;

		/*
		 * If the recv() was canceled pass the word on.
		 */
		killit = destroy_disp_ok(disp);
		UNLOCK(&disp->lock);
		if (killit) {
			isc_task_send(disp->task, &disp->ctlevent);
		}
		return;
	}

	dispatch_log(disp, LVL(90), "result %d, length == %d, addr = %p",
		     eresult, region->length, region->base);

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
	 * Allocate an event to send to the query or response client, and
	 * allocate a new buffer for our use.
	 */

	/*
	 * Look at flags.  If query, drop it. If response,
	 * look to see where it goes.
	 */
	if ((flags & DNS_MESSAGEFLAG_QR) == 0) {
		/*
		 * Query.
		 */
		goto next;
	}

sendevent:
	/*
	 * Response.
	 */
	bucket = dns_hash(qid, &peer, id, disp->localport);
	LOCK(&qid->lock);
	resp = entry_search(qid, &peer, id, disp->localport, bucket);
	dispatch_log(disp, LVL(90), "search for response in bucket %d: %s",
		     bucket, (resp == NULL ? "not found" : "found"));
	if (resp == NULL) {
		UNLOCK(&qid->lock);
		goto next;
	}

	queue_response = resp->item_out;
	rev = allocate_devent(disp);

	/*
	 * At this point, rev contains the event we want to fill in, and
	 * resp contains the information on the place to send it to.
	 * Send the event off.
	 */
	rev->result = eresult;
	resp->item_out = true;
	if (region != NULL) {
		disp->tcpbuffers++;
		rev->region.base = isc_mem_get(disp->mgr->mctx, region->length);
		rev->region.length = region->length;
		memmove(rev->region.base, region->base, region->length);
		isc_buffer_init(&rev->buffer, rev->region.base,
				rev->region.length);
		isc_buffer_add(&rev->buffer, rev->region.length);
	}

	if (queue_response) {
		ISC_LIST_APPEND(resp->items, rev, ev_link);
	} else {
		ISC_EVENT_INIT(rev, sizeof(*rev), 0, NULL, DNS_EVENT_DISPATCH,
			       action, resp->arg, resp, NULL, NULL);
		request_log(disp, resp, LVL(90),
			    "[b] Sent event %p buffer %p len %d to task %p",
			    rev, rev->buffer.base, rev->buffer.length,
			    resp->task);
		isc_task_send(resp->task, ISC_EVENT_PTR(&rev));
	}
	UNLOCK(&qid->lock);

next:
	startrecv(disp, NULL);
	UNLOCK(&disp->lock);
}

/*
 * Mgr must be locked when calling this function.
 */
static bool
destroy_mgr_ok(dns_dispatchmgr_t *mgr) {
	mgr_log(mgr, LVL(90),
		"destroy_mgr_ok: shuttingdown=%d, listnonempty=%d, ",
		MGR_IS_SHUTTINGDOWN(mgr), !ISC_LIST_EMPTY(mgr->list));
	if (!MGR_IS_SHUTTINGDOWN(mgr)) {
		return (false);
	}
	if (!ISC_LIST_EMPTY(mgr->list)) {
		return (false);
	}
	if (isc_refcount_current(&mgr->irefs) != 0) {
		return (false);
	}

	return (true);
}

/*
 * Mgr must be unlocked when calling this function.
 */
static void
destroy_mgr(dns_dispatchmgr_t **mgrp) {
	dns_dispatchmgr_t *mgr = NULL;

	mgr = *mgrp;
	*mgrp = NULL;

	mgr->magic = 0;
	isc_mutex_destroy(&mgr->lock);
	mgr->state = 0;

	if (mgr->qid != NULL) {
		qid_destroy(mgr->mctx, &mgr->qid);
	}

	isc_mutex_destroy(&mgr->buffer_lock);

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

	isc_refcount_init(&mgr->irefs, 0);

	isc_mem_attach(mctx, &mgr->mctx);
	isc_nm_attach(nm, &mgr->nm);

	isc_mutex_init(&mgr->lock);
	isc_mutex_init(&mgr->buffer_lock);

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

void
dns_dispatchmgr_destroy(dns_dispatchmgr_t **mgrp) {
	dns_dispatchmgr_t *mgr = NULL;
	bool killit;

	REQUIRE(mgrp != NULL);
	REQUIRE(VALID_DISPATCHMGR(*mgrp));

	mgr = *mgrp;
	*mgrp = NULL;

	LOCK(&mgr->lock);
	mgr->state |= MGR_SHUTTINGDOWN;
	killit = destroy_mgr_ok(mgr);
	UNLOCK(&mgr->lock);

	mgr_log(mgr, LVL(90), "destroy: killit=%d", killit);

	if (killit) {
		destroy_mgr(&mgr);
	}
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
dispatch_allocate(dns_dispatchmgr_t *mgr, isc_socktype_t type, int pf,
		  unsigned int attributes, dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(dispp != NULL && *dispp == NULL);

	/*
	 * Set up the dispatcher, mostly.  Don't bother setting some of
	 * the options that are controlled by tcp vs. udp, etc.
	 */

	disp = isc_mem_get(mgr->mctx, sizeof(*disp));
	isc_refcount_increment0(&mgr->irefs);

	*disp = (dns_dispatch_t){ .mgr = mgr,
				  .socktype = type,
				  .shutdown_why = ISC_R_UNEXPECTED };
	isc_refcount_init(&disp->refcount, 1);
	ISC_LINK_INIT(disp, link);
	ISC_LIST_INIT(disp->activesockets);
	ISC_LIST_INIT(disp->inactivesockets);

	switch (type) {
	case isc_socktype_tcp:
		disp->attributes |= DNS_DISPATCHATTR_TCP;
		break;
	case isc_socktype_udp:
		disp->attributes |= DNS_DISPATCHATTR_UDP;
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	switch (pf) {
	case PF_INET:
		disp->attributes |= DNS_DISPATCHATTR_IPV4;
		break;
	case PF_INET6:
		disp->attributes |= DNS_DISPATCHATTR_IPV6;
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	/*
	 * Set whatever attributes were passed in that haven't been
	 * reset automatically by the code above.
	 */
	attributes &= ~(DNS_DISPATCHATTR_UDP | DNS_DISPATCHATTR_TCP |
			DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_IPV6);
	disp->attributes |= attributes;

	isc_mutex_init(&disp->lock);
	disp->failsafe_ev = allocate_devent(disp);
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

	mgr = disp->mgr;
	REQUIRE(VALID_DISPATCHMGR(mgr));

	INSIST(disp->requests == 0);
	INSIST(disp->recv_pending == 0);
	INSIST(ISC_LIST_EMPTY(disp->activesockets));
	INSIST(ISC_LIST_EMPTY(disp->inactivesockets));

	isc_refcount_decrement(&mgr->irefs);

	if (disp->failsafe_ev != NULL) {
		isc_mem_put(mgr->mctx, disp->failsafe_ev,
			    sizeof(*disp->failsafe_ev));
		disp->failsafe_ev = NULL;
	}

	disp->mgr = NULL;
	isc_mutex_destroy(&disp->lock);
	disp->magic = 0;
	isc_refcount_decrement(&mgr->irefs);
	isc_mem_put(mgr->mctx, disp, sizeof(*disp));
}

isc_result_t
dns_dispatch_createtcp(dns_dispatchmgr_t *mgr, isc_taskmgr_t *taskmgr,
		       const isc_sockaddr_t *localaddr,
		       const isc_sockaddr_t *destaddr, unsigned int attributes,
		       isc_dscp_t dscp, dns_dispatch_t **dispp) {
	isc_result_t result;
	dns_dispatch_t *disp = NULL;
	int pf;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(destaddr != NULL);

	UNUSED(dscp);

	LOCK(&mgr->lock);

	pf = isc_sockaddr_pf(destaddr);
	dispatch_allocate(mgr, isc_socktype_tcp, pf, attributes, &disp);

	disp->peer = *destaddr;

	if (localaddr != NULL) {
		disp->local = *localaddr;
	} else {
		isc_sockaddr_anyofpf(&disp->local, pf);
		isc_sockaddr_setport(&disp->local, 0);
	}

	result = isc_task_create(taskmgr, 50, &disp->task);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	disp->ctlevent =
		isc_event_allocate(mgr->mctx, disp, DNS_EVENT_DISPATCHCONTROL,
				   destroy_disp, disp, sizeof(isc_event_t));

	isc_task_setname(disp->task, "tcpdispatch", disp);

	/*
	 * Append it to the dispatcher list.
	 */
	ISC_LIST_APPEND(mgr->list, disp, link);
	UNLOCK(&mgr->lock);

	if (isc_log_wouldlog(dns_lctx, 90)) {
		mgr_log(mgr, LVL(90),
			"dns_dispatch_createtcp: created TCP dispatch %p",
			disp);
		dispatch_log(disp, LVL(90), "created task %p", disp->task);
	}
	*dispp = disp;

	return (ISC_R_SUCCESS);

cleanup:
	dispatch_free(&disp);

	UNLOCK(&mgr->lock);

	return (result);
}

#define ATTRMATCH(_a1, _a2, _mask) (((_a1) & (_mask)) == ((_a2) & (_mask)))

isc_result_t
dns_dispatch_gettcp(dns_dispatchmgr_t *mgr, const isc_sockaddr_t *destaddr,
		    const isc_sockaddr_t *localaddr, bool *connected,
		    dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;
	isc_sockaddr_t peeraddr;
	isc_sockaddr_t sockname;
	unsigned int attributes, mask;
	bool match = false;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(destaddr != NULL);
	REQUIRE(dispp != NULL && *dispp == NULL);

	/* First pass  */
	attributes = DNS_DISPATCHATTR_TCP | DNS_DISPATCHATTR_CONNECTED;
	mask = DNS_DISPATCHATTR_TCP | DNS_DISPATCHATTR_PRIVATE |
	       DNS_DISPATCHATTR_CONNECTED;

	LOCK(&mgr->lock);
	disp = ISC_LIST_HEAD(mgr->list);
	while (disp != NULL && !match) {
		LOCK(&disp->lock);
		if ((disp->shutting_down == 0) &&
		    ATTRMATCH(disp->attributes, attributes, mask) &&
		    (localaddr == NULL ||
		     isc_sockaddr_eqaddr(localaddr, &disp->local)))
		{
			sockname = isc_nmhandle_localaddr(disp->handle);
			peeraddr = isc_nmhandle_peeraddr(disp->handle);
			if (isc_sockaddr_equal(destaddr, &peeraddr) &&
			    (localaddr == NULL ||
			     isc_sockaddr_eqaddr(localaddr, &sockname)))
			{
				/* attach */
				isc_refcount_increment(&disp->refcount);
				*dispp = disp;
				match = true;
				if (connected != NULL) {
					*connected = true;
				}
			}
		}
		UNLOCK(&disp->lock);
		disp = ISC_LIST_NEXT(disp, link);
	}
	if (match || connected == NULL) {
		UNLOCK(&mgr->lock);
		return (match ? ISC_R_SUCCESS : ISC_R_NOTFOUND);
	}

	/* Second pass, only if connected != NULL */
	attributes = DNS_DISPATCHATTR_TCP;

	disp = ISC_LIST_HEAD(mgr->list);
	while (disp != NULL && !match) {
		LOCK(&disp->lock);
		if ((disp->shutting_down == 0) &&
		    ATTRMATCH(disp->attributes, attributes, mask) &&
		    (localaddr == NULL ||
		     isc_sockaddr_eqaddr(localaddr, &disp->local)) &&
		    isc_sockaddr_equal(destaddr, &disp->peer))
		{
			/* attach */
			isc_refcount_increment(&disp->refcount);
			*dispp = disp;
			match = true;
		}
		UNLOCK(&disp->lock);
		disp = ISC_LIST_NEXT(disp, link);
	}
	UNLOCK(&mgr->lock);

	return (match ? ISC_R_SUCCESS : ISC_R_NOTFOUND);
}

isc_result_t
dns_dispatch_createudp(dns_dispatchmgr_t *mgr, isc_taskmgr_t *taskmgr,
		       const isc_sockaddr_t *localaddr, unsigned int attributes,
		       dns_dispatch_t **dispp) {
	isc_result_t result;
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_DISPATCHMGR(mgr));
	REQUIRE(localaddr != NULL);
	REQUIRE(taskmgr != NULL);
	REQUIRE(dispp != NULL && *dispp == NULL);

	LOCK(&mgr->lock);
	result = dispatch_createudp(mgr, taskmgr, localaddr, attributes, &disp);
	if (result == ISC_R_SUCCESS) {
		*dispp = disp;
	}
	UNLOCK(&mgr->lock);

	return (result);
}

static isc_result_t
dispatch_createudp(dns_dispatchmgr_t *mgr, isc_taskmgr_t *taskmgr,
		   const isc_sockaddr_t *localaddr, unsigned int attributes,
		   dns_dispatch_t **dispp) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_dispatch_t *disp = NULL;
	isc_sockaddr_t sa_any;
	int pf;

	pf = isc_sockaddr_pf(localaddr);
	dispatch_allocate(mgr, isc_socktype_udp, pf, attributes, &disp);

	/*
	 * Check whether this address/port is available locally.
	 */
	isc_sockaddr_anyofpf(&sa_any, pf);
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
	result = isc_task_create(taskmgr, 0, &disp->task);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	disp->ctlevent =
		isc_event_allocate(mgr->mctx, disp, DNS_EVENT_DISPATCHCONTROL,
				   destroy_disp, disp, sizeof(isc_event_t));

	disp->sepool = NULL;
	isc_mem_create(&disp->sepool);
	isc_mem_setname(disp->sepool, "disp_sepool");

	/*
	 * Append it to the dispatcher list.
	 */
	ISC_LIST_APPEND(mgr->list, disp, link);

	mgr_log(mgr, LVL(90), "created UDP dispatcher %p", disp);
	dispatch_log(disp, LVL(90), "created task %p", disp->task);

	*dispp = disp;

	return (result);

	/*
	 * Error returns.
	 */
cleanup:
	dispatch_free(&disp);

	return (result);
}

void
dns_dispatch_attach(dns_dispatch_t *disp, dns_dispatch_t **dispp) {
	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(dispp != NULL && *dispp == NULL);

	isc_refcount_increment(&disp->refcount);
	*dispp = disp;
}

void
dns_dispatch_detach(dns_dispatch_t **dispp) {
	dns_dispatch_t *disp = NULL;
	dispsocket_t *dispsock = NULL;
	bool killit = false;

	REQUIRE(dispp != NULL && VALID_DISPATCH(*dispp));

	disp = *dispp;
	*dispp = NULL;

	if (isc_refcount_decrement(&disp->refcount) == 1) {
		LOCK(&disp->lock);
		if (disp->recv_pending != 0 && disp->handle != NULL) {
			isc_nm_cancelread(disp->handle);
		}
		if (disp->handle != NULL) {
			isc_nmhandle_detach(&disp->handle);
		}
		for (dispsock = ISC_LIST_HEAD(disp->activesockets);
		     dispsock != NULL; dispsock = ISC_LIST_NEXT(dispsock, link))
		{
			if (dispsock->handle != NULL) {
				isc_nmhandle_detach(&dispsock->handle);
			}
		}
		disp->shutting_down = 1;
		do_cancel(disp);

		killit = destroy_disp_ok(disp);
		UNLOCK(&disp->lock);
	}

	dispatch_log(disp, LVL(90), "detach: refcount %" PRIuFAST32,
		     isc_refcount_current(&disp->refcount));

	if (killit) {
		isc_task_send(disp->task, &disp->ctlevent);
	}
}

isc_result_t
dns_dispatch_addresponse(dns_dispatch_t *disp, unsigned int options,
			 unsigned int timeout, const isc_sockaddr_t *dest,
			 isc_task_t *task, isc_nm_cb_t connected,
			 isc_nm_cb_t sent, isc_taskaction_t action,
			 isc_taskaction_t timeout_action, void *arg,
			 dns_messageid_t *idp, dns_dispentry_t **resp) {
	isc_result_t result;
	dns_dispentry_t *res = NULL;
	dispsocket_t *dispsocket = NULL;
	dns_qid_t *qid = NULL;
	in_port_t localport = 0;
	dns_messageid_t id;
	unsigned int bucket;
	bool ok = false;
	int i = 0;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(task != NULL);
	REQUIRE(dest != NULL);
	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(idp != NULL);
	REQUIRE(disp->socktype == isc_socktype_tcp ||
		disp->socktype == isc_socktype_udp);

	LOCK(&disp->lock);

	if (disp->shutting_down == 1) {
		UNLOCK(&disp->lock);
		return (ISC_R_SHUTTINGDOWN);
	}

	if (disp->requests >= DNS_DISPATCH_MAXREQUESTS) {
		UNLOCK(&disp->lock);
		return (ISC_R_QUOTA);
	}

	qid = disp->mgr->qid;

	if (disp->socktype == isc_socktype_udp &&
	    disp->nsockets > DNS_DISPATCH_SOCKSQUOTA)
	{
		dispsocket_t *oldestsocket = NULL;
		dns_dispentry_t *oldestresp = NULL;
		dns_dispatchevent_t *rev = NULL;

		/*
		 * Kill oldest outstanding query if the number of sockets
		 * exceeds the quota to keep the room for new queries.
		 */
		oldestsocket = ISC_LIST_HEAD(disp->activesockets);
		oldestresp = oldestsocket->resp;
		if (oldestresp != NULL && !oldestresp->item_out) {
			rev = allocate_devent(oldestresp->disp);
			rev->buffer.base = NULL;
			rev->result = ISC_R_CANCELED;
			ISC_EVENT_INIT(rev, sizeof(*rev), 0, NULL,
				       DNS_EVENT_DISPATCH, oldestresp->action,
				       oldestresp->arg, oldestresp, NULL, NULL);
			oldestresp->item_out = true;
			isc_task_send(oldestresp->task, ISC_EVENT_PTR(&rev));
			inc_stats(disp->mgr, dns_resstatscounter_dispabort);
		}

		/*
		 * Move this entry to the tail so that it won't (easily) be
		 * examined before actually being canceled.
		 */
		ISC_LIST_UNLINK(disp->activesockets, oldestsocket, link);
		ISC_LIST_APPEND(disp->activesockets, oldestsocket, link);
	}

	if (disp->socktype == isc_socktype_udp) {
		/*
		 * Get a separate UDP socket with a random port number.
		 */
		result = get_dispsocket(disp, dest, &dispsocket, &localport);
		if (result != ISC_R_SUCCESS) {
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
		UNLOCK(&disp->lock);
		return (ISC_R_NOMORE);
	}

	res = isc_mem_get(disp->mgr->mctx, sizeof(*res));
	isc_refcount_increment0(&disp->mgr->irefs);

	*res = (dns_dispentry_t){ .id = id,
				  .port = localport,
				  .bucket = bucket,
				  .timeout = timeout,
				  .peer = *dest,
				  .connected = connected,
				  .sent = sent,
				  .action = action,
				  .timeout_action = timeout_action,
				  .arg = arg,
				  .dispsocket = dispsocket };

	dns_dispatch_attach(disp, &res->disp);
	isc_task_attach(task, &res->task);

	ISC_LIST_INIT(res->items);
	ISC_LINK_INIT(res, link);
	res->magic = RESPONSE_MAGIC;

	disp->requests++;

	if (dispsocket != NULL) {
		dispsocket->resp = res;
	}

	LOCK(&qid->lock);
	ISC_LIST_APPEND(qid->qid_table[bucket], res, link);
	UNLOCK(&qid->lock);

	request_log(disp, res, LVL(90), "attached to task %p", res->task);

	inc_stats(disp->mgr, (disp->socktype == isc_socktype_udp)
				     ? dns_resstatscounter_disprequdp
				     : dns_resstatscounter_dispreqtcp);

	if (dispsocket != NULL) {
		ISC_LIST_APPEND(disp->activesockets, dispsocket, link);
	}

	UNLOCK(&disp->lock);

	INSIST(disp->socktype == isc_socktype_tcp || res->dispsocket != NULL);

	*idp = id;
	*resp = res;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_dispatch_getnext(dns_dispentry_t *resp, dns_dispatchevent_t **sockevent) {
	dns_dispatch_t *disp = NULL;
	dns_dispatchevent_t *ev = NULL;

	REQUIRE(VALID_RESPONSE(resp));
	REQUIRE(sockevent != NULL && *sockevent != NULL);

	disp = resp->disp;
	REQUIRE(VALID_DISPATCH(disp));

	ev = *sockevent;
	*sockevent = NULL;

	LOCK(&disp->lock);

	REQUIRE(resp->item_out);
	resp->item_out = false;

	free_devent(disp, ev);

	if (disp->shutting_down == 1) {
		UNLOCK(&disp->lock);
		return (ISC_R_SHUTTINGDOWN);
	}

	ev = ISC_LIST_HEAD(resp->items);
	if (ev != NULL) {
		ISC_LIST_UNLINK(resp->items, ev, ev_link);
		ISC_EVENT_INIT(ev, sizeof(*ev), 0, NULL, DNS_EVENT_DISPATCH,
			       resp->action, resp->arg, resp, NULL, NULL);
		request_log(disp, resp, LVL(90),
			    "[c] Sent event %p buffer %p len %d to task %p", ev,
			    ev->buffer.base, ev->buffer.length, resp->task);
		resp->item_out = true;
		isc_task_send(resp->task, ISC_EVENT_PTR(&ev));
	}

	startrecv(disp, resp->dispsocket);

	UNLOCK(&disp->lock);

	return (ISC_R_SUCCESS);
}

void
dns_dispatch_removeresponse(dns_dispentry_t **resp,
			    dns_dispatchevent_t **sockevent) {
	dns_dispatchmgr_t *mgr = NULL;
	dns_dispatch_t *disp = NULL;
	dns_dispentry_t *res = NULL;
	dns_dispatchevent_t *ev = NULL;
	unsigned int bucket;
	isc_eventlist_t events;
	dns_qid_t *qid = NULL;

	REQUIRE(resp != NULL);
	REQUIRE(VALID_RESPONSE(*resp));

	res = *resp;
	*resp = NULL;

	disp = res->disp;
	res->disp = NULL;
	REQUIRE(VALID_DISPATCH(disp));

	mgr = disp->mgr;
	REQUIRE(VALID_DISPATCHMGR(mgr));
	qid = mgr->qid;

	if (sockevent != NULL) {
		REQUIRE(*sockevent != NULL);
		ev = *sockevent;
		*sockevent = NULL;
	} else {
		ev = NULL;
	}

	LOCK(&disp->lock);
	INSIST(disp->requests > 0);
	disp->requests--;
	dec_stats(disp->mgr, (disp->socktype == isc_socktype_udp)
				     ? dns_resstatscounter_disprequdp
				     : dns_resstatscounter_dispreqtcp);

	if (res->dispsocket != NULL) {
		deactivate_dispsocket(disp, res->dispsocket);
	}
	UNLOCK(&disp->lock);

	bucket = res->bucket;

	LOCK(&qid->lock);
	ISC_LIST_UNLINK(qid->qid_table[bucket], res, link);
	UNLOCK(&qid->lock);

	if (ev == NULL && res->item_out) {
		unsigned int n;

		/*
		 * We've posted our event, but the caller hasn't gotten it
		 * yet.  Take it back.
		 */
		ISC_LIST_INIT(events);
		n = isc_task_unsend(res->task, res, DNS_EVENT_DISPATCH, NULL,
				    &events);
		/*
		 * We had better have gotten it back.
		 */
		INSIST(n == 1);
		ev = (dns_dispatchevent_t *)ISC_LIST_HEAD(events);
	}

	if (ev != NULL) {
		REQUIRE(res->item_out);
		res->item_out = false;
		free_devent(disp, ev);
	}

	request_log(disp, res, LVL(90), "detaching from task %p", res->task);
	isc_task_detach(&res->task);

	/*
	 * Free any buffered responses as well
	 */
	ev = ISC_LIST_HEAD(res->items);
	while (ev != NULL) {
		ISC_LIST_UNLINK(res->items, ev, ev_link);
		free_devent(disp, ev);
		ev = ISC_LIST_HEAD(res->items);
	}
	res->magic = 0;
	isc_refcount_decrement(&disp->mgr->irefs);
	isc_mem_put(disp->mgr->mctx, res, sizeof(*res));

	dns_dispatch_detach(&disp);
}

/*
 * disp must be locked.
 */
static void
startrecv(dns_dispatch_t *disp, dispsocket_t *dispsocket) {
	isc_nmhandle_t *handle = NULL;

	if (disp->shutting_down == 1) {
		return;
	}

	if (dispsocket == NULL) {
		if (disp->socktype == isc_socktype_udp ||
		    disp->recv_pending != 0) {
			return;
		}
		isc_nmhandle_attach(disp->handle, &handle);
	} else {
		handle = dispsocket->handle;
	}

	switch (disp->socktype) {
	case isc_socktype_udp:
		isc_nm_read(handle, udp_recv, dispsocket);
		break;

	case isc_socktype_tcp:
		isc_nm_read(handle, tcp_recv, disp);
		INSIST(disp->recv_pending == 0);
		disp->recv_pending = 1;
		break;

	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

static void
disp_connected(isc_nmhandle_t *handle, isc_result_t eresult, void *arg) {
	dns_dispentry_t *resp = (dns_dispentry_t *)arg;
	dns_dispatch_t *disp = resp->disp;
	dispsocket_t *dispsocket = NULL;

	if (eresult == ISC_R_SUCCESS) {
		if (disp->socktype == isc_socktype_udp) {
			dispsocket = resp->dispsocket;
			isc_nmhandle_attach(handle, &dispsocket->handle);
		} else if (disp->handle == NULL) {
			disp->attributes |= DNS_DISPATCHATTR_CONNECTED;
			isc_nmhandle_attach(handle, &disp->handle);
		}

		startrecv(disp, dispsocket);
	}

	if (resp->connected != NULL) {
		resp->connected(handle, eresult, resp->arg);
	}
}

isc_result_t
dns_dispatch_connect(dns_dispentry_t *resp) {
	dns_dispatch_t *disp = NULL;

	REQUIRE(VALID_RESPONSE(resp));

	disp = resp->disp;

	switch (disp->socktype) {
	case isc_socktype_tcp:
		if (disp->handle != NULL) {
			break;
		}

		isc_nm_tcpdnsconnect(disp->mgr->nm, &disp->local, &disp->peer,
				     disp_connected, resp, resp->timeout, 0);
		break;
	case isc_socktype_udp:
		isc_nm_udpconnect(disp->mgr->nm, &resp->dispsocket->local,
				  &resp->dispsocket->peer, disp_connected, resp,
				  resp->timeout, 0);
		break;
	default:
		return (ISC_R_NOTIMPLEMENTED);
	}

	return (ISC_R_SUCCESS);
}

void
dns_dispatch_send(dns_dispentry_t *resp, isc_region_t *r, isc_dscp_t dscp) {
	isc_nmhandle_t *handle = NULL;

	REQUIRE(VALID_RESPONSE(resp));

	UNUSED(dscp);

	handle = getentryhandle(resp);

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

	isc_nm_send(handle, r, resp->sent, resp->arg);
}

void
dns_dispatch_cancel(dns_dispatch_t *disp, dns_dispentry_t *resp, bool sending,
		    bool connecting) {
	isc_nmhandle_t *handle = NULL;

	REQUIRE(disp != NULL || resp != NULL);

	if (resp != NULL) {
		REQUIRE(VALID_RESPONSE(resp));
		handle = getentryhandle(resp);
	} else if (disp != NULL) {
		REQUIRE(VALID_DISPATCH(disp));
		handle = gethandle(disp);
	} else {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	if (handle == NULL) {
		return;
	}

	if (connecting) {
		// isc_socket_cancel(sock, NULL, ISC_SOCKCANCEL_CONNECT);
	}

	if (sending) {
		// isc_socket_cancel(sock, NULL, ISC_SOCKCANCEL_SEND);
	}
}

/*
 * disp must be locked.
 */
static void
do_cancel(dns_dispatch_t *disp) {
	dns_dispatchevent_t *ev = NULL;
	dns_dispentry_t *resp = NULL;
	dns_qid_t *qid = disp->mgr->qid;

	if (disp->shutdown_out == 1) {
		return;
	}

	/*
	 * Search for the first response handler without packets outstanding
	 * unless a specific handler is given.
	 */
	LOCK(&qid->lock);
	for (resp = linear_first(qid); resp != NULL && resp->item_out;
	     /* Empty. */)
	{
		resp = linear_next(qid, resp);
	}

	/*
	 * No one to send the cancel event to, so nothing to do.
	 */
	if (resp == NULL) {
		goto unlock;
	}

	/*
	 * Send the shutdown failsafe event to this resp.
	 */
	ev = disp->failsafe_ev;
	disp->failsafe_ev = NULL;
	ISC_EVENT_INIT(ev, sizeof(*ev), 0, NULL, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	ev->result = disp->shutdown_why;
	ev->buffer.base = NULL;
	ev->buffer.length = 0;
	disp->shutdown_out = 1;
	request_log(disp, resp, LVL(10), "cancel: failsafe event %p -> task %p",
		    ev, resp->task);
	resp->item_out = true;
	isc_task_send(resp->task, ISC_EVENT_PTR(&ev));
unlock:
	UNLOCK(&qid->lock);
}

static isc_nmhandle_t *
gethandle(dns_dispatch_t *disp) {
	REQUIRE(VALID_DISPATCH(disp));

	return (disp->handle);
}

static isc_nmhandle_t *
getentryhandle(dns_dispentry_t *resp) {
	REQUIRE(VALID_RESPONSE(resp));

	if (resp->disp->socktype == isc_socktype_tcp) {
		return (resp->disp->handle);
	} else if (resp->dispsocket != NULL) {
		return (resp->dispsocket->handle);
	} else {
		return (NULL);
	}
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

	if (resp->dispsocket != NULL && resp->dispsocket->handle != NULL) {
		*addrp = isc_nmhandle_localaddr(resp->dispsocket->handle);
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_NOTIMPLEMENTED);
}

unsigned int
dns_dispatch_getattributes(dns_dispatch_t *disp) {
	REQUIRE(VALID_DISPATCH(disp));

	/*
	 * We don't bother locking disp here; it's the caller's responsibility
	 * to use only non volatile flags.
	 */
	return (disp->attributes);
}

void
dns_dispatch_changeattributes(dns_dispatch_t *disp, unsigned int attributes,
			      unsigned int mask) {
	REQUIRE(VALID_DISPATCH(disp));

	LOCK(&disp->lock);

	disp->attributes &= ~mask;
	disp->attributes |= (attributes & mask);
	UNLOCK(&disp->lock);
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
dns_dispatchset_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       dns_dispatch_t *source, dns_dispatchset_t **dsetp,
		       int n) {
	isc_result_t result;
	dns_dispatchset_t *dset = NULL;
	dns_dispatchmgr_t *mgr = NULL;
	int i, j;

	REQUIRE(VALID_DISPATCH(source));
	REQUIRE((source->attributes & DNS_DISPATCHATTR_UDP) != 0);
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
		result = dispatch_createudp(mgr, taskmgr, &source->local,
					    source->attributes,
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
