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

#include <assert.h>
#include <inttypes.h>
#include <unistd.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/backtrace.h>
#include <isc/barrier.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/errno.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/print.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/stats.h>
#include <isc/strerr.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/tls.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "../loop_p.h"
#include "netmgr-int.h"
#include "openssl_shim.h"
#include "trampoline_p.h"

/*%
 * How many isc_nmhandles and isc_nm_uvreqs will we be
 * caching for reuse in a socket.
 */
#define ISC_NM_HANDLES_STACK_SIZE 600
#define ISC_NM_REQS_STACK_SIZE	  600

/*%
 * Shortcut index arrays to get access to statistics counters.
 */

static const isc_statscounter_t udp4statsindex[] = {
	isc_sockstatscounter_udp4open,
	isc_sockstatscounter_udp4openfail,
	isc_sockstatscounter_udp4close,
	isc_sockstatscounter_udp4bindfail,
	isc_sockstatscounter_udp4connectfail,
	isc_sockstatscounter_udp4connect,
	-1,
	-1,
	isc_sockstatscounter_udp4sendfail,
	isc_sockstatscounter_udp4recvfail,
	isc_sockstatscounter_udp4active
};

static const isc_statscounter_t udp6statsindex[] = {
	isc_sockstatscounter_udp6open,
	isc_sockstatscounter_udp6openfail,
	isc_sockstatscounter_udp6close,
	isc_sockstatscounter_udp6bindfail,
	isc_sockstatscounter_udp6connectfail,
	isc_sockstatscounter_udp6connect,
	-1,
	-1,
	isc_sockstatscounter_udp6sendfail,
	isc_sockstatscounter_udp6recvfail,
	isc_sockstatscounter_udp6active
};

static const isc_statscounter_t tcp4statsindex[] = {
	isc_sockstatscounter_tcp4open,	      isc_sockstatscounter_tcp4openfail,
	isc_sockstatscounter_tcp4close,	      isc_sockstatscounter_tcp4bindfail,
	isc_sockstatscounter_tcp4connectfail, isc_sockstatscounter_tcp4connect,
	isc_sockstatscounter_tcp4acceptfail,  isc_sockstatscounter_tcp4accept,
	isc_sockstatscounter_tcp4sendfail,    isc_sockstatscounter_tcp4recvfail,
	isc_sockstatscounter_tcp4active
};

static const isc_statscounter_t tcp6statsindex[] = {
	isc_sockstatscounter_tcp6open,	      isc_sockstatscounter_tcp6openfail,
	isc_sockstatscounter_tcp6close,	      isc_sockstatscounter_tcp6bindfail,
	isc_sockstatscounter_tcp6connectfail, isc_sockstatscounter_tcp6connect,
	isc_sockstatscounter_tcp6acceptfail,  isc_sockstatscounter_tcp6accept,
	isc_sockstatscounter_tcp6sendfail,    isc_sockstatscounter_tcp6recvfail,
	isc_sockstatscounter_tcp6active
};

#if 0
/* XXX: not currently used */
static const isc_statscounter_t unixstatsindex[] = {
	isc_sockstatscounter_unixopen,
	isc_sockstatscounter_unixopenfail,
	isc_sockstatscounter_unixclose,
	isc_sockstatscounter_unixbindfail,
	isc_sockstatscounter_unixconnectfail,
	isc_sockstatscounter_unixconnect,
	isc_sockstatscounter_unixacceptfail,
	isc_sockstatscounter_unixaccept,
	isc_sockstatscounter_unixsendfail,
	isc_sockstatscounter_unixrecvfail,
	isc_sockstatscounter_unixactive
};
#endif /* if 0 */

/*
 * Set by the -T dscp option on the command line. If set to a value
 * other than -1, we check to make sure DSCP values match it, and
 * assert if not. (Not currently in use.)
 */
int isc_dscp_check_value = -1;

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock FLARG);
static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle);

static void
process_netievent(void *arg);

static void
isc__nm_async_detach(isc__networker_t *worker, isc__netievent_t *ev0);

/*%<
 * Issue a 'handle closed' callback on the socket.
 */

static void
nmhandle_detach_cb(isc_nmhandle_t **handlep FLARG);

static void
shutdown_walk_cb(uv_handle_t *handle, void *arg);

static void
networker_teardown(void *arg) {
	isc__networker_t *worker = arg;
	isc_loop_t *loop = worker->loop;

	worker->shuttingdown = true;

	isc__netmgr_log(worker->netmgr, ISC_LOG_DEBUG(1),
			"Shutting down network manager worker on loop %p(%d)",
			loop, isc_tid());

	uv_walk(&loop->loop, shutdown_walk_cb, NULL);

	isc__networker_detach(&worker);
}

static void
netmgr_teardown(void *arg) {
	isc_nm_t *netmgr = (void *)arg;

	if (atomic_compare_exchange_strong(&netmgr->shuttingdown,
					   &(bool){ false }, true))
	{
		isc__netmgr_log(netmgr, ISC_LOG_DEBUG(1),
				"Shutting down network manager");
	}
}

#if HAVE_DECL_UV_UDP_LINUX_RECVERR
#define MINIMAL_UV_VERSION UV_VERSION(1, 42, 0)
#elif HAVE_DECL_UV_UDP_MMSG_FREE
#define MINIMAL_UV_VERSION UV_VERSION(1, 40, 0)
#elif HAVE_DECL_UV_UDP_RECVMMSG
#define MINIMAL_UV_VERSION UV_VERSION(1, 37, 0)
#elif HAVE_DECL_UV_UDP_MMSG_CHUNK
#define MINIMAL_UV_VERSION UV_VERSION(1, 35, 0)
#else
#define MINIMAL_UV_VERSION UV_VERSION(1, 0, 0)
#endif

void
isc_netmgr_create(isc_mem_t *mctx, isc_loopmgr_t *loopmgr, isc_nm_t **netmgrp) {
	isc_nm_t *netmgr = NULL;

	if (uv_version() < MINIMAL_UV_VERSION) {
		FATAL_ERROR("libuv version too old: running with libuv %s "
			    "when compiled with libuv %s will lead to "
			    "libuv failures because of unknown flags",
			    uv_version_string(), UV_VERSION_STRING);
	}

	netmgr = isc_mem_get(mctx, sizeof(*netmgr));
	*netmgr = (isc_nm_t){
		.loopmgr = loopmgr,
		.nloops = isc_loopmgr_nloops(loopmgr),
	};

	isc_mem_attach(mctx, &netmgr->mctx);
	isc_mutex_init(&netmgr->lock);
	isc_refcount_init(&netmgr->references, 1);
	atomic_init(&netmgr->maxudp, 0);
	atomic_init(&netmgr->shuttingdown, false);
	atomic_init(&netmgr->recv_tcp_buffer_size, 0);
	atomic_init(&netmgr->send_tcp_buffer_size, 0);
	atomic_init(&netmgr->recv_udp_buffer_size, 0);
	atomic_init(&netmgr->send_udp_buffer_size, 0);
#if HAVE_SO_REUSEPORT_LB
	netmgr->load_balance_sockets = true;
#else
	netmgr->load_balance_sockets = false;
#endif

#ifdef NETMGR_TRACE
	ISC_LIST_INIT(netmgr->active_sockets);
#endif

	/*
	 * Default TCP timeout values.
	 * May be updated by isc_nm_tcptimeouts().
	 */
	atomic_init(&netmgr->init, 30000);
	atomic_init(&netmgr->idle, 30000);
	atomic_init(&netmgr->keepalive, 30000);
	atomic_init(&netmgr->advertised, 30000);

	netmgr->workers =
		isc_mem_get(mctx, netmgr->nloops * sizeof(netmgr->workers[0]));

	isc_loopmgr_teardown(loopmgr, netmgr_teardown, netmgr);

	netmgr->magic = NM_MAGIC;

	for (size_t i = 0; i < netmgr->nloops; i++) {
		isc_loop_t *loop = isc_loop_get(netmgr->loopmgr, i);
		isc__networker_t *worker = &netmgr->workers[i];

		*worker = (isc__networker_t){
			.recvbuf = isc_mem_get(loop->mctx,
					       ISC_NETMGR_RECVBUF_SIZE),
			.sendbuf = isc_mem_get(loop->mctx,
					       ISC_NETMGR_SENDBUF_SIZE),
		};

		isc_nm_attach(netmgr, &worker->netmgr);

		isc_mem_attach(loop->mctx, &worker->mctx);

		isc_loop_attach(loop, &worker->loop);
		isc_loop_teardown(loop, networker_teardown, worker);
		isc_refcount_init(&worker->references, 1);
	}

	*netmgrp = netmgr;
}

/*
 * Free the resources of the network manager.
 */
static void
nm_destroy(isc_nm_t **mgr0) {
	REQUIRE(VALID_NM(*mgr0));

	isc_nm_t *mgr = *mgr0;
	*mgr0 = NULL;

	isc_refcount_destroy(&mgr->references);

	mgr->magic = 0;

	if (mgr->stats != NULL) {
		isc_stats_detach(&mgr->stats);
	}

	isc_mutex_destroy(&mgr->lock);

	isc_mem_put(mgr->mctx, mgr->workers,
		    mgr->nloops * sizeof(mgr->workers[0]));
	isc_mem_putanddetach(&mgr->mctx, mgr, sizeof(*mgr));
}

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst) {
	REQUIRE(VALID_NM(mgr));
	REQUIRE(dst != NULL && *dst == NULL);

	isc_refcount_increment(&mgr->references);

	*dst = mgr;
}

void
isc_nm_detach(isc_nm_t **mgr0) {
	isc_nm_t *mgr = NULL;

	REQUIRE(mgr0 != NULL);
	REQUIRE(VALID_NM(*mgr0));

	mgr = *mgr0;
	*mgr0 = NULL;

	if (isc_refcount_decrement(&mgr->references) == 1) {
		nm_destroy(&mgr);
	}
}

void
isc_netmgr_destroy(isc_nm_t **netmgrp) {
	isc_nm_t *mgr = NULL;

	REQUIRE(VALID_NM(*netmgrp));

	mgr = *netmgrp;
	*netmgrp = NULL;

	REQUIRE(isc_refcount_decrement(&mgr->references) == 1);
	nm_destroy(&mgr);
}

void
isc_nm_maxudp(isc_nm_t *mgr, uint32_t maxudp) {
	REQUIRE(VALID_NM(mgr));

	atomic_store(&mgr->maxudp, maxudp);
}

void
isc_nmhandle_setwritetimeout(isc_nmhandle_t *handle, uint64_t write_timeout) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->tid == isc_tid());

	switch (handle->sock->type) {
	case isc_nm_tcpsocket:
	case isc_nm_udpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		handle->sock->write_timeout = write_timeout;
		break;
#ifdef HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nmhandle_tls_setwritetimeout(handle, write_timeout);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNREACHABLE();
		break;
	}
}

void
isc_nm_settimeouts(isc_nm_t *mgr, uint32_t init, uint32_t idle,
		   uint32_t keepalive, uint32_t advertised) {
	REQUIRE(VALID_NM(mgr));

	atomic_store(&mgr->init, init);
	atomic_store(&mgr->idle, idle);
	atomic_store(&mgr->keepalive, keepalive);
	atomic_store(&mgr->advertised, advertised);
}

void
isc_nm_setnetbuffers(isc_nm_t *mgr, int32_t recv_tcp, int32_t send_tcp,
		     int32_t recv_udp, int32_t send_udp) {
	REQUIRE(VALID_NM(mgr));

	atomic_store(&mgr->recv_tcp_buffer_size, recv_tcp);
	atomic_store(&mgr->send_tcp_buffer_size, send_tcp);
	atomic_store(&mgr->recv_udp_buffer_size, recv_udp);
	atomic_store(&mgr->send_udp_buffer_size, send_udp);
}

bool
isc_nm_getloadbalancesockets(isc_nm_t *mgr) {
	REQUIRE(VALID_NM(mgr));

	return (mgr->load_balance_sockets);
}

void
isc_nm_setloadbalancesockets(isc_nm_t *mgr, bool enabled) {
	REQUIRE(VALID_NM(mgr));

#if HAVE_SO_REUSEPORT_LB
	mgr->load_balance_sockets = enabled;
#else
	UNUSED(enabled);
#endif
}

void
isc_nm_gettimeouts(isc_nm_t *mgr, uint32_t *initial, uint32_t *idle,
		   uint32_t *keepalive, uint32_t *advertised) {
	REQUIRE(VALID_NM(mgr));

	if (initial != NULL) {
		*initial = atomic_load(&mgr->init);
	}

	if (idle != NULL) {
		*idle = atomic_load(&mgr->idle);
	}

	if (keepalive != NULL) {
		*keepalive = atomic_load(&mgr->keepalive);
	}

	if (advertised != NULL) {
		*advertised = atomic_load(&mgr->advertised);
	}
}

/*
 * The two macros here generate the individual cases for the process_netievent()
 * function.  The NETIEVENT_CASE(type) macro is the common case, and
 * NETIEVENT_CASE_NOMORE(type) is a macro that causes the loop in the
 * process_queue() to stop, e.g. it's only used for the netievent that
 * stops/pauses processing the enqueued netievents.
 */
#define NETIEVENT_CASE(type)                                          \
	case netievent_##type: {                                      \
		isc__nm_async_##type(worker, ievent);                 \
		isc__nm_put_netievent_##type(                         \
			worker, (isc__netievent_##type##_t *)ievent); \
		return;                                               \
	}

static void
process_netievent(void *arg) {
	isc__netievent_t *ievent = (isc__netievent_t *)arg;
	isc__networker_t *worker = ievent->worker;

	switch (ievent->type) {
		NETIEVENT_CASE(udplisten);
		NETIEVENT_CASE(udpstop);
		NETIEVENT_CASE(udpcancel);

		NETIEVENT_CASE(tcpaccept);
		NETIEVENT_CASE(tcplisten);
		NETIEVENT_CASE(tcpstop);

		NETIEVENT_CASE(tcpdnsaccept);
		NETIEVENT_CASE(tcpdnslisten);
		NETIEVENT_CASE(tcpdnsconnect);
		NETIEVENT_CASE(tcpdnssend);
		NETIEVENT_CASE(tcpdnscancel);
		NETIEVENT_CASE(tcpdnsclose);
		NETIEVENT_CASE(tcpdnsread);
		NETIEVENT_CASE(tcpdnsstop);

		NETIEVENT_CASE(tlsdnscycle);
		NETIEVENT_CASE(tlsdnsaccept);
		NETIEVENT_CASE(tlsdnslisten);
		NETIEVENT_CASE(tlsdnsconnect);
		NETIEVENT_CASE(tlsdnssend);
		NETIEVENT_CASE(tlsdnscancel);
		NETIEVENT_CASE(tlsdnsclose);
		NETIEVENT_CASE(tlsdnsread);
		NETIEVENT_CASE(tlsdnsstop);
		NETIEVENT_CASE(tlsdnsshutdown);

#if HAVE_LIBNGHTTP2
		NETIEVENT_CASE(tlssend);
		NETIEVENT_CASE(tlsclose);
		NETIEVENT_CASE(tlsdobio);

		NETIEVENT_CASE(httpsend);
		NETIEVENT_CASE(httpclose);
		NETIEVENT_CASE(httpendpoints);
#endif
		NETIEVENT_CASE(settlsctx);
		NETIEVENT_CASE(sockstop);

		NETIEVENT_CASE(connectcb);
		NETIEVENT_CASE(readcb);
		NETIEVENT_CASE(sendcb);

		NETIEVENT_CASE(detach);
	default:
		UNREACHABLE();
	}
}

void *
isc__nm_get_netievent(isc__networker_t *worker, isc__netievent_type type) {
	isc__netievent_storage_t *event = isc_mem_get(worker->mctx,
						      sizeof(*event));

	*event = (isc__netievent_storage_t){ .ni.type = type };
	ISC_LINK_INIT(&(event->ni), link);

	isc__networker_ref(worker);

	return (event);
}

void
isc__nm_put_netievent(isc__networker_t *worker, void *ievent) {
	isc_mem_put(worker->mctx, ievent, sizeof(isc__netievent_storage_t));
	isc__networker_unref(worker);
}

NETIEVENT_SOCKET_DEF(tcplisten);
NETIEVENT_SOCKET_DEF(tcpstop);
NETIEVENT_SOCKET_DEF(tlsclose);
NETIEVENT_SOCKET_DEF(tlsconnect);
NETIEVENT_SOCKET_DEF(tlsdobio);
NETIEVENT_SOCKET_DEF(udplisten);
NETIEVENT_SOCKET_DEF(udpstop);
NETIEVENT_SOCKET_HANDLE_DEF(udpcancel);

NETIEVENT_SOCKET_DEF(tcpdnsclose);
NETIEVENT_SOCKET_DEF(tcpdnsread);
NETIEVENT_SOCKET_DEF(tcpdnsstop);
NETIEVENT_SOCKET_DEF(tcpdnslisten);
NETIEVENT_SOCKET_REQ_DEF(tcpdnsconnect);
NETIEVENT_SOCKET_REQ_DEF(tcpdnssend);
NETIEVENT_SOCKET_HANDLE_DEF(tcpdnscancel);
NETIEVENT_SOCKET_QUOTA_DEF(tcpdnsaccept);

NETIEVENT_SOCKET_DEF(tlsdnsclose);
NETIEVENT_SOCKET_DEF(tlsdnsread);
NETIEVENT_SOCKET_DEF(tlsdnsstop);
NETIEVENT_SOCKET_DEF(tlsdnslisten);
NETIEVENT_SOCKET_REQ_DEF(tlsdnsconnect);
NETIEVENT_SOCKET_REQ_DEF(tlsdnssend);
NETIEVENT_SOCKET_HANDLE_DEF(tlsdnscancel);
NETIEVENT_SOCKET_QUOTA_DEF(tlsdnsaccept);
NETIEVENT_SOCKET_DEF(tlsdnscycle);
NETIEVENT_SOCKET_DEF(tlsdnsshutdown);

#ifdef HAVE_LIBNGHTTP2
NETIEVENT_SOCKET_REQ_DEF(httpsend);
NETIEVENT_SOCKET_DEF(httpclose);
NETIEVENT_SOCKET_HTTP_EPS_DEF(httpendpoints);
#endif /* HAVE_LIBNGHTTP2 */

NETIEVENT_SOCKET_REQ_DEF(tlssend);
NETIEVENT_SOCKET_REQ_RESULT_DEF(connectcb);
NETIEVENT_SOCKET_REQ_RESULT_DEF(readcb);
NETIEVENT_SOCKET_REQ_RESULT_DEF(sendcb);

NETIEVENT_SOCKET_DEF(detach);

NETIEVENT_SOCKET_QUOTA_DEF(tcpaccept);

NETIEVENT_SOCKET_TLSCTX_DEF(settlsctx);
NETIEVENT_SOCKET_DEF(sockstop);

void
isc__nm_process_ievent(isc__networker_t *worker, isc__netievent_t *event) {
	event->worker = worker;
	process_netievent(event);
}

void
isc__nm_maybe_enqueue_ievent(isc__networker_t *worker,
			     isc__netievent_t *event) {
	/*
	 * If we are already in the matching nmthread, process the ievent
	 * directly.
	 */
	if (worker->loop == isc_loop_current(worker->netmgr->loopmgr)) {
		isc__nm_process_ievent(worker, event);
		return;
	}

	isc__nm_enqueue_ievent(worker, event);
}

void
isc__nm_enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event) {
	event->worker = worker;

	isc_async_run(worker->loop, process_netievent, event);
}

bool
isc__nmsocket_active(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	if (sock->parent != NULL) {
		return (atomic_load(&sock->parent->active));
	}

	return (atomic_load(&sock->active));
}

bool
isc__nmsocket_deactivate(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (sock->parent != NULL) {
		return (atomic_compare_exchange_strong(&sock->parent->active,
						       &(bool){ true }, false));
	}

	return (atomic_compare_exchange_strong(&sock->active, &(bool){ true },
					       false));
}

void
isc___nmsocket_attach(isc_nmsocket_t *sock, isc_nmsocket_t **target FLARG) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(target != NULL && *target == NULL);

	isc_nmsocket_t *rsock = NULL;

	if (sock->parent != NULL) {
		rsock = sock->parent;
		INSIST(rsock->parent == NULL); /* sanity check */
	} else {
		rsock = sock;
	}

	NETMGR_TRACE_LOG("isc__nmsocket_attach():%p->references = %" PRIuFAST32
			 "\n",
			 rsock, isc_refcount_current(&rsock->references) + 1);

	isc_refcount_increment0(&rsock->references);

	*target = sock;
}

/*
 * Free all resources inside a socket (including its children if any).
 */
static void
nmsocket_cleanup(isc_nmsocket_t *sock, bool dofree FLARG) {
	isc_nmhandle_t *handle = NULL;
	isc__nm_uvreq_t *uvreq = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(!isc__nmsocket_active(sock));

	NETMGR_TRACE_LOG("nmsocket_cleanup():%p->references = %" PRIuFAST32
			 "\n",
			 sock, isc_refcount_current(&sock->references));

	isc_refcount_destroy(&sock->references);

	isc__nm_decstats(sock, STATID_ACTIVE);

	atomic_store(&sock->destroying, true);

	if (sock->parent == NULL && sock->children != NULL) {
		/*
		 * We shouldn't be here unless there are no active handles,
		 * so we can clean up and free the children.
		 */
		for (size_t i = 0; i < sock->nchildren; i++) {
			REQUIRE(!atomic_load(&sock->children[i].destroying));
			if (isc_refcount_decrement(
				    &sock->children[i].references))
			{
				nmsocket_cleanup(&sock->children[i],
						 false FLARG_PASS);
			}
		}

		/*
		 * Now free them.
		 */
		isc_mem_put(sock->worker->mctx, sock->children,
			    sock->nchildren * sizeof(*sock));
		sock->children = NULL;
		sock->nchildren = 0;
	}

	sock->statichandle = NULL;

	if (sock->outerhandle != NULL) {
		isc__nmhandle_detach(&sock->outerhandle FLARG_PASS);
	}

	if (sock->outer != NULL) {
		isc___nmsocket_detach(&sock->outer FLARG_PASS);
	}

	while ((handle = isc_astack_pop(sock->inactivehandles)) != NULL) {
		nmhandle_free(sock, handle);
	}

	if (sock->buf != NULL) {
		isc_mem_put(sock->worker->mctx, sock->buf, sock->buf_size);
	}

	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	sock->pquota = NULL;

	isc_astack_destroy(sock->inactivehandles);

	while ((uvreq = isc_astack_pop(sock->inactivereqs)) != NULL) {
		isc_mem_put(sock->worker->mctx, uvreq, sizeof(*uvreq));
	}

	isc_astack_destroy(sock->inactivereqs);

	isc__nm_tlsdns_cleanup_data(sock);
#if HAVE_LIBNGHTTP2
	isc__nm_tls_cleanup_data(sock);
	isc__nm_http_cleanup_data(sock);
#endif

	if (sock->barrier_initialised) {
		isc_barrier_destroy(&sock->barrier);
	}

	sock->magic = 0;

#ifdef NETMGR_TRACE
	LOCK(&sock->worker->netmgr->lock);
	ISC_LIST_UNLINK(sock->worker->netmgr->active_sockets, sock,
			active_link);
	UNLOCK(&sock->worker->netmgr->lock);
	isc_mutex_destroy(&sock->tracelock);
#endif

	isc_mutex_destroy(&sock->lock);

	if (dofree) {
		isc__networker_t *worker = sock->worker;
		isc_mem_put(worker->mctx, sock, sizeof(*sock));
		isc__networker_detach(&worker);
	} else {
		isc__networker_detach(&sock->worker);
	}
}

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock FLARG) {
	int active_handles;
	bool destroy = false;

	NETMGR_TRACE_LOG("%s():%p->references = %" PRIuFAST32 "\n", __func__,
			 sock, isc_refcount_current(&sock->references));

	if (sock->parent != NULL) {
		/*
		 * This is a child socket and cannot be destroyed except
		 * as a side effect of destroying the parent, so let's go
		 * see if the parent is ready to be destroyed.
		 */
		nmsocket_maybe_destroy(sock->parent FLARG_PASS);
		return;
	}

	/*
	 * This is a parent socket (or a standalone). See whether the
	 * children have active handles before deciding whether to
	 * accept destruction.
	 */
	if (atomic_load(&sock->active) || atomic_load(&sock->destroying) ||
	    !atomic_load(&sock->closed) || atomic_load(&sock->references) != 0)
	{
		return;
	}

	active_handles = atomic_load(&sock->ah);
	if (sock->children != NULL) {
		for (size_t i = 0; i < sock->nchildren; i++) {
			active_handles += atomic_load(&sock->children[i].ah);
		}
	}

	if (active_handles == 0 || sock->statichandle != NULL) {
		destroy = true;
	}

	NETMGR_TRACE_LOG("%s:%p->active_handles = %d, .statichandle = %p\n",
			 __func__, sock, active_handles, sock->statichandle);

	if (destroy) {
		atomic_store(&sock->destroying, true);
		nmsocket_cleanup(sock, true FLARG_PASS);
	}
}

void
isc_nmhandle_close(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc__nmsocket_clearcb(handle->sock);
	isc__nm_failed_read_cb(handle->sock, ISC_R_EOF, false);
}

void
isc___nmsocket_prep_destroy(isc_nmsocket_t *sock FLARG) {
	REQUIRE(sock->parent == NULL);

	NETMGR_TRACE_LOG("isc___nmsocket_prep_destroy():%p->references = "
			 "%" PRIuFAST32 "\n",
			 sock, isc_refcount_current(&sock->references));

	/*
	 * The final external reference to the socket is gone. We can try
	 * destroying the socket, but we have to wait for all the inflight
	 * handles to finish first.
	 */
	atomic_store(&sock->active, false);

	/*
	 * If the socket has children, they'll need to be marked inactive
	 * so they can be cleaned up too.
	 */
	if (sock->children != NULL) {
		for (size_t i = 0; i < sock->nchildren; i++) {
			atomic_store(&sock->children[i].active, false);
		}
	}

	/*
	 * If we're here then we already stopped listening; otherwise
	 * we'd have a hanging reference from the listening process.
	 *
	 * If it's a regular socket we may need to close it.
	 */
	if (!atomic_load(&sock->closing) && !atomic_load(&sock->closed)) {
		switch (sock->type) {
		case isc_nm_udpsocket:
			isc__nm_udp_close(sock);
			return;
		case isc_nm_tcpsocket:
			isc__nm_tcp_close(sock);
			return;
		case isc_nm_tcpdnssocket:
			isc__nm_tcpdns_close(sock);
			return;
		case isc_nm_tlsdnssocket:
			isc__nm_tlsdns_close(sock);
			return;
#if HAVE_LIBNGHTTP2
		case isc_nm_tlssocket:
			isc__nm_tls_close(sock);
			return;
		case isc_nm_httpsocket:
			isc__nm_http_close(sock);
			return;
#endif
		default:
			break;
		}
	}

	nmsocket_maybe_destroy(sock FLARG_PASS);
}

void
isc___nmsocket_detach(isc_nmsocket_t **sockp FLARG) {
	REQUIRE(sockp != NULL && *sockp != NULL);
	REQUIRE(VALID_NMSOCK(*sockp));

	isc_nmsocket_t *sock = *sockp, *rsock = NULL;
	*sockp = NULL;

	/*
	 * If the socket is a part of a set (a child socket) we are
	 * counting references for the whole set at the parent.
	 */
	if (sock->parent != NULL) {
		rsock = sock->parent;
		INSIST(rsock->parent == NULL); /* Sanity check */
	} else {
		rsock = sock;
	}

	NETMGR_TRACE_LOG("isc__nmsocket_detach():%p->references = %" PRIuFAST32
			 "\n",
			 rsock, isc_refcount_current(&rsock->references) - 1);

	if (isc_refcount_decrement(&rsock->references) == 1) {
		isc___nmsocket_prep_destroy(rsock FLARG_PASS);
	}
}

void
isc_nmsocket_close(isc_nmsocket_t **sockp) {
	REQUIRE(sockp != NULL);
	REQUIRE(VALID_NMSOCK(*sockp));
	REQUIRE((*sockp)->type == isc_nm_udplistener ||
		(*sockp)->type == isc_nm_tcplistener ||
		(*sockp)->type == isc_nm_tcpdnslistener ||
		(*sockp)->type == isc_nm_tlsdnslistener ||
		(*sockp)->type == isc_nm_tlslistener ||
		(*sockp)->type == isc_nm_httplistener);

	isc__nmsocket_detach(sockp);
}

void
isc___nmsocket_init(isc_nmsocket_t *sock, isc__networker_t *worker,
		    isc_nmsocket_type type, isc_sockaddr_t *iface FLARG) {
	uint16_t family;

	REQUIRE(sock != NULL);
	REQUIRE(worker != NULL);

	*sock = (isc_nmsocket_t){
		.type = type,
		.tid = worker->loop->tid,
		.fd = -1,
		.inactivehandles = isc_astack_new(worker->mctx,
						  ISC_NM_HANDLES_STACK_SIZE),
		.inactivereqs = isc_astack_new(worker->mctx,
					       ISC_NM_REQS_STACK_SIZE),
		.result = ISC_R_UNSET,
	};

	ISC_LIST_INIT(sock->tls.sendreqs);
	isc_mutex_init(&sock->lock);

	if (iface != NULL) {
		family = iface->type.sa.sa_family;
		sock->iface = *iface;
	} else {
		family = AF_UNSPEC;
	}

#if NETMGR_TRACE
	sock->backtrace_size = isc_backtrace(sock->backtrace, TRACE_SIZE);
	ISC_LINK_INIT(sock, active_link);
	ISC_LIST_INIT(sock->active_handles);
	LOCK(&worker->netmgr->lock);
	ISC_LIST_APPEND(worker->netmgr->active_sockets, sock, active_link);
	UNLOCK(&worker->netmgr->lock);
	isc_mutex_init(&sock->tracelock);
#endif

	isc__networker_attach(worker, &sock->worker);
	sock->uv_handle.handle.data = sock;

	ISC_LINK_INIT(&sock->quotacb, link);

	switch (type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		switch (family) {
		case AF_INET:
			sock->statsindex = udp4statsindex;
			break;
		case AF_INET6:
			sock->statsindex = udp6statsindex;
			break;
		case AF_UNSPEC:
			/*
			 * Route sockets are AF_UNSPEC, and don't
			 * have stats counters.
			 */
			break;
		default:
			UNREACHABLE();
		}
		break;
	case isc_nm_tcpsocket:
	case isc_nm_tcplistener:
	case isc_nm_tcpdnssocket:
	case isc_nm_tcpdnslistener:
	case isc_nm_tlsdnssocket:
	case isc_nm_tlsdnslistener:
	case isc_nm_httpsocket:
	case isc_nm_httplistener:
		switch (family) {
		case AF_INET:
			sock->statsindex = tcp4statsindex;
			break;
		case AF_INET6:
			sock->statsindex = tcp6statsindex;
			break;
		default:
			UNREACHABLE();
		}
		break;
	default:
		break;
	}

	isc_refcount_init(&sock->references, 1);

#if HAVE_LIBNGHTTP2
	memset(&sock->tlsstream, 0, sizeof(sock->tlsstream));
#endif /* HAVE_LIBNGHTTP2 */

	NETMGR_TRACE_LOG("isc__nmsocket_init():%p->references = %" PRIuFAST32
			 "\n",
			 sock, isc_refcount_current(&sock->references));

	atomic_init(&sock->active, true);
	atomic_init(&sock->closing, false);
	atomic_init(&sock->listening, 0);
	atomic_init(&sock->closed, 0);
	atomic_init(&sock->destroying, 0);
	atomic_init(&sock->ah, 0);
	atomic_init(&sock->client, 0);
	atomic_init(&sock->connecting, false);
	atomic_init(&sock->keepalive, false);
	atomic_init(&sock->connected, false);
	atomic_init(&sock->timedout, false);

	atomic_init(&sock->active_child_connections, 0);

#if HAVE_LIBNGHTTP2
	isc__nm_http_initsocket(sock);
#endif

	sock->magic = NMSOCK_MAGIC;

	isc__nm_incstats(sock, STATID_ACTIVE);
}

void
isc__nmsocket_clearcb(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	sock->recv_cb = NULL;
	sock->recv_cbarg = NULL;
	sock->accept_cb = NULL;
	sock->accept_cbarg = NULL;
	sock->connect_cb = NULL;
	sock->connect_cbarg = NULL;
}

void
isc__nm_free_uvbuf(isc_nmsocket_t *sock, const uv_buf_t *buf) {
	REQUIRE(VALID_NMSOCK(sock));

	REQUIRE(buf->base == sock->worker->recvbuf);

	sock->worker->recvbuf_inuse = false;
}

static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *sock) {
	isc_nmhandle_t *handle = isc_mem_get(sock->worker->mctx,
					     sizeof(isc_nmhandle_t));

	*handle = (isc_nmhandle_t){ .magic = NMHANDLE_MAGIC };
#ifdef NETMGR_TRACE
	ISC_LINK_INIT(handle, active_link);
#endif
	isc_refcount_init(&handle->references, 1);

	return (handle);
}

isc_nmhandle_t *
isc___nmhandle_get(isc_nmsocket_t *sock, isc_sockaddr_t *peer,
		   isc_sockaddr_t *local FLARG) {
	isc_nmhandle_t *handle = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	handle = isc_astack_pop(sock->inactivehandles);

	if (handle == NULL) {
		handle = alloc_handle(sock);
	} else {
		isc_refcount_init(&handle->references, 1);
		INSIST(VALID_NMHANDLE(handle));
	}

	NETMGR_TRACE_LOG(
		"isc__nmhandle_get():handle %p->references = %" PRIuFAST32 "\n",
		handle, isc_refcount_current(&handle->references));

	isc___nmsocket_attach(sock, &handle->sock FLARG_PASS);

#if NETMGR_TRACE
	handle->backtrace_size = isc_backtrace(handle->backtrace, TRACE_SIZE);
#endif

	if (peer != NULL) {
		handle->peer = *peer;
	} else {
		handle->peer = sock->peer;
	}

	if (local != NULL) {
		handle->local = *local;
	} else {
		handle->local = sock->iface;
	}

	(void)atomic_fetch_add(&sock->ah, 1);

#ifdef NETMGR_TRACE
	LOCK(&sock->tracelock);
	ISC_LIST_APPEND(sock->active_handles, handle, active_link);
	UNLOCK(&sock->tracelock);
#endif

	switch (sock->type) {
	case isc_nm_udpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		if (!atomic_load(&sock->client)) {
			break;
		}
		FALLTHROUGH;
	case isc_nm_tcpsocket:
	case isc_nm_tlssocket:
		INSIST(sock->statichandle == NULL);

		/*
		 * statichandle must be assigned, not attached;
		 * otherwise, if a handle was detached elsewhere
		 * it could never reach 0 references, and the
		 * handle and socket would never be freed.
		 */
		sock->statichandle = handle;
		break;
	default:
		break;
	}

#if HAVE_LIBNGHTTP2
	if (sock->type == isc_nm_httpsocket && sock->h2.session) {
		isc__nm_httpsession_attach(sock->h2.session,
					   &handle->httpsession);
	}
#endif

	return (handle);
}

void
isc__nmhandle_attach(isc_nmhandle_t *handle, isc_nmhandle_t **handlep FLARG) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(handlep != NULL && *handlep == NULL);

	NETMGR_TRACE_LOG("isc__nmhandle_attach():handle %p->references = "
			 "%" PRIuFAST32 "\n",
			 handle, isc_refcount_current(&handle->references) + 1);

	isc_refcount_increment(&handle->references);
	*handlep = handle;
}

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->sock->type == isc_nm_tcpsocket ||
		handle->sock->type == isc_nm_tcpdnssocket ||
		handle->sock->type == isc_nm_tlssocket ||
		handle->sock->type == isc_nm_tlsdnssocket ||
		handle->sock->type == isc_nm_httpsocket);
}

static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle) {
	isc_refcount_destroy(&handle->references);

	if (handle->dofree != NULL) {
		handle->dofree(handle->opaque);
	}

	*handle = (isc_nmhandle_t){ .magic = 0 };

	isc_mem_put(sock->worker->mctx, handle, sizeof(isc_nmhandle_t));
}

static void
nmhandle_deactivate(isc_nmsocket_t *sock, isc_nmhandle_t *handle) {
	bool reuse = false;
	uint_fast32_t ah;

	/*
	 * We do all of this under lock to avoid races with socket
	 * destruction.  We have to do this now, because at this point the
	 * socket is either unused or still attached to event->sock.
	 */
#ifdef NETMGR_TRACE
	ISC_LIST_UNLINK(sock->active_handles, handle, active_link);
#endif

	ah = atomic_fetch_sub(&sock->ah, 1);
	INSIST(ah > 0);

#if !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__
	if (atomic_load(&sock->active)) {
		reuse = isc_astack_trypush(sock->inactivehandles, handle);
	}
#endif /* !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__ */
	if (!reuse) {
		nmhandle_free(sock, handle);
	}
}

void
isc__nmhandle_detach(isc_nmhandle_t **handlep FLARG) {
	isc_nmsocket_t *sock = NULL;
	isc_nmhandle_t *handle = NULL;

	REQUIRE(handlep != NULL);
	REQUIRE(VALID_NMHANDLE(*handlep));

	handle = *handlep;
	*handlep = NULL;

	/*
	 * If the closehandle_cb is set, it needs to run asynchronously to
	 * ensure correct ordering of the isc__nm_process_sock_buffer().
	 */
	sock = handle->sock;
	if (sock->tid == isc_tid() && sock->closehandle_cb == NULL) {
		nmhandle_detach_cb(&handle FLARG_PASS);
	} else {
		isc__netievent_detach_t *event =
			isc__nm_get_netievent_detach(sock->worker, sock);
		/*
		 * we are using implicit "attach" as the last reference
		 * need to be destroyed explicitly in the async callback
		 */
		event->handle = handle;
		FLARG_IEVENT_PASS(event);
		isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)event);
	}
}

static void
nmhandle_detach_cb(isc_nmhandle_t **handlep FLARG) {
	isc_nmsocket_t *sock = NULL;
	isc_nmhandle_t *handle = NULL;

	REQUIRE(handlep != NULL);
	REQUIRE(VALID_NMHANDLE(*handlep));

	handle = *handlep;
	*handlep = NULL;

	NETMGR_TRACE_LOG("isc__nmhandle_detach():%p->references = %" PRIuFAST32
			 "\n",
			 handle, isc_refcount_current(&handle->references) - 1);

	if (isc_refcount_decrement(&handle->references) > 1) {
		return;
	}

	/* We need an acquire memory barrier here */
	(void)isc_refcount_current(&handle->references);

	sock = handle->sock;
	handle->sock = NULL;

	if (handle->doreset != NULL) {
		handle->doreset(handle->opaque);
	}

#if HAVE_LIBNGHTTP2
	if (sock->type == isc_nm_httpsocket && handle->httpsession != NULL) {
		isc__nm_httpsession_detach(&handle->httpsession);
	}
#endif

	nmhandle_deactivate(sock, handle);

	/*
	 * The handle is gone now. If the socket has a callback configured
	 * for that (e.g., to perform cleanup after request processing),
	 * call it now..
	 */
	if (sock->closehandle_cb != NULL) {
		sock->closehandle_cb(sock);
	}

	if (handle == sock->statichandle) {
		/* statichandle is assigned, not attached. */
		sock->statichandle = NULL;
	}

	isc___nmsocket_detach(&sock FLARG_PASS);
}

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->opaque);
}

void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg,
		     isc_nm_opaquecb_t doreset, isc_nm_opaquecb_t dofree) {
	REQUIRE(VALID_NMHANDLE(handle));

	handle->opaque = arg;
	handle->doreset = doreset;
	handle->dofree = dofree;
}

void
isc__nm_alloc_dnsbuf(isc_nmsocket_t *sock, size_t len) {
	REQUIRE(len <= NM_BIG_BUF);

	if (sock->buf == NULL) {
		/* We don't have the buffer at all */
		size_t alloc_len = len < NM_REG_BUF ? NM_REG_BUF : NM_BIG_BUF;
		sock->buf = isc_mem_get(sock->worker->mctx, alloc_len);
		sock->buf_size = alloc_len;
	} else {
		/* We have the buffer but it's too small */
		sock->buf = isc_mem_reget(sock->worker->mctx, sock->buf,
					  sock->buf_size, NM_BIG_BUF);
		sock->buf_size = NM_BIG_BUF;
	}
}

void
isc__nm_failed_send_cb(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
		       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));

	if (req->cb.send != NULL) {
		isc__nm_sendcb(sock, req, eresult, async);
	} else {
		isc__nm_uvreq_put(&req, sock);
	}
}

void
isc__nm_failed_accept_cb(isc_nmsocket_t *sock, isc_result_t eresult) {
	REQUIRE(atomic_load(&sock->accepting));
	REQUIRE(sock->server);

	/*
	 * Detach the quota early to make room for other connections;
	 * otherwise it'd be detached later asynchronously, and clog
	 * the quota unnecessarily.
	 */
	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	isc__nmsocket_detach(&sock->server);

	atomic_store(&sock->accepting, false);

	switch (eresult) {
	case ISC_R_NOTCONNECTED:
		/* IGNORE: The client disconnected before we could accept */
		break;
	default:
		isc__nmsocket_log(sock, ISC_LOG_ERROR,
				  "Accepting TCP connection failed: %s",
				  isc_result_totext(eresult));
	}
}

void
isc__nm_failed_connect_cb(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
			  isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(req->cb.connect != NULL);

	isc__nm_incstats(sock, STATID_CONNECTFAIL);

	isc__nmsocket_timer_stop(sock);
	uv_handle_set_data((uv_handle_t *)&sock->read_timer, sock);

	atomic_compare_exchange_enforced(&sock->connecting, &(bool){ true },
					 false);

	isc__nmsocket_clearcb(sock);
	isc__nm_connectcb(sock, req, eresult, async);

	isc__nmsocket_prep_destroy(sock);
}

void
isc__nm_failed_read_cb(isc_nmsocket_t *sock, isc_result_t result, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	switch (sock->type) {
	case isc_nm_udpsocket:
		isc__nm_udp_failed_read_cb(sock, result, async);
		return;
	case isc_nm_tcpsocket:
		isc__nm_tcp_failed_read_cb(sock, result, async);
		return;
	case isc_nm_tcpdnssocket:
		isc__nm_tcpdns_failed_read_cb(sock, result, async);
		return;
	case isc_nm_tlsdnssocket:
		isc__nm_tlsdns_failed_read_cb(sock, result, async);
		return;
#ifdef HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nm_tls_failed_read_cb(sock, result, async);
		return;
#endif
	default:
		UNREACHABLE();
	}
}

void
isc__nmsocket_connecttimeout_cb(uv_timer_t *timer) {
	uv_connect_t *uvreq = uv_handle_get_data((uv_handle_t *)timer);
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)uvreq->handle);
	isc__nm_uvreq_t *req = uv_handle_get_data((uv_handle_t *)uvreq);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(atomic_load(&sock->connecting));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(VALID_NMHANDLE(req->handle));

	isc__nmsocket_timer_stop(sock);

	if (sock->tls.pending_req != NULL) {
		REQUIRE(req == sock->tls.pending_req);
		sock->tls.pending_req = NULL;
	}

	/*
	 * Mark the connection as timed out and shutdown the socket.
	 */
	atomic_compare_exchange_enforced(&sock->timedout, &(bool){ false },
					 true);
	isc__nmsocket_clearcb(sock);
	isc__nmsocket_shutdown(sock);
}

void
isc__nm_accept_connection_log(isc_nmsocket_t *sock, isc_result_t result,
			      bool can_log_quota) {
	int level;

	switch (result) {
	case ISC_R_SUCCESS:
	case ISC_R_NOCONN:
		return;
	case ISC_R_QUOTA:
	case ISC_R_SOFTQUOTA:
		if (!can_log_quota) {
			return;
		}
		level = ISC_LOG_INFO;
		break;
	case ISC_R_NOTCONNECTED:
		level = ISC_LOG_INFO;
		break;
	default:
		level = ISC_LOG_ERROR;
	}

	isc__nmsocket_log(sock, level, "Accepting TCP connection failed: %s",
			  isc_result_totext(result));
}

void
isc__nmsocket_writetimeout_cb(void *data, isc_result_t eresult) {
	isc__nm_uvreq_t *req = data;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(eresult == ISC_R_TIMEDOUT);
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(VALID_NMSOCK(req->sock));

	sock = req->sock;

	isc__nmsocket_reset(sock);
}

void
isc__nmsocket_readtimeout_cb(uv_timer_t *timer) {
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)timer);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->reading);

	if (atomic_load(&sock->client)) {
		uv_timer_stop(timer);

		sock->recv_read = false;

		if (sock->recv_cb != NULL) {
			isc__nm_uvreq_t *req = isc__nm_get_read_req(sock, NULL);
			isc__nm_readcb(sock, req, ISC_R_TIMEDOUT, false);
		}

		if (!isc__nmsocket_timer_running(sock)) {
			isc__nmsocket_clearcb(sock);
			isc__nm_failed_read_cb(sock, ISC_R_CANCELED, false);
		}
	} else {
		isc__nm_failed_read_cb(sock, ISC_R_TIMEDOUT, false);
	}
}

void
isc__nmsocket_timer_restart(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (uv_is_closing((uv_handle_t *)&sock->read_timer)) {
		return;
	}

	if (atomic_load(&sock->connecting)) {
		int r;

		if (sock->connect_timeout == 0) {
			return;
		}

		r = uv_timer_start(&sock->read_timer,
				   isc__nmsocket_connecttimeout_cb,
				   sock->connect_timeout + 10, 0);
		UV_RUNTIME_CHECK(uv_timer_start, r);

	} else {
		int r;

		if (sock->read_timeout == 0) {
			return;
		}

		r = uv_timer_start(&sock->read_timer,
				   isc__nmsocket_readtimeout_cb,
				   sock->read_timeout, 0);
		UV_RUNTIME_CHECK(uv_timer_start, r);
	}
}

bool
isc__nmsocket_timer_running(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	return (uv_is_active((uv_handle_t *)&sock->read_timer));
}

void
isc__nmsocket_timer_start(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (isc__nmsocket_timer_running(sock)) {
		return;
	}

	isc__nmsocket_timer_restart(sock);
}

void
isc__nmsocket_timer_stop(isc_nmsocket_t *sock) {
	int r;

	REQUIRE(VALID_NMSOCK(sock));

	/* uv_timer_stop() is idempotent, no need to check if running */

	r = uv_timer_stop(&sock->read_timer);
	UV_RUNTIME_CHECK(uv_timer_stop, r);
}

isc__nm_uvreq_t *
isc__nm_get_read_req(isc_nmsocket_t *sock, isc_sockaddr_t *sockaddr) {
	isc__nm_uvreq_t *req = NULL;

	req = isc__nm_uvreq_get(sock->worker, sock);
	req->cb.recv = sock->recv_cb;
	req->cbarg = sock->recv_cbarg;

	switch (sock->type) {
	case isc_nm_tcpsocket:
	case isc_nm_tlssocket:
		isc_nmhandle_attach(sock->statichandle, &req->handle);
		break;
	default:
		if (atomic_load(&sock->client) && sock->statichandle != NULL) {
			isc_nmhandle_attach(sock->statichandle, &req->handle);
		} else {
			req->handle = isc__nmhandle_get(sock, sockaddr, NULL);
		}
		break;
	}

	return (req);
}

/*%<
 * Allocator callback for read operations.
 *
 * Note this doesn't actually allocate anything, it just assigns the
 * worker's receive buffer to a socket, and marks it as "in use".
 */
void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	/*
	 * The size provided by libuv is only suggested size, and it always
	 * defaults to 64 * 1024 in the current versions of libuv (see
	 * src/unix/udp.c and src/unix/stream.c).
	 */
	UNUSED(size);

	worker = sock->worker;
	INSIST(!worker->recvbuf_inuse);
	INSIST(worker->recvbuf != NULL);

	switch (sock->type) {
	case isc_nm_udpsocket:
		buf->len = ISC_NETMGR_UDP_RECVBUF_SIZE;
		break;
	case isc_nm_tcpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		buf->len = ISC_NETMGR_TCP_RECVBUF_SIZE;
		break;
	default:
		UNREACHABLE();
	}

	REQUIRE(buf->len <= ISC_NETMGR_RECVBUF_SIZE);
	buf->base = worker->recvbuf;

	worker->recvbuf_inuse = true;
}

isc_result_t
isc__nm_start_reading(isc_nmsocket_t *sock) {
	isc_result_t result = ISC_R_SUCCESS;
	int r;

	if (sock->reading) {
		return (ISC_R_SUCCESS);
	}

	switch (sock->type) {
	case isc_nm_udpsocket:
		r = uv_udp_recv_start(&sock->uv_handle.udp, isc__nm_alloc_cb,
				      isc__nm_udp_read_cb);
		break;
	case isc_nm_tcpsocket:
		r = uv_read_start(&sock->uv_handle.stream, isc__nm_alloc_cb,
				  isc__nm_tcp_read_cb);
		break;
	case isc_nm_tcpdnssocket:
		r = uv_read_start(&sock->uv_handle.stream, isc__nm_alloc_cb,
				  isc__nm_tcpdns_read_cb);
		break;
	case isc_nm_tlsdnssocket:
		r = uv_read_start(&sock->uv_handle.stream, isc__nm_alloc_cb,
				  isc__nm_tlsdns_read_cb);
		break;
	default:
		UNREACHABLE();
	}
	if (r != 0) {
		result = isc_uverr2result(r);
	} else {
		sock->reading = true;
	}

	return (result);
}

void
isc__nm_stop_reading(isc_nmsocket_t *sock) {
	int r;

	if (!sock->reading) {
		return;
	}

	switch (sock->type) {
	case isc_nm_udpsocket:
		r = uv_udp_recv_stop(&sock->uv_handle.udp);
		UV_RUNTIME_CHECK(uv_udp_recv_stop, r);
		break;
	case isc_nm_tcpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		r = uv_read_stop(&sock->uv_handle.stream);
		UV_RUNTIME_CHECK(uv_read_stop, r);
		break;
	default:
		UNREACHABLE();
	}
	sock->reading = false;
}

bool
isc__nm_closing(isc__networker_t *worker) {
	return (worker->shuttingdown);
}

bool
isc__nmsocket_closing(isc_nmsocket_t *sock) {
	return (!isc__nmsocket_active(sock) || atomic_load(&sock->closing) ||
		isc__nm_closing(sock->worker) ||
		(sock->server != NULL && !isc__nmsocket_active(sock->server)));
}

static isc_result_t
processbuffer(isc_nmsocket_t *sock) {
	switch (sock->type) {
	case isc_nm_tcpdnssocket:
		return (isc__nm_tcpdns_processbuffer(sock));
	case isc_nm_tlsdnssocket:
		return (isc__nm_tlsdns_processbuffer(sock));
	default:
		UNREACHABLE();
	}
}

/*
 * Process a DNS message.
 *
 * If we only have an incomplete DNS message, we don't touch any
 * timers. If we do have a full message, reset the timer.
 *
 * Stop reading if this is a client socket.  In this case we'll be
 * called again later by isc__nm_resume_processing().
 */
isc_result_t
isc__nm_process_sock_buffer(isc_nmsocket_t *sock) {
	for (;;) {
		int_fast32_t ah = atomic_load(&sock->ah);
		isc_result_t result = processbuffer(sock);
		switch (result) {
		case ISC_R_NOMORE:
			/*
			 * Don't reset the timer until we have a
			 * full DNS message.
			 */
			result = isc__nm_start_reading(sock);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
			/*
			 * Start the timer only if there are no externally used
			 * active handles, there's always one active handle
			 * attached internally to sock->recv_handle in
			 * accept_connection()
			 */
			if (ah == 1) {
				isc__nmsocket_timer_start(sock);
			}
			goto done;
		case ISC_R_CANCELED:
			isc__nmsocket_timer_stop(sock);
			isc__nm_stop_reading(sock);
			goto done;
		case ISC_R_SUCCESS:
			/*
			 * Stop the timer on the successful message read, this
			 * also allows to restart the timer when we have no more
			 * data.
			 */
			isc__nmsocket_timer_stop(sock);

			if (atomic_load(&sock->client)) {
				isc__nm_stop_reading(sock);
				goto done;
			}
			break;
		default:
			UNREACHABLE();
		}
	}
done:
	return (ISC_R_SUCCESS);
}

void
isc__nm_resume_processing(void *arg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)arg;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(!atomic_load(&sock->client));

	if (isc__nmsocket_closing(sock)) {
		return;
	}

	isc__nm_process_sock_buffer(sock);
}

void
isc_nmhandle_cleartimeout(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	switch (handle->sock->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_cleartimeout(handle);
		return;
	case isc_nm_tlssocket:
		isc__nm_tls_cleartimeout(handle);
		return;
#endif
	default:
		handle->sock->read_timeout = 0;

		if (uv_is_active((uv_handle_t *)&handle->sock->read_timer)) {
			isc__nmsocket_timer_stop(handle->sock);
		}
	}
}

void
isc_nmhandle_settimeout(isc_nmhandle_t *handle, uint32_t timeout) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	switch (handle->sock->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_settimeout(handle, timeout);
		return;
	case isc_nm_tlssocket:
		isc__nm_tls_settimeout(handle, timeout);
		return;
#endif
	default:
		handle->sock->read_timeout = timeout;
		isc__nmsocket_timer_restart(handle->sock);
	}
}

void
isc_nmhandle_keepalive(isc_nmhandle_t *handle, bool value) {
	isc_nmsocket_t *sock = NULL;
	isc_nm_t *netmgr = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	netmgr = sock->worker->netmgr;

	switch (sock->type) {
	case isc_nm_tcpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		atomic_store(&sock->keepalive, value);
		sock->read_timeout = value ? atomic_load(&netmgr->keepalive)
					   : atomic_load(&netmgr->idle);
		sock->write_timeout = value ? atomic_load(&netmgr->keepalive)
					    : atomic_load(&netmgr->idle);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nmhandle_tls_keepalive(handle, value);
		break;
	case isc_nm_httpsocket:
		isc__nmhandle_http_keepalive(handle, value);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		/*
		 * For any other protocol, this is a no-op.
		 */
		return;
	}
}

bool
isc_nmhandle_timer_running(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return (isc__nmsocket_timer_running(handle->sock));
}

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->peer);
}

isc_sockaddr_t
isc_nmhandle_localaddr(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->local);
}

isc_nm_t *
isc_nmhandle_netmgr(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return (handle->sock->worker->netmgr);
}

/* FIXME: Use per-worker mempool */
isc__nm_uvreq_t *
isc___nm_uvreq_get(isc__networker_t *worker, isc_nmsocket_t *sock FLARG) {
	isc__nm_uvreq_t *req = NULL;

	REQUIRE(worker != NULL);
	REQUIRE(VALID_NMSOCK(sock));

	if (sock != NULL && isc__nmsocket_active(sock)) {
		/* Try to reuse one */
		req = isc_astack_pop(sock->inactivereqs);
	}

	if (req == NULL) {
		req = isc_mem_get(worker->mctx, sizeof(*req));
	}

	*req = (isc__nm_uvreq_t){
		.magic = 0,
		.connect_tries = 3,
	};
	ISC_LINK_INIT(req, link);
	req->uv_req.req.data = req;
	isc___nmsocket_attach(sock, &req->sock FLARG_PASS);
	req->magic = UVREQ_MAGIC;

	return (req);
}

void
isc___nm_uvreq_put(isc__nm_uvreq_t **req0, isc_nmsocket_t *sock FLARG) {
	isc__nm_uvreq_t *req = NULL;
	isc_nmhandle_t *handle = NULL;

	REQUIRE(req0 != NULL);
	REQUIRE(VALID_UVREQ(*req0));

	req = *req0;
	*req0 = NULL;

	INSIST(sock == req->sock);

	req->magic = 0;

	/*
	 * We need to save this first to make sure that handle,
	 * sock, and the netmgr won't all disappear.
	 */
	handle = req->handle;
	req->handle = NULL;

#if !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__
	if (!isc__nmsocket_active(sock) ||
	    !isc_astack_trypush(sock->inactivereqs, req))
	{
		isc_mem_put(sock->worker->mctx, req, sizeof(*req));
	}
#else  /* !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__ */
	isc_mem_put(sock->worker->mctx, req, sizeof(*req));
#endif /* !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__ */

	if (handle != NULL) {
		isc__nmhandle_detach(&handle FLARG_PASS);
	}

	isc___nmsocket_detach(&sock FLARG_PASS);
}

void
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
	    void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));

	switch (handle->sock->type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		isc__nm_udp_send(handle, region, cb, cbarg);
		break;
	case isc_nm_tcpsocket:
		isc__nm_tcp_send(handle, region, cb, cbarg);
		break;
	case isc_nm_tcpdnssocket:
		isc__nm_tcpdns_send(handle, region, cb, cbarg);
		break;
	case isc_nm_tlsdnssocket:
		isc__nm_tlsdns_send(handle, region, cb, cbarg);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nm_tls_send(handle, region, cb, cbarg);
		break;
	case isc_nm_httpsocket:
		isc__nm_http_send(handle, region, cb, cbarg);
		break;
#endif
	default:
		UNREACHABLE();
	}
}

void
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));

	switch (handle->sock->type) {
	case isc_nm_udpsocket:
		isc__nm_udp_read(handle, cb, cbarg);
		break;
	case isc_nm_tcpsocket:
		isc__nm_tcp_read(handle, cb, cbarg);
		break;
	case isc_nm_tcpdnssocket:
		isc__nm_tcpdns_read(handle, cb, cbarg);
		break;
	case isc_nm_tlsdnssocket:
		isc__nm_tlsdns_read(handle, cb, cbarg);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nm_tls_read(handle, cb, cbarg);
		break;
	case isc_nm_httpsocket:
		isc__nm_http_read(handle, cb, cbarg);
		break;
#endif
	default:
		UNREACHABLE();
	}
}

void
isc_nm_cancelread(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	switch (handle->sock->type) {
	case isc_nm_udpsocket:
		isc__nm_udp_cancelread(handle);
		break;
	case isc_nm_tcpdnssocket:
		isc__nm_tcpdns_cancelread(handle);
		break;
	case isc_nm_tlsdnssocket:
		isc__nm_tlsdns_cancelread(handle);
		break;
	default:
		UNREACHABLE();
	}
}

void
isc_nm_read_stop(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	isc_nmsocket_t *sock = handle->sock;

	switch (sock->type) {
	case isc_nm_tcpsocket:
		isc__nm_tcp_read_stop(handle);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		isc__nm_tls_read_stop(handle);
		break;
#endif
	default:
		UNREACHABLE();
	}
}

void
isc_nm_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	switch (sock->type) {
	case isc_nm_udplistener:
		isc__nm_udp_stoplistening(sock);
		break;
	case isc_nm_tcpdnslistener:
		isc__nm_tcpdns_stoplistening(sock);
		break;
	case isc_nm_tcplistener:
		isc__nm_tcp_stoplistening(sock);
		break;
	case isc_nm_tlsdnslistener:
		isc__nm_tlsdns_stoplistening(sock);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlslistener:
		isc__nm_tls_stoplistening(sock);
		break;
	case isc_nm_httplistener:
		isc__nm_http_stoplistening(sock);
		break;
#endif
	default:
		UNREACHABLE();
	}
}

void
isc__nmsocket_stop(isc_nmsocket_t *listener) {
	isc__netievent_sockstop_t ievent = { .sock = listener };

	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(listener->tid == isc_tid());
	REQUIRE(listener->tid == 0);

	if (!atomic_compare_exchange_strong(&listener->closing,
					    &(bool){ false }, true))
	{
		UNREACHABLE();
	}

	for (size_t i = 1; i < listener->nchildren; i++) {
		isc__networker_t *worker =
			&listener->worker->netmgr->workers[i];
		isc__netievent_sockstop_t *ev =
			isc__nm_get_netievent_sockstop(worker, listener);
		isc__nm_enqueue_ievent(worker, (isc__netievent_t *)ev);
	}

	isc__nm_async_sockstop(listener->worker, (isc__netievent_t *)&ievent);
	INSIST(atomic_load(&listener->rchildren) == 0);

	if (!atomic_compare_exchange_strong(&listener->listening,
					    &(bool){ true }, false))
	{
		UNREACHABLE();
	}

	listener->accept_cb = NULL;
	listener->accept_cbarg = NULL;
	listener->recv_cb = NULL;
	listener->recv_cbarg = NULL;

	if (listener->outer != NULL) {
		isc_nm_stoplistening(listener->outer);
		isc__nmsocket_detach(&listener->outer);
	}

	atomic_store(&listener->closed, true);
}

void
isc__nmsocket_barrier_init(isc_nmsocket_t *listener) {
	REQUIRE(listener->nchildren > 0);
	isc_barrier_init(&listener->barrier, listener->nchildren);
	listener->barrier_initialised = true;
}

void
isc__nm_async_sockstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_sockstop_t *ievent = (isc__netievent_sockstop_t *)ev0;
	isc_nmsocket_t *listener = ievent->sock;
	UNUSED(worker);

	(void)atomic_fetch_sub(&listener->rchildren, 1);
	isc_barrier_wait(&listener->barrier);
}

void
isc__nm_connectcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
		  isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	if (!async) {
		isc__netievent_connectcb_t ievent = { .sock = sock,
						      .req = uvreq,
						      .result = eresult };
		isc__nm_async_connectcb(NULL, (isc__netievent_t *)&ievent);
	} else {
		isc__netievent_connectcb_t *ievent =
			isc__nm_get_netievent_connectcb(sock->worker, sock,
							uvreq, eresult);
		isc__nm_enqueue_ievent(sock->worker,
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_connectcb(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_connectcb_t *ievent = (isc__netievent_connectcb_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *uvreq = ievent->req;
	isc_result_t eresult = ievent->result;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));
	REQUIRE(ievent->sock->tid == isc_tid());
	REQUIRE(uvreq->cb.connect != NULL);

	uvreq->cb.connect(uvreq->handle, eresult, uvreq->cbarg);

	isc__nm_uvreq_put(&uvreq, sock);
}

void
isc__nm_readcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
	       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	if (!async) {
		isc__netievent_readcb_t ievent = { .type = netievent_readcb,
						   .sock = sock,
						   .req = uvreq,
						   .result = eresult };

		isc__nm_async_readcb(NULL, (isc__netievent_t *)&ievent);
		return;
	}

	isc__netievent_readcb_t *ievent = isc__nm_get_netievent_readcb(
		sock->worker, sock, uvreq, eresult);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

void
isc__nm_async_readcb(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_readcb_t *ievent = (isc__netievent_readcb_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *uvreq = ievent->req;
	isc_result_t eresult = ievent->result;
	isc_region_t region;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));
	REQUIRE(sock->tid == isc_tid());

	region.base = (unsigned char *)uvreq->uvbuf.base;
	region.length = uvreq->uvbuf.len;

	uvreq->cb.recv(uvreq->handle, eresult, &region, uvreq->cbarg);

	isc__nm_uvreq_put(&uvreq, sock);
}

void
isc__nm_sendcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
	       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	if (!async) {
		isc__netievent_sendcb_t ievent = { .sock = sock,
						   .req = uvreq,
						   .result = eresult };
		isc__nm_async_sendcb(NULL, (isc__netievent_t *)&ievent);
		return;
	}

	isc__netievent_sendcb_t *ievent = isc__nm_get_netievent_sendcb(
		sock->worker, sock, uvreq, eresult);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

void
isc__nm_async_sendcb(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_sendcb_t *ievent = (isc__netievent_sendcb_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *uvreq = ievent->req;
	isc_result_t eresult = ievent->result;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));
	REQUIRE(sock->tid == isc_tid());

	uvreq->cb.send(uvreq->handle, eresult, uvreq->cbarg);

	isc__nm_uvreq_put(&uvreq, sock);
}

void
isc__nm_async_detach(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_detach_t *ievent = (isc__netievent_detach_t *)ev0;
	FLARG_IEVENT(ievent);

	REQUIRE(VALID_NMSOCK(ievent->sock));
	REQUIRE(VALID_NMHANDLE(ievent->handle));
	REQUIRE(ievent->sock->tid == isc_tid());

	UNUSED(worker);

	nmhandle_detach_cb(&ievent->handle FLARG_PASS);
}

static void
reset_shutdown(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);

	isc__nmsocket_shutdown(sock);
	isc__nmsocket_detach(&sock);
}

void
isc__nmsocket_reset(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	switch (sock->type) {
	case isc_nm_tcpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		/*
		 * This can be called from the TCP write timeout, or
		 * from the TCPDNS or TLSDNS branches of isc_nm_bad_request().
		 */
		REQUIRE(sock->parent == NULL);
		break;
	default:
		UNREACHABLE();
		break;
	}

	if (!uv_is_closing(&sock->uv_handle.handle) &&
	    uv_is_active(&sock->uv_handle.handle))
	{
		/*
		 * The real shutdown will be handled in the respective
		 * close functions.
		 */
		isc__nmsocket_attach(sock, &(isc_nmsocket_t *){ NULL });
		int r = uv_tcp_close_reset(&sock->uv_handle.tcp,
					   reset_shutdown);
		UV_RUNTIME_CHECK(uv_tcp_close_reset, r);
	} else {
		isc__nmsocket_shutdown(sock);
	}
}

void
isc__nmsocket_shutdown(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	switch (sock->type) {
	case isc_nm_udpsocket:
		isc__nm_udp_shutdown(sock);
		break;
	case isc_nm_tcpsocket:
		isc__nm_tcp_shutdown(sock);
		break;
	case isc_nm_tcpdnssocket:
		isc__nm_tcpdns_shutdown(sock);
		break;
	case isc_nm_tlsdnssocket:
		isc__nm_tlsdns_shutdown(sock);
		break;
	case isc_nm_udplistener:
	case isc_nm_tcplistener:
	case isc_nm_tcpdnslistener:
	case isc_nm_tlsdnslistener:
		return;
	default:
		UNREACHABLE();
	}
}

static void
shutdown_walk_cb(uv_handle_t *handle, void *arg) {
	isc_nmsocket_t *sock = NULL;
	UNUSED(arg);

	if (uv_is_closing(handle)) {
		return;
	}

	sock = uv_handle_get_data(handle);

	switch (handle->type) {
	case UV_UDP:
		isc__nmsocket_shutdown(sock);
		return;
	case UV_TCP:
		switch (sock->type) {
		case isc_nm_tcpsocket:
		case isc_nm_tcpdnssocket:
		case isc_nm_tlsdnssocket:
			if (sock->parent == NULL) {
				/* Reset the TCP connections on shutdown */
				isc__nmsocket_reset(sock);
				return;
			}
			FALLTHROUGH;
		default:
			isc__nmsocket_shutdown(sock);
		}

		return;
	default:
		return;
	}
}

void
isc_nm_setstats(isc_nm_t *mgr, isc_stats_t *stats) {
	REQUIRE(VALID_NM(mgr));
	REQUIRE(mgr->stats == NULL);
	REQUIRE(isc_stats_ncounters(stats) == isc_sockstatscounter_max);

	isc_stats_attach(stats, &mgr->stats);
}

void
isc__nm_incstats(isc_nmsocket_t *sock, isc__nm_statid_t id) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(id < STATID_MAX);

	if (sock->statsindex != NULL && sock->worker->netmgr->stats != NULL) {
		isc_stats_increment(sock->worker->netmgr->stats,
				    sock->statsindex[id]);
	}
}

void
isc__nm_decstats(isc_nmsocket_t *sock, isc__nm_statid_t id) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(id < STATID_MAX);

	if (sock->statsindex != NULL && sock->worker->netmgr->stats != NULL) {
		isc_stats_decrement(sock->worker->netmgr->stats,
				    sock->statsindex[id]);
	}
}

isc_result_t
isc_nm_checkaddr(const isc_sockaddr_t *addr, isc_socktype_t type) {
	int proto, pf, addrlen, fd, r;

	REQUIRE(addr != NULL);

	switch (type) {
	case isc_socktype_tcp:
		proto = SOCK_STREAM;
		break;
	case isc_socktype_udp:
		proto = SOCK_DGRAM;
		break;
	default:
		return (ISC_R_NOTIMPLEMENTED);
	}

	pf = isc_sockaddr_pf(addr);
	if (pf == AF_INET) {
		addrlen = sizeof(struct sockaddr_in);
	} else {
		addrlen = sizeof(struct sockaddr_in6);
	}

	fd = socket(pf, proto, 0);
	if (fd < 0) {
		return (isc_errno_toresult(errno));
	}

	r = bind(fd, (const struct sockaddr *)&addr->type.sa, addrlen);
	if (r < 0) {
		close(fd);
		return (isc_errno_toresult(errno));
	}

	close(fd);
	return (ISC_R_SUCCESS);
}

#if defined(TCP_CONNECTIONTIMEOUT)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_CONNECTIONTIMEOUT
#elif defined(TCP_RXT_CONNDROPTIME)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_RXT_CONNDROPTIME
#elif defined(TCP_USER_TIMEOUT)
#define TIMEOUT_TYPE	unsigned int
#define TIMEOUT_DIV	1
#define TIMEOUT_OPTNAME TCP_USER_TIMEOUT
#elif defined(TCP_KEEPINIT)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_KEEPINIT
#endif

void
isc__nm_set_network_buffers(isc_nm_t *nm, uv_handle_t *handle) {
	int32_t recv_buffer_size = 0;
	int32_t send_buffer_size = 0;

	switch (handle->type) {
	case UV_TCP:
		recv_buffer_size =
			atomic_load_relaxed(&nm->recv_tcp_buffer_size);
		send_buffer_size =
			atomic_load_relaxed(&nm->send_tcp_buffer_size);
		break;
	case UV_UDP:
		recv_buffer_size =
			atomic_load_relaxed(&nm->recv_udp_buffer_size);
		send_buffer_size =
			atomic_load_relaxed(&nm->send_udp_buffer_size);
		break;
	default:
		UNREACHABLE();
	}

	if (recv_buffer_size > 0) {
		int r = uv_recv_buffer_size(handle, &recv_buffer_size);
		UV_RUNTIME_CHECK(uv_recv_buffer_size, r);
	}

	if (send_buffer_size > 0) {
		int r = uv_send_buffer_size(handle, &send_buffer_size);
		UV_RUNTIME_CHECK(uv_send_buffer_size, r);
	}
}

void
isc_nm_bad_request(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	switch (sock->type) {
	case isc_nm_udpsocket:
		return;
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		REQUIRE(sock->parent == NULL);
		isc__nmsocket_reset(sock);
		return;
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_bad_request(handle);
		return;
#endif /* HAVE_LIBNGHTTP2 */
	case isc_nm_tcpsocket:
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNREACHABLE();
		break;
	}
}

bool
isc_nm_xfr_allowed(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	switch (sock->type) {
	case isc_nm_tcpdnssocket:
		return (true);
	case isc_nm_tlsdnssocket:
		return (isc__nm_tlsdns_xfr_allowed(sock));
	default:
		return (false);
	}

	UNREACHABLE();

	return (false);
}

bool
isc_nm_is_http_handle(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return (handle->sock->type == isc_nm_httpsocket);
}

void
isc_nm_set_maxage(isc_nmhandle_t *handle, const uint32_t ttl) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(!atomic_load(&handle->sock->client));

#if !HAVE_LIBNGHTTP2
	UNUSED(ttl);
#endif

	sock = handle->sock;
	switch (sock->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_set_maxage(handle, ttl);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	case isc_nm_udpsocket:
	case isc_nm_tcpdnssocket:
	case isc_nm_tlsdnssocket:
		return;
		break;

	case isc_nm_tcpsocket:
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNREACHABLE();
		break;
	}
}

isc_nmsocket_type
isc_nm_socket_type(const isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return (handle->sock->type);
}

bool
isc_nm_has_encryption(const isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	switch (handle->sock->type) {
	case isc_nm_tlsdnssocket:
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
#endif /* HAVE_LIBNGHTTP2 */
		return (true);
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		return (isc__nm_http_has_encryption(handle));
#endif /* HAVE_LIBNGHTTP2 */
	default:
		return (false);
	};

	return (false);
}

const char *
isc_nm_verify_tls_peer_result_string(const isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	switch (sock->type) {
	case isc_nm_tlsdnssocket:
		return (isc__nm_tlsdns_verify_tls_peer_result_string(handle));
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlssocket:
		return (isc__nm_tls_verify_tls_peer_result_string(handle));
		break;
	case isc_nm_httpsocket:
		return (isc__nm_http_verify_tls_peer_result_string(handle));
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		break;
	}

	return (NULL);
}

void
isc__nm_async_settlsctx(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent__tlsctx_t *ev_tlsctx = (isc__netievent__tlsctx_t *)ev0;
	const int tid = isc_tid();
	isc_nmsocket_t *listener = ev_tlsctx->sock;
	isc_tlsctx_t *tlsctx = ev_tlsctx->tlsctx;

	UNUSED(worker);

	switch (listener->type) {
	case isc_nm_tlsdnslistener:
		isc__nm_async_tlsdns_set_tlsctx(listener, tlsctx, tid);
		break;
#if HAVE_LIBNGHTTP2
	case isc_nm_tlslistener:
		isc__nm_async_tls_set_tlsctx(listener, tlsctx, tid);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNREACHABLE();
		break;
	};
}

static void
set_tlsctx_workers(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx) {
	const size_t nworkers =
		(size_t)isc_loopmgr_nloops(listener->worker->netmgr->loopmgr);
	/* Update the TLS context reference for every worker thread. */
	for (size_t i = 0; i < nworkers; i++) {
		isc__networker_t *worker =
			&listener->worker->netmgr->workers[i];
		isc__netievent__tlsctx_t *ievent =
			isc__nm_get_netievent_settlsctx(worker, listener,
							tlsctx);
		isc__nm_enqueue_ievent(worker, (isc__netievent_t *)ievent);
	}
}

void
isc_nmsocket_set_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx) {
	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(tlsctx != NULL);

	switch (listener->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httplistener:
		/*
		 * We handle HTTP listener sockets differently, as they rely
		 * on underlying TLS sockets for networking. The TLS context
		 * will get passed to these underlying sockets via the call to
		 * isc__nm_http_set_tlsctx().
		 */
		isc__nm_http_set_tlsctx(listener, tlsctx);
		break;
	case isc_nm_tlslistener:
		set_tlsctx_workers(listener, tlsctx);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	case isc_nm_tlsdnslistener:
		set_tlsctx_workers(listener, tlsctx);
		break;
	default:
		UNREACHABLE();
		break;
	};
}

void
isc_nmsocket_set_max_streams(isc_nmsocket_t *listener,
			     const uint32_t max_streams) {
	REQUIRE(VALID_NMSOCK(listener));
	switch (listener->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httplistener:
		isc__nm_http_set_max_streams(listener, max_streams);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNUSED(max_streams);
		break;
	};
	return;
}

void
isc__nmsocket_log_tls_session_reuse(isc_nmsocket_t *sock, isc_tls_t *tls) {
	const int log_level = ISC_LOG_DEBUG(1);
	char client_sabuf[ISC_SOCKADDR_FORMATSIZE];
	char local_sabuf[ISC_SOCKADDR_FORMATSIZE];

	REQUIRE(tls != NULL);

	if (!isc_log_wouldlog(isc_lctx, log_level)) {
		return;
	};

	isc_sockaddr_format(&sock->peer, client_sabuf, sizeof(client_sabuf));
	isc_sockaddr_format(&sock->iface, local_sabuf, sizeof(local_sabuf));
	isc__nmsocket_log(sock, log_level, "TLS %s session %s for %s on %s",
			  SSL_is_server(tls) ? "server" : "client",
			  SSL_session_reused(tls) ? "resumed" : "created",
			  client_sabuf, local_sabuf);
}

static void
isc__networker_destroy(isc__networker_t *worker) {
	isc_nm_t *netmgr = worker->netmgr;
	worker->netmgr = NULL;

	isc__netmgr_log(netmgr, ISC_LOG_DEBUG(1),
			"Destroying down network manager worker on loop %p(%d)",
			worker->loop, isc_tid());

	isc_loop_detach(&worker->loop);

	isc_mem_put(worker->mctx, worker->sendbuf, ISC_NETMGR_SENDBUF_SIZE);
	isc_mem_putanddetach(&worker->mctx, worker->recvbuf,
			     ISC_NETMGR_RECVBUF_SIZE);
	isc_nm_detach(&netmgr);
}

ISC_REFCOUNT_IMPL(isc__networker, isc__networker_destroy);

void
isc__netmgr_log(const isc_nm_t *netmgr, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(isc_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(isc_lctx, ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_NETMGR,
		      level, "netmgr %p: %s", netmgr, msgbuf);
}

void
isc__nmsocket_log(const isc_nmsocket_t *sock, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(isc_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(isc_lctx, ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_NETMGR,
		      level, "socket %p: %s", sock, msgbuf);
}

void
isc__nmhandle_log(const isc_nmhandle_t *handle, int level, const char *fmt,
		  ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(isc_lctx, level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc__nmsocket_log(handle->sock, level, "handle %p: %s", handle, msgbuf);
}

#ifdef NETMGR_TRACE
/*
 * Dump all active sockets in netmgr. We output to stderr
 * as the logger might be already shut down.
 */

static const char *
nmsocket_type_totext(isc_nmsocket_type type) {
	switch (type) {
	case isc_nm_udpsocket:
		return ("isc_nm_udpsocket");
	case isc_nm_udplistener:
		return ("isc_nm_udplistener");
	case isc_nm_tcpsocket:
		return ("isc_nm_tcpsocket");
	case isc_nm_tcplistener:
		return ("isc_nm_tcplistener");
	case isc_nm_tcpdnslistener:
		return ("isc_nm_tcpdnslistener");
	case isc_nm_tcpdnssocket:
		return ("isc_nm_tcpdnssocket");
	case isc_nm_tlssocket:
		return ("isc_nm_tlssocket");
	case isc_nm_tlslistener:
		return ("isc_nm_tlslistener");
	case isc_nm_tlsdnslistener:
		return ("isc_nm_tlsdnslistener");
	case isc_nm_tlsdnssocket:
		return ("isc_nm_tlsdnssocket");
	case isc_nm_httplistener:
		return ("isc_nm_httplistener");
	case isc_nm_httpsocket:
		return ("isc_nm_httpsocket");
	default:
		UNREACHABLE();
	}
}

static void
nmhandle_dump(isc_nmhandle_t *handle) {
	fprintf(stderr, "Active handle %p, refs %" PRIuFAST32 "\n", handle,
		isc_refcount_current(&handle->references));
	fprintf(stderr, "Created by:\n");
	isc_backtrace_symbols_fd(handle->backtrace, handle->backtrace_size,
				 STDERR_FILENO);
	fprintf(stderr, "\n\n");
}

static void
nmsocket_dump(isc_nmsocket_t *sock) {
	isc_nmhandle_t *handle = NULL;

	LOCK(&sock->tracelock);
	fprintf(stderr, "\n=================\n");
	fprintf(stderr, "Active %s socket %p, type %s, refs %" PRIuFAST32 "\n",
		atomic_load(&sock->client) ? "client" : "server", sock,
		nmsocket_type_totext(sock->type),
		isc_refcount_current(&sock->references));
	fprintf(stderr,
		"Parent %p, listener %p, server %p, statichandle = "
		"%p\n",
		sock->parent, sock->listener, sock->server, sock->statichandle);
	fprintf(stderr, "Flags:%s%s%s%s%s\n",
		atomic_load(&sock->active) ? " active" : "",
		atomic_load(&sock->closing) ? " closing" : "",
		atomic_load(&sock->destroying) ? " destroying" : "",
		atomic_load(&sock->connecting) ? " connecting" : "",
		atomic_load(&sock->accepting) ? " accepting" : "");
	fprintf(stderr, "Created by:\n");
	isc_backtrace_symbols_fd(sock->backtrace, sock->backtrace_size,
				 STDERR_FILENO);
	fprintf(stderr, "\n");

	for (handle = ISC_LIST_HEAD(sock->active_handles); handle != NULL;
	     handle = ISC_LIST_NEXT(handle, active_link))
	{
		static bool first = true;
		if (first) {
			fprintf(stderr, "Active handles:\n");
			first = false;
		}
		nmhandle_dump(handle);
	}

	fprintf(stderr, "\n");
	UNLOCK(&sock->tracelock);
}

void
isc__nm_dump_active(isc_nm_t *nm) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NM(nm));

	LOCK(&nm->lock);
	for (sock = ISC_LIST_HEAD(nm->active_sockets); sock != NULL;
	     sock = ISC_LIST_NEXT(sock, active_link))
	{
		static bool first = true;
		if (first) {
			fprintf(stderr, "Outstanding sockets\n");
			first = false;
		}
		nmsocket_dump(sock);
	}
	UNLOCK(&nm->lock);
}
#endif
