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

#include <libgen.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/barrier.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/errno.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/stdtime.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "../loop_p.h"
#include "netmgr-int.h"

static atomic_uint_fast32_t last_tcpquota_log = 0;

static bool
can_log_tcp_quota(void) {
	isc_stdtime_t now, last;

	isc_stdtime_get(&now);
	last = atomic_exchange_relaxed(&last_tcpquota_log, now);
	if (now != last) {
		return (true);
	}

	return (false);
}

static isc_result_t
tcp_connect_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req);

static isc_result_t
tcp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req);
static void
tcp_connect_cb(uv_connect_t *uvreq, int status);
static void
tcp_stop_cb(uv_handle_t *handle);

static void
tcp_connection_cb(uv_stream_t *server, int status);

static void
tcp_close_cb(uv_handle_t *uvhandle);

static isc_result_t
accept_connection(isc_nmsocket_t *ssock, isc_quota_t *quota);

static void
quota_accept_cb(isc_quota_t *quota, void *sock0);

static void
failed_accept_cb(isc_nmsocket_t *sock, isc_result_t eresult);

static void
failed_accept_cb(isc_nmsocket_t *sock, isc_result_t eresult) {
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

static isc_result_t
tcp_connect_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	isc__networker_t *worker = NULL;
	isc_result_t result = ISC_R_UNSET;
	int r;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));

	REQUIRE(sock->tid == isc_tid());

	worker = sock->worker;

	atomic_store(&sock->connecting, true);

	/* 2 minute timeout */
	result = isc__nm_socket_connectiontimeout(sock->fd, 120 * 1000);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	r = uv_tcp_init(&worker->loop->loop, &sock->uv_handle.tcp);
	UV_RUNTIME_CHECK(uv_tcp_init, r);
	uv_handle_set_data(&sock->uv_handle.handle, sock);

	r = uv_timer_init(&worker->loop->loop, &sock->read_timer);
	UV_RUNTIME_CHECK(uv_timer_init, r);
	uv_handle_set_data((uv_handle_t *)&sock->read_timer, sock);

	r = uv_tcp_open(&sock->uv_handle.tcp, sock->fd);
	if (r != 0) {
		isc__nm_closesocket(sock->fd);
		isc__nm_incstats(sock, STATID_OPENFAIL);
		return (isc_uverr2result(r));
	}
	isc__nm_incstats(sock, STATID_OPEN);

	if (req->local.length != 0) {
		r = uv_tcp_bind(&sock->uv_handle.tcp, &req->local.type.sa, 0);
		if (r != 0) {
			isc__nm_incstats(sock, STATID_BINDFAIL);
			return (isc_uverr2result(r));
		}
	}

	isc__nm_set_network_buffers(sock->worker->netmgr,
				    &sock->uv_handle.handle);

	uv_handle_set_data(&req->uv_req.handle, req);
	r = uv_tcp_connect(&req->uv_req.connect, &sock->uv_handle.tcp,
			   &req->peer.type.sa, tcp_connect_cb);
	if (r != 0) {
		isc__nm_incstats(sock, STATID_CONNECTFAIL);
		return (isc_uverr2result(r));
	}

	uv_handle_set_data((uv_handle_t *)&sock->read_timer,
			   &req->uv_req.connect);
	isc__nmsocket_timer_start(sock);

	atomic_store(&sock->connected, true);

	return (ISC_R_SUCCESS);
}

static void
tcp_connect_cb(uv_connect_t *uvreq, int status) {
	isc_result_t result = ISC_R_UNSET;
	isc__nm_uvreq_t *req = NULL;
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)uvreq->handle);
	struct sockaddr_storage ss;
	isc__networker_t *worker = NULL;
	int r;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	worker = sock->worker;

	req = uv_handle_get_data((uv_handle_t *)uvreq);

	REQUIRE(VALID_UVREQ(req));
	REQUIRE(VALID_NMHANDLE(req->handle));

	if (atomic_load(&sock->timedout)) {
		result = ISC_R_TIMEDOUT;
		goto error;
	} else if (!atomic_load(&sock->connecting)) {
		/*
		 * The connect was cancelled from timeout; just clean up
		 * the req.
		 */
		isc__nm_uvreq_put(&req, sock);
		return;
	} else if (isc__nm_closing(worker)) {
		/* Network manager shutting down */
		result = ISC_R_SHUTTINGDOWN;
		goto error;
	} else if (isc__nmsocket_closing(sock)) {
		/* Connection canceled */
		result = ISC_R_CANCELED;
		goto error;
	} else if (status == UV_ETIMEDOUT) {
		/* Timeout status code here indicates hard error */
		result = ISC_R_TIMEDOUT;
		goto error;
	} else if (status == UV_EADDRINUSE) {
		/*
		 * On FreeBSD the TCP connect() call sometimes results in a
		 * spurious transient EADDRINUSE. Try a few more times before
		 * giving up.
		 */
		if (--req->connect_tries > 0) {
			r = uv_tcp_connect(&req->uv_req.connect,
					   &sock->uv_handle.tcp,
					   &req->peer.type.sa, tcp_connect_cb);
			if (r != 0) {
				result = isc_uverr2result(r);
				goto error;
			}
			return;
		}
		result = isc_uverr2result(status);
		goto error;
	} else if (status != 0) {
		result = isc_uverr2result(status);
		goto error;
	}

	isc__nmsocket_timer_stop(sock);
	uv_handle_set_data((uv_handle_t *)&sock->read_timer, sock);

	isc__nm_incstats(sock, STATID_CONNECT);
	r = uv_tcp_getpeername(&sock->uv_handle.tcp, (struct sockaddr *)&ss,
			       &(int){ sizeof(ss) });
	if (r != 0) {
		result = isc_uverr2result(r);
		goto error;
	}

	atomic_store(&sock->connecting, false);

	result = isc_sockaddr_fromsockaddr(&sock->peer, (struct sockaddr *)&ss);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	isc__nm_connectcb(sock, req, ISC_R_SUCCESS, false);

	return;
error:
	isc__nm_failed_connect_cb(sock, req, result, false);
}

void
isc_nm_tcpconnect(isc_nm_t *mgr, isc_sockaddr_t *local, isc_sockaddr_t *peer,
		  isc_nm_cb_t cb, void *cbarg, unsigned int timeout) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *sock = NULL;
	isc__nm_uvreq_t *req = NULL;
	sa_family_t sa_family;
	isc__networker_t *worker = &mgr->workers[isc_tid()];
	uv_os_sock_t fd = -1;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	if (isc__nm_closing(worker)) {
		cb(NULL, ISC_R_SHUTTINGDOWN, cbarg);
		return;
	}

	sa_family = peer->type.sa.sa_family;

	result = isc__nm_socket(sa_family, SOCK_STREAM, 0, &fd);
	if (result != ISC_R_SUCCESS) {
		cb(NULL, result, cbarg);
		return;
	}

	sock = isc_mem_get(worker->mctx, sizeof(*sock));
	isc__nmsocket_init(sock, worker, isc_nm_tcpsocket, local);

	sock->connect_timeout = timeout;
	sock->fd = fd;
	atomic_init(&sock->client, true);

	req = isc__nm_uvreq_get(worker, sock);
	req->cb.connect = cb;
	req->cbarg = cbarg;
	req->peer = *peer;
	req->local = *local;
	req->handle = isc__nmhandle_get(sock, &req->peer, &sock->iface);

	(void)isc__nm_socket_min_mtu(sock->fd, sa_family);
	(void)isc__nm_socket_tcp_maxseg(sock->fd, NM_MAXSEG);

	atomic_store(&sock->active, true);

	result = tcp_connect_direct(sock, req);
	if (result != ISC_R_SUCCESS) {
		atomic_store(&sock->active, false);
		isc__nm_tcp_close(sock);
		isc__nm_connectcb(sock, req, result, true);
	}

	/*
	 * The sock is now attached to the handle.
	 */
	isc__nmsocket_detach(&sock);
}

static uv_os_sock_t
isc__nm_tcp_lb_socket(isc_nm_t *mgr, sa_family_t sa_family) {
	isc_result_t result;
	uv_os_sock_t sock;

	result = isc__nm_socket(sa_family, SOCK_STREAM, 0, &sock);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	(void)isc__nm_socket_incoming_cpu(sock);
	(void)isc__nm_socket_v6only(sock, sa_family);

	/* FIXME: set mss */

	result = isc__nm_socket_reuse(sock);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	if (mgr->load_balance_sockets) {
		result = isc__nm_socket_reuse_lb(sock);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	}

	return (sock);
}

static void
start_tcp_child(isc_nm_t *mgr, isc_sockaddr_t *iface, isc_nmsocket_t *sock,
		uv_os_sock_t fd, int tid) {
	isc__netievent_tcplisten_t *ievent = NULL;
	isc_nmsocket_t *csock = &sock->children[tid];
	isc__networker_t *worker = &mgr->workers[tid];

	isc__nmsocket_init(csock, worker, isc_nm_tcpsocket, iface);
	csock->parent = sock;
	csock->accept_cb = sock->accept_cb;
	csock->accept_cbarg = sock->accept_cbarg;
	csock->backlog = sock->backlog;

	/*
	 * We don't attach to quota, just assign - to avoid
	 * increasing quota unnecessarily.
	 */
	csock->pquota = sock->pquota;
	isc_quota_cb_init(&csock->quotacb, quota_accept_cb, csock);

	if (mgr->load_balance_sockets) {
		UNUSED(fd);
		csock->fd = isc__nm_tcp_lb_socket(mgr,
						  iface->type.sa.sa_family);
	} else {
		csock->fd = dup(fd);
	}
	REQUIRE(csock->fd >= 0);

	ievent = isc__nm_get_netievent_tcplisten(csock->worker, csock);

	if (tid == 0) {
		isc__nm_process_ievent(csock->worker,
				       (isc__netievent_t *)ievent);
	} else {
		isc__nm_enqueue_ievent(csock->worker,
				       (isc__netievent_t *)ievent);
	}
}

isc_result_t
isc_nm_listentcp(isc_nm_t *mgr, uint32_t workers, isc_sockaddr_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg, int backlog,
		 isc_quota_t *quota, isc_nmsocket_t **sockp) {
	isc_nmsocket_t *sock = NULL;
	size_t children_size = 0;
	uv_os_sock_t fd = -1;
	isc_result_t result = ISC_R_UNSET;
	isc__networker_t *worker = &mgr->workers[0];

	REQUIRE(VALID_NM(mgr));
	REQUIRE(isc_tid() == 0);

	if (workers == 0) {
		workers = mgr->nloops;
	}
	REQUIRE(workers <= mgr->nloops);

	sock = isc_mem_get(worker->mctx, sizeof(*sock));
	isc__nmsocket_init(sock, worker, isc_nm_tcplistener, iface);

	atomic_init(&sock->rchildren, 0);
	sock->nchildren = (workers == ISC_NM_LISTEN_ALL) ? (uint32_t)mgr->nloops
							 : workers;
	children_size = sock->nchildren * sizeof(sock->children[0]);
	sock->children = isc_mem_getx(worker->mctx, children_size,
				      ISC_MEM_ZERO);

	isc__nmsocket_barrier_init(sock);

	sock->accept_cb = accept_cb;
	sock->accept_cbarg = accept_cbarg;
	sock->backlog = backlog;
	sock->pquota = quota;

	if (!mgr->load_balance_sockets) {
		fd = isc__nm_tcp_lb_socket(mgr, iface->type.sa.sa_family);
	}

	for (size_t i = 1; i < sock->nchildren; i++) {
		start_tcp_child(mgr, iface, sock, fd, i);
	}

	start_tcp_child(mgr, iface, sock, fd, 0);

	if (!mgr->load_balance_sockets) {
		isc__nm_closesocket(fd);
	}

	LOCK(&sock->lock);
	result = sock->result;
	UNLOCK(&sock->lock);
	INSIST(result != ISC_R_UNSET);

	atomic_store(&sock->active, true);

	if (result != ISC_R_SUCCESS) {
		atomic_store(&sock->active, false);
		isc__nm_tcp_stoplistening(sock);
		isc_nmsocket_close(&sock);

		return (result);
	}

	REQUIRE(atomic_load(&sock->rchildren) == sock->nchildren);
	*sockp = sock;
	return (ISC_R_SUCCESS);
}

void
isc__nm_async_tcplisten(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcplisten_t *ievent = (isc__netievent_tcplisten_t *)ev0;
	sa_family_t sa_family;
	int r;
	int flags = 0;
	isc_nmsocket_t *sock = NULL;
	isc_result_t result = ISC_R_UNSET;

	REQUIRE(VALID_NMSOCK(ievent->sock));
	REQUIRE(ievent->sock->tid == isc_tid());
	REQUIRE(VALID_NMSOCK(ievent->sock->parent));

	sock = ievent->sock;
	sa_family = sock->iface.type.sa.sa_family;

	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(sock->parent != NULL);
	REQUIRE(sock->tid == isc_tid());

	(void)isc__nm_socket_min_mtu(sock->fd, sa_family);
	(void)isc__nm_socket_tcp_maxseg(sock->fd, NM_MAXSEG);

	r = uv_tcp_init(&worker->loop->loop, &sock->uv_handle.tcp);
	UV_RUNTIME_CHECK(uv_tcp_init, r);
	uv_handle_set_data(&sock->uv_handle.handle, sock);
	/* This keeps the socket alive after everything else is gone */
	isc__nmsocket_attach(sock, &(isc_nmsocket_t *){ NULL });

	r = uv_timer_init(&worker->loop->loop, &sock->read_timer);
	UV_RUNTIME_CHECK(uv_timer_init, r);
	uv_handle_set_data((uv_handle_t *)&sock->read_timer, sock);

	r = uv_tcp_open(&sock->uv_handle.tcp, sock->fd);
	if (r < 0) {
		isc__nm_closesocket(sock->fd);
		isc__nm_incstats(sock, STATID_OPENFAIL);
		goto done;
	}
	isc__nm_incstats(sock, STATID_OPEN);

	if (sa_family == AF_INET6) {
		flags = UV_TCP_IPV6ONLY;
	}

	if (sock->worker->netmgr->load_balance_sockets) {
		r = isc__nm_tcp_freebind(&sock->uv_handle.tcp,
					 &sock->iface.type.sa, flags);
		if (r < 0) {
			isc__nm_incstats(sock, STATID_BINDFAIL);
			goto done;
		}
	} else {
		LOCK(&sock->parent->lock);
		if (sock->parent->fd == -1) {
			r = isc__nm_tcp_freebind(&sock->uv_handle.tcp,
						 &sock->iface.type.sa, flags);
			if (r < 0) {
				isc__nm_incstats(sock, STATID_BINDFAIL);
				UNLOCK(&sock->parent->lock);
				goto done;
			}
			sock->parent->uv_handle.tcp.flags =
				sock->uv_handle.tcp.flags;
			sock->parent->fd = sock->fd;
		} else {
			/* The socket is already bound, just copy the flags */
			sock->uv_handle.tcp.flags =
				sock->parent->uv_handle.tcp.flags;
		}
		UNLOCK(&sock->parent->lock);
	}

	isc__nm_set_network_buffers(sock->worker->netmgr,
				    &sock->uv_handle.handle);

	/*
	 * The callback will run in the same thread uv_listen() was called
	 * from, so a race with tcp_connection_cb() isn't possible.
	 */
	r = uv_listen((uv_stream_t *)&sock->uv_handle.tcp, sock->backlog,
		      tcp_connection_cb);
	if (r != 0) {
		isc__nmsocket_log(sock, ISC_LOG_ERROR, "uv_listen failed: %s",
				  isc_result_totext(isc_uverr2result(r)));
		isc__nm_incstats(sock, STATID_BINDFAIL);
		goto done;
	}

	atomic_store(&sock->listening, true);

done:
	result = isc_uverr2result(r);
	atomic_fetch_add(&sock->parent->rchildren, 1);

	if (result != ISC_R_SUCCESS) {
		sock->pquota = NULL;
	}

	LOCK(&sock->parent->lock);
	if (sock->parent->result == ISC_R_UNSET) {
		sock->parent->result = result;
	} else {
		REQUIRE(sock->parent->result == result);
	}
	UNLOCK(&sock->parent->lock);

	REQUIRE(!worker->loop->paused);
	isc_barrier_wait(&sock->parent->barrier);
}

static void
tcp_connection_cb(uv_stream_t *server, int status) {
	isc_nmsocket_t *ssock = uv_handle_get_data((uv_handle_t *)server);
	isc_result_t result;
	isc_quota_t *quota = NULL;

	if (status != 0) {
		result = isc_uverr2result(status);
		goto done;
	}

	REQUIRE(VALID_NMSOCK(ssock));
	REQUIRE(ssock->tid == isc_tid());

	if (isc__nmsocket_closing(ssock)) {
		result = ISC_R_CANCELED;
		goto done;
	}

	if (ssock->pquota != NULL) {
		result = isc_quota_attach_cb(ssock->pquota, &quota,
					     &ssock->quotacb);
		if (result == ISC_R_QUOTA) {
			isc__nm_incstats(ssock, STATID_ACCEPTFAIL);
			goto done;
		}
	}

	result = accept_connection(ssock, quota);
done:
	isc__nm_accept_connection_log(ssock, result, can_log_tcp_quota());
}

static void
stop_tcp_child(isc_nmsocket_t *sock, uint32_t tid) {
	isc_nmsocket_t *csock = NULL;
	isc__netievent_tcpstop_t *ievent = NULL;

	csock = &sock->children[tid];
	REQUIRE(VALID_NMSOCK(csock));

	atomic_store(&csock->active, false);
	ievent = isc__nm_get_netievent_tcpstop(csock->worker, csock);

	if (tid == 0) {
		isc__nm_process_ievent(csock->worker,
				       (isc__netievent_t *)ievent);
	} else {
		isc__nm_enqueue_ievent(csock->worker,
				       (isc__netievent_t *)ievent);
	}
}

static void
stop_tcp_parent(isc_nmsocket_t *sock) {
	/* Stop the parent */
	atomic_store(&sock->closed, true);
	isc__nmsocket_prep_destroy(sock);
}

void
isc__nm_tcp_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcplistener);
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->tid == 0);

	RUNTIME_CHECK(atomic_compare_exchange_strong(&sock->closing,
						     &(bool){ false }, true));

	for (size_t i = 1; i < sock->nchildren; i++) {
		stop_tcp_child(sock, i);
	}

	stop_tcp_child(sock, 0);

	stop_tcp_parent(sock);
}

static void
tcp_stop_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	uv_handle_set_data(handle, NULL);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(atomic_load(&sock->closing));
	REQUIRE(sock->type == isc_nm_tcpsocket);

	RUNTIME_CHECK(atomic_compare_exchange_strong(&sock->closed,
						     &(bool){ false }, true));

	isc__nm_incstats(sock, STATID_CLOSE);

	atomic_store(&sock->listening, false);

	isc__nmsocket_detach(&sock);
}

void
isc__nm_async_tcpstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpstop_t *ievent = (isc__netievent_tcpstop_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->parent != NULL);
	REQUIRE(sock->type == isc_nm_tcpsocket);

	RUNTIME_CHECK(atomic_compare_exchange_strong(&sock->closing,
						     &(bool){ false }, true));

	/*
	 * The order of the close operation is important here, the uv_close()
	 * gets scheduled in the reverse order, so we need to close the timer
	 * last, so its gone by the time we destroy the socket
	 */

	/* 2. close the listening socket */
	isc__nmsocket_clearcb(sock);
	isc__nm_stop_reading(sock);
	uv_close(&sock->uv_handle.handle, tcp_stop_cb);

	/* 1. close the read timer */
	isc__nmsocket_timer_stop(sock);
	uv_close(&sock->read_timer, NULL);

	(void)atomic_fetch_sub(&sock->parent->rchildren, 1);

	REQUIRE(!worker->loop->paused);
	isc_barrier_wait(&sock->parent->barrier);
}

void
isc__nm_tcp_failed_read_cb(isc_nmsocket_t *sock, isc_result_t result,
			   bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(result != ISC_R_SUCCESS);

	isc__nmsocket_timer_stop(sock);
	isc__nm_stop_reading(sock);

	if (!sock->recv_read) {
		goto destroy;
	}
	sock->recv_read = false;

	if (sock->recv_cb != NULL) {
		isc__nm_uvreq_t *req = isc__nm_get_read_req(sock, NULL);
		isc__nmsocket_clearcb(sock);
		isc__nm_readcb(sock, req, result, async);
	}

destroy:
	isc__nmsocket_prep_destroy(sock);

	/*
	 * We need to detach from quota after the read callback function had a
	 * chance to be executed.
	 */
	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}
}

void
isc__nm_tcp_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock;
	isc_nm_t *netmgr;
	isc_result_t result;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	netmgr = sock->worker->netmgr;

	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(sock->statichandle == handle);

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;
	sock->recv_read = true;

	/* Initialize the timer */
	if (sock->read_timeout == 0) {
		sock->read_timeout = (atomic_load(&sock->keepalive)
					      ? atomic_load(&netmgr->keepalive)
					      : atomic_load(&netmgr->idle));
	}

	if (isc__nmsocket_closing(sock)) {
		result = ISC_R_CANCELED;
		goto failure;
	}

	result = isc__nm_start_reading(sock);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	isc__nmsocket_timer_start(sock);

	return;
failure:
	sock->reading = true;
	isc__nm_tcp_failed_read_cb(sock, result, true);
}

void
isc__nm_tcp_read_stop(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc_nmsocket_t *sock = handle->sock;

	isc__nmsocket_timer_stop(sock);
	isc__nm_stop_reading(sock);

	return;
}

void
isc__nm_tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)stream);
	isc__nm_uvreq_t *req = NULL;
	isc_nm_t *netmgr = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->reading);
	REQUIRE(buf != NULL);

	netmgr = sock->worker->netmgr;

	if (isc__nmsocket_closing(sock)) {
		isc__nm_tcp_failed_read_cb(sock, ISC_R_CANCELED, false);
		goto free;
	}

	if (nread < 0) {
		if (nread != UV_EOF) {
			isc__nm_incstats(sock, STATID_RECVFAIL);
		}

		isc__nm_tcp_failed_read_cb(sock, isc_uverr2result(nread),
					   false);

		goto free;
	}

	req = isc__nm_get_read_req(sock, NULL);

	/*
	 * The callback will be called synchronously because the
	 * result is ISC_R_SUCCESS, so we don't need to retain
	 * the buffer
	 */
	req->uvbuf.base = buf->base;
	req->uvbuf.len = nread;

	if (!atomic_load(&sock->client)) {
		sock->read_timeout = (atomic_load(&sock->keepalive)
					      ? atomic_load(&netmgr->keepalive)
					      : atomic_load(&netmgr->idle));
	}

	isc__nm_readcb(sock, req, ISC_R_SUCCESS, false);

	/* The readcb could have paused the reading */
	if (sock->reading) {
		/* The timer will be updated */
		isc__nmsocket_timer_restart(sock);
	}

free:
	if (nread < 0) {
		/*
		 * The buffer may be a null buffer on error.
		 */
		if (buf->base == NULL && buf->len == 0) {
			return;
		}
	}

	isc__nm_free_uvbuf(sock, buf);
}

static void
quota_accept_cb(isc_quota_t *quota, void *sock0) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)sock0;
	isc__netievent_tcpaccept_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	/*
	 * Create a tcpaccept event and pass it using the async channel.  This
	 * needs to be asynchronous, because the quota might have been released
	 * by a different child socket.
	 */
	ievent = isc__nm_get_netievent_tcpaccept(sock->worker, sock, quota);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

/*
 * This is called after we get a quota_accept_cb() callback.
 */
void
isc__nm_async_tcpaccept(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpaccept_t *ievent = (isc__netievent_tcpaccept_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc_result_t result;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	result = accept_connection(sock, ievent->quota);
	isc__nm_accept_connection_log(sock, result, can_log_tcp_quota());
}

static isc_result_t
accept_connection(isc_nmsocket_t *ssock, isc_quota_t *quota) {
	isc_nmsocket_t *csock = NULL;
	isc__networker_t *worker = NULL;
	int r;
	isc_result_t result;
	struct sockaddr_storage ss;
	isc_sockaddr_t local;
	isc_nmhandle_t *handle = NULL;

	REQUIRE(VALID_NMSOCK(ssock));
	REQUIRE(ssock->tid == isc_tid());

	if (isc__nmsocket_closing(ssock)) {
		if (quota != NULL) {
			isc_quota_detach(&quota);
		}
		return (ISC_R_CANCELED);
	}

	REQUIRE(ssock->accept_cb != NULL);

	csock = isc_mem_get(ssock->worker->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(csock, ssock->worker, isc_nm_tcpsocket,
			   &ssock->iface);
	isc__nmsocket_attach(ssock, &csock->server);
	csock->recv_cb = ssock->recv_cb;
	csock->recv_cbarg = ssock->recv_cbarg;
	csock->quota = quota;
	atomic_init(&csock->accepting, true);

	worker = csock->worker;

	r = uv_tcp_init(&worker->loop->loop, &csock->uv_handle.tcp);
	UV_RUNTIME_CHECK(uv_tcp_init, r);
	uv_handle_set_data(&csock->uv_handle.handle, csock);

	r = uv_timer_init(&worker->loop->loop, &csock->read_timer);
	UV_RUNTIME_CHECK(uv_timer_init, r);
	uv_handle_set_data((uv_handle_t *)&csock->read_timer, csock);

	r = uv_accept(&ssock->uv_handle.stream, &csock->uv_handle.stream);
	if (r != 0) {
		result = isc_uverr2result(r);
		goto failure;
	}

	r = uv_tcp_getpeername(&csock->uv_handle.tcp, (struct sockaddr *)&ss,
			       &(int){ sizeof(ss) });
	if (r != 0) {
		result = isc_uverr2result(r);
		goto failure;
	}

	result = isc_sockaddr_fromsockaddr(&csock->peer,
					   (struct sockaddr *)&ss);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	r = uv_tcp_getsockname(&csock->uv_handle.tcp, (struct sockaddr *)&ss,
			       &(int){ sizeof(ss) });
	if (r != 0) {
		result = isc_uverr2result(r);
		goto failure;
	}

	result = isc_sockaddr_fromsockaddr(&local, (struct sockaddr *)&ss);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	handle = isc__nmhandle_get(csock, NULL, &local);

	result = ssock->accept_cb(handle, ISC_R_SUCCESS, ssock->accept_cbarg);
	if (result != ISC_R_SUCCESS) {
		isc_nmhandle_detach(&handle);
		goto failure;
	}

	atomic_store(&csock->accepting, false);

	isc__nm_incstats(csock, STATID_ACCEPT);

	csock->read_timeout = atomic_load(&csock->worker->netmgr->init);

	/*
	 * The acceptcb needs to attach to the handle if it wants to keep the
	 * connection alive
	 */
	isc_nmhandle_detach(&handle);

	/*
	 * sock is now attached to the handle.
	 */
	isc__nmsocket_detach(&csock);

	return (ISC_R_SUCCESS);

failure:
	atomic_store(&csock->active, false);

	failed_accept_cb(csock, result);

	isc__nmsocket_prep_destroy(csock);

	isc__nmsocket_detach(&csock);

	return (result);
}

void
isc__nm_tcp_send(isc_nmhandle_t *handle, const isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc_nmsocket_t *sock = handle->sock;
	isc_result_t result;
	isc__nm_uvreq_t *uvreq = NULL;
	isc_nm_t *netmgr = sock->worker->netmgr;

	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(sock->tid == isc_tid());

	uvreq = isc__nm_uvreq_get(sock->worker, sock);
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	isc_nmhandle_attach(handle, &uvreq->handle);

	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (sock->write_timeout == 0) {
		sock->write_timeout = (atomic_load(&sock->keepalive)
					       ? atomic_load(&netmgr->keepalive)
					       : atomic_load(&netmgr->idle));
	}

	result = tcp_send_direct(sock, uvreq);
	if (result != ISC_R_SUCCESS) {
		isc__nm_incstats(sock, STATID_SENDFAIL);
		isc__nm_failed_send_cb(sock, uvreq, result, true);
	}

	return;
}

static void
tcp_send_cb(uv_write_t *req, int status) {
	isc__nm_uvreq_t *uvreq = (isc__nm_uvreq_t *)req->data;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMSOCK(uvreq->sock));

	sock = uvreq->sock;

	isc_nm_timer_stop(uvreq->timer);
	isc_nm_timer_detach(&uvreq->timer);

	if (status < 0) {
		isc__nm_incstats(sock, STATID_SENDFAIL);
		isc__nm_failed_send_cb(sock, uvreq, isc_uverr2result(status),
				       false);
		return;
	}

	isc__nm_sendcb(sock, uvreq, ISC_R_SUCCESS, false);
}

static isc_result_t
tcp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	int r;

	if (isc__nmsocket_closing(sock)) {
		return (ISC_R_CANCELED);
	}

	uv_buf_t uvbuf = { .base = req->uvbuf.base, .len = req->uvbuf.len };

	r = uv_try_write(&sock->uv_handle.stream, &uvbuf, 1);

	if (r == (int)(uvbuf.len)) {
		/* Wrote everything */
		isc__nm_sendcb(sock, req, ISC_R_SUCCESS, true);
		return (ISC_R_SUCCESS);
	} else if (r > 0) {
		uvbuf.base += (size_t)r;
		uvbuf.len -= (size_t)r;
	} else if (!(r == UV_ENOSYS || r == UV_EAGAIN)) {
		return (isc_uverr2result(r));
	}

	r = uv_write(&req->uv_req.write, &sock->uv_handle.stream, &uvbuf, 1,
		     tcp_send_cb);
	if (r < 0) {
		return (isc_uverr2result(r));
	}

	isc_nm_timer_create(req->handle, isc__nmsocket_writetimeout_cb, req,
			    &req->timer);
	if (sock->write_timeout > 0) {
		isc_nm_timer_start(req->timer, sock->write_timeout);
	}

	return (ISC_R_SUCCESS);
}

static void
tcp_close_sock(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(atomic_load(&sock->closing));

	RUNTIME_CHECK(atomic_compare_exchange_strong(&sock->closed,
						     &(bool){ false }, true));

	isc__nm_incstats(sock, STATID_CLOSE);

	if (sock->server != NULL) {
		isc__nmsocket_detach(&sock->server);
	}

	atomic_store(&sock->connected, false);

	isc__nmsocket_prep_destroy(sock);
}

static void
tcp_close_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	uv_handle_set_data(handle, NULL);

	tcp_close_sock(sock);
}

void
isc__nm_tcp_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(!isc__nmsocket_active(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->parent == NULL);

	RUNTIME_CHECK(atomic_compare_exchange_strong(&sock->closing,
						     &(bool){ false }, true));

	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	/*
	 * The order of the close operation is important here, the uv_close()
	 * gets scheduled in the reverse order, so we need to close the timer
	 * last, so its gone by the time we destroy the socket
	 */

	if (!uv_is_closing(&sock->uv_handle.handle)) {
		/* Normal order of operation */

		/* 2. close the socket + destroy the socket in callback */
		isc__nmsocket_clearcb(sock);
		isc__nm_stop_reading(sock);
		uv_close(&sock->uv_handle.handle, tcp_close_cb);

		/* 1. close the timer */
		isc__nmsocket_timer_stop(sock);
		uv_close((uv_handle_t *)&sock->read_timer, NULL);
	} else {
		/* The socket was already closed elsewhere */

		/* 1. close the timer + destroy the socket in callback */
		isc__nmsocket_timer_stop(sock);
		uv_handle_set_data((uv_handle_t *)&sock->read_timer, sock);
		uv_close((uv_handle_t *)&sock->read_timer, tcp_close_cb);
	}
}

static void
tcp_close_connect_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);

	REQUIRE(VALID_NMSOCK(sock));

	REQUIRE(sock->tid == isc_tid());

	isc__nmsocket_prep_destroy(sock);
	isc__nmsocket_detach(&sock);
}

void
isc__nm_tcp_shutdown(isc_nmsocket_t *sock) {
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	worker = sock->worker;

	/*
	 * If the socket is active, mark it inactive and
	 * continue. If it isn't active, stop now.
	 */
	if (!isc__nmsocket_deactivate(sock)) {
		return;
	}

	if (atomic_load(&sock->accepting)) {
		return;
	}

	if (atomic_load(&sock->connecting)) {
		isc_nmsocket_t *tsock = NULL;
		isc__nmsocket_attach(sock, &tsock);
		uv_close(&sock->uv_handle.handle, tcp_close_connect_cb);
		return;
	}

	if (sock->statichandle != NULL) {
		if (isc__nm_closing(worker)) {
			isc__nm_failed_read_cb(sock, ISC_R_SHUTTINGDOWN, false);
		} else {
			isc__nm_failed_read_cb(sock, ISC_R_CANCELED, false);
		}
		return;
	}

	/*
	 * Otherwise, we just send the socket to abyss...
	 */
	if (sock->parent == NULL) {
		isc__nmsocket_prep_destroy(sock);
	}
}
