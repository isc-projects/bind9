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

#include <libgen.h>
#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
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

#include "netmgr-int.h"
#include "uv-compat.h"

static atomic_uint_fast32_t last_tcpquota_log = ATOMIC_VAR_INIT(0);

static bool
can_log_tcp_quota() {
	isc_stdtime_t now, last;

	isc_stdtime_get(&now);
	last = atomic_exchange_relaxed(&last_tcpquota_log, now);
	if (now != last) {
		return (true);
	}

	return (false);
}

static int
tcp_connect_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req);

static void
tcp_close_direct(isc_nmsocket_t *sock);

static isc_result_t
tcp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req);
static void
tcp_connect_cb(uv_connect_t *uvreq, int status);

static void
tcp_connection_cb(uv_stream_t *server, int status);

static void
read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

static void
tcp_close_cb(uv_handle_t *uvhandle);

static void
tcp_listenclose_cb(uv_handle_t *handle);
static isc_result_t
accept_connection(isc_nmsocket_t *ssock, isc_quota_t *quota);

static void
quota_accept_cb(isc_quota_t *quota, void *sock0);

static void
failed_accept_cb(isc_nmsocket_t *sock, isc_result_t eresult);

static void
failed_accept_cb(isc_nmsocket_t *sock, isc_result_t eresult) {
	/*
	 * Detach the quota early to make room for other connections;
	 * otherwise it'd be detached later asynchronously, and clog
	 * the quota unnecessarily.
	 */
	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	if (!sock->accepting) {
		return;
	}
	sock->accepting = false;

	switch (eresult) {
	case ISC_R_NOTCONNECTED:
		/* IGNORE: The client disconnected before we could accept */
		break;
	default:
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
			      "Accepting TCP connection failed: %s",
			      isc_result_totext(eresult));
	}

	/*
	 * Detach the socket properly to make sure uv_close() is called.
	 */
	isc__nmsocket_detach(&sock);
}

static void
failed_connect_cb(isc_nmsocket_t *sock, isc_result_t eresult) {
	isc__nm_uvreq_t *req;
	REQUIRE(sock->tid == isc_nm_tid());

	if (sock->timer_running) {
		uv_timer_stop(&sock->timer);
		sock->timer_running = false;
	}

	if (!atomic_load(&sock->connecting)) {
		return;
	}

	atomic_store(&sock->connecting, false);

	req = uv_handle_get_data((uv_handle_t *)&sock->timer);

	isc__nmsocket_clearcb(sock);
	if (req->cb.connect != NULL) {
		req->cb.connect(NULL, eresult, req->cbarg);
	}
	req->cb.connect = NULL;
	req->cbarg = NULL;

	isc__nm_uvreq_put(&req, sock);
	isc__nmsocket_detach(&sock);
}

static void
connecttimeout_cb(uv_timer_t *handle) {
	isc__nm_uvreq_t *req = uv_handle_get_data((uv_handle_t *)handle);
	isc_nmsocket_t *sock = req->sock;

	REQUIRE(sock->tid == isc_nm_tid());

	failed_connect_cb(sock, ISC_R_TIMEDOUT);
}

static int
tcp_connect_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	isc__networker_t *worker = NULL;
	int r;

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(sock->tid == isc_nm_tid());

	worker = &sock->mgr->workers[sock->tid];

	if (!sock->timer_initialized) {
		uv_timer_init(&worker->loop, &sock->timer);
		uv_handle_set_data((uv_handle_t *)&sock->timer, req);
		sock->timer_initialized = true;
	}

	atomic_store(&sock->connecting, true);

	r = uv_tcp_init(&worker->loop, &sock->uv_handle.tcp);
	if (r != 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_OPENFAIL]);
		atomic_store(&sock->closed, true);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->connect_error, true);
		return (r);
	}

	if (req->local.length != 0) {
		r = uv_tcp_bind(&sock->uv_handle.tcp, &req->local.type.sa, 0);
		if (r != 0) {
			isc__nm_incstats(sock->mgr,
					 sock->statsindex[STATID_BINDFAIL]);
			atomic_store(&sock->result, isc__nm_uverr2result(r));
			atomic_store(&sock->connect_error, true);
			failed_connect_cb(sock, isc__nm_uverr2result(-22));
			tcp_close_direct(sock);
			return (r);
		}
	}

	uv_handle_set_data(&sock->uv_handle.handle, sock);

	r = uv_tcp_connect(&req->uv_req.connect, &sock->uv_handle.tcp,
			   &req->peer.type.sa, tcp_connect_cb);
	if (r != 0) {
		isc__nm_incstats(sock->mgr,
				 sock->statsindex[STATID_CONNECTFAIL]);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->connect_error, true);
		failed_connect_cb(sock, isc__nm_uverr2result(-22));
		tcp_close_direct(sock);
		return (r);
	}
	isc__nm_incstats(sock->mgr, sock->statsindex[STATID_CONNECT]);

	uv_timer_start(&sock->timer, connecttimeout_cb, sock->connect_timeout,
		       0);
	sock->timer_running = true;

	return (0);
}

void
isc__nm_async_tcpconnect(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpconnect_t *ievent =
		(isc__netievent_tcpconnect_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;
	int r;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	UNUSED(worker);

	r = tcp_connect_direct(sock, req);
	if (r != 0) {
		LOCK(&sock->lock);
		SIGNAL(&sock->cond);
		UNLOCK(&sock->lock);
		return;
	}

	atomic_store(&sock->connected, true);

	LOCK(&sock->lock);
	SIGNAL(&sock->cond);
	UNLOCK(&sock->lock);
}

static void
tcp_connect_cb(uv_connect_t *uvreq, int status) {
	isc_result_t result;
	isc__nm_uvreq_t *req = (isc__nm_uvreq_t *)uvreq->data;
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)uvreq->handle);
	struct sockaddr_storage ss;
	isc_nmhandle_t *handle = NULL;

	REQUIRE(sock->tid == isc_nm_tid());

	if (status != 0) {
		failed_connect_cb(sock, isc__nm_uverr2result(status));
		return;
	}

	if (sock->timer_running) {
		uv_timer_stop(&sock->timer);
		sock->timer_running = false;
	}

	if (!atomic_load(&sock->connecting)) {
		return;
	}

	atomic_store(&sock->connecting, false);

	REQUIRE(VALID_UVREQ(req));

	sock = uv_handle_get_data((uv_handle_t *)uvreq->handle);

	isc__nm_incstats(sock->mgr, sock->statsindex[STATID_CONNECT]);
	uv_tcp_getpeername(&sock->uv_handle.tcp, (struct sockaddr *)&ss,
			   &(int){ sizeof(ss) });
	result = isc_sockaddr_fromsockaddr(&sock->peer, (struct sockaddr *)&ss);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	handle = isc__nmhandle_get(sock, NULL, NULL);
	req->cb.connect(handle, ISC_R_SUCCESS, req->cbarg);

	isc__nm_uvreq_put(&req, sock);

	/*
	 * The sock is now attached to the handle.
	 */
	isc__nmsocket_detach(&sock);

	/*
	 * The connect callback should have attached to the handle.
	 * If it didn't, the socket will be closed now.
	 */
	isc_nmhandle_detach(&handle);
}

isc_result_t
isc_nm_tcpconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_cb_t cb, void *cbarg, unsigned int timeout,
		  size_t extrahandlesize) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *nsock = NULL, *tmp = NULL;
	isc__netievent_tcpconnect_t *ievent = NULL;
	isc__nm_uvreq_t *req = NULL;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	nsock = isc_mem_get(mgr->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, mgr, isc_nm_tcpsocket, local);

	nsock->extrahandlesize = extrahandlesize;
	nsock->connect_timeout = timeout;

	atomic_init(&nsock->result, ISC_R_SUCCESS);
	atomic_init(&nsock->client, true);

	req = isc__nm_uvreq_get(mgr, nsock);
	req->cb.connect = cb;
	req->cbarg = cbarg;
	req->peer = peer->addr;
	req->local = local->addr;

	ievent = isc__nm_get_ievent(mgr, netievent_tcpconnect);
	ievent->sock = nsock;
	ievent->req = req;

	/*
	 * Async callbacks can dereference the socket in the meantime,
	 * we need to hold an additional reference to it.
	 */
	isc__nmsocket_attach(nsock, &tmp);

	if (isc__nm_in_netthread()) {
		nsock->tid = isc_nm_tid();
		isc__nm_async_tcpconnect(&mgr->workers[nsock->tid],
					 (isc__netievent_t *)ievent);
		isc__nm_put_ievent(mgr, ievent);
	} else {
		nsock->tid = isc_random_uniform(mgr->nworkers);
		isc__nm_enqueue_ievent(&mgr->workers[nsock->tid],
				       (isc__netievent_t *)ievent);

		LOCK(&nsock->lock);
		while (!atomic_load(&nsock->connected) &&
		       !atomic_load(&nsock->connect_error)) {
			WAIT(&nsock->cond, &nsock->lock);
		}
		UNLOCK(&nsock->lock);
	}

	result = atomic_load(&nsock->result);

	isc__nmsocket_detach(&tmp);

	return (result);
}

isc_result_t
isc_nm_listentcp(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		 size_t extrahandlesize, int backlog, isc_quota_t *quota,
		 isc_nmsocket_t **sockp) {
	isc_nmsocket_t *nsock = NULL;
	isc__netievent_tcplisten_t *ievent = NULL;

	REQUIRE(VALID_NM(mgr));

	nsock = isc_mem_get(mgr->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, mgr, isc_nm_tcplistener, iface);

	nsock->accept_cb = accept_cb;
	nsock->accept_cbarg = accept_cbarg;
	nsock->extrahandlesize = extrahandlesize;
	nsock->backlog = backlog;
	atomic_init(&nsock->result, ISC_R_SUCCESS);
	if (quota != NULL) {
		/*
		 * We don't attach to quota, just assign - to avoid
		 * increasing quota unnecessarily.
		 */
		nsock->pquota = quota;
	}
	isc_quota_cb_init(&nsock->quotacb, quota_accept_cb, nsock);

	ievent = isc__nm_get_ievent(mgr, netievent_tcplisten);
	ievent->sock = nsock;
	if (isc__nm_in_netthread()) {
		nsock->tid = isc_nm_tid();
		isc__nm_async_tcplisten(&mgr->workers[nsock->tid],
					(isc__netievent_t *)ievent);
		isc__nm_put_ievent(mgr, ievent);
	} else {
		nsock->tid = isc_random_uniform(mgr->nworkers);
		isc__nm_enqueue_ievent(&mgr->workers[nsock->tid],
				       (isc__netievent_t *)ievent);

		LOCK(&nsock->lock);
		while (!atomic_load(&nsock->listening) &&
		       !atomic_load(&nsock->listen_error)) {
			WAIT(&nsock->cond, &nsock->lock);
		}
		UNLOCK(&nsock->lock);
	}

	if (atomic_load(&nsock->result) == ISC_R_SUCCESS) {
		*sockp = nsock;
		return (ISC_R_SUCCESS);
	} else {
		isc_result_t result = atomic_load(&nsock->result);
		isc__nmsocket_detach(&nsock);
		return (result);
	}
}

/*
 * For multi-threaded TCP listening, we create a single socket,
 * bind to it, and start listening. On an incoming connection we accept
 * it, and then pass the accepted socket using the uv_export/uv_import
 * mechanism to a child thread.
 */
void
isc__nm_async_tcplisten(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcplisten_t *ievent = (isc__netievent_tcplisten_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	struct sockaddr_storage sname;
	int r, flags = 0, snamelen = sizeof(sname);
	sa_family_t sa_family;
	uv_os_sock_t fd;

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(sock->type == isc_nm_tcplistener);

	r = uv_tcp_init(&worker->loop, &sock->uv_handle.tcp);
	if (r != 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_OPENFAIL]);
		/* The socket was never opened, so no need for uv_close() */
		atomic_store(&sock->closed, true);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->listen_error, true);
		goto done;
	}

	isc__nm_incstats(sock->mgr, sock->statsindex[STATID_OPEN]);

	sa_family = sock->iface->addr.type.sa.sa_family;
	if (sa_family == AF_INET6) {
		flags = UV_TCP_IPV6ONLY;
	}

	r = uv_tcp_bind(&sock->uv_handle.tcp, &sock->iface->addr.type.sa,
			flags);
	if (r == UV_EADDRNOTAVAIL &&
	    uv_fileno(&sock->uv_handle.handle, (uv_os_fd_t *)&fd) == 0 &&
	    isc__nm_socket_freebind(fd, sa_family) == ISC_R_SUCCESS)
	{
		/*
		 * Retry binding with IP_FREEBIND (or equivalent option) if the
		 * address is not available. This helps with IPv6 tentative
		 * addresses which are reported by the route socket, although
		 * named is not yet able to properly bind to them.
		 */
		r = uv_tcp_bind(&sock->uv_handle.tcp,
				&sock->iface->addr.type.sa, flags);
	}

	if (r != 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_BINDFAIL]);
		uv_close(&sock->uv_handle.handle, tcp_close_cb);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->listen_error, true);
		goto done;
	}

	/*
	 * By doing this now, we can find out immediately whether bind()
	 * failed, and quit if so. (uv_bind() uses a delayed error,
	 * initially returning success even if bind() fails, and this
	 * could cause a deadlock later if we didn't check first.)
	 */
	r = uv_tcp_getsockname(&sock->uv_handle.tcp, (struct sockaddr *)&sname,
			       &snamelen);
	if (r != 0) {
		uv_close(&sock->uv_handle.handle, tcp_close_cb);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->listen_error, true);
		goto done;
	}

	/*
	 * The callback will run in the same thread uv_listen() was called
	 * from, so a race with tcp_connection_cb() isn't possible.
	 */
	r = uv_listen((uv_stream_t *)&sock->uv_handle.tcp, sock->backlog,
		      tcp_connection_cb);
	if (r != 0) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
			      "uv_listen failed: %s",
			      isc_result_totext(isc__nm_uverr2result(r)));
		uv_close(&sock->uv_handle.handle, tcp_close_cb);
		atomic_store(&sock->result, isc__nm_uverr2result(r));
		atomic_store(&sock->listen_error, true);
		goto done;
	}

	uv_handle_set_data(&sock->uv_handle.handle, sock);

	atomic_store(&sock->listening, true);

done:
	LOCK(&sock->lock);
	SIGNAL(&sock->cond);
	UNLOCK(&sock->lock);
	return;
}

static void
tcp_connection_cb(uv_stream_t *server, int status) {
	isc_nmsocket_t *psock = uv_handle_get_data((uv_handle_t *)server);
	isc_result_t result;

	UNUSED(status);

	result = accept_connection(psock, NULL);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOCONN) {
		if ((result != ISC_R_QUOTA && result != ISC_R_SOFTQUOTA) ||
		    can_log_tcp_quota()) {
			isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
				      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
				      "TCP connection failed: %s",
				      isc_result_totext(result));
		}
	}
}

void
isc__nm_async_tcpchildaccept(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpchildaccept_t *ievent =
		(isc__netievent_tcpchildaccept_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc_nmhandle_t *handle;
	isc_result_t result;
	struct sockaddr_storage ss;
	isc_sockaddr_t local;
	int r;
	isc_nm_accept_cb_t accept_cb;
	void *accept_cbarg;

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(sock->tid == isc_nm_tid());

	if (!sock->accepting) {
		return;
	}

	/* Socket was closed midflight by isc__nm_tcp_shutdown() */
	if (!isc__nmsocket_active(sock)) {
		failed_accept_cb(sock, ISC_R_CANCELED);
		return;
	}

	INSIST(sock->server != NULL);

	if (!isc__nmsocket_active(sock->server)) {
		failed_accept_cb(sock, ISC_R_CANCELED);
		return;
	}

	sock->quota = ievent->quota;
	ievent->quota = NULL;

	worker = &sock->mgr->workers[isc_nm_tid()];
	uv_tcp_init(&worker->loop, &sock->uv_handle.tcp);

	r = isc_uv_import(&sock->uv_handle.stream, &ievent->streaminfo);
	if (r != 0) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
			      "uv_import failed: %s",
			      isc_result_totext(isc__nm_uverr2result(r)));
		result = isc__nm_uverr2result(r);
		goto error;
	}

	r = uv_tcp_getpeername(&sock->uv_handle.tcp, (struct sockaddr *)&ss,
			       &(int){ sizeof(ss) });
	if (r != 0) {
		result = isc__nm_uverr2result(r);
		goto error;
	}

	result = isc_sockaddr_fromsockaddr(&sock->peer, (struct sockaddr *)&ss);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	r = uv_tcp_getsockname(&sock->uv_handle.tcp, (struct sockaddr *)&ss,
			       &(int){ sizeof(ss) });
	if (r != 0) {
		result = isc__nm_uverr2result(r);
		goto error;
	}

	result = isc_sockaddr_fromsockaddr(&local, (struct sockaddr *)&ss);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}
	sock->accepting = false;

	handle = isc__nmhandle_get(sock, NULL, &local);

	INSIST(sock->accept_cb != NULL);
	accept_cb = sock->accept_cb;
	accept_cbarg = sock->accept_cbarg;

	sock->read_timeout = sock->mgr->init;
	accept_cb(handle, ISC_R_SUCCESS, accept_cbarg);

	/*
	 * sock is now attached to the handle.
	 */
	isc__nmsocket_detach(&sock);

	/*
	 * The accept callback should have attached to the handle.
	 * If it didn't, the socket will be closed now.
	 */
	isc_nmhandle_detach(&handle);
	return;

error:
	failed_accept_cb(sock, result);
}

void
isc__nm_tcp_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcplistener);

	isc__netievent_tcpstop_t *ievent =
		isc__nm_get_ievent(sock->mgr, netievent_tcpstop);
	isc__nmsocket_attach(sock, &ievent->sock);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_async_tcpstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpstop_t *ievent = (isc__netievent_tcpstop_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcplistener);

	/*
	 * If network manager is interlocked, re-enqueue the event for later.
	 */
	if (!isc__nm_acquire_interlocked(sock->mgr)) {
		isc__netievent_tcpstop_t *event = NULL;

		event = isc__nm_get_ievent(sock->mgr, netievent_tcpstop);
		event->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)event);
	} else {
		uv_close((uv_handle_t *)&sock->uv_handle.tcp,
			 tcp_listenclose_cb);
		isc__nm_drop_interlocked(sock->mgr);
	}
}

/*
 * This callback is used for closing listening sockets.
 */
static void
tcp_listenclose_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);

	LOCK(&sock->lock);
	atomic_store(&sock->closed, true);
	atomic_store(&sock->listening, false);
	sock->pquota = NULL;
	UNLOCK(&sock->lock);

	isc__nmsocket_detach(&sock);
}

static void
failed_read_cb(isc_nmsocket_t *sock, isc_result_t result) {
	isc_nm_recv_cb_t cb;
	void *cbarg = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->statichandle != NULL);

	if (sock->timer_initialized) {
		uv_timer_stop(&sock->timer);
		sock->timer_running = false;
	}

	if (sock->quota) {
		isc_quota_detach(&sock->quota);
	}

	uv_read_stop(&sock->uv_handle.stream);

	cb = sock->recv_cb;
	cbarg = sock->recv_cbarg;
	isc__nmsocket_clearcb(sock);

	if (cb != NULL) {
		cb(sock->statichandle, result, NULL, cbarg);
	}
}

static void
readtimeout_cb(uv_timer_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)handle);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	/*
	 * Socket is actively processing something, so restart the timer
	 * and return.
	 */
	if (atomic_load(&sock->processing)) {
		uv_timer_start(handle, readtimeout_cb, sock->read_timeout, 0);
		sock->timer_running = true;
		return;
	}

	/*
	 * Timeout; stop reading and process whatever we have.
	 */
	failed_read_cb(sock, ISC_R_TIMEDOUT);
}

void
isc__nm_tcp_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc__netievent_startread_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	if (!isc__nmsocket_active(sock)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_RECVFAIL]);
		cb(handle, ISC_R_CANCELED, NULL, cbarg);
		return;
	}

	if (sock->server != NULL && !isc__nmsocket_active(sock->server)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, NULL, cbarg);
		return;
	}

	if (atomic_load(&sock->mgr->closing)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, NULL, cbarg);
		return;
	}

	REQUIRE(sock->tid == isc_nm_tid());

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstartread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_tcp_startread(&sock->mgr->workers[sock->tid],
					    (isc__netievent_t *)ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}

	return;
}

/*%<
 * Allocator for TCP read operations. Limited to size 2^16.
 *
 * Note this doesn't actually allocate anything, it just assigns the
 * worker's receive buffer to a socket, and marks it as "in use".
 */
static void
tcp_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(isc__nm_in_netthread());
	REQUIRE(size <= 65536);

	worker = &sock->mgr->workers[sock->tid];
	INSIST(!worker->recvbuf_inuse);

	buf->base = worker->recvbuf;
	buf->len = size;
	worker->recvbuf_inuse = true;
}

void
isc__nm_async_tcp_startread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_startread_t *ievent = (isc__netievent_startread_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	int r;

	REQUIRE(worker->id == isc_nm_tid());

	if (!isc__nmsocket_active(sock)) {
		failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	if (sock->server != NULL && !isc__nmsocket_active(sock->server)) {
		failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	if (atomic_load(&sock->mgr->closing)) {
		failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	r = uv_read_start(&sock->uv_handle.stream, tcp_alloc_cb, read_cb);
	if (r != 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_RECVFAIL]);
		failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	if (sock->read_timeout != 0) {
		if (!sock->timer_initialized) {
			uv_timer_init(&worker->loop, &sock->timer);
			uv_handle_set_data((uv_handle_t *)&sock->timer, sock);
			sock->timer_initialized = true;
		}
		uv_timer_start(&sock->timer, readtimeout_cb, sock->read_timeout,
			       0);
		sock->timer_running = true;
	}
}

void
isc__nm_tcp_pauseread(isc_nmsocket_t *sock) {
	isc__netievent_pauseread_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	if (!atomic_compare_exchange_strong(&sock->readpaused, &(bool){ false },
					    true)) {
		return;
	}

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcppauseread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_tcp_pauseread(&sock->mgr->workers[sock->tid],
					    (isc__netievent_t *)ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}

	return;
}

void
isc__nm_async_tcp_pauseread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_pauseread_t *ievent = (isc__netievent_pauseread_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(worker->id == isc_nm_tid());

	if (sock->timer_running) {
		uv_timer_stop(&sock->timer);
		sock->timer_running = false;
	}
	uv_read_stop(&sock->uv_handle.stream);
}

void
isc__nm_tcp_resumeread(isc_nmsocket_t *sock) {
	isc__netievent_startread_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	if (sock->recv_cb == NULL) {
		return;
	}

	if (!isc__nmsocket_active(sock)) {
		failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	if (!atomic_compare_exchange_strong(&sock->readpaused, &(bool){ true },
					    false)) {
		return;
	}

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstartread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_tcp_startread(&sock->mgr->workers[sock->tid],
					    (isc__netievent_t *)ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
}

static void
read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)stream);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(buf != NULL);

	if (nread >= 0) {
		isc_region_t region = { .base = (unsigned char *)buf->base,
					.length = nread };
		isc_nm_recv_cb_t cb = sock->recv_cb;
		void *cbarg = sock->recv_cbarg;

		if (cb != NULL) {
			cb(sock->statichandle, ISC_R_SUCCESS, &region, cbarg);
		}

		sock->read_timeout = (atomic_load(&sock->keepalive)
					      ? sock->mgr->keepalive
					      : sock->mgr->idle);

		if (sock->timer_initialized && sock->read_timeout != 0) {
			/* The timer will be updated */
			uv_timer_start(&sock->timer, readtimeout_cb,
				       sock->read_timeout, 0);
			sock->timer_running = true;
		}
	} else {
		/*
		 * This might happen if the inner socket is closing.  It means
		 * that it's detached, so the socket will be closed.
		 */
		if (nread != UV_EOF) {
			isc__nm_incstats(sock->mgr,
					 sock->statsindex[STATID_RECVFAIL]);
		}

		failed_read_cb(sock, ISC_R_EOF);
	}
	isc__nm_free_uvbuf(sock, buf);
}

static void
quota_accept_cb(isc_quota_t *quota, void *sock0) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)sock0;
	isc__netievent_tcpaccept_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	/*
	 * Create a tcpaccept event and pass it using the async channel.
	 */
	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpaccept);
	ievent->sock = sock;
	ievent->quota = quota;
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

/*
 * This is called after we get a quota_accept_cb() callback.
 */
void
isc__nm_async_tcpaccept(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc_result_t result;
	isc__netievent_tcpaccept_t *ievent = (isc__netievent_tcpaccept_t *)ev0;

	REQUIRE(worker->id == ievent->sock->tid);

	result = accept_connection(ievent->sock, ievent->quota);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOCONN) {
		if ((result != ISC_R_QUOTA && result != ISC_R_SOFTQUOTA) ||
		    can_log_tcp_quota()) {
			isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
				      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
				      "TCP connection failed: %s",
				      isc_result_totext(result));
		}
	}

	/*
	 * The socket was attached just before we called isc_quota_attach_cb().
	 */
	isc__nmsocket_detach(&ievent->sock);
}

/*
 * Close callback for uv_tcp_t strutures created in accept_connection().
 */
static void
free_uvtcpt(uv_handle_t *uvs) {
	isc_mem_t *mctx = (isc_mem_t *)uv_handle_get_data(uvs);
	isc_mem_putanddetach(&mctx, uvs, sizeof(uv_tcp_t));
}

static isc_result_t
accept_connection(isc_nmsocket_t *ssock, isc_quota_t *quota) {
	isc_result_t result;
	isc__netievent_tcpchildaccept_t *event = NULL;
	isc__networker_t *worker = NULL;
	uv_tcp_t *uvstream = NULL;
	isc_nmsocket_t *csock = NULL;
	isc_mem_t *mctx = NULL;
	int r, w;

	REQUIRE(VALID_NMSOCK(ssock));

	if (!isc__nmsocket_active(ssock) || atomic_load(&ssock->mgr->closing)) {
		/* We're closing, bail */
		if (quota != NULL) {
			isc_quota_detach(&quota);
		}
		return (ISC_R_CANCELED);
	}

	/* We can be called directly or as a callback from quota */
	if (ssock->pquota != NULL && quota == NULL) {
		/*
		 * We need to attach to ssock, because it might be queued
		 * waiting for a TCP quota slot.  If so, then we'll detach it
		 * later when the connection is accepted. (XXX: This may be
		 * suboptimal, it might be better not to attach unless
		 * we need to - but we risk a race then.)
		 */
		isc_nmsocket_t *tsock = NULL;
		isc__nmsocket_attach(ssock, &tsock);
		result = isc_quota_attach_cb(ssock->pquota, &quota,
					     &ssock->quotacb);
		if (result == ISC_R_QUOTA) {
			isc__nm_incstats(ssock->mgr,
					 ssock->statsindex[STATID_ACCEPTFAIL]);
			return (result);
		}

		/*
		 * We're under quota, so there's no need to wait;
		 * Detach the socket.
		 */
		isc__nmsocket_detach(&tsock);
	}

	isc__nm_incstats(ssock->mgr, ssock->statsindex[STATID_ACCEPT]);

	worker = &ssock->mgr->workers[isc_nm_tid()];
	uvstream = isc_mem_get(ssock->mgr->mctx, sizeof(uv_tcp_t));

	isc_mem_attach(ssock->mgr->mctx, &mctx);
	uv_handle_set_data((uv_handle_t *)uvstream, mctx);
	mctx = NULL; /* Detached later in free_uvtcpt() */

	uv_tcp_init(&worker->loop, uvstream);

	r = uv_accept(&ssock->uv_handle.stream, (uv_stream_t *)uvstream);
	if (r != 0) {
		result = isc__nm_uverr2result(r);
		uv_close((uv_handle_t *)uvstream, free_uvtcpt);
		if (quota != NULL) {
			isc_quota_detach(&quota);
		}
		return (result);
	}

	/* We have an accepted TCP socket, pass it to a random worker */
	w = isc_random_uniform(ssock->mgr->nworkers);
	event = isc__nm_get_ievent(ssock->mgr, netievent_tcpchildaccept);

	/* Duplicate the server socket */
	r = isc_uv_export((uv_stream_t *)uvstream, &event->streaminfo);
	if (r != 0) {
		result = isc_errno_toresult(errno);
		uv_close((uv_handle_t *)uvstream, free_uvtcpt);
		if (quota != NULL) {
			isc_quota_detach(&quota);
		}
		isc__nm_put_ievent(ssock->mgr, event);
		return (result);
	}

	csock = isc_mem_get(ssock->mgr->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(csock, ssock->mgr, isc_nm_tcpsocket, ssock->iface);
	csock->tid = w;
	csock->extrahandlesize = ssock->extrahandlesize;
	isc__nmsocket_attach(ssock, &csock->server);
	csock->accept_cb = ssock->accept_cb;
	csock->accept_cbarg = ssock->accept_cbarg;
	csock->accepting = true;

	event->sock = csock;
	event->quota = quota;

	uv_close((uv_handle_t *)uvstream, free_uvtcpt);

	if (w == isc_nm_tid()) {
		isc__nm_async_tcpchildaccept(&ssock->mgr->workers[w],
					     (isc__netievent_t *)event);
		isc__nm_put_ievent(ssock->mgr, event);
	} else {
		isc__nm_enqueue_ievent(&ssock->mgr->workers[w],
				       (isc__netievent_t *)event);
	}

	return (ISC_R_SUCCESS);
}

void
isc__nm_tcp_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
		 void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc__netievent_tcpsend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;

	REQUIRE(sock->type == isc_nm_tcpsocket);

	if (!isc__nmsocket_active(sock)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	if (sock->server != NULL && !isc__nmsocket_active(sock->server)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	if (atomic_load(&sock->mgr->closing)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	isc_nmhandle_attach(handle, &uvreq->handle);

	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (sock->tid == isc_nm_tid()) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		isc_result_t result = tcp_send_direct(sock, uvreq);
		if (result != ISC_R_SUCCESS) {
			isc__nm_incstats(sock->mgr,
					 sock->statsindex[STATID_SENDFAIL]);
			uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
			isc__nm_uvreq_put(&uvreq, sock);
		}
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpsend);
		ievent->sock = sock;
		ievent->req = uvreq;

		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
	return;
}

static void
tcp_send_cb(uv_write_t *req, int status) {
	isc_result_t result = ISC_R_SUCCESS;
	isc__nm_uvreq_t *uvreq = (isc__nm_uvreq_t *)req->data;
	isc_nmsocket_t *sock = uvreq->sock;

	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	if (status < 0) {
		result = isc__nm_uverr2result(status);
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
	}

	uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
	isc__nm_uvreq_put(&uvreq, sock);
}

/*
 * Handle 'tcpsend' async event - send a packet on the socket
 */
void
isc__nm_async_tcpsend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc_result_t result;
	isc__netievent_tcpsend_t *ievent = (isc__netievent_tcpsend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *uvreq = ievent->req;

	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(worker->id == ievent->sock->tid);

	result = tcp_send_direct(sock, uvreq);
	if (result != ISC_R_SUCCESS) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
		isc__nm_uvreq_put(&uvreq, sock);
	}
}

static isc_result_t
tcp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	int r;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	if (!isc__nmsocket_active(sock)) {
		return (ISC_R_CANCELED);
	}
	if (sock->server != NULL && !isc__nmsocket_active(sock->server)) {
		return (ISC_R_CANCELED);
	}
	if (atomic_load(&sock->mgr->closing)) {
		return (ISC_R_CANCELED);
	}

	r = uv_write(&req->uv_req.write, &sock->uv_handle.stream, &req->uvbuf,
		     1, tcp_send_cb);
	if (r < 0) {
		return (isc__nm_uverr2result(r));
	}

	return (ISC_R_SUCCESS);
}

static void
tcp_close_cb(uv_handle_t *uvhandle) {
	isc_nmsocket_t *sock = uv_handle_get_data(uvhandle);

	REQUIRE(VALID_NMSOCK(sock));

	isc__nm_incstats(sock->mgr, sock->statsindex[STATID_CLOSE]);
	atomic_store(&sock->closed, true);
	atomic_store(&sock->connected, false);

	if (sock->server != NULL) {
		isc__nmsocket_detach(&sock->server);
	}

	isc__nmsocket_prep_destroy(sock);
}

static void
timer_close_cb(uv_handle_t *uvhandle) {
	isc_nmsocket_t *sock = uv_handle_get_data(uvhandle);

	REQUIRE(VALID_NMSOCK(sock));

	uv_close(&sock->uv_handle.handle, tcp_close_cb);
}

static void
tcp_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	uv_read_stop((uv_stream_t *)&sock->uv_handle.handle);

	if (sock->timer_running) {
		uv_timer_stop(&sock->timer);
		sock->timer_running = false;
	}

	if (sock->timer_initialized) {
		sock->timer_initialized = false;
		uv_handle_set_data((uv_handle_t *)&sock->timer, sock);
		uv_close((uv_handle_t *)&sock->timer, timer_close_cb);
	} else {
		uv_close(&sock->uv_handle.handle, tcp_close_cb);
	}
}

void
isc__nm_tcp_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(!isc__nmsocket_active(sock));

	if (sock->tid == isc_nm_tid()) {
		tcp_close_direct(sock);
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		isc__netievent_tcpclose_t *ievent =
			isc__nm_get_ievent(sock->mgr, netievent_tcpclose);

		ievent->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_tcpclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpclose_t *ievent = (isc__netievent_tcpclose_t *)ev0;

	REQUIRE(worker->id == ievent->sock->tid);

	tcp_close_direct(ievent->sock);
}

void
isc__nm_tcp_shutdown(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	if (sock->type != isc_nm_tcpsocket) {
		return;
	}

	if (atomic_load(&sock->connecting)) {
		failed_connect_cb(sock, ISC_R_CANCELED);
		return;
	}

	/*
	 * If the socket is active, mark it inactive and
	 * continue. If it isn't active, stop now.
	 */
	if (!isc__nmsocket_deactivate(sock)) {
		return;
	}

	if (sock->accepting) {
		failed_accept_cb(sock, ISC_R_CANCELED);
		return;
	}

	if (sock->statichandle != NULL) {
		failed_read_cb(sock, ISC_R_CANCELED);
	}
}

void
isc__nm_tcp_cancelread(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;
	isc__netievent_tcpcancel_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	sock = handle->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpsocket);

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpcancel);
	ievent->sock = sock;
	isc_nmhandle_attach(handle, &ievent->handle);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_async_tcpcancel(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpcancel_t *ievent = (isc__netievent_tcpcancel_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc_nmhandle_t *handle = ievent->handle;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(worker->id == sock->tid);
	REQUIRE(sock->tid == isc_nm_tid());

	uv_read_stop(&sock->uv_handle.stream);

	if (atomic_load(&sock->client)) {
		failed_read_cb(sock, ISC_R_EOF);
	}

	isc_nmhandle_detach(&handle);
}
