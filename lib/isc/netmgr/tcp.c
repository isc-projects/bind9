/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
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
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"

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

static int
tcp_connect_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	isc__networker_t *worker;
	int r;

	REQUIRE(isc__nm_in_netthread());

	worker = &sock->mgr->workers[isc_nm_tid()];

	r = uv_tcp_init(&worker->loop, &sock->uv_handle.tcp);
	if (r != 0) {
		return (r);
	}

	if (req->local.length != 0) {
		r = uv_tcp_bind(&sock->uv_handle.tcp, &req->local.type.sa, 0);
		if (r != 0) {
			tcp_close_direct(sock);
			return (r);
		}
	}

	r = uv_tcp_connect(&req->uv_req.connect, &sock->uv_handle.tcp,
			   &req->peer.type.sa, tcp_connect_cb);
	return (r);
}

void
isc__nm_async_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_tcpconnect_t *ievent =
		(isc__netievent_tcpconnect_t *) ievent0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;
	int r;

	REQUIRE(sock->type == isc_nm_tcpsocket);
	REQUIRE(worker->id == ievent->req->sock->mgr->workers[isc_nm_tid()].id);

	r = tcp_connect_direct(sock, req);
	if (r != 0) {
		/* We need to issue callbacks ourselves */
		tcp_connect_cb(&req->uv_req.connect, r);
	}
}

static void
tcp_connect_cb(uv_connect_t *uvreq, int status) {
	isc__nm_uvreq_t *req = (isc__nm_uvreq_t *) uvreq->data;
	isc_nmsocket_t *sock = uvreq->handle->data;

	REQUIRE(VALID_UVREQ(req));

	if (status == 0) {
		isc_result_t result;
		isc_nmhandle_t *handle = NULL;
		struct sockaddr_storage ss;

		uv_tcp_getpeername(&sock->uv_handle.tcp,
				   (struct sockaddr *) &ss,
				   &(int){sizeof(ss)});
		result = isc_sockaddr_fromsockaddr(&sock->peer,
						   (struct sockaddr *) &ss);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		handle = isc__nmhandle_get(sock, NULL, NULL);
		req->cb.connect(handle, ISC_R_SUCCESS, req->cbarg);
	} else {
		/*
		 * TODO:
		 * Handle the connect error properly and free the socket.
		 */
		req->cb.connect(NULL, isc__nm_uverr2result(status), req->cbarg);
	}

	isc__nm_uvreq_put(&req, sock);
}

isc_result_t
isc_nm_listentcp(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_cb_t cb, void *cbarg,
		 size_t extrahandlesize, isc_quota_t *quota,
		 isc_nmsocket_t **sockp)
{
	isc__netievent_tcplisten_t *ievent = NULL;
	isc_nmsocket_t *nsock = NULL;

	REQUIRE(VALID_NM(mgr));

	nsock = isc_mem_get(mgr->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, mgr, isc_nm_tcplistener);
	nsock->iface = iface;
	nsock->rcb.accept = cb;
	nsock->rcbarg = cbarg;
	nsock->extrahandlesize = extrahandlesize;
	if (quota != NULL) {
		/*
		 * We need to force it to make sure we get it attached.
		 * An example failure mode would be server under attack
		 * reconfiguring interfaces - that might cause weak attach
		 * to fail and leave this listening socket without limits.
		 * We can ignore the result.
		 */
		isc_quota_force(quota, &nsock->quota);
	}
	nsock->tid = isc_random_uniform(mgr->nworkers);

	/*
	 * Listening to TCP is rare enough not to care about the
	 * added overhead from passing this to another thread.
	 */
	ievent = isc__nm_get_ievent(mgr, netievent_tcplisten);
	ievent->sock = nsock;
	isc__nm_enqueue_ievent(&mgr->workers[nsock->tid],
			       (isc__netievent_t *) ievent);
	*sockp = nsock;

	return (ISC_R_SUCCESS);
}

void
isc__nm_async_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_tcplisten_t *ievent =
		(isc__netievent_tcplisten_t *) ievent0;
	isc_nmsocket_t *sock = ievent->sock;
	int r;

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(sock->type == isc_nm_tcplistener);

	r = uv_tcp_init(&worker->loop, &sock->uv_handle.tcp);
	if (r != 0) {
		return;
	}

	uv_tcp_bind(&sock->uv_handle.tcp, &sock->iface->addr.type.sa, 0);
	r = uv_listen((uv_stream_t *) &sock->uv_handle.tcp, 10,
		      tcp_connection_cb);
	if (r != 0) {
		return;
	}

	atomic_store(&sock->listening, true);

	return;
}

void
isc_nm_tcp_stoplistening(isc_nmsocket_t *sock) {
	isc__netievent_tcpstoplisten_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(!isc__nm_in_netthread());

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstoplisten);
	isc_nmsocket_attach(sock, &ievent->sock);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *) ievent);
}

static void
stoplistening_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = handle->data;

	LOCK(&sock->lock);
	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);
	SIGNAL(&sock->cond);
	UNLOCK(&sock->lock);

	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	isc_nmsocket_detach(&sock);
}

void
isc__nm_async_tcpstoplisten(isc__networker_t *worker,
			    isc__netievent_t *ievent0)
{
	isc__netievent_tcpstoplisten_t *ievent =
		(isc__netievent_tcpstoplisten_t *) ievent0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	REQUIRE(isc__nm_in_netthread());
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcplistener);

	uv_close(&sock->uv_handle.handle, stoplistening_cb);
}

static void
readtimeout_cb(uv_timer_t *handle) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *) handle->data;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	/*
	 * Socket is actively processing something, so restart the timer
	 * and return.
	 */
	if (atomic_load(&sock->processing)) {
		uv_timer_start(handle, readtimeout_cb, sock->read_timeout, 0);
		return;
	}

	/*
	 * Timeout; stop reading and process whatever we have.
	 */
	uv_read_stop(&sock->uv_handle.stream);
	if (sock->quota) {
		isc_quota_detach(&sock->quota);
	}
	sock->rcb.recv(sock->tcphandle, NULL, sock->rcbarg);
}

isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock = NULL;
	isc__netievent_startread_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	sock->rcb.recv = cb;
	sock->rcbarg = cbarg;

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstartread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_startread(&sock->mgr->workers[sock->tid],
					(isc__netievent_t *) ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *) ievent);
	}

	return (ISC_R_SUCCESS);
}

void
isc__nm_async_startread(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_startread_t *ievent =
		(isc__netievent_startread_t *) ievent0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(worker->id == isc_nm_tid());
	if (sock->read_timeout != 0) {
		if (!sock->timer_initialized) {
			uv_timer_init(&worker->loop, &sock->timer);
			sock->timer.data = sock;
			sock->timer_initialized = true;
		}
		uv_timer_start(&sock->timer, readtimeout_cb,
			       sock->read_timeout, 0);
	}

	uv_read_start(&sock->uv_handle.stream, isc__nm_alloc_cb, read_cb);
}

isc_result_t
isc_nm_pauseread(isc_nmsocket_t *sock) {
	isc__netievent_pauseread_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	if (atomic_load(&sock->readpaused)) {
		return (ISC_R_SUCCESS);
	}

	atomic_store(&sock->readpaused, true);
	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcppauseread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_pauseread(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *) ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *) ievent);
	}

	return (ISC_R_SUCCESS);
}

void
isc__nm_async_pauseread(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_pauseread_t *ievent =
		(isc__netievent_pauseread_t *) ievent0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(worker->id == isc_nm_tid());

	if (sock->timer_initialized) {
		uv_timer_stop(&sock->timer);
	}
	uv_read_stop(&sock->uv_handle.stream);
}

isc_result_t
isc_nm_resumeread(isc_nmsocket_t *sock) {
	isc__netievent_startread_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->rcb.recv != NULL);

	if (!atomic_load(&sock->readpaused)) {
		return (ISC_R_SUCCESS);
	}

	atomic_store(&sock->readpaused, false);

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstartread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_startread(&sock->mgr->workers[sock->tid],
					(isc__netievent_t *) ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *) ievent);
	}

	return (ISC_R_SUCCESS);
}

static void
read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	isc_nmsocket_t *sock = stream->data;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(buf != NULL);

	if (nread >= 0) {
		isc_region_t region = {
			.base = (unsigned char *) buf->base,
			.length = nread
		};

		INSIST(sock->rcb.recv != NULL);
		sock->rcb.recv(sock->tcphandle, &region, sock->rcbarg);

		sock->read_timeout = (atomic_load(&sock->keepalive)
				      ? sock->mgr->keepalive
				      : sock->mgr->idle);

		if (sock->timer_initialized && sock->read_timeout != 0) {
			/* The timer will be updated */
			uv_timer_start(&sock->timer, readtimeout_cb,
				       sock->read_timeout, 0);
		}
		isc__nm_free_uvbuf(sock, buf);
		return;
	}

	isc__nm_free_uvbuf(sock, buf);
	if (sock->quota) {
		isc_quota_detach(&sock->quota);
	}
	sock->rcb.recv(sock->tcphandle, NULL, sock->rcbarg);

	/*
	 * We don't need to clean up now; the socket will be closed and
	 * resources and quota reclaimed when handle is freed in
	 * isc__nm_tcp_close().
	 */
}

static isc_result_t
accept_connection(isc_nmsocket_t *ssock) {
	isc_result_t result;
	isc_quota_t *quota = NULL;
	isc_nmsocket_t *csock = NULL;
	isc__networker_t *worker = NULL;
	isc_nmhandle_t *handle = NULL;
	struct sockaddr_storage ss;
	isc_sockaddr_t local;
	int r;

	REQUIRE(VALID_NMSOCK(ssock));
	REQUIRE(ssock->tid == isc_nm_tid());

	if (!atomic_load_relaxed(&ssock->active)) {
		/* We're closing, bail */
		return (ISC_R_CANCELED);
	}

	if (ssock->quota != NULL) {
		result = isc_quota_attach(ssock->quota, &quota);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	csock = isc_mem_get(ssock->mgr->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(csock, ssock->mgr, isc_nm_tcpsocket);
	csock->tid = isc_nm_tid();
	csock->extrahandlesize = ssock->extrahandlesize;
	csock->iface = ssock->iface;
	csock->quota = quota;
	quota = NULL;

	worker = &ssock->mgr->workers[isc_nm_tid()];
	uv_tcp_init(&worker->loop, &csock->uv_handle.tcp);

	r = uv_accept(&ssock->uv_handle.stream, &csock->uv_handle.stream);
	if (r != 0) {
		if (csock->quota != NULL) {
			isc_quota_detach(&csock->quota);
		}
		isc_mem_put(ssock->mgr->mctx, csock, sizeof(isc_nmsocket_t));

		return (isc__nm_uverr2result(r));
	}

	isc_nmsocket_attach(ssock, &csock->server);

	uv_tcp_getpeername(&csock->uv_handle.tcp, (struct sockaddr *) &ss,
			   &(int){sizeof(ss)});

	result = isc_sockaddr_fromsockaddr(&csock->peer,
					   (struct sockaddr *) &ss);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	uv_tcp_getsockname(&csock->uv_handle.tcp, (struct sockaddr *) &ss,
			   &(int){sizeof(ss)});
	result = isc_sockaddr_fromsockaddr(&local,
					   (struct sockaddr *) &ss);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	handle = isc__nmhandle_get(csock, NULL, &local);

	INSIST(ssock->rcb.accept != NULL);
	csock->read_timeout = ssock->mgr->init;
	ssock->rcb.accept(handle, ISC_R_SUCCESS, ssock->rcbarg);
	isc_nmsocket_detach(&csock);

	return (ISC_R_SUCCESS);
}

static void
tcp_connection_cb(uv_stream_t *server, int status) {
	isc_nmsocket_t *ssock = server->data;
	isc_result_t result;

	UNUSED(status);

	result = accept_connection(ssock);
	if (result != ISC_R_SUCCESS) {
		if (result == ISC_R_QUOTA || result == ISC_R_SOFTQUOTA) {
			ssock->overquota = true;
		}
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_NETMGR, ISC_LOG_ERROR,
			      "TCP connection failed: %s",
			      isc_result_totext(result));
	}
}

isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle, isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg)
{
	isc_nmsocket_t *sock = handle->sock;
	isc__netievent_tcpsend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;

	REQUIRE(sock->type == isc_nm_tcpsocket);

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	uvreq->uvbuf.base = (char *) region->base;
	uvreq->uvbuf.len = region->length;
	uvreq->handle = handle;
	isc_nmhandle_ref(uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (sock->tid == isc_nm_tid()) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (tcp_send_direct(sock, uvreq));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpsend);
		ievent->sock = sock;
		ievent->req = uvreq;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *) ievent);
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_UNEXPECTED);
}

static void
tcp_send_cb(uv_write_t *req, int status) {
	isc_result_t result = ISC_R_SUCCESS;
	isc__nm_uvreq_t *uvreq = (isc__nm_uvreq_t *) req->data;

	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	if (status < 0) {
		result = isc__nm_uverr2result(status);
	}

	uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
	isc_nmhandle_unref(uvreq->handle);
	isc__nm_uvreq_put(&uvreq, uvreq->handle->sock);
}

/*
 * Handle 'tcpsend' async event - send a packet on the socket
 */
void
isc__nm_async_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc_result_t result;
	isc__netievent_tcpsend_t *ievent = (isc__netievent_tcpsend_t *) ievent0;

	REQUIRE(worker->id == ievent->sock->tid);

	if (!atomic_load(&ievent->sock->active)) {
		return;
	}

	result = tcp_send_direct(ievent->sock, ievent->req);
	if (result != ISC_R_SUCCESS) {
		ievent->req->cb.send(ievent->req->handle,
				     result, ievent->req->cbarg);
		isc__nm_uvreq_put(&ievent->req, ievent->req->handle->sock);
	}
}

static isc_result_t
tcp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	int r;

	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	isc_nmhandle_ref(req->handle);
	r = uv_write(&req->uv_req.write, &sock->uv_handle.stream,
		     &req->uvbuf, 1, tcp_send_cb);
	if (r < 0) {
		req->cb.send(NULL, isc__nm_uverr2result(r), req->cbarg);
		isc__nm_uvreq_put(&req, sock);
		return (isc__nm_uverr2result(r));
	}

	return (ISC_R_SUCCESS);
}

static void
tcp_close_cb(uv_handle_t *uvhandle) {
	isc_nmsocket_t *sock = uvhandle->data;

	REQUIRE(VALID_NMSOCK(sock));

	atomic_store(&sock->closed, true);
	isc__nmsocket_prep_destroy(sock);
}

static void
timer_close_cb(uv_handle_t *uvhandle) {
	isc_nmsocket_t *sock = uvhandle->data;

	REQUIRE(VALID_NMSOCK(sock));

	isc_nmsocket_detach(&sock->server);
	uv_close(&sock->uv_handle.handle, tcp_close_cb);
}

static void
tcp_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_tcpsocket);

	if (sock->quota != NULL) {
		isc_nmsocket_t *ssock = sock->server;

		isc_quota_detach(&sock->quota);

		if (ssock->overquota) {
			isc_result_t result = accept_connection(ssock);
			if (result != ISC_R_QUOTA && result != ISC_R_SOFTQUOTA)
			{
				ssock->overquota = false;
			}
		}
	}
	if (sock->timer_initialized) {
		uv_close((uv_handle_t *)&sock->timer, timer_close_cb);
		sock->timer_initialized = false;
	} else {
		isc_nmsocket_detach(&sock->server);
		uv_close(&sock->uv_handle.handle, tcp_close_cb);
	}
}

void
isc__nm_tcp_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpsocket);

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
				       (isc__netievent_t *) ievent);
	}
}

void
isc__nm_async_tcpclose(isc__networker_t *worker, isc__netievent_t *ievent0) {
	isc__netievent_tcpclose_t *ievent =
		(isc__netievent_tcpclose_t *) ievent0;

	REQUIRE(worker->id == ievent->sock->tid);

	tcp_close_direct(ievent->sock);
}
