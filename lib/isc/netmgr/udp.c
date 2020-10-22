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

#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"
#include "uv-compat.h"

static isc_result_t
udp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
		isc_sockaddr_t *peer);

static void
udp_recv_cb(uv_udp_t *handle, ssize_t nrecv, const uv_buf_t *buf,
	    const struct sockaddr *addr, unsigned flags);

static void
udp_send_cb(uv_udp_send_t *req, int status);

isc_result_t
isc_nm_listenudp(isc_nm_t *mgr, isc_nmiface_t *iface, isc_nm_recv_cb_t cb,
		 void *cbarg, size_t extrahandlesize, isc_nmsocket_t **sockp) {
	isc_nmsocket_t *nsock = NULL;

	REQUIRE(VALID_NM(mgr));

	/*
	 * We are creating mgr->nworkers duplicated sockets, one
	 * socket for each worker thread.
	 */
	nsock = isc_mem_get(mgr->mctx, sizeof(isc_nmsocket_t));
	isc__nmsocket_init(nsock, mgr, isc_nm_udplistener, iface);
	nsock->nchildren = mgr->nworkers;
	atomic_init(&nsock->rchildren, mgr->nworkers);
	nsock->children = isc_mem_get(mgr->mctx,
				      mgr->nworkers * sizeof(*nsock));
	memset(nsock->children, 0, mgr->nworkers * sizeof(*nsock));

	INSIST(nsock->recv_cb == NULL && nsock->recv_cbarg == NULL);
	nsock->recv_cb = cb;
	nsock->recv_cbarg = cbarg;
	nsock->extrahandlesize = extrahandlesize;

	for (size_t i = 0; i < mgr->nworkers; i++) {
		isc_result_t result;
		uint16_t family = iface->addr.type.sa.sa_family;

		isc__netievent_udplisten_t *ievent = NULL;
		isc_nmsocket_t *csock = &nsock->children[i];

		isc__nmsocket_init(csock, mgr, isc_nm_udpsocket, iface);
		csock->parent = nsock;
		csock->tid = i;
		csock->extrahandlesize = extrahandlesize;

		INSIST(csock->recv_cb == NULL && csock->recv_cbarg == NULL);
		csock->recv_cb = cb;
		csock->recv_cbarg = cbarg;
		csock->fd = socket(family, SOCK_DGRAM, 0);
		RUNTIME_CHECK(csock->fd >= 0);

		result = isc__nm_socket_reuse(csock->fd);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_NOTIMPLEMENTED);

		result = isc__nm_socket_reuse_lb(csock->fd);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_NOTIMPLEMENTED);

		/* We don't check for the result, because SO_INCOMING_CPU can be
		 * available without the setter on Linux kernel version 4.4, and
		 * setting SO_INCOMING_CPU is just an optimization.
		 */
		(void)isc__nm_socket_incoming_cpu(csock->fd);

		ievent = isc__nm_get_ievent(mgr, netievent_udplisten);
		ievent->sock = csock;
		isc__nm_enqueue_ievent(&mgr->workers[i],
				       (isc__netievent_t *)ievent);
	}

	*sockp = nsock;
	return (ISC_R_SUCCESS);
}

/*%<
 * Allocator for UDP recv operations. Limited to size 20 * (2^16 + 2),
 * which allows enough space for recvmmsg() to get multiple messages at
 * a time.
 *
 * Note this doesn't actually allocate anything, it just assigns the
 * worker's receive buffer to a socket, and marks it as "in use".
 */
static void
udp_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_udpsocket);
	REQUIRE(isc__nm_in_netthread());
	REQUIRE(size <= ISC_NETMGR_RECVBUF_SIZE);

	worker = &sock->mgr->workers[sock->tid];
	INSIST(!worker->recvbuf_inuse);

	buf->base = worker->recvbuf;
	buf->len = ISC_NETMGR_RECVBUF_SIZE;
	worker->recvbuf_inuse = true;
}

/*
 * Asynchronous 'udplisten' call handler: start listening on a UDP socket.
 */
void
isc__nm_async_udplisten(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_udplisten_t *ievent = (isc__netievent_udplisten_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	int r, uv_bind_flags = 0;
	int uv_init_flags = 0;
	sa_family_t sa_family;

	REQUIRE(sock->type == isc_nm_udpsocket);
	REQUIRE(sock->iface != NULL);
	REQUIRE(sock->parent != NULL);
	REQUIRE(sock->tid == isc_nm_tid());

#ifdef UV_UDP_RECVMMSG
	uv_init_flags |= UV_UDP_RECVMMSG;
#endif
	uv_udp_init_ex(&worker->loop, &sock->uv_handle.udp, uv_init_flags);
	uv_handle_set_data(&sock->uv_handle.handle, NULL);
	isc__nmsocket_attach(sock,
			     (isc_nmsocket_t **)&sock->uv_handle.udp.data);

	r = uv_udp_open(&sock->uv_handle.udp, sock->fd);
	if (r == 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_OPEN]);
	} else {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_OPENFAIL]);
	}

	sa_family = sock->iface->addr.type.sa.sa_family;
	if (sa_family == AF_INET6) {
		uv_bind_flags |= UV_UDP_IPV6ONLY;
	}

	r = uv_udp_bind(&sock->uv_handle.udp,
			&sock->parent->iface->addr.type.sa, uv_bind_flags);
	if (r == UV_EADDRNOTAVAIL &&
	    isc__nm_socket_freebind(sock->fd, sa_family) == ISC_R_SUCCESS)
	{
		/*
		 * Retry binding with IP_FREEBIND (or equivalent option) if the
		 * address is not available. This helps with IPv6 tentative
		 * addresses which are reported by the route socket, although
		 * named is not yet able to properly bind to them.
		 */
		r = uv_udp_bind(&sock->uv_handle.udp,
				&sock->parent->iface->addr.type.sa,
				uv_bind_flags);
	}

	if (r < 0) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_BINDFAIL]);
	}
#ifdef ISC_RECV_BUFFER_SIZE
	uv_recv_buffer_size(&sock->uv_handle.handle,
			    &(int){ ISC_RECV_BUFFER_SIZE });
#endif
#ifdef ISC_SEND_BUFFER_SIZE
	uv_send_buffer_size(&sock->uv_handle.handle,
			    &(int){ ISC_SEND_BUFFER_SIZE });
#endif
	uv_udp_recv_start(&sock->uv_handle.udp, udp_alloc_cb, udp_recv_cb);
}

static void
udp_stop_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	atomic_store(&sock->closed, true);

	isc__nmsocket_detach((isc_nmsocket_t **)&sock->uv_handle.udp.data);
}

static void
stop_udp_child(isc_nmsocket_t *sock) {
	REQUIRE(sock->type == isc_nm_udpsocket);
	REQUIRE(sock->tid == isc_nm_tid());

	uv_udp_recv_stop(&sock->uv_handle.udp);
	uv_close((uv_handle_t *)&sock->uv_handle.udp, udp_stop_cb);

	isc__nm_incstats(sock->mgr, sock->statsindex[STATID_CLOSE]);

	LOCK(&sock->parent->lock);
	atomic_fetch_sub(&sock->parent->rchildren, 1);
	UNLOCK(&sock->parent->lock);
	BROADCAST(&sock->parent->cond);
}

static void
stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(sock->type == isc_nm_udplistener);

	for (int i = 0; i < sock->nchildren; i++) {
		isc__netievent_udpstop_t *event = NULL;

		if (isc_nm_tid() == sock->children[i].tid) {
			stop_udp_child(&sock->children[i]);
			continue;
		}

		event = isc__nm_get_ievent(sock->mgr, netievent_udpstop);
		event->sock = &sock->children[i];
		isc__nm_enqueue_ievent(&sock->mgr->workers[i],
				       (isc__netievent_t *)event);
	}

	LOCK(&sock->lock);
	while (atomic_load_relaxed(&sock->rchildren) > 0) {
		WAIT(&sock->cond, &sock->lock);
	}
	atomic_store(&sock->closed, true);
	UNLOCK(&sock->lock);

	isc__nmsocket_prep_destroy(sock);
}

void
isc__nm_udp_stoplistening(isc_nmsocket_t *sock) {
	isc__netievent_udpstop_t *ievent = NULL;

	/* We can't be launched from network thread, we'd deadlock */
	REQUIRE(!isc__nm_in_netthread());
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_udplistener);

	/*
	 * If the socket is active, mark it inactive and
	 * continue. If it isn't active, stop now.
	 */
	if (!isc__nmsocket_deactivate(sock)) {
		return;
	}

	/*
	 * If the manager is interlocked, re-enqueue this as an asynchronous
	 * event. Otherwise, go ahead and stop listening right away.
	 */
	if (!isc__nm_acquire_interlocked(sock->mgr)) {
		ievent = isc__nm_get_ievent(sock->mgr, netievent_udpstop);
		ievent->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	} else {
		stoplistening(sock);
		isc__nm_drop_interlocked(sock->mgr);
	}
}

/*
 * Asynchronous 'udpstop' call handler: stop listening on a UDP socket.
 */
void
isc__nm_async_udpstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_udpstop_t *ievent = (isc__netievent_udpstop_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(sock->iface != NULL);
	UNUSED(worker);

	/*
	 * If this is a child socket, stop listening and return.
	 */
	if (sock->parent != NULL) {
		stop_udp_child(sock);
		return;
	}

	/*
	 * If network manager is paused, re-enqueue the event for later.
	 */
	if (!isc__nm_acquire_interlocked(sock->mgr)) {
		isc__netievent_udplisten_t *event = NULL;

		event = isc__nm_get_ievent(sock->mgr, netievent_udpstop);
		event->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)event);
	} else {
		stoplistening(sock);
		isc__nm_drop_interlocked(sock->mgr);
	}
}

/*
 * udp_recv_cb handles incoming UDP packet from uv.  The buffer here is
 * reused for a series of packets, so we need to allocate a new one. This
 * new one can be reused to send the response then.
 */
static void
udp_recv_cb(uv_udp_t *handle, ssize_t nrecv, const uv_buf_t *buf,
	    const struct sockaddr *addr, unsigned flags) {
	isc_result_t result;
	isc_nmhandle_t *nmhandle = NULL;
	isc_sockaddr_t sockaddr;
	isc_nmsocket_t *sock = NULL;
	isc_region_t region;
	uint32_t maxudp;
	bool free_buf = true;
	isc_nm_recv_cb_t cb;
	void *cbarg;

	/*
	 * Even though destruction of the socket can only happen from the
	 * network thread that we're in, we still attach to the socket here
	 * to ensure it won't be destroyed by the recv callback.
	 */
	isc__nmsocket_attach(uv_handle_get_data((uv_handle_t *)handle), &sock);

#ifdef UV_UDP_MMSG_CHUNK
	free_buf = ((flags & UV_UDP_MMSG_CHUNK) == 0);
#else
	UNUSED(flags);
#endif

	/*
	 * Three possible reasons to return now without processing:
	 * - If addr == NULL, in which case it's the end of stream;
	 *   we can free the buffer and bail.
	 * - If we're simulating a firewall blocking UDP packets
	 *   bigger than 'maxudp' bytes for testing purposes.
	 * - If the socket is no longer active.
	 */
	maxudp = atomic_load(&sock->mgr->maxudp);
	if ((addr == NULL) || (maxudp != 0 && (uint32_t)nrecv > maxudp) ||
	    (!isc__nmsocket_active(sock)))
	{
		if (free_buf) {
			isc__nm_free_uvbuf(sock, buf);
		}
		isc__nmsocket_detach(&sock);
		return;
	}

	result = isc_sockaddr_fromsockaddr(&sockaddr, addr);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	nmhandle = isc__nmhandle_get(sock, &sockaddr, NULL);
	region.base = (unsigned char *)buf->base;
	region.length = nrecv;

	INSIST(sock->tid == isc_nm_tid());
	INSIST(sock->recv_cb != NULL);
	cb = sock->recv_cb;
	cbarg = sock->recv_cbarg;

	cb(nmhandle, ISC_R_SUCCESS, &region, cbarg);

	if (free_buf) {
		isc__nm_free_uvbuf(sock, buf);
	}

	/*
	 * The sock is now attached to the handle, we can detach our ref.
	 */
	isc__nmsocket_detach(&sock);

	/*
	 * If the recv callback wants to hold on to the handle,
	 * it needs to attach to it.
	 */
	isc_nmhandle_detach(&nmhandle);
}

/*
 * Send the data in 'region' to a peer via a UDP socket. We try to find
 * a proper sibling/child socket so that we won't have to jump to another
 * thread.
 */
void
isc__nm_udp_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
		 void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc_nmsocket_t *psock = NULL, *rsock = sock;
	isc_sockaddr_t *peer = &handle->peer;
	isc__netievent_udpsend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;
	uint32_t maxudp = atomic_load(&sock->mgr->maxudp);
	int ntid;

	if (!isc__nmsocket_active(sock)) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	/*
	 * We're simulating a firewall blocking UDP packets bigger than
	 * 'maxudp' bytes, for testing purposes.
	 *
	 * The client would ordinarily have unreferenced the handle
	 * in the callback, but that won't happen in this case, so
	 * we need to do so here.
	 */
	if (maxudp != 0 && region->length > maxudp) {
		isc_nmhandle_detach(&handle);
		return;
	}

	if (sock->type == isc_nm_udpsocket && !atomic_load(&sock->client)) {
		INSIST(sock->parent != NULL);
		psock = sock->parent;
	} else if (sock->type == isc_nm_udplistener) {
		psock = sock;
	} else if (!atomic_load(&sock->client)) {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	/*
	 * If we're in the network thread, we can send directly.  If the
	 * handle is associated with a UDP socket, we can reuse its thread
	 * (assuming CPU affinity). Otherwise, pick a thread at random.
	 */
	if (isc__nm_in_netthread()) {
		ntid = isc_nm_tid();
	} else if (sock->type == isc_nm_udpsocket &&
		   !atomic_load(&sock->client)) {
		ntid = sock->tid;
	} else {
		ntid = (int)isc_random_uniform(sock->nchildren);
	}

	if (psock != NULL) {
		rsock = &psock->children[ntid];
	}

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	isc_nmhandle_attach(handle, &uvreq->handle);

	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (isc_nm_tid() == rsock->tid) {
		/*
		 * If we're in the same thread as the socket we can send
		 * the data directly, but we still need to return errors
		 * via the callback for API consistency.
		 */
		isc_result_t result = udp_send_direct(rsock, uvreq, peer);
		if (result != ISC_R_SUCCESS) {
			isc__nm_incstats(rsock->mgr,
					 rsock->statsindex[STATID_SENDFAIL]);
			uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
			isc__nm_uvreq_put(&uvreq, sock);
		}
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(sock->mgr, netievent_udpsend);
		ievent->sock = rsock;
		ievent->peer = *peer;
		ievent->req = uvreq;

		isc__nm_enqueue_ievent(&sock->mgr->workers[rsock->tid],
				       (isc__netievent_t *)ievent);
	}
}

/*
 * Asynchronous 'udpsend' event handler: send a packet on a UDP socket.
 */
void
isc__nm_async_udpsend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc_result_t result;
	isc__netievent_udpsend_t *ievent = (isc__netievent_udpsend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *uvreq = ievent->req;

	REQUIRE(sock->type == isc_nm_udpsocket);
	REQUIRE(worker->id == sock->tid);

	result = udp_send_direct(sock, uvreq, &ievent->peer);
	if (result != ISC_R_SUCCESS) {
		isc__nm_incstats(sock->mgr, sock->statsindex[STATID_SENDFAIL]);
		uvreq->cb.send(uvreq->handle, result, uvreq->cbarg);
		isc__nm_uvreq_put(&uvreq, sock);
	}
}

static void
udp_send_cb(uv_udp_send_t *req, int status) {
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
	isc__nm_uvreq_put(&uvreq, uvreq->sock);
}

/*
 * udp_send_direct sends buf to a peer on a socket. Sock has to be in
 * the same thread as the callee.
 */
static isc_result_t
udp_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
		isc_sockaddr_t *peer) {
	const struct sockaddr *sa = NULL;
	int r;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_udpsocket);

	if (!isc__nmsocket_active(sock)) {
		return (ISC_R_CANCELED);
	}

	sa = atomic_load(&sock->connected) ? NULL : &peer->type.sa;
	r = uv_udp_send(&req->uv_req.udp_send, &sock->uv_handle.udp,
			&req->uvbuf, 1, sa, udp_send_cb);
	if (r < 0) {
		return (isc__nm_uverr2result(r));
	}

	return (ISC_R_SUCCESS);
}
