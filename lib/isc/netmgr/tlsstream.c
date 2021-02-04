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

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/once.h>
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

#define TLS_BUF_SIZE 65536

static isc_result_t
tls_error_to_result(int tls_err) {
	switch (tls_err) {
	case SSL_ERROR_ZERO_RETURN:
		return (ISC_R_EOF);
	case SSL_ERROR_SSL:
		return (ISC_R_TLSERROR);
	default:
		return (ISC_R_UNEXPECTED);
	}
}

static void
tls_do_bio(isc_nmsocket_t *sock, isc__nm_uvreq_t *send_data, bool finish);

static void
tls_close_direct(isc_nmsocket_t *sock);

static void
async_tls_do_bio(isc_nmsocket_t *sock);

/*
 * The socket is closing, outerhandle has been detached, listener is
 * inactive, or the netmgr is closing: any operation on it should abort
 * with ISC_R_CANCELED.
 */
static bool
inactive(isc_nmsocket_t *sock) {
	return (!isc__nmsocket_active(sock) || atomic_load(&sock->closing) ||
		sock->outerhandle == NULL ||
		!isc__nmsocket_active(sock->outerhandle->sock) ||
		atomic_load(&sock->outerhandle->sock->closing) ||
		(sock->listener != NULL &&
		 !isc__nmsocket_active(sock->listener)) ||
		atomic_load(&sock->mgr->closing));
}

static void
update_result(isc_nmsocket_t *sock, const isc_result_t result) {
	if (!sock->tlsstream.server) {
		LOCK(&sock->lock);
		sock->result = result;
		SIGNAL(&sock->cond);
		while (!atomic_load(&sock->active)) {
			WAIT(&sock->scond, &sock->lock);
		}
		UNLOCK(&sock->lock);
	} else {
		LOCK(&sock->lock);
		sock->result = result;
		UNLOCK(&sock->lock);
	}
}

static void
tls_call_connect_cb(isc_nmsocket_t *sock, isc_nmhandle_t *handle,
		    const isc_result_t result) {
	if (sock->connect_cb == NULL) {
		return;
	}
	sock->connect_cb(handle, result, sock->connect_cbarg);
	update_result(sock, result);
	if (result != ISC_R_SUCCESS) {
		isc__nmsocket_clearcb(handle->sock);
	}
}

static void
tls_senddone(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmsocket_tls_send_req_t *send_req =
		(isc_nmsocket_tls_send_req_t *)cbarg;
	isc_nmsocket_t *tlssock = NULL;
	bool finish = send_req->finish;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(VALID_NMSOCK(send_req->tlssock));

	tlssock = send_req->tlssock;
	send_req->tlssock = NULL;

	if (send_req->cb != NULL) {
		send_req->cb(send_req->handle, eresult, send_req->cbarg);
		isc_nmhandle_detach(&send_req->handle);
	}

	isc_mem_put(handle->sock->mgr->mctx, send_req->data.base,
		    send_req->data.length);
	isc_mem_put(handle->sock->mgr->mctx, send_req, sizeof(*send_req));
	tlssock->tlsstream.nsending--;

	if (finish && eresult == ISC_R_SUCCESS) {
		isc_nm_cancelread(handle);
	} else if (eresult == ISC_R_SUCCESS) {
		tls_do_bio(tlssock, NULL, false);
	}

	isc__nmsocket_detach(&tlssock);
}

static void
tls_failed_read_cb(isc_nmsocket_t *sock, isc_nmhandle_t *handle,
		   const isc_result_t result) {
	REQUIRE(VALID_NMSOCK(sock));

	if (!sock->tlsstream.server &&
	    (sock->tlsstream.state == TLS_INIT ||
	     sock->tlsstream.state == TLS_HANDSHAKE) &&
	    sock->connect_cb != NULL)
	{
		INSIST(handle == NULL);
		handle = isc__nmhandle_get(sock, NULL, NULL);
		tls_call_connect_cb(sock, handle, result);
		isc_nmhandle_detach(&handle);
	} else if (sock->recv_cb != NULL) {
		isc__nm_uvreq_t *req = NULL;
		req = isc__nm_uvreq_get(sock->mgr, sock);
		req->cb.recv = sock->recv_cb;
		req->cbarg = sock->recv_cbarg;
		req->handle = NULL;
		if (handle != NULL) {
			REQUIRE(VALID_NMHANDLE(handle));
			isc_nmhandle_attach(handle, &req->handle);
		} else {
			req->handle = isc__nmhandle_get(sock, NULL, NULL);
		}
		isc__nmsocket_clearcb(sock);
		isc__nm_readcb(sock, req, result);
	}

	isc__nmsocket_prep_destroy(sock);
	isc__nmsocket_detach(&sock);
}

static void
async_tls_do_bio(isc_nmsocket_t *sock) {
	isc__netievent_tlsdobio_t *ievent =
		isc__nm_get_netievent_tlsdobio(sock->mgr, sock);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

static int
tls_send_outgoing(isc_nmsocket_t *sock, bool finish, isc_nmhandle_t *tlshandle,
		  isc_nm_cb_t cb, void *cbarg) {
	isc_nmsocket_tls_send_req_t *send_req = NULL;
	int pending;
	int rv;

	if (inactive(sock)) {
		if (cb != NULL) {
			INSIST(VALID_NMHANDLE(tlshandle));
			cb(tlshandle, ISC_R_CANCELED, cbarg);
		}
		return (0);
	}

	if (finish && (SSL_get_shutdown(sock->tlsstream.tls) &
		       SSL_SENT_SHUTDOWN) != SSL_SENT_SHUTDOWN)
	{
		(void)SSL_shutdown(sock->tlsstream.tls);
	}

	pending = BIO_pending(sock->tlsstream.app_bio);
	if (pending <= 0) {
		return (pending);
	}

	/* TODO Should we keep track of these requests in a list? */
	if (pending > TLS_BUF_SIZE) {
		pending = TLS_BUF_SIZE;
	}

	send_req = isc_mem_get(sock->mgr->mctx, sizeof(*send_req));
	*send_req = (isc_nmsocket_tls_send_req_t){
		.finish = finish,
		.data.base = isc_mem_get(sock->mgr->mctx, pending),
		.data.length = pending
	};

	isc__nmsocket_attach(sock, &send_req->tlssock);
	if (cb != NULL) {
		send_req->cb = cb;
		send_req->cbarg = cbarg;
		isc_nmhandle_attach(tlshandle, &send_req->handle);
	}

	rv = BIO_read(sock->tlsstream.app_bio, send_req->data.base, pending);
	/* There's something pending, read must succeed */
	RUNTIME_CHECK(rv == pending);

	INSIST(VALID_NMHANDLE(sock->outerhandle));

	sock->tlsstream.nsending++;
	isc_nm_send(sock->outerhandle, &send_req->data, tls_senddone, send_req);

	return (pending);
}

static void
tls_do_bio(isc_nmsocket_t *sock, isc__nm_uvreq_t *send_data, bool finish) {
	isc_result_t result = ISC_R_SUCCESS;
	int pending, tls_err = 0;
	int rv;
	char buf[1];
	bool sent_shutdown, received_shutdown;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	/* We will resume read if TLS layer wants us to */
	if (sock->outerhandle != NULL) {
		REQUIRE(VALID_NMHANDLE(sock->outerhandle));
		isc_nm_pauseread(sock->outerhandle);
	}

	if (sock->tlsstream.state == TLS_INIT) {
		(void)SSL_do_handshake(sock->tlsstream.tls);
		sock->tlsstream.state = TLS_HANDSHAKE;
	} else if (sock->tlsstream.state == TLS_CLOSED) {
		return;
	}

	received_shutdown = (SSL_get_shutdown(sock->tlsstream.tls) &
			     SSL_RECEIVED_SHUTDOWN) == SSL_RECEIVED_SHUTDOWN;

	/* Data from TLS to client */
	if (sock->tlsstream.state >= TLS_IO && sock->recv_cb != NULL &&
	    !atomic_load(&sock->readpaused))
	{
		(void)SSL_peek(sock->tlsstream.tls, buf, 1);
		while ((pending = SSL_pending(sock->tlsstream.tls)) > 0) {
			uint8_t recv_buf[TLS_BUF_SIZE];
			isc_region_t region, dregion;

			if (pending > TLS_BUF_SIZE) {
				pending = TLS_BUF_SIZE;
			}
			region = (isc_region_t){ .base = &recv_buf[0],
						 .length = pending };

			rv = SSL_read(sock->tlsstream.tls, region.base,
				      region.length);
			/* Pending succeded, so should read */
			RUNTIME_CHECK(rv == pending);

			dregion = (isc_region_t){ region.base, rv };
			sock->recv_cb(sock->statichandle, ISC_R_SUCCESS,
				      &dregion, sock->recv_cbarg);
		}
	}

	if (send_data != NULL) {
		INSIST(sock->tlsstream.state > TLS_HANDSHAKE);
		rv = SSL_write(sock->tlsstream.tls, send_data->uvbuf.base,
			       send_data->uvbuf.len);
		if (rv != (int)send_data->uvbuf.len) {
			result = received_shutdown ? ISC_R_CANCELED
						   : ISC_R_TLSERROR;
			send_data->cb.send(send_data->handle, result,
					   send_data->cbarg);
			send_data = NULL;
			if (!received_shutdown) {
				isc__nmsocket_detach(&sock);
				return;
			}
		}
	}

	sent_shutdown = (SSL_get_shutdown(sock->tlsstream.tls) &
			 SSL_SENT_SHUTDOWN) == SSL_SENT_SHUTDOWN;

	/* Peek to move the session forward */
	(void)SSL_peek(sock->tlsstream.tls, buf, 1);

	/* Data from TLS to network */
	if (send_data != NULL) {
		pending = tls_send_outgoing(sock, finish, send_data->handle,
					    send_data->cb.send,
					    send_data->cbarg);
	} else {
		if (received_shutdown && !sent_shutdown) {
			finish = true;
			(void)SSL_shutdown(sock->tlsstream.tls);
		}
		pending = tls_send_outgoing(sock, finish, NULL, NULL, NULL);
	}

	if (pending > 0) {
		/* We'll continue in tls_senddone */
		return;
	}

	/* Get the potential error code */
	rv = SSL_peek(sock->tlsstream.tls, buf, 1);
	if (rv < 0) {
		tls_err = SSL_get_error(sock->tlsstream.tls, rv);
	}

	/* Only after doing the IO we can check if SSL handshake is done */
	if (sock->tlsstream.state == TLS_HANDSHAKE &&
	    SSL_is_init_finished(sock->tlsstream.tls) == 1)
	{
		isc_nmhandle_t *tlshandle = isc__nmhandle_get(sock, NULL, NULL);
		if (sock->tlsstream.server) {
			sock->listener->accept_cb(sock->statichandle,
						  ISC_R_SUCCESS,
						  sock->listener->accept_cbarg);
		} else {
			tls_call_connect_cb(sock, tlshandle, ISC_R_SUCCESS);
		}
		isc_nmhandle_detach(&tlshandle);
		sock->tlsstream.state = TLS_IO;
		async_tls_do_bio(sock);
		return;
	}

	switch (tls_err) {
	case SSL_ERROR_NONE:
		if (sent_shutdown && received_shutdown) {
			/* clean shutdown */
			isc_nm_cancelread(sock->outerhandle);
			isc__nm_tls_close(sock);
		};
		return;
		break;
	case SSL_ERROR_WANT_WRITE:
		if (sock->tlsstream.nsending == 0) {
			/*
			 * Launch tls_do_bio asynchronously. If we're sending
			 * already the send callback will call it.
			 */
			async_tls_do_bio(sock);
			return;
		} else {
			return;
		}
		break;
	case SSL_ERROR_WANT_READ:
		if (sock->outerhandle != NULL) {
			INSIST(VALID_NMHANDLE(sock->outerhandle));
			isc_nm_resumeread(sock->outerhandle);
		}
		return;
		break;
	default:
		result = tls_error_to_result(tls_err);
		goto error;
	}

	return;

error:
	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
		      ISC_LOG_ERROR, "SSL error in BIO: %d %s", tls_err,
		      isc_result_totext(result));
	tls_failed_read_cb(sock, sock->statichandle, result);
}

static void
tls_readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	   void *cbarg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)cbarg;
	int rv;

	REQUIRE(VALID_NMSOCK(tlssock));
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(tlssock->tid == isc_nm_tid());
	if (result != ISC_R_SUCCESS) {
		tls_failed_read_cb(tlssock, tlssock->statichandle, result);
		return;
	}
	rv = BIO_write(tlssock->tlsstream.app_bio, region->base,
		       region->length);
	if (rv != (int)region->length) {
		/* XXXWPK log it? */
		tls_failed_read_cb(tlssock, tlssock->statichandle,
				   ISC_R_TLSERROR);
		return;
	}
	tls_do_bio(tlssock, NULL, false);
}

static isc_result_t
initialize_tls(isc_nmsocket_t *sock, bool server) {
	REQUIRE(sock->tid == isc_nm_tid());

	if (BIO_new_bio_pair(&(sock->tlsstream.ssl_bio), TLS_BUF_SIZE,
			     &(sock->tlsstream.app_bio), TLS_BUF_SIZE) != 1)
	{
		isc_tls_free(&sock->tlsstream.tls);
		return (ISC_R_TLSERROR);
	}

	SSL_set_bio(sock->tlsstream.tls, sock->tlsstream.ssl_bio,
		    sock->tlsstream.ssl_bio);
	if (server) {
		SSL_set_accept_state(sock->tlsstream.tls);
	} else {
		SSL_set_connect_state(sock->tlsstream.tls);
	}
	sock->tlsstream.nsending = 0;
	isc_nm_read(sock->outerhandle, tls_readcb, sock);
	tls_do_bio(sock, NULL, false);
	return (ISC_R_SUCCESS);
}

static isc_result_t
tlslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlslistensock = (isc_nmsocket_t *)cbarg;
	isc_nmsocket_t *tlssock = NULL;

	/* If accept() was unsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(VALID_NMSOCK(tlslistensock));
	REQUIRE(tlslistensock->type == isc_nm_tlslistener);

	/*
	 * We need to create a 'wrapper' tlssocket for this connection.
	 */
	tlssock = isc_mem_get(handle->sock->mgr->mctx, sizeof(*tlssock));
	isc__nmsocket_init(tlssock, handle->sock->mgr, isc_nm_tlssocket,
			   &tlslistensock->tlsstream.server_iface);

	/* We need to initialize SSL now to reference SSL_CTX properly */
	tlssock->tlsstream.ctx = tlslistensock->tlsstream.ctx;
	tlssock->tlsstream.tls = isc_tls_create(tlssock->tlsstream.ctx);
	if (tlssock->tlsstream.tls == NULL) {
		atomic_store(&tlssock->closed, true);
		isc__nmsocket_detach(&tlssock);
		return (ISC_R_TLSERROR);
	}

	tlssock->extrahandlesize = tlslistensock->extrahandlesize;
	isc__nmsocket_attach(tlslistensock, &tlssock->listener);
	isc_nmhandle_attach(handle, &tlssock->outerhandle);
	tlssock->peer = handle->sock->peer;
	tlssock->read_timeout = atomic_load(&handle->sock->mgr->init);
	tlssock->tid = isc_nm_tid();
	tlssock->tlsstream.server = true;
	tlssock->tlsstream.state = TLS_INIT;

	tlssock->tlsstream.ctx = tlslistensock->tlsstream.ctx;

	result = initialize_tls(tlssock, true);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	/* TODO: catch failure code, detach tlssock, and log the error */

	return (result);
}

isc_result_t
isc_nm_listentls(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		 size_t extrahandlesize, int backlog, isc_quota_t *quota,
		 SSL_CTX *sslctx, isc_nmsocket_t **sockp) {
	isc_result_t result;
	isc_nmsocket_t *tlssock = isc_mem_get(mgr->mctx, sizeof(*tlssock));
	isc_nmsocket_t *tsock = NULL;

	REQUIRE(VALID_NM(mgr));

	isc__nmsocket_init(tlssock, mgr, isc_nm_tlslistener, iface);
	tlssock->tlsstream.server_iface = *iface;
	ISC_LINK_INIT(&tlssock->tlsstream.server_iface.addr, link);
	tlssock->iface = &tlssock->tlsstream.server_iface;
	tlssock->result = ISC_R_DEFAULT;
	tlssock->accept_cb = accept_cb;
	tlssock->accept_cbarg = accept_cbarg;
	tlssock->extrahandlesize = extrahandlesize;
	tlssock->tlsstream.ctx = sslctx;
	tlssock->tlsstream.tls = NULL;

	/*
	 * tlssock will be a TLS 'wrapper' around an unencrypted stream.
	 * We set tlssock->outer to a socket listening for a TCP connection.
	 */
	result = isc_nm_listentcp(mgr, iface, tlslisten_acceptcb, tlssock,
				  extrahandlesize, backlog, quota,
				  &tlssock->outer);
	if (result != ISC_R_SUCCESS) {
		atomic_store(&tlssock->closed, true);
		isc__nmsocket_detach(&tlssock);
		return (result);
	}

	/* wait for listen result */
	isc__nmsocket_attach(tlssock->outer, &tsock);
	LOCK(&tlssock->outer->lock);
	while (tlssock->outer->rchildren != tlssock->outer->nchildren) {
		WAIT(&tlssock->outer->cond, &tlssock->outer->lock);
	}
	result = tlssock->outer->result;
	tlssock->result = result;
	atomic_store(&tlssock->active, true);
	INSIST(tlssock->outer->tlsstream.tlslistener == NULL);
	isc__nmsocket_attach(tlssock, &tlssock->outer->tlsstream.tlslistener);
	BROADCAST(&tlssock->outer->scond);
	UNLOCK(&tlssock->outer->lock);
	isc__nmsocket_detach(&tsock);
	INSIST(result != ISC_R_DEFAULT);

	if (result == ISC_R_SUCCESS) {
		atomic_store(&tlssock->listening, true);
		*sockp = tlssock;
	}

	return (result);
}

void
isc__nm_async_tlssend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlssend_t *ievent = (isc__netievent_tlssend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;

	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_nm_tid());

	UNUSED(worker);

	ievent->req = NULL;

	if (inactive(sock)) {
		req->cb.send(req->handle, ISC_R_CANCELED, req->cbarg);
		isc__nm_uvreq_put(&req, sock);
		return;
	}

	tls_do_bio(sock, req, false);
	isc__nm_uvreq_put(&req, sock);
	return;
}

void
isc__nm_tls_send(isc_nmhandle_t *handle, const isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg) {
	isc__netievent_tlssend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	REQUIRE(sock->type == isc_nm_tlssocket);

	if (inactive(sock)) {
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	/*
	 * We need to create an event and pass it using async channel
	 */
	ievent = isc__nm_get_netievent_tlssend(sock->mgr, sock, uvreq);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_async_tlsstartread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsstartread_t *ievent =
		(isc__netievent_tlsstartread_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(sock->tid == isc_nm_tid());

	UNUSED(worker);

	tls_do_bio(sock, NULL, false);
}

void
isc__nm_tls_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc__netievent_tlsstartread_t *ievent = NULL;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	sock = handle->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->statichandle == handle);
	REQUIRE(sock->tid == isc_nm_tid());

	if (inactive(sock)) {
		cb(handle, ISC_R_NOTCONNECTED, NULL, cbarg);
		return;
	}

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;

	ievent = isc__nm_get_netievent_tlsstartread(sock->mgr, sock);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_tls_pauseread(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	atomic_store(&handle->sock->readpaused, true);
	if (handle->sock->outerhandle != NULL) {
		isc_nm_pauseread(handle->sock->outerhandle);
	}
}

void
isc__nm_tls_resumeread(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	atomic_store(&handle->sock->readpaused, false);
	async_tls_do_bio(handle->sock);
}

static void
tls_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());
	/*
	 * At this point we're certain that there are no
	 * external references, we can close everything.
	 */
	if (sock->outerhandle != NULL) {
		isc_nm_pauseread(sock->outerhandle);
		isc_nmhandle_detach(&sock->outerhandle);
	}

	if (sock->listener != NULL) {
		isc__nmsocket_detach(&sock->listener);
	}

	/* further cleanup performed in isc__nm_tls_cleanup_data() */
	atomic_store(&sock->active, false);
	atomic_store(&sock->closed, true);
	sock->tlsstream.state = TLS_CLOSED;
}

void
isc__nm_tls_close(isc_nmsocket_t *sock) {
	isc__netievent_tlsclose_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlssocket);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		return;
	}

	ievent = isc__nm_get_netievent_tlsclose(sock->mgr, sock);
	isc__nm_maybe_enqueue_ievent(&sock->mgr->workers[sock->tid],
				     (isc__netievent_t *)ievent);
}

void
isc__nm_async_tlsclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsclose_t *ievent = (isc__netievent_tlsclose_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(ievent->sock->tid == isc_nm_tid());

	UNUSED(worker);

	tls_close_direct(sock);
}

void
isc__nm_tls_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlslistener);

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);
	sock->recv_cb = NULL;
	sock->recv_cbarg = NULL;
	if (sock->tlsstream.tls != NULL) {
		isc_tls_free(&sock->tlsstream.tls);
		sock->tlsstream.ctx = NULL;
	}

	if (sock->outer != NULL) {
		isc_nm_stoplistening(sock->outer);
		isc__nmsocket_detach(&sock->outer);
	}
}

isc_result_t
isc_nm_tlsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_cb_t cb, void *cbarg, SSL_CTX *ctx,
		  unsigned int timeout, size_t extrahandlesize) {
	isc_nmsocket_t *nsock = NULL, *tsock = NULL;
	isc__netievent_tlsconnect_t *ievent = NULL;
	isc_result_t result = ISC_R_DEFAULT;

	REQUIRE(VALID_NM(mgr));

	nsock = isc_mem_get(mgr->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, mgr, isc_nm_tlssocket, local);
	nsock->tlsstream.local_iface = *local;
	ISC_LINK_INIT(&nsock->tlsstream.local_iface.addr, link);
	nsock->iface = &nsock->tlsstream.local_iface;
	nsock->extrahandlesize = extrahandlesize;
	nsock->result = ISC_R_DEFAULT;
	nsock->connect_cb = cb;
	nsock->connect_cbarg = cbarg;
	nsock->connect_timeout = timeout;
	nsock->tlsstream.ctx = ctx;

	ievent = isc__nm_get_netievent_tlsconnect(mgr, nsock);
	ievent->local = local->addr;
	ievent->peer = peer->addr;
	ievent->ctx = ctx;

	isc__nmsocket_attach(nsock, &tsock);
	if (isc__nm_in_netthread()) {
		nsock->tid = isc_nm_tid();
		isc__nm_async_tlsconnect(&mgr->workers[nsock->tid],
					 (isc__netievent_t *)ievent);
		isc__nm_put_netievent_tlsconnect(mgr, ievent);
	} else {
		nsock->tid = isc_random_uniform(mgr->nworkers);
		isc__nm_enqueue_ievent(&mgr->workers[nsock->tid],
				       (isc__netievent_t *)ievent);
	}

	LOCK(&nsock->lock);
	result = nsock->result;
	while (result == ISC_R_DEFAULT) {
		WAIT(&nsock->cond, &nsock->lock);
		result = nsock->result;
	}
	atomic_store(&nsock->active, true);
	BROADCAST(&nsock->scond);
	UNLOCK(&nsock->lock);
	INSIST(VALID_NMSOCK(nsock));
	isc__nmsocket_detach(&tsock);

	INSIST(result != ISC_R_DEFAULT);

	return (result);
}

static void
tcp_connected(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)cbarg;
	isc_nmhandle_t *tlshandle = NULL;

	REQUIRE(VALID_NMSOCK(tlssock));
	REQUIRE(VALID_NMHANDLE(handle));

	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	tlssock->peer = isc_nmhandle_peeraddr(handle);
	isc_nmhandle_attach(handle, &tlssock->outerhandle);
	result = initialize_tls(tlssock, false);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	return;
error:
	tlshandle = isc__nmhandle_get(tlssock, NULL, NULL);
	atomic_store(&tlssock->closed, true);
	tls_call_connect_cb(tlssock, tlshandle, result);
	isc_nmhandle_detach(&tlshandle);
	isc__nmsocket_detach(&tlssock);
}

void
isc__nm_async_tlsconnect(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsconnect_t *ievent =
		(isc__netievent_tlsconnect_t *)ev0;
	isc_nmsocket_t *tlssock = ievent->sock;
	isc_result_t result;
	isc_nmhandle_t *tlshandle = NULL;

	UNUSED(worker);

	/*
	 * We need to initialize SSL now to reference SSL_CTX properly.
	 */
	tlssock->tlsstream.tls = isc_tls_create(tlssock->tlsstream.ctx);
	if (tlssock->tlsstream.tls == NULL) {
		result = ISC_R_TLSERROR;
		update_result(tlssock, result);
		goto error;
	}

	tlssock->tid = isc_nm_tid();
	tlssock->tlsstream.state = TLS_INIT;

	(void)isc_nm_tcpconnect(worker->mgr, (isc_nmiface_t *)&ievent->local,
				(isc_nmiface_t *)&ievent->peer, tcp_connected,
				tlssock, tlssock->connect_timeout, 0);
	return;

error:
	tlshandle = isc__nmhandle_get(tlssock, NULL, NULL);
	atomic_store(&tlssock->closed, true);
	tls_call_connect_cb(tlssock, tlshandle, result);
	isc_nmhandle_detach(&tlshandle);
	isc__nmsocket_detach(&tlssock);
}

static void
tls_cancelread(isc_nmsocket_t *sock) {
	if (!inactive(sock) && sock->tlsstream.state == TLS_IO) {
		tls_do_bio(sock, NULL, true);
	} else if (sock->outerhandle != NULL) {
		isc_nm_cancelread(sock->outerhandle);
	}
}

void
isc__nm_tls_cancelread(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;
	isc__netievent_tlscancel_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	sock = handle->sock;

	REQUIRE(sock->type == isc_nm_tlssocket);

	if (sock->tid == isc_nm_tid()) {
		tls_cancelread(sock);
	} else {
		ievent = isc__nm_get_netievent_tlscancel(sock->mgr, sock,
							 handle);
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_tlscancel(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlscancel_t *ievent = (isc__netievent_tlscancel_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(worker->id == sock->tid);
	REQUIRE(sock->tid == isc_nm_tid());

	UNUSED(worker);
	tls_cancelread(sock);
}

void
isc__nm_async_tlsdobio(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsdobio_t *ievent = (isc__netievent_tlsdobio_t *)ev0;

	UNUSED(worker);

	tls_do_bio(ievent->sock, NULL, false);
}

void
isc__nm_tls_cleanup_data(isc_nmsocket_t *sock) {
	if (sock->type == isc_nm_tcplistener &&
	    sock->tlsstream.tlslistener != NULL) {
		REQUIRE(VALID_NMSOCK(sock->tlsstream.tlslistener));
		isc__nmsocket_detach(&sock->tlsstream.tlslistener);
	} else if (sock->type == isc_nm_tlssocket) {
		if (sock->tlsstream.tls != NULL) {
			isc_tls_free(&sock->tlsstream.tls);
			/* These are destroyed when we free SSL */
			sock->tlsstream.ctx = NULL;
			sock->tlsstream.ssl_bio = NULL;
		}
		if (sock->tlsstream.app_bio != NULL) {
			BIO_free(sock->tlsstream.app_bio);
			sock->tlsstream.app_bio = NULL;
		}
	}
}

void
isc__nm_tls_settimeout(isc_nmhandle_t *handle, uint32_t timeout) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_settimeout(sock->outerhandle, timeout);
	}
}
