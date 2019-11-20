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

#define TCPDNS_CLIENTS_PER_CONN 23
/*%<
 *
 * Maximum number of simultaneous handles in flight supported for a single
 * connected TCPDNS socket. This value was chosen arbitrarily, and may be
 * changed in the future.
 */

static void
dnslisten_readcb(isc_nmhandle_t *handle, isc_region_t *region, void *arg);

static void
resume_processing(void *arg);

static inline size_t
dnslen(unsigned char* base) {
	return ((base[0] << 8) + (base[1]));
}

#define NM_REG_BUF 4096
#define NM_BIG_BUF 65536
static inline void
alloc_dnsbuf(isc_nmsocket_t *sock, size_t len) {
	REQUIRE(len <= NM_BIG_BUF);

	if (sock->buf == NULL) {
		/* We don't have the buffer at all */
		size_t alloc_len = len < NM_REG_BUF ? NM_REG_BUF : NM_BIG_BUF;
		sock->buf = isc_mem_allocate(sock->mgr->mctx, alloc_len);
		sock->buf_size = alloc_len;
	} else {
		/* We have the buffer but it's too small */
		sock->buf = isc_mem_reallocate(sock->mgr->mctx, sock->buf,
					       NM_BIG_BUF);
		sock->buf_size = NM_BIG_BUF;
	}
}

/*
 * Accept callback for TCP-DNS connection
 */
static void
dnslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *dnslistensock = (isc_nmsocket_t *) cbarg;
	isc_nmsocket_t *dnssock = NULL;

	REQUIRE(VALID_NMSOCK(dnslistensock));
	REQUIRE(dnslistensock->type == isc_nm_tcpdnslistener);

	/* If accept() was unnsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return;
	}

	/* We need to create a 'wrapper' dnssocket for this connection */
	dnssock = isc_mem_get(handle->sock->mgr->mctx, sizeof(*dnssock));
	isc__nmsocket_init(dnssock, handle->sock->mgr,
			   isc_nm_tcpdnssocket);

	/* We need to copy read callbacks from outer socket */
	dnssock->rcb.recv = dnslistensock->rcb.recv;
	dnssock->rcbarg = dnslistensock->rcbarg;
	dnssock->extrahandlesize = dnslistensock->extrahandlesize;
	isc_nmsocket_attach(handle->sock, &dnssock->outer);
	dnssock->peer = handle->sock->peer;
	dnssock->iface = handle->sock->iface;
	dnssock->closehandle_cb = resume_processing;

	isc_nm_read(handle, dnslisten_readcb, dnssock);
}

static bool
connection_limit(isc_nmsocket_t *sock) {
	int ah;

	REQUIRE(sock->type == isc_nm_tcpdnssocket && sock->outer != NULL);

	if (atomic_load(&sock->sequential)) {
		/*
		 * We're already non-pipelining, so there's
		 * no need to check per-connection limits.
		 */
		return (false);
	}

	LOCK(&sock->lock);
	ah = sock->ah;
	UNLOCK(&sock->lock);

	if (ah >= TCPDNS_CLIENTS_PER_CONN) {
		atomic_store(&sock->overlimit, true);
		isc_nm_pauseread(sock->outer);
		return (true);
	}

	return (false);
}

/* Process all complete packets out of incoming buffer */
static void
processbuffer(isc_nmsocket_t *dnssock) {
	REQUIRE(VALID_NMSOCK(dnssock));

	/* While we have a complete packet in the buffer */
	while (dnssock->buf_len > 2 &&
	       dnslen(dnssock->buf) <= dnssock->buf_len - 2 &&
	       !connection_limit(dnssock))
	{
		isc_nmhandle_t *dnshandle = NULL;
		isc_region_t r2 = {
			.base = dnssock->buf + 2,
			.length = dnslen(dnssock->buf)
		};
		size_t len;

		dnshandle = isc__nmhandle_get(dnssock, NULL, NULL);
		atomic_store(&dnssock->processing, true);
		dnssock->rcb.recv(dnshandle, &r2, dnssock->rcbarg);

		/*
		 * If the recv callback wants to hold on to the
		 * handle, it needs to attach to it.
		 */
		isc_nmhandle_unref(dnshandle);

		len = dnslen(dnssock->buf) + 2;
		dnssock->buf_len -= len;
		if (len > 0) {
			memmove(dnssock->buf, dnssock->buf + len,
				dnssock->buf_len);
		}

		/* Check here to make sure we do the processing at least once */
		if (atomic_load(&dnssock->processing)) {
			return;
		}
	}
}

/*
 * We've got a read on our underlying socket, need to check if we have
 * a complete DNS packet and, if so - call the callback
 */
static void
dnslisten_readcb(isc_nmhandle_t *handle, isc_region_t *region, void *arg) {
	isc_nmsocket_t *dnssock = (isc_nmsocket_t *) arg;
	isc_sockaddr_t local;
	unsigned char *base = NULL;
	size_t len;

	REQUIRE(VALID_NMSOCK(dnssock));
	REQUIRE(VALID_NMHANDLE(handle));

	if (region == NULL) {
		/* Connection closed */
		atomic_store(&dnssock->closed, true);
		isc_nmsocket_detach(&dnssock->outer);
		isc_nmsocket_detach(&dnssock);
		return;
	}

	local = isc_nmhandle_localaddr(handle);

	base = region->base;
	len = region->length;

	/*
	 * We have something in the buffer, we need to glue it.
	 */
	if (dnssock->buf_len > 0) {
		if (dnssock->buf_len == 1) {
			/* Make sure we have the length */
			dnssock->buf[1] = base[0];
			dnssock->buf_len = 2;
			base++;
			len--;
		}

		processbuffer(dnssock);
	}

	if (dnssock->buf_len > 0) {
		size_t plen;

		if (dnssock->buf_len == 1) {
			/* Make sure we have the length */
			dnssock->buf[1] = base[0];
			dnssock->buf_len = 2;
			base++;
			len--;
		}

		/* At this point we definitely have 2 bytes there. */
		plen = ISC_MIN(len, (dnslen(dnssock->buf) + 2 -
				     dnssock->buf_len));

		if (dnssock->buf_len + plen > NM_BIG_BUF) {
			/*
			 * XXX: continuing to read will overrun the
			 * socket buffer. We may need to force the
			 * connection to close so the client will have
			 * to open a new one.
			 */
			return;
		}

		if (dnssock->buf_len + plen > dnssock->buf_size) {
			alloc_dnsbuf(dnssock, dnssock->buf_len + plen);
		}

		memmove(dnssock->buf + dnssock->buf_len, base, plen);
		dnssock->buf_len += plen;
		base += plen;
		len -= plen;

		/* Do we have a complete packet in the buffer? */
		if (dnslen(dnssock->buf) >= dnssock->buf_len - 2 &&
		    !connection_limit(dnssock))
		{
			isc_nmhandle_t *dnshandle = NULL;
			isc_region_t r2 = {
				.base = dnssock->buf + 2,
				.length = dnslen(dnssock->buf)
			};

			dnshandle = isc__nmhandle_get(dnssock, NULL, &local);
			atomic_store(&dnssock->processing, true);
			dnssock->rcb.recv(dnshandle, &r2, dnssock->rcbarg);
			dnssock->buf_len = 0;

			/*
			 * If the recv callback wants to hold on to the
			 * handle, it needs to attach to it.
			 */
			isc_nmhandle_unref(dnshandle);
		}
	}

	/*
	 * At this point we've processed whatever was previously in the
	 * socket buffer. If there are more messages to be found in what
	 * we've read, and if we're either pipelining or not processing
	 * anything else currently, then we can process those messages now.
	 */
	while (len >= 2 && dnslen(base) <= len - 2 &&
	       (!atomic_load(&dnssock->sequential) ||
		!atomic_load(&dnssock->processing)) &&
	       !connection_limit(dnssock))
	{
		isc_nmhandle_t *dnshandle = NULL;
		isc_region_t r2 = {
			.base = base + 2,
			.length = dnslen(base)
		};

		len -= dnslen(base) + 2;
		base += dnslen(base) + 2;

		dnshandle = isc__nmhandle_get(dnssock, NULL, &local);
		atomic_store(&dnssock->processing, true);
		dnssock->rcb.recv(dnshandle, &r2, dnssock->rcbarg);

		/*
		 * If the recv callback wants to hold on to the
		 * handle, it needs to attach to it.
		 */
		isc_nmhandle_unref(dnshandle);
	}

	/*
	 * We have less than a full message remaining; it can be
	 * stored in the socket buffer for next time.
	 */
	if (len > 0) {
		if (len > dnssock->buf_size) {
			alloc_dnsbuf(dnssock, len);
		}

		INSIST(len <= dnssock->buf_size);
		memmove(dnssock->buf, base, len);
		dnssock->buf_len = len;
	}
}

/*
 * isc_nm_listentcpdns listens for connections and accepts
 * them immediately, then calls the cb for each incoming DNS packet
 * (with 2-byte length stripped) - just like for UDP packet.
 */
isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface,
		    isc_nm_recv_cb_t cb, void *cbarg,
		    size_t extrahandlesize, isc_quota_t *quota,
		    isc_nmsocket_t **rv)
{
	/* A 'wrapper' socket object with outer set to true TCP socket */
	isc_nmsocket_t *dnslistensock =
		isc_mem_get(mgr->mctx, sizeof(*dnslistensock));
	isc_result_t result;

	REQUIRE(VALID_NM(mgr));

	isc__nmsocket_init(dnslistensock, mgr, isc_nm_tcpdnslistener);
	dnslistensock->iface = iface;
	dnslistensock->rcb.recv = cb;
	dnslistensock->rcbarg = cbarg;
	dnslistensock->extrahandlesize = extrahandlesize;

	/* We set dnslistensock->outer to a true listening socket */
	result = isc_nm_listentcp(mgr, iface, dnslisten_acceptcb,
				  dnslistensock, extrahandlesize,
				  quota, &dnslistensock->outer);

	atomic_store(&dnslistensock->listening, true);
	*rv = dnslistensock;
	return (result);
}

void
isc_nm_tcpdns_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpdnslistener);

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);

	if (sock->outer != NULL) {
		isc_nm_tcp_stoplistening(sock->outer);
		isc_nmsocket_detach(&sock->outer);
	}
}

void
isc_nm_tcpdns_sequential(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	if (handle->sock->type != isc_nm_tcpdnssocket ||
	    handle->sock->outer == NULL)
	{
		return;
	}

	/*
	 * We don't want pipelining on this connection. That means
	 * that we need to pause after reading each request, and
	 * resume only after the request has been processed. This
	 * is done in resume_processing(), which is the socket's
	 * closehandle_cb callback, called whenever a handle
	 * is released.
	 */
	isc_nm_pauseread(handle->sock->outer);
	atomic_store(&handle->sock->sequential, true);
}

typedef struct tcpsend {
	isc_mem_t		*mctx;
	isc_nmhandle_t		*handle;
	isc_region_t		region;
	isc_nmhandle_t		*orighandle;
	isc_nm_cb_t		cb;
	void 			*cbarg;
} tcpsend_t;

static void
resume_processing(void *arg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *) arg;

	REQUIRE(VALID_NMSOCK(sock));

	if (sock->type != isc_nm_tcpdnssocket || sock->outer == NULL) {
		return;
	}

	/*
	 * If we're in sequential mode or over the
	 * clients-per-connection limit, the sock can
	 * resume reading now.
	 */
	if (atomic_load(&sock->overlimit) || atomic_load(&sock->sequential)) {
		atomic_store(&sock->overlimit, false);
		atomic_store(&sock->processing, false);
		isc_nm_resumeread(sock->outer);
	}
}

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t *ts = (tcpsend_t *) cbarg;

	UNUSED(handle);

	ts->cb(ts->orighandle, result, ts->cbarg);
	isc_mem_put(ts->mctx, ts->region.base, ts->region.length);

	/*
	 * The response was sent; if we're in sequential or overlimit
	 * mode, resume processing now.
	 */
	if (atomic_load(&ts->orighandle->sock->sequential) ||
	    atomic_load(&ts->orighandle->sock->overlimit))
	{
		atomic_store(&ts->orighandle->sock->processing, false);
		atomic_store(&ts->orighandle->sock->overlimit, false);
		processbuffer(ts->orighandle->sock);
		isc_nm_resumeread(handle->sock);
	}

	isc_nmhandle_unref(ts->orighandle);
	isc_mem_putanddetach(&ts->mctx, ts, sizeof(*ts));
}

/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle, isc_region_t *region,
		    isc_nm_cb_t cb, void *cbarg)
{
	tcpsend_t *t = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	isc_nmsocket_t *sock = handle->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpdnssocket);

	if (sock->outer == NULL) {
		/* The socket is closed, just issue the callback */
		cb(handle, ISC_R_FAILURE, cbarg);
		return (ISC_R_NOTCONNECTED);
	}

	t = isc_mem_get(sock->mgr->mctx, sizeof(*t));
	*t = (tcpsend_t) {
		.cb = cb,
		.cbarg = cbarg,
		.handle = handle->sock->outer->tcphandle,
	};

	isc_mem_attach(sock->mgr->mctx, &t->mctx);
	t->orighandle = handle;
	isc_nmhandle_ref(t->orighandle);

	t->region = (isc_region_t) {
		.base = isc_mem_get(t->mctx, region->length + 2),
		.length = region->length + 2
	};

	*(uint16_t *) t->region.base = htons(region->length);
	memmove(t->region.base + 2, region->base, region->length);

	return (isc__nm_tcp_send(t->handle, &t->region, tcpdnssend_cb, t));
}

void
isc__nm_tcpdns_close(isc_nmsocket_t *sock) {
	if (sock->outer != NULL) {
		isc_nmsocket_detach(&sock->outer);
	}

	atomic_store(&sock->closed, true);
	isc__nmsocket_prep_destroy(sock);
}
