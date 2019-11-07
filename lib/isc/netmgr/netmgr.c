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

#include <inttypes.h>
#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/quota.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"

/*
 * libuv is not thread safe, but has mechanisms to pass messages
 * between threads. Each socket is owned by a thread. For UDP
 * sockets we have a set of sockets for each interface and we can
 * choose a sibling and send the message directly. For TCP, or if
 * we're calling from a non-networking thread, we need to pass the
 * request using async_cb.
 */

#if defined(HAVE_TLS)
#if defined(HAVE_THREAD_LOCAL)
#include <threads.h>
static thread_local int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___THREAD)
static __thread int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#elif defined(HAVE___DECLSPEC_THREAD)
static __declspec( thread ) int isc__nm_tid_v = ISC_NETMGR_TID_UNKNOWN;
#else  /* if defined(HAVE_THREAD_LOCAL) */
#error "Unknown method for defining a TLS variable!"
#endif /* if defined(HAVE_THREAD_LOCAL) */
#else  /* if defined(HAVE_TLS) */
static int isc__nm_tid_v = ISC_NETMGR_TID_NOTLS;
#endif /* if defined(HAVE_TLS) */

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock);
static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle);
static void *
nm_thread(void *worker0);
static void
async_cb(uv_async_t *handle);

int
isc_nm_tid() {
	return (isc__nm_tid_v);
}

bool
isc__nm_in_netthread() {
	return (isc__nm_tid_v >= 0);
}

isc_nm_t *
isc_nm_start(isc_mem_t *mctx, uint32_t workers) {
	isc_nm_t *mgr = NULL;
	char name[32];

	mgr = isc_mem_get(mctx, sizeof(*mgr));
	*mgr = (isc_nm_t) {
		.nworkers = workers
	};

	isc_mem_attach(mctx, &mgr->mctx);
	isc_mutex_init(&mgr->lock);
	isc_condition_init(&mgr->wkstatecond);
	isc_refcount_init(&mgr->references, 1);
	atomic_init(&mgr->workers_running, 0);
	atomic_init(&mgr->workers_paused, 0);
	atomic_init(&mgr->maxudp, 0);
	atomic_init(&mgr->paused, false);
	atomic_init(&mgr->interlocked, false);

	mgr->workers = isc_mem_get(mctx, workers * sizeof(isc__networker_t));
	for (size_t i = 0; i < workers; i++) {
		int r;
		isc__networker_t *worker = &mgr->workers[i];
		*worker = (isc__networker_t) {
			.mgr = mgr,
			.id = i,
		};

		r = uv_loop_init(&worker->loop);
		RUNTIME_CHECK(r == 0);

		worker->loop.data = &mgr->workers[i];

		r = uv_async_init(&worker->loop, &worker->async, async_cb);
		RUNTIME_CHECK(r == 0);

		isc_mutex_init(&worker->lock);
		isc_condition_init(&worker->cond);

		isc_mempool_create(mgr->mctx, 65536, &worker->mpool_bufs);
		worker->ievents = isc_queue_new(mgr->mctx, 128);

		/*
		 * We need to do this here and not in nm_thread to avoid a
		 * race - we could exit isc_nm_start, launch nm_destroy,
		 * and nm_thread would still not be up.
		 */
		atomic_fetch_add_explicit(&mgr->workers_running, 1,
					  memory_order_relaxed);
		isc_thread_create(nm_thread, &mgr->workers[i], &worker->thread);

		snprintf(name, sizeof(name), "isc-net-%04zu", i);
		isc_thread_setname(worker->thread, name);
	}

	mgr->magic = NM_MAGIC;
	return (mgr);
}

/*
 * Free the resources of the network manager.
 *
 * TODO we need to clean up properly - launch all missing callbacks,
 * destroy all listeners, etc.
 */
static void
nm_destroy(isc_nm_t **mgr0) {
	REQUIRE(VALID_NM(*mgr0));
	REQUIRE(!isc__nm_in_netthread());

	isc_nm_t *mgr = *mgr0;

	LOCK(&mgr->lock);
	mgr->magic = 0;

	for (size_t i = 0; i < mgr->nworkers; i++) {
		isc__netievent_t *event = NULL;

		LOCK(&mgr->workers[i].lock);
		mgr->workers[i].finished = true;
		UNLOCK(&mgr->workers[i].lock);
		event = isc__nm_get_ievent(mgr, netievent_stop);
		isc__nm_enqueue_ievent(&mgr->workers[i], event);
	}

	while (atomic_load(&mgr->workers_running) > 0) {
		WAIT(&mgr->wkstatecond, &mgr->lock);
	}
	UNLOCK(&mgr->lock);

	for (size_t i = 0; i < mgr->nworkers; i++) {
		/* Empty the async event queue */
		isc__netievent_t *ievent;
		while ((ievent = (isc__netievent_t *)
			isc_queue_dequeue(mgr->workers[i].ievents)) != NULL)
		{
			isc_mem_put(mgr->mctx, ievent,
				    sizeof(isc__netievent_storage_t));
		}
		isc_queue_destroy(mgr->workers[i].ievents);
		isc_mempool_destroy(&mgr->workers[i].mpool_bufs);
	}

	isc_condition_destroy(&mgr->wkstatecond);
	isc_mutex_destroy(&mgr->lock);
	isc_mem_put(mgr->mctx, mgr->workers,
		    mgr->nworkers * sizeof(isc__networker_t));
	isc_mem_putanddetach(&mgr->mctx, mgr, sizeof(*mgr));
	*mgr0 = NULL;
}

void
isc_nm_pause(isc_nm_t *mgr) {
	REQUIRE(VALID_NM(mgr));
	REQUIRE(!isc__nm_in_netthread());

	atomic_store(&mgr->paused, true);
	isc__nm_acquire_interlocked_force(mgr);

	for (size_t i = 0; i < mgr->nworkers; i++) {
		isc__netievent_t *event = NULL;

		LOCK(&mgr->workers[i].lock);
		mgr->workers[i].paused = true;
		UNLOCK(&mgr->workers[i].lock);

		/*
		 * We have to issue a stop, otherwise the uv_run loop will
		 * run indefinitely!
		 */
		event = isc__nm_get_ievent(mgr, netievent_stop);
		isc__nm_enqueue_ievent(&mgr->workers[i], event);
	}

	LOCK(&mgr->lock);
	while (atomic_load_relaxed(&mgr->workers_paused) !=
	       atomic_load_relaxed(&mgr->workers_running))
	{
		WAIT(&mgr->wkstatecond, &mgr->lock);
	}
	UNLOCK(&mgr->lock);
}

void
isc_nm_resume(isc_nm_t *mgr) {
	REQUIRE(VALID_NM(mgr));
	REQUIRE(!isc__nm_in_netthread());

	for (size_t i = 0; i < mgr->nworkers; i++) {
		LOCK(&mgr->workers[i].lock);
		mgr->workers[i].paused = false;
		SIGNAL(&mgr->workers[i].cond);
		UNLOCK(&mgr->workers[i].lock);
	}
	isc__nm_drop_interlocked(mgr);

	/*
	 * We're not waiting for all the workers to come back to life;
	 * they eventually will, we don't care.
	 */
}

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst) {
	int refs;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(dst != NULL && *dst == NULL);

	refs = isc_refcount_increment(&mgr->references);
	INSIST(refs > 0);

	*dst = mgr;
}

void
isc_nm_detach(isc_nm_t **mgr0) {
	isc_nm_t *mgr = NULL;
	int references;

	REQUIRE(mgr0 != NULL);
	REQUIRE(VALID_NM(*mgr0));

	mgr = *mgr0;
	*mgr0 = NULL;

	references = isc_refcount_decrement(&mgr->references);
	INSIST(references > 0);
	if (references == 1) {
		nm_destroy(&mgr);
	}
}


void
isc_nm_destroy(isc_nm_t **mgr0) {
	isc_nm_t *mgr = NULL;
	int references;

	REQUIRE(mgr0 != NULL);
	REQUIRE(VALID_NM(*mgr0));

	mgr = *mgr0;
	*mgr0 = NULL;

	/*
	 * Wait for the manager to be dereferenced elsehwere.
	 */
	while (isc_refcount_current(&mgr->references) > 1) {
#ifdef WIN32
			_sleep(1000);
#else
			usleep(1000000);
#endif
	}
	references = isc_refcount_decrement(&mgr->references);
	INSIST(references > 0);
	if (references == 1) {
		nm_destroy(&mgr);
	}
}

void
isc_nm_maxudp(isc_nm_t *mgr, uint32_t maxudp) {
	REQUIRE(VALID_NM(mgr));

	atomic_store(&mgr->maxudp, maxudp);
}

/*
 * nm_thread is a single worker thread, that runs uv_run event loop
 * until asked to stop.
 */
static void *
nm_thread(void *worker0) {
	isc__networker_t *worker = (isc__networker_t *) worker0;

	isc__nm_tid_v = worker->id;
	isc_thread_setaffinity(isc__nm_tid_v);

	while (true) {
		int r = uv_run(&worker->loop, UV_RUN_DEFAULT);
		bool pausing = false;

		/*
		 * or there's nothing to do. In the first case - wait
		 * for condition. In the latter - timedwait
		 */
		LOCK(&worker->lock);
		while (worker->paused) {
			LOCK(&worker->mgr->lock);
			if (!pausing) {
				atomic_fetch_add_explicit(
						  &worker->mgr->workers_paused,
						  1, memory_order_acquire);
				pausing = true;
			}

			SIGNAL(&worker->mgr->wkstatecond);
			UNLOCK(&worker->mgr->lock);

			WAIT(&worker->cond, &worker->lock);
		}
		if (pausing) {
			uint32_t wp = atomic_fetch_sub_explicit(
					       &worker->mgr->workers_paused,
					       1, memory_order_release);
			if (wp == 1) {
				atomic_store(&worker->mgr->paused, false);
			}
		}
		UNLOCK(&worker->lock);

		if (worker->finished) {
			/* TODO walk the handles and free them! */
			break;
		}

		if (r == 0) {
			/*
			 * TODO it should never happen - we don't have
			 * any sockets we're listening on?
			 */
#ifdef WIN32
			_sleep(100);
#else
			usleep(100000);
#endif
		}

		/*
		 * Empty the async queue.
		 */
		async_cb(&worker->async);
	}

	LOCK(&worker->mgr->lock);
	atomic_fetch_sub_explicit(&worker->mgr->workers_running, 1,
				  memory_order_relaxed);
	SIGNAL(&worker->mgr->wkstatecond);
	UNLOCK(&worker->mgr->lock);
	return (NULL);
}

/*
 * async_cb is an universal callback for 'async' events sent to event loop.
 * It's the only way to safely pass data to libuv event loop. We use a single
 * async event and a lockless queue of 'isc__netievent_t' structures passed
 * from other threads.
 */
static void
async_cb(uv_async_t *handle) {
	isc__networker_t *worker = (isc__networker_t *) handle->loop->data;
	isc__netievent_t *ievent;

	/*
	 * We only try dequeue to not waste time, libuv guarantees
	 * that if someone calls uv_async_send -after- async_cb was called
	 * then async_cb will be called again, we won't loose any signals.
	 */
	while ((ievent = (isc__netievent_t *)
		isc_queue_dequeue(worker->ievents)) != NULL)
	{
		switch (ievent->type) {
		case netievent_stop:
			uv_stop(handle->loop);
			isc_mem_put(worker->mgr->mctx, ievent,
				    sizeof(isc__netievent_storage_t));
			return;
		case netievent_udplisten:
			isc__nm_async_udplisten(worker, ievent);
			break;
		case netievent_udpstoplisten:
			isc__nm_async_udpstoplisten(worker, ievent);
			break;
		case netievent_udpsend:
			isc__nm_async_udpsend(worker, ievent);
			break;
		case netievent_tcpconnect:
			isc__nm_async_tcpconnect(worker, ievent);
			break;
		case netievent_tcplisten:
			isc__nm_async_tcplisten(worker, ievent);
			break;
		case netievent_tcpstartread:
			isc__nm_async_startread(worker, ievent);
			break;
		case netievent_tcppauseread:
			isc__nm_async_pauseread(worker, ievent);
			break;
		case netievent_tcpsend:
			isc__nm_async_tcpsend(worker, ievent);
			break;
		case netievent_tcpstoplisten:
			isc__nm_async_tcpstoplisten(worker, ievent);
			break;
		case netievent_tcpclose:
			isc__nm_async_tcpclose(worker, ievent);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		isc_mem_put(worker->mgr->mctx, ievent,
			    sizeof(isc__netievent_storage_t));
	}
}

void *
isc__nm_get_ievent(isc_nm_t *mgr, isc__netievent_type type) {
	isc__netievent_storage_t *event =
		isc_mem_get(mgr->mctx, sizeof(isc__netievent_storage_t));

	/* XXX: use a memory pool? */
	*event = (isc__netievent_storage_t) {
		.ni.type = type
	};
	return (event);
}

void
isc__nm_enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event) {
	isc_queue_enqueue(worker->ievents, (uintptr_t)event);
	uv_async_send(&worker->async);
}

static bool
isc__nmsocket_active(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	if (sock->parent != NULL) {
		return (atomic_load(&sock->parent->active));
	}

	return (atomic_load(&sock->active));
}

void
isc_nmsocket_attach(isc_nmsocket_t *sock, isc_nmsocket_t **target) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(target != NULL && *target == NULL);

	if (sock->parent != NULL) {
		INSIST(sock->parent->parent == NULL); /* sanity check */
		isc_refcount_increment(&sock->parent->references);
	} else {
		isc_refcount_increment(&sock->references);
	}

	*target = sock;
}

/*
 * Free all resources inside a socket (including its children if any).
 */
static void
nmsocket_cleanup(isc_nmsocket_t *sock, bool dofree) {
	isc_nmhandle_t *handle = NULL;
	isc__nm_uvreq_t *uvreq = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(!isc__nmsocket_active(sock));

	atomic_store(&sock->destroying, true);

	if (sock->parent == NULL && sock->children != NULL) {
		/*
		 * We shouldn't be here unless there are no active handles,
		 * so we can clean up and free the children.
		 */
		for (int i = 0; i < sock->nchildren; i++) {
			if (!atomic_load(&sock->children[i].destroying)) {
				nmsocket_cleanup(&sock->children[i], false);
			}
		}

		/*
		 * This was a parent socket; free the children.
		 */
		isc_mem_put(sock->mgr->mctx, sock->children,
			    sock->nchildren * sizeof(*sock));
		sock->children = NULL;
		sock->nchildren = 0;
	}

	if (sock->tcphandle != NULL) {
		isc_nmhandle_unref(sock->tcphandle);
		sock->tcphandle = NULL;
	}

	while ((handle = isc_astack_pop(sock->inactivehandles)) != NULL) {
		nmhandle_free(sock, handle);
	}

	if (sock->buf != NULL) {
		isc_mem_put(sock->mgr->mctx, sock->buf, sock->buf_size);
	}

	if (sock->quota != NULL) {
		isc_quota_detach(&sock->quota);
	}

	isc_astack_destroy(sock->inactivehandles);

	while ((uvreq = isc_astack_pop(sock->inactivereqs)) != NULL) {
		isc_mem_put(sock->mgr->mctx, uvreq, sizeof(*uvreq));
	}

	isc_astack_destroy(sock->inactivereqs);

	isc_mem_free(sock->mgr->mctx, sock->ah_frees);
	isc_mem_free(sock->mgr->mctx, sock->ah_handles);

	if (dofree) {
		isc_nm_t *mgr = sock->mgr;
		isc_mem_put(mgr->mctx, sock, sizeof(*sock));
		isc_nm_detach(&mgr);
	} else {
		isc_nm_detach(&sock->mgr);
	}

}

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock) {
	int active_handles = 0;
	bool destroy = false;

	REQUIRE(!isc__nmsocket_active(sock));

	if (sock->parent != NULL) {
		/*
		 * This is a child socket and cannot be destroyed except
		 * as a side effect of destroying the parent, so let's go
		 * see if the parent is ready to be destroyed.
		 */
		nmsocket_maybe_destroy(sock->parent);
		return;
	}

	/*
	 * This is a parent socket (or a standalone). See whether the
	 * children have active handles before deciding whether to
	 * accept destruction.
	 */
	LOCK(&sock->lock);
	active_handles += sock->ah_cpos;
	if (sock->children != NULL) {
		for (int i = 0; i < sock->nchildren; i++) {
			LOCK(&sock->children[i].lock);
			active_handles += sock->children[i].ah_cpos;
			UNLOCK(&sock->children[i].lock);
		}
	}

	if (atomic_load(&sock->closed) &&
	    atomic_load(&sock->references) == 0 &&
	    (active_handles == 0 || sock->tcphandle != NULL))
	{
		destroy = true;
	}
	UNLOCK(&sock->lock);

	if (destroy) {
		nmsocket_cleanup(sock, true);
	}
}

void
isc__nmsocket_prep_destroy(isc_nmsocket_t *sock) {
	REQUIRE(sock->parent == NULL);

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
		for (int i = 0; i < sock->nchildren; i++) {
			atomic_store(&sock->children[i].active, false);
		}
	}

	/*
	 * If we're here then we already stopped listening; otherwise
	 * we'd have a hanging reference from the listening process.
	 *
	 * If it's a regular socket we may need to close it.
	 */
	if (!atomic_load(&sock->closed)) {
		switch (sock->type) {
		case isc_nm_tcpsocket:
			isc__nm_tcp_close(sock);
			break;
		case isc_nm_tcpdnssocket:
			isc__nm_tcpdns_close(sock);
			break;
		default:
			break;
		}
	}

	nmsocket_maybe_destroy(sock);
}

void
isc_nmsocket_detach(isc_nmsocket_t **sockp) {
	REQUIRE(sockp != NULL && *sockp != NULL);
	REQUIRE(VALID_NMSOCK(*sockp));

	isc_nmsocket_t *sock = *sockp, *rsock = NULL;
	int references;
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

	references = isc_refcount_decrement(&rsock->references);
	INSIST(references > 0);
	if (references == 1) {
		isc__nmsocket_prep_destroy(rsock);
	}

}

void
isc__nmsocket_init(isc_nmsocket_t *sock, isc_nm_t *mgr,
		   isc_nmsocket_type type)
{
	*sock = (isc_nmsocket_t) {
		.type = type,
		.fd = -1,
		.ah_size = 32,
		.inactivehandles = isc_astack_new(mgr->mctx, 60),
		.inactivereqs = isc_astack_new(mgr->mctx, 60)
	};

	isc_nm_attach(mgr, &sock->mgr);
	sock->uv_handle.handle.data = sock;

	sock->ah_frees = isc_mem_allocate(mgr->mctx,
					  sock->ah_size * sizeof(size_t));
	sock->ah_handles = isc_mem_allocate(mgr->mctx,
					    sock->ah_size *
					     sizeof(isc_nmhandle_t *));
	for (size_t i = 0; i < 32; i++) {
		sock->ah_frees[i] = i;
		sock->ah_handles[i] = NULL;
	}

	isc_mutex_init(&sock->lock);
	isc_condition_init(&sock->cond);
	isc_refcount_init(&sock->references, 1);
	atomic_init(&sock->active, true);

	sock->magic = NMSOCK_MAGIC;
}

void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *) handle->data;
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(isc__nm_in_netthread());
	REQUIRE(size <= 65536);

	/* TODO that's for UDP only! */
	worker = &sock->mgr->workers[sock->tid];
	INSIST(!worker->udprecvbuf_inuse);

	buf->base = worker->udprecvbuf;
	worker->udprecvbuf_inuse = true;
	buf->len = size;
}

void
isc__nm_free_uvbuf(isc_nmsocket_t *sock, const uv_buf_t *buf) {
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	worker = &sock->mgr->workers[sock->tid];

	REQUIRE(worker->udprecvbuf_inuse);
	REQUIRE(buf->base == worker->udprecvbuf);

	UNUSED(buf);

	worker->udprecvbuf_inuse = false;
}

static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *sock) {
	isc_nmhandle_t *handle =
		isc_mem_get(sock->mgr->mctx,
			    sizeof(isc_nmhandle_t) + sock->extrahandlesize);

	*handle = (isc_nmhandle_t) {
		.magic = NMHANDLE_MAGIC
	};
	isc_refcount_init(&handle->references, 1);

	return (handle);
}

isc_nmhandle_t *
isc__nmhandle_get(isc_nmsocket_t *sock, isc_sockaddr_t *peer,
		  isc_sockaddr_t *local)
{
	isc_nmhandle_t *handle = NULL;
	int pos;

	REQUIRE(VALID_NMSOCK(sock));

	handle = isc_astack_pop(sock->inactivehandles);

	if (handle == NULL) {
		handle = alloc_handle(sock);
	} else {
		INSIST(VALID_NMHANDLE(handle));
		isc_refcount_increment(&handle->references);
	}

	handle->sock = sock;
	if (peer != NULL) {
		memcpy(&handle->peer, peer, sizeof(isc_sockaddr_t));
	} else {
		memcpy(&handle->peer, &sock->peer, sizeof(isc_sockaddr_t));
	}

	if (local != NULL) {
		memcpy(&handle->local, local, sizeof(isc_sockaddr_t));
	} else if (sock->iface != NULL) {
		memcpy(&handle->local, &sock->iface->addr,
		       sizeof(isc_sockaddr_t));
	} else {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	LOCK(&sock->lock);
	/* We need to add this handle to the list of active handles */
	if (sock->ah_cpos == sock->ah_size) {
		sock->ah_frees =
			isc_mem_reallocate(sock->mgr->mctx, sock->ah_frees,
					   sock->ah_size * 2 *
					   sizeof(size_t));
		sock->ah_handles =
			isc_mem_reallocate(sock->mgr->mctx,
					   sock->ah_handles,
					   sock->ah_size * 2 *
					   sizeof(isc_nmhandle_t *));

		for (size_t i = sock->ah_size; i < sock->ah_size * 2; i++) {
			sock->ah_frees[i] = i;
			sock->ah_handles[i] = NULL;
		}

		sock->ah_size *= 2;
	}

	pos = sock->ah_frees[sock->ah_cpos++];
	INSIST(sock->ah_handles[pos] == NULL);
	sock->ah_handles[pos] = handle;
	handle->ah_pos = pos;
	UNLOCK(&sock->lock);

	if (sock->type == isc_nm_tcpsocket) {
		INSIST(sock->tcphandle == NULL);
		sock->tcphandle = handle;
	}

	return (handle);
}

void
isc_nmhandle_ref(isc_nmhandle_t *handle) {
	int refs;

	REQUIRE(VALID_NMHANDLE(handle));

	refs = isc_refcount_increment(&handle->references);
	INSIST(refs > 0);

}

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->sock->type == isc_nm_tcpsocket ||
	       handle->sock->type == isc_nm_tcpdnssocket);
}

static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle) {
	size_t extra = sock->extrahandlesize;

	if (handle->dofree) {
		handle->dofree(handle->opaque);
	}

	*handle = (isc_nmhandle_t) {
		.magic = 0
	};
	isc_mem_put(sock->mgr->mctx, handle, sizeof(isc_nmhandle_t) + extra);
}

void
isc_nmhandle_unref(isc_nmhandle_t *handle) {
	int refs;

	REQUIRE(VALID_NMHANDLE(handle));

	refs = isc_refcount_decrement(&handle->references);
	INSIST(refs > 0);
	if (refs == 1) {
		isc_nmsocket_t *sock = handle->sock;
		bool reuse = false;

		handle->sock = NULL;
		if (handle->doreset != NULL) {
			handle->doreset(handle->opaque);
		}

		/*
		 * We do it all under lock to avoid races with socket
		 * destruction.
		 */
		LOCK(&sock->lock);
		INSIST(sock->ah_handles[handle->ah_pos] == handle);
		INSIST(sock->ah_size > handle->ah_pos);
		INSIST(sock->ah_cpos > 0);
		sock->ah_handles[handle->ah_pos] = NULL;
		sock->ah_frees[--sock->ah_cpos] = handle->ah_pos;
		handle->ah_pos = 0;

		if (atomic_load(&sock->active)) {
			reuse = isc_astack_trypush(sock->inactivehandles,
						   handle);
		}
		UNLOCK(&sock->lock);

		if (!reuse) {
			nmhandle_free(sock, handle);
		}

		if (sock->ah_cpos == 0 &&
		    !atomic_load(&sock->active) &&
		    !atomic_load(&sock->destroying))
		{
			nmsocket_maybe_destroy(sock);
		}
	}
}

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->opaque);
}

void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg,
		     isc_nm_opaquecb doreset, isc_nm_opaquecb dofree)
{
	REQUIRE(VALID_NMHANDLE(handle));

	handle->opaque = arg;
	handle->doreset = doreset;
	handle->dofree = dofree;
}

void *
isc_nmhandle_getextra(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return (handle->extra);
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

isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *sock) {
	isc__nm_uvreq_t *req = NULL;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(VALID_NMSOCK(sock));

	if (sock != NULL && atomic_load(&sock->active)) {
		/* Try to reuse one */
		req = isc_astack_pop(sock->inactivereqs);
	}

	if (req == NULL) {
		req = isc_mem_get(mgr->mctx, sizeof(isc__nm_uvreq_t));
	}

	*req = (isc__nm_uvreq_t) {
		.magic = 0
	};
	req->uv_req.req.data = req;
	isc_nmsocket_attach(sock, &req->sock);
	req->magic = UVREQ_MAGIC;

	return (req);
}

void
isc__nm_uvreq_put(isc__nm_uvreq_t **req0, isc_nmsocket_t *sock) {
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

	if (!atomic_load(&sock->active) ||
	    !isc_astack_trypush(sock->inactivereqs, req))
	{
		isc_mem_put(sock->mgr->mctx, req, sizeof(isc__nm_uvreq_t));
	}

	if (handle != NULL) {
		isc_nmhandle_unref(handle);
	}

	isc_nmsocket_detach(&sock);
}

isc_result_t
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region,
	    isc_nm_cb_t cb, void *cbarg)
{
	REQUIRE(VALID_NMHANDLE(handle));

	switch (handle->sock->type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		return (isc__nm_udp_send(handle, region, cb, cbarg));
	case isc_nm_tcpsocket:
		return (isc__nm_tcp_send(handle, region, cb, cbarg));
	case isc_nm_tcpdnssocket:
		return (isc__nm_tcpdns_send(handle, region, cb, cbarg));
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

bool
isc__nm_acquire_interlocked(isc_nm_t *mgr) {
	LOCK(&mgr->lock);
	bool success = atomic_compare_exchange_strong(&mgr->interlocked,
						      &(bool){false}, true);
	UNLOCK(&mgr->lock);
	return (success);
}

void
isc__nm_drop_interlocked(isc_nm_t *mgr) {
	LOCK(&mgr->lock);
	bool success = atomic_compare_exchange_strong(&mgr->interlocked,
						      &(bool){true}, false);
	INSIST(success == true);
	BROADCAST(&mgr->wkstatecond);
	UNLOCK(&mgr->lock);
}

void
isc__nm_acquire_interlocked_force(isc_nm_t *mgr) {
	LOCK(&mgr->lock);
	while (!atomic_compare_exchange_strong(&mgr->interlocked,
					       &(bool){false}, true))
	{
		WAIT(&mgr->wkstatecond, &mgr->lock);
	}
	UNLOCK(&mgr->lock);
}
