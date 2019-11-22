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

#include <isc/astack.h>
#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/queue.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#define ISC_NETMGR_TID_UNKNOWN -1
#define ISC_NETMGR_TID_NOTLS -2

/*
 * Single network event loop worker.
 */
typedef struct isc__networker {
	isc_nm_t *		   mgr;
	int			   id;          /* thread id */
	uv_loop_t		   loop;        /* libuv loop structure */
	uv_async_t		   async;       /* async channel to send
						 * data to this networker */
	isc_mutex_t		   lock;
	isc_condition_t		   cond;
	bool			   paused;
	bool			   finished;
	isc_thread_t		   thread;
	isc_queue_t		   *ievents;     /* incoming async events */
	isc_refcount_t		   references;
	atomic_int_fast64_t	   pktcount;
	char			   recvbuf[65536];
	bool			   recvbuf_inuse;
} isc__networker_t;

/*
 * A general handle for a connection bound to a networker.  For UDP
 * connections we have peer address here, so both TCP and UDP can be
 * handled with a simple send-like function
 */
#define NMHANDLE_MAGIC                        ISC_MAGIC('N', 'M', 'H', 'D')
#define VALID_NMHANDLE(t)                     ISC_MAGIC_VALID(t, \
							      NMHANDLE_MAGIC)

typedef void (*isc__nm_closecb)(isc_nmhandle_t *);

struct isc_nmhandle {
	int			magic;
	isc_refcount_t		references;

	/*
	 * The socket is not 'attached' in the traditional
	 * reference-counting sense. Instead, we keep all handles in an
	 * array in the socket object.  This way, we don't have circular
	 * dependencies and we can close all handles when we're destroying
	 * the socket.
	 */
	isc_nmsocket_t		*sock;
	size_t			ah_pos;    /* Position in the socket's
					    * 'active handles' array */

	/*
	 * The handle is 'inflight' if netmgr is not currently processing
	 * it in any way - it might mean that e.g. a recursive resolution
	 * is happening. For an inflight handle we must wait for the
	 * calling code to finish before we can free it.
	 */
	atomic_bool		inflight;

	isc_sockaddr_t		peer;
	isc_sockaddr_t		local;
	isc_nm_opaquecb_t	doreset; /* reset extra callback, external */
	isc_nm_opaquecb_t	dofree;  /* free extra callback, external */
	void *			opaque;
	char			extra[];
};

/*
 * An interface - an address we can listen on.
 */
struct isc_nmiface {
	isc_sockaddr_t        addr;
};

typedef enum isc__netievent_type {
	netievent_stop,
	netievent_udplisten,
	netievent_udpstoplisten,
	netievent_udpsend,
	netievent_udprecv,
	netievent_tcpconnect,
	netievent_tcpsend,
	netievent_tcprecv,
	netievent_tcpstartread,
	netievent_tcppauseread,
	netievent_tcplisten,
	netievent_tcpstoplisten,
	netievent_tcpclose,
	netievent_closecb,
} isc__netievent_type;

typedef struct isc__netievent_stop {
	isc__netievent_type        type;
} isc__netievent_stop_t;

/*
 * We have to split it because we can read and write on a socket
 * simultaneously.
 */
typedef union {
	isc_nm_recv_cb_t	recv;
	isc_nm_cb_t	  	accept;
} isc__nm_readcb_t;

typedef union {
	isc_nm_cb_t	   	send;
	isc_nm_cb_t	   	connect;
} isc__nm_writecb_t;

typedef union {
	isc_nm_recv_cb_t	recv;
	isc_nm_cb_t		accept;
	isc_nm_cb_t		send;
	isc_nm_cb_t		connect;
} isc__nm_cb_t;

/*
 * Wrapper around uv_req_t with 'our' fields in it.  req->data should
 * always point to its parent.  Note that we always allocate more than
 * sizeof(struct) because we make room for different req types;
 */
#define UVREQ_MAGIC                        ISC_MAGIC('N', 'M', 'U', 'R')
#define VALID_UVREQ(t)                     ISC_MAGIC_VALID(t, UVREQ_MAGIC)

typedef struct isc__nm_uvreq {
	int			magic;
	isc_nmsocket_t *	sock;
	isc_nmhandle_t *	handle;
	uv_buf_t		uvbuf;	/* translated isc_region_t, to be
					   sent or received */
	isc_sockaddr_t		local;	/* local address */
	isc_sockaddr_t		peer;	/* peer address */
	isc__nm_cb_t		cb;	/* callback */
	void *			cbarg;	/* callback argument */
	union {
		uv_req_t		req;
		uv_getaddrinfo_t	getaddrinfo;
		uv_getnameinfo_t	getnameinfo;
		uv_shutdown_t		shutdown;
		uv_write_t		write;
		uv_connect_t		connect;
		uv_udp_send_t		udp_send;
		uv_fs_t			fs;
		uv_work_t		work;
	} uv_req;
} isc__nm_uvreq_t;

typedef struct isc__netievent__socket {
	isc__netievent_type	type;
	isc_nmsocket_t		*sock;
} isc__netievent__socket_t;

typedef isc__netievent__socket_t isc__netievent_udplisten_t;
typedef isc__netievent__socket_t isc__netievent_udpstoplisten_t;
typedef isc__netievent__socket_t isc__netievent_tcpstoplisten_t;
typedef isc__netievent__socket_t isc__netievent_tcpclose_t;
typedef isc__netievent__socket_t isc__netievent_startread_t;
typedef isc__netievent__socket_t isc__netievent_pauseread_t;
typedef isc__netievent__socket_t isc__netievent_resumeread_t;
typedef isc__netievent__socket_t isc__netievent_closecb_t;

typedef struct isc__netievent__socket_req {
	isc__netievent_type	type;
	isc_nmsocket_t		*sock;
	isc__nm_uvreq_t		*req;
} isc__netievent__socket_req_t;

typedef isc__netievent__socket_req_t isc__netievent_tcpconnect_t;
typedef isc__netievent__socket_req_t isc__netievent_tcplisten_t;
typedef isc__netievent__socket_req_t isc__netievent_tcpsend_t;

typedef struct isc__netievent_udpsend {
	isc__netievent_type	type;
	isc_nmsocket_t		*sock;
	isc_sockaddr_t		peer;
	isc__nm_uvreq_t		*req;
} isc__netievent_udpsend_t;

typedef struct isc__netievent {
	isc__netievent_type	type;
} isc__netievent_t;

typedef union {
		isc__netievent_t		  ni;
		isc__netievent_stop_t		  nis;
		isc__netievent_udplisten_t	  niul;
		isc__netievent_udpsend_t	  nius;
} isc__netievent_storage_t;

/*
 * Network manager
 */
#define NM_MAGIC                        ISC_MAGIC('N', 'E', 'T', 'M')
#define VALID_NM(t)                     ISC_MAGIC_VALID(t, NM_MAGIC)

struct isc_nm {
	int			magic;
	isc_refcount_t		references;
	isc_mem_t		*mctx;
	uint32_t		nworkers;
	isc_mutex_t		lock;
	isc_condition_t		wkstatecond;
	isc__networker_t	*workers;

	isc_mempool_t		*reqpool;
	isc_mutex_t		reqlock;

	isc_mempool_t		*evpool;
	isc_mutex_t		evlock;

	atomic_uint_fast32_t	workers_running;
	atomic_uint_fast32_t	workers_paused;
	atomic_uint_fast32_t	maxudp;
	atomic_bool		paused;

	/*
	 * A worker is actively waiting for other workers, for example to
	 * stop listening; that means no other thread can do the same thing
	 * or pause, or we'll deadlock. We have to either re-enqueue our
	 * event or wait for the other one to finish if we want to pause.
	 */
	atomic_bool		interlocked;

	/*
	 * Timeout values for TCP connections, coresponding to
	 * tcp-intiial-timeout, tcp-idle-timeout, tcp-keepalive-timeout,
	 * and tcp-advertised-timeout. Note that these are stored in
	 * milliseconds so they can be used directly with the libuv timer,
	 * but they are configured in tenths of seconds.
	 */
	uint32_t		init;
	uint32_t		idle;
	uint32_t		keepalive;
	uint32_t		advertised;
};

typedef enum isc_nmsocket_type {
	isc_nm_udpsocket,
	isc_nm_udplistener, /* Aggregate of nm_udpsocks */
	isc_nm_tcpsocket,
	isc_nm_tcplistener,
	isc_nm_tcpdnslistener,
	isc_nm_tcpdnssocket
} isc_nmsocket_type;

/*%
 * A universal structure for either a single socket or a group of
 * dup'd/SO_REUSE_PORT-using sockets listening on the same interface.
 */
#define NMSOCK_MAGIC                    ISC_MAGIC('N', 'M', 'S', 'K')
#define VALID_NMSOCK(t)                 ISC_MAGIC_VALID(t, NMSOCK_MAGIC)

struct isc_nmsocket {
	/*% Unlocked, RO */
	int			magic;
	int			tid;
	isc_nmsocket_type	type;
	isc_nm_t		*mgr;
	isc_nmsocket_t		*parent;
	isc_quota_t		*quota;
	bool			overquota;
	uv_timer_t		timer;
	bool			timer_initialized;
	uint64_t		read_timeout;

	/*% outer socket is for 'wrapped' sockets - e.g. tcpdns in tcp */
	isc_nmsocket_t		*outer;

	/*% server socket for connections */
	isc_nmsocket_t		*server;

	/*% children sockets for multi-socket setups */
	isc_nmsocket_t		*children;
	int			nchildren;
	isc_nmiface_t		*iface;
	isc_nmhandle_t		*tcphandle;

	/*% extra data allocated at the end of each isc_nmhandle_t */
	size_t			extrahandlesize;

	/*% libuv data */
	uv_os_sock_t		fd;
	union uv_any_handle	uv_handle;

	isc_sockaddr_t		peer;

	/* Atomic */
	/*% Number of running (e.g. listening) children sockets */
	atomic_int_fast32_t     rchildren;

	/*%
	 * Socket if active if it's listening, working, etc., if we're
	 * closing a socket it doesn't make any sense to e.g. still
	 * push handles or reqs for reuse
	 */
	atomic_bool        	active;
	atomic_bool	   	destroying;

	/*%
	 * Socket is closed if it's not active and all the possible
	 * callbacks were fired, there are no active handles, etc.
	 * active==false, closed==false means the socket is closing.
	 */
	atomic_bool	      	closed;
	atomic_bool	      	listening;
	isc_refcount_t	      	references;

	/*%
	 * TCPDNS socket has been set not to pipeliine.
	 */
	atomic_bool		sequential;

	/*%
	 * TCPDNS socket has exceeded the maximum number of
	 * simultaneous requests per connecton, so will be temporarily
	 * restricted from pipelining.
	 */
	atomic_bool		overlimit;

	/*%
	 * TCPDNS socket in sequential mode is currently processing a packet,
	 * we need to wait until it finishes.
	 */
	atomic_bool		processing;

	/*%
	 * A TCP socket has had isc_nm_pauseread() called.
	 */
	atomic_bool		readpaused;

	/*%
	 * A TCP or TCPDNS socket has been set to use the keepalive
	 * timeout instead of the default idle timeout.
	 */
	atomic_bool		keepalive;

	/*%
	 * 'spare' handles for that can be reused to avoid allocations,
	 * for UDP.
	 */
	isc_astack_t 		*inactivehandles;
	isc_astack_t 		*inactivereqs;

	/* Used for active/rchildren during shutdown */
	isc_mutex_t		lock;
	isc_condition_t		cond;

	/*%
	 * List of active handles.
	 * ah - current position in 'ah_frees'; this represents the
	 *	current number of active handles;
	 * ah_size - size of the 'ah_frees' and 'ah_handles' arrays
	 * ah_handles - array pointers to active handles
	 *
	 * Adding a handle
	 *  - if ah == ah_size, reallocate
	 *  - x = ah_frees[ah]
	 *  - ah_frees[ah++] = 0;
	 *  - ah_handles[x] = handle
	 *  - x must be stored with the handle!
	 * Removing a handle:
	 *  - ah_frees[--ah] = x
	 *  - ah_handles[x] = NULL;
	 *
	 * XXX: for now this is locked with socket->lock, but we
	 * might want to change it to something lockless in the
	 * future.
	 */
	atomic_int_fast32_t     ah;
	size_t			ah_size;
	size_t			*ah_frees;
	isc_nmhandle_t		**ah_handles;

	/* Buffer for TCPDNS processing, optional */
	size_t			buf_size;
	size_t			buf_len;
	unsigned char		*buf;

	/*
	 * This function will be called with handle->sock
	 * as the argument whenever a handle's references drop
	 * to zero, after its reset callback has been called.
	 */
	isc_nm_opaquecb_t	closehandle_cb;

	isc__nm_readcb_t	rcb;
	void			*rcbarg;
};

bool
isc__nm_in_netthread(void);
/*%
 * Returns 'true' if we're in the network thread.
 */

void *
isc__nm_get_ievent(isc_nm_t *mgr, isc__netievent_type type);
/*%<
 * Allocate an ievent and set the type.
 */
void
isc__nm_put_ievent(isc_nm_t *mgr, void *ievent);

void
isc__nm_enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event);
/*%<
 * Enqueue an ievent onto a specific worker queue. (This the only safe
 * way to use an isc__networker_t from another thread.)
 */

void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
/*%<
 * Allocator for recv operations.
 *
 * Note that as currently implemented, this doesn't actually
 * allocate anything, it just assigns the the isc__networker's UDP
 * receive buffer to a socket, and marks it as "in use".
 */

void
isc__nm_free_uvbuf(isc_nmsocket_t *sock, const uv_buf_t *buf);
/*%<
 * Free a buffer allocated for a receive operation.
 *
 * Note that as currently implemented, this doesn't actually
 * free anything, marks the isc__networker's UDP receive buffer
 * as "not in use".
 */


isc_nmhandle_t *
isc__nmhandle_get(isc_nmsocket_t *sock, isc_sockaddr_t *peer,
		  isc_sockaddr_t *local);
/*%<
 * Get a handle for the socket 'sock', allocating a new one
 * if there isn't one availbale in 'sock->inactivehandles'.
 *
 * If 'peer' is not NULL, set the handle's peer address to 'peer',
 * otherwise set it to 'sock->peer'.
 *
 * If 'local' is not NULL, set the handle's local address to 'local',
 * otherwise set it to 'sock->iface->addr'.
 */

isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *sock);
/*%<
 * Get a UV request structure for the socket 'sock', allocating a
 * new one if there isn't one availbale in 'sock->inactivereqs'.
 */

void
isc__nm_uvreq_put(isc__nm_uvreq_t **req, isc_nmsocket_t *sock);
/*%<
 * Completes the use of a UV request structure, setting '*req' to NULL.
 *
 * The UV request is pushed onto the 'sock->inactivereqs' stack or,
 * if that doesn't work, freed.
 */

void
isc__nmsocket_init(isc_nmsocket_t *sock, isc_nm_t *mgr,
		   isc_nmsocket_type type);
/*%<
 * Initialize socket 'sock', attach it to 'mgr', and set it to type 'type'.
 */

void
isc__nmsocket_prep_destroy(isc_nmsocket_t *sock);
/*%<
 * Market 'sock' as inactive, close it if necessary, and destroy it
 * if there are no remaining references or active handles.
 */

void
isc__nm_async_closecb(isc__networker_t *worker, isc__netievent_t *ievent0);
/*%<
 * Issue a 'handle closed' callback on the socket.
 */

isc_result_t
isc__nm_udp_send(isc_nmhandle_t *handle, isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg);
/*%<
 * Back-end implemenation of isc_nm_send() for UDP handles.
 */

void
isc__nm_async_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0);

void
isc__nm_async_udpstoplisten(isc__networker_t *worker,
			    isc__netievent_t *ievent0);
void
isc__nm_async_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0);
/*%<
 * Callback handlers for asynchronous UDP events (listen, stoplisten, send).
 */

isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle, isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg);
/*%<
 * Back-end implemenation of isc_nm_send() for TCP handles.
 */

void
isc__nm_tcp_close(isc_nmsocket_t *sock);
/*%<
 * Close a TCP socket.
 */

void
isc__nm_async_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_tcpstoplisten(isc__networker_t *worker,
			    isc__netievent_t *ievent0);
void
isc__nm_async_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_startread(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_pauseread(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_resumeread(isc__networker_t *worker, isc__netievent_t *ievent0);
void
isc__nm_async_tcpclose(isc__networker_t *worker, isc__netievent_t *ievent0);
/*%<
 * Callback handlers for asynchronous TCP events (connect, listen,
 * stoplisten, send, read, pauseread, resumeread, close).
 */


isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle, isc_region_t *region,
		    isc_nm_cb_t cb, void *cbarg);
/*%<
 * Back-end implemenation of isc_nm_send() for TCPDNS handles.
 */

void
isc__nm_tcpdns_close(isc_nmsocket_t *sock);
/*%<
 * Close a TCPDNS socket.
 */

#define isc__nm_uverr2result(x) \
	isc___nm_uverr2result(x, true, __FILE__, __LINE__)
isc_result_t
isc___nm_uverr2result(int uverr, bool dolog,
		      const char *file, unsigned int line);
/*%<
 * Convert a libuv error value into an isc_result_t.  The
 * list of supported error values is not complete; new users
 * of this function should add any expected errors that are
 * not already there.
 */

bool
isc__nm_acquire_interlocked(isc_nm_t *mgr);
/*%<
 * Try to acquire interlocked state; return true if successful.
 */

void
isc__nm_drop_interlocked(isc_nm_t *mgr);
/*%<
 * Drop interlocked state; signal waiters.
 */

void
isc__nm_acquire_interlocked_force(isc_nm_t *mgr);
/*%<
 * Actively wait for interlocked state.
 */
