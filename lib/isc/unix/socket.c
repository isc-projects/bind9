/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <config.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/thread.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/socket.h>
#include <isc/list.h>

#include "util.h"

/*
 * Some systems define the socket length argument as an int, some as size_t,
 * some as socklen_t.  This is here, so it can be easily changed if needed.
 */
#ifndef ISC_SOCKADDR_LEN_T
#define ISC_SOCKADDR_LEN_T int
#endif

/*
 * As above, one system (solaris) wants the pointers passed into recv() and
 * the other network functions to be char *.  All the others seem to use
 * void *.  Cast everything to char * for now.
 */
#ifndef ISC_SOCKDATA_CAST
#define ISC_SOCKDATA_CAST(x) ((char *)(x))
#endif

/*
 * If we cannot send to this task, the application is broken.
 */
#define ISC_TASK_SEND(a, b) do { \
	RUNTIME_CHECK(isc_task_send(a, b) == ISC_R_SUCCESS); \
} while (0)

/*
 * Define what the possible "soft" errors can be.  These are non-fatal returns
 * of various network related functions, like recv() and so on.
 *
 * For some reason, BSDI (and perhaps others) will sometimes return <0
 * from recv() but will have errno==0.  This is broken, but we have to
 * work around it here.
 */
#define SOFT_ERROR(e)	((e) == EAGAIN || \
			 (e) == EWOULDBLOCK || \
			 (e) == EINTR || \
			 (e) == 0)

#if 0
#define ISC_SOCKET_DEBUG
#endif

#if defined(ISC_SOCKET_DEBUG)
#define TRACE_WATCHER	0x0001
#define TRACE_LISTEN	0x0002
#define TRACE_CONNECT	0x0004
#define TRACE_RECV	0x0008
#define TRACE_SEND    	0x0010
#define TRACE_MANAGER	0x0020

int trace_level = TRACE_WATCHER | TRACE_MANAGER | TRACE_CONNECT;
#define XTRACE(l, a)	do { if ((l) & trace_level) printf a; } while (0)
#define XENTER(l, a)	do {						\
				if ((l) & trace_level)			\
					printf("ENTER %s\n", (a));	\
			} while (0)
#define XEXIT(l, a)	do {						\
				if ((l) & trace_level)			\
					printf("EXIT %s\n", (a));	\
			} while (0)
#else
#define XTRACE(l, a)
#define XENTER(l, a)
#define XEXIT(l, a)
#endif

/*
 * Internal event used to send readable/writable events to our internal
 * functions.
 */
typedef struct rwintev {
	isc_event_t			common;	   /* Sender is the socket. */
	isc_task_t		       *task;	   /* task to send these to */
	isc_socketevent_t	       *done_ev;   /* the done event to post */
	isc_boolean_t			canceled;  /* I/O was canceled */
	isc_boolean_t			posted;	   /* event posted to task */
	ISC_LINK(struct rwintev)	link;	   /* next event */
} rwintev_t;

typedef struct intev intev_t;
struct intev {
	ISC_EVENT_COMMON(intev_t);
};

typedef struct cnintev {
	isc_event_t			common;	   /* Sender is the socket */
	isc_task_t		       *task;	   /* task to send these to */
	isc_socket_connev_t	       *done_ev;   /* the done event */
	isc_boolean_t			canceled;  /* connect was canceled */
	isc_boolean_t			posted;	   /* event posted to task */
} cnintev_t;

#define SOCKET_MAGIC		0x494f696fU	/* IOio */
#define VALID_SOCKET(t)		((t) != NULL && (t)->magic == SOCKET_MAGIC)

struct isc_socket {
	/* Not locked. */
	unsigned int			magic;
	isc_socketmgr_t		       *manager;
	isc_mutex_t			lock;
	isc_sockettype_t		type;

	/* Locked by socket lock. */
	unsigned int			references;
	int				fd;
	isc_result_t			recv_result;
	isc_result_t			send_result;
	ISC_LIST(rwintev_t)		recv_list;
	ISC_LIST(rwintev_t)		send_list;

	ISC_LIST(isc_socket_newconnev_t)	accept_list;
	intev_t				readable_ev;

	cnintev_t		       *connect_ev;
	unsigned int			pending_recv : 1,
					pending_send : 1,
					pending_accept : 1,
					listener : 1, /* listener socket */
					connected : 1,
					connecting : 1; /* connect pending */
	rwintev_t		       *riev; /* allocated recv intev */
	rwintev_t		       *wiev; /* allocated send intev */
	cnintev_t		       *ciev; /* allocated accept intev */
	isc_sockaddr_t			address;  /* remote address */
	int				addrlength; /* remote addrlen */
};

#define SOCKET_MANAGER_MAGIC		0x494f6d67U	/* IOmg */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == SOCKET_MANAGER_MAGIC)
struct isc_socketmgr {
	/* Not locked. */
	unsigned int			magic;
	isc_mem_t		       *mctx;
	isc_mutex_t			lock;
	/* Locked by manager lock. */
	unsigned int			nsockets;  /* sockets managed */
	isc_thread_t			watcher;
	isc_condition_t			shutdown_ok;
	fd_set				read_fds;
	fd_set				write_fds;
	isc_socket_t		       *fds[FD_SETSIZE];
	int				fdstate[FD_SETSIZE];
	int				maxfd;
	int				pipe_fds[2];
};

#define CLOSED		0	/* this one must be zero */
#define MANAGED		1
#define CLOSE_PENDING	2

static void send_recvdone_event(isc_socket_t *, isc_task_t **, rwintev_t **,
				isc_socketevent_t **, isc_result_t);
static void send_senddone_event(isc_socket_t *, isc_task_t **, rwintev_t **,
				isc_socketevent_t **, isc_result_t);
static void free_socket(isc_socket_t **);
static isc_result_t allocate_socket(isc_socketmgr_t *, isc_sockettype_t,
				    isc_socket_t **);
static void destroy(isc_socket_t **);
static void internal_accept(isc_task_t *, isc_event_t *);
static void internal_connect(isc_task_t *, isc_event_t *);
static void internal_recv(isc_task_t *, isc_event_t *);
static void internal_send(isc_task_t *, isc_event_t *);

#define SELECT_POKE_SHUTDOWN		(-1)
#define SELECT_POKE_NOTHING		(-2)
#define SELECT_POKE_RESCAN		(-3) /* XXX implement */

/*
 * Poke the select loop when there is something for us to do.
 * We assume that if a write completes here, it will be inserted into the
 * queue fully.  That is, we will not get partial writes.
 */
static void
select_poke(isc_socketmgr_t *mgr, int msg)
{
	int cc;

	do {
		cc = write(mgr->pipe_fds[1], &msg, sizeof(int));
	} while (cc < 0 && SOFT_ERROR(errno));

	if (cc < 0)
		FATAL_ERROR(__FILE__, __LINE__,
			    "write() failed during watcher poke: %s",
			    strerror(errno));

	INSIST(cc == sizeof(int));
}

/*
 * read a message on the internal fd.
 */
static int
select_readmsg(isc_socketmgr_t *mgr)
{
	int msg;
	int cc;

	cc = read(mgr->pipe_fds[0], &msg, sizeof(int));
	if (cc < 0) {
		if (SOFT_ERROR(errno))
			return (SELECT_POKE_NOTHING);

		FATAL_ERROR(__FILE__, __LINE__,
			    "read() failed during watcher poke: %s",
			    strerror(errno));

		return (SELECT_POKE_NOTHING);
	}

	return (msg);
}

/*
 * Make a fd non-blocking
 */
static isc_result_t
make_nonblock(int fd)
{
	int ret;
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);

	if (ret == -1) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "fcntl(%d, F_SETFL, %d): %s",
				 fd, flags, strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

#ifdef ISC_SOCKET_DEBUG
static void
socket_dump(isc_socket_t *sock)
{
	rwintev_t *	rwiev;
	ncintev_t *	aiev;

	printf("--------\nDump of socket %p\n", sock);
	printf("fd: %d, references %u\n", sock->fd, sock->references);

	printf("recv queue:\n");
	rwiev = ISC_LIST_HEAD(sock->recv_list);
	while (rwiev != NULL) {
		printf("\tintev %p, done_ev %p, task %p, "
		       "canceled %d, posted %d\n",
		       rwiev, rwiev->done_ev, rwiev->task, rwiev->canceled,
		       rwiev->posted);
		rwiev = ISC_LIST_NEXT(rwiev, link);
	}

	printf("send queue:\n");
	rwiev = ISC_LIST_HEAD(sock->send_list);
	while (rwiev != NULL) {
		printf("\tintev %p, done_ev %p, task %p, "
		       "canceled %d, posted %d\n",
		       rwiev, rwiev->done_ev, rwiev->task, rwiev->canceled,
		       rwiev->posted);
		rwiev = ISC_LIST_NEXT(rwiev, link);
	}

	printf("accept queue:\n");
	aiev = sock->accept_ev;
	printf("\tintev %p, task %p, canceled %d, posted %d\n",
	       aiev, aiev->task, aiev->canceled, aiev->posted);

	printf("--------\n");
}
#endif

/*
 * Kill.
 *
 * Caller must ensure locking.
 */
static void
destroy(isc_socket_t **sockp)
{
	isc_socket_t *sock = *sockp;
	isc_socketmgr_t *manager = sock->manager;

	XTRACE(TRACE_MANAGER,
	       ("destroy sockp = %p, sock = %p\n", sockp, sock));

	if (sock->riev)
		isc_event_free((isc_event_t **)&sock->riev);
	if (sock->wiev)
		isc_event_free((isc_event_t **)&sock->wiev);
	if (sock->ciev)
		isc_event_free((isc_event_t **)&sock->ciev);
	if (sock->connect_ev)
		isc_event_free((isc_event_t **)&sock->connect_ev);

	LOCK(&manager->lock);

	/*
	 * Noone has this socket open, so the watcher doesn't have to be
	 * poked, and the socket doesn't have to be locked.
	 */
	manager->fds[sock->fd] = NULL;
	manager->fdstate[sock->fd] = CLOSE_PENDING;
	select_poke(sock->manager, sock->fd);
	manager->nsockets--;
	XTRACE(TRACE_MANAGER, ("nsockets == %d\n", manager->nsockets));
	if (manager->nsockets == 0)
		SIGNAL(&manager->shutdown_ok);

	/*
	 * XXX should reset manager->maxfd here
	 */

	UNLOCK(&manager->lock);

	free_socket(sockp);
}

static isc_result_t
allocate_socket(isc_socketmgr_t *manager, isc_sockettype_t type,
		isc_socket_t **socketp)
{
	isc_socket_t *sock;
	isc_result_t ret;

	sock = isc_mem_get(manager->mctx, sizeof *sock);

	if (sock == NULL)
		return (ISC_R_NOMEMORY);

	ret = ISC_R_UNEXPECTED;

	sock->magic = 0;
	sock->references = 0;

	sock->manager = manager;
	sock->type = type;
	sock->fd = -1;

	/*
	 * set up list of readers and writers to be initially empty
	 */
	ISC_LIST_INIT(sock->recv_list);
	ISC_LIST_INIT(sock->send_list);
	sock->connect_ev = NULL;
	sock->pending_recv = 0;
	sock->pending_send = 0;
	sock->pending_accept = 0;
	sock->listener = 0;
	sock->connected = 0;
	sock->connecting = 0;
	sock->riev = NULL;
	sock->wiev = NULL;
	sock->ciev = NULL;

	ISC_LIST_INIT(sock->accept_list);

	sock->addrlength = 0;

	sock->recv_result = ISC_R_SUCCESS;
	sock->send_result = ISC_R_SUCCESS;

	/*
	 * initialize the lock
	 */
	if (isc_mutex_init(&sock->lock) != ISC_R_SUCCESS) {
		sock->magic = 0;
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		ret = ISC_R_UNEXPECTED;
		goto err1;
	}

	/*
	 * Initialize readable event
	 */
	ISC_EVENT_INIT(&sock->readable_ev, sizeof(intev_t),
		       ISC_EVENTATTR_NOPURGE, 0, ISC_SOCKEVENT_INTR,
		       NULL, sock, sock, NULL, NULL);

	sock->magic = SOCKET_MAGIC;
	*socketp = sock;

	return (ISC_R_SUCCESS);

 err1: /* socket allocated */
	isc_mem_put(manager->mctx, sock, sizeof *sock);

	return (ret);
}

/*
 * This event requires that the various lists be empty, that the reference
 * count be 1, and that the magic number is valid.  The other socket bits,
 * like the lock, must be initialized as well.  The fd associated must be
 * marked as closed, by setting it to -1 on close, or this routine will
 * also close the socket.
 */
static void
free_socket(isc_socket_t **socketp)
{
	isc_socket_t *sock = *socketp;

#ifdef ISC_SOCKET_DEBUG
	socket_dump(sock);
#endif
	REQUIRE(sock->references == 0);
	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(!sock->connecting);
	REQUIRE(!sock->pending_recv);
	REQUIRE(!sock->pending_send);
	REQUIRE(!sock->pending_accept);
	REQUIRE(EMPTY(sock->recv_list));
	REQUIRE(EMPTY(sock->send_list));

	sock->magic = 0;

	(void)isc_mutex_destroy(&sock->lock);

	isc_mem_put(sock->manager->mctx, sock, sizeof *sock);

	*socketp = NULL;
}

/*
 * Create a new 'type' socket managed by 'manager'.  The sockets
 * parameters are specified by 'expires' and 'interval'.  Events
 * will be posted to 'task' and when dispatched 'action' will be
 * called with 'arg' as the arg value.  The new socket is returned
 * in 'socketp'.
 */
isc_result_t
isc_socket_create(isc_socketmgr_t *manager, isc_sockettype_t type,
		  isc_socket_t **socketp)
{
	isc_socket_t *sock = NULL;
	isc_result_t ret;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(socketp != NULL && *socketp == NULL);

	XENTER(TRACE_MANAGER, "isc_socket_create");
	
	ret = allocate_socket(manager, type, &sock);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	switch (type) {
	case isc_socket_udp:
		sock->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		break;
	case isc_socket_tcp:
		sock->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		break;
	}
	if (sock->fd < 0) {
		free_socket(&sock);

		switch (errno) {
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
			return (ISC_R_NORESOURCES);
			/* NOTREACHED */
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "socket() failed: %s",
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
			/* NOTREACHED */
			break;
		}
	}

	if (make_nonblock(sock->fd) != ISC_R_SUCCESS) {
		free_socket(&sock);
		return (ISC_R_UNEXPECTED);
	}

	sock->references = 1;
	*socketp = sock;

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the socket like we normally would because
	 * there are no external references to it yet.
	 */

	manager->fds[sock->fd] = sock;
	manager->fdstate[sock->fd] = MANAGED;
	manager->nsockets++;
	XTRACE(TRACE_MANAGER, ("nsockets == %d\n", manager->nsockets));
	if (manager->maxfd < sock->fd)
		manager->maxfd = sock->fd;

	UNLOCK(&manager->lock);

	XEXIT(TRACE_MANAGER, "isc_socket_create");

	return (ISC_R_SUCCESS);
}

/*
 * Attach to a socket.  Caller must explicitly detach when it is done.
 */
void
isc_socket_attach(isc_socket_t *sock, isc_socket_t **socketp)
{
	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(socketp != NULL && *socketp == NULL);

	LOCK(&sock->lock);
	sock->references++;
	UNLOCK(&sock->lock);
	
	*socketp = sock;
}

/*
 * Dereference a socket.  If this is the last reference to it, clean things
 * up by destroying the socket.
 */
void 
isc_socket_detach(isc_socket_t **socketp)
{
	isc_socket_t *sock;
	isc_boolean_t kill_socket = ISC_FALSE;

	REQUIRE(socketp != NULL);
	sock = *socketp;
	REQUIRE(VALID_SOCKET(sock));

	XENTER(TRACE_MANAGER, "isc_socket_detach");

	LOCK(&sock->lock);
	REQUIRE(sock->references > 0);
	sock->references--;
	if (sock->references == 0)
		kill_socket = ISC_TRUE;
	UNLOCK(&sock->lock);
	
	if (kill_socket)
		destroy(&sock);

	XEXIT(TRACE_MANAGER, "isc_socket_detach");

	*socketp = NULL;
}

/*
 * I/O is possible on a given socket.  Schedule an event to this task that
 * will call an internal function to do the I/O.  This will charge the
 * task with the I/O operation and let our select loop handler get back
 * to doing something real as fast as possible.
 *
 * The socket and manager must be locked before calling this function.
 */
static void
dispatch_read(isc_socket_t *sock)
{
	rwintev_t *iev;
	isc_event_t *ev;

	iev = ISC_LIST_HEAD(sock->recv_list);
	ev = (isc_event_t *)iev;

	REQUIRE(!sock->pending_recv);

	sock->pending_recv = 1;

	XTRACE(TRACE_WATCHER, ("dispatch_read:  posted event %p to task %p\n",
			       ev, iev->task));

	iev->posted = ISC_TRUE;

	ISC_TASK_SEND(iev->task, &ev);
}

static void
dispatch_write(isc_socket_t *sock)
{
	rwintev_t *iev;
	isc_event_t *ev;

	iev = ISC_LIST_HEAD(sock->send_list);
	ev = (isc_event_t *)iev;

	REQUIRE(!sock->pending_send);
	sock->pending_send = 1;

	iev->posted = ISC_TRUE;

	ISC_TASK_SEND(iev->task, &ev);
}

/*
 * Dispatch an internal accept event.
 */
static void
dispatch_accept(isc_socket_t *sock)
{
	intev_t *iev;
	isc_socket_newconnev_t *ev;

	iev = &sock->readable_ev;
	ev = ISC_LIST_HEAD(sock->accept_list);

	INSIST(ev != NULL);
	INSIST(!sock->pending_accept);

	sock->references++;  /* keep socket around for this internal event */
	iev->sender = sock;
	iev->action = internal_accept;
	iev->arg = sock;
	sock->pending_accept = 1;

	ISC_TASK_SEND(ev->sender, (isc_event_t **)&iev);
}

static void
dispatch_connect(isc_socket_t *sock)
{
	cnintev_t *iev;

	REQUIRE(sock->connecting);

	iev = sock->connect_ev;

	iev->posted = ISC_TRUE;

	ISC_TASK_SEND(iev->task, (isc_event_t **)&iev);
}

/*
 * Dequeue an item off the given socket's read queue, set the result code
 * in the done event to the one provided, and send it to the task it was
 * destined for.
 *
 * Entry:  socket is a valid, locked socket.
 *	   *task is a valid task.
 *	   if iev != NULL, *iev must be valid, and the first item on the
 *		socket's receive queue.
 *	   *dev is a valid done event.
 *	   resultcode is the code to be set within the done event.
 *
 * Exit:   task is detached iff iev != NULL
 *         iev is freed if != NULL
 *         done event is sent to the task.
 *
 * Caller must have the socket locked.
 */
static void
send_recvdone_event(isc_socket_t *sock, isc_task_t **task,
		    rwintev_t **iev,
		    isc_socketevent_t **dev, isc_result_t resultcode)
{
	REQUIRE(dev != NULL);
	REQUIRE(*dev != NULL);
	REQUIRE(task != NULL);
	REQUIRE(*task != NULL);

	if (iev != NULL) {
		REQUIRE(!EMPTY(sock->recv_list));
		REQUIRE(*iev != NULL);
		REQUIRE((*iev)->task == *task);

		ISC_LIST_DEQUEUE(sock->recv_list, *iev, link);
	}

	(*dev)->result = resultcode;
	ISC_TASK_SEND(*task, (isc_event_t **)dev);

	/*
	 * task might be an element in iev, so it cannot be used after iev
	 * is freed!
	 */
	if (iev != NULL) {
		isc_task_detach(task);
		(*iev)->done_ev = NULL;
		isc_event_free((isc_event_t **)iev);
	}
}

/*
 * See comments for send_recvdone_event() above.
 *
 * Caller must have the socket locked.
 */
static void
send_senddone_event(isc_socket_t *sock, isc_task_t **task,
		    rwintev_t **iev,
		    isc_socketevent_t **dev, isc_result_t resultcode)
{
	REQUIRE(dev != NULL);
	REQUIRE(*dev != NULL);
	REQUIRE(task != NULL);
	REQUIRE(*task != NULL);

	if (iev != NULL) {
		REQUIRE(*iev != NULL);
		REQUIRE(!EMPTY(sock->send_list));
		REQUIRE((*iev)->task == *task);

		ISC_LIST_DEQUEUE(sock->send_list, *iev, link);
	}

	(*dev)->result = resultcode;
	ISC_TASK_SEND(*task, (isc_event_t **)dev);

	/*
	 * task might be an element in iev, so it cannot be used after iev
	 * is freed!
	 */
	if (iev != NULL) {
		isc_task_detach(task);
		(*iev)->done_ev = NULL;
		isc_event_free((isc_event_t **)iev);
	}
}

/*
 * Call accept() on a socket, to get the new file descriptor.  The listen
 * socket is used as a prototype to create a new isc_socket_t.  The new
 * socket has one outstanding reference.  The task receiving the event
 * will be detached from just after the event is delivered.
 *
 * On entry to this function, the event delivered is the internal
 * readable event, and the first item on the accept_list should be
 * the done event we want to send.  If the list is empty, this is a no-op,
 * so just unlock and return.
 */
static void
internal_accept(isc_task_t *task, isc_event_t *ev)
{
	isc_socket_t *sock;
	isc_socketmgr_t *manager;
	isc_socket_newconnev_t *dev;
	intev_t *iev = (intev_t *)ev;
	struct sockaddr addr;
	ISC_SOCKADDR_LEN_T addrlen;
	int fd;
	isc_result_t result = ISC_R_SUCCESS;

	sock = ev->sender;
	REQUIRE(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	XTRACE(TRACE_LISTEN,
	       ("internal_accept called, locked parent sock %p\n", sock));

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	INSIST(sock->listener);

	/*
	 * Reset the internal event, since we no longer need it.  It was
	 * used only to get us here, and is unused in the remainder of this
	 * function.
	 */
	iev = (intev_t *)ev;
	iev = NULL;  /* Make certain we don't use this anymore */
	INSIST(sock->references > 0);
	sock->references--;  /* the internal event is done with this socket */
	if (sock->references == 0) {
		UNLOCK(&sock->lock);
		destroy(&sock);
		return;
	}

	INSIST(sock->pending_accept);
	sock->pending_accept = 0;

	/*
	 * Get the first item off the accept list.
	 * If it is empty, unlock the socket and return.
	 */
	dev = ISC_LIST_HEAD(sock->accept_list);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return;
	}

	/*
	 * Try to accept the new connection.  If the accept fails with
	 * EAGAIN or EINTR, simply poke the watcher to watch this socket
	 * again.
	 */
	addrlen = sizeof(addr);
	fd = accept(sock->fd, &addr, &addrlen);
	if (fd < 0) {
		if (SOFT_ERROR(errno)) {
			select_poke(sock->manager, sock->fd);
			UNLOCK(&sock->lock);
			return;
		}

		/*
		 * If some other error, ignore it as well and hope
		 * for the best, but log it.
		 */
		XTRACE(TRACE_LISTEN, ("internal_accept: accept returned %s\n",
				      strerror(errno)));

		fd = -1;

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "internal_accept: accept() failed: %s",
				 strerror(errno));

		result = ISC_R_UNEXPECTED;
	}

	/*
	 * Pull off the done event.
	 */
	ISC_LIST_UNLINK(sock->accept_list, dev, link);

	/*
	 * Poke watcher if there are more pending accepts.
	 */
	if (!EMPTY(sock->accept_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);

	if (fd != -1 && (make_nonblock(fd) != ISC_R_SUCCESS)) {
		close(fd);
		fd = -1;

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "internal_accept: make_nonblock() failed: %s",
				 strerror(errno));

		result = ISC_R_UNEXPECTED;
	}

	/*
	 * -1 means the new socket didn't happen.
	 */
	if (fd != -1) {
		dev->newsocket->fd = fd;

		/*
		 * Save away the remote address
		 */
		dev->newsocket->addrlength = addrlen;
		memcpy(&dev->newsocket->address, &addr, addrlen);
		dev->addrlength = addrlen;
		memcpy(&dev->address, &addr, addrlen);

		LOCK(&manager->lock);
		manager->fds[fd] = dev->newsocket;
		manager->fdstate[fd] = MANAGED;
		if (manager->maxfd < fd)
			manager->maxfd = fd;
		manager->nsockets++;
		XTRACE(TRACE_MANAGER, ("nsockets == %d\n", manager->nsockets));
		UNLOCK(&manager->lock);

		XTRACE(TRACE_LISTEN, ("internal_accept: newsock %p, fd %d\n",
				      dev->newsocket, fd));
	}

	/*
	 * Fill in the done event details and send it off.
	 */
	dev->result = result;
	task = (isc_task_t *)(dev->sender);
	dev->sender = sock;

	ISC_TASK_SEND(task, (isc_event_t **)&dev);
	isc_task_detach(&task);
}

static void
internal_recv(isc_task_t *task, isc_event_t *ev)
{
	rwintev_t *iev;
	isc_socketevent_t *dev;
	isc_socket_t *sock;
	int cc;
	size_t read_count;
	struct sockaddr addr;
	ISC_SOCKADDR_LEN_T addrlen;

	/*
	 * Find out what socket this is and lock it.
	 */
	sock = (isc_socket_t *)ev->sender;
	LOCK(&sock->lock);

	INSIST(sock->pending_recv == 1);
	sock->pending_recv = 0;

	XTRACE(TRACE_RECV,
	       ("internal_recv: sock %p, fd %d\n", sock, sock->fd));

	/*
	 * Pull the first entry off the list, and look at it.  If it is
	 * NULL, or not ours, something bad happened.
	 */
	iev = ISC_LIST_HEAD(sock->recv_list);
	INSIST(iev != NULL);
	INSIST(iev->task == task);

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum read count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	do {
		iev = ISC_LIST_HEAD(sock->recv_list);
		dev = iev->done_ev;

		/*
		 * check for canceled I/O
		 */
		if (iev->canceled) {
			ISC_LIST_DEQUEUE(sock->recv_list, iev, link);
			isc_event_free((isc_event_t **)&iev);
			goto next;
		}

		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->common.type == ISC_SOCKEVENT_RECVMARK) {
			send_recvdone_event(sock, &iev->task, &iev, &dev,
					    sock->recv_result);
			goto next;
		}

		/*
		 * It must be a read request.  Try to satisfy it as best
		 * we can.
		 */
		read_count = dev->region.length - dev->n;
		if (sock->type == isc_socket_udp) {
			addrlen = sizeof(addr);
			cc = recvfrom(sock->fd,
				      ISC_SOCKDATA_CAST(dev->region.base
							+ dev->n),
				      read_count, 0,
				      (struct sockaddr *)&addr,
				      &addrlen);
			if (cc >= 0) {
				memcpy(&dev->address, &addr, addrlen);
				dev->addrlength = addrlen;
			}
		} else {
			cc = recv(sock->fd,
				  ISC_SOCKDATA_CAST(dev->region.base + dev->n),
				  read_count, 0);
			if (cc >= 0) {
				memcpy(&dev->address, &sock->address,
				       (size_t)sock->addrlength);
				dev->addrlength = sock->addrlength;
			}
		}			

		XTRACE(TRACE_RECV,
		       ("internal_recv:  read(%d) %d\n", sock->fd, cc));

		/*
		 * check for error or block condition
		 */
		if (cc < 0) {
			if (SOFT_ERROR(errno))
				goto poke;

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			if (sock->type == isc_socket_tcp) \
				sock->recv_result = _isc; \
			send_recvdone_event(sock, &iev->task, &iev, \
					    &dev, _isc); \
		} \
		goto next; \
	}

			SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
			SOFT_OR_HARD(ENETUNREACH, ISC_R_NETUNREACH);
			SOFT_OR_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#undef SOFT_OR_HARD

			/*
			 * This might not be a permanent error.
			 */
			if (errno == ENOBUFS) {
				send_recvdone_event(sock, &iev->task,
						    &iev, &dev,
						    ISC_R_NORESOURCES);

				goto next;
			}

			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal read: %s", strerror(errno));

			sock->recv_result = ISC_R_UNEXPECTED;
			send_recvdone_event(sock, &iev->task, &iev, &dev,
					    ISC_R_UNEXPECTED);

			goto next;
		}

		/*
		 * read of 0 means the remote end was closed.  Run through
		 * the event queue and dispatch all the events with an EOF
		 * result code.  This will set the EOF flag in markers as
		 * well, but that's really ok.
		 */
		if ((sock->type == isc_socket_tcp) && (cc == 0)) {
			do {
				send_recvdone_event(sock, &iev->task,
						    &iev, &dev,
						    ISC_R_EOF);
				iev = ISC_LIST_HEAD(sock->recv_list);
			} while (iev != NULL);

			goto poke;
		}

		/*
		 * if we read less than we expected, update counters,
		 * poke.
		 */
		if ((size_t)cc < read_count) {
			dev->n += cc;

			/*
			 * If partial reads are allowed, we return whatever
			 * was read with a success result, and continue
			 * the loop.
			 */
			if (dev->partial) {
				send_recvdone_event(sock, &iev->task,
						    &iev, &dev,
						    ISC_R_SUCCESS);
				goto next;
			}

			/*
			 * Partials not ok.  Exit the loop and notify the
			 * watcher to wait for more reads
			 */
			goto poke;
		}

		/*
		 * Exactly what we wanted to read.  We're done with this
		 * entry.  Post its completion event.
		 */
		if ((size_t)cc == read_count) {
			dev->n += read_count;
			send_recvdone_event(sock, &iev->task, &iev, &dev,
					    ISC_R_SUCCESS);
		}

	next:
		; /* some compilers need this here... */
	} while (!EMPTY(sock->recv_list));

 poke:
	if (!EMPTY(sock->recv_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);
}

static void
internal_send(isc_task_t *task, isc_event_t *ev)
{
	rwintev_t *iev;
	isc_socketevent_t *dev;
	isc_socket_t *sock;
	int cc;
	size_t write_count;

	/*
	 * Find out what socket this is and lock it.
	 */
	sock = (isc_socket_t *)ev->sender;
	LOCK(&sock->lock);

	INSIST(sock->pending_send == 1);
	sock->pending_send = 0;

	XTRACE(TRACE_SEND,
	       ("internal_send: sock %p, fd %d\n", sock, sock->fd));

	/*
	 * Pull the first entry off the list, and look at it.  If it is
	 * NULL, or not ours, something bad happened.
	 */
	iev = ISC_LIST_HEAD(sock->send_list);
	INSIST(iev != NULL);
	INSIST(iev->task == task);

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum write count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	do {
		iev = ISC_LIST_HEAD(sock->send_list);
		dev = iev->done_ev;

		/*
		 * check for canceled I/O
		 */
		if (iev->canceled) {
			ISC_LIST_DEQUEUE(sock->send_list, iev, link);
			isc_event_free((isc_event_t **)&iev);
			goto next;
		}

		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->common.type == ISC_SOCKEVENT_SENDMARK) {
			send_senddone_event(sock, &iev->task, &iev, &dev,
					    sock->send_result);
			goto next;
		}

		/*
		 * It must be a write request.  Try to satisfy it as best
		 * we can.
		 */
		write_count = dev->region.length - dev->n;
		if (sock->type == isc_socket_udp)
			cc = sendto(sock->fd,
				    ISC_SOCKDATA_CAST(dev->region.base
						      + dev->n),
				    write_count, 0,
				    (struct sockaddr *)&dev->address,
				    (int)dev->addrlength);

		else
			cc = send(sock->fd,
				  ISC_SOCKDATA_CAST(dev->region.base + dev->n),
				  write_count, 0);

		/*
		 * check for error or block condition
		 */
		if (cc < 0) {
			if (SOFT_ERROR(errno))
				goto poke;

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			if (sock->type == isc_socket_tcp) \
				sock->send_result = _isc; \
			send_senddone_event(sock, &iev->task, &iev, \
					    &dev, _isc); \
		} \
		goto next; \
	}

			SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
			SOFT_OR_HARD(ENETUNREACH, ISC_R_NETUNREACH);
			SOFT_OR_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#undef SOFT_OR_HARD

			/*
			 * This might not be a permanent error.
			 */
			if (errno == ENOBUFS) {
				send_senddone_event(sock, &iev->task, &iev,
						    &dev, ISC_R_NORESOURCES);

				goto next;
			}

			/*
			 * The other error types depend on whether or not the
			 * socket is UDP or TCP.  If it is UDP, some errors
			 * that we expect to be fatal under TCP are merely
			 * annoying, and are really soft errors.
			 *
			 * However, these soft errors are still returned as
			 * a status.
			 */
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_send: %s",
					 strerror(errno));
			sock->send_result = ISC_R_UNEXPECTED;
			send_senddone_event(sock, &iev->task, &iev, &dev,
					    ISC_R_UNEXPECTED);

			goto next;
		}

		if (cc == 0)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_send: send() returned 0");

		/*
		 * if we write less than we expected, update counters,
		 * poke.
		 */
		if ((size_t)cc < write_count) {
			dev->n += cc;

			goto poke;
		}

		/*
		 * Exactly what we wanted to write.  We're done with this
		 * entry.  Post its completion event.
		 */
		if ((size_t)cc == write_count) {
			dev->n += write_count;
			send_senddone_event(sock, &iev->task,
					    &iev, &dev, ISC_R_SUCCESS);

			goto next;
		}

	next:
		; /* some compilers need this here... */
	} while (!EMPTY(sock->send_list));

 poke:
	if (!EMPTY(sock->send_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);
}

/*
 * This is the thread that will loop forever, always in a select or poll
 * call.
 *
 * When select returns something to do, track down what thread gets to do
 * this I/O and post the event to it.
 */
static isc_threadresult_t
watcher(void *uap)
{
	isc_socketmgr_t *manager = uap;
	isc_socket_t *sock;
	isc_boolean_t done;
	int ctlfd;
	int cc;
	fd_set readfds;
	fd_set writefds;
	int msg;
	isc_boolean_t unlock_sock;
	int i;
	rwintev_t *iev;
	isc_event_t *ev2;
	int maxfd;

	/*
	 * Get the control fd here.  This will never change.
	 */
	LOCK(&manager->lock);
	ctlfd = manager->pipe_fds[0];

	done = ISC_FALSE;
	while (!done) {
		do {
			readfds = manager->read_fds;
			writefds = manager->write_fds;
			maxfd = manager->maxfd + 1;

#ifdef ISC_SOCKET_DEBUG
			XTRACE(TRACE_WATCHER, ("select maxfd %d\n", maxfd));
			for (i = 0 ; i < FD_SETSIZE ; i++) {
				int printit;

				printit = 0;

				if (FD_ISSET(i, &readfds)) {
					printf("watcher: select r on %d\n", i);
					printit = 1;
				}
				if (FD_ISSET(i, &writefds)) {
					printf("watcher: select w on %d\n", i);
					printit = 1;
				}

				if (printit && manager->fds[i] != NULL)
					socket_dump(manager->fds[i]);
			}
#endif
					
			UNLOCK(&manager->lock);

			cc = select(maxfd, &readfds, &writefds, NULL, NULL);
			XTRACE(TRACE_WATCHER,
			       ("select(%d, ...) == %d, errno %d\n",
				maxfd, cc, errno));
			if (cc < 0) {
				if (!SOFT_ERROR(errno))
					FATAL_ERROR(__FILE__, __LINE__,
						    "select failed: %s",
						    strerror(errno));
			}

			LOCK(&manager->lock);
		} while (cc < 0);


		/*
		 * Process reads on internal, control fd.
		 */
		if (FD_ISSET(ctlfd, &readfds)) {
			while (1) {
				msg = select_readmsg(manager);

				XTRACE(TRACE_WATCHER,
				       ("watcher got message %d\n", msg));

				/*
				 * Nothing to read?
				 */
				if (msg == SELECT_POKE_NOTHING)
					break;

				/*
				 * handle shutdown message.  We really should
				 * jump out of this loop right away, but
				 * it doesn't matter if we have to do a little
				 * more work first.
				 */
				if (msg == SELECT_POKE_SHUTDOWN) {
					XTRACE(TRACE_WATCHER,
					       ("watcher got SHUTDOWN\n"));
					done = ISC_TRUE;

					break;
				}

				/*
				 * This is a wakeup on a socket.  Look
				 * at the event queue for both read and write,
				 * and decide if we need to watch on it now
				 * or not.
				 */
				if (msg >= 0) {
					INSIST(msg < FD_SETSIZE);

					if (manager->fdstate[msg] ==
					    CLOSE_PENDING) {
						manager->fdstate[msg] = CLOSED;
						FD_CLR(msg,
						       &manager->read_fds);
						FD_CLR(msg,
						       &manager->write_fds);

						close(msg);
						XTRACE(TRACE_WATCHER,
						       ("Watcher closed %d\n",
							msg));

						continue;
					}

					if (manager->fdstate[msg] != MANAGED)
						continue;

					sock = manager->fds[msg];

					LOCK(&sock->lock);
					XTRACE(TRACE_WATCHER,
					       ("watcher locked socket %p\n",
						sock));

					/*
					 * If there are no events, or there
					 * is an event but we have already
					 * queued up the internal event on a
					 * task's queue, clear the bit.
					 * Otherwise, set it.
					 */
					iev = ISC_LIST_HEAD(sock->recv_list);
					ev2 = (isc_event_t *)ISC_LIST_HEAD(sock->accept_list);
					if ((iev == NULL && ev2 == NULL)
					    || sock->pending_recv
					    || sock->pending_accept) {
						FD_CLR(sock->fd,
						       &manager->read_fds);
						XTRACE(TRACE_WATCHER,
						       ("watch cleared r\n"));
					} else {
						FD_SET(sock->fd,
						       &manager->read_fds);
						XTRACE(TRACE_WATCHER,
						       ("watch set r\n"));
					}

					iev = ISC_LIST_HEAD(sock->send_list);
					if ((iev == NULL
					     || sock->pending_send)
					    && !sock->connecting) {
						FD_CLR(sock->fd,
						       &manager->write_fds);
						XTRACE(TRACE_WATCHER,
						       ("watch cleared w\n"));
					} else {
						FD_SET(sock->fd,
						       &manager->write_fds);
						XTRACE(TRACE_WATCHER,
						       ("watch set w\n"));
					}

					UNLOCK(&sock->lock);
				}
			}
		}

		/*
		 * Process read/writes on other fds here.  Avoid locking
		 * and unlocking twice if both reads and writes are possible.
		 */
		for (i = 0 ; i < maxfd ; i++) {
			if (i == manager->pipe_fds[0]
			    || i == manager->pipe_fds[1])
				continue;

			if (manager->fdstate[i] == CLOSE_PENDING) {
				manager->fdstate[i] = CLOSED;
				FD_CLR(i, &manager->read_fds);
				FD_CLR(i, &manager->write_fds);
				
				close(i);
				XTRACE(TRACE_WATCHER,
				       ("Watcher closed %d\n", i));
				
				continue;
			}

			sock = manager->fds[i];
			unlock_sock = ISC_FALSE;
			if (FD_ISSET(i, &readfds)) {
				if (sock == NULL) {
					FD_CLR(i, &manager->read_fds);
					goto check_write;
				}
				XTRACE(TRACE_WATCHER,
				       ("watcher r on %d, sock %p\n",
					i, manager->fds[i]));
				unlock_sock = ISC_TRUE;
				LOCK(&sock->lock);
				if (sock->listener)
					dispatch_accept(sock);
				else
					dispatch_read(sock);
				FD_CLR(i, &manager->read_fds);
			}
		check_write:
			if (FD_ISSET(i, &writefds)) {
				if (sock == NULL) {
					FD_CLR(i, &manager->write_fds);
					continue;
				}
				XTRACE(TRACE_WATCHER,
				       ("watcher w on %d, sock %p\n",
					i, manager->fds[i]));
				if (!unlock_sock) {
					unlock_sock = ISC_TRUE;
					LOCK(&sock->lock);
				}
				if (sock->connecting)
					dispatch_connect(sock);
				else
					dispatch_write(sock);
				FD_CLR(i, &manager->write_fds);
			}
			if (unlock_sock)
				UNLOCK(&sock->lock);
		}
	}

	XTRACE(TRACE_WATCHER, ("Watcher exiting\n"));

	UNLOCK(&manager->lock);
	return ((isc_threadresult_t)0);
}

/*
 * Create a new socket manager.
 */
isc_result_t
isc_socketmgr_create(isc_mem_t *mctx, isc_socketmgr_t **managerp)
{
	isc_socketmgr_t *manager;

	REQUIRE(managerp != NULL && *managerp == NULL);

	XENTER(TRACE_MANAGER, "isc_socketmgr_create");

	manager = isc_mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);
	
	manager->magic = SOCKET_MANAGER_MAGIC;
	manager->mctx = mctx;
	memset(manager->fds, 0, sizeof(manager->fds));
	manager->nsockets = 0;
	if (isc_mutex_init(&manager->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	if (isc_condition_init(&manager->shutdown_ok) != ISC_R_SUCCESS) {
		(void)isc_mutex_destroy(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Create the special fds that will be used to wake up the
	 * select/poll loop when something internal needs to be done.
	 */
	if (pipe(manager->pipe_fds) != 0) {
		(void)isc_mutex_destroy(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "pipe() failed: %s",
				 strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	RUNTIME_CHECK(make_nonblock(manager->pipe_fds[0]) == ISC_R_SUCCESS);
	RUNTIME_CHECK(make_nonblock(manager->pipe_fds[1]) == ISC_R_SUCCESS);

	/*
	 * Set up initial state for the select loop
	 */
	FD_ZERO(&manager->read_fds);
	FD_ZERO(&manager->write_fds);
	FD_SET(manager->pipe_fds[0], &manager->read_fds);
	manager->maxfd = manager->pipe_fds[0];
	memset(manager->fdstate, 0, sizeof(manager->fdstate));

	/*
	 * Start up the select/poll thread.
	 */
	if (isc_thread_create(watcher, manager, &manager->watcher) !=
	    ISC_R_SUCCESS) {
		(void)isc_mutex_destroy(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_create() failed");
		close(manager->pipe_fds[0]);
		close(manager->pipe_fds[1]);
		return (ISC_R_UNEXPECTED);
	}

	*managerp = manager;

	XEXIT(TRACE_MANAGER, "isc_socketmgr_create (normal)");
	return (ISC_R_SUCCESS);
}

void
isc_socketmgr_destroy(isc_socketmgr_t **managerp)
{
	isc_socketmgr_t *manager;
	int i;

	/*
	 * Destroy a socket manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);

	XTRACE(TRACE_MANAGER, ("nsockets == %d\n", manager->nsockets));
	/*
	 * Wait for all sockets to be destroyed.
	 */
	while (manager->nsockets != 0) {
		XTRACE(TRACE_MANAGER, ("nsockets == %d\n", manager->nsockets));
		WAIT(&manager->shutdown_ok, &manager->lock);
	}

	UNLOCK(&manager->lock);

	/*
	 * Here, poke our select/poll thread.  Do this by closing the write
	 * half of the pipe, which will send EOF to the read half.
	 */
	select_poke(manager, SELECT_POKE_SHUTDOWN);

	/*
	 * Wait for thread to exit.
	 */
	if (isc_thread_join(manager->watcher, NULL) != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_join() failed");

	/*
	 * Clean up.
	 */
	close(manager->pipe_fds[0]);
	close(manager->pipe_fds[1]);

	for (i = 0 ; i < FD_SETSIZE ; i++)
		if (manager->fdstate[i] == CLOSE_PENDING)
			close(i);

	(void)isc_condition_destroy(&manager->shutdown_ok);
	(void)isc_mutex_destroy(&manager->lock);
	manager->magic = 0;
	isc_mem_put(manager->mctx, manager, sizeof *manager);

	*managerp = NULL;
}

isc_result_t
isc_socket_recv(isc_socket_t *sock, isc_region_t *region,
		isc_boolean_t partial, isc_task_t *task,
		isc_taskaction_t action, void *arg)
{
	isc_socketevent_t *dev;
	rwintev_t *iev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	int cc;

	manager = sock->manager;

	dev = (isc_socketevent_t *)isc_event_allocate(manager->mctx, sock,
						      ISC_SOCKEVENT_RECVDONE,
						      action, arg,
						      sizeof(*dev));
	if (dev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	if (sock->riev == NULL) {
		iev = (rwintev_t *)isc_event_allocate(manager->mctx,
						      sock,
						      ISC_SOCKEVENT_INTRECV,
						      internal_recv,
						      sock,
						      sizeof(*iev));
		if (iev == NULL) {
			/* no special free routine yet */
			isc_event_free((isc_event_t **)&dev);
			UNLOCK(&sock->lock);
			return (ISC_R_NOMEMORY);
		}

		ISC_LINK_INIT(iev, link);
		iev->posted = ISC_FALSE;


		sock->riev = iev;
		iev = NULL;  /* just in case */
	}

	/*
	 * UDP sockets are always partial read
	 */
	if (sock->type == isc_socket_udp)
		partial = ISC_TRUE;

	dev->region = *region;
	dev->n = 0;
	dev->result = ISC_R_SUCCESS;
	dev->partial = partial;

	/*
	 * If the read queue is empty, try to do the I/O right now.
	 */
	if (EMPTY(sock->recv_list)) {
		if (sock->type == isc_socket_udp) {
			ISC_SOCKADDR_LEN_T addrlen;
			dev->addrlength = sizeof(isc_sockaddr_t);
			addrlen = (ISC_SOCKADDR_LEN_T)dev->addrlength;
			cc = recvfrom(sock->fd,
				      ISC_SOCKDATA_CAST(dev->region.base),
				      dev->region.length, 0,
				      (struct sockaddr *)&dev->address,
				      &addrlen);
			dev->addrlength = (unsigned int)addrlen;
		} else {
			/*
			 * recv() is used on TCP sockets, since some OSs
			 * don't like recvfrom() being called on TCP sockets.
			 * Failures range from function failure returns to
			 * the addresses not being filled in properly.
			 */
			cc = recv(sock->fd,
				  ISC_SOCKDATA_CAST(dev->region.base),
				  dev->region.length, 0);
			dev->address = sock->address;
			dev->addrlength = sock->addrlength;
		}

		if (cc < 0) {
			if (SOFT_ERROR(errno))
				goto queue;

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			if (sock->type == isc_socket_tcp) \
				sock->recv_result = _isc; \
			send_recvdone_event(sock, &task, NULL, &dev, _isc); \
		} \
		select_poke(sock->manager, sock->fd); \
		goto out; \
	}

			SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
			SOFT_OR_HARD(ENETUNREACH, ISC_R_NETUNREACH);
			SOFT_OR_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#undef SOFT_OR_HARD

			/*
			 * This might not be a permanent error.
			 */
			if (errno == ENOBUFS) {
				send_recvdone_event(sock, &task, NULL, &dev,
						    ISC_R_NORESOURCES);

				goto queue;
			}

			sock->recv_result = ISC_R_UNEXPECTED;
			send_recvdone_event(sock, &task, NULL, &dev,
					    ISC_R_UNEXPECTED);

			UNLOCK(&sock->lock);
			return (ISC_R_SUCCESS);
		}

		/*
		 * On TCP, zero length reads indicate EOF, while on
		 * UDP, zero length reads are perfectly valid, although
		 * strange.
		 */
		if ((sock->type == isc_socket_tcp) && (cc == 0)) {
			sock->recv_result = ISC_R_EOF;
			send_recvdone_event(sock, &task, NULL,
					    &dev, ISC_R_EOF);

			UNLOCK(&sock->lock);
			return (ISC_R_SUCCESS);
		}

		dev->n = cc;

		/*
		 * Partial reads need to be queued
		 */
		if ((size_t)cc != dev->region.length && !partial)
			goto queue;

		/*
		 * full reads are posted, or partials if partials are ok.
		 */
		send_recvdone_event(sock, &task, NULL, &dev, ISC_R_SUCCESS);

		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

	/*
	 * We couldn't read all or part of the request right now, so queue
	 * it.
	 */
 queue:
	iev = sock->riev;
	sock->riev = NULL;

	isc_task_attach(task, &ntask);

	iev->done_ev = dev;
	iev->task = ntask;
	iev->canceled = ISC_FALSE;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	if (EMPTY(sock->recv_list)) {
		ISC_LIST_ENQUEUE(sock->recv_list, iev, link);
		select_poke(sock->manager, sock->fd);
	} else {
		ISC_LIST_ENQUEUE(sock->recv_list, iev, link);
	}

	XTRACE(TRACE_RECV,
	       ("isc_socket_recv: posted ievent %p, dev %p, task %p\n",
		iev, iev->done_ev, task));

 out:
	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_send(isc_socket_t *sock, isc_region_t *region,
		isc_task_t *task, isc_taskaction_t action, void *arg)
{
	return (isc_socket_sendto(sock, region, task, action, arg, NULL, 0));
}

isc_result_t
isc_socket_sendto(isc_socket_t *sock, isc_region_t *region,
		  isc_task_t *task, isc_taskaction_t action, void *arg,
		  isc_sockaddr_t *address, unsigned int addrlen)
{
	isc_socketevent_t *dev;
	rwintev_t *iev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	int cc;
	ISC_SOCKADDR_LEN_T addrlength = (ISC_SOCKADDR_LEN_T)addrlen;

	REQUIRE(VALID_SOCKET(sock));

	manager = sock->manager;

	dev = (isc_socketevent_t *)isc_event_allocate(manager->mctx, sock,
						      ISC_SOCKEVENT_SENDDONE,
						      action, arg,
						      sizeof(*dev));
	if (dev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	if (sock->wiev == NULL) {
		iev = (rwintev_t *)isc_event_allocate(manager->mctx,
						      sock,
						      ISC_SOCKEVENT_INTSEND,
						      internal_send,
						      sock,
						      sizeof(*iev));
		if (iev == NULL) {
			/* no special free routine yet */
			isc_event_free((isc_event_t **)&dev);
			UNLOCK(&sock->lock);
			return (ISC_R_NOMEMORY);
		}

		ISC_LINK_INIT(iev, link);
		iev->posted = ISC_FALSE;

		sock->wiev = iev;
		iev = NULL;  /* just in case */
	}

	dev->region = *region;
	dev->n = 0;
	dev->result = ISC_R_SUCCESS;
	dev->partial = ISC_FALSE; /* doesn't matter */

	/*
	 * If the write queue is empty, try to do the I/O right now.
	 */
	if (sock->type == isc_socket_udp) {
		INSIST(addrlength > 0 || sock->addrlength > 0);
		if (addrlength > 0) {
			dev->address = *address;
			dev->addrlength = addrlength;
		} else if (sock->addrlength > 0) {
			dev->address = sock->address;
			dev->addrlength = sock->addrlength;
		}
	} else if (sock->type == isc_socket_tcp) {
		INSIST(address == NULL);
		INSIST(addrlength == 0);
		dev->address = sock->address;
		dev->addrlength = sock->addrlength;
	}

	if (EMPTY(sock->send_list)) {
		if (sock->type == isc_socket_udp)
			cc = sendto(sock->fd,
				    ISC_SOCKDATA_CAST(dev->region.base),
				    dev->region.length, 0,
				    (struct sockaddr *)&dev->address,
				    (int)dev->addrlength);
		else if (sock->type == isc_socket_tcp)
			cc = send(sock->fd,
				  ISC_SOCKDATA_CAST(dev->region.base),
				  dev->region.length, 0);
		else {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_socket_send: "
					 "unknown socket type");
			UNLOCK(&sock->lock);
			return (ISC_R_UNEXPECTED);
		}

		if (cc < 0) {
			if (SOFT_ERROR(errno))
				goto queue;

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			if (sock->type == isc_socket_tcp) \
				sock->send_result = _isc; \
			send_senddone_event(sock, &task, NULL, &dev, _isc); \
		} \
		select_poke(sock->manager, sock->fd); \
		goto out; \
	}

			SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
			SOFT_OR_HARD(ENETUNREACH, ISC_R_NETUNREACH);
			SOFT_OR_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#undef SOFT_OR_HARD

			/*
			 * This might not be a permanent error.
			 */
			if (errno == ENOBUFS) {
				send_senddone_event(sock, &task, NULL, &dev,
						    ISC_R_NORESOURCES);

				goto out;
			}

			sock->send_result = ISC_R_UNEXPECTED;
			send_senddone_event(sock, &task, NULL, &dev,
					    ISC_R_UNEXPECTED);

			UNLOCK(&sock->lock);
			return (ISC_R_SUCCESS);
		}

		dev->n = cc;

		/*
		 * Partial writes need to be queued
		 */
		if ((size_t)cc != dev->region.length)
			goto queue;

		/*
		 * full writes are posted.
		 */
		send_senddone_event(sock, &task, NULL, &dev, ISC_R_SUCCESS);

		UNLOCK(&sock->lock);

		return (ISC_R_SUCCESS);
	}

	/*
	 * We couldn't send all or part of the request right now, so queue
	 * it.
	 */
 queue:
	iev = sock->wiev;
	sock->wiev = NULL;

	isc_task_attach(task, &ntask);

	iev->done_ev = dev;
	iev->task = ntask;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	if (EMPTY(sock->send_list)) {
		ISC_LIST_ENQUEUE(sock->send_list, iev, link);
		select_poke(sock->manager, sock->fd);
	} else {
		ISC_LIST_ENQUEUE(sock->send_list, iev, link);
	}

	XTRACE(TRACE_SEND,
	       ("isc_socket_send: posted ievent %p, dev %p, task %p\n",
		iev, iev->done_ev, task));

 out:
	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_bind(isc_socket_t *sock, isc_sockaddr_t *sockaddr,
		int addrlen)
{
	int on = 1;

	LOCK(&sock->lock);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR,
		       ISC_SOCKDATA_CAST(&on), sizeof on) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__, "setsockopt(%d) failed",
				 sock->fd);
		/* Press on... */
	}
	if (bind(sock->fd, (struct sockaddr *)sockaddr, addrlen) < 0) {
		UNLOCK(&sock->lock);
		switch (errno) {
		case EACCES:
			return (ISC_R_NOPERM);
			/* NOTREACHED */
			break;
		case EADDRNOTAVAIL:
			return (ISC_R_ADDRNOTAVAIL);
			/* NOTREACHED */
			break;
		case EADDRINUSE:
			return (ISC_R_ADDRINUSE);
			/* NOTREACHED */
			break;
		case EINVAL:
			return (ISC_R_BOUND);
			/* NOTREACHED */
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "bind: %s", strerror(errno));
			return (ISC_R_UNEXPECTED);
			/* NOTREACHED */
			break;
		}
	}

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

/*
 * set up to listen on a given socket.  We do this by creating an internal
 * event that will be dispatched when the socket has read activity.  The
 * watcher will send the internal event to the task when there is a new
 * connection.
 *
 * Unlike in read, we don't preallocate a done event here.  Every time there
 * is a new connection we'll have to allocate a new one anyway, so we might
 * as well keep things simple rather than having to track them.
 */
isc_result_t
isc_socket_listen(isc_socket_t *sock, unsigned int backlog)
{
	REQUIRE(VALID_SOCKET(sock));

	LOCK(&sock->lock);

	REQUIRE(!sock->listener);
	REQUIRE(sock->type == isc_socket_tcp);

	if (backlog == 0)
		backlog = SOMAXCONN;

	if (listen(sock->fd, (int)backlog) < 0) {
		UNLOCK(&sock->lock);
		UNEXPECTED_ERROR(__FILE__, __LINE__, "listen: %s",
				 strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	sock->listener = 1;
	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

/*
 * This should try to do agressive accept() XXXMLG
 */
isc_result_t
isc_socket_accept(isc_socket_t *sock,
		  isc_task_t *task, isc_taskaction_t action, void *arg)
{
	isc_socket_newconnev_t *dev;
	isc_task_t *ntask = NULL;
	isc_socketmgr_t *manager;
	isc_socket_t *nsock;
	isc_result_t ret;

	XENTER(TRACE_LISTEN, "isc_socket_accept");

	REQUIRE(VALID_SOCKET(sock));
	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	REQUIRE(sock->listener);

	/*
	 * Sender field is overloaded here with the task we will be sending
	 * this event to.  Just before the actual event is delivered the
	 * actual sender will be touched up to be the socket.
	 */
	dev = (isc_socket_newconnev_t *)
		isc_event_allocate(manager->mctx, task, ISC_SOCKEVENT_NEWCONN,
				   action, arg, sizeof (*dev));
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	ret = allocate_socket(manager, sock->type, &nsock);
	if (ret != ISC_R_SUCCESS) {
		UNLOCK(&sock->lock);
		isc_event_free((isc_event_t **)&dev);
		return (ret);
	}

	/*
	 * Attach to socket and to task
	 */
	isc_task_attach(task, &ntask);
	nsock->references++;

	dev->sender = ntask;
	dev->newsocket = nsock;

	/*
	 * poke watcher here.  We still have the socket locked, so there
	 * is no race condition.  We will keep the lock for such a short
	 * bit of time waking it up now or later won't matter all that much.
	 */
	if (EMPTY(sock->accept_list))
		select_poke(manager, sock->fd);

	ISC_LIST_ENQUEUE(sock->accept_list, dev, link);

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_connect(isc_socket_t *sock, isc_sockaddr_t *addr, int addrlen,
		   isc_task_t *task, isc_taskaction_t action, void *arg)
{
	isc_socket_connev_t *dev;
	isc_task_t *ntask = NULL;
	isc_socketmgr_t *manager;
	int cc;

	XENTER(TRACE_CONNECT, "isc_socket_connect");
	REQUIRE(VALID_SOCKET(sock));
	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(addr != NULL);

	LOCK(&sock->lock);

	REQUIRE(!sock->connecting);

	if (sock->ciev == NULL) {
		sock->ciev = (cnintev_t *)
			isc_event_allocate(manager->mctx,
					   sock,
					   ISC_SOCKEVENT_INTCONN,
					   internal_connect,
					   sock,
					   sizeof(*(sock->ciev)));
		if (sock->ciev == NULL) {
			UNLOCK(&sock->lock);
			return (ISC_R_NOMEMORY);
		}

		sock->ciev->posted = ISC_FALSE;
	}

	dev = (isc_socket_connev_t *)isc_event_allocate(manager->mctx,
							sock,
							ISC_SOCKEVENT_CONNECT,
							action,
							arg,
							sizeof (*dev));
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	/*
	 * Try to do the connect right away, as there can be only one
	 * outstanding, and it might happen to complete.
	 */
	sock->address = *addr;
	sock->addrlength = addrlen;
	cc = connect(sock->fd, (struct sockaddr *)addr, addrlen);
	if (cc < 0) {
		if (SOFT_ERROR(errno) || errno == EINPROGRESS)
			goto queue;

		switch (errno) {
		case ECONNREFUSED:
			dev->result = ISC_R_CONNREFUSED;
			goto err_exit;
		case ENETUNREACH:
			dev->result = ISC_R_NETUNREACH;
			goto err_exit;
		}

		sock->connected = 0;

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "%s", strerror(errno));

		UNLOCK(&sock->lock);
		return (ISC_R_UNEXPECTED);

	err_exit:
		sock->connected = 0;
		ISC_TASK_SEND(task, (isc_event_t **)&dev);
		UNLOCK(&sock->lock);

		return (ISC_R_SUCCESS);
	}

	/*
	 * If connect completed, fire off the done event
	 */
	if (cc == 0) {
		sock->connected = 1;
		dev->result = ISC_R_SUCCESS;
		ISC_TASK_SEND(task, (isc_event_t **)&dev);
		UNLOCK(&sock->lock);

		return (ISC_R_SUCCESS);
	}

 queue:

	XTRACE(TRACE_CONNECT, ("queueing connect internal event\n"));
	/*
	 * Attach to to task
	 */
	isc_task_attach(task, &ntask);

	sock->connecting = 1;

	sock->ciev->task = ntask;
	sock->ciev->done_ev = dev;
	sock->ciev->canceled = ISC_FALSE;

	/*
	 * poke watcher here.  We still have the socket locked, so there
	 * is no race condition.  We will keep the lock for such a short
	 * bit of time waking it up now or later won't matter all that much.
	 */
	if (sock->connect_ev == NULL)
		select_poke(manager, sock->fd);

	sock->connect_ev = sock->ciev;
	sock->ciev = NULL;

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

/*
 * Called when a socket with a pending connect() finishes.
 */
static void
internal_connect(isc_task_t *task, isc_event_t *ev)
{
	isc_socket_t *sock;
	isc_socket_connev_t *dev;
	cnintev_t *iev;
	int cc;
	ISC_SOCKADDR_LEN_T optlen;

	sock = ev->sender;
	iev = (cnintev_t *)ev;

	REQUIRE(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	XTRACE(TRACE_CONNECT,
	       ("internal_connect called, locked parent sock %p\n", sock));

	REQUIRE(sock->connecting);
	REQUIRE(sock->connect_ev == (cnintev_t *)ev);
	REQUIRE(iev->task == task);

	sock->connect_ev = NULL;

	sock->connecting = 0;

	/*
	 * Has this event been canceled?
	 */
	if (iev->canceled) {
		isc_event_free((isc_event_t **)(sock->connect_ev));
		UNLOCK(&sock->lock);
		return;
	}

	dev = iev->done_ev;

	/*
	 * Get any possible error status here.
	 */
	optlen = sizeof(cc);
	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR,
		       (char *)&cc, &optlen) < 0)
		cc = errno;
	else
		errno = cc;

	if (errno != 0) {
		/*
		 * If the error is EAGAIN, just re-select on this
		 * fd and pretend nothing strange happened.
		 */
		if (SOFT_ERROR(errno) || errno == EINPROGRESS) {
			sock->connecting = 1;
			select_poke(sock->manager, sock->fd);
			UNLOCK(&sock->lock);

			return;
		}

		/*
		 * Translate other errors into ISC_R_* flavors.
		 */
		switch (errno) {
		case ETIMEDOUT:
			dev->result = ISC_R_TIMEDOUT;
			break;
		case ECONNREFUSED:
			dev->result = ISC_R_CONNREFUSED;
			break;
		case ENETUNREACH:
			dev->result = ISC_R_NETUNREACH;
			break;
		default:
			dev->result = ISC_R_UNEXPECTED;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_connect: connect() %s",
					 strerror(errno));
			break;
		}
	}


	UNLOCK(&sock->lock);

	ISC_TASK_SEND(iev->task, (isc_event_t **)&dev);
	isc_task_detach(&iev->task);
	iev->done_ev = NULL;
	isc_event_free((isc_event_t **)&iev);
}

isc_result_t
isc_socket_getpeername(isc_socket_t *sock, isc_sockaddr_t *addressp,
		       int *lengthp)
{
	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(addressp != NULL);
	REQUIRE(lengthp != NULL);

	LOCK(&sock->lock);

	if (*lengthp < sock->addrlength) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOSPACE);
	}

	memcpy(addressp, &sock->address, (size_t)sock->addrlength);
	*lengthp = sock->addrlength;

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_getsockname(isc_socket_t *sock, isc_sockaddr_t *addressp,
		       int *lengthp)
{
	isc_sockaddr_t addr;
	ISC_SOCKADDR_LEN_T len;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(addressp != NULL);
	REQUIRE(lengthp != NULL);

	LOCK(&sock->lock);

	len = sizeof(addr);
	if (getsockname(sock->fd, (struct sockaddr *)&addr, &len) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "getsockname: %s", strerror(errno));
		UNLOCK(&sock->lock);
		return (ISC_R_UNEXPECTED);
	}

	if ((unsigned int)*lengthp < (unsigned int)len) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOSPACE);
	}

	memcpy(addressp, &sock->address, (size_t)len);
	*lengthp = (unsigned int)len;

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

/*
 * Run through the list of events on this socket, and cancel the ones
 * queued for task "task" of type "how".  "how" is a bitmask.
 */
void
isc_socket_cancel(isc_socket_t *sock, isc_task_t *task,
		  unsigned int how)
{
	isc_boolean_t poke_needed;

	REQUIRE(VALID_SOCKET(sock));

	/*
	 * Quick exit if there is nothing to do.  Don't even bother locking
	 * in this case.
	 */
	if (how == 0)
		return;

	poke_needed = ISC_FALSE;

	LOCK(&sock->lock);

	/*
	 * All of these do the same thing, more or less.
	 * Each will:
	 *	o If the internal event is marked as "posted" try to
	 *	  remove it from the task's queue.  If this fails, mark it
	 *	  as canceled instead, and let the task clean it up later.
	 *	o For each I/O request for that task of that type, post
	 *	  its done event with status of "ISC_R_CANCELED".
	 *	o Reset any state needed.
	 */
	if (((how & ISC_SOCKCANCEL_RECV) == ISC_SOCKCANCEL_RECV)
	    && !EMPTY(sock->recv_list)) {
		rwintev_t 	       *iev;
		rwintev_t	       *next;
		isc_socketevent_t      *dev;
		isc_task_t	       *current_task;

		iev = ISC_LIST_HEAD(sock->recv_list);
		next = ISC_LIST_NEXT(iev, link);

		if ((task == NULL || task == iev->task) && !iev->canceled) {
			dev = iev->done_ev;
			current_task = iev->task;

			/*
			 * DEQUEUE here, and if the item cannot be removed
			 * from the task's queue, PREPEND it to the front
			 * of the list again, so the normal cleanup thing
			 * will occur.
			 */
			ISC_LIST_DEQUEUE(sock->recv_list, iev, link);
			if (iev->posted) {
				if (isc_task_purge(current_task, sock,
						   ISC_SOCKEVENT_INTRECV, 0)
				    == 0) {
					iev->canceled = ISC_TRUE;
					iev->done_ev = NULL;
					ISC_LIST_PREPEND(sock->recv_list,
							 iev, link);
				}
			} else {
				isc_event_free((isc_event_t **)&iev);
			}

			dev->result = ISC_R_CANCELED;
			ISC_TASK_SEND(current_task, (isc_event_t **)&dev);
			isc_task_detach(&current_task);
		}

		iev = next;

		/*
		 * run through the event queue, posting done events with the
		 * canceled result, and freeing the internal event.
		 */
		while (iev != NULL) {
			next = ISC_LIST_NEXT(iev, link);

			if (task == NULL || task == iev->task)
				send_recvdone_event(sock, &iev->task, &iev,
						    &iev->done_ev,
						    ISC_R_CANCELED);

			iev = next;
		}
	}

	if (((how & ISC_SOCKCANCEL_SEND) == ISC_SOCKCANCEL_SEND)
	    && !EMPTY(sock->send_list)) {
		rwintev_t 	       *iev;
		rwintev_t 	       *next;
		isc_socketevent_t      *dev;
		isc_task_t	       *current_task;

		iev = ISC_LIST_HEAD(sock->send_list);
		next = ISC_LIST_NEXT(iev, link);

		if ((task == NULL || task == iev->task) && !iev->canceled) {
			dev = iev->done_ev;
			current_task = iev->task;

			ISC_LIST_DEQUEUE(sock->send_list, iev, link);
			if (iev->posted) {
				if (isc_task_purge(current_task, sock,
						   ISC_SOCKEVENT_INTSEND, 0)
				    == 0) {
					iev->canceled = ISC_TRUE;
					iev->done_ev = NULL;
					ISC_LIST_PREPEND(sock->send_list,
							 iev, link);
				}
			} else {
				isc_event_free((isc_event_t **)&iev);
			}

			dev->result = ISC_R_CANCELED;
			ISC_TASK_SEND(current_task, (isc_event_t **)&dev);
			isc_task_detach(&current_task);
		}

		iev = next;

		while (iev != NULL) {
			next = ISC_LIST_NEXT(iev, link);

			if ((task == NULL) || (task == iev->task))
				send_senddone_event(sock, &iev->task, &iev,
						    &iev->done_ev,
						    ISC_R_CANCELED);

			iev = next;
		}
	}

	if (((how & ISC_SOCKCANCEL_ACCEPT) == ISC_SOCKCANCEL_ACCEPT)
	    && !EMPTY(sock->accept_list)) {
		isc_socket_newconnev_t *dev;
		isc_socket_newconnev_t *next;
		isc_task_t	       *current_task;

		dev = ISC_LIST_HEAD(sock->accept_list);
		while (dev != NULL) {
			current_task = dev->sender;
			next = ISC_LIST_NEXT(dev, link);

			if ((task == NULL) || (task == current_task)) {

				ISC_LIST_UNLINK(sock->accept_list, dev, link);

				dev->newsocket->references--;
				free_socket(&dev->newsocket);

				dev->result = ISC_R_CANCELED;
				dev->sender = sock;
				ISC_TASK_SEND(current_task,
					      (isc_event_t **)&dev);
				isc_task_detach(&current_task);
			}

			dev = next;
		}
	}

	/*
	 * Connecting is not a list.
	 */
	if (((how & ISC_SOCKCANCEL_CONNECT) == ISC_SOCKCANCEL_CONNECT)
	    && sock->connect_ev != NULL) {
		cnintev_t *		iev;
		isc_socket_connev_t    *dev;
		isc_task_t	       *current_task;

		iev = sock->connect_ev;
		dev = iev->done_ev;
		current_task = iev->task;

		if ((task == NULL || task == iev->task) && !iev->canceled) {
			sock->connect_ev = NULL;
			if (iev->posted) {
				if (isc_task_purge(current_task, sock,
						   ISC_SOCKEVENT_INTCONN, 0)
				    == 0) {
					iev->canceled = ISC_TRUE;
					iev->done_ev = NULL;
					sock->connect_ev = iev;
				}
			} else {
				isc_event_free((isc_event_t **)&iev);
			}

			dev->result = ISC_R_CANCELED;
			ISC_TASK_SEND(current_task, (isc_event_t **)&dev);
			isc_task_detach(&current_task);
		}
	}

	/*
	 * Need to guess if we need to poke or not... XXX
	 */
	select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);
}

isc_result_t
isc_socket_recvmark(isc_socket_t *sock,
		    isc_task_t *task, isc_taskaction_t action, void *arg)
{
	isc_socketevent_t *dev;
	rwintev_t *iev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;

	manager = sock->manager;

	dev = (isc_socketevent_t *)isc_event_allocate(manager->mctx, sock,
						      ISC_SOCKEVENT_RECVMARK,
						      action, arg,
						      sizeof(*dev));
	if (dev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	/*
	 * If the queue is empty, simply return the last error we got on
	 * this socket as the result code, and send off the done event.
	 */
	if (EMPTY(sock->recv_list)) {
		dev->result = sock->recv_result;

		ISC_TASK_SEND(task, (isc_event_t **)&dev);

		UNLOCK(&sock->lock);

		return (ISC_R_SUCCESS);
	}

	/*
	 * Bad luck.  The queue wasn't empty.  Insert this in the proper
	 * place.
	 */
	iev = (rwintev_t *)isc_event_allocate(manager->mctx,
					      sock,
					      ISC_SOCKEVENT_INTRECV,
					      internal_recv,
					      sock,
					      sizeof(*iev));

	if (iev == NULL) {
		isc_event_free((isc_event_t **)&dev);
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	ISC_LINK_INIT(iev, link);
	iev->posted = ISC_FALSE;

	dev->result = ISC_R_SUCCESS;
	dev->partial = ISC_FALSE; /* doesn't matter */

	isc_task_attach(task, &ntask);

	iev->done_ev = dev;
	iev->task = ntask;

	ISC_LIST_ENQUEUE(sock->send_list, iev, link);

	XTRACE(TRACE_RECV,
	       ("isc_socket_recvmark: posted ievent %p, dev %p, task %p\n",
		iev, dev, task));

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_sendmark(isc_socket_t *sock,
		    isc_task_t *task, isc_taskaction_t action, void *arg)
{
	isc_socketevent_t *dev;
	rwintev_t *iev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;

	manager = sock->manager;

	dev = (isc_socketevent_t *)isc_event_allocate(manager->mctx, sock,
						      ISC_SOCKEVENT_SENDMARK,
						      action, arg,
						      sizeof(*dev));
	if (dev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	/*
	 * If the queue is empty, simply return the last error we got on
	 * this socket as the result code, and send off the done event.
	 */
	if (EMPTY(sock->send_list)) {
		dev->result = sock->send_result;

		ISC_TASK_SEND(task, (isc_event_t **)&dev);

		UNLOCK(&sock->lock);

		return (ISC_R_SUCCESS);
	}

	/*
	 * Bad luck.  The queue wasn't empty.  Insert this in the proper
	 * place.
	 */
	iev = (rwintev_t *)isc_event_allocate(manager->mctx,
					      sock,
					      ISC_SOCKEVENT_INTSEND,
					      internal_send,
					      sock,
					      sizeof(*iev));

	if (iev == NULL) {
		isc_event_free((isc_event_t **)&dev);
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	ISC_LINK_INIT(iev, link);
	iev->posted = ISC_FALSE;

	dev->result = ISC_R_SUCCESS;
	dev->partial = ISC_FALSE; /* doesn't matter */

	isc_task_attach(task, &ntask);

	iev->done_ev = dev;
	iev->task = ntask;

	ISC_LIST_ENQUEUE(sock->send_list, iev, link);

	XTRACE(TRACE_SEND,
	       ("isc_socket_sendmark: posted ievent %p, dev %p, task %p\n",
		iev, dev, task));

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}
