/* $Id: socket.c,v 1.6 1998/11/11 00:43:13 explorer Exp $ */

#include "attribute.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/thread.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/socket.h>

#ifndef _WIN32
#define WINAPI /* we're not windows */
#endif

/*
 * We use macros instead of calling the routines directly because
 * the capital letters make the locking stand out.
 *
 * We INSIST that they succeed since there's no way for us to continue
 * if they fail.
 */

#define LOCK(lp) \
	INSIST(isc_mutex_lock((lp)) == ISC_R_SUCCESS);
#define UNLOCK(lp) \
	INSIST(isc_mutex_unlock((lp)) == ISC_R_SUCCESS);

/*
 * Debugging
 */
#if 1
#define XTRACE(a)	printf a
#define XENTER(a)	printf("ENTER %s\n", (a))
#define XEXIT(a)	printf("EXIT %s\n", (a))
#else
#define XTRACE(a)
#define XENTER(a)
#define XEXIT(a)
#endif

/*
 * internal event used to send readable/writable events to our internal
 * functions.
 */
typedef struct isc_socket_intev {
	struct isc_event		common;	   /* Sender is the socket. */
	isc_task_t			task;	   /* task to send these to */
	isc_socketevent_t		done_ev;   /* the done event to post */
	isc_boolean_t			partial;   /* partial i/o ok */
	isc_boolean_t			canceled;  /* I/O was canceled */
	LINK(struct isc_socket_intev)	link;
} *isc_socket_intev_t;

typedef struct isc_socket_ncintev {
	struct isc_event	common;
	isc_boolean_t		canceled;
	isc_task_t		task;
	isc_socket_newconnev_t	done;  /* the done event */
	LINK(struct isc_socket_ncintev)	link;
} *isc_socket_ncintev_t;

#define SOCKET_MAGIC			0x494f696fU	/* IOio */
#define VALID_SOCKET(t)			((t) != NULL && \
				 (t)->magic == SOCKET_MAGIC)
struct isc_socket {
	/* Not locked. */
	unsigned int			magic;
	isc_socketmgr_t			manager;
	isc_mutex_t			lock;
	/* Locked by socket lock. */
	unsigned int			references;
	int				fd;
	LIST(struct isc_socket_intev)	read_list;
	LIST(struct isc_socket_intev)	write_list;
	LIST(struct isc_socket_ncintev)	listen_list;
	isc_boolean_t			pending_read;
	isc_boolean_t			pending_write;
	isc_boolean_t			listener;  /* listener socket */
	isc_sockettype_t		type;
	isc_socket_intev_t		riev;
	isc_socket_intev_t		wiev;
	struct isc_sockaddr		address;
	int				addrlength;
};

#define SOCKET_MANAGER_MAGIC		0x494f6d67U	/* IOmg */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == SOCKET_MANAGER_MAGIC)
struct isc_socketmgr {
	/* Not locked. */
	unsigned int			magic;
	isc_memctx_t			mctx;
	isc_mutex_t			lock;
	/* Locked by manager lock. */
	isc_boolean_t			done;
	unsigned int			nscheduled;
	unsigned int			nsockets;  /* sockets managed */
	isc_thread_t			thread;
	fd_set				read_fds;
	fd_set				write_fds;
	isc_socket_t			fds[FD_SETSIZE];
	int				pipe_fds[2];
	sig_atomic_t			pipe_msgs;
};

#define SELECT_POKE_SHUTDOWN		(-1)
#define SELECT_POKE_NOTHING		(-2)

static void send_rwdone_event(isc_socket_t, isc_socket_intev_t *,
			      isc_socketevent_t *, isc_result_t);
static void rwdone_event_destroy(isc_event_t);
static void free_socket(isc_socket_t *);
static isc_result_t allocate_socket(isc_socketmgr_t, isc_sockettype_t,
				    isc_socket_t *);
static void destroy(isc_socket_t *);

/*
 * poke the select loop when there is something for us to do.  Manager must
 * be locked.
 */
static void
select_poke(isc_socketmgr_t mgr, int msg)
{
	int cc;

	XTRACE(("Poking watcher with data %d\n", msg));
	cc = write(mgr->pipe_fds[1], &msg, sizeof(int));
	if (cc < 0)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "write() failed during watcher poke: %s",
				 strerror(errno));

	INSIST(cc == sizeof(int));
}

/*
 * read a message on the internal fd.
 */
static int
select_readmsg(isc_socketmgr_t mgr)
{
	int msg;
	int cc;

	cc = read(mgr->pipe_fds[0], &msg, sizeof(int));
	if (cc < 0) {
		if (errno == EWOULDBLOCK)
			return SELECT_POKE_NOTHING;

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "read() failed during watcher poke: %s",
				 strerror(errno));
		return SELECT_POKE_NOTHING;  /* XXX */
	}

	INSIST(cc == sizeof(int));

	return msg;
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
		return ISC_R_UNEXPECTED;
	}

	return ISC_R_SUCCESS;
}

/*
 * Handle freeing a done event when needed.
 */
static void
rwdone_event_destroy(isc_event_t ev)
{
	isc_socket_t sock = ev->sender;
	isc_boolean_t kill_socket = ISC_FALSE;

	/*
	 * detach from the socket.  We would have already detached from the
	 * task when we actually queue this event up.
	 */
	LOCK(&sock->lock);

	REQUIRE(sock->references > 0);
	sock->references--;
	XTRACE(("rwdone_event_destroy: sock %p, ref cnt == %d\n",
		sock, sock->references));

	if (sock->references == 0)
		kill_socket = ISC_TRUE;
	UNLOCK(&sock->lock);
	
	if (kill_socket)
		destroy(&sock);
}

static void
ncdone_event_destroy(isc_event_t ev)
{
	isc_socket_t sock = ev->sender;
	isc_boolean_t kill_socket = ISC_FALSE;

	/*
	 * detach from the socket.  We would have already detached from the
	 * task when we actually queue this event up.
	 */
	LOCK(&sock->lock);
	sock->references--;

	if (sock->references == 0)
		kill_socket = ISC_TRUE;
	UNLOCK(&sock->lock);
	
	if (kill_socket)
		destroy(&sock);
}

/*
 * Kill.
 *
 * Caller must ensure locking.
 */
static void
destroy(isc_socket_t *sockp)
{
	isc_socket_t sock = *sockp;
	isc_socketmgr_t manager = sock->manager;

	XTRACE(("destroy sockp = %p, sock = %p\n", sockp, sock));

	LOCK(&manager->lock);

	/*
	 * Noone has this socket open, so the watcher doesn't have to be
	 * poked, and the socket doesn't have to be locked.
	 */
	manager->fds[sock->fd] = NULL;
	manager->nsockets--;

	UNLOCK(&manager->lock);

	free_socket(sockp);
}

static isc_result_t
allocate_socket(isc_socketmgr_t manager, isc_sockettype_t type,
		isc_socket_t *socketp)
{
	isc_socket_t sock;

	sock = isc_mem_get(manager->mctx, sizeof *sock);

	if (sock == NULL)
		return (NULL);

	sock->magic = SOCKET_MAGIC;
	sock->references = 1;

	sock->manager = manager;
	sock->type = type;

	/*
	 * set up list of readers and writers to be initially empty
	 */
	INIT_LIST(sock->read_list);
	INIT_LIST(sock->write_list);
	INIT_LIST(sock->listen_list);
	sock->pending_read = ISC_FALSE;
	sock->pending_write = ISC_FALSE;

	/*
	 * initialize the lock
	 */
	if (isc_mutex_init(&sock->lock) != ISC_R_SUCCESS) {
		sock->magic = 0;
		isc_mem_put(manager->mctx, sock, sizeof *sock);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	*socketp = sock;

	return (ISC_R_SUCCESS);
}

/*
 * This event requires that the various lists be empty, that the reference
 * count be 1, and that the magic number is valid.  The other socket bits,
 * like the lock, must be initialized as well.  The fd associated must be
 * marked as closed, by setting it to -1 on close, or this routine will
 * also close the socket.
 */
static void
free_socket(isc_socket_t *socketp)
{
	isc_socket_t sock = *socketp;

	REQUIRE(sock->references == 0);
	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(!sock->listener);
	REQUIRE(!sock->pending_read);
	REQUIRE(!sock->pending_write);
	REQUIRE(EMPTY(sock->read_list));
	REQUIRE(EMPTY(sock->write_list));
	REQUIRE(EMPTY(sock->listen_list));

	sock->magic = 0;

	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}

	(void)isc_mutex_destroy(&sock->lock);

	isc_mem_put(sock->manager->mctx, sock, sizeof *sock);
}

/*
 * Create a new 'type' socket managed by 'manager'.  The sockets
 * parameters are specified by 'expires' and 'interval'.  Events
 * will be posted to 'task' and when dispatched 'action' will be
 * called with 'arg' as the arg value.  The new socket is returned
 * in 'socketp'.
 */
isc_result_t
isc_socket_create(isc_socketmgr_t manager, isc_sockettype_t type,
		  isc_socket_t *socketp)
{
	isc_socket_t sock = NULL;
	isc_result_t ret;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(socketp != NULL && *socketp == NULL);

	XENTER("isc_socket_create");

	
	ret = allocate_socket(manager, type, &sock);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	/*
	 * Create the associated socket XXX
	 */
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
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "socket() failed: %s",
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
			break;
		}
	}

	if (make_nonblock(sock->fd) != ISC_R_SUCCESS) {
		free_socket(&sock);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "make_nonblock(%d)", sock->fd);
		return (ISC_R_UNEXPECTED);
	}

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the socket like we normally would because
	 * there are no external references to it yet.
	 */

	manager->fds[sock->fd] = sock;
	manager->nsockets++;

	UNLOCK(&manager->lock);

	sock->references++;

	*socketp = sock;

	XEXIT("isc_socket_create");

	return (ISC_R_SUCCESS);
}

/*
 * Attach to a socket.  Caller must explicitly detach when it is done.
 */
void
isc_socket_attach(isc_socket_t sock, isc_socket_t *socketp)
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
isc_socket_detach(isc_socket_t *socketp)
{
	isc_socket_t sock;
	isc_boolean_t kill_socket = ISC_FALSE;

	REQUIRE(socketp != NULL);
	sock = *socketp;
	REQUIRE(VALID_SOCKET(sock));

	XENTER("isc_socket_detach");

	LOCK(&sock->lock);
	REQUIRE(sock->references > 0);
	sock->references--;
	if (sock->references == 0)
		kill_socket = ISC_TRUE;
	UNLOCK(&sock->lock);
	
	if (kill_socket)
		destroy(&sock);

	XEXIT("isc_socket_detach");

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
dispatch_read(isc_socket_t sock)
{
	isc_socket_intev_t iev;
	isc_event_t ev;

	iev = HEAD(sock->read_list);
	ev = (isc_event_t)iev;

	INSIST(!sock->pending_read);

	sock->pending_read = ISC_TRUE;

	XTRACE(("dispatch_read:  posted event %p to task %p\n",
		ev, iev->task));

	INSIST(isc_task_send(iev->task, &ev) == ISC_R_SUCCESS);
}

static void
dispatch_write(isc_socket_t sock)
{
	isc_socket_intev_t iev;
	isc_event_t ev;

	iev = HEAD(sock->write_list);
	ev = (isc_event_t)iev;

	INSIST(!sock->pending_write);
	sock->pending_write = ISC_TRUE;

	isc_task_send(iev->task, &ev);
}

static void
dispatch_listen(isc_socket_t sock)
{
	isc_socket_ncintev_t iev;
	isc_event_t ev;

	iev = HEAD(sock->listen_list);
	ev = (isc_event_t)iev;

	INSIST(!sock->pending_read);

	sock->pending_read = ISC_TRUE;

	isc_task_send(iev->task, &ev);
}

/*
 * Dequeue an item off the given socket's read queue, set the result code
 * in the done event to the one provided, and send it to the task it was
 * destined for.
 *
 * Caller must have the socket locked.
 */
static void
send_rwdone_event(isc_socket_t sock, isc_socket_intev_t *iev,
		isc_socketevent_t *dev, isc_result_t resultcode)
{
	REQUIRE(!EMPTY(sock->read_list));
	REQUIRE(iev != NULL);
	REQUIRE(*iev != NULL);
	REQUIRE(dev != NULL);
	REQUIRE(*dev != NULL);

	DEQUEUE(sock->read_list, *iev, link);
	(*dev)->result = resultcode;
	isc_task_send((*iev)->task, (isc_event_t *)dev);
	(*iev)->done_ev = NULL;
	isc_event_free((isc_event_t *)iev);
}

static void
send_ncdone_event(isc_socket_t sock, isc_socket_ncintev_t *iev,
		  isc_socket_newconnev_t *dev, isc_result_t resultcode)
{
	REQUIRE(!EMPTY(sock->listen_list));
	REQUIRE(iev != NULL);
	REQUIRE(*iev != NULL);
	REQUIRE(dev != NULL);
	REQUIRE(*dev != NULL);

	DEQUEUE(sock->listen_list, *iev, link);
	(*dev)->result = resultcode;
	isc_task_send((*iev)->task, (isc_event_t *)dev);
	(*iev)->done = NULL;

	isc_event_free((isc_event_t *)iev);
}

/*
 * Call accept() on a socket, to get the new file descriptor.  The listen
 * socket is used as a prototype to create a new isc_socket_t.  The new
 * socket is referenced twice (one for the task which is receiving this
 * message, and once for the message itself) so the task does not need to
 * attach to the socket again.  The task is not attached at all.
 */
static isc_boolean_t
internal_accept(isc_task_t task, isc_event_t ev)
{
	isc_socket_t sock;
	isc_socket_newconnev_t dev;
	isc_socket_ncintev_t iev;
	struct sockaddr addr;
	int addrlen;
	int fd;

	sock = ev->sender;
	iev = (isc_socket_ncintev_t)ev;

	LOCK(&sock->lock);
	XTRACE(("internal_accept called, locked parent sock %p\n", sock));

	REQUIRE(sock->pending_read);
	REQUIRE(sock->listener);
	REQUIRE(!EMPTY(sock->listen_list));
	REQUIRE(iev->task == task);

	sock->pending_read = ISC_FALSE;

	/*
	 * Has this event been canceled?
	 */
	if (iev->canceled) {
		DEQUEUE(sock->listen_list, iev, link);
		isc_event_free((isc_event_t *)iev);
		if (!EMPTY(sock->listen_list))
			select_poke(sock->manager, sock->fd);

		UNLOCK(&sock->lock);

		return (0);
	}

	/*
	 * Try to accept the new connection.  If the accept fails with
	 * EWOULDBLOCK, simply poke the watcher to watch this socket
	 * again.
	 */
	fd = accept(sock->fd, &addr, &addrlen);
	if (fd < 0) {
		if (errno == EWOULDBLOCK) {
			XTRACE(("internal_accept: ewouldblock\n"));
			sock->pending_read = ISC_FALSE;
			select_poke(sock->manager, sock->fd);
			UNLOCK(&sock->lock);
			return (0);
		}

		/*
		 * If some other error, ignore it as well and hope
		 * for the best, but log it.  XXX This will have to be
		 * changed, thanks to broken OSs trying to overload what
		 * accept does.
		 */
		XTRACE(("internal_accept: accept returned %s\n",
			strerror(errno)));
		sock->pending_read = ISC_FALSE;
		select_poke(sock->manager, sock->fd);
		UNLOCK(&sock->lock);
		return (0);
	}

	/*
	 * The accept succeeded.  Pull off the done event and set the
	 * fd and other information in the socket descriptor here.  These
	 * were preallocated for us.
	 */
	dev = iev->done;
	iev->done = NULL;

	dev->newsocket->fd = fd;

	XTRACE(("internal_accept: newsock %p, fd %d\n",
		dev->newsocket, fd));

	UNLOCK(&sock->lock);

	/*
	 * It's safe to do this, since the done event's free routine will
	 * detach from the socket, so sock can't disappear out from under
	 * us.
	 */
	LOCK(&sock->manager->lock);
	sock->manager->fds[fd] = dev->newsocket;
	UNLOCK(&sock->manager->lock);

	send_ncdone_event(sock, &iev, &dev, ISC_R_SUCCESS);

	return (0);
}

static isc_boolean_t
internal_read(isc_task_t task, isc_event_t ev)
{
	isc_socket_intev_t iev;
	isc_socketevent_t dev;
	isc_socket_t sock;
	int cc;
	size_t read_count;

	/*
	 * Find out what socket this is and lock it.
	 */
	sock = (isc_socket_t)ev->sender;
	LOCK(&sock->lock);

	INSIST(sock->pending_read == ISC_TRUE);
	sock->pending_read = ISC_FALSE;

	XTRACE(("internal_read: sock %p, fd %d\n", sock, sock->fd));

	/*
	 * Pull the first entry off the list, and look at it.  If it is
	 * NULL, or not ours, something bad happened.
	 */
	iev = HEAD(sock->read_list);
	INSIST(iev != NULL);
	INSIST(iev->task == task);

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum read count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	do {
		iev = HEAD(sock->read_list);
		dev = iev->done_ev;

		/*
		 * check for canceled I/O
		 */
		if (iev->canceled) {
			DEQUEUE(sock->read_list, iev, link);
			isc_event_free((isc_event_t *)&iev);
			continue;
		}

		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->common.type == ISC_SOCKEVENT_RECVMARK) {
			send_rwdone_event(sock, &iev, &dev, ISC_R_SUCCESS);
			continue;
		}

		/*
		 * It must be a read request.  Try to satisfy it as best
		 * we can.
		 */
		read_count = dev->region.length - dev->n;
		cc = recv(sock->fd, dev->region.base + dev->n, read_count, 0);

		XTRACE(("internal_read:  read(%d) %d\n", sock->fd, cc));

		/*
		 * check for error or block condition
		 */
		if (cc < 0) {
			if (cc == EWOULDBLOCK)
				goto poke;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal read: %s",
					 strerror(errno));
			INSIST(cc >= 0);
		}
		/*
		 * read of 0 means the remote end was closed.  Run through
		 * the event queue and dispatch all the events with an EOF
		 * result code.  This will set the EOF flag in markers as
		 * well, but that's really ok.
		 */
		if (cc == 0) {
			do {
				send_rwdone_event(sock, &iev, &dev,
						  ISC_R_EOF);
				iev = HEAD(sock->read_list);
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
			if (iev->partial) {
				send_rwdone_event(sock, &iev, &dev,
						  ISC_R_SUCCESS);
				continue;
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
			send_rwdone_event(sock, &iev, &dev, ISC_R_SUCCESS);
		}

	} while (!EMPTY(sock->read_list));

 poke:
	if (!EMPTY(sock->read_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);

	return (0);
}

static isc_boolean_t
internal_write(isc_task_t task, isc_event_t ev)
{
	isc_socket_intev_t iev;
	isc_socketevent_t dev;
	isc_socket_t sock;
	int cc;
	size_t write_count;

	/*
	 * Find out what socket this is and lock it.
	 */
	sock = (isc_socket_t)ev->sender;
	LOCK(&sock->lock);

	INSIST(sock->pending_write == ISC_TRUE);
	sock->pending_write = ISC_FALSE;

	XTRACE(("internal_write: sock %p, fd %d\n", sock, sock->fd));

	/*
	 * Pull the first entry off the list, and look at it.  If it is
	 * NULL, or not ours, something bad happened.
	 */
	iev = HEAD(sock->write_list);
	INSIST(iev != NULL);
	INSIST(iev->task == task);

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum write count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	do {
		iev = HEAD(sock->write_list);
		dev = iev->done_ev;

		/*
		 * check for canceled I/O
		 */
		if (iev->canceled) {
			DEQUEUE(sock->write_list, iev, link);
			isc_event_free((isc_event_t *)&iev);
			continue;
		}

		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->common.type == ISC_SOCKEVENT_SENDMARK) {
			send_rwdone_event(sock, &iev, &dev, ISC_R_SUCCESS);
			continue;
		}

		/*
		 * It must be a write request.  Try to satisfy it as best
		 * we can.
		 */
		write_count = dev->region.length - dev->n;
		if (sock->type == isc_socket_udp)
			cc = sendto(sock->fd, dev->region.base + dev->n,
				    write_count, 0,
				    (struct sockaddr *)&dev->address,
				    dev->addrlength);
		else
			cc = send(sock->fd, dev->region.base + dev->n,
				  write_count, 0);

		XTRACE(("internal_write:  send(%d) %d\n", sock->fd, cc));

		/*
		 * check for error or block condition
		 */
		if (cc < 0) {
			if (cc == EWOULDBLOCK)
				goto poke;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_write: %s",
					 strerror(errno));
			INSIST(cc >= 0);
		}
		/*
		 * write of 0 means the remote end was closed.  Run through
		 * the event queue and dispatch all the events with an EOF
		 * result code.  This will set the EOF flag in markers as
		 * well, but that's really ok.
		 */
		if (cc == 0) {
			do {
				send_rwdone_event(sock, &iev, &dev,
						  ISC_R_EOF);
				iev = HEAD(sock->write_list);
			} while (iev != NULL);

			goto poke;
		}

		/*
		 * if we write less than we expected, update counters,
		 * poke.
		 */
		if ((size_t)cc < write_count) {
			dev->n += cc;

			/*
			 * If partial writes are allowed, we return whatever
			 * was read with a success result, and continue
			 * the loop.
			 */
			if (iev->partial) {
				send_rwdone_event(sock, &iev, &dev,
						  ISC_R_SUCCESS);
				continue;
			}

			/*
			 * Partials not ok.  Exit the loop and notify the
			 * watcher to wait for more writes
			 */
			goto poke;
		}

		/*
		 * Exactly what we wanted to read.  We're done with this
		 * entry.  Post its completion event.
		 */
		if ((size_t)cc == write_count) {
			dev->n += write_count;
			send_rwdone_event(sock, &iev, &dev, ISC_R_SUCCESS);
		}

	} while (!EMPTY(sock->write_list));

 poke:
	if (!EMPTY(sock->write_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);

	return (0);
}

/*
 * This is the thread that will loop forever, always in a select or poll
 * call.
 *
 * When select returns something to do, track down what thread gets to do
 * this I/O and post the event to it.
 */
static isc_threadresult_t
WINAPI
watcher(void *uap)
{
	isc_socketmgr_t manager = uap;
	isc_socket_t sock;
	isc_boolean_t done;
	int ctlfd;
	int cc;
	fd_set readfds;
	fd_set writefds;
	int msg;
	isc_boolean_t unlock_sock;
	int i;
	isc_socket_intev_t	iev;
	isc_socket_ncintev_t	nciev;

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

			UNLOCK(&manager->lock);

			cc = select(FD_SETSIZE, &readfds, &writefds, NULL,
				    NULL);
			if (cc < 0) {
				if (errno != EINTR)
					UNEXPECTED_ERROR(__FILE__, __LINE__,
							 "select failed: %s",
							 strerror(errno));
			}

			LOCK(&manager->lock);
		} while (cc < 0);


		XTRACE(("watcher got manager lock\n"));

		/*
		 * Process reads on internal, control fd.
		 */
		if (FD_ISSET(ctlfd, &readfds)) {
			while (1) {
				msg = select_readmsg(manager);

				XTRACE(("watcher got message %d\n", msg));

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
				if (msg == SELECT_POKE_SHUTDOWN)
					done = ISC_TRUE;

				/*
				 * This is a wakeup on a socket.  Look
				 * at the event queue for both read and write,
				 * and decide if we need to watch on it now
				 * or not.
				 */
				if (msg >= 0) {
					INSIST(msg < FD_SETSIZE);

					sock = manager->fds[msg];
					LOCK(&sock->lock);
					XTRACE(("watcher locked socket %p\n",
						sock));

					/*
					 * If there are no events, or there
					 * is an event but we have already
					 * queued up the internal event on a
					 * task's queue, clear the bit.
					 * Otherwise, set it.
					 */
					iev = HEAD(sock->read_list);
					nciev = HEAD(sock->listen_list);
					if ((iev == NULL && nciev == NULL)
					    || sock->pending_read) {
						FD_CLR(sock->fd,
						       &manager->read_fds);
						XTRACE(("watch cleared r\n"));
					} else {
						FD_SET(sock->fd,
						       &manager->read_fds);
						XTRACE(("watch set r\n"));
					}

					iev = HEAD(sock->write_list);
					if (iev == NULL || sock->pending_write) {
						FD_CLR(sock->fd,
						       &manager->write_fds);
						XTRACE(("watch cleared w\n"));
					} else {
						FD_SET(sock->fd,
						       &manager->write_fds);
						XTRACE(("watch set w\n"));
					}

					UNLOCK(&sock->lock);
				}
			}
		}

		/*
		 * Process read/writes on other fds here.  Avoid locking
		 * and unlocking twice if both reads and writes are possible.
		 */
		for (i = 0 ; i < FD_SETSIZE ; i++) {
			if (manager->fds[i] != NULL) {
				sock = manager->fds[i];
				unlock_sock = ISC_FALSE;
				if (FD_ISSET(i, &readfds)) {
					XTRACE(("watcher r on %d, sock %p\n",
						i, manager->fds[i]));
					unlock_sock = ISC_TRUE;
					LOCK(&sock->lock);
					if (sock->listener)
						dispatch_listen(sock);
					else
						dispatch_read(sock);
					FD_CLR(i, &manager->read_fds);
				}
				if (FD_ISSET(i, &writefds)) {
					XTRACE(("watcher w on %d, sock %p\n",
						i, manager->fds[i]));
					if (!unlock_sock) {
						unlock_sock = ISC_TRUE;
						LOCK(&sock->lock);
					}
					dispatch_write(sock);
					FD_CLR(i, &manager->write_fds);
				}
				if (unlock_sock)
					UNLOCK(&sock->lock);
			}
		}
	}

	UNLOCK(&manager->lock);
	return ((isc_threadresult_t)0);
}

/*
 * Create a new socket manager.
 */
isc_result_t
isc_socketmgr_create(isc_memctx_t mctx, isc_socketmgr_t *managerp)
{
	isc_socketmgr_t manager;

	REQUIRE(managerp != NULL && *managerp == NULL);

	XENTER("isc_socketmgr_create");

	manager = isc_mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);
	
	manager->magic = SOCKET_MANAGER_MAGIC;
	manager->mctx = mctx;
	manager->done = ISC_FALSE;
	memset(manager->fds, 0, sizeof(manager->fds));
	manager->nsockets = 0;
	manager->nscheduled = 0;
	if (isc_mutex_init(&manager->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
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
				 strerror(errno)); /* XXX */

		return (ISC_R_UNEXPECTED);
	}

	INSIST(make_nonblock(manager->pipe_fds[0]) == ISC_R_SUCCESS);
	INSIST(make_nonblock(manager->pipe_fds[1]) == ISC_R_SUCCESS);

	/*
	 * Set up initial state for the select loop
	 */
	FD_ZERO(&manager->read_fds);
	FD_ZERO(&manager->write_fds);
	FD_SET(manager->pipe_fds[0], &manager->read_fds);

	/*
	 * Start up the select/poll thread.
	 */
	if (isc_thread_create(watcher, manager, &manager->thread) !=
	    ISC_R_SUCCESS) {
		(void)isc_mutex_destroy(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_create() failed");
		return (ISC_R_UNEXPECTED);
	}

	*managerp = manager;

	XEXIT("isc_socketmgr_create (normal)");
	return (ISC_R_SUCCESS);
}

void
isc_socketmgr_destroy(isc_socketmgr_t *managerp)
{
	isc_socketmgr_t manager;

	/*
	 * Destroy a socket manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);
	REQUIRE(manager->nsockets == 0);
	manager->done = ISC_TRUE;
	UNLOCK(&manager->lock);

	/*
	 * Here, poke our select/poll thread.  Do this by closing the write
	 * half of the pipe, which will send EOF to the read half.
	 */
	select_poke(manager, SELECT_POKE_SHUTDOWN);

	/*
	 * Wait for thread to exit.
	 */
	if (isc_thread_join(manager->thread, NULL) != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_join() failed");

	/*
	 * Clean up.
	 */
	close(manager->pipe_fds[0]);
	close(manager->pipe_fds[1]);
	(void)isc_mutex_destroy(&manager->lock);
	manager->magic = 0;
	isc_mem_put(manager->mctx, manager, sizeof *manager);

	*managerp = NULL;
}

isc_result_t
isc_socket_recv(isc_socket_t sock, isc_region_t region,
		isc_boolean_t partial, isc_task_t task,
		isc_taskaction_t action, void *arg)
{
	isc_socketevent_t ev;
	isc_socket_intev_t iev;
	isc_socketmgr_t manager;
	isc_task_t ntask = NULL;
	int cc;

	manager = sock->manager;

	ev = (isc_socketevent_t)isc_event_allocate(manager->mctx, sock,
						   ISC_SOCKEVENT_RECVDONE,
						   action, arg, sizeof(*ev));
	if (ev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	if (sock->riev == NULL) {
		iev = (isc_socket_intev_t)isc_event_allocate(manager->mctx,
							     sock,
							     ISC_SOCKEVENT_INTIO,
							     internal_read,
							     sock,
							     sizeof(*iev));
		if (iev == NULL) {
			/* no special free routine yet */
			isc_event_free((isc_event_t *)&ev);
			return (ISC_R_NOMEMORY);
		}

		INIT_LINK(iev, link);

		sock->riev = iev;
		iev = NULL;  /* just in case */
	}

	sock->references++;  /* attach to socket in cheap way */

	/*
	 * UDP sockets are always partial read
	 */
	if (sock->type == isc_socket_udp)
		partial = ISC_TRUE;

	/*
	 * Remember that we need to detach on event free
	 */
	ev->common.destroy = rwdone_event_destroy;

	ev->region = *region;
	ev->n = 0;

	/*
	 * If the read queue is empty, try to do the I/O right now.
	 */
	if (EMPTY(sock->read_list)) {
		if (sock->type == isc_socket_udp) {
			cc = recvfrom(sock->fd, ev->region.base,
				      ev->region.length, 0,
				      (struct sockaddr *)&ev->address,
				      &ev->addrlength);
		} else {
			cc = recv(sock->fd, ev->region.base,
				  ev->region.length, 0);
			ev->address = sock->address;
			ev->addrlength = sock->addrlength;
		}

		if (cc < 0) {
			if (cc == EWOULDBLOCK)
				goto queue;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_socket_recv: %s",
					 strerror(errno));
			INSIST(cc >= 0);
		}

		if (cc == 0) {
			ev->result = ISC_R_EOF;
			isc_task_send(task, (isc_event_t *)&ev);

			UNLOCK(&sock->lock);
			return (ISC_R_SUCCESS);
		}

		ev->n = cc;

		/*
		 * Partial reads need to be queued
		 */
		if ((size_t)cc != ev->region.length && !partial)
			goto queue;

		/*
		 * full reads are posted, or partials if partials are ok.
		 */
		isc_task_send(task, (isc_event_t *)&ev);

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

	iev->done_ev = ev;
	iev->task = ntask;
	iev->partial = partial;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	if (EMPTY(sock->read_list)) {
		ENQUEUE(sock->read_list, iev, link);
		select_poke(sock->manager, sock->fd);
	} else {
		ENQUEUE(sock->read_list, iev, link);
	}

	XTRACE(("isc_socket_recv: posted ievent %p, dev %p, task %p\n",
		iev, iev->done_ev, task));

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_send(isc_socket_t sock, isc_region_t region,
		isc_task_t task, isc_taskaction_t action, void *arg)
{
	return isc_socket_sendto(sock, region, task, action, arg, NULL, 0);
}

isc_result_t
isc_socket_sendto(isc_socket_t sock, isc_region_t region,
		  isc_task_t task, isc_taskaction_t action, void *arg,
		  isc_sockaddr_t address, int addrlength)
{
	isc_socketevent_t ev;
	isc_socket_intev_t iev;
	isc_socketmgr_t manager;
	isc_task_t ntask = NULL;
	int cc;

	manager = sock->manager;

	ev = (isc_socketevent_t)isc_event_allocate(manager->mctx, sock,
						   ISC_SOCKEVENT_SENDDONE,
						   action, arg, sizeof(*ev));
	if (ev == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&sock->lock);

	if (sock->wiev == NULL) {
		iev = (isc_socket_intev_t)isc_event_allocate(manager->mctx,
							     sock,
							     ISC_SOCKEVENT_INTIO,
							     internal_write,
							     sock,
							     sizeof(*iev));
		if (iev == NULL) {
			/* no special free routine yet */
			isc_event_free((isc_event_t *)&ev);
			return (ISC_R_NOMEMORY);
		}

		INIT_LINK(iev, link);

		sock->wiev = iev;
		iev = NULL;  /* just in case */
	}

	sock->references++;  /* attach to socket in cheap way */

	/*
	 * Remember that we need to detach on event free
	 */
	ev->common.destroy = rwdone_event_destroy;

	ev->region = *region;
	ev->n = 0;

	/*
	 * If the write queue is empty, try to do the I/O right now.
	 */
	if (sock->type == isc_socket_udp) {
		INSIST(addrlength > 0 || sock->addrlength > 0);
		if (addrlength > 0) {
			ev->address = *address;
			ev->addrlength = addrlength;
		} else if (sock->addrlength > 0) {
			ev->address = sock->address;
			ev->addrlength = sock->addrlength;
		}
	} else if (sock->type == isc_socket_tcp) {
		INSIST(address == NULL);
		INSIST(addrlength == 0);
		ev->address = sock->address;
		ev->addrlength = sock->addrlength;
	}
	if (EMPTY(sock->write_list)) {
		if (sock->type == isc_socket_udp)
			cc = sendto(sock->fd, ev->region.base,
				    ev->region.length, 0,
				    (struct sockaddr *)&ev->address,
				    ev->addrlength);
		else if (sock->type == isc_socket_tcp)
			cc = send(sock->fd, ev->region.base,
				  ev->region.length, 0);
		else
			cc = -1;  /* XXX */

		if (cc < 0) {
			if (cc == EWOULDBLOCK)
				goto queue;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_socket_send: %s",
					 strerror(errno));
			INSIST(cc >= 0);
		}

		if (cc == 0) {
			ev->result = ISC_R_EOF;
			isc_task_send(task, (isc_event_t *)&ev);

			UNLOCK(&sock->lock);
			return (ISC_R_SUCCESS);
		}

		ev->n = cc;

		/*
		 * Partial writes need to be queued
		 */
		if ((size_t)cc != ev->region.length)
			goto queue;

		/*
		 * full writes are posted.
		 */
		isc_task_send(task, (isc_event_t *)&ev);

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

	iev->done_ev = ev;
	iev->task = ntask;
	iev->partial = ISC_FALSE; /* doesn't matter */

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	if (EMPTY(sock->write_list)) {
		ENQUEUE(sock->write_list, iev, link);
		select_poke(sock->manager, sock->fd);
	} else {
		ENQUEUE(sock->write_list, iev, link);
	}

	XTRACE(("isc_socket_send: posted ievent %p, dev %p, task %p\n",
		iev, iev->done_ev, task));

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_bind(isc_socket_t sock, struct isc_sockaddr *sockaddr,
		int addrlen)
{
	LOCK(&sock->lock);

	if (bind(sock->fd, (struct sockaddr *)sockaddr, addrlen) < 0) {
		UNLOCK(&sock->lock);
		switch (errno) {
		case EACCES:
			return (ISC_R_NOPERM);
			break;
		case EADDRNOTAVAIL:
			return (ISC_R_ADDRNOTAVAIL);
			break;
		case EADDRINUSE:
			return (ISC_R_ADDRINUSE);
			break;
		case EINVAL:
			return (ISC_R_BOUND);
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "bind: %s", strerror(errno));
			return (ISC_R_UNEXPECTED);
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
isc_socket_listen(isc_socket_t sock, int backlog)
{
	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(backlog >= 0);

	LOCK(&sock->lock);

	if (sock->type != isc_socket_tcp) {
		UNLOCK(&sock->lock);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "Socket is not isc_socket_tcp");
		return (ISC_R_UNEXPECTED);
	}

	if (sock->listener) {
		UNLOCK(&sock->lock);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "Socket already listener");
		return (ISC_R_UNEXPECTED);
	}

	if (backlog == 0)
		backlog = SOMAXCONN;

	if (listen(sock->fd, backlog) < 0) {
		UNLOCK(&sock->lock);
		UNEXPECTED_ERROR(__FILE__, __LINE__, "listen: %s",
				 strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	sock->listener = ISC_TRUE;
	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_accept(isc_socket_t sock,
		  isc_task_t task, isc_taskaction_t action, void *arg)
{
	isc_socket_ncintev_t iev;
	isc_socket_newconnev_t dev;
	isc_task_t ntask = NULL;
	isc_socketmgr_t manager;
	isc_socket_t nsock;
	isc_result_t ret;

	XENTER("isc_socket_accept");
	REQUIRE(VALID_SOCKET(sock));
	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	REQUIRE(sock->listener);

	iev = (isc_socket_ncintev_t)isc_event_allocate(manager->mctx,
						       sock,
						       ISC_SOCKEVENT_INTCONN,
						       internal_accept,
						       sock,
						       sizeof(*iev));
	if (iev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	dev = (isc_socket_newconnev_t)isc_event_allocate(manager->mctx,
							 sock,
							 ISC_SOCKEVENT_NEWCONN,
							 action,
							 arg,
							 sizeof (*dev));
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		isc_event_free((isc_event_t *)&iev);
		return (ISC_R_NOMEMORY);
	}


	ret = allocate_socket(manager, sock->type, &nsock);
	if (ret != ISC_R_SUCCESS) {
		UNLOCK(&sock->lock);
		isc_event_free((isc_event_t *)&iev);
		isc_event_free((isc_event_t *)&dev);
		return (ret);
	}

	INIT_LINK(iev, link);

	/*
	 * Attach to socket and to task
	 */
	isc_task_attach(task, &ntask);
	sock->references++;

	sock->listener = ISC_TRUE;

	iev->task = ntask;
	iev->done = dev;
	iev->canceled = ISC_FALSE;
	dev->common.destroy = ncdone_event_destroy;
	dev->newsocket = nsock;

	/*
	 * poke watcher here.  We still have the socket locked, so there
	 * is no race condition.  We will keep the lock for such a short
	 * bit of time waking it up now or later won't matter all that much.
	 */
	if (EMPTY(sock->listen_list))
		select_poke(manager, sock->fd);

	ENQUEUE(sock->listen_list, iev, link);

	UNLOCK(&sock->lock);

	return (ISC_R_SUCCESS);
}
