/*
 * Copyright (C) 1998-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: socket.c,v 1.178.2.4 2001/02/07 20:21:46 bwelling Exp $ */

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <isc/buffer.h>
#include <isc/bufferlist.h>
#include <isc/condition.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/msgs.h>
#include <isc/mutex.h>
#include <isc/net.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/util.h>

#ifndef ISC_PLATFORM_USETHREADS
#include "socket_p.h"
#endif /* ISC_PLATFORM_USETHREADS */

/*
 * Some systems define the socket length argument as an int, some as size_t,
 * some as socklen_t.  This is here so it can be easily changed if needed.
 */
#ifndef ISC_SOCKADDR_LEN_T
#define ISC_SOCKADDR_LEN_T unsigned int
#endif

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

#define DLVL(x) ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_SOCKET, ISC_LOG_DEBUG(x)

/*
 * DLVL(90)  --  Function entry/exit and other tracing.
 * DLVL(70)  --  Socket "correctness" -- including returning of events, etc.
 * DLVL(60)  --  Socket data send/receive
 * DLVL(50)  --  Event tracing, including receiving/sending completion events.
 * DLVL(20)  --  Socket creation/destruction.
 */
#define TRACE_LEVEL		90
#define CORRECTNESS_LEVEL	70
#define IOEVENT_LEVEL		60
#define EVENT_LEVEL		50
#define CREATION_LEVEL		20

#define TRACE		DLVL(TRACE_LEVEL)
#define CORRECTNESS	DLVL(CORRECTNESS_LEVEL)
#define IOEVENT		DLVL(IOEVENT_LEVEL)
#define EVENT		DLVL(EVENT_LEVEL)
#define CREATION	DLVL(CREATION_LEVEL)

typedef isc_event_t intev_t;

#define SOCKET_MAGIC		0x494f696fU	/* IOio */
#define VALID_SOCKET(t)		((t) != NULL && (t)->magic == SOCKET_MAGIC)

/*
 * IPv6 control information.  If the socket is an IPv6 socket we want
 * to collect the destination address and interface so the client can
 * set them on outgoing packets.
 */
#ifdef ISC_PLATFORM_HAVEIPV6
#ifndef USE_CMSG
#define USE_CMSG	1
#endif
#endif

/*
 * NetBSD and FreeBSD can timestamp packets.  XXXMLG Should we have
 * a setsockopt() like interface to request timestamps, and if the OS
 * doesn't do it for us, call gettimeofday() on every UDP receive?
 */
#ifdef SO_TIMESTAMP
#ifndef USE_CMSG
#define USE_CMSG	1
#endif
#endif

/*
 * Check to see if we have even basic support for cracking messages from
 * the control data returned from/sent via recvmsg()/sendmsg().
 */
#if defined(USE_CMSG) && (!defined(CMSG_LEN) || !defined(CMSG_SPACE))
#undef USE_CMSG
#endif

struct isc_socket {
	/* Not locked. */
	unsigned int		magic;
	isc_socketmgr_t	       *manager;
	isc_mutex_t		lock;
	isc_sockettype_t	type;

	/* Locked by socket lock. */
	ISC_LINK(isc_socket_t)	link;
	unsigned int		references;
	int			fd;
	int			pf;

	ISC_LIST(isc_socketevent_t)		send_list;
	ISC_LIST(isc_socketevent_t)		recv_list;
	ISC_LIST(isc_socket_newconnev_t)	accept_list;
	isc_socket_connev_t		       *connect_ev;

	/*
	 * Internal events.  Posted when a descriptor is readable or
	 * writable.  These are statically allocated and never freed.
	 * They will be set to non-purgable before use.
	 */
	intev_t			readable_ev;
	intev_t			writable_ev;

	isc_sockaddr_t		address;  /* remote address */

	unsigned int		pending_recv : 1,
				pending_send : 1,
				pending_accept : 1,
				listener : 1, /* listener socket */
				connected : 1,
				connecting : 1, /* connect pending */
				bound : 1; /* bound to local addr */

#ifdef ISC_NET_RECVOVERFLOW
	unsigned char		overflow; /* used for MSG_TRUNC fake */
#endif
#ifdef USE_CMSG
	unsigned char	       *cmsg;
	unsigned int		cmsglen;
#endif
};

#define SOCKET_MANAGER_MAGIC	0x494f6d67U	/* IOmg */
#define VALID_MANAGER(m)	((m) != NULL && \
				 (m)->magic == SOCKET_MANAGER_MAGIC)
struct isc_socketmgr {
	/* Not locked. */
	unsigned int		magic;
	isc_mem_t	       *mctx;
	isc_mutex_t		lock;
	/* Locked by manager lock. */
	ISC_LIST(isc_socket_t)	socklist;
	fd_set			read_fds;
	fd_set			write_fds;
	isc_socket_t	       *fds[FD_SETSIZE];
	int			fdstate[FD_SETSIZE];
	int			maxfd;
#ifdef ISC_PLATFORM_USETHREADS
	isc_thread_t		watcher;
	isc_condition_t		shutdown_ok;
	int			pipe_fds[2];
#else /* ISC_PLATFORM_USETHREADS */
	unsigned int		refs;
#endif /* ISC_PLATFORM_USETHREADS */
};

#ifndef ISC_PLATFORM_USETHREADS
static isc_socketmgr_t *socketmgr = NULL;
#endif /* ISC_PLATFORM_USETHREADS */

#define CLOSED		0	/* this one must be zero */
#define MANAGED		1
#define CLOSE_PENDING	2

/*
 * send() and recv() iovec counts
 */
#define MAXSCATTERGATHER_SEND	(ISC_SOCKET_MAXSCATTERGATHER)
#ifdef ISC_NET_RECVOVERFLOW
# define MAXSCATTERGATHER_RECV	(ISC_SOCKET_MAXSCATTERGATHER + 1)
#else
# define MAXSCATTERGATHER_RECV	(ISC_SOCKET_MAXSCATTERGATHER)
#endif

static void send_recvdone_event(isc_socket_t *, isc_socketevent_t **,
				isc_result_t);
static void send_senddone_event(isc_socket_t *, isc_socketevent_t **,
				isc_result_t);
static void free_socket(isc_socket_t **);
static isc_result_t allocate_socket(isc_socketmgr_t *, isc_sockettype_t,
				    isc_socket_t **);
static void destroy(isc_socket_t **);
static void internal_accept(isc_task_t *, isc_event_t *);
static void internal_connect(isc_task_t *, isc_event_t *);
static void internal_recv(isc_task_t *, isc_event_t *);
static void internal_send(isc_task_t *, isc_event_t *);
static void process_cmsg(isc_socket_t *, struct msghdr *, isc_socketevent_t *);
static void build_msghdr_send(isc_socket_t *, isc_socketevent_t *,
			      struct msghdr *, struct iovec *, size_t *);
static void build_msghdr_recv(isc_socket_t *, isc_socketevent_t *,
			      struct msghdr *, struct iovec *, size_t *);

#define SELECT_POKE_SHUTDOWN		(-1)
#define SELECT_POKE_NOTHING		(-2)

#define SOCK_DEAD(s)			((s)->references == 0)

static void
manager_log(isc_socketmgr_t *sockmgr,
	    isc_logcategory_t *category, isc_logmodule_t *module, int level,
	    const char *fmt, ...)
{
	char msgbuf[2048];
	va_list ap;

	if (! isc_log_wouldlog(isc_lctx, level))
		return;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(isc_lctx, category, module, level,
		      "sockmgr %p: %s", sockmgr, msgbuf);
}

static void
socket_log(isc_socket_t *sock, isc_sockaddr_t *address,
	   isc_logcategory_t *category, isc_logmodule_t *module, int level,
	   isc_msgcat_t *msgcat, int msgset, int message,
	   const char *fmt, ...)
{
	char msgbuf[2048];
	char peerbuf[256];
	va_list ap;

	if (! isc_log_wouldlog(isc_lctx, level))
		return;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	if (address == NULL) {
		isc_log_iwrite(isc_lctx, category, module, level,
			       msgcat, msgset, message,
			       "socket %p: %s", sock, msgbuf);
	} else {
		isc_sockaddr_format(address, peerbuf, sizeof peerbuf);
		isc_log_iwrite(isc_lctx, category, module, level,
			       msgcat, msgset, message,
			       "socket %p %s: %s", sock, peerbuf, msgbuf);
	}
}

static void
wakeup_socket(isc_socketmgr_t *manager, int fd) {
	isc_event_t *ev2;
	isc_socketevent_t *rev;
	isc_socket_t *sock;

	/*
	 * This is a wakeup on a socket.  Look at the event queue for both
	 * read and write, and decide if we need to watch on it now or not.
	 */
	INSIST(fd < FD_SETSIZE);

	if (manager->fdstate[fd] == CLOSE_PENDING) {
		manager->fdstate[fd] = CLOSED;
		FD_CLR(fd, &manager->read_fds);
		FD_CLR(fd, &manager->write_fds);
		close(fd);
		return;
	}
	if (manager->fdstate[fd] != MANAGED)
		return;

	sock = manager->fds[fd];

	/*
	 * If there are no events, or there is an event but we
	 * have already queued up the internal event on a task's
	 * queue, clear the bit.  Otherwise, set it.
	 */
	rev = ISC_LIST_HEAD(sock->recv_list);
	ev2 = (isc_event_t *) ISC_LIST_HEAD(sock->accept_list);
	if ((rev == NULL && ev2 == NULL)
	    || sock->pending_recv || sock->pending_accept)
		FD_CLR(sock->fd, &manager->read_fds);
	else
		FD_SET(sock->fd, &manager->read_fds);

	rev = ISC_LIST_HEAD(sock->send_list);
	if ((rev == NULL || sock->pending_send) && !sock->connecting)
		FD_CLR(sock->fd, &manager->write_fds);
	else
		FD_SET(sock->fd, &manager->write_fds);
}

#ifdef ISC_PLATFORM_USETHREADS
/*
 * Poke the select loop when there is something for us to do.
 * We assume that if a write completes here, it will be inserted into the
 * queue fully.  That is, we will not get partial writes.
 */
static void
select_poke(isc_socketmgr_t *mgr, int msg) {
	int cc;

	do {
		cc = write(mgr->pipe_fds[1], &msg, sizeof(int));
	} while (cc < 0 && SOFT_ERROR(errno));
			        
	if (cc < 0)
		FATAL_ERROR(__FILE__, __LINE__,
			    isc_msgcat_get(isc_msgcat, ISC_MSGSET_SOCKET,
					   ISC_MSG_WRITEFAILED,
					   "write() failed "
					   "during watcher poke: %s"),
			    strerror(errno));

	INSIST(cc == sizeof(int));
}

/*
 * Read a message on the internal fd.
 */
static int
select_readmsg(isc_socketmgr_t *mgr) {
	int msg;
	int cc;

	cc = read(mgr->pipe_fds[0], &msg, sizeof(int));
	if (cc < 0) {
		if (SOFT_ERROR(errno))
			return (SELECT_POKE_NOTHING);

		FATAL_ERROR(__FILE__, __LINE__,
			    isc_msgcat_get(isc_msgcat, ISC_MSGSET_SOCKET,
					   ISC_MSG_READFAILED,
					   "read() failed "
					   "during watcher poke: %s"),
			    strerror(errno));
		
		return (SELECT_POKE_NOTHING);
	}

	return (msg);
}
#else /* ISC_PLATFORM_USETHREADS */
/*
 * Update the state of the socketmgr when something changes.
 */
static void
select_poke(isc_socketmgr_t *manager, int msg) {
	if (msg == SELECT_POKE_SHUTDOWN)
		return;
	else if (msg >= 0)
		wakeup_socket(manager, msg);
	return;
}
#endif /* ISC_PLATFORM_USETHREADS */

/*
 * Make a fd non-blocking.
 */
static isc_result_t
make_nonblock(int fd) {
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

/*
 * Process control messages received on a socket.
 */
static void
process_cmsg(isc_socket_t *sock, struct msghdr *msg, isc_socketevent_t *dev) {
#ifdef USE_CMSG
	struct cmsghdr *cmsgp;
#ifdef ISC_PLATFORM_HAVEIPV6
	struct in6_pktinfo *pktinfop;
#endif
#ifdef SO_TIMESTAMP
	struct timeval *timevalp;
#endif
#endif

	/*
	 * sock is used only when ISC_NET_BSD44MSGHDR and USE_CMSG are defined.
	 * msg and dev are used only when ISC_NET_BSD44MSGHDR is defined.
	 * They are all here, outside of the CPP tests, because it is
	 * more consistent with the usual ISC coding style.
	 */
	UNUSED(sock);
	UNUSED(msg);
	UNUSED(dev);

#ifndef ISC_NET_BSD44MSGHDR
	return;

#else  /* defined ISC_NET_BSD44MSGHDR */

#ifdef MSG_TRUNC
	if ((msg->msg_flags & MSG_TRUNC) == MSG_TRUNC)
		dev->attributes |= ISC_SOCKEVENTATTR_TRUNC;
#endif

#ifdef MSG_CTRUNC
	if ((msg->msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
		dev->attributes |= ISC_SOCKEVENTATTR_CTRUNC;
#endif

	/*
	 * Check for multicast.
	 */
	if (isc_sockaddr_ismulticast(&dev->address))
		dev->attributes |= ISC_SOCKEVENTATTR_MULTICAST;

#ifndef USE_CMSG
	return;
#else
	if (msg->msg_controllen == 0 || msg->msg_control == NULL)
		return;

#ifdef SO_TIMESTAMP
	timevalp = NULL;
#endif
#ifdef ISC_PLATFORM_HAVEIPV6
	pktinfop = NULL;
#endif

	cmsgp = CMSG_FIRSTHDR(msg);
	while (cmsgp != NULL) {
		socket_log(sock, NULL, TRACE,
			   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_PROCESSCMSG,
			   "processing cmsg %p", cmsgp);

#ifdef ISC_PLATFORM_HAVEIPV6
		if (cmsgp->cmsg_level == IPPROTO_IPV6
		    && cmsgp->cmsg_type == IPV6_PKTINFO) {

			pktinfop = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
			memcpy(&dev->pktinfo, pktinfop,
			       sizeof(struct in6_pktinfo));
			dev->attributes |= ISC_SOCKEVENTATTR_PKTINFO;
			socket_log(sock, NULL, TRACE,
				   isc_msgcat, ISC_MSGSET_SOCKET,
				   ISC_MSG_IFRECEIVED,
				   "interface received on ifindex %u",
				   dev->pktinfo.ipi6_ifindex);
			goto next;
		}
#endif

#ifdef SO_TIMESTAMP
		if (cmsgp->cmsg_level == SOL_SOCKET
		    && cmsgp->cmsg_type == SCM_TIMESTAMP) {
			timevalp = (struct timeval *)CMSG_DATA(cmsgp);
			dev->timestamp.seconds = timevalp->tv_sec;
			dev->timestamp.nanoseconds = timevalp->tv_usec * 1000;
			dev->attributes |= ISC_SOCKEVENTATTR_TIMESTAMP;
			goto next;
		}
#endif

	next:
		cmsgp = CMSG_NXTHDR(msg, cmsgp);
	}
#endif /* USE_CMSG */

#endif /* ISC_NET_BSD44MSGHDR */

}

/*
 * Construct an iov array and attach it to the msghdr passed in.  Return
 * 0 on success, non-zero on failure.  This is the SEND constructor, which
 * will used the used region of the buffer (if using a buffer list) or
 * will use the internal region (if a single buffer I/O is requested).
 *
 * Nothing can be NULL, and the done event must list at least one buffer
 * on the buffer linked list for this function to be meaningful.
 *
 * If write_countp != NULL, *write_countp will hold the number of bytes
 * this transaction can send.
 */
static void
build_msghdr_send(isc_socket_t *sock, isc_socketevent_t *dev,
		  struct msghdr *msg, struct iovec *iov, size_t *write_countp)
{
	unsigned int iovcount;
	isc_buffer_t *buffer;
	isc_region_t used;
	size_t write_count;
	size_t skip_count;

	memset(msg, 0, sizeof (*msg));

	if (sock->type == isc_sockettype_udp) {
		msg->msg_name = (void *)&dev->address.type.sa;
		msg->msg_namelen = dev->address.length;
	} else {
		msg->msg_name = NULL;
		msg->msg_namelen = 0;
	}

	buffer = ISC_LIST_HEAD(dev->bufferlist);
	write_count = 0;
	iovcount = 0;

	/*
	 * Single buffer I/O?  Skip what we've done so far in this region.
	 */
	if (buffer == NULL) {
		write_count = dev->region.length - dev->n;
		iov[0].iov_base = (void *)(dev->region.base + dev->n);
		iov[0].iov_len = write_count;
		iovcount = 1;

		goto config;
	}

	/*
	 * Multibuffer I/O.
	 * Skip the data in the buffer list that we have already written.
	 */
	skip_count = dev->n;
	while (buffer != NULL) {
		REQUIRE(ISC_BUFFER_VALID(buffer));
		if (skip_count < isc_buffer_usedlength(buffer))
			break;
		skip_count -= isc_buffer_usedlength(buffer);
		buffer = ISC_LIST_NEXT(buffer, link);
	}

	while (buffer != NULL) {
		INSIST(iovcount < MAXSCATTERGATHER_SEND);

		isc_buffer_usedregion(buffer, &used);

		if (used.length > 0) {
			iov[iovcount].iov_base = (void *)(used.base
							  + skip_count);
			iov[iovcount].iov_len = used.length - skip_count;
			write_count += (used.length - skip_count);
			skip_count = 0;
			iovcount++;
		}
		buffer = ISC_LIST_NEXT(buffer, link);
	}

	INSIST(skip_count == 0);

 config:
	msg->msg_iov = iov;
	msg->msg_iovlen = iovcount;

#ifdef ISC_NET_BSD44MSGHDR
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_flags = 0;
#if defined(USE_CMSG)
	if ((sock->type == isc_sockettype_udp)
	    && ((dev->attributes & ISC_SOCKEVENTATTR_PKTINFO) != 0)) {
		struct cmsghdr *cmsgp;
		struct in6_pktinfo *pktinfop;

		socket_log(sock, NULL, TRACE,
			   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_SENDTODATA,
			   "sendto pktinfo data, ifindex %u",
			   dev->pktinfo.ipi6_ifindex);

		msg->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
		msg->msg_control = (void *)sock->cmsg;

		cmsgp = (struct cmsghdr *)sock->cmsg;
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_PKTINFO;
		cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		pktinfop = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
		memcpy(pktinfop, &dev->pktinfo, sizeof(struct in6_pktinfo));
	}
#endif /* USE_CMSG */
#else /* ISC_NET_BSD44MSGHDR */
	msg->msg_accrights = NULL;
	msg->msg_accrightslen = 0;
#endif /* ISC_NET_BSD44MSGHDR */

	if (write_countp != NULL)
		*write_countp = write_count;
}

/*
 * Construct an iov array and attach it to the msghdr passed in.  Return
 * 0 on success, non-zero on failure.  This is the RECV constructor, which
 * will use the avialable region of the buffer (if using a buffer list) or
 * will use the internal region (if a single buffer I/O is requested).
 *
 * Nothing can be NULL, and the done event must list at least one buffer
 * on the buffer linked list for this function to be meaningful.
 *
 * If read_countp != NULL, *read_countp will hold the number of bytes
 * this transaction can receive.
 */
static void
build_msghdr_recv(isc_socket_t *sock, isc_socketevent_t *dev,
		  struct msghdr *msg, struct iovec *iov, size_t *read_countp)
{
	unsigned int iovcount;
	isc_buffer_t *buffer;
	isc_region_t available;
	size_t read_count;

	memset(msg, 0, sizeof (struct msghdr));

	if (sock->type == isc_sockettype_udp) {
		memset(&dev->address, 0, sizeof(dev->address));
		msg->msg_name = (void *)&dev->address.type.sa;
		msg->msg_namelen = sizeof(dev->address.type);
#ifdef ISC_NET_RECVOVERFLOW
		/* If needed, steal one iovec for overflow detection. */
		maxiov--;
#endif
	} else { /* TCP */
		msg->msg_name = NULL;
		msg->msg_namelen = 0;
		dev->address = sock->address;
	}

	buffer = ISC_LIST_HEAD(dev->bufferlist);
	read_count = 0;

	/*
	 * Single buffer I/O?  Skip what we've done so far in this region.
	 */
	if (buffer == NULL) {
		read_count = dev->region.length - dev->n;
		iov[0].iov_base = (void *)(dev->region.base + dev->n);
		iov[0].iov_len = read_count;
		iovcount = 1;

		goto config;
	}

	/*
	 * Multibuffer I/O.
	 * Skip empty buffers.
	 */
	while (buffer != NULL) {
		REQUIRE(ISC_BUFFER_VALID(buffer));
		if (isc_buffer_availablelength(buffer) != 0)
			break;
		buffer = ISC_LIST_NEXT(buffer, link);
	}

	iovcount = 0;
	while (buffer != NULL) {
		INSIST(iovcount < MAXSCATTERGATHER_RECV);

		isc_buffer_availableregion(buffer, &available);

		if (available.length > 0) {
			iov[iovcount].iov_base = (void *)(available.base);
			iov[iovcount].iov_len = available.length;
			read_count += available.length;
			iovcount++;
		}
		buffer = ISC_LIST_NEXT(buffer, link);
	}

 config:

	/*
	 * If needed, set up to receive that one extra byte.  Note that
	 * we know there is at least one iov left, since we stole it
	 * at the top of this function.
	 */
#ifdef ISC_NET_RECVOVERFLOW
	if (sock->type == isc_sockettype_udp) {
		iov[iovcount].iov_base = (void *)(&sock->overflow);
		iov[iovcount].iov_len = 1;
		iovcount++;
	}
#endif

	msg->msg_iov = iov;
	msg->msg_iovlen = iovcount;

#ifdef ISC_NET_BSD44MSGHDR
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_flags = 0;
#if defined(USE_CMSG)
	if (sock->type == isc_sockettype_udp) {
		msg->msg_control = (void *)sock->cmsg;
		msg->msg_controllen = sock->cmsglen;
	}
#endif /* USE_CMSG */
#else /* ISC_NET_BSD44MSGHDR */
	msg->msg_accrights = NULL;
	msg->msg_accrightslen = 0;
#endif /* ISC_NET_BSD44MSGHDR */

	if (read_countp != NULL)
		*read_countp = read_count;
}

static void
set_dev_address(isc_sockaddr_t *address, isc_socket_t *sock,
		isc_socketevent_t *dev)
{
	if (sock->type == isc_sockettype_udp) {
		if (address != NULL)
			dev->address = *address;
		else
			dev->address = sock->address;
	} else if (sock->type == isc_sockettype_tcp) {
		INSIST(address == NULL);
		dev->address = sock->address;
	}
}

static isc_socketevent_t *
allocate_socketevent(isc_socket_t *sock, isc_eventtype_t eventtype,
		     isc_taskaction_t action, const void *arg)
{
	isc_socketevent_t *ev;

	ev = (isc_socketevent_t *)isc_event_allocate(sock->manager->mctx,
						     sock, eventtype,
						     action, arg,
						     sizeof (*ev));

	if (ev == NULL)
		return (NULL);

	ev->result = ISC_R_UNEXPECTED;
	ISC_LINK_INIT(ev, ev_link);
	ISC_LIST_INIT(ev->bufferlist);
	ev->region.base = NULL;
	ev->n = 0;
	ev->offset = 0;
	ev->attributes = 0;

	return (ev);
}

#if defined(ISC_SOCKET_DEBUG)
static void
dump_msg(struct msghdr *msg) {
	unsigned int i;

	printf("MSGHDR %p\n", msg);
	printf("\tname %p, namelen %d\n", msg->msg_name, msg->msg_namelen);
	printf("\tiov %p, iovlen %d\n", msg->msg_iov, msg->msg_iovlen);
	for (i = 0 ; i < (unsigned int)msg->msg_iovlen ; i++)
		printf("\t\t%d\tbase %p, len %d\n", i,
		       msg->msg_iov[i].iov_base,
		       msg->msg_iov[i].iov_len);
#ifdef ISC_NET_BSD44MSGHDR
	printf("\tcontrol %p, controllen %d\n", msg->msg_control,
	       msg->msg_controllen);
#endif
}
#endif

#define DOIO_SUCCESS		0	/* i/o ok, event sent */
#define DOIO_SOFT		1	/* i/o ok, soft error, no event sent */
#define DOIO_HARD		2	/* i/o error, event sent */
#define DOIO_EOF		3	/* EOF, no event sent */

static int
doio_recv(isc_socket_t *sock, isc_socketevent_t *dev) {
	int cc;
	struct iovec iov[MAXSCATTERGATHER_RECV];
	size_t read_count;
	size_t actual_count;
	struct msghdr msghdr;
	isc_buffer_t *buffer;

	build_msghdr_recv(sock, dev, &msghdr, iov, &read_count);

#if defined(ISC_SOCKET_DEBUG)
	dump_msg(&msghdr);
#endif

	cc = recvmsg(sock->fd, &msghdr, 0);

	if (cc < 0) {
		if (SOFT_ERROR(errno))
			return (DOIO_SOFT);

		if (isc_log_wouldlog(isc_lctx, IOEVENT_LEVEL))
			socket_log(sock, NULL, IOEVENT,
				   isc_msgcat, ISC_MSGSET_SOCKET,
				   ISC_MSG_DOIORECV, 
				  "doio_recv: recvmsg(%d) %d bytes, err %d/%s",
				   sock->fd, cc, errno, strerror(errno));

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			send_recvdone_event(sock, &dev, _isc); \
			return (DOIO_HARD); \
		} \
		return (DOIO_SOFT); \
	}
#define ALWAYS_HARD(_system, _isc) \
	if (errno == _system) { \
		send_recvdone_event(sock, &dev, _isc); \
		return (DOIO_HARD); \
	}

		SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
		SOFT_OR_HARD(ENETUNREACH, ISC_R_NETUNREACH);
		SOFT_OR_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
		ALWAYS_HARD(ENOBUFS, ISC_R_NORESOURCES);

#undef SOFT_OR_HARD
#undef ALWAYS_HARD

		send_recvdone_event(sock, &dev, ISC_R_UNEXPECTED);
		return (DOIO_SUCCESS);
	}

	/*
	 * On TCP, zero length reads indicate EOF, while on
	 * UDP, zero length reads are perfectly valid, although
	 * strange.
	 */
	if ((sock->type == isc_sockettype_tcp) && (cc == 0))
		return (DOIO_EOF);

	if (sock->type == isc_sockettype_udp)
		dev->address.length = msghdr.msg_namelen;

	socket_log(sock, &dev->address, IOEVENT,
		   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_PKTRECV,
		   "packet received correctly");

	/*
	 * Overflow bit detection.  If we received MORE bytes than we should,
	 * this indicates an overflow situation.  Set the flag in the
	 * dev entry and adjust how much we read by one.
	 */
#ifdef ISC_NET_RECVOVERFLOW
	if ((sock->type == isc_sockettype_udp) && ((size_t)cc > read_count)) {
		dev->attributes |= ISC_SOCKEVENTATTR_TRUNC;
		cc--;
	}
#endif

	/*
	 * If there are control messages attached, run through them and pull
	 * out the interesting bits.
	 */
	if (sock->type == isc_sockettype_udp)
		process_cmsg(sock, &msghdr, dev);

	/*
	 * update the buffers (if any) and the i/o count
	 */
	dev->n += cc;
	actual_count = cc;
	buffer = ISC_LIST_HEAD(dev->bufferlist);
	while (buffer != NULL && actual_count > 0) {
		REQUIRE(ISC_BUFFER_VALID(buffer));
		if (isc_buffer_availablelength(buffer) <= actual_count) {
			actual_count -= isc_buffer_availablelength(buffer);
			isc_buffer_add(buffer,
				       isc_buffer_availablelength(buffer));
		} else {
			isc_buffer_add(buffer, actual_count);
			actual_count = 0;
			break;
		}
		buffer = ISC_LIST_NEXT(buffer, link);
		if (buffer == NULL) {
			INSIST(actual_count == 0);
		}
	}

	/*
	 * If we read less than we expected, update counters,
	 * and let the upper layer poke the descriptor.
	 */
	if (((size_t)cc != read_count) && (dev->n < dev->minimum))
		return (DOIO_SOFT);

	/*
	 * Full reads are posted, or partials if partials are ok.
	 */
	send_recvdone_event(sock, &dev, ISC_R_SUCCESS);
	return (DOIO_SUCCESS);
}

/*
 * Returns:
 *	DOIO_SUCCESS	The operation succeeded.  The senddone event
 *			was sent.
 *
 *	DOIO_HARD	A hard or unexpected I/O error was encountered.
 *			The senddone event was sent.
 *
 *	DOIO_SOFT	A soft I/O error was encountered.  No senddone
 *			event was sent.  The operation should be retried.
 *
 *	No other return values are possible.
 */
static int
doio_send(isc_socket_t *sock, isc_socketevent_t *dev) {
	int cc;
	struct iovec iov[MAXSCATTERGATHER_SEND];
	size_t write_count;
	struct msghdr msghdr;
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];

	build_msghdr_send(sock, dev, &msghdr, iov, &write_count);

	cc = sendmsg(sock->fd, &msghdr, 0);

	/*
	 * Check for error or block condition.
	 */
	if (cc < 0) {
		if (SOFT_ERROR(errno))
			return (DOIO_SOFT);

#define SOFT_OR_HARD(_system, _isc) \
	if (errno == _system) { \
		if (sock->connected) { \
			send_senddone_event(sock, &dev, _isc); \
			return (DOIO_HARD); \
		} \
		return (DOIO_SOFT); \
	}
#define ALWAYS_HARD(_system, _isc) \
	if (errno == _system) { \
		send_senddone_event(sock, &dev, _isc); \
		return (DOIO_HARD); \
	}

		SOFT_OR_HARD(EACCES, ISC_R_NOPERM);
		SOFT_OR_HARD(EAFNOSUPPORT, ISC_R_ADDRNOTAVAIL);
		SOFT_OR_HARD(ECONNREFUSED, ISC_R_CONNREFUSED);
		ALWAYS_HARD(EADDRNOTAVAIL, ISC_R_ADDRNOTAVAIL);
		ALWAYS_HARD(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#ifdef EHOSTDOWN
		ALWAYS_HARD(EHOSTDOWN, ISC_R_HOSTUNREACH);
#endif
		ALWAYS_HARD(ENETUNREACH, ISC_R_NETUNREACH);
		ALWAYS_HARD(ENOBUFS, ISC_R_NORESOURCES);
		ALWAYS_HARD(EPERM, ISC_R_HOSTUNREACH);
		ALWAYS_HARD(EPIPE, ISC_R_NOTCONNECTED);

#undef SOFT_OR_HARD
#undef ALWAYS_HARD

		/*
		 * The other error types depend on whether or not the
		 * socket is UDP or TCP.  If it is UDP, some errors
		 * that we expect to be fatal under TCP are merely
		 * annoying, and are really soft errors.
		 *
		 * However, these soft errors are still returned as
		 * a status.
		 */
		isc_sockaddr_format(&dev->address, addrbuf, sizeof(addrbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "internal_send: %s: %s",
				 addrbuf, strerror(errno));
		send_senddone_event(sock, &dev, ISC_R_UNEXPECTED);
		return (DOIO_HARD);
	}

	if (cc == 0)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "internal_send: send() %s 0",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_RETURNED, "returned"));

	/*
	 * If we write less than we expected, update counters, poke.
	 */
	dev->n += cc;
	if ((size_t)cc != write_count)
		return (DOIO_SOFT);

	/*
	 * Exactly what we wanted to write.  We're done with this
	 * entry.  Post its completion event.
	 */
	send_senddone_event(sock, &dev, ISC_R_SUCCESS);
	return (DOIO_SUCCESS);
}

/*
 * Kill.
 *
 * Caller must ensure that the socket is not locked and no external
 * references exist.
 */
static void
destroy(isc_socket_t **sockp) {
	isc_socket_t *sock = *sockp;
	isc_socketmgr_t *manager = sock->manager;

	socket_log(sock, NULL, CREATION, isc_msgcat, ISC_MSGSET_SOCKET,
		   ISC_MSG_DESTROYING, "destroying");

	INSIST(ISC_LIST_EMPTY(sock->accept_list));
	INSIST(ISC_LIST_EMPTY(sock->recv_list));
	INSIST(ISC_LIST_EMPTY(sock->send_list));
	INSIST(sock->connect_ev == NULL);

	LOCK(&manager->lock);

	/*
	 * No one has this socket open, so the watcher doesn't have to be
	 * poked, and the socket doesn't have to be locked.
	 */
	manager->fds[sock->fd] = NULL;
	manager->fdstate[sock->fd] = CLOSE_PENDING;
	select_poke(manager, sock->fd);
	ISC_LIST_UNLINK(manager->socklist, sock, link);

#ifdef ISC_PLATFORM_USETHREADS
	if (ISC_LIST_EMPTY(manager->socklist))
		SIGNAL(&manager->shutdown_ok);
#endif /* ISC_PLATFORM_USETHREADS */

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

#if USE_CMSG  /* Let's hope the OSs are sane, and pad correctly XXXMLG */
	sock->cmsglen = 0;
#ifdef ISC_PLATFORM_HAVEIPV6
	sock->cmsglen += CMSG_SPACE(sizeof(struct in6_pktinfo));
#endif
#ifdef SO_TIMESTAMP
	sock->cmsglen += CMSG_SPACE(sizeof(struct timeval));
#endif
	sock->cmsg = isc_mem_get(manager->mctx, sock->cmsglen);
	if (sock->cmsg == NULL) {
		ret = ISC_R_NOMEMORY;
		goto err1;
	}
#endif

	ret = ISC_R_UNEXPECTED;

	sock->magic = 0;
	sock->references = 0;

	sock->manager = manager;
	sock->type = type;
	sock->fd = -1;

	ISC_LINK_INIT(sock, link);

	/*
	 * set up list of readers and writers to be initially empty
	 */
	ISC_LIST_INIT(sock->recv_list);
	ISC_LIST_INIT(sock->send_list);
	ISC_LIST_INIT(sock->accept_list);
	sock->connect_ev = NULL;
	sock->pending_recv = 0;
	sock->pending_send = 0;
	sock->pending_accept = 0;
	sock->listener = 0;
	sock->connected = 0;
	sock->connecting = 0;
	sock->bound = 0;

	/*
	 * initialize the lock
	 */
	if (isc_mutex_init(&sock->lock) != ISC_R_SUCCESS) {
		sock->magic = 0;
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
		ret = ISC_R_UNEXPECTED;
		goto err2;
	}

	/*
	 * Initialize readable and writable events
	 */
	ISC_EVENT_INIT(&sock->readable_ev, sizeof(intev_t),
		       ISC_EVENTATTR_NOPURGE, NULL, ISC_SOCKEVENT_INTR,
		       NULL, sock, sock, NULL, NULL);
	ISC_EVENT_INIT(&sock->writable_ev, sizeof(intev_t),
		       ISC_EVENTATTR_NOPURGE, NULL, ISC_SOCKEVENT_INTW,
		       NULL, sock, sock, NULL, NULL);

	sock->magic = SOCKET_MAGIC;
	*socketp = sock;

	return (ISC_R_SUCCESS);

 err2: /* cmsg allocated */
#ifdef USE_CMSG
	isc_mem_put(manager->mctx, sock->cmsg, sock->cmsglen);
	sock->cmsglen = 0;
	sock->cmsg = NULL;
 err1: /* socket allocated */
#endif
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
free_socket(isc_socket_t **socketp) {
	isc_socket_t *sock = *socketp;

	INSIST(sock->references == 0);
	INSIST(VALID_SOCKET(sock));
	INSIST(!sock->connecting);
	INSIST(!sock->pending_recv);
	INSIST(!sock->pending_send);
	INSIST(!sock->pending_accept);
	INSIST(ISC_LIST_EMPTY(sock->recv_list));
	INSIST(ISC_LIST_EMPTY(sock->send_list));
	INSIST(ISC_LIST_EMPTY(sock->accept_list));
	INSIST(!ISC_LINK_LINKED(sock, link));

	sock->magic = 0;

	DESTROYLOCK(&sock->lock);

#ifdef USE_CMSG
	isc_mem_put(sock->manager->mctx, sock->cmsg, sock->cmsglen);
#endif
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
isc_socket_create(isc_socketmgr_t *manager, int pf, isc_sockettype_t type,
		  isc_socket_t **socketp)
{
	isc_socket_t *sock = NULL;
	isc_result_t ret;
#if defined(USE_CMSG) || defined(SO_BSDCOMPAT)
	int on = 1;
#endif

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(socketp != NULL && *socketp == NULL);

	ret = allocate_socket(manager, type, &sock);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	sock->pf = pf;
	switch (type) {
	case isc_sockettype_udp:
		sock->fd = socket(pf, SOCK_DGRAM, IPPROTO_UDP);
		break;
	case isc_sockettype_tcp:
		sock->fd = socket(pf, SOCK_STREAM, IPPROTO_TCP);
		break;
	}
	if (sock->fd < 0) {
		free_socket(&sock);

		switch (errno) {
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
			return (ISC_R_NORESOURCES);

		case EPROTONOSUPPORT:
		case EPFNOSUPPORT:
		case EAFNOSUPPORT:
#ifdef LINUX
		/*
		 * Linux 2.2 (and maybe others) return EINVAL instead of
		 * EAFNOSUPPORT.
		 */
		case EINVAL:
#endif
			return (ISC_R_FAMILYNOSUPPORT);

		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "socket() %s: %s",
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_GENERAL,
							ISC_MSG_FAILED,
							"failed"),
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
	}

	if (make_nonblock(sock->fd) != ISC_R_SUCCESS) {
		free_socket(&sock);
		return (ISC_R_UNEXPECTED);
	}

#ifdef SO_BSDCOMPAT
	if (setsockopt(sock->fd, SOL_SOCKET, SO_BSDCOMPAT,
		       (void *)&on, sizeof on) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "setsockopt(%d, SO_BSDCOMPAT) %s: %s",
				 sock->fd,
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"),
				 strerror(errno));
		/* Press on... */
	}
#endif

#if defined(USE_CMSG)
	if (type == isc_sockettype_udp) {

#if defined(SO_TIMESTAMP)
		if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP,
			       (void *)&on, sizeof on) < 0
		    && errno != ENOPROTOOPT) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "setsockopt(%d, SO_TIMESTAMP) %s: %s",
					 sock->fd, 
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_GENERAL,
							ISC_MSG_FAILED,
							"failed"),
					 strerror(errno));
			/* Press on... */
		}
#endif /* SO_TIMESTAMP */

#if defined(ISC_PLATFORM_HAVEIPV6)
#ifdef IPV6_RECVPKTINFO
		/* 2292bis */
		if ((pf == AF_INET6)
		    && (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
				   (void *)&on, sizeof (on)) < 0)) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "setsockopt(%d, IPV6_RECVPKTINFO) "
					 "%s: %s", sock->fd,
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_GENERAL,
							ISC_MSG_FAILED,
							"failed"),
					 strerror(errno));
		}
#else
		/* 2292 */
		if ((pf == AF_INET6)
		    && (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_PKTINFO,
				   (void *)&on, sizeof (on)) < 0)) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "setsockopt(%d, IPV6_PKTINFO) %s: %s",
					 sock->fd,
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_GENERAL,
							ISC_MSG_FAILED,
							"failed"),
					 strerror(errno));
		}
#endif /* IPV6_RECVPKTINFO */
#ifdef IPV6_USE_MIN_MTU        /*2292bis, not too common yet*/
		/* use minimum MTU */
		if (pf == AF_INET6) {
			(void)setsockopt(sock->fd, IPPROTO_IPV6,
					 IPV6_USE_MIN_MTU,
					 (void *)&on, sizeof (on));
		}
#endif
#endif /* ISC_PLATFORM_HAVEIPV6 */

	}
#endif /* USE_CMSG */

	sock->references = 1;
	*socketp = sock;

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the socket like we normally would because
	 * there are no external references to it yet.
	 */

	manager->fds[sock->fd] = sock;
	manager->fdstate[sock->fd] = MANAGED;
	ISC_LIST_APPEND(manager->socklist, sock, link);
	if (manager->maxfd < sock->fd)
		manager->maxfd = sock->fd;

	UNLOCK(&manager->lock);

	socket_log(sock, NULL, CREATION, isc_msgcat, ISC_MSGSET_SOCKET,
		   ISC_MSG_CREATED, "created");

	return (ISC_R_SUCCESS);
}

/*
 * Attach to a socket.  Caller must explicitly detach when it is done.
 */
void
isc_socket_attach(isc_socket_t *sock, isc_socket_t **socketp) {
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
isc_socket_detach(isc_socket_t **socketp) {
	isc_socket_t *sock;
	isc_boolean_t kill_socket = ISC_FALSE;

	REQUIRE(socketp != NULL);
	sock = *socketp;
	REQUIRE(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	REQUIRE(sock->references > 0);
	sock->references--;
	if (sock->references == 0)
		kill_socket = ISC_TRUE;
	UNLOCK(&sock->lock);

	if (kill_socket)
		destroy(&sock);

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
dispatch_recv(isc_socket_t *sock) {
	intev_t *iev;
	isc_socketevent_t *ev;

	INSIST(!sock->pending_recv);

	ev = ISC_LIST_HEAD(sock->recv_list);
	if (ev == NULL)
		return;

	sock->pending_recv = 1;
	iev = &sock->readable_ev;

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "dispatch_recv:  event %p -> task %p", ev, ev->ev_sender);

	sock->references++;
	iev->ev_sender = sock;
	iev->ev_action = internal_recv;
	iev->ev_arg = sock;

	isc_task_send(ev->ev_sender, (isc_event_t **)&iev);
}

static void
dispatch_send(isc_socket_t *sock) {
	intev_t *iev;
	isc_socketevent_t *ev;

	INSIST(!sock->pending_send);

	ev = ISC_LIST_HEAD(sock->send_list);
	if (ev == NULL)
		return;

	sock->pending_send = 1;
	iev = &sock->writable_ev;

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "dispatch_send:  event %p -> task %p", ev, ev->ev_sender);

	sock->references++;
	iev->ev_sender = sock;
	iev->ev_action = internal_send;
	iev->ev_arg = sock;

	isc_task_send(ev->ev_sender, (isc_event_t **)&iev);
}

/*
 * Dispatch an internal accept event.
 */
static void
dispatch_accept(isc_socket_t *sock) {
	intev_t *iev;
	isc_socket_newconnev_t *ev;

	INSIST(!sock->pending_accept);

	/*
	 * Are there any done events left, or were they all canceled
	 * before the manager got the socket lock?
	 */
	ev = ISC_LIST_HEAD(sock->accept_list);
	if (ev == NULL)
		return;

	sock->pending_accept = 1;
	iev = &sock->readable_ev;

	sock->references++;  /* keep socket around for this internal event */
	iev->ev_sender = sock;
	iev->ev_action = internal_accept;
	iev->ev_arg = sock;

	isc_task_send(ev->ev_sender, (isc_event_t **)&iev);
}

static void
dispatch_connect(isc_socket_t *sock) {
	intev_t *iev;
	isc_socket_connev_t *ev;

	iev = &sock->writable_ev;

	ev = sock->connect_ev;
	INSIST(ev != NULL); /* XXX */

	INSIST(sock->connecting);

	sock->references++;  /* keep socket around for this internal event */
	iev->ev_sender = sock;
	iev->ev_action = internal_connect;
	iev->ev_arg = sock;

	isc_task_send(ev->ev_sender, (isc_event_t **)&iev);
}

/*
 * Dequeue an item off the given socket's read queue, set the result code
 * in the done event to the one provided, and send it to the task it was
 * destined for.
 *
 * If the event to be sent is on a list, remove it before sending.  If
 * asked to, send and detach from the socket as well.
 *
 * Caller must have the socket locked.
 */
static void
send_recvdone_event(isc_socket_t *sock, isc_socketevent_t **dev,
		    isc_result_t resultcode)
{
	isc_task_t *task;

	task = (*dev)->ev_sender;

	(*dev)->result = resultcode;
	(*dev)->ev_sender = sock;

	if (ISC_LINK_LINKED(*dev, ev_link))
		ISC_LIST_DEQUEUE(sock->recv_list, *dev, ev_link);

	if (((*dev)->attributes & ISC_SOCKEVENTATTR_ATTACHED)
	    == ISC_SOCKEVENTATTR_ATTACHED)
		isc_task_sendanddetach(&task, (isc_event_t **)dev);
	else
		isc_task_send(task, (isc_event_t **)dev);
}

/*
 * See comments for send_recvdone_event() above.
 *
 * Caller must have the socket locked.
 */
static void
send_senddone_event(isc_socket_t *sock, isc_socketevent_t **dev,
		    isc_result_t resultcode)
{
	isc_task_t *task;

	INSIST(dev != NULL && *dev != NULL);

	task = (*dev)->ev_sender;
	(*dev)->result = resultcode;
	(*dev)->ev_sender = sock;

	if (ISC_LINK_LINKED(*dev, ev_link))
		ISC_LIST_DEQUEUE(sock->send_list, *dev, ev_link);

	if (((*dev)->attributes & ISC_SOCKEVENTATTR_ATTACHED)
	    == ISC_SOCKEVENTATTR_ATTACHED)
		isc_task_sendanddetach(&task, (isc_event_t **)dev);
	else
		isc_task_send(task, (isc_event_t **)dev);
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
internal_accept(isc_task_t *me, isc_event_t *ev) {
	isc_socket_t *sock;
	isc_socketmgr_t *manager;
	isc_socket_newconnev_t *dev;
	isc_task_t *task;
	ISC_SOCKADDR_LEN_T addrlen;
	int fd;
	isc_result_t result = ISC_R_SUCCESS;

	UNUSED(me);

	sock = ev->ev_sender;
	INSIST(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	socket_log(sock, NULL, TRACE,
		   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_ACCEPTLOCK,
		   "internal_accept called, locked socket");

	manager = sock->manager;
	INSIST(VALID_MANAGER(manager));

	INSIST(sock->listener);
	INSIST(sock->pending_accept == 1);
	sock->pending_accept = 0;

	INSIST(sock->references > 0);
	sock->references--;  /* the internal event is done with this socket */
	if (sock->references == 0) {
		UNLOCK(&sock->lock);
		destroy(&sock);
		return;
	}

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
	addrlen = sizeof dev->newsocket->address.type;
	memset(&dev->newsocket->address.type.sa, 0, addrlen);
	fd = accept(sock->fd, &dev->newsocket->address.type.sa,
		    (void *)&addrlen);
	if (fd < 0) {
		if (! SOFT_ERROR(errno)) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_accept: accept() %s: %s",
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_GENERAL,
							ISC_MSG_FAILED,
							"failed"),
					 strerror(errno));
		}
		select_poke(sock->manager, sock->fd);
		UNLOCK(&sock->lock);
		return;
	} else {
		if (dev->newsocket->address.type.sa.sa_family != sock->pf) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_accept(): "
					 "accept() returned peer address "
					 "family %u (expected %u)",
					 dev->newsocket->address.
					 type.sa.sa_family,
					 sock->pf);
			(void)close(fd);
			select_poke(sock->manager, sock->fd);
			UNLOCK(&sock->lock);
			return;
		}
	}

	dev->newsocket->address.length = addrlen;
	dev->newsocket->pf = sock->pf;

	/*
	 * Pull off the done event.
	 */
	ISC_LIST_UNLINK(sock->accept_list, dev, ev_link);

	/*
	 * Poke watcher if there are more pending accepts.
	 */
	if (!ISC_LIST_EMPTY(sock->accept_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);

	if (fd != -1 && (make_nonblock(fd) != ISC_R_SUCCESS)) {
		close(fd);
		fd = -1;
		result = ISC_R_UNEXPECTED;
	}

	LOCK(&manager->lock);
	ISC_LIST_APPEND(manager->socklist, dev->newsocket, link);

	/*
	 * -1 means the new socket didn't happen.
	 */
	if (fd != -1) {
		dev->newsocket->fd = fd;
		dev->newsocket->bound = 1;
		dev->newsocket->connected = 1;

		/*
		 * Save away the remote address
		 */
		dev->address = dev->newsocket->address;

		manager->fds[fd] = dev->newsocket;
		manager->fdstate[fd] = MANAGED;
		if (manager->maxfd < fd)
			manager->maxfd = fd;

		socket_log(sock, &dev->newsocket->address, CREATION,
			   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_ACCEPTEDCXN,
			   "accepted connection, new socket %p",
			   dev->newsocket);
	}

	UNLOCK(&manager->lock);

	/*
	 * Fill in the done event details and send it off.
	 */
	dev->result = result;
	task = dev->ev_sender;
	dev->ev_sender = sock;

	isc_task_sendanddetach(&task, (isc_event_t **)&dev);
}

static void
internal_recv(isc_task_t *me, isc_event_t *ev) {
	isc_socketevent_t *dev;
	isc_socket_t *sock;

	INSIST(ev->ev_type == ISC_SOCKEVENT_INTR);

	sock = ev->ev_sender;
	INSIST(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	socket_log(sock, NULL, IOEVENT,
		   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_INTERNALRECV,
		   "internal_recv: task %p got event %p", me, ev, sock);

	INSIST(sock->pending_recv == 1);
	sock->pending_recv = 0;

	INSIST(sock->references > 0);
	sock->references--;  /* the internal event is done with this socket */
	if (sock->references == 0) {
		UNLOCK(&sock->lock);
		destroy(&sock);
		return;
	}

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum read count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	dev = ISC_LIST_HEAD(sock->recv_list);
	while (dev != NULL) {
		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->ev_type == ISC_SOCKEVENT_RECVMARK) {
			send_recvdone_event(sock, &dev, ISC_R_SUCCESS);
			goto next;
		}

		switch (doio_recv(sock, dev)) {
		case DOIO_SOFT:
			goto poke;

		case DOIO_EOF:
			/*
			 * read of 0 means the remote end was closed.
			 * Run through the event queue and dispatch all
			 * the events with an EOF result code.  This will
			 *  set the EOF flag in markers as well, but
			 * that's really ok.
			 */
			do {
				send_recvdone_event(sock, &dev, ISC_R_EOF);
				dev = ISC_LIST_HEAD(sock->recv_list);
			} while (dev != NULL);
			goto poke;

		case DOIO_SUCCESS:
		case DOIO_HARD:
			break;
		}

	next:
		dev = ISC_LIST_HEAD(sock->recv_list);
	}

 poke:
	if (!ISC_LIST_EMPTY(sock->recv_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);
}

static void
internal_send(isc_task_t *me, isc_event_t *ev) {
	isc_socketevent_t *dev;
	isc_socket_t *sock;

	INSIST(ev->ev_type == ISC_SOCKEVENT_INTW);

	/*
	 * Find out what socket this is and lock it.
	 */
	sock = (isc_socket_t *)ev->ev_sender;
	INSIST(VALID_SOCKET(sock));

	LOCK(&sock->lock);
	socket_log(sock, NULL, IOEVENT,
		   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_INTERNALSEND,
		   "internal_send: task %p got event %p", me, ev, sock);

	INSIST(sock->pending_send == 1);
	sock->pending_send = 0;

	INSIST(sock->references > 0);
	sock->references--;  /* the internal event is done with this socket */
	if (sock->references == 0) {
		UNLOCK(&sock->lock);
		destroy(&sock);
		return;
	}

	/*
	 * Try to do as much I/O as possible on this socket.  There are no
	 * limits here, currently.  If some sort of quantum write count is
	 * desired before giving up control, make certain to process markers
	 * regardless of quantum.
	 */
	dev = ISC_LIST_HEAD(sock->send_list);
	while (dev != NULL) {
		/*
		 * If this is a marker event, post its completion and
		 * continue the loop.
		 */
		if (dev->ev_type == ISC_SOCKEVENT_SENDMARK) {
			send_senddone_event(sock, &dev, ISC_R_SUCCESS);
			goto next;
		}

		switch (doio_send(sock, dev)) {
		case DOIO_SOFT:
			goto poke;

		case DOIO_HARD:
		case DOIO_SUCCESS:
			break;
		}

	next:
		dev = ISC_LIST_HEAD(sock->send_list);
	}

 poke:
	if (!ISC_LIST_EMPTY(sock->send_list))
		select_poke(sock->manager, sock->fd);

	UNLOCK(&sock->lock);
}

static void
process_fds(isc_socketmgr_t *manager, int maxfd,
	    fd_set *readfds, fd_set *writefds)
{
	int i;
	isc_socket_t *sock;
	isc_boolean_t unlock_sock;

	/*
	 * Process read/writes on other fds here.  Avoid locking
	 * and unlocking twice if both reads and writes are possible.
	 */
	for (i = 0 ; i < maxfd ; i++) {
#ifdef ISC_PLATFORM_USETHREADS
		if (i == manager->pipe_fds[0] || i == manager->pipe_fds[1])
			continue;
#endif /* ISC_PLATFORM_USETHREADS */

		if (manager->fdstate[i] == CLOSE_PENDING) {
			manager->fdstate[i] = CLOSED;
			FD_CLR(i, &manager->read_fds);
			FD_CLR(i, &manager->write_fds);

			close(i);

			continue;
		}

		sock = manager->fds[i];
		unlock_sock = ISC_FALSE;
		if (FD_ISSET(i, readfds)) {
			if (sock == NULL) {
				FD_CLR(i, &manager->read_fds);
				goto check_write;
			}
			unlock_sock = ISC_TRUE;
			LOCK(&sock->lock);
			if (!SOCK_DEAD(sock)) {
				if (sock->listener)
					dispatch_accept(sock);
				else
					dispatch_recv(sock);
			}
			FD_CLR(i, &manager->read_fds);
		}
	check_write:
		if (FD_ISSET(i, writefds)) {
			if (sock == NULL) {
				FD_CLR(i, &manager->write_fds);
				continue;
			}
			if (!unlock_sock) {
				unlock_sock = ISC_TRUE;
				LOCK(&sock->lock);
			}
			if (!SOCK_DEAD(sock)) {
				if (sock->connecting)
					dispatch_connect(sock);
				else
					dispatch_send(sock);
			}
			FD_CLR(i, &manager->write_fds);
		}
		if (unlock_sock)
			UNLOCK(&sock->lock);
	}
}

#ifdef ISC_PLATFORM_USETHREADS
/*
 * This is the thread that will loop forever, always in a select or poll
 * call.
 *
 * When select returns something to do, track down what thread gets to do
 * this I/O and post the event to it.
 */
static isc_threadresult_t
watcher(void *uap) {
	isc_socketmgr_t *manager = uap;
	isc_boolean_t done;
	int ctlfd;
	int cc;
	fd_set readfds;
	fd_set writefds;
	int msg;
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

			UNLOCK(&manager->lock);

			cc = select(maxfd, &readfds, &writefds, NULL, NULL);
			if (cc < 0) {
				if (!SOFT_ERROR(errno))
					FATAL_ERROR(__FILE__, __LINE__,
						    "select() %s: %s",
						    isc_msgcat_get(isc_msgcat,
							    ISC_MSGSET_GENERAL,
							    ISC_MSG_FAILED,
							    "failed"),
						    strerror(errno));
			}

			LOCK(&manager->lock);
		} while (cc < 0);


		/*
		 * Process reads on internal, control fd.
		 */
		if (FD_ISSET(ctlfd, &readfds)) {
			for (;;) {
				msg = select_readmsg(manager);

				manager_log(manager, IOEVENT,
					    isc_msgcat_get(isc_msgcat,
						     ISC_MSGSET_SOCKET,
						     ISC_MSG_WATCHERMSG,
						     "watcher got message %d"),
						     msg);

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
					done = ISC_TRUE;

					break;
				}

				/*
				 * This is a wakeup on a socket.  Look
				 * at the event queue for both read and write,
				 * and decide if we need to watch on it now
				 * or not.
				 */
				if (msg >= 0)
					wakeup_socket(manager, msg);
			}
		}

		process_fds(manager, maxfd, &readfds, &writefds);
	}

	manager_log(manager, TRACE,
		    isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
				   ISC_MSG_EXITING, "watcher exiting"));

	UNLOCK(&manager->lock);
	return ((isc_threadresult_t)0);
}
#endif /* ISC_PLATFORM_USETHREADS */

/*
 * Create a new socket manager.
 */
isc_result_t
isc_socketmgr_create(isc_mem_t *mctx, isc_socketmgr_t **managerp) {
	isc_socketmgr_t *manager;

	REQUIRE(managerp != NULL && *managerp == NULL);

#ifndef ISC_PLATFORM_USETHREADS
	if (socketmgr != NULL) {
		socketmgr->refs++;
		*managerp = socketmgr;
		return (ISC_R_SUCCESS);
	}
#endif /* ISC_PLATFORM_USETHREADS */

	manager = isc_mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);

	manager->magic = SOCKET_MANAGER_MAGIC;
	manager->mctx = NULL;
	memset(manager->fds, 0, sizeof(manager->fds));
	ISC_LIST_INIT(manager->socklist);
	if (isc_mutex_init(&manager->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
		return (ISC_R_UNEXPECTED);
	}
#ifdef ISC_PLATFORM_USETHREADS
	if (isc_condition_init(&manager->shutdown_ok) != ISC_R_SUCCESS) {
		DESTROYLOCK(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init() %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Create the special fds that will be used to wake up the
	 * select/poll loop when something internal needs to be done.
	 */
	if (pipe(manager->pipe_fds) != 0) {
		DESTROYLOCK(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "pipe() %s: %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"),
				 strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	RUNTIME_CHECK(make_nonblock(manager->pipe_fds[0]) == ISC_R_SUCCESS);
#if 0
	RUNTIME_CHECK(make_nonblock(manager->pipe_fds[1]) == ISC_R_SUCCESS);
#endif
#else /* ISC_PLATFORM_USETHREADS */
	manager->refs = 1;
#endif /* ISC_PLATFORM_USETHREADS */

	/*
	 * Set up initial state for the select loop
	 */
	FD_ZERO(&manager->read_fds);
	FD_ZERO(&manager->write_fds);
#ifdef ISC_PLATFORM_USETHREADS
	FD_SET(manager->pipe_fds[0], &manager->read_fds);
	manager->maxfd = manager->pipe_fds[0];
#else /* ISC_PLATFORM_USETHREADS */
	manager->maxfd = 0;
#endif /* ISC_PLATFORM_USETHREADS */
	memset(manager->fdstate, 0, sizeof(manager->fdstate));

#ifdef ISC_PLATFORM_USETHREADS
	/*
	 * Start up the select/poll thread.
	 */
	if (isc_thread_create(watcher, manager, &manager->watcher) !=
	    ISC_R_SUCCESS) {
		DESTROYLOCK(&manager->lock);
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_create() %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
		close(manager->pipe_fds[0]);
		close(manager->pipe_fds[1]);
		return (ISC_R_UNEXPECTED);
	}
#endif /* ISC_PLATFORM_USETHREADS */
	isc_mem_attach(mctx, &manager->mctx);

#ifndef ISC_PLATFORM_USETHREADS
	socketmgr = manager;
#endif /* ISC_PLATFORM_USETHREADS */
	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
isc_socketmgr_destroy(isc_socketmgr_t **managerp) {
	isc_socketmgr_t *manager;
	int i;
	isc_mem_t *mctx;

	/*
	 * Destroy a socket manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

#ifndef ISC_PLATFORM_USETHREADS
	if (manager->refs > 1) {
		manager->refs--;
		*managerp = NULL;
		return;
	}
#endif /* ISC_PLATFORM_USETHREADS */

	LOCK(&manager->lock);

#ifdef ISC_PLATFORM_USETHREADS
	/*
	 * Wait for all sockets to be destroyed.
	 */
	while (!ISC_LIST_EMPTY(manager->socklist)) {
		manager_log(manager, CREATION,
			    isc_msgcat_get(isc_msgcat, ISC_MSGSET_SOCKET,
					   ISC_MSG_SOCKETSREMAIN,
					   "sockets exist"));
		WAIT(&manager->shutdown_ok, &manager->lock);
	}
#else /* ISC_PLATFORM_USETHREADS */
	/*
	 * Hope all sockets have been destroyed.
	 */
	if (!ISC_LIST_EMPTY(manager->socklist)) {
		manager_log(manager, CREATION,
			    isc_msgcat_get(isc_msgcat, ISC_MSGSET_SOCKET,
					   ISC_MSG_SOCKETSREMAIN,
					   "sockets exist"));
		INSIST(0);
	}
#endif /* ISC_PLATFORM_USETHREADS */

	UNLOCK(&manager->lock);

	/*
	 * Here, poke our select/poll thread.  Do this by closing the write
	 * half of the pipe, which will send EOF to the read half.
	 * This is currently a no-op in the non-threaded case.
	 */
	select_poke(manager, SELECT_POKE_SHUTDOWN);

#ifdef ISC_PLATFORM_USETHREADS
	/*
	 * Wait for thread to exit.
	 */
	if (isc_thread_join(manager->watcher, NULL) != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_thread_join() %s",
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
#endif /* ISC_PLATFORM_USETHREADS */

	/*
	 * Clean up.
	 */
#ifdef ISC_PLATFORM_USETHREADS
	close(manager->pipe_fds[0]);
	close(manager->pipe_fds[1]);
	(void)isc_condition_destroy(&manager->shutdown_ok);
#endif /* ISC_PLATFORM_USETHREADS */

	for (i = 0 ; i < FD_SETSIZE ; i++)
		if (manager->fdstate[i] == CLOSE_PENDING)
			close(i);

	DESTROYLOCK(&manager->lock);
	manager->magic = 0;
	mctx= manager->mctx;
	isc_mem_put(mctx, manager, sizeof *manager);

	isc_mem_detach(&mctx);

	*managerp = NULL;
}

isc_result_t
isc_socket_recvv(isc_socket_t *sock, isc_bufferlist_t *buflist,
		 unsigned int minimum, isc_task_t *task,
		 isc_taskaction_t action, const void *arg)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	isc_boolean_t was_empty;
	unsigned int iocount;
	isc_buffer_t *buffer;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(buflist != NULL);
	REQUIRE(!ISC_LIST_EMPTY(*buflist));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	iocount = isc_bufferlist_availablecount(buflist);
	REQUIRE(iocount > 0);

	LOCK(&sock->lock);

	INSIST(sock->bound);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_RECVDONE, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	/***
	 *** From here down, only ISC_R_SUCCESS can be returned.  Any further
	 *** error information will result in the done event being posted
	 *** to the task rather than this function failing.
	 ***/

	/*
	 * UDP sockets are always partial read
	 */
	if (sock->type == isc_sockettype_udp)
		dev->minimum = 1;
	else {
		if (minimum == 0)
			dev->minimum = iocount;
		else
			dev->minimum = minimum;
	}

	dev->ev_sender = task;

	/*
	 * Move each buffer from the passed in list to our internal one.
	 */
	buffer = ISC_LIST_HEAD(*buflist);
	while (buffer != NULL) {
		ISC_LIST_DEQUEUE(*buflist, buffer, link);
		ISC_LIST_ENQUEUE(dev->bufferlist, buffer, link);
		buffer = ISC_LIST_HEAD(*buflist);
	}

	/*
	 * If the read queue is empty, try to do the I/O right now.
	 */
	was_empty = ISC_LIST_EMPTY(sock->recv_list);
	if (!was_empty)
		goto queue;

	switch (doio_recv(sock, dev)) {
	case DOIO_SOFT:
		goto queue;

	case DOIO_EOF:
		send_recvdone_event(sock, &dev, ISC_R_EOF);
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);

	case DOIO_HARD:
	case DOIO_SUCCESS:
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

 queue:
	/*
	 * We couldn't read all or part of the request right now, so queue
	 * it.
	 *
	 * Attach to socket and to task
	 */
	isc_task_attach(task, &ntask);
	dev->attributes |= ISC_SOCKEVENTATTR_ATTACHED;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	ISC_LIST_ENQUEUE(sock->recv_list, dev, ev_link);
	if (was_empty)
		select_poke(sock->manager, sock->fd);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_recvv: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_recv(isc_socket_t *sock, isc_region_t *region, unsigned int minimum,
		isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	isc_boolean_t was_empty;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(region != NULL);
	REQUIRE(region->length >= minimum);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	INSIST(sock->bound);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_RECVDONE, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	/*
	 * UDP sockets are always partial read.
	 */
	if (sock->type == isc_sockettype_udp)
		dev->minimum = 1;
	else {
		if (minimum == 0)
			dev->minimum = region->length;
		else
			dev->minimum = minimum;
	}

	dev->result = ISC_R_SUCCESS;
	dev->n = 0;
	dev->region = *region;
	dev->ev_sender = task;


	/*
	 * If the read queue is empty, try to do the I/O right now.
	 */
	was_empty = ISC_LIST_EMPTY(sock->recv_list);
	if (!was_empty)
		goto queue;

	switch (doio_recv(sock, dev)) {
	case DOIO_SOFT:
		goto queue;

	case DOIO_EOF:
		send_recvdone_event(sock, &dev, ISC_R_EOF);
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);

	case DOIO_HARD:
	case DOIO_SUCCESS:
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

 queue:
	/*
	 * We couldn't read all or part of the request right now, so queue
	 * it.
	 *
	 * Attach to socket and to task.
	 */
	isc_task_attach(task, &ntask);
	dev->attributes |= ISC_SOCKEVENTATTR_ATTACHED;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	ISC_LIST_ENQUEUE(sock->recv_list, dev, ev_link);
	if (was_empty)
		select_poke(sock->manager, sock->fd);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_recv: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_send(isc_socket_t *sock, isc_region_t *region,
		isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	/*
	 * REQUIRE() checking is performed in isc_socket_sendto().
	 */
	return (isc_socket_sendto(sock, region, task, action, arg, NULL,
				  NULL));
}

isc_result_t
isc_socket_sendto(isc_socket_t *sock, isc_region_t *region,
		  isc_task_t *task, isc_taskaction_t action, const void *arg,
		  isc_sockaddr_t *address, struct in6_pktinfo *pktinfo)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	isc_boolean_t was_empty;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(region != NULL);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	INSIST(sock->bound);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_SENDDONE, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	dev->region = *region;
	dev->ev_sender = task;

	set_dev_address(address, sock, dev);
	if (pktinfo != NULL) {
		socket_log(sock, NULL, TRACE, isc_msgcat, ISC_MSGSET_SOCKET,
			   ISC_MSG_PKTINFOPROVIDED,
			   "pktinfo structure provided, ifindex %u (set to 0)",
			   pktinfo->ipi6_ifindex);

		dev->attributes |= ISC_SOCKEVENTATTR_PKTINFO;
		dev->pktinfo = *pktinfo;
		/*
		 * Set the pktinfo index to 0 here, to let the kernel decide
		 * what interface it should send on.
		 */
		dev->pktinfo.ipi6_ifindex = 0;
	}

	/*
	 * If the write queue is empty, try to do the I/O right now.
	 */
	was_empty = ISC_LIST_EMPTY(sock->send_list);
	if (!was_empty)
		goto queue;

	switch (doio_send(sock, dev)) {
	case DOIO_SOFT:
		goto queue;

	case DOIO_HARD:
	case DOIO_SUCCESS:
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

 queue:
	/*
	 * We couldn't send all or part of the request right now, so queue
	 * it.
	 */
	isc_task_attach(task, &ntask);
	dev->attributes |= ISC_SOCKEVENTATTR_ATTACHED;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	ISC_LIST_ENQUEUE(sock->send_list, dev, ev_link);
	if (was_empty)
		select_poke(sock->manager, sock->fd);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_sendto: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_sendv(isc_socket_t *sock, isc_bufferlist_t *buflist,
		 isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	return (isc_socket_sendtov(sock, buflist, task, action, arg, NULL,
				   NULL));
}

isc_result_t
isc_socket_sendtov(isc_socket_t *sock, isc_bufferlist_t *buflist,
		   isc_task_t *task, isc_taskaction_t action, const void *arg,
		   isc_sockaddr_t *address, struct in6_pktinfo *pktinfo)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	isc_boolean_t was_empty;
	unsigned int iocount;
	isc_buffer_t *buffer;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(buflist != NULL);
	REQUIRE(!ISC_LIST_EMPTY(*buflist));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	iocount = isc_bufferlist_usedcount(buflist);
	REQUIRE(iocount > 0);

	LOCK(&sock->lock);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_SENDDONE, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	/*
	 * From here down, only ISC_R_SUCCESS can be returned.  Any further
	 * error information will result in the done event being posted
	 * to the task rather than this function failing.
	 */

	dev->ev_sender = task;

	set_dev_address(address, sock, dev);
	if (pktinfo != NULL) {
		dev->attributes |= ISC_SOCKEVENTATTR_PKTINFO;
		dev->pktinfo = *pktinfo;
	}

	/*
	 * Move each buffer from the passed in list to our internal one.
	 */
	buffer = ISC_LIST_HEAD(*buflist);
	while (buffer != NULL) {
		ISC_LIST_DEQUEUE(*buflist, buffer, link);
		ISC_LIST_ENQUEUE(dev->bufferlist, buffer, link);
		buffer = ISC_LIST_HEAD(*buflist);
	}

	/*
	 * If the read queue is empty, try to do the I/O right now.
	 */
	was_empty = ISC_LIST_EMPTY(sock->send_list);
	if (!was_empty)
		goto queue;

	switch (doio_send(sock, dev)) {
	case DOIO_SOFT:
		goto queue;

	case DOIO_HARD:
	case DOIO_SUCCESS:
		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

 queue:
	/*
	 * We couldn't send all or part of the request right now, so queue
	 * it.
	 */
	isc_task_attach(task, &ntask);
	dev->attributes |= ISC_SOCKEVENTATTR_ATTACHED;

	/*
	 * Enqueue the request.  If the socket was previously not being
	 * watched, poke the watcher to start paying attention to it.
	 */
	ISC_LIST_ENQUEUE(sock->send_list, dev, ev_link);
	if (was_empty)
		select_poke(sock->manager, sock->fd);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_sendtov: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_bind(isc_socket_t *sock, isc_sockaddr_t *sockaddr) {
	int on = 1;

	LOCK(&sock->lock);

	INSIST(!sock->bound);

	if (sock->pf != sockaddr->type.sa.sa_family) {
		UNLOCK(&sock->lock);
		return (ISC_R_FAMILYMISMATCH);
	}
	if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on,
		       sizeof on) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "setsockopt(%d) %s", sock->fd,
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_GENERAL,
						ISC_MSG_FAILED, "failed"));
		/* Press on... */
	}
	if (bind(sock->fd, &sockaddr->type.sa, sockaddr->length) < 0) {
		UNLOCK(&sock->lock);
		switch (errno) {
		case EACCES:
			return (ISC_R_NOPERM);
		case EADDRNOTAVAIL:
			return (ISC_R_ADDRNOTAVAIL);
		case EADDRINUSE:
			return (ISC_R_ADDRINUSE);
		case EINVAL:
			return (ISC_R_BOUND);
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "bind: %s", strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
	}

	socket_log(sock, sockaddr, TRACE,
		   isc_msgcat, ISC_MSGSET_SOCKET, ISC_MSG_BOUND, "bound");
	sock->bound = 1;

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

/*
 * Set up to listen on a given socket.  We do this by creating an internal
 * event that will be dispatched when the socket has read activity.  The
 * watcher will send the internal event to the task when there is a new
 * connection.
 *
 * Unlike in read, we don't preallocate a done event here.  Every time there
 * is a new connection we'll have to allocate a new one anyway, so we might
 * as well keep things simple rather than having to track them.
 */
isc_result_t
isc_socket_listen(isc_socket_t *sock, unsigned int backlog) {
	REQUIRE(VALID_SOCKET(sock));

	LOCK(&sock->lock);

	REQUIRE(!sock->listener);
	REQUIRE(sock->bound);
	REQUIRE(sock->type == isc_sockettype_tcp);

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
		  isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	isc_socket_newconnev_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;
	isc_socket_t *nsock;
	isc_result_t ret;
	isc_boolean_t do_poke = ISC_FALSE;

	REQUIRE(VALID_SOCKET(sock));
	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	REQUIRE(sock->listener);

	/*
	 * Sender field is overloaded here with the task we will be sending
	 * this event to.  Just before the actual event is delivered the
	 * actual ev_sender will be touched up to be the socket.
	 */
	dev = (isc_socket_newconnev_t *)
		isc_event_allocate(manager->mctx, task, ISC_SOCKEVENT_NEWCONN,
				   action, arg, sizeof (*dev));
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}
	ISC_LINK_INIT(dev, ev_link);

	ret = allocate_socket(manager, sock->type, &nsock);
	if (ret != ISC_R_SUCCESS) {
		isc_event_free((isc_event_t **)&dev);
		UNLOCK(&sock->lock);
		return (ret);
	}

	/*
	 * Attach to socket and to task.
	 */
	isc_task_attach(task, &ntask);
	nsock->references++;

	dev->ev_sender = ntask;
	dev->newsocket = nsock;

	/*
	 * Poke watcher here.  We still have the socket locked, so there
	 * is no race condition.  We will keep the lock for such a short
	 * bit of time waking it up now or later won't matter all that much.
	 */
	if (ISC_LIST_EMPTY(sock->accept_list))
		do_poke = ISC_TRUE;

	ISC_LIST_ENQUEUE(sock->accept_list, dev, ev_link);

	if (do_poke)
		select_poke(manager, sock->fd);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_connect(isc_socket_t *sock, isc_sockaddr_t *addr,
		   isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	isc_socket_connev_t *dev;
	isc_task_t *ntask = NULL;
	isc_socketmgr_t *manager;
	int cc;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(addr != NULL);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(addr != NULL);

	if (isc_sockaddr_ismulticast(addr))
		return (ISC_R_MULTICAST);

	LOCK(&sock->lock);

	REQUIRE(!sock->connecting);

	dev = (isc_socket_connev_t *)isc_event_allocate(manager->mctx, sock,
							ISC_SOCKEVENT_CONNECT,
							action,	arg,
							sizeof (*dev));
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}
	ISC_LINK_INIT(dev, ev_link);

	/*
	 * Try to do the connect right away, as there can be only one
	 * outstanding, and it might happen to complete.
	 */
	sock->address = *addr;
	cc = connect(sock->fd, &addr->type.sa, addr->length);
	if (cc < 0) {
		if (SOFT_ERROR(errno) || errno == EINPROGRESS)
			goto queue;

		switch (errno) {
#define ERROR_MATCH(a, b) case a: dev->result = b; goto err_exit;
			ERROR_MATCH(EACCES, ISC_R_NOPERM);
			ERROR_MATCH(EADDRNOTAVAIL, ISC_R_ADDRNOTAVAIL);
			ERROR_MATCH(EAFNOSUPPORT, ISC_R_ADDRNOTAVAIL);
			ERROR_MATCH(ECONNREFUSED, ISC_R_CONNREFUSED);
			ERROR_MATCH(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#ifdef EHOSTDOWN
			ERROR_MATCH(EHOSTDOWN, ISC_R_HOSTUNREACH);
#endif
			ERROR_MATCH(ENETUNREACH, ISC_R_NETUNREACH);
			ERROR_MATCH(ENOBUFS, ISC_R_NORESOURCES);
			ERROR_MATCH(EPERM, ISC_R_HOSTUNREACH);
			ERROR_MATCH(EPIPE, ISC_R_NOTCONNECTED);
#undef ERROR_MATCH
		}

		sock->connected = 0;

		UNEXPECTED_ERROR(__FILE__, __LINE__, "%d/%s",
				 errno, strerror(errno));

		UNLOCK(&sock->lock);
		isc_event_free((isc_event_t **)&dev);
		return (ISC_R_UNEXPECTED);

	err_exit:
		sock->connected = 0;
		isc_task_send(task, (isc_event_t **)&dev);

		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

	/*
	 * If connect completed, fire off the done event.
	 */
	if (cc == 0) {
		sock->connected = 1;
		sock->bound = 1;
		dev->result = ISC_R_SUCCESS;
		isc_task_send(task, (isc_event_t **)&dev);

		UNLOCK(&sock->lock);
		return (ISC_R_SUCCESS);
	}

 queue:

	/*
	 * Attach to task.
	 */
	isc_task_attach(task, &ntask);

	sock->connecting = 1;

	dev->ev_sender = ntask;

	/*
	 * Poke watcher here.  We still have the socket locked, so there
	 * is no race condition.  We will keep the lock for such a short
	 * bit of time waking it up now or later won't matter all that much.
	 */
	if (sock->connect_ev == NULL)
		select_poke(manager, sock->fd);

	sock->connect_ev = dev;

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

/*
 * Called when a socket with a pending connect() finishes.
 */
static void
internal_connect(isc_task_t *me, isc_event_t *ev) {
	isc_socket_t *sock;
	isc_socket_connev_t *dev;
	isc_task_t *task;
	int cc;
	ISC_SOCKADDR_LEN_T optlen;

	UNUSED(me);
	INSIST(ev->ev_type == ISC_SOCKEVENT_INTW);

	sock = ev->ev_sender;
	INSIST(VALID_SOCKET(sock));

	LOCK(&sock->lock);

	/*
	 * When the internal event was sent the reference count was bumped
	 * to keep the socket around for us.  Decrement the count here.
	 */
	INSIST(sock->references > 0);
	sock->references--;
	if (sock->references == 0) {
		UNLOCK(&sock->lock);
		destroy(&sock);
		return;
	}

	/*
	 * Has this event been canceled?
	 */
	dev = sock->connect_ev;
	if (dev == NULL) {
		INSIST(!sock->connecting);
		UNLOCK(&sock->lock);
		return;
	}

	INSIST(sock->connecting);
	sock->connecting = 0;

	/*
	 * Get any possible error status here.
	 */
	optlen = sizeof(cc);
	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR,
		       (void *)&cc, (void *)&optlen) < 0)
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
#define ERROR_MATCH(a, b) case a: dev->result = b; break;
			ERROR_MATCH(EACCES, ISC_R_NOPERM);
			ERROR_MATCH(EADDRNOTAVAIL, ISC_R_ADDRNOTAVAIL);
			ERROR_MATCH(EAFNOSUPPORT, ISC_R_ADDRNOTAVAIL);
			ERROR_MATCH(ECONNREFUSED, ISC_R_CONNREFUSED);
			ERROR_MATCH(EHOSTUNREACH, ISC_R_HOSTUNREACH);
#ifdef EHOSTDOWN
			ERROR_MATCH(EHOSTDOWN, ISC_R_HOSTUNREACH);
#endif
			ERROR_MATCH(ENETUNREACH, ISC_R_NETUNREACH);
			ERROR_MATCH(ENOBUFS, ISC_R_NORESOURCES);
			ERROR_MATCH(EPERM, ISC_R_HOSTUNREACH);
			ERROR_MATCH(EPIPE, ISC_R_NOTCONNECTED);
			ERROR_MATCH(ETIMEDOUT, ISC_R_TIMEDOUT);
#undef ERROR_MATCH
		default:
			dev->result = ISC_R_UNEXPECTED;
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "internal_connect: connect() %s",
					 strerror(errno));
		}
	} else {
		dev->result = ISC_R_SUCCESS;
		sock->connected = 1;
		sock->bound = 1;
	}

	sock->connect_ev = NULL;

	UNLOCK(&sock->lock);

	task = dev->ev_sender;
	dev->ev_sender = sock;
	isc_task_sendanddetach(&task, (isc_event_t **)&dev);
}

isc_result_t
isc_socket_getpeername(isc_socket_t *sock, isc_sockaddr_t *addressp) {
	isc_result_t ret;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(addressp != NULL);

	LOCK(&sock->lock);

	if (sock->connected) {
		*addressp = sock->address;
		ret = ISC_R_SUCCESS;
	} else {
		ret = ISC_R_NOTCONNECTED;
	}

	UNLOCK(&sock->lock);

	return (ret);
}

isc_result_t
isc_socket_getsockname(isc_socket_t *sock, isc_sockaddr_t *addressp) {
	ISC_SOCKADDR_LEN_T len;
	isc_result_t ret;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(addressp != NULL);

	LOCK(&sock->lock);

	if (!sock->bound) {
		ret = ISC_R_NOTBOUND;
		goto out;
	}

	ret = ISC_R_SUCCESS;

	len = sizeof addressp->type;
	if (getsockname(sock->fd, &addressp->type.sa, (void *)&len) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "getsockname: %s", strerror(errno));
		ret = ISC_R_UNEXPECTED;
		goto out;
	}
	addressp->length = (unsigned int)len;

 out:
	UNLOCK(&sock->lock);

	return (ret);
}

/*
 * Run through the list of events on this socket, and cancel the ones
 * queued for task "task" of type "how".  "how" is a bitmask.
 */
void
isc_socket_cancel(isc_socket_t *sock, isc_task_t *task, unsigned int how) {

	REQUIRE(VALID_SOCKET(sock));

	/*
	 * Quick exit if there is nothing to do.  Don't even bother locking
	 * in this case.
	 */
	if (how == 0)
		return;

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
	    && !ISC_LIST_EMPTY(sock->recv_list)) {
		isc_socketevent_t      *dev;
		isc_socketevent_t      *next;
		isc_task_t	       *current_task;

		dev = ISC_LIST_HEAD(sock->recv_list);

		while (dev != NULL) {
			current_task = dev->ev_sender;
			next = ISC_LIST_NEXT(dev, ev_link);

			if ((task == NULL) || (task == current_task))
				send_recvdone_event(sock, &dev,
						    ISC_R_CANCELED);
			dev = next;
		}
	}

	if (((how & ISC_SOCKCANCEL_SEND) == ISC_SOCKCANCEL_SEND)
	    && !ISC_LIST_EMPTY(sock->send_list)) {
		isc_socketevent_t      *dev;
		isc_socketevent_t      *next;
		isc_task_t	       *current_task;

		dev = ISC_LIST_HEAD(sock->send_list);

		while (dev != NULL) {
			current_task = dev->ev_sender;
			next = ISC_LIST_NEXT(dev, ev_link);

			if ((task == NULL) || (task == current_task))
				send_senddone_event(sock, &dev,
						    ISC_R_CANCELED);
			dev = next;
		}
	}

	if (((how & ISC_SOCKCANCEL_ACCEPT) == ISC_SOCKCANCEL_ACCEPT)
	    && !ISC_LIST_EMPTY(sock->accept_list)) {
		isc_socket_newconnev_t *dev;
		isc_socket_newconnev_t *next;
		isc_task_t	       *current_task;

		dev = ISC_LIST_HEAD(sock->accept_list);
		while (dev != NULL) {
			current_task = dev->ev_sender;
			next = ISC_LIST_NEXT(dev, ev_link);

			if ((task == NULL) || (task == current_task)) {

				ISC_LIST_UNLINK(sock->accept_list, dev,
						ev_link);

				dev->newsocket->references--;
				free_socket(&dev->newsocket);

				dev->result = ISC_R_CANCELED;
				dev->ev_sender = sock;
				isc_task_sendanddetach(&current_task,
						       (isc_event_t **)&dev);
			}

			dev = next;
		}
	}

	/*
	 * Connecting is not a list.
	 */
	if (((how & ISC_SOCKCANCEL_CONNECT) == ISC_SOCKCANCEL_CONNECT)
	    && sock->connect_ev != NULL) {
		isc_socket_connev_t    *dev;
		isc_task_t	       *current_task;

		INSIST(sock->connecting);
		sock->connecting = 0;

		dev = sock->connect_ev;
		current_task = dev->ev_sender;

		if ((task == NULL) || (task == current_task)) {
			sock->connect_ev = NULL;

			dev->result = ISC_R_CANCELED;
			dev->ev_sender = sock;
			isc_task_sendanddetach(&current_task,
					       (isc_event_t **)&dev);
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
		    isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	INSIST(sock->bound);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_RECVMARK, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	dev->result = ISC_R_SUCCESS;
	dev->minimum = 0;

	/*
	 * Bad luck.  The queue wasn't empty.  Insert this in the proper
	 * place.
	 */
	isc_task_attach(task, &ntask);

	dev->ev_sender = ntask;

	ISC_LIST_ENQUEUE(sock->recv_list, dev, ev_link);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_recvmark: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_socket_sendmark(isc_socket_t *sock,
		    isc_task_t *task, isc_taskaction_t action, const void *arg)
{
	isc_socketevent_t *dev;
	isc_socketmgr_t *manager;
	isc_task_t *ntask = NULL;

	REQUIRE(VALID_SOCKET(sock));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);

	manager = sock->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&sock->lock);

	INSIST(sock->bound);

	dev = allocate_socketevent(sock, ISC_SOCKEVENT_SENDMARK, action, arg);
	if (dev == NULL) {
		UNLOCK(&sock->lock);
		return (ISC_R_NOMEMORY);
	}

	dev->result = ISC_R_SUCCESS;
	dev->minimum = 0;

	/*
	 * Bad luck.  The queue wasn't empty.  Insert this in the proper
	 * place.
	 */
	isc_task_attach(task, &ntask);

	dev->ev_sender = ntask;

	ISC_LIST_ENQUEUE(sock->send_list, dev, ev_link);

	socket_log(sock, NULL, EVENT, NULL, 0, 0,
		   "isc_socket_sendmark: event %p -> task %p", dev, ntask);

	UNLOCK(&sock->lock);
	return (ISC_R_SUCCESS);
}

isc_sockettype_t
isc_socket_gettype(isc_socket_t *sock) {
	REQUIRE(VALID_SOCKET(sock));

	return (sock->type);
}

isc_boolean_t
isc_socket_isbound(isc_socket_t *sock) {
	isc_boolean_t val;

	LOCK(&sock->lock);
	val = ((sock->bound) ? ISC_TRUE : ISC_FALSE);
	UNLOCK(&sock->lock);

	return (val);
}

#ifndef ISC_PLATFORM_USETHREADS
void
isc__socketmgr_getfdsets(fd_set *readset, fd_set *writeset, int *maxfd) {
	if (socketmgr == NULL)
		*maxfd = 0;
	else {
		*readset = socketmgr->read_fds;
		*writeset = socketmgr->write_fds;
		*maxfd = socketmgr->maxfd + 1;
	}
}

isc_result_t
isc__socketmgr_dispatch(fd_set *readset, fd_set *writeset, int maxfd) {
	isc_socketmgr_t *manager = socketmgr;

	if (manager == NULL)
		return (ISC_R_NOTFOUND);

	process_fds(manager, maxfd, readset, writeset);
	return (ISC_R_SUCCESS);
}
#endif /* ISC_PLATFORM_USETHREADS */
