
#include "attribute.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
#define BROADCAST(cvp) \
	INSIST(isc_condition_broadcast((cvp)) == ISC_R_SUCCESS);
#define SIGNAL(cvp) \
	INSIST(isc_condition_signal((cvp)) == ISC_R_SUCCESS);
#define WAIT(cvp, lp) \
	INSIST(isc_condition_wait((cvp), (lp)) == ISC_R_SUCCESS);
#define WAITUNTIL(cvp, lp, tp) \
	isc_condition_waituntil((cvp), (lp), (tp))

/*
 * Debugging
 */
#if 1
#define XTRACE(a)	fprintf(stderr, a)
#define XENTER(a)	fprintf(stderr, "ENTER %s\n", (a))
#define XEXIT(a)	fprintf(stderr, "EXIT %s\n", (a))
#else
#define XTRACE(a)
#define XENTER(a)
#define XEXIT(a)
#endif

/*
 * A socket request.  These are allocated XXX
 */
struct isc_socket_req {
	isc_task_t		task;
};
	

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
	LIST(struct isc_socket_req)	read_reqs;
	LIST(struct isc_socket_req)	write_reqs;
	/* Locked by manager lock. */
	isc_sockettype_t		type;
	LINK(struct isc_socket)		link;
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
	LIST(struct isc_socket)		sockets;
	unsigned int			nscheduled;
	isc_thread_t			thread;
	int				pipe_fds[2]; /* XXX lock needed? */
	fd_set				read_fds;  /* XXX This sucks... */
	fd_set				write_fds;
};

#define SELECT_POKE_SHUTDOWN		(1)
#define SELECT_POKE_REFRESH		(2)

typedef unsigned long select_msg_t;

/*
 * poke the select loop when there is something for us to do.
 */
static void
select_poke(isc_socketmgr_t mgr, select_msg_t msg)
{
	write(mgr->pipe_fds[1], &msg, sizeof(select_msg_t));
}

/*
 * read a message on the internal fd.
 */
static select_msg_t
select_readmsg(isc_socketmgr_t mgr)
{
	select_msg_t msg;

	read(mgr->pipe_fds[0], &msg, sizeof(select_msg_t));

	return msg;
}

/*
 * Set a socket up for reading or writing.  This is a low level, internal
 * routine.
 *
 * Caller must ensure locking.
 */
static inline isc_result_t
schedule(isc_socket_t sock)
{
	isc_result_t result;
	isc_socketmgr_t manager;

	/*
	 * do stuff here to arange to track I/O on this socket.
	 */

	return (ISC_R_SUCCESS);
}

/*
 * Remove either read, write, or both from a socket.
 *
 * Caller must ensure locking.
 */
static inline void
deschedule(isc_socket_t sock)
{
	isc_boolean_t need_wakeup = ISC_FALSE;
	isc_socketmgr_t manager;

	manager = sock->manager;
}

/*
 * Kill.
 *
 * Caller must ensure locking.
 */
static void
destroy(isc_socket_t sock)
{
	isc_socketmgr_t manager = sock->manager;

	LOCK(&manager->lock);

	/*
	 * XXX
	 * This is going to be tricky...  Run through the list of all
	 * tasks attached to this socket and purge events in their
	 * queues.
	 */
	deschedule(sock);
	UNLINK(manager->sockets, sock, link);

	UNLOCK(&manager->lock);

	(void)isc_mutex_destroy(&sock->lock);
	sock->magic = 0;
	isc_mem_put(manager->mctx, sock, sizeof *sock);
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
	isc_socket_t sock;
	isc_result_t result;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(socketp != NULL && *socketp == NULL);

	XENTER("isc_socket_create");

	sock = isc_mem_get(manager->mctx, sizeof *sock);
	if (sock == NULL)
		return (ISC_R_NOMEMORY);

	sock->magic = SOCKET_MAGIC;
	sock->manager = manager;
	sock->references = 1;
	sock->type = type;

	/*
	 * set up list of readers and writers to be initially empty
	 */
	INIT_LIST(sock->read_reqs);
	INIT_LIST(sock->write_reqs);

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
		isc_mem_put(manager->mctx, sock, sizeof *sock);

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

	/*
	 * initialize the lock
	 */
	if (isc_mutex_init(&sock->lock) != ISC_R_SUCCESS) {
		isc_mem_put(manager->mctx, sock, sizeof *sock);
		close(sock->fd);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the socket like we normally would because
	 * there are no external references to it yet.
	 */

	APPEND(manager->sockets, sock, link);
	result = schedule(sock);

	UNLOCK(&manager->lock);

	if (result == ISC_R_SUCCESS)
		*socketp = sock;

	XEXIT("isc_socket_create");

	return (result);
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
	isc_boolean_t free_socket = ISC_FALSE;

	REQUIRE(socketp != NULL);
	sock = *socketp;
	REQUIRE(VALID_SOCKET(sock));

	XENTER("isc_socket_detach");

	LOCK(&sock->lock);
	REQUIRE(sock->references > 0);
	sock->references--;
	if (sock->references == 0)
		free_socket = ISC_TRUE;
	UNLOCK(&sock->lock);
	
	if (free_socket)
		destroy(sock);

	XEXIT("isc_socket_detach");

	*socketp = NULL;
}

static void
dispatch(isc_socketmgr_t manager, isc_socket_t sock)
{
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t post_event;
	isc_boolean_t need_schedule;
	isc_event_t event;
	isc_eventtype_t type = 0;
	isc_result_t result;

	while (manager->nscheduled > 0 && !done) {
		/*
		 * Do what here? XXX
		 */
	} 
}

/*
 * This is the task that will loop forever, always in a select or poll call.
 * When select returns something to do, track down what thread gets to do
 * this I/O and post the event to it.
 */
static isc_threadresult_t
WINAPI
run(void *uap)
{
	isc_socketmgr_t manager = uap;
	isc_boolean_t done;
	int ctlfd;
	int cc;
	fd_set readfds;
	fd_set writefds;
	select_msg_t msg;

	/*
	 * Get the control fd here.  This will never change.
	 */
	LOCK(&manager->lock);
	ctlfd = manager->pipe_fds[0];

	done = ISC_FALSE;
	while (!done) {
		readfds = manager->read_fds;
		writefds = manager->write_fds;

		UNLOCK(&manager->lock);

		/*
		 * call select/poll.  This will block. XXX flesh out
		 */
		cc = select(FD_SETSIZE, &readfds, &writefds, NULL, NULL);
		if (cc < 0) {
			if (errno != EINTR)
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "select returned error (%s)",
						 strerror(errno));
		}

		LOCK(&manager->lock);

		/*
		 * Process reads on internal, control fd.
		 */
		if (FD_ISSET(ctlfd, &readfds)) {
			msg = select_readmsg(manager);

			/*
			 * handle shutdown message.  No other type is handled
			 * here, as REFRESH tells us to reread our fd_sets,
			 * which we always do at the top of the loop.
			 */
			if (msg == SELECT_POKE_SHUTDOWN)
				done = ISC_TRUE;
		}

		/*
		 * Process read/writes on other fds here
		 */
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
	INIT_LIST(manager->sockets);
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

	/*
	 * Set up initial state for the select loop
	 */
	FD_ZERO(&manager->read_fds);
	FD_ZERO(&manager->write_fds);
	FD_SET(manager->pipe_fds[0], &manager->read_fds);

	/*
	 * Start up the select/poll thread.
	 */
	if (isc_thread_create(run, manager, &manager->thread) !=
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
	REQUIRE(EMPTY(manager->sockets));
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
