/* $Id: socket.h,v 1.10 1998/12/04 11:21:11 explorer Exp $ */

#ifndef ISC_SOCKET_H
#define ISC_SOCKET_H 1

/*****
 ***** Module Info
 *****/

/*
 * Sockets
 *
 * Provides TCP and UDP sockets for network I/O.  The sockets are event
 * sources in the task system.
 *
 * When I/O completes, a completion event for the socket is posted to the
 * event queue of the task which requested the I/O.
 *
 * MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates.
 *
 *	Clients of this module must not be holding a socket's task's lock when
 *	making a call that affects that socket.  Failure to follow this rule
 *	can result in deadlock.
 *
 *	The caller must ensure that isc_socketmgr_destroy() is called only
 *	once for a given manager.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	<TBS>
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	None.
 */

/***
 *** Imports
 ***/

#include <isc/boolean.h>
#include <isc/result.h>
#include <isc/event.h>

#include <isc/task.h>
#include <isc/region.h>
#include <isc/memcluster.h>

#include <netinet/in.h>

/***
 *** Types
 ***/

typedef struct isc_socket *isc_socket_t;
typedef struct isc_socketmgr *isc_socketmgr_t;

/*
 * XXX Export this as isc/sockaddr.h
 */
typedef struct isc_sockaddr {
	/*
	 * XXX  Must be big enough for all sockaddr types we care about.
	 */
	union {
		struct sockaddr_in sin;
	} type;
} *isc_sockaddr_t;

typedef struct isc_socketevent {
	struct isc_event	common;		/* Sender is the socket. */
	isc_result_t		result;		/* OK, EOF, whatever else */
	unsigned int		n;		/* bytes read or written */
	struct isc_region	region;		/* the region info */
	struct isc_sockaddr	address;	/* source address */
	unsigned int		addrlength;	/* length of address */
} *isc_socketevent_t;

typedef struct isc_socket_newconnev {
	struct isc_event	common;
	isc_socket_t		newsocket;
	isc_result_t		result;		/* OK, EOF, whatever else */
	struct isc_sockaddr	address;	/* source address */
	unsigned int		addrlength;	/* length of address */
} *isc_socket_newconnev_t;

typedef struct isc_socket_connev {
	struct isc_event	common;
	isc_result_t		result;		/* OK, EOF, whatever else */
} *isc_socket_connev_t;

#define ISC_SOCKEVENT_ANYEVENT  (0)
#define ISC_SOCKEVENT_RECVDONE	(ISC_EVENTCLASS_SOCKET + 1)
#define ISC_SOCKEVENT_SENDDONE	(ISC_EVENTCLASS_SOCKET + 2)
#define ISC_SOCKEVENT_NEWCONN	(ISC_EVENTCLASS_SOCKET + 3)
#define ISC_SOCKEVENT_CONNECT	(ISC_EVENTCLASS_SOCKET + 4)
#define ISC_SOCKEVENT_RECVMARK	(ISC_EVENTCLASS_SOCKET + 5)
#define ISC_SOCKEVENT_SENDMARK	(ISC_EVENTCLASS_SOCKET + 6)

/*
 * Internal events.
 */
#define ISC_SOCKEVENT_INTIO	(ISC_EVENTCLASS_SOCKET + 257)
#define ISC_SOCKEVENT_INTCONN	(ISC_EVENTCLASS_SOCKET + 258)


typedef enum {
	isc_socket_udp,
	isc_socket_tcp
} isc_sockettype_t;

typedef enum {
	isc_sockshut_reading,
	isc_sockshut_writing,
	isc_sockshut_all
} isc_socketshutdown_t;

/***
 *** Socket and Socket Manager Functions
 ***
 *** Note: all Ensures conditions apply only if the result is success for
 *** those functions which return an isc_result.
 ***/

isc_result_t
isc_socket_create(isc_socketmgr_t manager,
		  isc_sockettype_t type,
		  isc_socket_t *socketp);
/*
 * Create a new 'type' socket managed by 'manager'.
 *
 * Requires:
 *
 *	'manager' is a valid manager
 *
 *	'socketp' is a valid pointer, and *socketp == NULL
 *
 * Ensures:
 *
 *	'*socketp' is attached to the newly created socket
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_NORESOURCES
 *	ISC_R_UNEXPECTED
 */

int
isc_socket_cancel(isc_socket_t socket, isc_task_t task,
		  unsigned int how);
/*
 * Cancel pending I/O of the type specified by "how".
 *
 * Note: if "task" is NULL, then the cancel applies to all tasks using the
 * socket.
 *
 * Requires:
 *
 *	"socket" is a valid socket
 *
 *	"task" is NULL or a valid task
 *
 * "how" is a bitmask describing the type of cancelation to perform.
 * The type ISC_SOCKCANCEL_ALL will cancel all pending I/O on this
 * socket.
 *
 * ISC_SOCKCANCEL_RECV:
 *	Cancel pending isc_socket_recv() calls.
 *
 * ISC_SOCKCANCEL_SEND:
 *	Cancel pending isc_socket_send() and isc_socket_sendto() calls.
 *
 * ISC_SOCKCANCEL_
 */

void 
isc_socket_shutdown(isc_socket_t socket, isc_socketshutdown_t how);
/*
 * Shutdown 'socket' according to 'how'.
 *
 * Requires:
 *
 *	'socket' is a valid socket.
 *
 *	'task' is NULL or is a valid task.
 *
 *	If 'how' is 'isc_sockshut_reading' or 'isc_sockshut_all' then
 *
 *		The read queue must be empty.
 *
 *		No further read requests may be made.
 *
 *	If 'how' is 'isc_sockshut_writing' or 'isc_sockshut_all' then
 *
 *		The write queue must be empty.
 *
 *		No further write requests may be made.
 */

void
isc_socket_attach(isc_socket_t socket, isc_socket_t *socketp);
/*
 * Attach *socketp to socket.
 *
 * Requires:
 *
 *	'socket' is a valid socket.
 *
 *	'socketp' points to a NULL socket.
 *
 * Ensures:
 *
 *	*socketp is attached to socket.
 */

void 
isc_socket_detach(isc_socket_t *socketp);
/*
 * Detach *socketp from its socket.
 *
 * Notes:
 *
 * 	Detaching the last reference may cause any still-pending I/O to be
 *	cancelled.
 * 
 * Requires:
 *
 *	'socketp' points to a valid socket.
 *
 * Ensures:
 *
 *	*socketp is NULL.
 *
 *	If '*socketp' is the last reference to the socket,
 *	then:
 *
 *		The socket will be shutdown (both reading and writing)
 *		for all tasks.
 *
 *		All resources used by the socket have been freed
 */

isc_result_t
isc_socket_bind(isc_socket_t socket, struct isc_sockaddr *addressp,
		int length);
/*
 * Bind 'socket' to '*addressp'.
 *
 * Requires:
 *
 *	'socket' is a valid socket
 *
 *	'addressp' points to a valid isc_sockaddr.
 *
 *	'length' is approprate for the isc_sockaddr type.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOPERM
 *	ISC_R_ADDRNOTAVAIL
 *	ISC_R_ADDRINUSE
 *	ISC_R_BOUND
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_listen(isc_socket_t socket, int backlog);
/*
 * Set listen mode on the socket.  After this call, the only function that
 * can be used (other than attach and detach) is isc_socket_accept().
 *
 * Notes:
 *
 *	'backlog' is as in the UNIX system call listen() and may be
 *	ignored by non-UNIX implementations.
 *
 * Requires:
 *
 *	'socket' is a valid TCP socket.
 *	'backlog' be >= 0.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_accept(isc_socket_t socket,
		  isc_task_t task, isc_taskaction_t action, void *arg);
/*
 * Queue accept event.  When a new connection is received, the task will
 * get an ISC_SOCKEVENT_NEWCONN event with the sender set to the listen
 * socket.  The new socket structure is sent inside the isc_socket_newconnev_t
 * event type, and is attached to the task 'task'.
 *
 * REQUIRES:
 *	'socket' is a valid TCP socket that isc_socket_listen() has been
 *	called on
 *
 *	'task' is a valid task
 *
 *	'action' is a valid action
 *
 * RETURNS:
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_connect(isc_socket_t socket, struct isc_sockaddr *addressp,
		   int length, isc_task_t task, isc_taskaction_t action,
		   void *arg);
/*
 * Connect 'socket' to peer with address *saddr.  When the connection
 * succeeds, or when an error occurs, a CONNECT event with action 'action'
 * and arg 'arg' will be posted to the event queue for 'task'.
 *
 * Requires:
 *
 *	'socket' is a valid TCP socket
 *
 *	'addressp' points to a valid isc_sockaddr
 *
 *	'length' is approprate for the isc_sockaddr type
 *
 *	'task' is a valid task
 *
 *	'action' is a valid action
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_UNEXPECTED
 *
 * Posted event's result code:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_TIMEDOUT
 *	ISC_R_CONNREFUSED
 *	ISC_R_NETUNREACH
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_getpeername(isc_socket_t socket, struct isc_sockaddr *addressp,
		       int *lengthp);
/*
 * Get the name of the peer connected to 'socket'.
 *
 * Requires:
 *
 *	'socket' is a valid TCP socket.
 *
 *	'addressp' points to '*lengthp' bytes.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_TOOSMALL
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_getsockname(isc_socket_t socket, struct isc_sockaddr *addressp,
		       int *lengthp);
/*
 * Get the name of 'socket'.
 *
 * Requires:
 *
 *	'socket' is a valid socket.
 *
 *	'addressp' points to '*lengthp' bytes.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_TOOSMALL
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_socket_recv(isc_socket_t socket, isc_region_t region,
		isc_boolean_t partial,
		isc_task_t task, isc_taskaction_t action, void *arg);
/*
 * Receive from 'socket', storing the results in region.
 *
 * Notes:
 *
 *	Let 'length' refer to the length of 'region'.
 *
 *	If 'partial' is true, then at most 'length' bytes will be read.
 *	Otherwise the read will not complete until exactly 'length' bytes
 *	have been read.
 *
 *	The read will complete when the desired number of bytes have been
 *	read, if end-of-input occurs, or if an error occurs.  A read done
 *	event with the given 'action' and 'arg' will be posted to the
 *	event queue of 'task'.
 *
 *	The caller may neither read from nor write to 'region' until it
 *	has received the read completion event.
 *
 * Requires:
 *
 *	'socket' is a valid socket
 *
 *	'region' is a valid region
 *
 *	'task' is a valid task
 *
 *	action != NULL and is a valid action
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_UNEXPECTED
 *
 * Event results:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_UNEXPECTED
 *	XXX needs other net-type errors
 */

isc_result_t
isc_socket_send(isc_socket_t socket, isc_region_t region,
		isc_task_t task, isc_taskaction_t action, void *arg);
isc_result_t
isc_socket_sendto(isc_socket_t socket, isc_region_t region,
		  isc_task_t task, isc_taskaction_t action, void *arg,
		  isc_sockaddr_t address, unsigned int addrlength);
/*
 * Send the contents of 'region' to the socket's peer.
 *
 * Notes:
 *
 *	Shutting down the requestor's task *may* result in any
 *	still pending writes being dropped.
 *
 *	If 'action' is NULL, then no completion event will be posted.
 *
 *	The caller may neither read from nor write to 'region' until it
 *	has received the write completion event, or all references to the
 *	socket have been detached.
 *
 * Requires:
 *
 *	'socket' is a valid socket
 *
 *	'region' is a valid region
 *
 *	'task' is a valid task
 *
 *	action == NULL or is a valid action
 *
 * Returns:
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_UNEXPECTED
 *
 * Event results:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_UNEXPECTED
 *	XXX needs other net-type errors
 */

isc_result_t
isc_socketmgr_create(isc_memctx_t mctx, isc_socketmgr_t *managerp);
/*
 * Create a socket manager.
 *
 * Notes:
 *
 *	All memory will be allocated in memory context 'mctx'.
 *
 * Requires:
 *
 *	'mctx' is a valid memory context.
 *
 *	'managerp' points to a NULL isc_socketmgr_t.
 *
 * Ensures:
 *
 *	'*managerp' is a valid isc_socketmgr_t.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_UNEXPECTED
 */

void
isc_socketmgr_destroy(isc_socketmgr_t *managerp);
/*
 * Destroy a socket manager.
 *
 * Notes:
 *	
 *	This routine blocks until there are no sockets left in the manager,
 *	so if the caller holds any socket references using the manager, it
 *	must detach them before calling isc_socketmgr_destroy() or it will
 *	block forever.
 *
 * Requires:
 *
 *	'*managerp' is a valid isc_socketmgr_t.
 *
 *	All sockets managed by this manager are fully detached.
 *
 * Ensures:
 *
 *	*managerp == NULL
 *
 *	All resources used by the manager have been freed.
 */

#endif /* ISC_SOCKET_H */
