#ifndef DNS_SOCKET_H
#define DNS_SOCKET_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Socket Management
 *
 * 	Shared UDP and single-use TCP sockets for queries and responses.
 *
 * MP:
 *
 *     	All locking is performed internally to each socket.
 *
 * Reliability:
 *
 * Resources:
 *
 * Security:
 *
 *	Depends on the isc_socket_t and dns_message_t for prevention of
 *	buffer overruns.
 *
 * Standards:
 *
 *	None.
 */

/***
 *** Imports
 ***/

#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/lang.h>

#include <dns/types.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

#define DNS_SOCKETEVENT_RECV	(ISC_EVENTCLASS_DNS + 1) /* XXXMLG */

/*
 * This event is sent to a task when a response (or request) comes in.
 * No part of this structure should ever be modified by the caller,
 * other than parts of the buffer.  The holy parts of the buffer are
 * the base and size of the buffer.  All other parts of the buffer may
 * be used.  On event delivery the used region contains the packet.
 *
 * "id" is the received message id,
 *
 * "addr" is the host that sent it to us,
 *
 * "buffer" holds state on the received data.
 *
 * The "free" routine for this event will clean up itself as well as
 * any buffer space allocated from common pools.
 */
typedef struct dns_socketevent dns_socketevent_t;
struct dns_socketevent_t {
	ISC_EVENT_COMMON(dns_sockevent_t);	/* standard event common */
	dns_result_t		result;		/* result code */
	isc_int16_t		id;		/* message id */
	isc_sockaddr_t		addr;		/* address recv'd from */
	unsigned int		attributes;	/* some private, some public */
	isc_buffer_t	        buffer;		/* data buffer */
};

/*
 * Private attributes of events (will be in socket.c)
 */
#define DNS_SOCKETATTR_MPOOL		0x00010000 /* allocated via mpool */

/*
 * Public attributes of events
 */
#define DNS_SOCKETATTR_TCP		0x00000001 /* is TCP */
#define DNS_SOCKETATTR_UDP		0x00000002 /* is UDP */

/*
 * Private structure (will be in socket.c)
 */
typedef struct dns_socket dns_socket_t;
struct dns_socket {
	unsigned int		magic;		/* magic */
	isc_mem_t	       *mctx;		/* memory context */
	isc_task_t	       *task;		/* internal task */
	isc_socket_t	       *socket;		/* isc socket attached to */
	unsigned int		buffersize;	/* size of each buffer */

	isc_mutex_t		lock;		/* locks all below */
	unsigned int		refcount;	/* number of users */
	isc_mempool_t	       *epool;		/* memory pool for events */
	isc_mempool_t	       *bpool;		/* memory pool for buffers */
	dns_restable_t		restable;	/* response table */
	ISC_LIST(dns_sockevent_t) rq_handlers;	/* request handler list */
};

dns_result_t
dns_socket_create(isc_mem_t *mctx, isc_socket_t *sock, isc_taskmgr_t *taskmgr,
		  unsigned int maxbuffersize, unsigned int copythresh,
		  unsigned int maxbuffers, unsigned int maxrequests,
		  dns_socket_t **dsock);
/*
 * Create a new dns_socket and attach it to the provided isc_socket_t.
 *
 * For all sockets, "maxbuffersize" is the maximum packet size we will
 * accept.  For UDP packets, "copythresh" is the minimum size a packet
 * needs to be before a copy is performed into a smaller, exactly sized
 * buffer.  "copythresh" is ignored for TCP packets, which always get an
 * exactly sized buffer.
 *
 * "maxbuffers" and "maxrequests" control the number of buffers in the
 * overall system and the number of buffers which can be allocated to
 * requests.
 *
 * Requires:
 *
 *	mctx is a valid memory context.
 *
 *	sock is a valid.
 *
 *	taskmgr is a valid task manager.
 *
 * 	"buffersize" >= 512, which is the minimum receive size for a
 *	DNS message.
 *
 *	For UDP sockets, "copythresh" <= "buffersize".  If "copythresh" == 0,
 *	copying is never done, and if == UINT_MAX, copying is always done.
 *
 *	maxbuffers > 0.
 *
 *	maxrequests <= maxbuffers.
 */

void
dns_socket_destroy(dns_socket_t **dsock);
/*
 * Destroys socket.  All buffers and other bits must be returned to the
 * socket before this is called.
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

dns_result_t
dns_socket_addresponse(dns_socket_t *dsock, isc_sockaddr_t *dest,
		       isc_uint16_t *id, isc_task_t *task,
		       isc_taskaction_t action, void *arg);
/*
 * Add a response entry for this socket.
 *
 * "*id" is filled in with the assigned message ID.
 *
 * Events are generated each time a packet comes in until the socket's quota
 * maximum is reached.
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *
 *	<id, dest> is a unique tuple.  That means incoming messages
 *	are identifiable.
 *
 * Returns:
 *	< mumble >
 */

dns_result_t
dns_socket_removeresponse(dns_socket_t *dsock, dns_socketevent_t **sockevent,
			  isc_sockaddr_t *dest, isc_uint16_t id);
/*
 * Stops the flow of responses for the provided id and destination.
 * If "sockevent" is non-NULL, the socket event and associated buffer is
 * also returned to the system.
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

dns_result_t
dns_socket_addrequest(dns_socket_t *dsock,
		      isc_task_t *task, isc_taskaction_t action, void *arg);
/*
 * Aranges for a one-shot request handler.  Only one request will ever be
 * handled per call to this function.  (Or should this be automatically
 * repeating?)
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

dns_result_t
dns_socket_removerequest(dns_socket_t *dsock,
			 isc_task_t *task, isc_taskaction_t action, void *arg);
/*
 * Stops the flow of responses for the provided id and destination.
 * If "sockevent" is non-NULL, the socket event and associated buffer is
 * also returned to the system.
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

void
dns_socket_freeevent(dns_socket_t *dsock, dns_socketevent_t **sockevent);
/*
 * Return a socketevent and associated buffer to the socket.  This needs
 * to be called if more events are desired but a particular event is fully
 * processed, and the associated buffer is no longer needed.
 *
 * Requires:
 *	< mumble >
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

ISC_LANG_ENDDECLS

#endif /* DNS_SOCKET_H */
