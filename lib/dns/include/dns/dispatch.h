#ifndef DNS_DISPATCH_H
#define DNS_DISPATCH_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Dispatch Management
 *
 * 	Shared UDP and single-use TCP dispatches for queries and responses.
 *
 * MP:
 *
 *     	All locking is performed internally to each dispatch.
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
#include <isc/sockaddr.h>

#include <dns/types.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

#define DNS_DISPATCHEVENT_RECV	(ISC_EVENTCLASS_DNS + 1) /* XXXMLG */

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
typedef struct dns_dispatchevent dns_dispatchevent_t;
struct dns_dispatchevent_t {
	ISC_EVENT_COMMON(dns_dispatchevent_t);	/* standard event common */
	dns_result_t		result;		/* result code */
	isc_int16_t		id;		/* message id */
	isc_sockaddr_t		addr;		/* address recv'd from */
	unsigned int		lattributes;	/* some private, some public */
	isc_buffer_t	        buffer;		/* data buffer */
};

typedef struct dns_dispatch dns_dispatch_t;
typedef struct dns_resentry dns_resentry_t; /* XXX name change */

/*
 * Private attributes of events
 */
#define DNS_DISPATCHATTR_MPOOL		0x00010000 /* allocated via mpool */

/*
 * Public attributes of events
 */
#define DNS_DISPATCHATTR_TCP		0x00000001 /* is TCP */
#define DNS_DISPATCHATTR_UDP		0x00000002 /* is UDP */

dns_result_t
dns_dispatch_create(isc_mem_t *mctx, isc_socket_t *sock, isc_task_t *task,
		    unsigned int maxbuffersize, unsigned int copythresh,
		    unsigned int maxbuffers, unsigned int maxrequests,
		    dns_dispatch_t **disp);
/*
 * Create a new dns_dispatch and attach it to the provided isc_socket_t.
 *
 * For all dispatches, "maxbuffersize" is the maximum packet size we will
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
dns_dispatch_destroy(dns_dispatch_t **disp);
/*
 * Destroys dispatch.  All buffers and other bits must be returned to the
 * dispatch before this is called.
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
dns_dispatch_addresponse(dns_dispatch_t *disp, isc_sockaddr_t *dest,
			 isc_task_t *task, isc_taskaction_t action, void *arg,
			 isc_uint16_t *idp, dns_resentry_t **resp);
/*
 * Add a response entry for this dispatch.
 *
 * "*idp" is filled in with the assigned message ID, and *resp is filled in
 * to contain the magic token used to request event flow stop.
 *
 * Events are generated each time a packet comes in until the dispatch's quota
 * maximum is reached.
 *
 * Requires:
 *	"idp" be non-NULL.
 *
 *	"task" "action" and "arg" be set as appropriate.
 *
 *	"dest" be non-NULL and valid.
 *
 *	"resp" be non-NULL and *resp be NULL
 *
 * Ensures:
 *
 *	<id, dest> is a unique tuple.  That means incoming messages
 *	are identifiable.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOMEMORY		-- memory could not be allocated.
 *	DNS_R_NOMORE		-- no more message ids can be allocated
 *				   for this destination.
 */

void
dns_dispatch_removeresponse(dns_dispatch_t *disp, dns_resentry_t **resp,
			    dns_dispatchevent_t **sockevent);
/*
 * Stops the flow of responses for the provided id and destination.
 * If "sockevent" is non-NULL, the dispatch event and associated buffer is
 * also returned to the system.
 *
 * Requires:
 *	"resp" != NULL and "*resp" contain a value previously allocated
 *	by dns_dispatch_addresponse();
 *
 * Ensures:
 *	< mumble >
 *
 * Returns:
 *	< mumble >
 */

dns_result_t
dns_dispatch_addrequest(dns_dispatch_t *disp,
			isc_task_t *task, isc_taskaction_t action, void *arg,
			dns_resentry_t **resp);
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

void
dns_dispatch_removerequest(dns_dispatch_t *disp, dns_resentry_t **resp,
			   dns_dispatchevent_t **sockevent);
/*
 * Stops the flow of responses for the provided id and destination.
 * If "sockevent" is non-NULL, the dispatch event and associated buffer is
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
dns_dispatch_freeevent(dns_dispatch_t *disp, dns_dispatchevent_t **sockevent);
/*
 * Return a dispatchevent and associated buffer to the dispatch.  This needs
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

#endif /* DNS_DISPATCH_H */
