/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef LWD_CLIENT_H
#define LWD_CLIENT_H 1

#include <isc/event.h>
#include <isc/eventclass.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>

#include <dns/adb.h>
#include <dns/cache.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/name.h>

#define LWRD_EVENTCLASS		ISC_EVENTCLASS(4242)

#define LWRD_SHUTDOWN		(LWRD_EVENTCLASS + 0x0001)

typedef struct client_s client_t;
typedef struct clientmgr_s clientmgr_t;

struct client_s {
	isc_sockaddr_t		sockaddr;	/* where to reply */
	clientmgr_t	       *clientmgr;	/* our parent */
	unsigned char		buffer[LWRES_RECVLENGTH]; /* receive buffer */
	isc_uint32_t		recvlength;	/* length recv'd */

	unsigned char	       *sendbuf;
	isc_uint32_t		sendlength;

	unsigned int		state;

	dns_adbfind_t		*v4find;
	dns_adbfind_t		*v6find;

	unsigned int		find_done;	/* addrs we have */
	unsigned int		find_wanted;
	

	ISC_LINK(client_t)	link;
};

/*
 * Client states.
 *
 * _IDLE	The client is not doing anything at all.
 *
 * _RECV	The client is waiting for data after issuing a socket recv().
 *
 * _RECVDONE	Data has been received, and is being processed.
 *
 * _FINDWAIT	An adb (or other) request was made that cannot be satisfied
 *		immediately.  An event will wake the client up.
 *
 * _SEND	All data for a response has completed, and a reply was
 *		sent via a socket send() call.
 *
 * _SENDDONE	The send done event was received.
 *
 * Badly formatted state table:
 *
 *	IDLE -> RECV when client has a recv() queued.
 *
 *	RECV -> RECVDONE when recvdone event received.
 *
 *	RECVDONE -> SEND if the data for a reply is at hand.
 *	RECVDONE -> FINDWAIT if more searching is needed, and events will
 *		eventually wake us up again.
 *
 *	FINDWAIT -> SEND when enough data was received to reply.
 *
 *	SENDDONE -> IDLE when a senddone event was received.
 *
 *	At any time -> IDLE on error.  Sometimes this will be -> SEND
 *	instead, if enough data is on hand to reply with a meaningful
 *	error.
 *
 *	Packets which are badly formatted may or may not get error returns.
 */
#define CLIENT_STATE_IDLE		1
#define CLIENT_STATE_RECV		2
#define CLIENT_STATE_RECVDONE		3
#define CLIENT_STATE_FINDWAIT		4
#define CLIENT_STATE_SEND		5
#define CLIENT_STATE_SENDDONE		6

#define CLIENT_ISIDLE(c)	((c)->state == CLIENT_STATE_IDLE)
#define CLIENT_ISRECV(c)	((c)->state == CLIENT_STATE_RECV)
#define CLIENT_ISRECVDONE(c)	((c)->state == CLIENT_STATE_RECVDONE)
#define CLIENT_ISFINDWAIT(c)	((c)->state == CLIENT_STATE_FINDWAIT)
#define CLIENT_ISSEND(c)	((c)->state == CLIENT_STATE_SEND)
#define CLIENT_ISSENDDONE(c)	((c)->state == CLIENT_STATE_SENDDONE)

#define CLIENT_SETIDLE(c)	((c)->state = CLIENT_STATE_IDLE)
#define CLIENT_SETRECV(c)	((c)->state = CLIENT_STATE_RECV)
#define CLIENT_SETRECVDONE(c)	((c)->state = CLIENT_STATE_RECVDONE)
#define CLIENT_SETFINDWAIT(c)	((c)->state = CLIENT_STATE_FINDWAIT)
#define CLIENT_SETSEND(c)	((c)->state = CLIENT_STATE_SEND)
#define CLIENT_SETSENDDONE(c)	((c)->state = CLIENT_STATE_SENDDONE)

struct clientmgr_s {
	isc_task_t	       *task;		/* owning task */
	isc_socket_t	       *sock;		/* socket to use */
	dns_view_t	       *view;
	unsigned int		flags;
	isc_event_t		sdev;		/* shutdown event */
	lwres_context_t	       *lwctx;		/* lightweight proto context */
	ISC_LIST(client_t)	idle;		/* idle client slots */
	ISC_LIST(client_t)	running;	/* running clients */
};

#define CLIENTMGR_FLAG_RECVPENDING		0x00000001
#define CLIENTMGR_FLAG_SHUTTINGDOWN		0x00000002

void client_recv(isc_task_t *, isc_event_t *);
void client_shutdown(isc_task_t *, isc_event_t *);
isc_result_t client_start_recv(clientmgr_t *);

/*
 * Processing functions of various types.
 */
isc_result_t process_gabn(client_t *, lwres_buffer_t *, lwres_lwpacket_t *);
isc_result_t process_gnba(client_t *, lwres_buffer_t *, lwres_lwpacket_t *);
isc_result_t process_noop(client_t *, lwres_buffer_t *, lwres_lwpacket_t *);

#endif /* LWD_CLIENT_H */
