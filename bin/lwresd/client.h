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
	isc_uint32_t		length;		/* length recv'd */

	isc_boolean_t		isidle;

	ISC_LINK(client_t)	link;
};

struct clientmgr_s {
	isc_task_t	       *task;		/* owning task */
	isc_socket_t	       *sock;		/* socket to use */
	dns_view_t	       *view;
	unsigned int		flags;
	isc_event_t		sdev;		/* shutdown event */
	ISC_LIST(client_t)	idle;		/* idle client slots */
	ISC_LIST(client_t)	running;	/* running clients */
};

#define CLIENTMGR_FLAG_RECVPENDING		0x00000001
#define CLIENTMGR_FLAG_SHUTTINGDOWN		0x00000002

void client_recv(isc_task_t *, isc_event_t *);
void client_shutdown(isc_task_t *, isc_event_t *);
isc_result_t client_start_recv(clientmgr_t *);

#endif /* LWD_CLIENT_H */
