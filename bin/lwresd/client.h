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

#include <isc/list.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>

typedef struct client_s client_t;
struct client_s {
	isc_socket_t	       *socket;			/* socket to reply */
	isc_sockaddr_t		sockaddr;		/* where to reply */
	unsigned char		buffer[LWRES_RECVLENGTH]; /* receive buffer */

	ISC_LINK(client_t)	link;
};

typedef struct clientmgr_s clientmgr_t;
struct clientmgr_s {
	isc_task_t	       *task;		/* owning task */
	ISC_LIST(client_t)	idle;		/* idle client slots */
	ISC_LIST(client_t)	running;	/* running clients */
};

#endif /* LWD_CLIENT_H */
