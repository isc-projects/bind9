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

#ifndef NS_CLIENT_H
#define NS_CLIENT_H 1

#include <isc/types.h>
#include <isc/stdtime.h>
#include <isc/buffer.h>

#include <dns/types.h>
#include <dns/tcpmsg.h>

#include <named/types.h>
#include <named/query.h>

typedef enum ns_clienttype {
	ns_clienttype_basic = 0,
	ns_clienttype_recursive,
	ns_clienttype_axfr,
	ns_clienttype_ixfr,
	ns_clienttype_tcp
} ns_clienttype_t;

typedef enum {
	ns_clientstate_idle = 0,
	ns_clientstate_listening,
	ns_clientstate_reading,
	ns_clientstate_working,
	ns_clientstate_waiting
} ns_clientstate_t;

struct ns_client {
	unsigned int			magic;
	isc_mem_t *			mctx;
	ns_clientmgr_t *		manager;
	ns_clienttype_t			type;
	ns_clientstate_t		state;
	unsigned int			attributes;
	unsigned int			waiting;
	isc_task_t *			task;
	dns_view_t *			view;
	dns_dispatch_t *		dispatch;
	dns_dispentry_t *		dispentry;
	dns_dispatchevent_t *		dispevent;
	isc_socket_t *			tcplistener;
	isc_socket_t *			tcpsocket;
	dns_tcpmsg_t			tcpmsg;
	isc_timer_t *			timer;
	dns_message_t *			message;
	unsigned int			nsends;
	isc_mempool_t *			sendbufs;
	dns_rdataset_t *		opt;
	isc_uint16_t			udpsize;
	void				(*next)(ns_client_t *, isc_result_t);
	ns_query_t			query;
	isc_stdtime_t			requesttime;
	isc_stdtime_t			now;
	ISC_LINK(struct ns_client)	link;
};

#define NS_CLIENT_MAGIC			0x4E534363U	/* NSCc */
#define NS_CLIENT_VALID(c)		((c) != NULL && \
					 (c)->magic == NS_CLIENT_MAGIC)

#define NS_CLIENTATTR_TCP		0x01

/*
 * Note!  These ns_client_ routines MUST be called ONLY from the client's
 * task in order to ensure synchronization.
 */
void
ns_client_error(ns_client_t *client, isc_result_t result);

void
ns_client_next(ns_client_t *client, isc_result_t result);

void
ns_client_send(ns_client_t *client);

void
ns_client_destroy(ns_client_t *client);

isc_result_t
ns_client_newnamebuf(ns_client_t *client);

isc_result_t
ns_clientmgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		    isc_timermgr_t *timermgr, ns_clientmgr_t **managerp);

void
ns_clientmgr_destroy(ns_clientmgr_t **managerp);

isc_result_t
ns_clientmgr_addtodispatch(ns_clientmgr_t *manager, unsigned int n,
			   dns_dispatch_t *dispatch);

isc_result_t
ns_clientmgr_accepttcp(ns_clientmgr_t *manager, isc_socket_t *socket,
		       unsigned int n);

isc_sockaddr_t *
ns_client_getsockaddr(ns_client_t *client);

#endif /* NS_CLIENT_H */
