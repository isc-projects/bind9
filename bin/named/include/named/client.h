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

#include <dns/name.h>
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

struct ns_client {
	unsigned int			magic;
	isc_mem_t *			mctx;
	ns_clientmgr_t *		manager;
	ns_clienttype_t			type;
	isc_boolean_t			shuttingdown;
	isc_boolean_t			waiting_for_bufs;
	int				naccepts;
	int				nreads;
	int				nsends;
	int				nwaiting;
	unsigned int			attributes;
	isc_task_t *			task;
	dns_view_t *			view;
	dns_dispatch_t *		dispatch;
	dns_dispentry_t *		dispentry;
	dns_dispatchevent_t *		dispevent;
	isc_socket_t *			tcplistener;
	isc_socket_t *			tcpsocket;
	dns_tcpmsg_t			tcpmsg;
	isc_boolean_t			tcpmsg_valid;
	isc_timer_t *			timer;
	dns_message_t *			message;
	isc_mempool_t *			sendbufs;
	dns_rdataset_t *		opt;
	isc_uint16_t			udpsize;
	void				(*next)(ns_client_t *, isc_result_t);
	ns_query_t			query;
	isc_stdtime_t			requesttime;
	isc_stdtime_t			now;
	dns_name_t			signername; /* [T]SIG key name */
	dns_name_t *			signer; /* NULL if not valid sig */
	isc_boolean_t			oneshot;
	ISC_LINK(struct ns_client)	link;
};

#define NS_CLIENT_MAGIC			0x4E534363U	/* NSCc */
#define NS_CLIENT_VALID(c)		((c) != NULL && \
					 (c)->magic == NS_CLIENT_MAGIC)

#define NS_CLIENTATTR_TCP		0x01
#define NS_CLIENTATTR_RA		0x02 /* Client gets recusive service */

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

isc_boolean_t
ns_client_shuttingdown(ns_client_t *client);
/*
 * Return ISC_TRUE iff the client is currently shutting down.
 */

void
ns_client_wait(ns_client_t *client);
/*
 * Increment reference count.
 */

void
ns_client_unwait(ns_client_t *client);
/*
 * Decrement reference count.
 */

isc_result_t
ns_client_replace(ns_client_t *client);
/*
 * Try to replace the current client with a new one, so that the
 * current one can go off and do some lengthy work without
 * leaving the dispatch/socket without service.
 *
 * If doing so would exceed a quota, return ISC_R_QUOTA.
 */

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
