/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: client.h,v 1.37 2000/06/22 21:49:38 tale Exp $ */

#ifndef NAMED_CLIENT_H
#define NAMED_CLIENT_H 1

/*****
 ***** Module Info
 *****/

/*
 * Client
 *
 * This module defines two objects, ns_client_t and ns_clientmgr_t.
 *
 * An ns_client_t object handles incoming DNS requests from clients
 * on a given network interface.
 *
 * Each ns_client_t object can handle only one TCP connection or UDP
 * request at a time.  Therefore, several ns_client_t objects are
 * typically created to serve each network interface, e.g., one
 * for handling TCP requests and a few (one per CPU) for handling 
 * UDP requests.
 *
 * Incoming requests are classified as queries, zone transfer
 * requests, update requests, notify requests, etc, and handed off 
 * to the appropriate request handler.  When the request has been
 * fully handled (which can be much later), the ns_client_t must be 
 * notified of this by calling one of the following functions 
 * exactly once in the context of its task:
 *
 *   ns_client_send()	(sending a non-error response)
 *   ns_client_error()	(sending an error response)
 *   ns_client_next()	(sending no response)
 *
 * This will release any resources used by the request and 
 * and allow the ns_client_t to listen for the next request.
 *
 * A ns_clientmgr_t manages a number of ns_client_t objects.
 * New ns_client_t objects are created by calling
 * ns_clientmgr_createclients(). They are destroyed by
 * destroying their manager.
 */

/***
 *** Imports
 ***/

#include <isc/buffer.h>
#include <isc/stdtime.h>
#include <isc/quota.h>

#include <dns/name.h>
#include <dns/types.h>
#include <dns/tcpmsg.h>

#include <named/types.h>
#include <named/query.h>

/***
 *** Types
 ***/

typedef ISC_LIST(ns_client_t) client_list_t;

struct ns_client {
	unsigned int		magic;
	isc_mem_t *		mctx;
	ns_clientmgr_t *	manager;
	int			state;
	int			newstate;
	isc_boolean_t		disconnect;
	int			naccepts;
	int			nreads;
	int			nsends;
	int			references;
	unsigned int		attributes;
	isc_task_t *		task;
	dns_view_t *		view;
	dns_view_t *		lockview;
	dns_dispatch_t *	dispatch;
	dns_dispentry_t *	dispentry;
	dns_dispatchevent_t *	dispevent;
	isc_socket_t *		tcplistener;
	isc_socket_t *		tcpsocket;
	unsigned char *		tcpbuf;
	dns_tcpmsg_t		tcpmsg;
	isc_boolean_t		tcpmsg_valid;
	isc_timer_t *		timer;
	dns_message_t *		message;
	unsigned char *		sendbuf;
	dns_rdataset_t *	opt;
	isc_uint16_t		udpsize;
	void			(*next)(ns_client_t *);
	void			(*shutdown)(void *arg, isc_result_t result);
	void 			*shutdown_arg;
	ns_query_t		query;
	isc_stdtime_t		requesttime;
	isc_stdtime_t		now;
	dns_name_t		signername;   /* [T]SIG key name */
	dns_name_t *		signer;	      /* NULL if not valid sig */
	isc_boolean_t		mortal;	      /* Die after handling request */
	isc_quota_t		*tcpquota;
	isc_quota_t		*recursionquota;
	ns_interface_t		*interface;
	isc_sockaddr_t		peeraddr;
	isc_boolean_t		peeraddr_valid;
	struct in6_pktinfo	pktinfo;
	ISC_LINK(ns_client_t)	link;
	/*
	 * The list 'link' is part of, or NULL if not on any list.
	 */
	client_list_t		*list;
};

#define NS_CLIENT_MAGIC			0x4E534363U	/* NSCc */
#define NS_CLIENT_VALID(c)		ISC_MAGIC_VALID(c, NS_CLIENT_MAGIC)

#define NS_CLIENTATTR_TCP		0x01
#define NS_CLIENTATTR_RA		0x02 /* Client gets recusive service */
#define NS_CLIENTATTR_PKTINFO		0x04 /* pktinfo is valid */
#define NS_CLIENTATTR_MULTICAST		0x08 /* recv'd from multicast */

/***
 *** Functions
 ***/

/*
 * Note!  These ns_client_ routines MUST be called ONLY from the client's
 * task in order to ensure synchronization.
 */

void
ns_client_send(ns_client_t *client);
/*
 * Finish processing the current client request and
 * send client->message as a response.
 */

void
ns_client_error(ns_client_t *client, isc_result_t result);
/*
 * Finish processing the current client request and return
 * an error response to the client.  The error response
 * will have an RCODE determined by 'result'.
 */

void
ns_client_next(ns_client_t *client, isc_result_t result);
/*
 * Finish processing the current client request, 
 * return no response to the client.
 */

isc_boolean_t
ns_client_shuttingdown(ns_client_t *client);
/*
 * Return ISC_TRUE iff the client is currently shutting down.
 */

void
ns_client_attach(ns_client_t *source, ns_client_t **target);
/*
 * Attach '*targetp' to 'source'.
 */

void
ns_client_detach(ns_client_t **clientp);
/*
 * Detach '*clientp' from its client.
 */

isc_result_t
ns_client_replace(ns_client_t *client);
/*
 * Try to replace the current client with a new one, so that the
 * current one can go off and do some lengthy work without
 * leaving the dispatch/socket without service.
 */

isc_result_t
ns_clientmgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		    isc_timermgr_t *timermgr, ns_clientmgr_t **managerp);
/*
 * Create a client manager.
 */

void
ns_clientmgr_destroy(ns_clientmgr_t **managerp);
/*
 * Destroy a client manager and all ns_client_t objects
 * managed by it.
 */

isc_result_t
ns_clientmgr_createclients(ns_clientmgr_t *manager, unsigned int n,
			   ns_interface_t *ifp, isc_boolean_t tcp);
/*
 * Create up to 'n' clients listening on interface 'ifp'.
 * If 'tcp' is ISC_TRUE, the clients will listen for TCP connections,
 * otherwise for UDP requests.
 */

isc_sockaddr_t *
ns_client_getsockaddr(ns_client_t *client);
/*
 * Get the socket address of the client whose request is
 * currently being processed.
 */

isc_result_t
ns_client_checkacl(ns_client_t  *client,
		   const char *opname, dns_acl_t *acl,
		   isc_boolean_t default_allow,
		   isc_boolean_t logfailure);
/*
 * Convenience function for client request ACL checking.
 *
 * Check the current client request against 'acl'.  If 'acl'
 * is NULL, allow the request iff 'default_allow' is ISC_TRUE.
 * Log the outcome of the check if deemed appropriate.
 * Log messages will refer to the request as an 'opname' request.
 *
 * Notes:
 *	This is appropriate for checking allow-update, 
 * 	allow-query, allow-transfer, etc.  It is not appropriate
 * 	for checking the blackhole list because we treat positive
 * 	matches as "allow" and negative matches as "deny"; in
 *	the case of the blackhole list this would be backwards.
 *
 * Requires:
 *	'client' points to a valid client.
 *	'opname' points to a null-terminated string.
 *	'acl' points to a valid ACL, or is NULL.
 *
 * Returns:
 *	ISC_R_SUCCESS	if the request should be allowed
 * 	ISC_R_REFUSED	if the request should be denied
 *	No other return values are possible.
 */

void
ns_client_log(ns_client_t *client, isc_logcategory_t *category,
	      isc_logmodule_t *module, int level,
	      const char *fmt, ...);

#endif /* NAMED_CLIENT_H */
