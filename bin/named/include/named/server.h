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

#ifndef NS_SERVER_H
#define NS_SERVER_H 1

#include <isc/log.h>
#include <isc/sockaddr.h>
#include <isc/types.h>
#include <isc/quota.h>

#include <dns/types.h>

#define NS_EVENTCLASS		ISC_EVENTCLASS(0x4E43)
#define NS_EVENT_RELOAD		(NS_EVENTCLASS + 0)

/*
 * Name server state.  Better here than in lots of separate global variables.
 */
struct ns_server {
	isc_uint32_t		magic;
	isc_mem_t *		mctx;

	isc_task_t *		task;

	/* Common rwlock for the server's configurable data. */
	isc_rwlock_t		conflock;
	
	/* Configurable data. */
	isc_boolean_t		recursion;
	isc_boolean_t		auth_nxdomain;
	dns_transfer_format_t	transfer_format;
	dns_acl_t *		queryacl;
	dns_acl_t *		recursionacl;
	dns_acl_t *		transferacl;
	isc_quota_t		xfroutquota;
	isc_quota_t		tcpquota;
	isc_quota_t		recursionquota;

	/* Server data structures. */
	dns_zonemgr_t *		zonemgr;
	ns_clientmgr_t *	clientmgr;
	dns_viewlist_t		viewlist;
	ns_interfacemgr_t *	interfacemgr;
	dns_db_t *		roothints;
	dns_tkey_ctx_t *	tkeyctx;
	isc_sockaddr_t		querysrc_address;
	dns_dispatch_t *	querysrc_dispatch;

	isc_mutex_t		reload_event_lock;
	isc_event_t *		reload_event;
};

#define NS_SERVER_MAGIC			0x53564552	/* SVER */
#define NS_SERVER_VALID(s)		((s) != NULL && \
					 (s)->magic == NS_SERVER_MAGIC)

void
ns_server_create(isc_mem_t *mctx, ns_server_t **serverp);
/*
 * Create a server object with default settings.
 * This function either succeeds or causes the program to exit
 * with a fatal error.
 */

void
ns_server_destroy(ns_server_t **serverp);
/*
 * Destroy a server object, freeing its memory.
 */

void
ns_server_reloadwanted(ns_server_t *server);
/*
 * Inform a server that a reload is wanted.  This function
 * may be called asynchronously, from outside the server's task.
 * If a reload is already scheduled or in progress, the call
 * is ignored.
 */


#endif /* NS_SERVER_H */
