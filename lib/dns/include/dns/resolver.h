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

#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Resolver
 *
 * XXX <TBS> XXX
 *
 * MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates.
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
 *	RFCs:	1034, 1035, 2181, <TBS>
 *	Drafts:	<TBS>
 */

#include <isc/types.h>
#include <isc/lang.h>
#include <isc/event.h>
#include <isc/socket.h>

#include <dns/types.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

typedef struct dns_fetchevent {
	ISC_EVENT_COMMON(struct dns_fetchevent);
	dns_fetch_t *			fetch;
	dns_result_t			result;
	dns_rdatatype_t			qtype;
	dns_db_t *			db;
	dns_dbnode_t *			node;
	dns_rdataset_t *		rdataset;
	dns_rdataset_t *		sigrdataset;
	dns_fixedname_t			foundname;
} dns_fetchevent_t;

#define DNS_FETCHOPT_TCP		0x01
#define DNS_FETCHOPT_UNSHARED		0x02
#define DNS_FETCHOPT_RECURSIVE		0x04
#define DNS_FETCHOPT_NOEDNS0		0x08

dns_result_t
dns_resolver_create(dns_view_t *view,
		    isc_taskmgr_t *taskmgr, unsigned int ntasks,
		    isc_socketmgr_t *socketmgr,
		    isc_timermgr_t *timermgr,
		    dns_dispatch_t *dispatch, dns_resolver_t **resp);

void
dns_resolver_attach(dns_resolver_t *source, dns_resolver_t **targetp);

void
dns_resolver_detach(dns_resolver_t **resp);

dns_result_t
dns_resolver_createfetch(dns_resolver_t *res, dns_name_t *name,
			 dns_rdatatype_t type,
			 dns_name_t *domain, dns_rdataset_t *nameservers,
			 dns_forwarders_t *forwarders,
			 unsigned int options, isc_task_t *task,
			 isc_taskaction_t action, void *arg,
			 dns_rdataset_t *rdataset,
			 dns_rdataset_t *sigrdataset, 
			 dns_fetch_t **fetchp);

void
dns_resolver_cancelfetch(dns_resolver_t *res, dns_fetch_t *fetch);

void
dns_resolver_destroyfetch(dns_resolver_t *res, dns_fetch_t **fetchp);

ISC_LANG_ENDDECLS

#endif /* DNS_RESOLVER_H */
