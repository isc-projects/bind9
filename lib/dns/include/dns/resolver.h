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

#include <isc/lang.h>
#include <isc/socket.h>

#include <dns/types.h>
#include <dns/fixedname.h>

ISC_LANG_BEGINDECLS

/*
 * A dns_fetchevent_t is sent when a 'fetch' completes.  Any of 'db',
 * 'node', 'rdataset', and 'sigrdataset' may be bound.  It is the
 * receiver's responsibility to detach before freeing the event.
 *
 * 'rdataset' and 'sigrdataset' are the values that were supplied when
 * dns_resolver_createfetch() was called.  They are returned to the
 * caller so that they may be freed.
 */
typedef struct dns_fetchevent {
	ISC_EVENT_COMMON(struct dns_fetchevent);
	dns_fetch_t *			fetch;
	isc_result_t			result;
	dns_rdatatype_t			qtype;
	dns_db_t *			db;
	dns_dbnode_t *			node;
	dns_rdataset_t *		rdataset;
	dns_rdataset_t *		sigrdataset;
	dns_fixedname_t			foundname;
} dns_fetchevent_t;

/*
 * Options that modify how a 'fetch' is done.
 */
#define DNS_FETCHOPT_TCP		0x01	     /* Use TCP. */
#define DNS_FETCHOPT_UNSHARED		0x02	     /* See below. */
#define DNS_FETCHOPT_RECURSIVE		0x04	     /* Set RD? */
#define DNS_FETCHOPT_NOEDNS0		0x08	     /* Do not use EDNS. */
#define DNS_FETCHOPT_FORWARDONLY	0x10	     /* Only use forwarders. */

/*
 * XXXRTH  Should this API be made semi-private?  (I.e.
 * _dns_resolver_create()).
 */

isc_result_t
dns_resolver_create(dns_view_t *view,
		    isc_taskmgr_t *taskmgr, unsigned int ntasks,
		    isc_socketmgr_t *socketmgr,
		    isc_timermgr_t *timermgr,
		    unsigned int options,
		    dns_dispatchmgr_t *dispatchmgr,
		    dns_dispatch_t *dispatchv4,
		    dns_dispatch_t *dispatchv6,
		    dns_resolver_t **resp);
/*
 * Create a resolver.
 *
 * Notes:
 *
 *	Generally, applications should not create a resolver directly, but
 *	should instead call dns_view_createresolver().
 *
 *	No options are currently defined.
 *
 * Requires:
 *
 *	'view' is a valid view.
 *
 *	'taskmgr' is a valid task manager.
 *
 *	'ntasks' > 0.
 *
 *	'socketmgr' is a valid socket manager.
 *
 *	'timermgr' is a valid timer manager.
 *
 *	'dispatchv4' is a valid dispatcher with an IPv4 UDP socket, or is NULL.
 *
 *	'dispatchv6' is a valid dispatcher with an IPv6 UDP socket, or is NULL.
 *
 *	*resp != NULL && *resp == NULL.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS				On success.
 *
 *	Anything else				Failure.
 */

isc_result_t
dns_resolver_setforwarders(dns_resolver_t *res,
			   isc_sockaddrlist_t *forwarders);
/*
 * Set the default forwarders to be used by the resolver.
 *
 * Requires:
 *
 *	'res' is a valid, unfrozen resolver.
 *
 *	'forwarders' is a valid nonempty list.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 */

isc_result_t
dns_resolver_setfwdpolicy(dns_resolver_t *res, dns_fwdpolicy_t fwdpolicy);
/*
 * Set the default forwarding policy to be used by the resolver.
 *
 * Requires:
 *
 *	'res' is a valid, unfrozen resolver.
 *
 *	'fwdpolicy' is a valid dns_fwdpolicy_t.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 */

void
dns_resolver_freeze(dns_resolver_t *res);
/*
 * Freeze resolver.
 *
 * Notes:
 *
 *	Certain configuration changes, e.g. setting forwarders,
 *	cannot be made after the resolver is frozen.  Fetches
 *	cannot be created until the resolver is frozen.
 *
 * Requires:
 *
 *	'res' is a valid, unfrozen resolver.
 *
 * Ensures:
 *
 *	'res' is frozen.
 */

void
dns_resolver_prime(dns_resolver_t *res);
/*
 * Prime resolver.
 *
 * Notes:
 *
 *	Resolvers which have a forwarding policy other than dns_fwdpolicy_only
 *	need to be primed with the root nameservers, otherwise the root
 *	nameserver hints data may be used indefinitely.  This function requests
 *	that the resolver start a priming fetch, if it isn't already priming.
 *
 * Requires:
 *
 *	'res' is a valid, frozen resolver.
 */


void
dns_resolver_whenshutdown(dns_resolver_t *res, isc_task_t *task,
			  isc_event_t **eventp);
/*
 * Send '*eventp' to 'task' when 'res' has completed shutdown.
 *
 * Notes:
 *
 *	It is not safe to detach the last reference to 'res' until
 *	shutdown is complete.
 *
 * Requires:
 *
 *	'res' is a valid resolver.
 *
 *	'task' is a valid task.
 *
 *	*eventp is a valid event.
 *
 * Ensures:
 *
 *	*eventp == NULL.
 */

void
dns_resolver_shutdown(dns_resolver_t *res);
/*
 * Start the shutdown process for 'res'.
 *
 * Notes:
 *
 *	This call has no effect if the resolver is already shutting down.
 *
 * Requires:
 *
 *	'res' is a valid resolver.
 */

void
dns_resolver_attach(dns_resolver_t *source, dns_resolver_t **targetp);

void
dns_resolver_detach(dns_resolver_t **resp);

isc_result_t
dns_resolver_createfetch(dns_resolver_t *res, dns_name_t *name,
			 dns_rdatatype_t type,
			 dns_name_t *domain, dns_rdataset_t *nameservers,
			 dns_forwarders_t *forwarders,
			 unsigned int options, isc_task_t *task,
			 isc_taskaction_t action, void *arg,
			 dns_rdataset_t *rdataset,
			 dns_rdataset_t *sigrdataset, 
			 dns_fetch_t **fetchp);
/*
 * Recurse to answer a question.
 *
 * Notes:
 *
 *	This call starts a query for 'name', type 'type'.
 *
 *	XXXRTH  Explain query domain and nameservers.
 *		'forwarders' is unimplmented, and subject to change when
 *		we figure out how selective forwarding will work.
 *
 *	When the fetch completes (successfully or otherwise), a 
 *	DNS_EVENT_FETCHDONE event with action 'action' and arg 'arg' will be
 *	posted to 'task'.
 *
 *	The values of 'rdataset' and 'sigrdataset' will be returned in
 *	the FETCHDONE event.
 *
 * Requires:
 *
 *	'res' is a valid resolver that has been frozen.
 *
 *	'name' is a valid name.
 *
 *	'type' is not a meta type other than ANY.
 *
 *	'domain' is a valid name or NULL.
 *
 *	'nameservers' is a valid NS rdataset (whose owner name is 'domain')
 *	iff. 'domain' is not NULL.
 *
 *	'forwarders' is NULL.
 *
 *	'options' contains valid options.
 *
 *	'rdataset' is a valid, disassociated rdataset.
 *
 *	'sigrdataset' is NULL, or is a valid, disassociated rdataset.
 *
 *	fetchp != NULL && *fetchp == NULL.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS					Success
 *
 *	Many other values are possible, all of which indicate failure.
 */

void
dns_resolver_cancelfetch(dns_fetch_t *fetch);
/*
 * Cancel 'fetch'.
 *
 * Notes:
 *
 *	If 'fetch' has not completed, post its FETCHDONE event with a
 *	result code of ISC_R_CANCELED.
 *
 * Requires:
 *
 *	'fetch' is a valid fetch.
 */

void
dns_resolver_destroyfetch(dns_fetch_t **fetchp);
/*
 * Destroy 'fetch'.
 *
 * Requires:
 *
 *	'*fetchp' is a valid fetch.
 *
 *	The caller has received the FETCHDONE event (either because the
 *	fetch completed or because dns_resolver_cancelfetch() was called).
 *
 * Ensures:
 *
 *	*fetchp == NULL.
 */

dns_dispatchmgr_t *
dns_resolver_dispatchmgr(dns_resolver_t *resolver);

dns_dispatch_t *
dns_resolver_dispatchv4(dns_resolver_t *resolver);

dns_dispatch_t *
dns_resolver_dispatchv6(dns_resolver_t *resolver);

isc_socketmgr_t *
dns_resolver_socketmgr(dns_resolver_t *resolver);

isc_taskmgr_t *
dns_resolver_taskmgr(dns_resolver_t *resolver);

ISC_LANG_ENDDECLS

#endif /* DNS_RESOLVER_H */
