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

#ifndef DNS_VIEW_H
#define DNS_VIEW_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS View
 *
 * A "view" is a DNS namespace, together with an optional resolver and a
 * forwarding policy.  A "DNS namespace" is a (possibly empty) set of
 * authoritative zones together with an optional cache and optional
 * "hints" information.
 *
 * XXXRTH  Not all of this items can be set currently, but future revisions
 * of this code will support them.
 *
 * Views start out "unfrozen".  In this state, core attributes like
 * the cache, set of zones, and forwarding policy may be set.  While
 * "unfrozen", the caller (e.g. nameserver configuration loading
 * code), must ensure exclusive access to the view.  When the view is
 * "frozen", the core attributes become immutable, and the view module
 * will ensure synchronization.  Freezing allows the view's core attributes
 * to be accessed without locking.
 *
 * MP:
 *	Before the view is frozen, the caller must ensure synchronization.
 *
 *	After the view is frozen, the module guarantees appropriate
 *	synchronization of any data structures it creates and manipulates.
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
 * None.  */

#include <isc/types.h>
#include <isc/lang.h>
#include <isc/event.h>
#include <isc/mutex.h>
#include <isc/stdtime.h>

#include <dns/types.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

struct dns_view {
	/* Unlocked. */
	unsigned int			magic;
	isc_mem_t *			mctx;
	dns_rdataclass_t		rdclass;
	char *				name;
	dns_dbtable_t *			dbtable;
	dns_resolver_t *		resolver;
	dns_db_t *			cachedb;
	isc_mutex_t			lock;
	isc_boolean_t			frozen;
	/* Locked by lock. */
	unsigned int			references;
	/* Under owner's locking control. */
	ISC_LINK(struct dns_view)	link;
};

#define DNS_VIEW_MAGIC			0x56696577	/* View. */
#define DNS_VIEW_VALID(view)		((view) != NULL && \
					 (view)->magic == DNS_VIEW_MAGIC)

isc_result_t
dns_view_create(isc_mem_t *mctx, dns_rdataclass_t rdclass, char *name,
		dns_view_t **viewp);
/*
 * Create a view.
 *
 * Notes:
 *
 *	The newly created view has no cache, no resolver, and an empty
 *	zone table.  The view is not frozen.
 *
 * Requires:
 *
 *	'mctx' is a valid memory context.
 *
 *	'rdclass' is a valid class.
 *
 *	'name' is a valid C string.
 *
 *	viewp != NULL && *viewp == NULL
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *
 *	Other errors are possible.
 */

void
dns_view_attach(dns_view_t *source, dns_view_t **targetp);
/*
 * Attach '*targetp' to 'source'.
 *
 * Requires:
 *
 *	'source' is a valid, frozen view.
 *
 *	'targetp' points to a NULL dns_view_t *.
 *
 * Ensures:
 *
 *	*targetp is attached to source.
 */

void
dns_view_detach(dns_view_t **viewp);
/*
 * Detach '*viewp' from its view.
 *
 * Requires:
 *
 *	'viewp' points to a valid dns_view_t *.
 *
 * Ensures:
 *
 *	*viewp is NULL.
 *
 *	If '*viewp' is the last reference to the view,
 *
 *		All resources used by the view will be freed.
 */

void
dns_view_setresolver(dns_view_t *view, dns_resolver_t *resolver);
/*
 * Set the view's resolver.
 *
 * Requires:
 *
 *	'view' is a valid, unfrozen view, whose resolver has not been
 *	set.
 *
 *	'resolver' is a valid resolver whose view is 'view'.
 *
 * Ensures:
 *
 *     	The resolver of 'view' is 'resolver'.
 */

void
dns_view_setcachedb(dns_view_t *view, dns_db_t *cachedb);
/*
 * Set the view's cache database.
 *
 * Note:
 *
 *	WARNING!  THIS ROUTINE WILL BE REPLACED WITH dns_view_setcache()
 *	WHEN WE HAVE INTEGRATED CACHE OBJECT SUPPORT INTO THE LIBRARY.
 *
 * Requires:
 *
 *	'view' is a valid, unfrozen view, whose cache database has not been
 *	set.
 *
 *	'cachedb' is a valid cache database.
 *
 * Ensures:
 *
 *     	The cache database of 'view' is 'cachedb'.
 */

isc_result_t
dns_view_addzonedb(dns_view_t *view, dns_db_t *db);
/*
 * Add zone database 'db' to 'view'.
 *
 * Note:
 *
 *	WARNING!  THIS ROUTINE WILL BE REPLACED WITH dns_view_addzone()
 *	WHEN WE HAVE INTEGRATED ZONE OBJECT SUPPORT INTO THE LIBRARY.
 *
 * Requires:
 *
 *	'view' is a valid, unfrozen view.
 *
 *	'db' is a valid zone database.
 *
 * Ensures:
 *
 *     	The cache database of 'view' is 'cachedb'.
 */

void
dns_view_freeze(dns_view_t *view);
/*
 * Freeze view.
 *
 * Requires:
 *
 *	'view' is a valid, unfrozen view.
 *
 * Ensures:
 *
 *	'view' is frozen.
 */

isc_result_t
dns_view_find(dns_view_t *view, dns_name_t *name, dns_rdatatype_t type,
	      isc_stdtime_t now, unsigned int options,
	      dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset);
/*
 * Find an rdataset whose owner name is 'name', and whose type is
 * 'type'.
 *
 * Notes:
 *
 *	This routine is appropriate for simple, exact-match queries of the
 *	view.
 *
 *	See the description of dns_db_find() for information about 'options'.
 *	If the caller sets DNS_DBFIND_GLUEOK, it must ensure that 'name'
 *	and 'type' are appropriate for glue retrieval.
 *
 *	If 'now' is zero, then the current time will be used.
 *
 *	If 'sigrdataset' is not NULL, and there is a SIG rdataset which
 *	covers 'type', then 'sigrdataset' will be bound to it.
 *
 * Requires:
 *
 *	'view' is a valid, frozen view.
 *
 *	'name' is valid name.
 *
 *	'type' is a valid dns_rdatatype_t, and is not a meta query type
 *	(e.g. dns_rdatatype_any), or dns_rdatatype_sig.
 *
 *	'rdataset' is a valid, disassociated rdataset.
 *
 *	'sigrdataset' is NULL, or is a valid, disassociated rdataset.
 *
 * Ensures:
 *
 *	If the result is ISC_R_SUCCESS or DNS_R_GLUE, then 'rdataset', and
 *	possibly 'sigrdataset', are bound to the found data.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS				Success.
 *	DNS_R_GLUE				Success; result is glue.
 *	ISC_R_NOTFOUND				Not matching data found.
 *
 *	Other results are possible, and indicate an error.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_VIEW_H */
