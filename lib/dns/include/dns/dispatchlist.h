/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#ifndef DNS_DISPATCHLIST_H
#define DNS_DISPATCHLIST_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Dispatch List Management
 *
 * 	Maintains a list of dispatchers to help various parts of the DNS
 *	library and applications keep track and share dispatchers.
 *
 * MP:
 *
 *     	All locking is performed internally to each list.
 *
 *	dns_dispatchlist_find() will return dispatches which are
 *	attached.
 *
 * Reliability:
 *
 * Resources:
 *
 * Security:
 *
 *	None.
 *
 * Standards:
 *
 *	None.
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>

#include <dns/types.h>

/*
 * Attributes for added dispatchers.
 *
 * Values with the mask 0xffff0000 are application defined.
 * Values with the mask 0x0000ffff are library defined.
 *
 * Insane values (like setting both TCP and UDP) are not caught.  Don't
 * do that.
 */
#define DNS_DISPATCHLISTATTR_PRIVATE	0x00000001U
#define DNS_DISPATCHLISTATTR_TCP	0x00000002U
#define DNS_DISPATCHLISTATTR_UDP	0x00000004U
#define DNS_DISPATCHLISTATTR_IPV4	0x00000008U
#define DNS_DISPATCHLISTATTR_IPV6	0x00000010U

ISC_LANG_BEGINDECLS

isc_result_t
dns_dispatchlist_create(isc_mem_t *mctx, dns_dispatchlist_t **listp);
/*
 * Creates a new dispatchlist object.
 *
 * Requires:
 *	"mctx" be a valid memory context.
 *
 *	listp != NULL && *listp == NULL
 *
 * Returns:
 *	ISC_R_SUCCESS	-- all ok
 *
 *	anything else	-- failure
 */


void
dns_dispatchlist_destroy(dns_dispatchlist_t **listp);
/*
 * Destroys the dispatchlist when it becomes empty.  This could be
 * immediately.
 *
 * Requires:
 *	listp != NULL && *listp is a valid dispatchlist.
 */


isc_result_t
dns_dispatchlist_add(dns_dispatchlist_t *list, dns_dispatch_t *disp,
		     unsigned int attributes);
/*
 * Add a new dispatch object to the dispatch list with the attributes
 * supplied.
 *
 * Requires:
 *	"list" be a valid dispatchlist.
 *
 *	"disp" be a valid dispatcher that is not already present on "list"
 *
 * Ensures:
 *	On successful return, the dispatcher is attached, preventing it
 *	from being deleted while on the dispatchlist.
 *
 * Returns:
 *	ISC_R_SUCCESS	-- added.
 *
 *	anything else	-- failure.
 */


isc_result_t
dns_dispatchlist_delete(dns_dispatchlist_t *list, dns_dispatch_t *disp);
/*
 * Deletes the dispatcher from the list.
 *
 * Requires:
 *	"list" be a valid dispatchlist.
 *
 *	"disp" be a valid dispatcher.
 *
 * Ensures:
 *	On successful return, the dispatcher is detached once, allowing it
 *	to be deleted.
 *
 * Returns:
 *	ISC_R_SUCCESS	-- deleted.
 *
 *	ISC_R_NOTFOUND	-- dispatcher is not on the list.
 *
 *	anything else	-- failure.
 */


isc_result_t
dns_dispatchlist_find(dns_dispatchlist_t *list, unsigned int attributes,
		      unsigned int mask, dns_dispatch_t **dispp);
/*
 * Search for a dispatcher that has the attributes specified by
 *	(attributes & mask)
 *
 * Requires:
 *	"list" be a valid dispatchlist.
 *
 *	dispp != NULL && *dispp == NULL.
 *
 * Ensures:
 *	The dispatcher returned into *dispp is attached on behalf of the
 *	caller.  It is required that the caller detach from it when it is
 *	no longer needed.
 *
 * Returns:
 *	ISC_R_SUCCESS	-- found.
 *
 *	ISC_R_NOTFOUND	-- no dispatcher matching the requirements found.
 *
 *	anything else	-- failure.
 */


ISC_LANG_ENDDECLS

#endif /* DNS_DISPATCHLIST_H */
