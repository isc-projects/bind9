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
 * XXX <TBS> XXX
 *
 * MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates, with the exception that the caller is
 *	responsible for the safe creation and destruction of view managers.
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
 *	None.
 */

#include <isc/types.h>
#include <isc/lang.h>
#include <isc/event.h>

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
		dns_db_t *cachedb, dns_resolver_t *resolver,
		dns_view_t **viewp);

void
dns_view_attach(dns_view_t *source, dns_view_t **targetp);

void
dns_view_detach(dns_view_t **viewp);

ISC_LANG_ENDDECLS

#endif /* DNS_VIEW_H */
