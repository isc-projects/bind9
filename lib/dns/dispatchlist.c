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

#include <config.h>

#include <stdlib.h>

#include <isc/mem.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/dispatchlist.h>
#include <dns/types.h>

/*
 * This module implements a dispatch list.  The items on the list are
 * dispatch objects.  These dispatchers have attributes such as shared,
 * TCP, UDP, IPv4, IPv6, etc.  When searching for a usable shared
 * dispatcher these flags are respected.
 */

typedef struct dns__dle dns__dle_t;

struct dns__dle {
	dns_dispatch_t	       *disp;
	unsigned int		attributes;
	ISC_LINK(dns__dle_t)	link;
};

struct dns_dispatchlist {
	/* Unlocked. */
	unsigned int		magic;
	isc_mem_t	       *mctx;

	/* Locked. */
	isc_mutex_t		lock;
	unsigned int		state;
	ISC_LIST(dns__dle_t)	list;
};

#define SHUTTINGDOWN		0x00000001U
#define IS_SHUTTINGDOWN(l)	(((l)->state & SHUTTINGDOWN) != 0)

#define IS_PRIVATE(dle)	(((dle)->attributes & DNS_DISPATCHLISTATTR_PRIVATE) \
			 != 0)

#define DNS_DISPATCHLIST_MAGIC		ISC_MAGIC('D', 'l', 's', 't')
#define DNS_DISPATCHLIST_VALID(a) \
	ISC_MAGIC_VALID(a, DNS_DISPATCHLIST_MAGIC)


isc_result_t
dns_dispatchlist_create(isc_mem_t *mctx, dns_dispatchlist_t **listp)
{
	dns_dispatchlist_t *list;
	isc_result_t result;

	REQUIRE(mctx != NULL);
	REQUIRE(listp != NULL && *listp == NULL);

	list = isc_mem_get(mctx, sizeof(dns_dispatchlist_t));
	if (list == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&list->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, list, sizeof(dns_dispatchlist_t));
		return (result);
	}

	list->magic = DNS_DISPATCHLIST_MAGIC;
	list->state = 0;
	list->mctx = NULL;
	isc_mem_attach(mctx, &list->mctx);
	ISC_LIST_INIT(list->list);

	*listp = list;
	return (ISC_R_SUCCESS);
}

/*
 * List must be locked when calling this function.
 */
static isc_boolean_t
destroy_ok(dns_dispatchlist_t *list)
{
	if ((list->state & SHUTTINGDOWN) == 0)
		return (ISC_FALSE);
	if (!ISC_LIST_EMPTY(list->list))
		return (ISC_FALSE);

	return (ISC_TRUE);
}

/*
 * List must be unlocked when calling this function.
 */
static void
destroy(dns_dispatchlist_t **listp)
{
	isc_mem_t *mctx;
	dns_dispatchlist_t *list;

	list = *listp;
	*listp = NULL;

	mctx = list->mctx;

	list->magic = 0;
	list->mctx = 0;
	isc_mutex_destroy(&list->lock);
	list->state = 0;

	isc_mem_put(mctx, list, sizeof(dns_dispatchlist_t));
	isc_mem_detach(&mctx);
}

void
dns_dispatchlist_destroy(dns_dispatchlist_t **listp)
{
	dns_dispatchlist_t *list;
	isc_boolean_t killit;

	REQUIRE(listp != NULL);
	REQUIRE(DNS_DISPATCHLIST_VALID(*listp));
	RUNTIME_CHECK(destroy_ok(*listp));

	list = *listp;
	*listp = NULL;

	LOCK(&list->lock);
	list->state |= SHUTTINGDOWN;
	killit = destroy_ok(list);
	UNLOCK(&list->lock);

	if (killit)
		destroy(&list);
}

isc_result_t
dns_dispatchlist_add(dns_dispatchlist_t *list, dns_dispatch_t *disp,
		     unsigned int attributes)
{
	dns__dle_t *dle;
	isc_result_t result;

	REQUIRE(DNS_DISPATCHLIST_VALID(list));
	REQUIRE(disp != NULL);

	LOCK(&list->lock);
	if (IS_SHUTTINGDOWN(list)) {
		result = ISC_R_SHUTTINGDOWN;
		goto out;
	}

	dle = isc_mem_get(list->mctx, sizeof(dns__dle_t));
	if (dle == NULL) {
		result = ISC_R_NOMEMORY;
		goto out;
	}

	dle->disp = NULL;
	dns_dispatch_attach(disp, &dle->disp);
	dle->attributes = attributes;
	ISC_LINK_INIT(dle, link);
	ISC_LIST_APPEND(list->list, dle, link);

	result = ISC_R_SUCCESS;

 out:
	UNLOCK(&list->lock);
	return (result);
}

isc_result_t
dns_dispatchlist_delete(dns_dispatchlist_t *list, dns_dispatch_t *disp)
{
	dns__dle_t *dle;
	isc_result_t result;
	isc_boolean_t killit;

	REQUIRE(DNS_DISPATCHLIST_VALID(list));
	REQUIRE(disp != NULL);

	LOCK(&list->lock);
	dle = ISC_LIST_HEAD(list->list);
	while (dle != NULL) {
		if (dle->disp == disp)
			break;
		dle = ISC_LIST_NEXT(dle, link);
	}

	if (dle == NULL) {
		result = ISC_R_NOTFOUND;
		goto out;
	}

	ISC_LIST_UNLINK(list->list, dle, link);
	dns_dispatch_detach(&dle->disp);

	isc_mem_put(list->mctx, dle, sizeof(dns__dle_t));

	result = ISC_R_SUCCESS;

 out:
	killit = destroy_ok(list);
	UNLOCK(&list->lock);

	if (killit)
		destroy(&list);

	return (result);
}

#define ATTRMATCH(_a1, _a2, _mask) (((_a1) & (_mask)) == ((_a2) & (_mask)))

isc_result_t
dns_dispatchlist_find(dns_dispatchlist_t *list, unsigned int attributes,
		      unsigned int mask, dns_dispatch_t **dispp)
{
	dns__dle_t *dle;
	isc_result_t result;

	REQUIRE(DNS_DISPATCHLIST_VALID(list));
	REQUIRE(dispp != NULL && *dispp == NULL);

	LOCK(&list->lock);
	dle = ISC_LIST_HEAD(list->list);
	while (dle != NULL) {
		if (!IS_PRIVATE(dle)
		    && ATTRMATCH(dle->attributes, attributes, mask))
			break;
		dle = ISC_LIST_NEXT(dle, link);
	}

	if (dle == NULL) {
		result = ISC_R_NOTFOUND;
		goto out;
	}

	dns_dispatch_attach(dle->disp, dispp);

	result = ISC_R_SUCCESS;

 out:
	UNLOCK(&list->lock);

	return (result);
}
