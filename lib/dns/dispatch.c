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

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>
#include <isc/socket.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/dispatch.h>

typedef struct dns_resentry dns_resentry_t;
struct dns_resentry {
	dns_messageid_t			id;
	isc_sockaddr_t			dest;
	isc_task_t		       *task;
	isc_taskaction_t		action;
	void			       *arg;

	ISC_LINK(dns_resentry_t)	link;
};

struct dns_dispatch {
	/* Unlocked. */
	unsigned int		magic;		/* magic */
	isc_mem_t	       *mctx;		/* memory context */
	isc_task_t	       *task;		/* internal task */
	isc_socket_t	       *socket;		/* isc socket attached to */
	unsigned int		buffersize;	/* size of each buffer */

	/* Locked. */
	isc_mutex_t		lock;		/* locks all below */
	unsigned int		refcount;	/* number of users */
	isc_mempool_t	       *epool;		/* memory pool for events */
	isc_mempool_t	       *bpool;		/* memory pool for buffers */
	isc_mempool_t	       *mpool;		/* resentries allocated here */
	ISC_LIST(dns_dispatchevent_t) rq_handlers; /* request handler list */
	isc_int32_t		qid_state;	/* state generator info */
	unsigned int		qid_hashsize;	/* hash table size */
	ISC_LIST(dns_dispatchevent_t) *qid_table; /* the table itself */
};

/*
 * Initializes a response table.
 *
 * Requires:
 *
 *	"hashsize" > 1.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOMEMORY		-- not enough memory to allocate
 */
static dns_result_t
restable_initialize(dns_dispatch_t *disp, unsigned int hashsize)
{
	return (DNS_R_UNKNOWN);
}

/*
 * Invalidate a ressponse table.
 *
 * Ensures:
 *
 *	All internal resources are freed.
 */
static void
restable_invalidate(dns_dispatch_t *disp)
{
}

/*
 * Add a response entry to the response table.
 * "*id" is filled in with the assigned message ID.
 *
 * The task, action, and arg are stored, and will be part of the data
 * returned on match operations.
 *
 * Requires:
 *
 *	"id" be non-NULL.
 *
 *	"task" "action" and "arg" be set as appropriate.
 *
 *	"dest" be non-NULL and valid.
 *
 * Ensures:
 *
 *	<id, dest> is a unique tuple.  That means incoming messages
 *	are identifiable.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOMEMORY		-- memory could not be allocated.
 *	DNS_R_NOMORE		-- no more message ids can be allocated
 *				   for this destination.
 */
static dns_result_t
restable_addresponse(dns_dispatch_t *disp, dns_messageid_t *id,
		     isc_sockaddr_t *dest, isc_task_t *task,
		     isc_taskaction_t action, void *arg)
{
	return (DNS_R_UNKNOWN);
}

/*
 * Find the entry for the given id and sockaddr.
 *
 * If entry is NULL, the return code is used merely as an existance test.
 * If "entry" is non-NULL, *entry will be set to point to the resentry.
 *
 * Requires:
 *
 *	"sockaddr" is non-NULL and valid.
 *
 *	if "entry" is non-NULL, "*entry" be NULL.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- item found.
 *	DNS_R_NOTFOUND		-- item not present.
 */
static dns_result_t
restable_find(dns_dispatch_t *disp, dns_messageid_t id,
	      isc_sockaddr_t *sockaddr, dns_resentry_t **entry)
{
	return (DNS_R_UNKNOWN);
}

/*
 * Find an item and remove it from the response table.  This is more
 * efficient than using restable_find() followed by _remove().
 *
 * Requires:
 *
 *	"sockaddr" is non-NULL and valid.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOTFOUND		-- item not present.
 */
static dns_result_t
restable_findremove(dns_dispatch_t *disp, dns_messageid_t id,
		    isc_sockaddr_t *sockaddr)
{
	return (DNS_R_UNKNOWN);
}

/*
 * Remove an entry from the response table.
 *
 * Requires:
 *
 *	"entry" is non-NULL, and "*entry" is non-NULL and points to a
 *	valid entry.
 *
 * Ensures:
 *
 *	"*entry" is NULL.
 */
static void
restable_remove(dns_dispatch_t *disp, dns_resentry_t **entry)
{
}
