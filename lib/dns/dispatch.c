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
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/socket.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/dispatch.h>

#include "../isc/util.h"

struct dns_resentry {
	unsigned int			magic;
	dns_messageid_t			id;
	unsigned int			bucket;
	isc_sockaddr_t			dest;
	isc_task_t		       *task;
	isc_taskaction_t		action;
	void			       *arg;
	ISC_LINK(dns_resentry_t)	link;
};
#define INVALID_BUCKET (0xffffdead);

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
	isc_mempool_t	       *rpool;		/* resentries allocated here */
	ISC_LIST(dns_resentry_t) rq_handlers; /* request handler list */
	isc_int32_t		qid_state;	/* state generator info */
	unsigned int		qid_hashsize;	/* hash table size */
	unsigned int		qid_mask;	/* mask for hash table */
	ISC_LIST(dns_resentry_t) *qid_table; /* the table itself */
};

#define REQUEST_MAGIC	0x53912051 /* "random" value */
#define VALID_REQUEST(e)  ((e) != NULL && (e)->magic == REQUEST_MAGIC)

#define RESPONSE_MAGIC	0x15021935 /* "random" value */
#define VALID_RESPONSE(e)  ((e) != NULL && (e)->magic == RESPONSE_MAGIC)

#define DISPATCH_MAGIC	0x69385829 /* "random" value */
#define VALID_DISPATCH(e)  ((e) != NULL && (e)->magic == DISPATCH_MAGIC)

/*
 * Initializes a response table.  The hash table becomes 2^hashsize
 * entries large.
 *
 * Requires:
 *
 *	0 <= "hashsize" <= 24.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOMEMORY		-- not enough memory to allocate
 */
static dns_result_t
restable_initialize(dns_dispatch_t *disp, unsigned int hashsize)
{
	unsigned int count;

	REQUIRE(hashsize <= 24);
	INSIST(disp->qid_table == NULL);

	count = (1 << hashsize);

	disp->qid_table = isc_mem_get(disp->mctx, count * sizeof(void *));
	if (disp->qid_table == NULL)
		return (DNS_R_NOMEMORY);
	disp->qid_mask = count - 1;
	disp->qid_hashsize = count;

	return (DNS_R_SUCCESS);
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
	REQUIRE(disp->qid_table != NULL);

	isc_mem_put(disp->mctx, disp->qid_table,
		    disp->qid_hashsize * sizeof(void *));
	disp->qid_table = NULL;
	disp->qid_hashsize = 0;
}

dns_result_t
dns_dispatch_addresponse(dns_dispatch_t *disp, isc_sockaddr_t *dest,
			 isc_task_t *task, isc_taskaction_t action, void *arg,
			 dns_messageid_t *idp, dns_resentry_t **resp)
{
	dns_resentry_t *res;
	unsigned int bucket;
	dns_messageid_t id;
	int i;
	isc_boolean_t ok;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(task != NULL);
	REQUIRE(dest != NULL);
	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(idp != NULL);

	LOCK(&disp->lock);

	/*
	 * Try somewhat hard to find an unique ID.
	 */
	id = randomid(disp);
	bucket = hash(disp, dest, id);
	ok = ISC_FALSE;
	for (i = 0 ; i < 64 ; i++) {
		if (bucket_search(disp, dest, id, bucket) == 0) {
			ok = ISC_TRUE;
			break;
		}
		id = randomid(disp);
		bucket = hash(disp, dest, id);
	}

	if (!ok) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMORE);
	}

	res = isc_mempool_get(disp->rpool);
	if (res == NULL) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMEMORY);
	}

	res->magic = RESPONSE_MAGIC;
	res->id = id;
	res->bucket = bucket;
	res->dest = *dest;
	res->task = task;
	res->action = action;
	res->arg = arg;
	ISC_LINK_INIT(res, link);
	ISC_LIST_APPEND(disp->qid_table[bucket], res, link);

	UNLOCK(&disp->lock);

	*idp = id;
	*resp = res;

	return (DNS_R_SUCCESS);
}

void
dns_dispatch_removeresponse(dns_dispatch_t *disp, dns_resentry_t **resp,
			    dns_dispatchevent_t **sockevent)
{
	dns_resentry_t *res;
	dns_dispatchevent_t *ev;
	unsigned int bucket;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(resp != NULL);
	REQUIRE(VALID_RESPONSE(*resp));

	res = *resp;
	*resp = NULL;

	if (sockevent != NULL) {
		REQUIRE(*sockevent != NULL);
		ev = *sockevent;
		*sockevent = NULL;
	} else {
		ev = NULL;
	}

	LOCK(&disp->lock);

	res->magic = 0;
	bucket = res->bucket;

	ISC_LIST_UNLINK(disp->qid_table[bucket], res, link);

	isc_mempool_put(disp->rpool, res);

	UNLOCK(&disp->lock);
}

dns_result_t
dns_dispatch_addrequest(dns_dispatch_t *disp,
			isc_task_t *task, isc_taskaction_t action, void *arg,
			dns_resentry_t **resp)
{
	dns_resentry_t *res;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(task != NULL);
	REQUIRE(resp != NULL && *resp == NULL);

	LOCK(&disp->lock);

	res = isc_mempool_get(disp->rpool);
	if (res == NULL) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMEMORY);
	}

	res->magic = REQUEST_MAGIC;
	res->bucket = INVALID_BUCKET;
	res->task = task;
	res->action = action;
	res->arg = arg;
	ISC_LINK_INIT(res, link);
	ISC_LIST_APPEND(disp->rq_handlers, res, link);

	UNLOCK(&disp->lock);

	*resp = res;

	return (DNS_R_SUCCESS);
}

void
dns_dispatch_removerequest(dns_dispatch_t *disp, dns_resentry_t **resp,
			   dns_dispatchevent_t **sockevent)
{
	dns_resentry_t *res;
	dns_dispatchevent_t *ev;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(resp != NULL);
	REQUIRE(VALID_REQUEST(*resp));

	res = *resp;
	*resp = NULL;

	if (sockevent != NULL) {
		REQUIRE(*sockevent != NULL);
		ev = *sockevent;
		*sockevent = NULL;
	} else {
		ev = NULL;
	}

	LOCK(&disp->lock);

	res->magic = 0;

	ISC_LIST_UNLINK(disp->rq_handlers, res, link);

	isc_mempool_put(disp->rpool, res);

	UNLOCK(&disp->lock);
}
