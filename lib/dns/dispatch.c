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

dns_result_t
dns_dispatch_create(isc_mem_t *mctx, isc_socket_t *sock, isc_task_t *task,
		    unsigned int maxbuffersize,
		    unsigned int maxbuffers, unsigned int maxrequests,
		    unsigned int hashsize, dns_dispatch_t **dispp)
{
	dns_dispatch_t *disp;
	unsigned int tablesize;
	dns_result_t res;

	REQUIRE(mctx != NULL);
	REQUIRE(sock != NULL);
	REQUIRE(task != NULL);
	REQUIRE(hashsize <= 24);
	REQUIRE(maxbuffersize >= 512 && maxbuffersize < (64*1024));
	REQUIRE(maxbuffers > 0);
	REQUIRE(maxrequests <= maxbuffers);
	REQUIRE(dispp != NULL && *dispp == NULL);

	res = DNS_R_SUCCESS;

	disp = isc_mem_get(mctx, sizeof(dns_dispatch_t));
	if (disp == NULL)
		return (DNS_R_NOMEMORY);

	disp->magic = 0;
	disp->mctx = mctx;
	disp->task = NULL; /* set below */
	disp->socket = NULL; /* set below */
	disp->buffersize = maxbuffersize;

	disp->refcount = 1;

	tablesize = (1 << hashsize);

	disp->qid_table = isc_mem_get(disp->mctx, tablesize * sizeof(void *));
	if (disp->qid_table == NULL) {
		res = DNS_R_NOMEMORY;
		goto out1;
	}

	disp->qid_mask = tablesize - 1;
	disp->qid_hashsize = tablesize;

	if (isc_mutex_init(&disp->lock) != ISC_R_SUCCESS) {
		res = DNS_R_UNEXPECTED;
		UNEXPECTED_ERROR(__FILE__, __LINE__, "isc_mutex_init failed");
		goto out2;
	}

	if (isc_mempool_create(mctx, sizeof(dns_dispatchevent_t),
			       &disp->epool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out3;
	}

	if (isc_mempool_create(mctx, maxbuffersize,
			       &disp->bpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out4;
	}

	if (isc_mempool_create(mctx, sizeof(dns_resentry_t),
			       &disp->rpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out5;
	}

	/*
	 * should initialize qid_state here XXXMLG
	 */

	disp->magic = DISPATCH_MAGIC;

	isc_task_attach(task, &disp->task);
	isc_socket_attach(sock, &disp->socket);

	*dispp = disp;
	return (DNS_R_SUCCESS);

	/*
	 * error returns
	 */
 out5:
	isc_mempool_destroy(&disp->rpool);
 out4:
	isc_mempool_destroy(&disp->bpool);
 out3:
	isc_mempool_destroy(&disp->epool);
 out2:
	isc_mem_put(mctx, disp->mctx, disp->qid_hashsize * sizeof(void *));
 out1:
	isc_mem_put(mctx, disp, sizeof(dns_dispatch_t));

	return (res);
}

/*
 * Called when refcount reaches 0 at any time.
 */
static void
destroy(dns_dispatch_t *disp)
{
	disp->magic = 0;

	isc_task_detach(&disp->task);
	isc_socket_detach(&disp->socket);

	isc_mempool_destroy(&disp->rpool);
	isc_mempool_destroy(&disp->bpool);
	isc_mempool_destroy(&disp->epool);
	isc_mem_put(disp->mctx, disp->qid_table,
		    disp->qid_hashsize * sizeof(void *));

	isc_mem_put(disp->mctx, disp, sizeof(dns_dispatch_t));
}

void
dns_dispatch_destroy(dns_dispatch_t **dispp)
{
	dns_dispatch_t *disp;
	isc_boolean_t killit;

	REQUIRE(dispp != NULL && VALID_DISPATCH(*dispp));

	disp = *dispp;
	*dispp = NULL;

	killit = ISC_FALSE;

	LOCK(&disp->lock);

	INSIST(disp->refcount > 0);
	disp->refcount--;
	if (disp->refcount == 0)
		killit = ISC_TRUE;

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
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

	disp->refcount++;

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
	isc_boolean_t killit;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(resp != NULL);
	REQUIRE(VALID_RESPONSE(*resp));

	res = *resp;
	*resp = NULL;

	killit = ISC_FALSE;

	if (sockevent != NULL) {
		REQUIRE(*sockevent != NULL);
		ev = *sockevent;
		*sockevent = NULL;
	} else {
		ev = NULL;
	}

	LOCK(&disp->lock);

	INSIST(disp->refcount > 0);
	disp->refcount--;
	if (disp->refcount == 0)
		killit = ISC_TRUE;

	res->magic = 0;
	bucket = res->bucket;

	ISC_LIST_UNLINK(disp->qid_table[bucket], res, link);

	isc_mempool_put(disp->rpool, res);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
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
	isc_boolean_t killit;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(resp != NULL);
	REQUIRE(VALID_REQUEST(*resp));

	res = *resp;
	*resp = NULL;

	killit = ISC_FALSE;

	if (sockevent != NULL) {
		REQUIRE(*sockevent != NULL);
		ev = *sockevent;
		*sockevent = NULL;
	} else {
		ev = NULL;
	}

	LOCK(&disp->lock);

	INSIST(disp->refcount > 0);
	disp->refcount--;
	if (disp->refcount == 0)
		killit = ISC_TRUE;

	res->magic = 0;

	ISC_LIST_UNLINK(disp->rq_handlers, res, link);

	isc_mempool_put(disp->rpool, res);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}
