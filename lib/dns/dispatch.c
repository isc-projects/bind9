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

#include <dns/events.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/dispatch.h>
#include <dns/message.h>

#include "../isc/util.h"

/*
 * If we cannot send to this task, the application is broken.
 */
#define ISC_TASK_SEND(a, b) do { \
	RUNTIME_CHECK(isc_task_send(a, b) == ISC_R_SUCCESS); \
} while (0)


struct dns_dispentry {
	unsigned int			magic;
	dns_messageid_t			id;
	unsigned int			bucket;
	isc_sockaddr_t			host;
	isc_task_t		       *task;
	isc_taskaction_t		action;
	void			       *arg;
	isc_boolean_t			item_out;
	ISC_LIST(dns_dispatchevent_t)	items;
	ISC_LINK(dns_dispentry_t)	link;
};

#define INVALID_BUCKET (0xffffdead)

typedef ISC_LIST(dns_dispentry_t)	dns_displist_t;

struct dns_dispatch {
	/* Unlocked. */
	unsigned int		magic;		/* magic */
	isc_mem_t	       *mctx;		/* memory context */
	isc_task_t	       *task;		/* internal task */
	isc_socket_t	       *socket;		/* isc socket attached to */
	unsigned int		buffersize;	/* size of each buffer */
	unsigned int		maxrequests;	/* max requests */
	unsigned int		maxbuffers;	/* max buffers */

	/* Locked. */
	isc_mutex_t		lock;		/* locks all below */
	unsigned int		refcount;	/* number of users */
	isc_mempool_t	       *epool;		/* memory pool for events */
	isc_mempool_t	       *bpool;		/* memory pool for buffers */
	isc_mempool_t	       *rpool;		/* memory pool request/reply */
	dns_dispatchevent_t    *failsafe_ev;	/* failsafe cancel event */
	unsigned int		recvs;		/* recv() calls outstanding */
	unsigned int		recvs_wanted;	/* recv() calls wanted */
	unsigned int		shutting_down : 1,
				shutdown_out : 1;
	dns_result_t		shutdown_why;
	unsigned int		requests;	/* how many requests we have */
	unsigned int		buffers;	/* allocated buffers */
	ISC_LIST(dns_dispentry_t) rq_handlers;	/* request handler list */
	ISC_LIST(dns_dispatchevent_t) rq_events; /* holder for rq events */
	isc_int32_t		qid_state;	/* state generator info */
	unsigned int		qid_hashsize;	/* hash table size */
	unsigned int		qid_mask;	/* mask for hash table */
	dns_displist_t	        *qid_table;	/* the table itself */
};

#define REQUEST_MAGIC	0x53912051 /* "random" value */
#define VALID_REQUEST(e)  ((e) != NULL && (e)->magic == REQUEST_MAGIC)

#define RESPONSE_MAGIC	0x15021935 /* "random" value */
#define VALID_RESPONSE(e)  ((e) != NULL && (e)->magic == RESPONSE_MAGIC)

#define DISPATCH_MAGIC	0x69385829 /* "random" value */
#define VALID_DISPATCH(e)  ((e) != NULL && (e)->magic == DISPATCH_MAGIC)

/*
 * statics.
 */
static dns_dispentry_t *
bucket_search(dns_dispatch_t *, isc_sockaddr_t *,
	      dns_messageid_t, unsigned int);

static void
destroy(dns_dispatch_t *);

static void
udp_recv(isc_task_t *, isc_event_t *);

static void
startrecv(dns_dispatch_t *);

static dns_messageid_t
randomid(dns_dispatch_t *);

static unsigned int
hash(dns_dispatch_t *, isc_sockaddr_t *, dns_messageid_t);

static void
free_buffer(dns_dispatch_t *disp, void *buf, unsigned int len);

static void *
allocate_buffer(dns_dispatch_t *disp, unsigned int len);

static inline void
free_event(dns_dispatch_t *disp, dns_dispatchevent_t *ev);

static inline dns_dispatchevent_t *
allocate_event(dns_dispatch_t *disp);

static void
do_next_request(dns_dispatch_t *disp, dns_dispentry_t *resp);

static void
do_next_response(dns_dispatch_t *disp, dns_dispentry_t *resp);

static void
do_cancel(dns_dispatch_t *disp, dns_dispentry_t *resp);

static dns_dispentry_t *
linear_first(dns_dispatch_t *disp);

static dns_dispentry_t *
linear_next(dns_dispatch_t *disp, dns_dispentry_t *resp);

static dns_dispentry_t *
linear_first(dns_dispatch_t *disp)
{
	dns_dispentry_t *ret;
	unsigned int bucket;

	bucket = 0;

	while (bucket < disp->qid_hashsize) {
		ret = ISC_LIST_HEAD(disp->qid_table[bucket]);
		if (ret != NULL)
			return (ret);
		bucket++;
	}

	return (NULL);
}

static dns_dispentry_t *
linear_next(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispentry_t *ret;
	unsigned int bucket;

	ret = ISC_LIST_NEXT(resp, link);
	if (ret != NULL)
		return (ret);

	bucket = resp->bucket;
	while (bucket < disp->qid_hashsize) {
		ret = ISC_LIST_HEAD(disp->qid_table[bucket]);
		if (ret != NULL)
			return (ret);
		bucket++;
	}

	return (NULL);
}

/*
 * Return a hash of the destination and message id.  For now, just return
 * the message id bits, and mask off the low order bits of that.
 */
static unsigned int
hash(dns_dispatch_t *disp, isc_sockaddr_t *dest, dns_messageid_t id)
{
	unsigned int ret;

	(void)dest;  /* shut up compiler warning. */

	ret = id;
	ret &= disp->qid_mask;

	return (ret);
}

/*
 * Return a random message ID.  For now this isn't too clever...
 * XXXMLG
 */
static dns_messageid_t
randomid(dns_dispatch_t *disp)
{
	disp->qid_state++;

	return ((dns_messageid_t)disp->qid_state);
}

/*
 * Called when refcount reaches 0 at any time.
 */
static void
destroy(dns_dispatch_t *disp)
{
	dns_dispatchevent_t *ev;

	disp->magic = 0;

	isc_socket_detach(&disp->socket);
	isc_task_detach(&disp->task);

	/*
	 * Final cleanup of packets on the request list.
	 */
	ev = ISC_LIST_HEAD(disp->rq_events);
	while (ev != NULL) {
		ISC_LIST_UNLINK(disp->rq_events, ev, link);
		free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
		ev = ISC_LIST_HEAD(disp->rq_events);
	}

	INSIST(disp->buffers == 0);
	INSIST(disp->requests == 0);
	INSIST(disp->recvs == 0);

	isc_mempool_put(disp->epool, disp->failsafe_ev);
	disp->failsafe_ev = NULL;

	isc_mempool_destroy(&disp->rpool);
	isc_mempool_destroy(&disp->bpool);
	isc_mempool_destroy(&disp->epool);
	isc_mem_put(disp->mctx, disp->qid_table,
		    disp->qid_hashsize * sizeof(void *));

	isc_mem_put(disp->mctx, disp, sizeof(dns_dispatch_t));
}


static dns_dispentry_t *
bucket_search(dns_dispatch_t *disp, isc_sockaddr_t *dest, dns_messageid_t id,
	      unsigned int bucket)
{
	dns_dispentry_t *res;

	res = ISC_LIST_HEAD(disp->qid_table[bucket]);

	while (res != NULL) {
		if ((res->id == id) && isc_sockaddr_equal(dest, &res->host))
			return (res);
		res = ISC_LIST_NEXT(res, link);
	}

	return (NULL);
}

static void
free_buffer(dns_dispatch_t *disp, void *buf, unsigned int len)
{
	INSIST(disp->buffers > 0);
	disp->buffers--;

	printf("Freeing buffer %p, length %d, into %s, %d remain\n",
	       buf, len, (len == disp->buffersize ? "mempool" : "mctx"),
	       disp->buffers);
	if (len == disp->buffersize)
		isc_mempool_put(disp->bpool, buf);
	else
		isc_mem_put(disp->mctx, buf, len);
}

static void *
allocate_buffer(dns_dispatch_t *disp, unsigned int len)
{
	void *temp;

	INSIST(len > 0);

	if (len == disp->buffersize)
		temp = isc_mempool_get(disp->bpool);
	else
		temp = isc_mem_get(disp->mctx, len);

	if (temp != NULL) {
		disp->buffers++;

		printf("Allocated buffer %p, length %d, from %s, %d total\n",
		       temp, len,
		       (len == disp->buffersize ? "mempool" : "mctx"),
		       disp->buffers);
	}

	return (temp);
}

static inline void
free_event(dns_dispatch_t *disp, dns_dispatchevent_t *ev)
{
	if (disp->failsafe_ev == ev) {
		INSIST(disp->shutdown_out == 1);
		disp->shutdown_out = 0;
		return;
	}

	isc_mempool_put(disp->epool, ev);
}

static inline dns_dispatchevent_t *
allocate_event(dns_dispatch_t *disp)
{
	dns_dispatchevent_t *ev;

	ev = isc_mempool_get(disp->epool);

	return (ev);
}

/*
 * General flow:
 *
 * If I/O result == CANCELED, free the buffer and notify everyone as
 * the various queues drain.
 *
 * If I/O is error (not canceled and not success) log it, free the buffer,
 * and restart.
 *
 * If query:
 *	if no listeners: free the buffer, restart.
 *	if listener: allocate event, fill in details.
 *		If cannot allocate, free buffer, restart.
 *	if rq event queue is not empty, queue.  else, send.
 *	restart.
 *
 * If response:
 *	Allocate event, fill in details.
 *		If cannot allocate, free buffer, restart.
 *	find target.  If not found, free buffer, restart.
 *	if event queue is not empty, queue.  else, send.
 *	restart.
 */
static void
udp_recv(isc_task_t *task, isc_event_t *ev_in)
{
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	dns_dispatch_t *disp = ev_in->arg;
	dns_messageid_t id;
	dns_result_t dres;
	isc_buffer_t source;
	unsigned int flags;
	dns_dispentry_t *resp;
	dns_dispatchevent_t *rev;
	unsigned int bucket;
	isc_boolean_t killit;
	isc_boolean_t queue_request;
	isc_boolean_t queue_response;

	(void)task;  /* shut up compiler */

	printf("Got packet!\n");

	LOCK(&disp->lock);

	INSIST(disp->recvs > 0);
	disp->recvs--;

	if (ev->result != ISC_R_SUCCESS) {
		/*
		 * If the recv() was canceled pass the word on.
		 */
		if (ev->result == ISC_R_CANCELED) {
			free_buffer(disp, ev->region.base, ev->region.length);

			killit = ISC_FALSE;
			if (disp->recvs == 0 && disp->refcount == 0)
				killit = ISC_TRUE;

			UNLOCK(&disp->lock);

			if (killit)
				destroy(disp);

			isc_event_free(&ev_in);
			return;
		}

		/*
		 * otherwise, on strange error, log it and restart.
		 * XXXMLG
		 */
		free_buffer(disp, ev->region.base, ev->region.length);
		goto restart;
	}

	printf("length == %d, buflen = %d, addr = %p\n",
	       ev->n, ev->region.length, ev->region.base);

	/*
	 * Peek into the buffer to see what we can see.
	 */
	isc_buffer_init(&source, ev->region.base, ev->region.length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, ev->n);
	dres = dns_message_peekheader(&source, &id, &flags);
	if (dres != DNS_R_SUCCESS) {
		free_buffer(disp, ev->region.base, ev->region.length);
		printf("dns_message_peekheader(): %s\n",
		       isc_result_totext(dres));
		/* XXXMLG log something here... */
		goto restart;
	}

	printf("Got valid DNS message header, /QR %c, id %d\n",
	       ((flags & DNS_MESSAGEFLAG_QR) ? '1' : '0'), id);

	/*
	 * Allocate an event to send to the query or response client, and
	 * allocate a new buffer for our use.
	 */

	/*
	 * Look at flags.  If query, check to see if we have someone handling
	 * them.  If response, look to see where it goes.
	 */
	queue_request = ISC_FALSE;
	queue_response = ISC_FALSE;
	if ((flags & DNS_MESSAGEFLAG_QR) == 0) {
		resp = ISC_LIST_HEAD(disp->rq_handlers);
		while (resp != NULL) {
			if (resp->item_out == ISC_FALSE)
				break;
			resp = ISC_LIST_NEXT(resp, link);
		}
		if (resp == NULL)
			queue_request = ISC_TRUE;
		rev = allocate_event(disp);
		if (rev == NULL) {
			free_buffer(disp, ev->region.base, ev->region.length);
			goto restart;
		}
		/* query */
	} else {
 		/* response */
		bucket = hash(disp, &ev->address, id);
		resp = bucket_search(disp, &ev->address, id, bucket);
		if (resp == NULL) {
			free_buffer(disp, ev->region.base, ev->region.length);
			goto restart;
		}
		queue_response = resp->item_out;
		rev = allocate_event(disp);
		if (rev == NULL) {
			free_buffer(disp, ev->region.base, ev->region.length);
			goto restart;
		}
	}

	/*
	 * At this point, rev contains the event we want to fill in, and
	 * resp contains the information on the place to send it to.
	 * Send the event off.
	 */
	isc_buffer_init(&rev->buffer, ev->region.base, ev->region.length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&rev->buffer, ev->n);
	rev->result = DNS_R_SUCCESS;
	rev->id = id;
	rev->addr = ev->address;
	if (queue_request) {
		ISC_LIST_APPEND(disp->rq_events, rev, link);
	} else if (queue_response) {
		ISC_LIST_APPEND(resp->items, rev, link);
	} else {
		ISC_EVENT_INIT(rev, sizeof(*rev), 0, 0, DNS_EVENT_DISPATCH,
			       resp->action, resp->arg, resp, NULL, NULL);
		printf("Sent event for buffer %p (len %d) to task %p\n",
		       rev->buffer.base, rev->buffer.length, resp->task);
		resp->item_out = ISC_TRUE;
		ISC_TASK_SEND(resp->task, (isc_event_t **)&rev);
	}

	/*
	 * Restart recv() to get the next packet.
	 */
 restart:
	startrecv(disp);

	UNLOCK(&disp->lock);

	isc_event_free(&ev_in);
}

/*
 * disp must be locked
 */
static void
startrecv(dns_dispatch_t *disp)
{
	isc_sockettype_t socktype;
	isc_result_t res;
	isc_region_t region;
	unsigned int wanted;

	if (disp->shutting_down == 1)
		return;

	wanted = ISC_MIN(disp->recvs_wanted, disp->requests + 2);
	if (wanted == 0)
		return;

	if (disp->recvs >= wanted)
		return;

	if (disp->buffers >= disp->maxbuffers)
		return;

	socktype = isc_socket_gettype(disp->socket);

	while (disp->recvs < wanted) {
		switch (socktype) {
			/*
			 * UDP reads are always maximal.
			 */
		case isc_socket_udp:
			region.length = disp->buffersize;
			region.base = allocate_buffer(disp, disp->buffersize);
			if (region.base == NULL)
				return;
			printf("Recv into %p, length %d\n", region.base,
			       region.length);
			res = isc_socket_recv(disp->socket, &region, ISC_TRUE,
					      disp->task, udp_recv, disp);
			if (res != ISC_R_SUCCESS) {
				disp->shutdown_why = res;
				do_cancel(disp, NULL);
				return;
			}
			disp->recvs++;
			break;

		case isc_socket_tcp:
			INSIST(1); /* XXXMLG */
			break;
		}
	}
}

/*
 * Publics.
 */

dns_result_t
dns_dispatch_create(isc_mem_t *mctx, isc_socket_t *sock, isc_task_t *task,
		    unsigned int maxbuffersize,
		    unsigned int maxbuffers, unsigned int maxrequests,
		    unsigned int hashsize, dns_dispatch_t **dispp)
{
	dns_dispatch_t *disp;
	unsigned int tablesize;
	dns_result_t res;
	isc_sockettype_t socktype;
	unsigned int i;

	REQUIRE(mctx != NULL);
	REQUIRE(sock != NULL);
	REQUIRE(task != NULL);
	REQUIRE(hashsize <= 24);
	REQUIRE(maxbuffersize >= 512 && maxbuffersize < (64 * 1024));
	REQUIRE(maxbuffers > 0);
	REQUIRE(dispp != NULL && *dispp == NULL);

	socktype = isc_socket_gettype(sock);
	REQUIRE(socktype == isc_socket_udp || socktype == isc_socket_tcp);

	res = DNS_R_SUCCESS;

	disp = isc_mem_get(mctx, sizeof(dns_dispatch_t));
	if (disp == NULL)
		return (DNS_R_NOMEMORY);

	disp->magic = 0;
	disp->mctx = mctx;
	disp->buffersize = maxbuffersize;
	disp->maxrequests = maxrequests;
	disp->maxbuffers = maxbuffers;
	disp->refcount = 1;
	disp->recvs = 0;
	if (socktype == isc_socket_udp)
		disp->recvs_wanted = 4; /* XXXMLG config option */
	else
		disp->recvs_wanted = 1;
	disp->shutting_down = 0;
	disp->shutdown_out = 0;
	disp->shutdown_why = ISC_R_UNEXPECTED;
	disp->requests = 0;
	disp->buffers = 0;
	ISC_LIST_INIT(disp->rq_handlers);
	ISC_LIST_INIT(disp->rq_events);

	tablesize = (1 << hashsize);

	disp->qid_table = isc_mem_get(disp->mctx,
				      tablesize * sizeof(dns_displist_t));
	if (disp->qid_table == NULL) {
		res = DNS_R_NOMEMORY;
		goto out1;
	}

	for (i = 0 ; i < tablesize ; i++)
		ISC_LIST_INIT(disp->qid_table[i]);

	disp->qid_mask = tablesize - 1;
	disp->qid_hashsize = tablesize;

	if (isc_mutex_init(&disp->lock) != ISC_R_SUCCESS) {
		res = DNS_R_UNEXPECTED;
		UNEXPECTED_ERROR(__FILE__, __LINE__, "isc_mutex_init failed");
		goto out2;
	}

	disp->epool = NULL;
	if (isc_mempool_create(mctx, sizeof(dns_dispatchevent_t),
			       &disp->epool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out3;
	}

	disp->bpool = NULL;
	if (isc_mempool_create(mctx, maxbuffersize,
			       &disp->bpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out4;
	}
	isc_mempool_setmaxalloc(disp->bpool, maxbuffers);

	disp->rpool = NULL;
	if (isc_mempool_create(mctx, sizeof(dns_dispentry_t),
			       &disp->rpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out5;
	}

	/*
	 * Keep some number of items around.  This should be a config
	 * option.  For now, keep 8, but later keep at least two even
	 * if the caller wants less.  This allows us to ensure certain
	 * things, like an event can be "freed" and the next allocation
	 * will always succeed.
	 *
	 * Note that if limits are placed on anything here, we use one
	 * event internally, so the actual limit should be "wanted + 1."
	 *
	 * XXXMLG
	 */
	isc_mempool_setfreemax(disp->epool, 8);
	isc_mempool_setfreemax(disp->bpool, 8);
	isc_mempool_setfreemax(disp->rpool, 8);

	disp->failsafe_ev = allocate_event(disp);
	if (disp->failsafe_ev == NULL) {
		res = DNS_R_NOMEMORY;
		goto out6;
	}

	/*
	 * should initialize qid_state here XXXMLG
	 */
	disp->qid_state = (unsigned int)disp;

	disp->magic = DISPATCH_MAGIC;

	disp->task = NULL;
	isc_task_attach(task, &disp->task);
	disp->socket = NULL;
	isc_socket_attach(sock, &disp->socket);

	*dispp = disp;

	return (DNS_R_SUCCESS);

	/*
	 * error returns
	 */
 out6:
	isc_mempool_destroy(&disp->rpool);
 out5:
	isc_mempool_destroy(&disp->bpool);
 out4:
	isc_mempool_destroy(&disp->epool);
 out3:
	isc_mutex_destroy(&disp->lock);
 out2:
	isc_mem_put(mctx, disp->mctx, disp->qid_hashsize * sizeof(void *));
 out1:
	isc_mem_put(mctx, disp, sizeof(dns_dispatch_t));

	return (res);
}

void
dns_dispatch_destroy(dns_dispatch_t **dispp)
{
	dns_dispatch_t *disp;
	isc_boolean_t killit;

	REQUIRE(dispp != NULL && VALID_DISPATCH(*dispp));

	disp = *dispp;
	*dispp = NULL;

	LOCK(&disp->lock);

	INSIST(disp->refcount > 0);
	disp->refcount--;
	killit = ISC_FALSE;
	if (disp->refcount == 0) {
		if (disp->recvs > 0)
			isc_socket_cancel(disp->socket, NULL,
					  ISC_SOCKCANCEL_RECV);
		else
			killit = ISC_TRUE;
	}

	printf("dns_dispatch_destory:  refcount = %d\n", disp->refcount);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}

dns_result_t
dns_dispatch_addresponse(dns_dispatch_t *disp, isc_sockaddr_t *dest,
			 isc_task_t *task, isc_taskaction_t action, void *arg,
			 dns_messageid_t *idp, dns_dispentry_t **resp)
{
	dns_dispentry_t *res;
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

	if (disp->requests == disp->maxrequests) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMORE); /* XXXMLG really a quota */
	}

	/*
	 * Try somewhat hard to find an unique ID.
	 */
	id = randomid(disp);
	bucket = hash(disp, dest, id);
	ok = ISC_FALSE;
	for (i = 0 ; i < 64 ; i++) {
		if (bucket_search(disp, dest, id, bucket) == NULL) {
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

	disp->refcount++;
	disp->requests++;
	res->task = NULL;
	isc_task_attach(task, &res->task);

	res->magic = RESPONSE_MAGIC;
	res->id = id;
	res->bucket = bucket;
	res->host = *dest;
	res->action = action;
	res->arg = arg;
	res->item_out = ISC_FALSE;
	ISC_LIST_INIT(res->items);
	ISC_LINK_INIT(res, link);
	ISC_LIST_APPEND(disp->qid_table[bucket], res, link);

	startrecv(disp);

	UNLOCK(&disp->lock);

	*idp = id;
	*resp = res;

	return (DNS_R_SUCCESS);
}

void
dns_dispatch_removeresponse(dns_dispatch_t *disp, dns_dispentry_t **resp,
			    dns_dispatchevent_t **sockevent)
{
	dns_dispentry_t *res;
	dns_dispatchevent_t *ev;
	unsigned int bucket;
	isc_boolean_t killit;

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

	INSIST(disp->requests > 0);
	disp->requests--;
	INSIST(disp->refcount > 0);
	disp->refcount--;
	killit = ISC_FALSE;
	if (disp->refcount == 0) {
		if (disp->recvs > 0)
			isc_socket_cancel(disp->socket, NULL,
					  ISC_SOCKCANCEL_RECV);
		else
			killit = ISC_TRUE;
	}

	res->magic = 0;
	bucket = res->bucket;

	ISC_LIST_UNLINK(disp->qid_table[bucket], res, link);

	isc_task_detach(&res->task);

	if (ev != NULL) {
		REQUIRE(res->item_out = ISC_TRUE);
		res->item_out = ISC_FALSE;
		free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
	}
	isc_mempool_put(disp->rpool, res);
	if (disp->shutting_down == 1)
		do_cancel(disp, NULL);

	startrecv(disp);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}

dns_result_t
dns_dispatch_addrequest(dns_dispatch_t *disp,
			isc_task_t *task, isc_taskaction_t action, void *arg,
			dns_dispentry_t **resp)
{
	dns_dispentry_t *res;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(task != NULL);
	REQUIRE(resp != NULL && *resp == NULL);

	LOCK(&disp->lock);

	if (disp->requests == disp->maxrequests) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMORE); /* XXXMLG really a quota */
	}

	res = isc_mempool_get(disp->rpool);
	if (res == NULL) {
		UNLOCK(&disp->lock);
		return (DNS_R_NOMEMORY);
	}

	disp->refcount++;
	disp->requests++;
	res->task = NULL;
	isc_task_attach(task, &res->task);

	res->magic = REQUEST_MAGIC;
	res->bucket = INVALID_BUCKET;
	res->action = action;
	res->arg = arg;
	res->item_out = ISC_FALSE;
	ISC_LIST_INIT(res->items);
	ISC_LINK_INIT(res, link);
	ISC_LIST_APPEND(disp->rq_handlers, res, link);

	/*
	 * If there are queries waiting to be processed, give this critter
	 * one of them.
	 */
	do_next_request(disp, res);

	startrecv(disp);

	UNLOCK(&disp->lock);

	*resp = res;

	return (DNS_R_SUCCESS);
}

void
dns_dispatch_removerequest(dns_dispatch_t *disp, dns_dispentry_t **resp,
			   dns_dispatchevent_t **sockevent)
{
	dns_dispentry_t *res;
	dns_dispatchevent_t *ev;
	isc_boolean_t killit;

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

	INSIST(disp->requests > 0);
	disp->requests--;
	INSIST(disp->refcount > 0);
	disp->refcount--;
	killit = ISC_FALSE;
	if (disp->refcount == 0) {
		if (disp->recvs > 0)
			isc_socket_cancel(disp->socket, NULL,
					  ISC_SOCKCANCEL_RECV);
		else
			killit = ISC_TRUE;
	}

	res->magic = 0;

	ISC_LIST_UNLINK(disp->rq_handlers, res, link);

	isc_task_detach(&res->task);

	isc_mempool_put(disp->rpool, res);
	if (ev != NULL) {
		REQUIRE(res->item_out = ISC_TRUE);
		res->item_out = ISC_FALSE;
		if (ev->buffer.length != 0)
			free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
	}

	startrecv(disp);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}

void
dns_dispatch_freeevent(dns_dispatch_t *disp, dns_dispentry_t *resp,
		       dns_dispatchevent_t **sockevent)
{
	dns_dispatchevent_t *ev;
	isc_boolean_t response;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(sockevent != NULL && *sockevent != NULL);

	ev = *sockevent;
	*sockevent = NULL;

	response = ISC_FALSE;
	if (VALID_RESPONSE(resp)) {
		response = ISC_TRUE;
	} else {
		REQUIRE(VALID_RESPONSE(resp) || VALID_REQUEST(resp));
	}

	LOCK(&disp->lock);
	REQUIRE(ev != disp->failsafe_ev);
	REQUIRE(resp->item_out = ISC_TRUE);
	resp->item_out = ISC_FALSE;

	free_buffer(disp, ev->buffer.base, ev->buffer.length);
	free_event(disp, ev);

	if (response)
		do_next_response(disp, resp);
	else
		do_next_request(disp, resp);

	startrecv(disp);

	UNLOCK(&disp->lock);
}

static void
do_next_response(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispatchevent_t *ev;

	INSIST(resp->item_out == ISC_FALSE);

	ev = ISC_LIST_HEAD(resp->items);
	if (ev == NULL) {
		if (disp->shutting_down == 1)
			do_cancel(disp, resp);
		return;
	}

	ISC_LIST_UNLINK(disp->rq_events, ev, link);

	ISC_EVENT_INIT(ev, sizeof(*ev), 0, 0, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	resp->item_out = ISC_TRUE;
	printf("Sent event for buffer %p (len %d) to task %p\n",
	       ev->buffer.base, ev->buffer.length, resp->task);
	ISC_TASK_SEND(resp->task, (isc_event_t **)&ev);
}

static void
do_next_request(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispatchevent_t *ev;

	INSIST(resp->item_out == ISC_FALSE);

	ev = ISC_LIST_HEAD(disp->rq_events);
	if (ev == NULL) {
		if (disp->shutting_down == 1)
			do_cancel(disp, resp);
		return;
	}

	ISC_LIST_UNLINK(disp->rq_events, ev, link);

	ISC_EVENT_INIT(ev, sizeof(*ev), 0, 0, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	resp->item_out = ISC_TRUE;
	printf("Sent event for buffer %p (len %d) to task %p\n",
	       ev->buffer.base, ev->buffer.length, resp->task);
	ISC_TASK_SEND(resp->task, (isc_event_t **)&ev);
}

static void
do_cancel(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispatchevent_t *ev;

	if (disp->shutdown_out == 1)
		return;

	/*
	 * If no target given, find the first request handler.  If
	 * there are packets waiting for any handler, however, don't
	 * kill them.
	 */
	if (resp == NULL) {
		resp = ISC_LIST_HEAD(disp->rq_handlers);
		if (resp != NULL && resp->item_out == ISC_FALSE)
			resp = NULL;
	}

	/*
	 * Search for the first responce handler without packets outstanding.
	 */
	if (resp == NULL) {
		resp = linear_first(disp);
		if (resp == NULL)  /* no first item? */
			return;

		do {
			if (resp->item_out == ISC_FALSE)
				break;

			resp = linear_next(disp, resp);
		} while (resp != NULL);

		/*
		 * No one to send the cancel event to, so nothing to do.
		 */
		if (resp == NULL)
			return;
	}

	/*
	 * Send the shutdown failsafe event to this resp.
	 */
	ev = disp->failsafe_ev;
	ISC_EVENT_INIT(ev, sizeof (*ev), 0, 0, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	ev->result = ISC_R_CANCELED;
	ev->buffer.base = NULL;
	ev->buffer.length = 0;
	ISC_TASK_SEND(resp->task, (isc_event_t **)&ev);
}
