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

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/lfsr.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/socket.h>
#include <isc/util.h>

#include <dns/events.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/dispatch.h>
#include <dns/message.h>
#include <dns/tcpmsg.h>

#ifdef DISPATCH_DEBUG
#define XDEBUG(x) printf x
#else
#define XDEBUG(x)
#endif

struct dns_dispentry {
	unsigned int			magic;
	isc_uint32_t			id;
	unsigned int			bucket;
	isc_sockaddr_t			host;
	isc_task_t		       *task;
	isc_taskaction_t		action;
	void			       *arg;
	isc_boolean_t			item_out;
	ISC_LIST(dns_dispatchevent_t)	items;
	ISC_LINK(dns_dispentry_t)	link;
};

#define INVALID_BUCKET		(0xffffdead)

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
	isc_result_t		shutdown_why;
	unsigned int		requests;	/* how many requests we have */
	unsigned int		buffers;	/* allocated buffers */
	ISC_LIST(dns_dispentry_t) rq_handlers;	/* request handler list */
	ISC_LIST(dns_dispatchevent_t) rq_events; /* holder for rq events */
	dns_tcpmsg_t		tcpmsg;		/* for tcp streams */
	dns_dispatchmethods_t	methods;	/* methods to use */
	isc_lfsr_t		qid_lfsr1;	/* state generator info */
	isc_lfsr_t		qid_lfsr2;	/* state generator info */
	unsigned int		qid_nbuckets;	/* hash table size */
	unsigned int		qid_increment;	/* id increment on collision */
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
static dns_dispentry_t *bucket_search(dns_dispatch_t *, isc_sockaddr_t *,
				      dns_messageid_t, unsigned int);
static void destroy(dns_dispatch_t *);
static void udp_recv(isc_task_t *, isc_event_t *);
static void tcp_recv(isc_task_t *, isc_event_t *);
static inline void startrecv(dns_dispatch_t *);
static isc_uint32_t dns_randomid(dns_dispatch_t *);
static isc_uint32_t dns_hash(dns_dispatch_t *, isc_sockaddr_t *, isc_uint32_t);
static void free_buffer(dns_dispatch_t *disp, void *buf, unsigned int len);
static void *allocate_buffer(dns_dispatch_t *disp, unsigned int len);
static inline void free_event(dns_dispatch_t *disp, dns_dispatchevent_t *ev);
static inline dns_dispatchevent_t *allocate_event(dns_dispatch_t *disp);
static void do_next_request(dns_dispatch_t *disp, dns_dispentry_t *resp);
static void do_next_response(dns_dispatch_t *disp, dns_dispentry_t *resp);
static void do_cancel(dns_dispatch_t *disp, dns_dispentry_t *resp);
static dns_dispentry_t *linear_first(dns_dispatch_t *disp);
static dns_dispentry_t *linear_next(dns_dispatch_t *disp,
				    dns_dispentry_t *resp);

static void
reseed_lfsr(isc_lfsr_t *lfsr, void *arg)
{
	UNUSED(arg);

	lfsr->count = (random() & 0x1f) + 32;	/* From 32 to 63 states */

	lfsr->state = random();
}

/*
 * Return an unpredictable message ID.
 */
static isc_uint32_t
dns_randomid(dns_dispatch_t *disp)
{
	isc_uint32_t id;

	id = isc_lfsr_generate32(&disp->qid_lfsr1, &disp->qid_lfsr2);

	return (id & 0x0000ffffU);
}

/*
 * Return a hash of the destination and message id.
 */
static isc_uint32_t
dns_hash(dns_dispatch_t *disp, isc_sockaddr_t *dest, isc_uint32_t id)
{
	unsigned int ret;

	ret = isc_sockaddr_hash(dest, ISC_TRUE);
	ret ^= (id & 0x0000ffff); /* important to mask off garbage bits */
	ret %= disp->qid_nbuckets;

	INSIST(ret < disp->qid_nbuckets);

	return (ret);
}

static dns_dispatchmethods_t dns_wire_methods = {
	dns_randomid,
	dns_hash
};

static dns_dispentry_t *
linear_first(dns_dispatch_t *disp)
{
	dns_dispentry_t *ret;
	unsigned int bucket;

	bucket = 0;

	while (bucket < disp->qid_nbuckets) {
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
	while (bucket < disp->qid_nbuckets) {
		ret = ISC_LIST_HEAD(disp->qid_table[bucket]);
		if (ret != NULL)
			return (ret);
		bucket++;
	}

	return (NULL);
}

/*
 * Called when refcount reaches 0 (and safe to destroy)
 */
static void
destroy(dns_dispatch_t *disp)
{
	dns_dispatchevent_t *ev;

	disp->magic = 0;

	dns_tcpmsg_invalidate(&disp->tcpmsg);

	XDEBUG(("dispatch::destroy:  detaching from sock %p and task %p\n",
		disp->socket, disp->task));

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

	isc_socket_detach(&disp->socket);
	isc_task_detach(&disp->task);

	isc_mempool_put(disp->epool, disp->failsafe_ev);
	disp->failsafe_ev = NULL;

	isc_mempool_destroy(&disp->rpool);
	isc_mempool_destroy(&disp->bpool);
	isc_mempool_destroy(&disp->epool);
	isc_mem_put(disp->mctx, disp->qid_table,
		    disp->qid_nbuckets * sizeof(dns_displist_t));

	isc_mem_put(disp->mctx, disp, sizeof(dns_dispatch_t));
}


static dns_dispentry_t *
bucket_search(dns_dispatch_t *disp, isc_sockaddr_t *dest, dns_messageid_t id,
	      unsigned int bucket)
{
	dns_dispentry_t *res;

	REQUIRE(bucket < disp->qid_nbuckets);

	res = ISC_LIST_HEAD(disp->qid_table[bucket]);

	while (res != NULL) {
		if ((res->id == id) && isc_sockaddr_equal(dest, &res->host))
			return (res);
		XDEBUG(("lengths (%d, %d), ids (%d, %d)\n",
			dest->length, res->host.length,
			res->id, id));
		res = ISC_LIST_NEXT(res, link);
	}

	return (NULL);
}

static void
free_buffer(dns_dispatch_t *disp, void *buf, unsigned int len)
{
	isc_sockettype_t socktype;

	INSIST(buf != NULL && len != 0);
	INSIST(disp->buffers > 0);
	disp->buffers--;

	socktype = isc_socket_gettype(disp->socket);

	switch (socktype) {
	case isc_sockettype_tcp:
		isc_mem_put(disp->mctx, buf, len);
		break;
	case isc_sockettype_udp:
		XDEBUG(("Freeing buffer %p, length %d, into %s, %d remain\n",
			buf, len,
			(len == disp->buffersize ? "mempool" : "mctx"),
			disp->buffers));
		if (len == disp->buffersize)
			isc_mempool_put(disp->bpool, buf);
		else
			isc_mem_put(disp->mctx, buf, len);
		break;
	default:
		INSIST(0);
		break;
	}
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

		XDEBUG(("Allocated buffer %p, length %d, from %s, %d total\n",
			temp, len,
			(len == disp->buffersize ? "mempool" : "mctx"),
			disp->buffers));
	}

	return (temp);
}

static inline void
free_event(dns_dispatch_t *disp, dns_dispatchevent_t *ev)
{
	if (disp->failsafe_ev == ev) {
		INSIST(disp->shutdown_out == 1);
		disp->shutdown_out = 0;
		XDEBUG(("Returning failsafe event to dispatcher\n"));
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
	isc_result_t dres;
	isc_buffer_t source;
	unsigned int flags;
	dns_dispentry_t *resp;
	dns_dispatchevent_t *rev;
	unsigned int bucket;
	isc_boolean_t killit;
	isc_boolean_t queue_request;
	isc_boolean_t queue_response;
	unsigned int attributes;

	(void)task;  /* shut up compiler */

	XDEBUG(("Got packet!\n"));

	LOCK(&disp->lock);

	XDEBUG(("requests:  %d, buffers:  %d, recvs:  %d\n",
		disp->requests, disp->buffers, disp->recvs));

	INSIST(disp->recvs > 0);
	disp->recvs--;

	if (disp->refcount == 0) {
		/*
		 * This dispatcher is shutting down.
		 */
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

	if (ev->result != ISC_R_SUCCESS) {
		XDEBUG(("recv result %d (%s)\n", ev->result,
			isc_result_totext(ev->result)));

		free_buffer(disp, ev->region.base, ev->region.length);

		/*
		 * If the recv() was canceled pass the word on.
		 */
		if (ev->result == ISC_R_CANCELED) {
			UNLOCK(&disp->lock);
			isc_event_free(&ev_in);
			return;
		}

		/*
		 * otherwise, on strange error, log it and restart.
		 * XXXMLG
		 */
		goto restart;
	}

	XDEBUG(("length == %d, buflen = %d, addr = %p\n",
		ev->n, ev->region.length, ev->region.base));

	/*
	 * Peek into the buffer to see what we can see.
	 */
	isc_buffer_init(&source, ev->region.base, ev->region.length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, ev->n);
	dres = dns_message_peekheader(&source, &id, &flags);
	if (dres != DNS_R_SUCCESS) {
		free_buffer(disp, ev->region.base, ev->region.length);
		XDEBUG(("dns_message_peekheader(): %s\n",
			isc_result_totext(dres)));
		/* XXXMLG log something here... */
		goto restart;
	}

	XDEBUG(("Got valid DNS message header, /QR %c, id %d\n",
		((flags & DNS_MESSAGEFLAG_QR) ? '1' : '0'), id));

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
		bucket = disp->methods.hash(disp, &ev->address, id);
		resp = bucket_search(disp, &ev->address, id, bucket);
		XDEBUG(("Search for response in bucket %d: %s\n",
			bucket, (resp == NULL ? "NOT FOUND" : "FOUND")));

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
	attributes = 0;
	if ((ev->attributes & ISC_SOCKEVENTATTR_PKTINFO) != 0) {
		rev->pktinfo = ev->pktinfo;
		attributes |= DNS_DISPATCHATTR_PKTINFO;
	} else {
		attributes &= ~DNS_DISPATCHATTR_PKTINFO;
	}
	if (queue_request) {
		ISC_LIST_APPEND(disp->rq_events, rev, link);
	} else if (queue_response) {
		ISC_LIST_APPEND(resp->items, rev, link);
	} else {
		ISC_EVENT_INIT(rev, sizeof(*rev), attributes, NULL,
			       DNS_EVENT_DISPATCH,
			       resp->action, resp->arg, resp, NULL, NULL);
		XDEBUG(("Sent event %p buffer %p len %d to task %p, resp %p\n",
			rev, rev->buffer.base, rev->buffer.length,
			resp->task, resp));
		resp->item_out = ISC_TRUE;
		isc_task_send(resp->task, (isc_event_t **)&rev);
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
tcp_recv(isc_task_t *task, isc_event_t *ev_in)
{
	dns_dispatch_t *disp = ev_in->arg;
	dns_tcpmsg_t *tcpmsg = &disp->tcpmsg;
	dns_messageid_t id;
	isc_result_t dres;
	unsigned int flags;
	dns_dispentry_t *resp;
	dns_dispatchevent_t *rev;
	unsigned int bucket;
	isc_boolean_t killit;
	isc_boolean_t queue_request;
	isc_boolean_t queue_response;

	(void)task;  /* shut up compiler */

	REQUIRE(VALID_DISPATCH(disp));

	XDEBUG(("Got TCP packet!\n"));

	LOCK(&disp->lock);

	INSIST(disp->recvs > 0);
	disp->recvs--;

	if (disp->refcount == 0) {
		/*
		 * This dispatcher is shutting down.  Force cancelation.
		 */
		tcpmsg->result = ISC_R_CANCELED;
	}

	switch (tcpmsg->result) {
	case ISC_R_SUCCESS:
		break;

	case ISC_R_EOF:
		XDEBUG(("Shutting down on EOF\n"));
		disp->shutdown_why = ISC_R_EOF;
		disp->shutting_down = 1;
		do_cancel(disp, NULL);
		/* FALLTHROUGH */
	case ISC_R_CANCELED:
		/*
		 * If the recv() was canceled pass the word on.
		 */
		killit = ISC_FALSE;
		if (disp->recvs == 0 && disp->refcount == 0)
			killit = ISC_TRUE;

		UNLOCK(&disp->lock);

		/*
		 * The event is statically allocated in the tcpmsg	
		 * structure, and destroy() frees the tcpmsg, so we must
		 * free the event *before* calling destroy().
		 */
		isc_event_free(&ev_in);

		if (killit)
			destroy(disp);

		return;

	default:
		/*
		 * otherwise, on strange error, log it and restart.
		 * XXXMLG
		 */
		goto restart;
	}

	XDEBUG(("result %d, length == %d, addr = %p\n",
		tcpmsg->result,
		tcpmsg->buffer.length, tcpmsg->buffer.base));

	/*
	 * Peek into the buffer to see what we can see.
	 */
	dres = dns_message_peekheader(&tcpmsg->buffer, &id, &flags);
	if (dres != DNS_R_SUCCESS) {
		XDEBUG(("dns_message_peekheader(): %s\n",
			isc_result_totext(dres)));
		/* XXXMLG log something here... */
		goto restart;
	}

	XDEBUG(("Got valid DNS message header, /QR %c, id %d\n",
		((flags & DNS_MESSAGEFLAG_QR) ? '1' : '0'), id));

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
		if (rev == NULL)
			goto restart;
		/* query */
	} else {
 		/* response */
		bucket = disp->methods.hash(disp, &tcpmsg->address, id);
		resp = bucket_search(disp, &tcpmsg->address, id, bucket);
		XDEBUG(("Search for response in bucket %d: %s\n",
			bucket, (resp == NULL ? "NOT FOUND" : "FOUND")));

		if (resp == NULL)
			goto restart;
		queue_response = resp->item_out;
		rev = allocate_event(disp);
		if (rev == NULL)
			goto restart;
	}

	/*
	 * At this point, rev contains the event we want to fill in, and
	 * resp contains the information on the place to send it to.
	 * Send the event off.
	 */
	dns_tcpmsg_keepbuffer(tcpmsg, &rev->buffer);
	disp->buffers++;
	rev->result = DNS_R_SUCCESS;
	rev->id = id;
	rev->addr = tcpmsg->address;
	if (queue_request) {
		ISC_LIST_APPEND(disp->rq_events, rev, link);
	} else if (queue_response) {
		ISC_LIST_APPEND(resp->items, rev, link);
	} else {
		ISC_EVENT_INIT(rev, sizeof(*rev), 0, NULL, DNS_EVENT_DISPATCH,
			       resp->action, resp->arg, resp, NULL, NULL);
		XDEBUG(("Sent event %p buffer %p len %d to task %p, resp %p\n",
			rev, rev->buffer.base, rev->buffer.length,
			resp->task, resp));
		resp->item_out = ISC_TRUE;
		isc_task_send(resp->task, (isc_event_t **)&rev);
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
		case isc_sockettype_udp:
			region.length = disp->buffersize;
			region.base = allocate_buffer(disp, disp->buffersize);
			if (region.base == NULL)
				return;
			XDEBUG(("Recv into %p, length %d\n", region.base,
				region.length));
			res = isc_socket_recv(disp->socket, &region, 1,
					      disp->task, udp_recv, disp);
			if (res != ISC_R_SUCCESS) {
				disp->shutdown_why = res;
				disp->shutting_down = 1;
				do_cancel(disp, NULL);
				return;
			}
			disp->recvs++;
			break;

		case isc_sockettype_tcp:
			XDEBUG(("Starting tcp receive\n"));
			res = dns_tcpmsg_readmessage(&disp->tcpmsg,
						     disp->task, tcp_recv,
						     disp);
			if (res != ISC_R_SUCCESS) {
				disp->shutdown_why = res;
				disp->shutting_down = 1;
				do_cancel(disp, NULL);
				return;
			}
			disp->recvs++;
			break;
		}
	}
}

/*
 * Publics.
 */

isc_result_t
dns_dispatch_create(isc_mem_t *mctx, isc_socket_t *sock, isc_task_t *task,
		    unsigned int maxbuffersize,
		    unsigned int maxbuffers, unsigned int maxrequests,
		    unsigned int buckets, unsigned int increment,
		    dns_dispatchmethods_t *methods,
		    dns_dispatch_t **dispp)
{
	dns_dispatch_t *disp;
	isc_result_t res;
	isc_sockettype_t socktype;
	unsigned int i;

	REQUIRE(mctx != NULL);
	REQUIRE(sock != NULL);
	REQUIRE(task != NULL);
	REQUIRE(buckets < 2097169);  /* next prime > 65536 * 32 */
	REQUIRE(increment > buckets);
	REQUIRE(maxbuffersize >= 512 && maxbuffersize < (64 * 1024));
	REQUIRE(maxbuffers > 0);
	REQUIRE(dispp != NULL && *dispp == NULL);

	socktype = isc_socket_gettype(sock);
	REQUIRE(socktype == isc_sockettype_udp ||
		socktype == isc_sockettype_tcp);

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
	if (socktype == isc_sockettype_udp) {
		disp->recvs_wanted = 4; /* XXXMLG config option */
	} else {
		disp->recvs_wanted = 1;
	}
	disp->shutting_down = 0;
	disp->shutdown_out = 0;
	disp->shutdown_why = ISC_R_UNEXPECTED;
	disp->requests = 0;
	disp->buffers = 0;
	ISC_LIST_INIT(disp->rq_handlers);
	ISC_LIST_INIT(disp->rq_events);

	if (methods == NULL)
		disp->methods = dns_wire_methods;
	else
		disp->methods = *methods;

	disp->qid_table = isc_mem_get(disp->mctx,
				      buckets * sizeof(dns_displist_t));
	if (disp->qid_table == NULL) {
		res = DNS_R_NOMEMORY;
		goto out1;
	}

	for (i = 0 ; i < buckets ; i++)
		ISC_LIST_INIT(disp->qid_table[i]);

	disp->qid_nbuckets = buckets;
	disp->qid_increment = increment;

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
	isc_mempool_setname(disp->epool, "disp_epool");

	disp->bpool = NULL;
	if (isc_mempool_create(mctx, maxbuffersize,
			       &disp->bpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out4;
	}
	isc_mempool_setmaxalloc(disp->bpool, maxbuffers);
	isc_mempool_setname(disp->bpool, "disp_bpool");

	disp->rpool = NULL;
	if (isc_mempool_create(mctx, sizeof(dns_dispentry_t),
			       &disp->rpool) != ISC_R_SUCCESS) {
		res = DNS_R_NOMEMORY;
		goto out5;
	}
	isc_mempool_setname(disp->rpool, "disp_rpool");

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
	 * Initialize to a 32-bit LFSR.  Both of these are from Applied
	 * Cryptography.
	 *
	 * lfsr1:
	 *	x^32 + x^7 + x^5 + x^3 + x^2 + x + 1
	 *
	 * lfsr2:
	 *	x^32 + x^7 + x^6 + x^2 + 1
	 */
	isc_lfsr_init(&disp->qid_lfsr1, 0, 32, 0x80000057U,
		      0, reseed_lfsr, disp);
	isc_lfsr_init(&disp->qid_lfsr2, 0, 32, 0x800000c2U,
		      0, reseed_lfsr, disp);

	disp->magic = DISPATCH_MAGIC;

	disp->task = NULL;
	isc_task_attach(task, &disp->task);
	XDEBUG(("dns_dispatch_create: attaching to task %p\n", disp->task));
	disp->socket = NULL;
	isc_socket_attach(sock, &disp->socket);
	XDEBUG(("dns_dispatch_create:  attaching to socket %p\n",
		disp->socket));

	dns_tcpmsg_init(disp->mctx, disp->socket, &disp->tcpmsg);

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
	isc_mem_put(mctx, disp->mctx, disp->qid_nbuckets * sizeof(void *));
 out1:
	isc_mem_put(mctx, disp, sizeof(dns_dispatch_t));

	return (res);
}

void
dns_dispatch_attach(dns_dispatch_t *disp, dns_dispatch_t **dispp)
{
	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(dispp != NULL && *dispp == NULL);

	disp->refcount++;

	*dispp = disp;
}


void
dns_dispatch_detach(dns_dispatch_t **dispp)
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

	XDEBUG(("dns_dispatch_detach:  refcount = %d\n", disp->refcount));

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}

isc_result_t
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

	if (disp->shutting_down == 1) {
		UNLOCK(&disp->lock);
		return (ISC_R_SHUTTINGDOWN);
	}

	if (disp->requests == disp->maxrequests) {
		UNLOCK(&disp->lock);
		return (ISC_R_QUOTA);
	}

	/*
	 * Try somewhat hard to find an unique ID.
	 */
	id = disp->methods.randomid(disp);
	bucket = disp->methods.hash(disp, dest, id);
	ok = ISC_FALSE;
	for (i = 0 ; i < 64 ; i++) {
		if (bucket_search(disp, dest, id, bucket) == NULL) {
			ok = ISC_TRUE;
			break;
		}
		id += disp->qid_increment;
		id &= 0x0000ffff;
		bucket = disp->methods.hash(disp, dest, id);
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
	XDEBUG(("dns_dispatch_addresponse:  attaching to task %p\n",
		res->task));

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

	XDEBUG(("Inserted response into bucket %d\n", bucket));

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
	unsigned int n;
	isc_eventlist_t events;

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

	if (ev == NULL && res->item_out) {
		/*
		 * We've posted our event, but the caller hasn't gotten it
		 * yet.  Take it back.
		 */
		ISC_LIST_INIT(events);
		n = isc_task_unsend(res->task, res, DNS_EVENT_DISPATCH,
				    NULL, &events);
		/*
		 * We had better have gotten it back.
		 */
		INSIST(n == 1);
		ev = (dns_dispatchevent_t *)ISC_LIST_HEAD(events);
	}

	if (ev != NULL) {
		REQUIRE(res->item_out == ISC_TRUE);
		res->item_out = ISC_FALSE;
		if (ev->buffer.base != NULL)
			free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
	}

	XDEBUG(("dns_dispatch_removeresponse:  detaching from task %p\n",
		res->task));
	isc_task_detach(&res->task);

	/*
	 * Free any buffered requests as well
	 */
	ev = ISC_LIST_HEAD(res->items);
	while (ev != NULL) {
		ISC_LIST_UNLINK(res->items, ev, link);
		if (ev->buffer.base != NULL)
			free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
		ev = ISC_LIST_HEAD(res->items);
	}
	isc_mempool_put(disp->rpool, res);
	if (disp->shutting_down == 1)
		do_cancel(disp, NULL);
	else
		startrecv(disp);

	UNLOCK(&disp->lock);

	if (killit)
		destroy(disp);
}

isc_result_t
dns_dispatch_addrequest(dns_dispatch_t *disp,
			isc_task_t *task, isc_taskaction_t action, void *arg,
			dns_dispentry_t **resp)
{
	dns_dispentry_t *res;

	REQUIRE(VALID_DISPATCH(disp));
	REQUIRE(task != NULL);
	REQUIRE(resp != NULL && *resp == NULL);

	LOCK(&disp->lock);

	if (disp->shutting_down == 1) {
		UNLOCK(&disp->lock);
		return (ISC_R_SHUTTINGDOWN);
	}

	if (disp->requests == disp->maxrequests) {
		UNLOCK(&disp->lock);
		return (ISC_R_QUOTA);
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
	XDEBUG(("dns_dispatch_addrequest:  attaching to task %p\n",
		res->task));

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
	unsigned int n;
	isc_eventlist_t events;

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

	if (ev == NULL && res->item_out) {
		/*
		 * We've posted our event, but the caller hasn't gotten it
		 * yet.  Take it back.
		 */
		ISC_LIST_INIT(events);
		n = isc_task_unsend(res->task, res, DNS_EVENT_DISPATCH,
				    NULL, &events);
		/*
		 * We had better have gotten it back.
		 */
		INSIST(n == 1);
		ev = (dns_dispatchevent_t *)ISC_LIST_HEAD(events);
	}

	if (ev != NULL) {
		REQUIRE(res->item_out == ISC_TRUE);
		res->item_out = ISC_FALSE;
		if (ev->buffer.base != NULL)
			free_buffer(disp, ev->buffer.base, ev->buffer.length);
		free_event(disp, ev);
	}

	XDEBUG(("dns_dispatch_removerequest:  detaching from task %p\n",
		res->task));
	isc_task_detach(&res->task);

	isc_mempool_put(disp->rpool, res);
	if (disp->shutting_down == 1)
		do_cancel(disp, NULL);
	else
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
	REQUIRE(resp->item_out == ISC_TRUE);
	REQUIRE(ev->result == ISC_R_SUCCESS);
	resp->item_out = ISC_FALSE;

	if (ev->buffer.base != NULL)
		free_buffer(disp, ev->buffer.base, ev->buffer.length);
	free_event(disp, ev);

	if (response)
		do_next_response(disp, resp);
	else
		do_next_request(disp, resp);

	if (disp->shutting_down == 0)
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
			do_cancel(disp, NULL); /* was resp */
		return;
	}

	ISC_LIST_UNLINK(disp->rq_events, ev, link);

	ISC_EVENT_INIT(ev, sizeof(*ev), 0, NULL, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	resp->item_out = ISC_TRUE;
	XDEBUG(("Sent event %p for buffer %p (len %d) to task %p, resp %p\n",
		ev, ev->buffer.base, ev->buffer.length, resp->task, resp));
	isc_task_send(resp->task, (isc_event_t **)&ev);
}

static void
do_next_request(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispatchevent_t *ev;

	INSIST(resp->item_out == ISC_FALSE);

	ev = ISC_LIST_HEAD(disp->rq_events);
	if (ev == NULL) {
		if (disp->shutting_down == 1)
			do_cancel(disp, NULL); /* was resp */
		return;
	}

	ISC_LIST_UNLINK(disp->rq_events, ev, link);

	ISC_EVENT_INIT(ev, sizeof(*ev), 0, NULL, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	resp->item_out = ISC_TRUE;
	XDEBUG(("Sent event %p for buffer %p (len %d) to task %p, resp %p\n",
		ev, ev->buffer.base, ev->buffer.length, resp->task, resp));
	isc_task_send(resp->task, (isc_event_t **)&ev);
}

static void
do_cancel(dns_dispatch_t *disp, dns_dispentry_t *resp)
{
	dns_dispatchevent_t *ev;

	if (disp->shutdown_out == 1) {
		XDEBUG(("do_cancel() call ignored\n"));
		return;
	}
	XDEBUG(("do_cancel:  disp = %p, resp = %p\n", disp, resp));

	/*
	 * If no target given, find the first request handler.  If
	 * there are packets waiting for any handler, however, don't
	 * kill them.
	 */
	if (resp == NULL) {
		XDEBUG(("do_cancel:  passed a NULL response, searching...\n"));
		if (ISC_LIST_EMPTY(disp->rq_events)) {
			XDEBUG(("do_cancel:  non-empty request list.\n"));
			resp = ISC_LIST_HEAD(disp->rq_handlers);
			while (resp != NULL) {
				XDEBUG(("do_cancel:  resp %p, item_out %s\n",
					resp,
					(resp->item_out ? "TRUE" : "FALSE")));
				if (resp->item_out == ISC_FALSE)
					break;
				resp = ISC_LIST_NEXT(resp, link);
			}
		}
	}

	/*
	 * Search for the first response handler without packets outstanding.
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
	}

	/*
	 * No one to send the cancel event to, so nothing to do.
	 */
	if (resp == NULL)
		return;

	/*
	 * Send the shutdown failsafe event to this resp.
	 */
	ev = disp->failsafe_ev;
	ISC_EVENT_INIT(ev, sizeof (*ev), 0, NULL, DNS_EVENT_DISPATCH,
		       resp->action, resp->arg, resp, NULL, NULL);
	ev->result = disp->shutdown_why;
	ev->buffer.base = NULL;
	ev->buffer.length = 0;
	disp->shutdown_out = 1;
	XDEBUG(("Sending failsafe event %p to task %p, resp %p\n",
		ev, resp->task, resp));
	resp->item_out = ISC_TRUE;
	isc_task_send(resp->task, (isc_event_t **)&ev);
}

isc_socket_t *
dns_dispatch_getsocket(dns_dispatch_t *disp)
{
	REQUIRE(VALID_DISPATCH(disp));

	return (disp->socket);
}

void
dns_dispatch_cancel(dns_dispatch_t *disp)
{
	REQUIRE(VALID_DISPATCH(disp));

	LOCK(&disp->lock);

	if (disp->shutting_down == 1) {
		UNLOCK(&disp->lock);
		return;
	}

	disp->shutdown_why = ISC_R_CANCELED;
	disp->shutting_down = 1;
	do_cancel(disp, NULL);

	UNLOCK(&disp->lock);

	return;
}
