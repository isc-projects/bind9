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

#include <isc/assertions.h>
#include <isc/result.h>
#include <isc/timer.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/task.h>
#include <isc/stdtime.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/message.h>
#include <dns/dispatch.h>
#include <dns/resolver.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/tsig.h>
#include <dns/view.h>

#include <dst/dst.h>

#include "../isc/util.h"		/* XXX */

#define DNS_RESOLVER_TRACE
#ifdef DNS_RESOLVER_TRACE
#define RTRACE(m)	printf("res %p: %s\n", res, (m))
#define RRTRACE(r, m)	printf("res %p: %s\n", (r), (m))
#define FCTXTRACE(m)	printf("fctx %p: %s\n", fctx, (m))
#define FTRACE(m)	printf("fetch %p (fctx %p): %s\n", \
			       fetch, fetch->private, (m))
#define QTRACE(m)	printf("query %p (res %p fctx %p): %s\n", \
			       query, query->fctx->res, query->fctx, (m))
#else
#define RTRACE(m)
#define RRTRACE(r, m)
#define FCTXTRACE(m)
#define FTRACE(m)
#define QTRACE(m)
#endif

typedef struct fetchctx fetchctx_t;

typedef struct query {
	/* Not locked. */
	unsigned int			magic;
	fetchctx_t *			fctx;
	dns_dispatch_t *		dispatch;
	/* Locked by fctx lock. */
	dns_messageid_t			id;
	dns_dispentry_t *		dispentry;	/* XXX name */
	ISC_LINK(struct query)		link;
	isc_buffer_t			buffer;
	dns_rdata_any_tsig_t		*tsig;
	dns_tsigkey_t			*tsigkey;
	unsigned char			data[512];
} resquery_t;

#define QUERY_MAGIC			0x51212121U	/* Q!!! */
#define VALID_QUERY(query)		((query) != NULL && \
					 (query)->magic == QUERY_MAGIC)

typedef enum {
	fetchstate_init = 0,
	fetchstate_active,
	fetchstate_done
} fetchstate;

struct fetchctx {
	/* Not locked. */
	unsigned int			magic;
	dns_resolver_t *		res;
	dns_name_t			name;
	dns_rdatatype_t			type;
	unsigned int			options;
	isc_task_t *			task;
	unsigned int			bucketnum;
	/* Locked by lock. */
	fetchstate			state;
	isc_boolean_t			exiting;
	unsigned int			references;
	isc_event_t			control_event;
	ISC_LINK(struct fetchctx)	link;
	ISC_LIST(dns_fetchevent_t)	events;
	/* Only changable by event actions running in the context's task */
	dns_name_t			domain;
	dns_rdataset_t			nameservers;
	isc_timer_t *			timer;
	isc_time_t			expires;
	isc_interval_t			interval;
	dns_message_t *			qmessage;
	dns_message_t *			rmessage;
	ISC_LIST(resquery_t)		queries;
	ISC_LIST(isc_sockaddr_t)	addresses;
	isc_sockaddr_t *	        address;
};

#define FCTX_MAGIC			0x46212121U	/* F!!! */
#define VALID_FCTX(fctx)		((fctx) != NULL && \
					 (fctx)->magic == FCTX_MAGIC)

struct dns_fetch {
	unsigned int			magic;
	void *				private;
};

#define DNS_FETCH_MAGIC			0x46746368U	/* Ftch */
#define DNS_FETCH_VALID(fetch)		((fetch) != NULL && \
					 (fetch)->magic == DNS_FETCH_MAGIC)

typedef struct fctxbucket {
	isc_task_t *			task;
	isc_mutex_t			lock;
	ISC_LIST(fetchctx_t)		fctxs;
	isc_boolean_t			exiting;
} fctxbucket_t;

struct dns_resolver {
	/* Unlocked */
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_mutex_t			lock;
	dns_rdataclass_t		rdclass;
	isc_socketmgr_t *		socketmgr;
	isc_timermgr_t *		timermgr;
	dns_view_t *			view;
	/* Locked by lock. */
	unsigned int			references;
	isc_boolean_t			exiting;
	isc_socket_t *			udpsocket4;
	isc_socket_t *			udpsocket6;
	dns_dispatch_t *		dispatch4;
	dns_dispatch_t *		dispatch6;
	unsigned int			nbuckets;
	unsigned int			activebuckets;
	fctxbucket_t *			buckets;
};

#define RES_MAGIC			0x52657321U	/* Res! */
#define VALID_RESOLVER(res)		((res) != NULL && \
					 (res)->magic == RES_MAGIC)


static void destroy(dns_resolver_t *res);
static void empty_bucket(dns_resolver_t *res);
static void query_response(isc_task_t *task, isc_event_t *event);

/*
 * Internal fetch routines.  Caller must be holding the proper lock.
 */

static inline isc_result_t
fctx_starttimer(fetchctx_t *fctx) {
	return (isc_timer_reset(fctx->timer, isc_timertype_once,
				&fctx->expires, &fctx->interval,
				ISC_FALSE));
}

static inline void
fctx_stoptimer(fetchctx_t *fctx) {
	isc_result_t result;

	/*
	 * We don't return a result if resetting the timer to inactive fails
	 * since there's nothing to be done about it.  Resetting to inactive
	 * should never fail anyway, since the code as currently written
	 * cannot fail in that case.
	 */
	result = isc_timer_reset(fctx->timer, isc_timertype_inactive,
				  NULL, NULL, ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_timer_reset(): %s",
				 isc_result_totext(result));
	}
}


static inline void
fctx_cancelquery(resquery_t **queryp, dns_dispatchevent_t **deventp) {
	fetchctx_t *fctx;
	resquery_t *query;

	FCTXTRACE("cancelquery");

	query = *queryp;
	fctx = query->fctx;

	/*
	 * XXXRTH  I don't think that dns_dispatch_removeresponse() will
	 *         reclaim events posted to this task.  What do we do
	 *	   about this?  Doing what we're doing now is bad, because
	 *	   we're destroying the query while there may be outstanding
	 *	   references to it.
	 */
	dns_dispatch_removeresponse(query->dispatch, &query->dispentry,
				    deventp);
	ISC_LIST_UNLINK(fctx->queries, query, link);
	query->magic = 0;
	if (query->tsig != NULL)
		dns_rdata_freestruct(query->tsig);
	isc_mem_put(fctx->res->mctx, query, sizeof *query);
	*queryp = NULL;
}

static void
fctx_cancelqueries(fetchctx_t *fctx) {
	resquery_t *query, *next_query;

	FCTXTRACE("cancelqueries");

	for (query = ISC_LIST_HEAD(fctx->queries);
	     query != NULL;
	     query = next_query) {
		next_query = ISC_LIST_NEXT(query, link);
		fctx_cancelquery(&query, NULL);
	}
}

static void
fctx_freeaddresses(fetchctx_t *fctx) {
	isc_sockaddr_t *address, *next_address;

	for (address = ISC_LIST_HEAD(fctx->addresses);
	     address != NULL;
	     address = next_address) {
		next_address = ISC_LIST_NEXT(address, link);
		isc_mem_put(fctx->res->mctx, address, sizeof *address);
	}
	fctx->address = NULL;
}

static void
fctx_done(fetchctx_t *fctx, isc_result_t result) {
	dns_fetchevent_t *event, *next_event;
	isc_task_t *task;
	dns_resolver_t *res;

	FCTXTRACE("done");

	res = fctx->res;

	fctx_freeaddresses(fctx);
	fctx_cancelqueries(fctx);
	fctx_stoptimer(fctx);

	LOCK(&res->buckets[fctx->bucketnum].lock);

	fctx->state = fetchstate_done;

	for (event = ISC_LIST_HEAD(fctx->events);
	     event != NULL;
	     event = next_event) {
		next_event = ISC_LIST_NEXT(event, link);
		task = event->sender;
		event->sender = fctx;
		if (result != ISC_R_SUCCESS)
			event->result = result;
		isc_task_sendanddetach(&task, (isc_event_t **)&event);
	}
	ISC_LIST_INIT(fctx->events);

	/*
	 * XXXRTH  check for finished state.
	 */

	UNLOCK(&res->buckets[fctx->bucketnum].lock);
}

static void
query_senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	resquery_t *query = event->arg;

	REQUIRE(event->type == ISC_SOCKEVENT_SENDDONE);

	/*
	 * XXXRTH
	 *
	 * Currently we don't wait for the senddone event before retrying
	 * a query.  This means that if we get really behind, we may end
	 * up doing extra work!
	 */

	(void)task;

	QTRACE("senddone");
	printf("query %p: sendto returned %s\n", query,
	       isc_result_totext(sevent->result));

	if (sevent->result != ISC_R_SUCCESS)
		fctx_cancelquery(&query, NULL);
				 
	isc_event_free(&event);
}

static isc_result_t
fctx_sendquery(fetchctx_t *fctx, isc_sockaddr_t *address) {
	resquery_t *query;
	isc_result_t result;
	dns_rdataset_t *qrdataset;
	dns_name_t *qname;
	isc_region_t r;
	dns_resolver_t *res;
	isc_task_t *task;

	FCTXTRACE("sendquery");

	res = fctx->res;
	task = res->buckets[fctx->bucketnum].task;

	result = fctx_starttimer(fctx);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_message_reset(fctx->rmessage, DNS_MESSAGE_INTENTPARSE);

	qname = NULL;
	result = dns_message_gettempname(fctx->qmessage, &qname);
	if (result != ISC_R_SUCCESS)
		goto cleanup_temps;
	qrdataset = NULL;
	result = dns_message_gettemprdataset(fctx->qmessage, &qrdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup_temps;

	query = isc_mem_get(res->mctx, sizeof *query);
	if (query == NULL)
		return (ISC_R_NOMEMORY);
	isc_buffer_init(&query->buffer, query->data, sizeof query->data,
			ISC_BUFFERTYPE_BINARY);
	
	/*
	 * If this is a TCP query, then we need to make a socket and
	 * a dispatch for it here.  Otherwise we use the resolver's
	 * shared dispatch.  We do not attach to the resolver's shared
	 * dispatch if we use it, so the resolver MUST ensure that no
	 * fetches are running before changing the shared dispatch.
	 */
	if ((fctx->options & DNS_FETCHOPT_TCP) != 0) {
		/* XXXRTH */
		result = DNS_R_NOTIMPLEMENTED;
		goto cleanup_query;
	} else {
		switch (isc_sockaddr_pf(address)) {
		case AF_INET:
			query->dispatch = res->dispatch4;
			break;
		case AF_INET6:
			query->dispatch = res->dispatch6;
			break;
		default:
			result = DNS_R_NOTIMPLEMENTED;
			goto cleanup_query;
		}
		/*
		 * We should always have a valid dispatcher here.  If we
		 * don't support a protocol family, then its dispatcher
		 * will be NULL, but we shouldn't be finding addresses for
		 * protocol types we don't support, so the dispatcher
		 * we found should never be NULL.
		 */
		INSIST(query->dispatch != NULL);
	}
	
	/*
	 * Get a query id from the dispatch.
	 */
	query->dispentry = NULL;
	result = dns_dispatch_addresponse(query->dispatch,
					  address,
					  task,
					  query_response,
					  query,
					  &query->id,
					  &query->dispentry);
	if (result != ISC_R_SUCCESS)
		goto cleanup_query;
	query->fctx = fctx;
	query->tsig = NULL;
	query->tsigkey = NULL;
	query->magic = QUERY_MAGIC;

	fctx->qmessage->opcode = dns_opcode_query;

	/*
	 * Set up question.
	 */
	dns_name_init(qname, NULL);
	dns_name_clone(&fctx->name, qname);
	dns_rdataset_init(qrdataset);
	dns_rdataset_makequestion(qrdataset, res->rdclass, fctx->type);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	dns_message_addname(fctx->qmessage, qname, DNS_SECTION_QUESTION);
	if ((fctx->options & DNS_FETCHOPT_RECURSIVE) != 0)
		fctx->qmessage->flags |= DNS_MESSAGEFLAG_RD;
	/*
	 * We don't have to set opcode because it defaults to query.
	 */
	fctx->qmessage->id = query->id;
	/*
	 * XXXRTH  Add TSIG and/or ENDS0 OPT record tailored to the current
	 *         recipient.
	 */

	/*
	 * Convert the question to wire format.
	 */
	result = dns_message_renderbegin(fctx->qmessage, &query->buffer);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;
	result = dns_message_rendersection(fctx->qmessage,
					   DNS_SECTION_QUESTION, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;
	result = dns_message_rendersection(fctx->qmessage,
					   DNS_SECTION_ADDITIONAL, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;
	result = dns_message_renderend(fctx->qmessage);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;

	if (fctx->qmessage->tsigkey != NULL) {
		query->tsigkey = fctx->qmessage->tsigkey;
		query->tsig = fctx->qmessage->tsig;
		fctx->qmessage->tsig = NULL;
	}

	/*
	 * We're now done with the query message.
	 */
	dns_message_reset(fctx->qmessage, DNS_MESSAGE_INTENTRENDER);

	/*
	 * Send the query!
	 */
	isc_buffer_used(&query->buffer, &r);
	result = isc_socket_sendto(dns_dispatch_getsocket(query->dispatch),
				   &r, task, query_senddone,
				   query, address);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;

	/*
	 * Finally, we've got everything going!
	 */
	ISC_LIST_APPEND(fctx->queries, query, link);

	QTRACE("sent");

	return (ISC_R_SUCCESS);

 cleanup_message:
	dns_message_reset(fctx->qmessage, DNS_MESSAGE_INTENTRENDER);

	/*
	 * Stop the dispatcher from listening.
	 */
	dns_dispatch_removeresponse(query->dispatch,
				    &query->dispentry,
				    NULL);

	/* 
	 * XXXRTH will need to cleanup a nonshared dispatch and TCP socket
	 * here.
	 */

 cleanup_query:
	query->magic = 0;
	isc_mem_put(res->mctx, query, sizeof *query);

 cleanup_temps:
	if (qname != NULL)
		dns_message_puttempname(fctx->qmessage, &qname);
	if (qrdataset != NULL)
		dns_message_puttemprdataset(fctx->qmessage, &qrdataset);

	fctx_stoptimer(fctx);

	return (result);
}

static isc_result_t
fctx_getaddresses(fetchctx_t *fctx) {
	isc_boolean_t use_hints;
	dns_rdata_t rdata;
	isc_region_t r;
	dns_name_t name;
	dns_rdataset_t rdataset;
	isc_sockaddr_t *address;
	struct in_addr ina;
	isc_result_t result;

	FCTXTRACE("getaddresses");

	/*
	 * XXXRTH  We don't try to handle forwarding yet.
	 */

	/*
	 * XXXRTH  This code is a temporary hack until we have working
	 * address code.
	 */

	ISC_LIST_INIT(fctx->addresses);
	fctx->address = NULL;

	use_hints = dns_name_equal(&fctx->domain, dns_rootname);

	INSIST(fctx->nameservers.type == dns_rdatatype_ns);
	result = dns_rdataset_first(&fctx->nameservers);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&fctx->nameservers, &rdata);
		dns_rdata_toregion(&rdata, &r);
		dns_name_init(&name, NULL);
		dns_name_fromregion(&name, &r);
		dns_rdataset_init(&rdataset);
		result = dns_view_find(fctx->res->view, &name,
				       dns_rdatatype_a, 0, DNS_DBFIND_GLUEOK,
				       use_hints, &rdataset, NULL);
		if (result == ISC_R_SUCCESS ||
		    result == DNS_R_GLUE ||
		    result == DNS_R_HINT) {
			result = dns_rdataset_first(&rdataset);
			while (result == ISC_R_SUCCESS) {
				address = isc_mem_get(fctx->res->mctx,
						      sizeof *address);
				if (address == NULL) {
					result = ISC_R_NOMEMORY;
					break;
				}
				dns_rdataset_current(&rdataset, &rdata);
				INSIST(rdata.length == 4);
				memcpy(&ina.s_addr, rdata.data, 4);
				isc_sockaddr_fromin(address, &ina, 53);
				ISC_LIST_APPEND(fctx->addresses, address,
						link);
				result = dns_rdataset_next(&rdataset);
			}
		}
		dns_rdataset_disassociate(&rdataset);
		result = dns_rdataset_next(&fctx->nameservers);
	}
	if (result == DNS_R_NOMORE)
		result = ISC_R_SUCCESS;

	return (result);
}

static void
fctx_try(fetchctx_t *fctx) {
	isc_result_t result;

	/*
	 * Caller must be holding the fetch's lock.
	 */

	FCTXTRACE("try");

	if (fctx->address != NULL)
		fctx->address = ISC_LIST_NEXT(fctx->address, link);

	if (fctx->address == NULL) {
		result = fctx_getaddresses(fctx);
		if (result != ISC_R_SUCCESS) {
			fctx_done(fctx, result);
			return;
		}
		fctx->address = ISC_LIST_HEAD(fctx->addresses);
	}

	if (fctx->address == NULL) {
		/*	
		 * XXXRTH No addresses are available...
		 */
		INSIST(0);
	}

	/*
	 * XXXRTH  This is the place where a try strategy routine would
	 *         be called to send one or more queries.  Instead, we
	 *	   just send a single query.
	 */

	result = fctx_sendquery(fctx, fctx->address);
	if (result != ISC_R_SUCCESS)
		fctx_done(fctx, result);
}

static isc_boolean_t
fctx_destroy(fetchctx_t *fctx) {
	dns_resolver_t *res;
	unsigned int bucketnum;

	/*
	 * Caller must be holding the bucket lock.
	 */

	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->state == fetchstate_done);
	REQUIRE(ISC_LIST_EMPTY(fctx->events));
	REQUIRE(ISC_LIST_EMPTY(fctx->queries));

	FCTXTRACE("destroy");

	res = fctx->res;
	bucketnum = fctx->bucketnum;

	ISC_LIST_UNLINK(res->buckets[bucketnum].fctxs, fctx, link);

	isc_timer_detach(&fctx->timer);
	dns_message_destroy(&fctx->rmessage);
	dns_message_destroy(&fctx->qmessage);
	if (dns_name_countlabels(&fctx->domain) > 0) {
		if (dns_rdataset_isassociated(&fctx->nameservers))
			dns_rdataset_disassociate(&fctx->nameservers);
		dns_name_free(&fctx->domain, res->mctx);
	}
	dns_name_free(&fctx->name, fctx->res->mctx);
	isc_mem_put(res->mctx, fctx, sizeof *fctx);

	if (res->buckets[bucketnum].exiting &&
	    ISC_LIST_EMPTY(res->buckets[bucketnum].fctxs))
		return (ISC_TRUE);

	return (ISC_FALSE);
}

/*
 * Fetch event handlers.
 */

static void
fctx_timeout(isc_task_t *task, isc_event_t *event) {
	fetchctx_t *fctx = event->arg;

	REQUIRE(VALID_FCTX(fctx));

	(void)task;	/* Keep compiler quiet. */

	FCTXTRACE("timeout");

	LOCK(&fctx->res->lock);
	REQUIRE(fctx->state == fetchstate_active);

	if (event->type == ISC_TIMEREVENT_LIFE) {
		fctx_cancelqueries(fctx);
		fctx_done(fctx, DNS_R_TIMEDOUT);
	} else {
		/*
		 * We could cancel the running queries here, or we could let
		 * them keep going.  Right now we choose the latter...
		 */
		fctx_try(fctx);
	}

	UNLOCK(&fctx->res->lock);

	isc_event_free(&event);
}

static void
fctx_shutdown(isc_task_t *task, isc_event_t *event) {
	fetchctx_t *fctx = event->arg;
	isc_boolean_t need_done = ISC_FALSE, bucket_empty = ISC_FALSE;
	dns_resolver_t *res;
	unsigned int bucketnum;

	REQUIRE(VALID_FCTX(fctx));

	res = fctx->res;
	bucketnum = fctx->bucketnum;
	(void)task;	/* Keep compiler quiet. */
	
	FCTXTRACE("shutdown");

	LOCK(&res->buckets[bucketnum].lock);
	
	INSIST(fctx->state == fetchstate_active ||
	       fctx->state == fetchstate_done);
	INSIST(fctx->exiting);

	if (fctx->state == fetchstate_done) {
		if (fctx->references == 0)
			bucket_empty = fctx_destroy(fctx);
	} else
		need_done = ISC_TRUE;

	UNLOCK(&res->buckets[bucketnum].lock);

	if (need_done)
		fctx_done(fctx, ISC_R_CANCELED);
	else if (bucket_empty)
		empty_bucket(res);
}

static void
fctx_start(isc_task_t *task, isc_event_t *event) {
	fetchctx_t *fctx = event->arg;
	isc_boolean_t done = ISC_FALSE, bucket_empty = ISC_FALSE;
	dns_resolver_t *res;
	unsigned int bucketnum;

	REQUIRE(VALID_FCTX(fctx));

	res = fctx->res;
	bucketnum = fctx->bucketnum;
	(void)task;	/* Keep compiler quiet. */

	FCTXTRACE("start");

	LOCK(&res->buckets[bucketnum].lock);

	INSIST(fctx->state == fetchstate_init);
	if (fctx->exiting) {
		/*
		 * We haven't started this fctx yet, and we've been requested
		 * to shut it down.
		 *
		 * The events list should be empty, so we INSIST on it.
		 */
		INSIST(ISC_LIST_EMPTY(fctx->events));
		bucket_empty = fctx_destroy(fctx);
		done = ISC_TRUE;
	} else {
		/*
		 * Normal fctx startup.
		 */
		fctx->state = fetchstate_active;
		/*
		 * Reset the control event for later use in shutting down
		 * the fctx.
		 */
		ISC_EVENT_INIT(event, sizeof *event, 0, NULL,
			       DNS_EVENT_FETCHCONTROL, fctx_shutdown, fctx,
			       (void *)fctx_shutdown, NULL, NULL);
	}

	UNLOCK(&res->buckets[bucketnum].lock);

	if (!done) {
		/*
		 * All is well.  Start working on the fetch.
		 */
		fctx_try(fctx);
	} else if (bucket_empty)
		empty_bucket(res);
}

/*
 * Fetch Creation, Joining, and Cancelation.
 */

static inline isc_result_t
fctx_join(fetchctx_t *fctx, isc_task_t *task, isc_taskaction_t action,
	  void *arg, dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
	  dns_fetch_t *fetch)
{
	isc_task_t *clone;
	dns_fetchevent_t *event;

	FCTXTRACE("join");

	/*
	 * We store the task we're going to send this event to in the
	 * sender field.  We'll make the fetch the sender when we actually
	 * send the event.
	 */
	clone = NULL;
	isc_task_attach(task, &clone);
	event = (dns_fetchevent_t *)
		isc_event_allocate(fctx->res->mctx, clone,
				   DNS_EVENT_FETCHDONE,
				   action, arg, sizeof *event);
	if (event == NULL)
		return (ISC_R_NOMEMORY);
	event->result = DNS_R_SERVFAIL;
	event->qtype = fctx->type;
	event->db = NULL;
	event->node = NULL;
	event->rdataset = rdataset;
	event->sigrdataset = sigrdataset;
	event->tag = fetch;
	dns_fixedname_init(&event->foundname);
	ISC_LIST_APPEND(fctx->events, event, link);

	fctx->references++;

	fetch->magic = DNS_FETCH_MAGIC;
	fetch->private = fctx;
	
	return (ISC_R_SUCCESS);
}

static isc_result_t
fctx_create(dns_resolver_t *res, dns_name_t *name, dns_rdatatype_t type,
	    dns_name_t *domain, dns_rdataset_t *nameservers,
	    unsigned int options, unsigned int bucketnum, fetchctx_t **fctxp)
{
	fetchctx_t *fctx;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t iresult;
	isc_interval_t interval;

	/*
	 * Caller must be holding the lock for bucket number 'bucketnum'.
	 */
	REQUIRE(fctxp != NULL && *fctxp == NULL);

	fctx = isc_mem_get(res->mctx, sizeof *fctx);
	if (fctx == NULL)
		return (ISC_R_NOMEMORY);
	FCTXTRACE("create");
	dns_name_init(&fctx->name, NULL);
	result = dns_name_dup(name, res->mctx, &fctx->name);
	if (result != ISC_R_SUCCESS)
		goto cleanup_fetch;
	dns_name_init(&fctx->domain, NULL);
	dns_rdataset_init(&fctx->nameservers);
	if (domain != NULL) {
		result = dns_name_dup(domain, res->mctx, &fctx->domain);
		if (result != ISC_R_SUCCESS)
			goto cleanup_name;
		dns_rdataset_clone(nameservers, &fctx->nameservers);
	}
	fctx->type = type;
	fctx->options = options;
	/*
	 * Note!  We do not attach to the task.  We are relying on the
	 * resolver to ensure that this task doesn't go away while we are
	 * using it.
	 */
	fctx->res = res;
	fctx->references = 0;
	fctx->bucketnum = bucketnum;
	fctx->state = fetchstate_init;
	fctx->exiting = ISC_FALSE;
	ISC_LIST_INIT(fctx->queries);
	ISC_LIST_INIT(fctx->addresses);
	fctx->address = NULL;

	fctx->qmessage = NULL;
	result = dns_message_create(res->mctx, DNS_MESSAGE_INTENTRENDER,
				    &fctx->qmessage);
				    
	if (result != ISC_R_SUCCESS)
		goto cleanup_domain;

	fctx->rmessage = NULL;
	result = dns_message_create(res->mctx, DNS_MESSAGE_INTENTPARSE,
				    &fctx->rmessage);
				    
	if (result != ISC_R_SUCCESS)
		goto cleanup_qmessage;

	/*
	 * Compute an expiration time for the entire fetch.
	 */
	isc_interval_set(&interval, 10, 0);		/* XXXRTH constant */
	iresult = isc_time_nowplusinterval(&fctx->expires, &interval);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_time_nowplusinterval: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_rmessage;
	}

	/*
	 * XXX Retry interval initialization.  Should be setup by the
	 * transmission strategy routine (when we have one).
	 */
	isc_interval_set(&fctx->interval, 1, 500000000);

	/*
	 * Create an inactive timer.  It will be made active when the fetch
	 * is actually started.
	 */
	fctx->timer = NULL;
	iresult = isc_timer_create(res->timermgr, isc_timertype_inactive,
				   NULL, NULL,
				   res->buckets[bucketnum].task, fctx_timeout,
				   fctx, &fctx->timer);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_timer_create: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_rmessage;
	}

	ISC_LIST_INIT(fctx->events);
	ISC_LINK_INIT(fctx, link);
	fctx->magic = FCTX_MAGIC;

	ISC_LIST_APPEND(res->buckets[bucketnum].fctxs, fctx, link);

	*fctxp = fctx;

	return (ISC_R_SUCCESS);

 cleanup_rmessage:
	dns_message_destroy(&fctx->rmessage);

 cleanup_qmessage:
	dns_message_destroy(&fctx->qmessage);

 cleanup_domain:
	if (dns_name_countlabels(&fctx->domain) > 0) {
		dns_rdataset_disassociate(&fctx->nameservers);
		dns_name_free(&fctx->domain, res->mctx);
	}

 cleanup_name:
	dns_name_free(&fctx->name, res->mctx);

 cleanup_fetch:
	isc_mem_put(res->mctx, fctx, sizeof *fctx);

	return (result);
}

/*
 * XXXRTH  Cleanup
 */
#ifdef obsolete
static void
fctx_cancel(fetchctx_t *fctx) {
	isc_result_t iresult;

	FCTXTRACE("cancel");

	if (fctx->state != fetchstate_done) {
		fctx_cancelqueries(fctx);

		iresult = isc_timer_reset(fctx->timer, isc_timertype_inactive,
					  NULL, NULL, ISC_TRUE);
		if (iresult != ISC_R_SUCCESS)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_timer_reset(): %s",
					 isc_result_totext(iresult));
		fctx_done(fctx, DNS_R_CANCELED);
	}
}
#endif

/*
 * Handle Responses
 */

static inline isc_result_t
same_question(fetchctx_t *fctx) {
	isc_result_t result;
	dns_message_t *message = fctx->rmessage;
	dns_name_t *name;
	dns_rdataset_t *rdataset;

	/*
	 * Caller must be holding the fctx lock.
	 */

	/*
	 * XXXRTH  Currently we support only one question.
	 */
	if (message->counts[DNS_SECTION_QUESTION] != 1)
		return (DNS_R_FORMERR);

	result = dns_message_firstname(message, DNS_SECTION_QUESTION);
	if (result != ISC_R_SUCCESS)
		return (result);
	name = NULL;
	dns_message_currentname(message, DNS_SECTION_QUESTION, &name);
	rdataset = ISC_LIST_HEAD(name->list);
	INSIST(rdataset != NULL);
	INSIST(ISC_LIST_NEXT(rdataset, link) == NULL);
	if (fctx->type != rdataset->type ||
	    fctx->res->rdclass != rdataset->rdclass ||
	    !dns_name_equal(&fctx->name, name))
		return (DNS_R_FORMERR);
	
	return (ISC_R_SUCCESS);
}

#define CACHE(r)	(((r)->attributes & DNS_RDATASETATTR_CACHE) != 0)
#define ANSWER(r)	(((r)->attributes & DNS_RDATASETATTR_ANSWER) != 0)
#define ANSWERSIG(r)	(((r)->attributes & DNS_RDATASETATTR_ANSWERSIG) != 0)
#define EXTERNAL(r)	(((r)->attributes & DNS_RDATASETATTR_EXTERNAL) != 0)

static inline isc_result_t
cache_name(fetchctx_t *fctx, dns_name_t *name, isc_stdtime_t now) {
	dns_rdataset_t *rdataset, *addedrdataset, *ardataset, *asigrdataset;
	dns_dbnode_t *node, **anodep;
	dns_db_t **adbp;
	dns_fixedname_t foundname;
	dns_name_t *fname, *aname;
	dns_resolver_t *res;
	void *data;
	isc_boolean_t need_validation;
	isc_result_t result;
	dns_fetchevent_t *event;

	/*
	 * The appropriate bucket lock must be held.
	 */

	res = fctx->res;
	need_validation = ISC_FALSE;

	/*
	 * Is DNSSEC validation required for this name?
	 */
	dns_fixedname_init(&foundname);
	fname = dns_fixedname_name(&foundname);
	data = NULL;
	result = dns_rbt_findname(res->view->secroots, name, fname, &data);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		/*
		 * This name is at or below one of the view's security roots,
		 * so DNSSEC validation is required.
		 */
		need_validation = ISC_TRUE;
	} else if (result != ISC_R_NOTFOUND) {
		/*
		 * Something bad happened.
		 */
		return (result);
	}

	adbp = NULL;
	aname = NULL;
	anodep = NULL;
	ardataset = NULL;
	asigrdataset = NULL;
	if ((name->attributes & DNS_NAMEATTR_ANSWER) != 0) {
		event = ISC_LIST_HEAD(fctx->events);
		if (event != NULL) {
			adbp = &event->db;
			aname = dns_fixedname_name(&event->foundname);
			result = dns_name_concatenate(name, NULL, aname, NULL);
			if (result != ISC_R_SUCCESS)
				return (result);
			anodep = &event->node;
			if (fctx->type != dns_rdatatype_any &&
			    fctx->type != dns_rdatatype_sig) {
				ardataset = event->rdataset;
				asigrdataset = event->sigrdataset;
			}
		}
	}

	/*
	 * Find or create the cache node.
	 */
	node = NULL;
	result = dns_db_findnode(res->view->cachedb,
				 name, ISC_TRUE,
				 &node);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Cache or validate each cacheable rdataset.
	 */
	for (rdataset = ISC_LIST_HEAD(name->list);
	     rdataset != NULL;
	     rdataset = ISC_LIST_NEXT(rdataset, link)) {
		if (!CACHE(rdataset))
			continue;
		if (need_validation) {
			INSIST(0);
		} else if (!EXTERNAL(rdataset)) {
			/*
			 * It's OK to cache this rdataset now.
			 */
			if (ANSWER(rdataset))
				addedrdataset = ardataset;
			else
				addedrdataset = NULL;
			result = dns_db_addrdataset(res->view->cachedb,
						    node, NULL, now,
						    rdataset,
						    ISC_FALSE,
						    addedrdataset);
			if (result != ISC_R_SUCCESS)
				break;
		}
	}

	if (result == ISC_R_SUCCESS) {
		if (adbp != NULL) {
			dns_db_attach(res->view->cachedb, adbp);
			*anodep = node;
		}
		/*
		 * XXXRTH  clone rdatasets to other events.
		 */
	} else
		dns_db_detachnode(res->view->cachedb, &node);

	return (result);
}

static inline isc_result_t
cache_message(fetchctx_t *fctx) {
	isc_result_t result;
	dns_section_t section;
	dns_name_t *name;
	isc_stdtime_t now;

	result = isc_stdtime_get(&now);
	if (result != ISC_R_SUCCESS)
		return (result);

	LOCK(&fctx->res->buckets[fctx->bucketnum].lock);

	for (section = DNS_SECTION_ANSWER;
	     section <= DNS_SECTION_ADDITIONAL;
	     section++) {
		result = dns_message_firstname(fctx->rmessage, section);
		while (result == ISC_R_SUCCESS) {
			name = NULL;
			dns_message_currentname(fctx->rmessage, section,
						&name);
			if ((name->attributes & DNS_NAMEATTR_CACHE) != 0) {
				result = cache_name(fctx, name, now);
				if (result != ISC_R_SUCCESS)
					break;
			}
			result = dns_message_nextname(fctx->rmessage, section);
		}
		if (result != ISC_R_NOMORE)
			break;
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

	UNLOCK(&fctx->res->buckets[fctx->bucketnum].lock);

	return (result);
}

static inline void
mark_related(dns_name_t *name, dns_rdataset_t *rdataset,
	     isc_boolean_t external)
{
	name->attributes |= DNS_NAMEATTR_CACHE;
	rdataset->trust = dns_trust_additional;
	rdataset->attributes |= DNS_RDATASETATTR_CACHE;
	if (external)
		rdataset->attributes |= DNS_RDATASETATTR_EXTERNAL;
}

static isc_result_t
check_related(void *arg, dns_name_t *addname, dns_rdatatype_t type) {
	fetchctx_t *fctx = arg;
	isc_result_t result;
	dns_name_t *name;
	dns_rdataset_t *rdataset;
	isc_boolean_t external;
	dns_rdatatype_t rtype;

	REQUIRE(VALID_FCTX(fctx));

	name = NULL;
	rdataset = NULL;
	result = dns_message_findname(fctx->rmessage, DNS_SECTION_ADDITIONAL,
				      addname, dns_rdatatype_any, 0, &name,
				      NULL);
	if (result == ISC_R_SUCCESS) {
		external = !dns_name_issubdomain(name, &fctx->domain);
		if (type == dns_rdatatype_a) {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				if (rdataset->type == dns_rdatatype_sig)
					rtype = rdataset->covers;
				else
					rtype = rdataset->type;
				if (rtype == dns_rdatatype_a ||
				    rtype == dns_rdatatype_aaaa ||
				    rtype == dns_rdatatype_a6)
					mark_related(name, rdataset, external);
				/*
				 * XXXRTH  Need to do a controlled recursion
				 *	   on the A6 prefix names to mark
				 *	   any additional data related to them.
				 *
				 *	   Ick.
				 */
			}
		} else {
			result = dns_message_findtype(name, type, 0,
						      &rdataset);
			if (result == ISC_R_SUCCESS) {
				mark_related(name, rdataset, external);
				/*
				 * Do we have its SIG too?
				 */
				result = dns_message_findtype(name,
						      dns_rdatatype_sig,
						      type, &rdataset);
				if (result == ISC_R_SUCCESS)
					mark_related(name, rdataset, external);
			}
		}
		/*
		 * XXXRTH  Some other stuff still needs to be marked.
		 *         See query.c.
		 */
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
answer_response(fetchctx_t *fctx) {
	isc_result_t result;
	dns_message_t *message;
	dns_name_t *name, *qname;
	dns_rdataset_t *rdataset;
	isc_boolean_t done, external, chaining, aa, found;
	unsigned int aflag;

	message = fctx->rmessage;

	/*
	 * Examine the answer section, marking those rdatasets which are
	 * part of the answer and should be cached.
	 */

	done = ISC_FALSE;
	chaining = ISC_FALSE;
	if ((message->flags & DNS_MESSAGEFLAG_AA) != 0)
		aa = ISC_TRUE;
	else
		aa = ISC_FALSE;
	qname = &fctx->name;
	result = dns_message_firstname(message, DNS_SECTION_ANSWER);
	while (!done && result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_ANSWER, &name);
		external = !dns_name_issubdomain(name, &fctx->domain);
		if (dns_name_equal(name, qname)) {

			/*
			 * XXXRTH  CNAME check.
			 */
#if 0
			if (cname) {
				qname = name;
				chaining = ISC_TRUE;
			}
#endif

			aflag = 0;
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				found = ISC_FALSE;
				if (rdataset->type == fctx->type ||
				    fctx->type == dns_rdatatype_any) {
					/*
					 * We've found an ordinary answer.
					 */
					found = ISC_TRUE;
					done = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWER;
				} else if (rdataset->type == dns_rdatatype_sig
					   && rdataset->covers == fctx->type) {
					/*
					 * We've found a signature that
					 * covers the type we're looking for.
					 */
					found = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWERSIG;
				}

				if (found) {
					/*
					 * We've found an answer to our
					 * question.
					 */
					name->attributes |=
						DNS_NAMEATTR_CACHE;
					rdataset->attributes |=
						DNS_RDATASETATTR_CACHE;
					rdataset->trust = dns_trust_answer;
					if (!chaining) {
						/*
						 * This data is "the" answer
						 * to our question only if
						 * we're not chaining (i.e.
						 * if we haven't followed
						 * a CNAME or DNAME).
						 */
						INSIST(!external);
						name->attributes |=
							DNS_NAMEATTR_ANSWER;
						rdataset->attributes |= aflag;
						if (aa)
							rdataset->trust =
							  dns_trust_authanswer;
					} else if (external) {
						/*
						 * This data is outside of
						 * our query domain, and
						 * may only be cached if it
						 * comes from a secure zone
						 * and validates.
						 */
						rdataset->attributes |=
						    DNS_RDATASETATTR_EXTERNAL;
					}

					/*
					 * Mark any additional data related
					 * to this rdataset.
					 */
					(void)dns_rdataset_additionaldata(
							rdataset,
							check_related,
							fctx);
					/*
					 * A6 special cases...
					 */
					if (rdataset->type ==
					    dns_rdatatype_a6) {
						check_related(fctx, name,
						      dns_rdatatype_a);
						check_related(fctx, name,
						      dns_rdatatype_aaaa);
					}
				}
				/*
				 * We could add an "else" clause here and
				 * log that we're ignoring this rdataset.
				 */
			}
		} else {
			/*
			 * Either this is a DNAME or we've got junk.
			 */
		}
		result = dns_message_nextname(message, DNS_SECTION_ANSWER);
	}
	if (result != ISC_R_NOMORE)
		return (result);

	/*
	 * Examine the authority section (if there is one).
	 *
	 * We expect there to be only one owner name for all the rdatasets
	 * in this section, and we expect that it is not external.
	 */

	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (!done && result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &name);
		external = !dns_name_issubdomain(name, &fctx->domain);
		if (!external) {
			/*
			 * We expect to find NS or SIG NS rdatasets, and
			 * nothing else.
			 */
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				if (rdataset->type == dns_rdatatype_ns ||
				    (rdataset->type == dns_rdatatype_sig &&
				     rdataset->covers == dns_rdatatype_ns)) {
					rdataset->attributes |=
						DNS_RDATASETATTR_CACHE;
					if (aa)
						rdataset->trust =
						    dns_trust_authauthority;
					else
						rdataset->trust =
						    dns_trust_additional;

					/*
					 * Mark any additional data related
					 * to this rdataset.
					 */
					(void)dns_rdataset_additionaldata(
							rdataset,
							check_related,
							fctx);
				}
			}
			/*
			 * Since we've found a non-external name in the
			 * authority section, we should stop looking, even
			 * if we didn't find any NS or SIG NS.
			 */
			done = ISC_TRUE;
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
	}
	if (result != ISC_R_NOMORE)
		return (result);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
noanswer_response(fetchctx_t *fctx) {
	isc_result_t result;
	dns_message_t *message;
	dns_name_t *name, *qname, *ns_name, *soa_name;
	dns_rdataset_t *rdataset;
	isc_boolean_t done, external, aa, negative_response;
	dns_rdatatype_t type;

	message = fctx->rmessage;
	negative_response = ISC_FALSE;

	/*
	 * We have to figure out if this is a negative response, or a
	 * referral.  We start by examining the rcode.
	 */
	if (message->rcode == dns_rcode_nxdomain)
		negative_response = ISC_TRUE;

	if ((message->flags & DNS_MESSAGEFLAG_AA) != 0)
		aa = ISC_TRUE;
	else
		aa = ISC_FALSE;
	qname = &fctx->name;

	if (message->counts[DNS_SECTION_ANSWER] != 0) {
		INSIST(0);
		if (!negative_response)
			return (DNS_R_FORMERR);
		done = ISC_FALSE;
		result = dns_message_firstname(message, DNS_SECTION_ANSWER);
		while (!done && result == ISC_R_SUCCESS) {
			name = NULL;
			dns_message_currentname(message, DNS_SECTION_ANSWER,
						&name);
			external = !dns_name_issubdomain(name, &fctx->domain);
			/*
			 * The only valid records are CNAME, DNAME, and
			 * their corresponding sigs.
			 */
			if (dns_name_equal(name, qname)) {
				/*
				 * XXXRTH  CNAME check.
				 */
			} else {
				/*
				 * XXXRTH  DNAME check.
				 */
			}
			result = dns_message_nextname(message,
						      DNS_SECTION_ANSWER);
		}
		if (result != ISC_R_NOMORE)
			return (result);
	}

	done = ISC_FALSE;
	ns_name = NULL;
	soa_name = NULL;
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (!done && result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &name);
		if (dns_name_issubdomain(name, &fctx->domain)) {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				type = rdataset->type;
				if (type == dns_rdatatype_sig)
					type = rdataset->covers;
				if (rdataset->type == dns_rdatatype_ns) {
					/*
					 * NS or SIG NS.
					 *
					 * Only one set of NS RRs is allowed.
					 */
					if (ns_name != NULL && name != ns_name)
						return (DNS_R_FORMERR);
					ns_name = name;
					name->attributes |=
						DNS_NAMEATTR_CACHE;
					rdataset->attributes |=
						DNS_RDATASETATTR_CACHE;
					/*
					 * XXXRTH  Should really use a lower
					 * level and then look for it in
					 * query.c.  We don't want to return
					 * glue we've cached as an answer.
					 */
					rdataset->trust = dns_trust_additional;
					/*
					 * Mark any additional data related
					 * to this rdataset.
					 */
					(void)dns_rdataset_additionaldata(
							rdataset,
							check_related,
							fctx);
				} else if (rdataset->type ==
					   dns_rdatatype_soa ||
					   rdataset->type ==
					   dns_rdatatype_nxt) {
					/*
					 * SOA, SIG SOA, NXT, or SIG NXT.
					 *
					 * Only one SOA is allowed.
					 */
					if (soa_name != NULL &&
					    name != soa_name)
						return (DNS_R_FORMERR);
					soa_name = name;
					negative_response = ISC_TRUE;
					name->attributes |=
						DNS_NAMEATTR_NCACHE;
					rdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					if (aa)
						rdataset->trust =
						    dns_trust_authauthority;
					else
						rdataset->trust =
							dns_trust_additional;
					/*
					 * No additional data needs to be
					 * marked.
					 */
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result != ISC_R_NOMORE)
			return (result);
	}

	/*
	 * If we found nothing, this responder is insane.
	 */
	if (!negative_response && ns_name == NULL)
		return (DNS_R_FORMERR);

	/*
	 * If we found both NS and SOA, they should be the same name.
	 */
	if (ns_name != NULL && soa_name != NULL) {
		if (ns_name != soa_name)
			return (DNS_R_FORMERR);
		/*
		 * Don't cache the NS RRs.
		 */
		ns_name->attributes &= ~DNS_NAMEATTR_CACHE;
	}

	/*
	 * A negative response without an SOA isn't useful.
	 *
	 * XXXRTH  This is probably not right...
	 */
	if (negative_response && soa_name == NULL)
		return (DNS_R_FORMERR);

	/*
	 * Do we have a referral?
	 */
	if (!negative_response && ns_name != NULL) {
		/*
		 * Set the current query domain to the referral name.
		 */
		INSIST(dns_name_countlabels(&fctx->domain) > 0);
		dns_name_free(&fctx->domain, fctx->res->mctx);
		dns_rdataset_disassociate(&fctx->nameservers);
		dns_name_init(&fctx->domain, NULL);
		result = dns_name_dup(ns_name, fctx->res->mctx, &fctx->domain);
		if (result != ISC_R_SUCCESS)
			return (result);
		return (DNS_R_DELEGATION);
	}

	return (ISC_R_SUCCESS);
}

static void
query_response(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	resquery_t *query = event->arg;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	isc_boolean_t keep_trying, broken_server, get_nameservers;
	dns_message_t *message;
	fetchctx_t *fctx;

	REQUIRE(VALID_QUERY(query));
	fctx = query->fctx;
	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(event->type == DNS_EVENT_DISPATCH);

	(void)task;
	QTRACE("response");

	keep_trying = ISC_FALSE;
	broken_server = ISC_FALSE;
	get_nameservers = ISC_FALSE;

	LOCK(&fctx->res->lock);
	INSIST(fctx->state == fetchstate_active);

	message = fctx->rmessage;
	message->querytsig = query->tsig;
	message->tsigkey = query->tsigkey;
	result = dns_message_parse(message, &devent->buffer, ISC_FALSE);
	if (result != ISC_R_SUCCESS) {
		switch (result) {
		case DNS_R_FORMERR:
		case DNS_R_UNEXPECTEDEND:
			broken_server = ISC_TRUE;
			keep_trying = ISC_TRUE;
			break;
		case DNS_R_MOREDATA:
			result = DNS_R_NOTIMPLEMENTED;
			break;
		}
		goto done;
	}

	INSIST((message->flags & DNS_MESSAGEFLAG_QR) != 0);
	/*
	 * INSIST() that the message comes from the place we sent it to,
	 * since the dispatch code should ensure this.
	 *
	 * INSIST() that the message id is correct (this should also be	
	 * ensured by the dispatch code).
	 */

	/*
	 * Is it a query response?
	 */
	if (message->opcode != dns_opcode_query) {
		/* XXXRTH Log */
		broken_server = ISC_TRUE;
		keep_trying = ISC_TRUE;
		goto done;
	}

	/*
	 * Is the remote server broken, or does it dislike us?
	 */
	if (message->rcode != dns_rcode_noerror &&
	    message->rcode != dns_rcode_nxdomain) {
		broken_server = ISC_TRUE;
		keep_trying = ISC_TRUE;
		/*
		 * XXXRTH If we want to catch a FORMERR caused by an EDNS0
		 *        OPT RR, this is the place to do it.
		 */
		goto done;
	}

	/*
	 * Is the question the same as the one we asked?
	 */
	result = same_question(fctx);
	if (result != ISC_R_SUCCESS) {
		/* XXXRTH Log */
		if (result == DNS_R_FORMERR) {
			broken_server = ISC_TRUE;
			keep_trying = ISC_TRUE;
		}
		goto done;
	}

	/*
	 * Did we get any answers?
	 */
	if (message->counts[DNS_SECTION_ANSWER] > 0 &&
	    message->rcode == dns_rcode_noerror) {
		/*
		 * We've got answers.
		 */
		result = answer_response(fctx);
		if (result != ISC_R_SUCCESS) {
			if (result == DNS_R_FORMERR)
				broken_server = ISC_TRUE;
			keep_trying = ISC_TRUE;
			goto done;
		}
	} else if (message->counts[DNS_SECTION_AUTHORITY] > 0 ||
		   message->rcode == dns_rcode_nxdomain) {
		/*
		 * NXDOMAIN, NXRDATASET, or referral.
		 */
		result = noanswer_response(fctx);
		if (result == DNS_R_DELEGATION) {
			/*
			 * We don't have the answer, but we know a better
			 * place to look.
			 */
			get_nameservers = ISC_TRUE;
			keep_trying = ISC_TRUE;
		} else if (result != ISC_R_SUCCESS) {
			if (result == DNS_R_FORMERR)
				broken_server = ISC_TRUE;
			keep_trying = ISC_TRUE;
			goto done;
		}
	} else {
		/*
		 * The server is insane.
		 */
		/* XXXRTH Log */
		broken_server = ISC_TRUE;
		keep_trying = ISC_TRUE;
		goto done;
	}

	query->tsig = NULL;
	fctx_stoptimer(fctx);
	fctx_cancelquery(&query, &devent);

	result = cache_message(fctx);

 done:
	/*
	 * XXXRTH  Record round-trip statistics here.
	 */
	if (keep_trying) {
		if (broken_server) {
			/*
			 * XXXRTH  We will mark the sender as bad here instead
			 *         of doing the printf().
			 */
			printf("broken sender\n");
		}
		if (query != NULL) {
			INSIST(devent != NULL);
			dns_dispatch_freeevent(query->dispatch,
					       query->dispentry,
					       &devent);
		}

		/*
		 * Do we need to find the best nameservers for this fetch?
		 */
		if (get_nameservers) {
			result = dns_view_find(fctx->res->view, &fctx->domain,
					       dns_rdatatype_ns, 0, 0,
					       ISC_FALSE, &fctx->nameservers,
					       NULL);
			if (result != ISC_R_SUCCESS)
				fctx_done(fctx, DNS_R_SERVFAIL);
			fctx_freeaddresses(fctx);
		}					  

		/*
		 * Try again.
		 */
		fctx_try(fctx);
	} else {
		/*
		 * All is well, or we got an error fatal to the fetch.
		 * In either case, we're done.
		 */
		fctx_done(fctx, result);
	}

	UNLOCK(&fctx->res->lock);
}


/***
 *** Resolver Methods
 ***/

static void
destroy(dns_resolver_t *res) {
	unsigned int i;

	REQUIRE(res->references == 0);

	RTRACE("destroy");

	isc_mutex_destroy(&res->lock);
	for (i = 0; i < res->nbuckets; i++) {
		INSIST(ISC_LIST_EMPTY(res->buckets[i].fctxs));
		isc_task_shutdown(res->buckets[i].task);
		isc_task_detach(&res->buckets[i].task);
		isc_mutex_destroy(&res->buckets[i].lock);
	}
	isc_mem_put(res->mctx, res->buckets,
		    res->nbuckets * sizeof (fctxbucket_t));
	if (res->dispatch4 != NULL)
		dns_dispatch_detach(&res->dispatch4);
	if (res->udpsocket4 != NULL)
		isc_socket_detach(&res->udpsocket4);
	if (res->dispatch6 != NULL)
		dns_dispatch_detach(&res->dispatch6);
	if (res->udpsocket6 != NULL)
		isc_socket_detach(&res->udpsocket6);
	res->magic = 0;
	isc_mem_put(res->mctx, res, sizeof *res);
}

static void
empty_bucket(dns_resolver_t *res) {
	isc_boolean_t need_destroy = ISC_FALSE;

	RTRACE("empty_bucket");

	LOCK(&res->lock);

	INSIST(res->activebuckets > 0);
	res->activebuckets--;
	if (res->activebuckets == 0)
		need_destroy = ISC_TRUE;

	UNLOCK(&res->lock);

	if (need_destroy)
		destroy(res);
}

isc_result_t
dns_resolver_create(dns_view_t *view,
		    isc_taskmgr_t *taskmgr, unsigned int ntasks,
		    isc_socketmgr_t *socketmgr,
		    isc_timermgr_t *timermgr,
		    dns_dispatch_t *dispatch, dns_resolver_t **resp)
{
	dns_resolver_t *res;
	isc_result_t result = ISC_R_SUCCESS;
	unsigned int i, buckets_created = 0;

	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(ntasks > 0);

	res = isc_mem_get(view->mctx, sizeof *res);
	if (res == NULL)
		return (ISC_R_NOMEMORY);
	RTRACE("create");
	res->mctx = view->mctx;
	res->rdclass = view->rdclass;
	res->socketmgr = socketmgr;
	res->timermgr = timermgr;
	res->view = view;

	res->nbuckets = ntasks;
	res->activebuckets = ntasks;
	res->buckets = isc_mem_get(view->mctx,
				   ntasks * sizeof (fctxbucket_t));
	if (res->buckets == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_res;
	}
	for (i = 0; i < ntasks; i++) {
		result = isc_mutex_init(&res->buckets[i].lock);
		if (result != ISC_R_SUCCESS)
			goto cleanup_buckets;
		res->buckets[i].task = NULL;
		result = isc_task_create(taskmgr, view->mctx, 0,
					  &res->buckets[i].task);
		if (result != ISC_R_SUCCESS) {
			isc_mutex_destroy(&res->buckets[i].lock);
			goto cleanup_buckets;
		}
		ISC_LIST_INIT(res->buckets[i].fctxs);
		res->buckets[i].exiting = ISC_FALSE;
		buckets_created++;
	}

	/*
	 * IPv4 Dispatcher.
	 */
	res->dispatch4 = NULL;
	res->udpsocket4 = NULL;
	if (dispatch != NULL) {
		dns_dispatch_attach(dispatch, &res->dispatch4);
	} else if (isc_net_probeipv4() == ISC_R_SUCCESS) {
		struct in_addr ina;
		isc_sockaddr_t sa;

		/*
		 * Create an IPv4 UDP socket and a dispatcher for it.
		 */
		result = isc_socket_create(socketmgr, AF_INET,
					   isc_sockettype_udp,
					   &res->udpsocket4);
		if (result != ISC_R_SUCCESS)
			goto cleanup_buckets;
		/*
		 * XXXRTH  Temporarily bind() to 5353 to make things
		 *	   easier for Bob's firewalls.
		 */
		ina.s_addr = htonl(INADDR_ANY);
		isc_sockaddr_fromin(&sa, &ina, 5353);
		result = isc_socket_bind(res->udpsocket4, &sa);
		if (result != ISC_R_SUCCESS)
			goto cleanup_buckets;
		result = dns_dispatch_create(res->mctx, res->udpsocket4,
					     res->buckets[0].task, 4096,
					     50, 50, 14, &res->dispatch4);
		if (result != ISC_R_SUCCESS)
			goto cleanup_udpsocket4;
	}

	/*
	 * IPv6 Dispatcher.
	 */
	res->dispatch6 = NULL;
	res->udpsocket6 = NULL;
	if (isc_net_probeipv6() == ISC_R_SUCCESS) {
		/*
		 * Create an IPv6 UDP socket and a dispatcher for it.
		 */
		result = isc_socket_create(socketmgr, AF_INET,
					   isc_sockettype_udp,
					   &res->udpsocket6);
		if (result != ISC_R_SUCCESS)
			goto cleanup_dispatch4;
		result = dns_dispatch_create(res->mctx, res->udpsocket6,
					     res->buckets[0].task, 4096, 
					     50, 50, 14, &res->dispatch6);
		if (result != ISC_R_SUCCESS)
			goto cleanup_udpsocket6;
	}
	
	res->references = 1;
	res->exiting = ISC_FALSE;

	result = isc_mutex_init(&res->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_dispatch6;

	res->magic = RES_MAGIC;
	
	*resp = res;

	return (ISC_R_SUCCESS);

 cleanup_dispatch6:
	if (res->dispatch6 != NULL)
		dns_dispatch_detach(&res->dispatch6);

 cleanup_udpsocket6:
	if (res->udpsocket6 != NULL)
		isc_socket_detach(&res->udpsocket6);

 cleanup_dispatch4:
	if (res->dispatch4 != NULL)
		dns_dispatch_detach(&res->dispatch4);

 cleanup_udpsocket4:
	if (res->udpsocket4 != NULL)
		isc_socket_detach(&res->udpsocket4);

 cleanup_buckets:
	for (i = 0; i < buckets_created; i++) {
		(void)isc_mutex_destroy(&res->buckets[i].lock);
		isc_task_shutdown(res->buckets[i].task);
		isc_task_detach(&res->buckets[i].task);
	}
	isc_mem_put(view->mctx, res->buckets,
		    res->nbuckets * sizeof (fctxbucket_t));

 cleanup_res:
	isc_mem_put(view->mctx, res, sizeof *res);

	return (result);
}

void
dns_resolver_attach(dns_resolver_t *source, dns_resolver_t **targetp) {
	REQUIRE(VALID_RESOLVER(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	RRTRACE(source, "attach");
	LOCK(&source->lock);
	REQUIRE(!source->exiting);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);
	UNLOCK(&source->lock);

	*targetp = source;
}

void
dns_resolver_detach(dns_resolver_t **resp) {
	dns_resolver_t *res;
	isc_boolean_t need_destroy = ISC_FALSE;
	unsigned int i;

	REQUIRE(resp != NULL);
	res = *resp;
	REQUIRE(VALID_RESOLVER(res));

	RTRACE("detach");
	LOCK(&res->lock);
	INSIST(res->references > 0);
	res->references--;
	if (res->references == 0) {
		RTRACE("exiting");
		res->exiting = ISC_TRUE;
		for (i = 0; i < res->nbuckets; i++) {
			/*
			 * XXXRTH  Post shutdown events?
			 */
			LOCK(&res->buckets[i].lock);
			if (res->udpsocket4 != NULL)
				isc_socket_cancel(res->udpsocket4,
						  res->buckets[i].task,
						  ISC_SOCKCANCEL_ALL);
			if (res->udpsocket6 != NULL)
				isc_socket_cancel(res->udpsocket6,
						  res->buckets[i].task,
						  ISC_SOCKCANCEL_ALL);
			res->buckets[i].exiting = ISC_TRUE;
			if (ISC_LIST_EMPTY(res->buckets[i].fctxs)) {
				INSIST(res->activebuckets > 0);
				res->activebuckets--;
			}
			UNLOCK(&res->buckets[i].lock);
		}
		if (res->activebuckets == 0)
			need_destroy = ISC_TRUE;
	}
	UNLOCK(&res->lock);

	if (need_destroy)
		destroy(res);

	*resp = NULL;
}

static inline isc_boolean_t
fctx_match(fetchctx_t *fctx, dns_name_t *name, dns_rdatatype_t type,
	   unsigned int options)
{
	if (fctx->type != type || fctx->options != options)
		return (ISC_FALSE);
	return (dns_name_equal(&fctx->name, name));
}

/*
 * XXXRTH  This routine takes an unconscionable number of arguments!
 *
 * Maybe caller should allocate an event and pass that in?  Something must
 * be done!
 */

isc_result_t
dns_resolver_createfetch(dns_resolver_t *res, dns_name_t *name,
			 dns_rdatatype_t type,
			 dns_name_t *domain, dns_rdataset_t *nameservers,
			 dns_forwarders_t *forwarders,
			 unsigned int options, isc_task_t *task,
			 isc_taskaction_t action, void *arg,
			 dns_rdataset_t *rdataset,
			 dns_rdataset_t *sigrdataset, 
			 dns_fetch_t **fetchp)
{
	dns_fetch_t *fetch;
	fetchctx_t *fctx = NULL;
	isc_result_t result;
	unsigned int bucketnum;
	isc_boolean_t new_fctx = ISC_FALSE;
	isc_event_t *event;

	(void)forwarders;

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(fetchp != NULL && *fetchp == NULL);

	RTRACE("createfetch");

	/* XXXRTH */
	if ((options & DNS_FETCHOPT_TCP) != 0)
		return (DNS_R_NOTIMPLEMENTED);

	/*
	 * XXXRTH  use a mempool?
	 */
	fetch = isc_mem_get(res->mctx, sizeof *fetch);
	if (fetch == NULL)
		return (ISC_R_NOMEMORY);

	bucketnum = dns_name_hash(name, ISC_FALSE) % res->nbuckets;

	LOCK(&res->buckets[bucketnum].lock);

	if (res->buckets[bucketnum].exiting) {
		result = ISC_R_SHUTTINGDOWN;
		goto unlock;
	}

	if ((options & DNS_FETCHOPT_UNSHARED) == 0) {
		for (fctx = ISC_LIST_HEAD(res->buckets[bucketnum].fctxs);
		     fctx != NULL;
		     fctx = ISC_LIST_NEXT(fctx, link)) {
			if (fctx_match(fctx, name, type, options))
				break;
		}
	}

	if (fctx == NULL || fctx->state == fetchstate_done) {
		fctx = NULL;
		result = fctx_create(res, name, type, domain, nameservers,
				     options, bucketnum, &fctx);
		if (result != ISC_R_SUCCESS)
			goto unlock;
		new_fctx = ISC_TRUE;
	}
	result = fctx_join(fctx, task, action, arg,
			   rdataset, sigrdataset, fetch);
	if (new_fctx) {
		if (result == ISC_R_SUCCESS) {
			/*
			 * Launch this fctx.
			 */
			event = &fctx->control_event;
			ISC_EVENT_INIT(event, sizeof *event, 0, NULL,
				       DNS_EVENT_FETCHCONTROL,
				       fctx_start, fctx, (void *)fctx_create,
				       NULL, NULL);
			isc_task_send(res->buckets[bucketnum].task, &event);
		} else {
			/*
			 * We don't care about the result of fctx_destroy()
			 * since we know we're not exiting.
			 */
			(void)fctx_destroy(fctx);
		}
	}

 unlock:
	UNLOCK(&res->buckets[bucketnum].lock);

	if (result == ISC_R_SUCCESS) {
		FTRACE("created");
		*fetchp = fetch;
	} else
		isc_mem_put(res->mctx, fetch, sizeof *fetch);

	return (result);
}

void
dns_resolver_destroyfetch(dns_resolver_t *res, dns_fetch_t **fetchp) {
	dns_fetch_t *fetch;
	dns_fetchevent_t *event, *next_event;
	isc_event_t *cevent;
	fetchctx_t *fctx;
	isc_task_t *etask;

	REQUIRE(fetchp != NULL);
	fetch = *fetchp;
	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;

	FTRACE("destroyfetch");

	LOCK(&res->buckets[fctx->bucketnum].lock);

	event = NULL;
	if (fctx->state != fetchstate_done) {
		for (event = ISC_LIST_HEAD(fctx->events);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, link);
			if (event->tag == fetch) {
				ISC_LIST_UNLINK(fctx->events, event,
						link);
				FTRACE("found");
				break;
			}
		}
	}
	if (event != NULL) {
		etask = event->sender;
		event->result = ISC_R_CANCELED;
		isc_task_sendanddetach(&etask, (isc_event_t **)&event);
	}

	INSIST(fctx->references > 0);
	fctx->references--;
	if (fctx->references == 0) {
		/*
		 * No one cares about the result of this fetch anymore.
		 * Shut it down.
		 */
		fctx->exiting = ISC_TRUE;

		/*
		 * Unless we're still initializing (in which case the
		 * control event is still outstanding), we need to post
		 * the control event to tell the fetch we want it to
		 * exit.
		 */
		if (fctx->state != fetchstate_init) {
			cevent = &fctx->control_event;
			isc_task_send(res->buckets[fctx->bucketnum].task,
				      &cevent);
		}
	}

	UNLOCK(&res->buckets[fctx->bucketnum].lock);

	isc_mem_put(res->mctx, fetch, sizeof *fetch);
	*fetchp = NULL;
}
