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
#include <isc/error.h>
#include <isc/result.h>
#include <isc/timer.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/task.h>
#include <isc/stdtime.h>

#include <dns/types.h>
#include <dns/adb.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/message.h>
#include <dns/ncache.h>
#include <dns/dispatch.h>
#include <dns/resolver.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/tsig.h>
#include <dns/view.h>
#include <dns/log.h>

#include <dst/dst.h>

#include "../isc/util.h"		/* XXX */

#define DNS_RESOLVER_TRACE
#ifdef DNS_RESOLVER_TRACE
#define RTRACE(m)	isc_log_write(dns_lctx, \
				      DNS_LOGCATEGORY_RESOLVER, \
				      DNS_LOGMODULE_RESOLVER, \
				      ISC_LOG_DEBUG(1), \
				      "res %p: %s", res, (m))
#define RRTRACE(r, m)	isc_log_write(dns_lctx, \
				      DNS_LOGCATEGORY_RESOLVER, \
				      DNS_LOGMODULE_RESOLVER, \
				      ISC_LOG_DEBUG(1), \
				      "res %p: %s", (r), (m))
#define FCTXTRACE(m)	isc_log_write(dns_lctx, \
				      DNS_LOGCATEGORY_RESOLVER, \
				      DNS_LOGMODULE_RESOLVER, \
				      ISC_LOG_DEBUG(1), \
				      "fctx %p: %s", fctx, (m))
#define FTRACE(m)	isc_log_write(dns_lctx, \
				      DNS_LOGCATEGORY_RESOLVER, \
				      DNS_LOGMODULE_RESOLVER, \
				      ISC_LOG_DEBUG(1), \
				      "fetch %p (fctx %p): %s", \
				      fetch, fetch->private, (m))
#define QTRACE(m)	isc_log_write(dns_lctx, \
				      DNS_LOGCATEGORY_RESOLVER, \
				      DNS_LOGMODULE_RESOLVER, \
				      ISC_LOG_DEBUG(1), \
				      "resquery %p (fctx %p): %s", \
				      query, query->fctx, (m))
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
	unsigned int			attributes;
	isc_timer_t *			timer;
	isc_time_t			expires;
	isc_interval_t			interval;
	dns_message_t *			qmessage;
	dns_message_t *			rmessage;
	ISC_LIST(resquery_t)		queries;
	ISC_LIST(dns_adbhandle_t)	lookups;
	dns_adbhandle_t *		lookup;
};

#define FCTX_MAGIC			0x46212121U	/* F!!! */
#define VALID_FCTX(fctx)		((fctx) != NULL && \
					 (fctx)->magic == FCTX_MAGIC)

#define FCTX_ATTR_HAVEANSWER		0x01
#define FCTX_ATTR_GLUING		0x02
#define FCTX_ATTR_ADDRWAIT		0x04

#define HAVE_ANSWER(f)		(((f)->attributes & FCTX_ATTR_HAVEANSWER) != \
				 0)
#define GLUING(f)		(((f)->attributes & FCTX_ATTR_GLUING) != \
				 0)
#define ADDRWAIT(f)		(((f)->attributes & FCTX_ATTR_ADDRWAIT) != \
				 0)

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
static void resquery_response(isc_task_t *task, isc_event_t *event);
static void fctx_try(fetchctx_t *fctx);


static inline isc_result_t
fctx_starttimer(fetchctx_t *fctx) {
	return (isc_timer_reset(fctx->timer, isc_timertype_once,
				&fctx->expires, &fctx->interval,
				ISC_FALSE));
}

static inline isc_result_t
fctx_stopidletimer(fetchctx_t *fctx) {
	return (isc_timer_reset(fctx->timer, isc_timertype_once,
				&fctx->expires, NULL,
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

	query = *queryp;
	fctx = query->fctx;

	FCTXTRACE("cancelquery");

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
fctx_freelookups(fetchctx_t *fctx) {
	dns_adbhandle_t *lookup, *next_lookup;

	for (lookup = ISC_LIST_HEAD(fctx->lookups);
	     lookup != NULL;
	     lookup = next_lookup) {
		next_lookup = ISC_LIST_NEXT(lookup, publink);
		ISC_LIST_UNLINK(fctx->lookups, lookup, publink);
		dns_adb_done(&lookup);
	}
	fctx->lookup = NULL;
}

static void
fctx_done(fetchctx_t *fctx, isc_result_t result) {
	dns_fetchevent_t *event, *next_event;
	isc_task_t *task;
	dns_resolver_t *res;

	FCTXTRACE("done");

	res = fctx->res;

	fctx_freelookups(fctx);
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
		if (!HAVE_ANSWER(fctx))
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
resquery_senddone(isc_task_t *task, isc_event_t *event) {
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
					  resquery_response,
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
				   &r, task, resquery_senddone,
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

static void
fctx_adbhandler(isc_task_t *task, isc_event_t *event) {
	fetchctx_t *fctx;
	isc_boolean_t want_try = ISC_FALSE;
	isc_boolean_t want_done = ISC_FALSE;

	fctx = event->arg;
	REQUIRE(VALID_FCTX(fctx));

	(void)task;

	FCTXTRACE("adbhandler");

	if (ADDRWAIT(fctx)) {
		fctx->attributes &= ~FCTX_ATTR_ADDRWAIT;
		if (event->type == DNS_EVENT_ADBMOREADDRESSES)
			want_try = ISC_TRUE;
		else
			want_done = ISC_TRUE;
	}
	
	isc_event_free(&event);

	if (want_try)
		fctx_try(fctx);
	else if (want_done)
		fctx_done(fctx, ISC_R_NOTFOUND);
}

static isc_result_t
fctx_getaddresses(fetchctx_t *fctx) {
	dns_rdata_t rdata;
	isc_region_t r;
	dns_name_t name;
	isc_result_t result;
	dns_resolver_t *res;
	isc_stdtime_t now;
	dns_adbhandle_t *lookup;
	isc_boolean_t found_something;
	unsigned int options;

	FCTXTRACE("getaddresses");

	found_something = ISC_FALSE;
	options = DNS_ADBFIND_WANTEVENT|DNS_ADBFIND_INET;
	res = fctx->res;
	result = isc_stdtime_get(&now);
	if (result != ISC_R_SUCCESS)
		return (result);

	fctx_freelookups(fctx);

	result = dns_rdataset_first(&fctx->nameservers);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&fctx->nameservers, &rdata);
		/*
		 * Extract the name from the NS record.
		 */
		dns_rdata_toregion(&rdata, &r);
		dns_name_init(&name, NULL);
		dns_name_fromregion(&name, &r);
		/*
		 * XXXRTH  If this name is the same as QNAME, remember
		 *         skip it, and remember that we did so so we can
		 *         use an ancestor QDOMAIN if we find no addresses.
		 */
		/*
		 * See what we know about this address.
		 */
		lookup = NULL;
		result = dns_adb_lookup(res->view->adb,
					res->buckets[fctx->bucketnum].task,
					fctx_adbhandler, fctx, &name,
					&fctx->domain, options, now, &lookup);
		if (result != ISC_R_SUCCESS)
			return (result);
		if (!ISC_LIST_EMPTY(lookup->list)) {
			/*
			 * We have at least some of the addresses for the
			 * name.
			 */
			found_something = ISC_TRUE;
			/*
			 * XXXRTH  Sort.
			 */
		} else {
			/*
			 * We don't know any of the addresses for this
			 * name.
			 */
			if (lookup->query_pending == 0) {
				/*
				 * We're not fetching them either.  We lose
				 * for this name.
				 */
				dns_adb_done(&lookup);
			}
		}
		if (lookup != NULL)
			ISC_LIST_APPEND(fctx->lookups, lookup, publink);
		result = dns_rdataset_next(&fctx->nameservers);
	}
	if (result != DNS_R_NOMORE)
		return (result);

	if (ISC_LIST_EMPTY(fctx->lookups)) {
		/*
		 * We've lost completely.  We don't know any addresses, and
		 * the ADB has told us it can't get them.
		 */
		result = ISC_R_NOTFOUND;
	} else if (!found_something) {
		/*
		 * We're fetching the addresses, but don't have any yet.
		 * Tell the caller to wait for an answer.
		 */
		result = DNS_R_WAIT;
	} else {
		/*
		 * We've found some addresses.  We might still be looking
		 * for more addresses.
		 */

		/*
		 * XXXRTH  Sort.
		 */

		result = ISC_R_SUCCESS;
	}

	return (result);
}

#define FCTX_ADDRINFO_MARK		0x01
#define UNMARKED(a)			(((a)->flags & FCTX_ADDRINFO_MARK) \
					 == 0)

static inline dns_adbaddrinfo_t *
fctx_nextaddress(fetchctx_t *fctx) {
	dns_adbhandle_t *lookup;
	dns_adbaddrinfo_t *addrinfo;
	int count = 0;

	/*
	 * Return the next untried address, if any.
	 */

	/*
	 * Move to the next lookup.
	 */
	lookup = fctx->lookup;
	if (lookup == NULL)
		lookup = ISC_LIST_HEAD(fctx->lookups);
	else {
		lookup = ISC_LIST_NEXT(lookup, publink);
		if (lookup == NULL)
			lookup = ISC_LIST_HEAD(fctx->lookups);
	}

	/*
	 * Find the first unmarked addrinfo.
	 */
	addrinfo = NULL;
	while (lookup != fctx->lookup) {
		count++;
		INSIST(count < 1000);
		for (addrinfo = ISC_LIST_HEAD(lookup->list);
		     addrinfo != NULL;
		     addrinfo = ISC_LIST_NEXT(addrinfo, publink)) {
			if (UNMARKED(addrinfo)) {
				addrinfo->flags |= FCTX_ADDRINFO_MARK;
				break;
			}
		}
		if (addrinfo != NULL)
			break;
		lookup = ISC_LIST_NEXT(lookup, publink);
		if (lookup != fctx->lookup && lookup == NULL)
			lookup = ISC_LIST_HEAD(fctx->lookups);
	}

	fctx->lookup = lookup;

	return (addrinfo);
}

static void
fctx_try(fetchctx_t *fctx) {
	isc_result_t result;
	dns_adbaddrinfo_t *addrinfo;

	FCTXTRACE("try");

	REQUIRE(!ADDRWAIT(fctx));

	/*
	 * XXXRTH  We don't try to handle forwarding yet.
	 */

	addrinfo = fctx_nextaddress(fctx);
	if (addrinfo == NULL) {
		/*
		 * We have no more addresses.  Start over.
		 */
		fctx_cancelqueries(fctx);
		result = fctx_getaddresses(fctx);
		if (result == DNS_R_WAIT) {
			/*
			 * Sleep waiting for addresses.
			 */
			FCTXTRACE("addrwait");
			fctx->attributes |= FCTX_ATTR_ADDRWAIT; 
			return;
		} else if (result != ISC_R_SUCCESS) {
			/*
			 * Something bad happened.
			 */
			fctx_done(fctx, result);
			return;
		}

		addrinfo = fctx_nextaddress(fctx);
		/*
		 * fctx_getaddresses() returned success, so at least one
		 * of the lookup lists should be nonempty.
		 */
		INSIST(addrinfo != NULL);
	}

	/*
	 * XXXRTH  This is the place where a try strategy routine would
	 *         be called to send one or more queries.  Instead, we
	 *	   just send a single query.
	 */

	result = fctx_sendquery(fctx, addrinfo->sockaddr);
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
	REQUIRE(ISC_LIST_EMPTY(fctx->lookups));

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

	if (event->type == ISC_TIMEREVENT_LIFE) {
		fctx_done(fctx, DNS_R_TIMEDOUT);
	} else {
		/*
		 * We could cancel the running queries here, or we could let
		 * them keep going.  Right now we choose the latter...
		 */
		fctx_try(fctx);
	}

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
	event->fetch = fetch;
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
	ISC_LIST_INIT(fctx->lookups);
	fctx->lookup = NULL;
	fctx->attributes = 0;

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
	isc_interval_set(&interval, 30, 0);		/* XXXRTH constant */
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

static void
clone_results(fetchctx_t *fctx) {
	dns_fetchevent_t *event, *hevent;
	isc_result_t result;
	dns_name_t *name, *hname;

	/*
	 * Set up any other events to have the same data as the first
	 * event.
	 *
	 * Caller must be holding the appropriate lock.
	 */

	hevent = ISC_LIST_HEAD(fctx->events);
	if (hevent == NULL)
		return;
	hname = dns_fixedname_name(&hevent->foundname);
	for (event = ISC_LIST_NEXT(hevent, link);
	     event != NULL;
	     event = ISC_LIST_NEXT(event, link)) {
		name = dns_fixedname_name(&event->foundname);
		result = dns_name_concatenate(hname, NULL, name, NULL);
		if (result != ISC_R_SUCCESS)
			event->result = result;
		else
			event->result = hevent->result;
		dns_db_attach(hevent->db, &event->db);
		dns_db_attachnode(hevent->db, hevent->node, &event->node);
		if (hevent->rdataset != NULL &&
		    dns_rdataset_isassociated(hevent->rdataset))
			dns_rdataset_clone(hevent->rdataset, event->rdataset);
		if (hevent->sigrdataset != NULL &&
		    dns_rdataset_isassociated(hevent->sigrdataset))
			dns_rdataset_clone(hevent->sigrdataset,
					   event->sigrdataset);
	}
}

#define CACHE(r)	(((r)->attributes & DNS_RDATASETATTR_CACHE) != 0)
#define ANSWER(r)	(((r)->attributes & DNS_RDATASETATTR_ANSWER) != 0)
#define ANSWERSIG(r)	(((r)->attributes & DNS_RDATASETATTR_ANSWERSIG) != 0)
#define EXTERNAL(r)	(((r)->attributes & DNS_RDATASETATTR_EXTERNAL) != 0)
#define CHAINING(r)	(((r)->attributes & DNS_RDATASETATTR_CHAINING) != 0)

static inline isc_result_t
cache_name(fetchctx_t *fctx, dns_name_t *name, isc_stdtime_t now) {
	dns_rdataset_t *rdataset, *addedrdataset, *ardataset, *asigrdataset;
	dns_dbnode_t *node, **anodep;
	dns_db_t **adbp;
	dns_fixedname_t foundname;
	dns_name_t *fname, *aname;
	dns_resolver_t *res;
	void *data;
	isc_boolean_t need_validation, have_answer;
	isc_result_t result, eresult;
	dns_fetchevent_t *event;

	/*
	 * The appropriate bucket lock must be held.
	 */

	res = fctx->res;
	need_validation = ISC_FALSE;
	have_answer = ISC_FALSE;
	eresult = ISC_R_SUCCESS;

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
	event = NULL;
	if ((name->attributes & DNS_NAMEATTR_ANSWER) != 0) {
		have_answer = ISC_TRUE;
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
			/*
			 * XXXRTH.
			 */
			return (DNS_R_NOTIMPLEMENTED);
		} else if (!EXTERNAL(rdataset)) {
			/*
			 * It's OK to cache this rdataset now.
			 */
			if (ANSWER(rdataset))
				addedrdataset = ardataset;
			else
				addedrdataset = NULL;
			if (CHAINING(rdataset)) {
				if (rdataset->type == dns_rdatatype_cname)
					eresult = DNS_R_CNAME;
				else {
					INSIST(rdataset->type ==
					       dns_rdatatype_dname);
					eresult = DNS_R_DNAME;
				}
			}
			result = dns_db_addrdataset(res->view->cachedb,
						    node, NULL, now,
						    rdataset,
						    ISC_FALSE,
						    addedrdataset);
			if (result == DNS_R_UNCHANGED) {
				if (ANSWER(rdataset) &&
				    ardataset != NULL &&
				    ardataset->type == 0) {
					/*
					 * The answer in the cache is better
					 * than the answer we found, and is
					 * a negative cache entry, so we
					 * must set eresult appropriately.
					 */
					 if (ardataset->covers ==
					     dns_rdatatype_any)
						 eresult =
							 DNS_R_NCACHENXDOMAIN;
					 else
						 eresult =
							 DNS_R_NCACHENXRRSET;
				}
				result = ISC_R_SUCCESS;
			} else if (result != ISC_R_SUCCESS)
				break;
		}
	}

	if (result == ISC_R_SUCCESS && have_answer) {
		fctx->attributes |= FCTX_ATTR_HAVEANSWER;
		if (event != NULL) {
			event->result = eresult;
			dns_db_attach(res->view->cachedb, adbp);
			*anodep = node;
			clone_results(fctx);
		}
	} else
		dns_db_detachnode(res->view->cachedb, &node);

	return (result);
}

static inline isc_result_t
cache_message(fetchctx_t *fctx, isc_stdtime_t now) {
	isc_result_t result;
	dns_section_t section;
	dns_name_t *name;

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

static inline isc_result_t
ncache_message(fetchctx_t *fctx, dns_rdatatype_t covers, isc_stdtime_t now) {
	isc_result_t result, eresult;
	dns_name_t *name;
	dns_resolver_t *res;
	dns_db_t **adbp;
	dns_dbnode_t *node, **anodep;
	dns_rdataset_t *ardataset;
	isc_boolean_t need_validation;
	dns_fixedname_t foundname;
	dns_name_t *fname, *aname;
	dns_fetchevent_t *event;
	void *data;

	res = fctx->res;
	need_validation = ISC_FALSE;
	eresult = ISC_R_SUCCESS;
	name = &fctx->name;

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

	LOCK(&res->buckets[fctx->bucketnum].lock);

	adbp = NULL;
	aname = NULL;
	anodep = NULL;
	ardataset = NULL;
	event = ISC_LIST_HEAD(fctx->events);
	if (event != NULL) {
		adbp = &event->db;
		aname = dns_fixedname_name(&event->foundname);
		result = dns_name_concatenate(name, NULL, aname, NULL);
		if (result != ISC_R_SUCCESS)
			goto unlock;
		anodep = &event->node;
		ardataset = event->rdataset;
	}

	node = NULL;
	result = dns_db_findnode(res->view->cachedb, name, ISC_TRUE,
				 &node);
	if (result != ISC_R_SUCCESS)
		goto unlock;
	result = dns_ncache_add(fctx->rmessage, res->view->cachedb, node,
				covers, now, ardataset);
	if (result == DNS_R_UNCHANGED) {
		/*
		 * The data in the cache is better than the negative cache
		 * entry we're trying to add.
		 */
		if (ardataset != NULL && ardataset->type == 0) {
			/*
			 * The cache data is also a negative cache
			 * entry.
			 */
			if (ardataset->covers == dns_rdatatype_any)
				eresult = DNS_R_NCACHENXDOMAIN;
			else
				eresult = DNS_R_NCACHENXRRSET;
		} else {
			/*
			 * Either we don't care about the nature of the
			 * cache rdataset (because no fetch is interested
			 * in the outcome), or the cache rdataset is not
			 * a negative cache entry.  Whichever case it is,
			 * we can return success.  In the latter case,
			 * 'eresult' is already set correctly.
			 */
			result = ISC_R_SUCCESS;
		}
	} else if (result == ISC_R_SUCCESS) {
		if (covers == dns_rdatatype_any)
			eresult = DNS_R_NCACHENXDOMAIN;
		else
			eresult = DNS_R_NCACHENXRRSET;
	} else
		goto unlock;

	fctx->attributes |= FCTX_ATTR_HAVEANSWER;
	if (event != NULL) {
		event->result = eresult;
		dns_db_attach(res->view->cachedb, adbp);
		*anodep = node;
		node = NULL;
		clone_results(fctx);
	}

 unlock:
	UNLOCK(&res->buckets[fctx->bucketnum].lock);

	if (node != NULL)
		dns_db_detachnode(res->view->cachedb, &node);

	return (result);
}

static inline void
mark_related(dns_name_t *name, dns_rdataset_t *rdataset,
	     isc_boolean_t external, isc_boolean_t gluing)
{
	name->attributes |= DNS_NAMEATTR_CACHE;
	if (gluing)
		rdataset->trust = dns_trust_glue;
	else
		rdataset->trust = dns_trust_additional;
	rdataset->attributes |= DNS_RDATASETATTR_CACHE;
	if (external)
		rdataset->attributes |= DNS_RDATASETATTR_EXTERNAL;
#if 0
	/*
	 * XXXRTH  TEMPORARY FOR TESTING!!!
	 */
	rdataset->ttl = 5;
#endif
}

static isc_result_t
check_related(void *arg, dns_name_t *addname, dns_rdatatype_t type) {
	fetchctx_t *fctx = arg;
	isc_result_t result;
	dns_name_t *name;
	dns_rdataset_t *rdataset;
	isc_boolean_t external;
	dns_rdatatype_t rtype;
	isc_boolean_t gluing;

	REQUIRE(VALID_FCTX(fctx));

	if (GLUING(fctx))
		gluing = ISC_TRUE;
	else
		gluing = ISC_FALSE;
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
					mark_related(name, rdataset, external,
						     gluing);
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
				mark_related(name, rdataset, external, gluing);
				/*
				 * Do we have its SIG too?
				 */
				result = dns_message_findtype(name,
						      dns_rdatatype_sig,
						      type, &rdataset);
				if (result == ISC_R_SUCCESS)
					mark_related(name, rdataset, external,
						     gluing);
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
cname_target(dns_rdataset_t *rdataset, dns_name_t *tname) {
	isc_result_t result;
	dns_rdata_t rdata;
	isc_region_t r;

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_rdataset_current(rdataset, &rdata);
	dns_rdata_toregion(&rdata, &r);
	dns_name_init(tname, NULL);
	dns_name_fromregion(tname, &r);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
dname_target(dns_rdataset_t *rdataset, dns_name_t *qname, dns_name_t *oname,
	     dns_fixedname_t *fixeddname)
{
	isc_result_t result;
	dns_rdata_t rdata;
	isc_region_t r;
	dns_name_t *dname, tname;
	unsigned int nlabels, nbits;
	int order;
	dns_namereln_t namereln;

	/*
	 * Get the target name of the DNAME.
	 */
	dns_fixedname_init(fixeddname);
	dname = dns_fixedname_name(fixeddname);

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_rdataset_current(rdataset, &rdata);
	dns_rdata_toregion(&rdata, &r);
	dns_name_init(&tname, NULL);
	dns_name_fromregion(&tname, &r);

	/*
	 * Get the prefix of qname.
	 */
	namereln = dns_name_fullcompare(qname, oname, &order, &nlabels,
					&nbits);
	if (namereln != dns_namereln_subdomain)
		return (DNS_R_FORMERR);
	result = dns_name_split(qname, nlabels, nbits, dname, NULL);
	if (result != ISC_R_SUCCESS)
		return (result);

	return (dns_name_concatenate(dname, &tname, dname, NULL));
}

static isc_result_t
noanswer_response(fetchctx_t *fctx, dns_name_t *oqname) {
	isc_result_t result;
	dns_message_t *message;
	dns_name_t *name, *qname, *ns_name, *soa_name;
	dns_rdataset_t *rdataset;
	isc_boolean_t done, aa, negative_response;
	dns_rdatatype_t type;

	message = fctx->rmessage;

	/*
	 * Setup qname.
	 */
	if (oqname == NULL) {
		/*
		 * We have a normal, non-chained negative response or
		 * referral.
		 */
		if ((message->flags & DNS_MESSAGEFLAG_AA) != 0)
			aa = ISC_TRUE;
		else
			aa = ISC_FALSE;
		qname = &fctx->name;
	} else {
		/*
		 * We're being invoked by answer_response() after it has
		 * followed a CNAME/DNAME chain.
		 */
		qname = oqname;
		aa = ISC_FALSE;
	}
	
	/*
	 * We have to figure out if this is a negative response, or a
	 * referral.  We start by examining the rcode.
	 */
	negative_response = ISC_FALSE;
	if (message->rcode == dns_rcode_nxdomain)
		negative_response = ISC_TRUE;

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
					rdataset->trust = dns_trust_glue;
					/*
					 * Mark any additional data related
					 * to this rdataset.
					 */
					fctx->attributes |=
						FCTX_ATTR_GLUING;
					(void)dns_rdataset_additionaldata(
							rdataset,
							check_related,
							fctx);
					fctx->attributes &=
						~FCTX_ATTR_GLUING;
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
	 * Did we find anything?
	 */
	if (!negative_response && ns_name == NULL) {
		/*
		 * Nope.
		 */
		if (oqname != NULL) {
			/*
			 * We've already got a partial CNAME/DNAME chain,
			 * and haven't found else anything useful here, but
			 * no error has occurred since we have an answer.
			 */
			return (ISC_R_SUCCESS);
		} else {
			/*
			 * The responder is insane.
			 */
			return (DNS_R_FORMERR);
		}
	}

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
	 */
	if (negative_response && soa_name == NULL) {
		if (oqname != NULL) {
			/*
			 * But again, we don't care if we've got an answer
			 * already.
			 */
			return (ISC_R_SUCCESS);
		} else
			return (DNS_R_FORMERR);
	}

	/*
	 * Do we have a referral?  (We only want to follow a referral if
	 * we're not following a chain.)
	 */
	if (!negative_response && ns_name != NULL && oqname == NULL) {
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

static inline isc_result_t
answer_response(fetchctx_t *fctx) {
	isc_result_t result;
	dns_message_t *message;
	dns_name_t *name, *qname, tname;
	dns_rdataset_t *rdataset;
	isc_boolean_t done, external, chaining, aa, found, want_chaining;
	isc_boolean_t have_sig, have_answer;
	unsigned int aflag;
	dns_rdatatype_t type;
	dns_fixedname_t dname;

	message = fctx->rmessage;

	/*
	 * Examine the answer section, marking those rdatasets which are
	 * part of the answer and should be cached.
	 */

	done = ISC_FALSE;
	chaining = ISC_FALSE;
	have_answer = ISC_FALSE;
	have_sig = ISC_FALSE;
	want_chaining = ISC_FALSE;
	if ((message->flags & DNS_MESSAGEFLAG_AA) != 0)
		aa = ISC_TRUE;
	else
		aa = ISC_FALSE;
	qname = &fctx->name;
	type = fctx->type;
	result = dns_message_firstname(message, DNS_SECTION_ANSWER);
	while (!done && result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_ANSWER, &name);
		external = !dns_name_issubdomain(name, &fctx->domain);
		if (dns_name_equal(name, qname)) {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				found = ISC_FALSE;
				want_chaining = ISC_FALSE;
				aflag = 0;
				if (rdataset->type == type ||
				    type == dns_rdatatype_any) {
					/*
					 * We've found an ordinary answer.
					 */
					found = ISC_TRUE;
					done = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWER;
				} else if (rdataset->type == dns_rdatatype_sig
					   && rdataset->covers == type) {
					/*
					 * We've found a signature that
					 * covers the type we're looking for.
					 */
					found = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWERSIG;
				} else if (rdataset->type ==
					   dns_rdatatype_cname) {
					/*
					 * We're looking for something else,
					 * but we found a CNAME.
					 *
					 * Getting a CNAME response for some
					 * query types is an error.
					 */
					if (type == dns_rdatatype_sig ||
					    type == dns_rdatatype_key ||
					    type == dns_rdatatype_nxt)
						return (DNS_R_FORMERR);
					found = ISC_TRUE;
					want_chaining = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWER;
					result = cname_target(rdataset,
							      &tname);
					if (result != ISC_R_SUCCESS)
						return (result);
				} else if (rdataset->type == dns_rdatatype_sig
					   && rdataset->covers ==
					   dns_rdatatype_cname) {
					/*
					 * We're looking for something else,
					 * but we found a SIG CNAME.
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
						if (aflag ==
						    DNS_RDATASETATTR_ANSWER)
							have_answer = ISC_TRUE;
						else
							have_sig = ISC_TRUE;
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

					/*
					 * CNAME chaining.
					 */
					if (want_chaining) {
						chaining = ISC_TRUE;
						rdataset->attributes |=
						    DNS_RDATASETATTR_CHAINING;
						qname = &tname;
					}
				}
				/*
				 * We could add an "else" clause here and
				 * log that we're ignoring this rdataset.
				 */
			}
		} else {
			/*
			 * Look for a DNAME (or its SIG).  Anything else is
			 * ignored.
			 */
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link)) {
				found = ISC_FALSE;
				want_chaining = ISC_FALSE;
				aflag = 0;
				if (rdataset->type == dns_rdatatype_dname) {
					/*
					 * We're looking for something else,
					 * but we found a DNAME.
					 *
					 * If we're not chaining, then the
					 * DNAME should not be external.
					 */
					if (!chaining && external)
						return (DNS_R_FORMERR);
					found = ISC_TRUE;
					want_chaining = ISC_TRUE;
					aflag = DNS_RDATASETATTR_ANSWER;
					result = dname_target(rdataset,
							      qname, name,
							      &dname);
					if (result == ISC_R_NOSPACE) {
						/*
						 * We can't construct the
						 * DNAME target.  Do not
						 * try to continue.
						 */
						want_chaining = ISC_FALSE;
					} else if (result != ISC_R_SUCCESS)
						return (result);
				} else if (rdataset->type == dns_rdatatype_sig
					   && rdataset->covers ==
					   dns_rdatatype_dname) {
					/*
					 * We've found a signature that
					 * covers the DNAME.
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
						 * we're not chaining.
						 */
						INSIST(!external);
						name->attributes |=
							DNS_NAMEATTR_ANSWER;
						rdataset->attributes |= aflag;
						if (aa)
							rdataset->trust =
							  dns_trust_authanswer;
					} else if (external) {
						rdataset->attributes |=
						    DNS_RDATASETATTR_EXTERNAL;
					}

					/*
					 * DNAME chaining.
					 */
					if (want_chaining) {
						chaining = ISC_TRUE;
						rdataset->attributes |=
						    DNS_RDATASETATTR_CHAINING;
						qname = dns_fixedname_name(
								   &dname);
					}
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_ANSWER);
	}
	if (result != ISC_R_NOMORE)
		return (result);

	/*
	 * We should have found an answer.
	 */
	if (!have_answer)
		return (DNS_R_FORMERR);

	/*
	 * Did chaining end before we got the final answer?
	 */
	if (want_chaining) {
		/*
		 * Yes.  This may be a negative reply, so hand off
		 * authority section processing to the noanswer code.
		 * If it isn't a noanswer response, no harm will be
		 * done.
		 */
		return (noanswer_response(fctx, qname));
	}

	/*
	 * We didn't end with an incomplete chain, so the rcode should be
	 * "no error".
	 */
	if (message->rcode != dns_rcode_noerror)
		return (DNS_R_FORMERR);

	/*
	 * Examine the authority section (if there is one).
	 *
	 * We expect there to be only one owner name for all the rdatasets
	 * in this section, and we expect that it is not external.
	 */
	done = ISC_FALSE;
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
					name->attributes |=
						DNS_NAMEATTR_CACHE;
					rdataset->attributes |=
						DNS_RDATASETATTR_CACHE;
					if (aa && !chaining)
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

static void
resquery_response(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	resquery_t *query = event->arg;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	isc_boolean_t keep_trying, broken_server, get_nameservers;
	dns_message_t *message;
	fetchctx_t *fctx;
	dns_rdatatype_t covers;
	dns_name_t *fname;
	dns_fixedname_t foundname;
	isc_stdtime_t now;

	REQUIRE(VALID_QUERY(query));
	fctx = query->fctx;
	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(event->type == DNS_EVENT_DISPATCH);

	(void)task;
	QTRACE("response");

	(void)isc_timer_touch(fctx->timer);

	keep_trying = ISC_FALSE;
	broken_server = ISC_FALSE;
	get_nameservers = ISC_FALSE;
	covers = 0;

	result = isc_stdtime_get(&now);
	if (result != ISC_R_SUCCESS)
		goto done;

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
		 *
		 * XXXRTH Need to deal with YXDOMAIN code.
		 */
		goto done;
	}

	/*
	 * Is the question the same as the one we asked?
	 */
	result = same_question(fctx);
	if (result != ISC_R_SUCCESS) {
		/* XXXRTH Log */
		if (result == DNS_R_FORMERR)
			keep_trying = ISC_TRUE;
		goto done;
	}

	/*
	 * Did we get any answers?
	 */
	if (message->counts[DNS_SECTION_ANSWER] > 0 &&
	    (message->rcode == dns_rcode_noerror ||
	     message->rcode == dns_rcode_nxdomain)) {
		/*
		 * We've got answers.
		 */
		result = answer_response(fctx);
		if (result != ISC_R_SUCCESS) {
			if (result == DNS_R_FORMERR)
				keep_trying = ISC_TRUE;
			goto done;
		}
	} else if (message->counts[DNS_SECTION_AUTHORITY] > 0) {
		/*
		 * NXDOMAIN, NXRDATASET, or referral.
		 */
		result = noanswer_response(fctx, NULL);
		if (result == DNS_R_DELEGATION) {
			/*
			 * We don't have the answer, but we know a better
			 * place to look.
			 */
			get_nameservers = ISC_TRUE;
			keep_trying = ISC_TRUE;
		} else if (result == ISC_R_SUCCESS) {
			if (message->rcode == dns_rcode_nxdomain)
				covers = dns_rdatatype_any;
			else
				covers = fctx->type;
			/*
			 * Cache any negative cache entries in the message.
			 * This may also cause work to be queued to the
			 * DNSSEC validator.
			 */
			result = ncache_message(fctx, covers, now);
			if (result != ISC_R_SUCCESS)
				goto done;
		} else {
			/*
			 * Something has gone wrong.
			 */
			if (result == DNS_R_FORMERR)
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

	/*
	 * XXXRTH  Explain this.
	 */
	query->tsig = NULL;

	/*
	 * Cache the cacheable parts of the message.  This may also cause
	 * work to be queued to the DNSSEC validator.
	 */
	result = cache_message(fctx, now);

 done:
	/*
	 * Give the event back to the dispatcher.
	 */
	dns_dispatch_freeevent(query->dispatch, query->dispentry, &devent);

	/*
	 * XXXRTH  Record round-trip statistics here.  Note that 'result'
	 *         MUST NOT be changed by this recording process.
	 */
	if (keep_trying) {
		if (result == DNS_R_FORMERR)
			broken_server = ISC_TRUE;
		/*
		 * XXXRTH  If we have a broken server at this point, we will
		 *	   decrease its 'goodness', possibly add a 'lame'
		 *         entry, and maybe log a message.
		 */
		if (get_nameservers) {
			dns_fixedname_init(&foundname);
			fname = dns_fixedname_name(&foundname);
			if (result != ISC_R_SUCCESS) {
				fctx_done(fctx, DNS_R_SERVFAIL);
				return;
			}
			result = dns_view_findzonecut(fctx->res->view,
						      &fctx->domain,
						      fname,
						      now, 0, ISC_TRUE,
						      &fctx->nameservers,
						      NULL);
			if (result != ISC_R_SUCCESS) {
				fctx_done(fctx, DNS_R_SERVFAIL);
				return;
			}
			if (!dns_name_issubdomain(fname, &fctx->domain)) {
				/*
				 * The best nameservers are now above our
				 * previous QDOMAIN.
				 *
				 * XXXRTH  What should we do here?
				 */
				QTRACE("avoiding upward referral");
				fctx_done(fctx, DNS_R_SERVFAIL);
				return;
			}
			dns_name_free(&fctx->domain, fctx->res->mctx);
			dns_name_init(&fctx->domain, NULL);
			result = dns_name_dup(fname, fctx->res->mctx,
					      &fctx->domain);
			if (result != ISC_R_SUCCESS) {
				fctx_done(fctx, DNS_R_SERVFAIL);
				return;
			}
			fctx_freelookups(fctx);
		}					  
		/*
		 * Try again.
		 */
		fctx_try(fctx);
	} else if (result == ISC_R_SUCCESS && !HAVE_ANSWER(fctx)) {
		/*
		 * All has gone well so far, but we are waiting for the
		 * DNSSEC validator to validate the answer.
		 */
		fctx_cancelqueries(fctx);
		result = fctx_stopidletimer(fctx);
		if (result != ISC_R_SUCCESS)
			fctx_done(fctx, result);
	} else {
		/*
		 * We're done.
		 */
		fctx_done(fctx, result);
	}
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
	in_port_t port = 5353;

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
		result = ISC_R_UNEXPECTED;
		while (result != ISC_R_SUCCESS && port < 5400) {
			ina.s_addr = htonl(INADDR_ANY);
			isc_sockaddr_fromin(&sa, &ina, port);
			result = isc_socket_bind(res->udpsocket4, &sa);
			if (result != ISC_R_SUCCESS)
				port++;
		}
		if (result != ISC_R_SUCCESS) {
			RTRACE("Could not open UDP port");
			goto cleanup_buckets;
		}
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
dns_resolver_cancelfetch(dns_resolver_t *res, dns_fetch_t *fetch) {
	fetchctx_t *fctx;
	dns_fetchevent_t *event, *next_event;
	isc_task_t *etask;

	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;

	FTRACE("cancelfetch");

	LOCK(&res->buckets[fctx->bucketnum].lock);

	event = NULL;
	if (fctx->state != fetchstate_done) {
		for (event = ISC_LIST_HEAD(fctx->events);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, link);
			if (event->fetch == fetch) {
				ISC_LIST_UNLINK(fctx->events, event,
						link);
				break;
			}
		}
	}
	if (event != NULL) {
		etask = event->sender;
		event->result = ISC_R_CANCELED;
		isc_task_sendanddetach(&etask, (isc_event_t **)&event);
	}

	UNLOCK(&res->buckets[fctx->bucketnum].lock);
}

void
dns_resolver_destroyfetch(dns_resolver_t *res, dns_fetch_t **fetchp) {
	dns_fetch_t *fetch;
	dns_fetchevent_t *event, *next_event;
	isc_event_t *cevent;
	fetchctx_t *fctx;

	REQUIRE(fetchp != NULL);
	fetch = *fetchp;
	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;

	FTRACE("destroyfetch");

	LOCK(&res->buckets[fctx->bucketnum].lock);

	/*
	 * Sanity check.  The caller should have either gotten its
	 * fetchevent before trying to destroy the fetch.
	 */
	event = NULL;
	if (fctx->state != fetchstate_done) {
		for (event = ISC_LIST_HEAD(fctx->events);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, link);
			RUNTIME_CHECK(event->fetch != fetch);
		}
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
