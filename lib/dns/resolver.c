
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
#include <dns/events.h>
#include <dns/message.h>
#include <dns/dispatch.h>
#include <dns/resolver.h>

#include "../isc/util.h"		/* XXX */

#define DNS_RESOLVER_TRACE
#ifdef DNS_RESOLVER_TRACE
#define RTRACE(m)	printf("res %p: %s\n", res, (m))
#define RRTRACE(r, m)	printf("res %p: %s\n", (r), (m))
#define FCTXTRACE(m)	printf("fctx %p: %s\n", fctx, (m))
#define FTRACE(m)	printf("fetch %p (res %p fctx %p tag %u): %s\n", \
			       fetch, fetch->res, fetch->private, fetch->tag, \
			       (m))
#else
#define RTRACE(m)
#define RRTRACE(r, m)
#define FCTXTRACE(m)
#define FTRACE(m)
#endif

typedef struct query {
	dns_messageid_t			id;
	ISC_LINK(struct query)		link;
} resquery_t;

typedef enum {
	fetchstate_init = 0,
	fetchstate_active,
	fetchstate_exiting,
	fetchstate_done
} fetchstate;

typedef struct fetchctx {
	unsigned int			magic;
	fetchstate			state;
	dns_resolver_t *		res;
	unsigned int			references;
	unsigned int			locknum;
	dns_name_t			name;
	dns_rdatatype_t			type;		/* multiple types??? */
	unsigned int			options;
	/* Locked by lock. */
	isc_timer_t *			timer;
	isc_time_t			expires;
	isc_interval_t			interval;
	unsigned int			next_tag;
	ISC_LIST(dns_fetchdoneevent_t)	events;
	isc_event_t			start_event;
	dns_dispatch_t *		dispatcher;
	dns_message_t *			message;
	ISC_LIST(resquery_t)		queries;
	ISC_LINK(struct fetchctx)	link;
} fetchctx_t;

#define FCTX_MAGIC			0x46212121U	/* F!!! */
#define VALID_FCTX(fctx)		((fctx) != NULL && \
					 (fctx)->magic == FCTX_MAGIC)

struct dns_resolver {
	/* Unlocked */
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_mutex_t			lock;
	dns_rdataclass_t		rdclass;
	isc_timermgr_t *		timermgr;
	/* Locked by lock. */
	unsigned int			references;
	isc_boolean_t			exiting;
	dns_dispatch_t *		shared_dispatcher;
	unsigned int			ntasks;
	unsigned int			next_task;
	isc_task_t **			tasks;
	ISC_LIST(fetchctx_t)		fctxs;
};

#define RES_MAGIC			0x52657321U	/* Res! */
#define VALID_RESOLVER(res)		((res) != NULL && \
					 (res)->magic == RES_MAGIC)


static void destroy(dns_resolver_t *res);

/*
 * Internal fetch routines.  Caller must be holding the proper lock.
 */

static void
fctx_done(fetchctx_t *fctx, dns_result_t result) {
	dns_fetchdoneevent_t *event, *next_event;
	isc_task_t *task;
	isc_result_t iresult;

	/*
	 * The caller must be holding the proper lock.
	 */

	FCTXTRACE("done");

	REQUIRE(fctx->state == fetchstate_active);

	fctx->state = fetchstate_done;

	for (event = ISC_LIST_HEAD(fctx->events);
	     event != NULL;
	     event = next_event) {
		next_event = ISC_LIST_NEXT(event, link);
		task = event->sender;
		event->sender = fctx;
		event->result = result;
		iresult = isc_task_send(task, (isc_event_t **)&event);
		if (iresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_task_send(): %s",
					 isc_result_totext(iresult));
			isc_event_free((isc_event_t **)&event);
		}
		isc_task_detach(&task);
	}
	ISC_LIST_INIT(fctx->events);
}

static dns_result_t
fctx_sendquery(fetchctx_t *fctx) {
	resquery_t *query;

	FCTXTRACE("sendquery");

	query = isc_mem_get(fctx->res->mctx, sizeof *query);
	if (query == NULL)
		return (DNS_R_NOMEMORY);
	ISC_LIST_APPEND(fctx->queries, query, link);

	/* XXXRTH do the rest of the work... */

	return (DNS_R_SUCCESS);
}

static void
fctx_cancelqueries(fetchctx_t *fctx) {
	resquery_t *query, *next_query;

	FCTXTRACE("cancelqueries");

	for (query = ISC_LIST_HEAD(fctx->queries);
	     query != NULL;
	     query = next_query) {
		next_query = ISC_LIST_NEXT(query, link);
		/* XXXRTH do the rest of the work... */
		isc_mem_put(fctx->res->mctx, query, sizeof *query);
	}
	ISC_LIST_INIT(fctx->queries);
}

static void
fctx_restart(fetchctx_t *fctx) {
	isc_result_t iresult;
	dns_result_t result;

	/*
	 * Caller must be holding the fetch's lock.
	 */

	REQUIRE(fctx->state = fetchstate_active);

	FCTXTRACE("restart");

	iresult = isc_timer_reset(fctx->timer, isc_timertype_once,
				  &fctx->expires, &fctx->interval,
				  ISC_FALSE);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_timer_reset(): %s",
				 isc_result_totext(iresult));
		fctx_done(fctx, DNS_R_UNEXPECTED);
	}

	result = fctx_sendquery(fctx);
	if (result != DNS_R_SUCCESS)
		fctx_done(fctx, result);
}

static void
fctx_destroy(fetchctx_t *fctx) {
	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->state == fetchstate_done);
	REQUIRE(ISC_LIST_EMPTY(fctx->events));
	REQUIRE(ISC_LIST_EMPTY(fctx->queries));

	FCTXTRACE("destroy");

	isc_timer_detach(&fctx->timer);
	dns_name_free(&fctx->name, fctx->res->mctx);
	isc_mem_put(fctx->res->mctx, fctx, sizeof *fctx);
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
	INSIST(fctx->state == fetchstate_active);

	if (event->type == ISC_TIMEREVENT_LIFE) {
		fctx_cancelqueries(fctx);
		fctx_done(fctx, DNS_R_TIMEDOUT);
	} else {
		/*
		 * We could cancel the running queries here, or we could let
		 * them keep going.  Right now we choose the latter...
		 */
		fctx_restart(fctx);
	}

	UNLOCK(&fctx->res->lock);

	isc_event_free(&event);
}

static void
fctx_start(isc_task_t *task, isc_event_t *event) {
	fetchctx_t *fctx = event->arg;
	isc_boolean_t need_fctx_destroy = ISC_FALSE;
	isc_boolean_t need_resolver_destroy = ISC_FALSE;
	dns_resolver_t *res;

	REQUIRE(VALID_FCTX(fctx));

	res = fctx->res;
	(void)task;	/* Keep compiler quiet. */

	FCTXTRACE("start");

	LOCK(&res->lock);

	INSIST(fctx->state == fetchstate_init ||
	       fctx->state == fetchstate_exiting);
	if (fctx->state == fetchstate_init) {
		fctx->state = fetchstate_active;
		fctx_restart(fctx);
	} else {
		fctx->state = fetchstate_done;
		need_fctx_destroy = ISC_TRUE;
		if (res->exiting && ISC_LIST_EMPTY(res->fctxs))
			need_resolver_destroy = ISC_TRUE;
	}

	UNLOCK(&res->lock);

	if (need_fctx_destroy)
		fctx_destroy(fctx);
	if (need_resolver_destroy)
		destroy(res);
}

/*
 * Fetch Creation, Joining, and Cancelation.
 */

static inline dns_result_t
fctx_join(fetchctx_t *fctx, isc_task_t *task, isc_taskaction_t action,
	   void *arg, dns_fetch_t *fetch)
{
	isc_task_t *clone;
	dns_fetchdoneevent_t *event;

	FCTXTRACE("join");

	/*
	 * We store the task we're going to send this event to in the
	 * sender field.  We'll make the fetch the sender when we actually
	 * send the event.
	 */
	clone = NULL;
	isc_task_attach(task, &clone);
	event = (dns_fetchdoneevent_t *)
		isc_event_allocate(fctx->res->mctx, clone,
				   DNS_EVENT_FETCHDONE,
				   action, arg, sizeof *event);
	if (event == NULL)
		return (DNS_R_NOMEMORY);
	event->result = DNS_R_SUCCESS;
	event->tag = fctx->next_tag++;
	INSIST(fctx->next_tag != 0);
	/*
	 * XXX other event initialization here.
	 */
	ISC_LIST_APPEND(fctx->events, event, link);

	fctx->references++;

	fetch->magic = DNS_FETCH_MAGIC;
	fetch->res = fctx->res;
	fetch->private = fctx;
	fetch->tag = event->tag;
	ISC_LINK_INIT(fetch, link);
	
	return (DNS_R_SUCCESS);
}

static dns_result_t
fctx_create(dns_resolver_t *res, dns_name_t *name, dns_rdatatype_t type,
	    unsigned int options,
	    isc_task_t *worker, isc_task_t *task, isc_taskaction_t action,
	    void *arg, dns_fetch_t *fetch)
{
	fetchctx_t *fctx;
	dns_result_t result = DNS_R_SUCCESS;
	isc_result_t iresult;
	isc_event_t *event;
	isc_interval_t interval;

	fctx = isc_mem_get(res->mctx, sizeof *fctx);
	if (fctx == NULL)
		return (DNS_R_NOMEMORY);
	FCTXTRACE("create");
	result = dns_name_dup(name, res->mctx, NULL, &fctx->name);
	if (result != DNS_R_SUCCESS)
		goto cleanup_fetch;
	fctx->type = type;
	fctx->options = options;
	fctx->res = res;
	fctx->references = 0;
	fctx->locknum = 0;
	fctx->state = fetchstate_init;
	fctx->dispatcher = NULL;		/* XXX */
	fctx->next_tag = 1;
	ISC_LIST_INIT(fctx->queries);

	fctx->message = NULL;
	result = dns_message_create(res->mctx, &fctx->message,
				    DNS_MESSAGE_INTENTPARSE);
	if (result != DNS_R_SUCCESS)
		goto cleanup_name;

	/*
	 * Compute an expiration time for the entire fetch.
	 */
	isc_interval_set(&interval, 10, 0);		/* XXXRTH constant */
	iresult = isc_time_nowplusinterval(&fctx->expires, &interval);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_stdtime_get: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_message;
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
	iresult = isc_timer_create(res->timermgr, isc_timertype_inactive,
				   NULL, NULL,
				   worker, fctx_timeout,
				   fctx, &fctx->timer);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_timer_create: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_message;
	}

	ISC_LIST_INIT(fctx->events);
	result = fctx_join(fctx, task, action, arg, fetch);
	if (result != DNS_R_SUCCESS)
		goto cleanup_timer;

	ISC_LINK_INIT(fctx, link);
	fctx->magic = FCTX_MAGIC;

	/*
	 * The fetch is now ready to go.  We send the start event to its
	 * task to get the ball rolling.
	 *
	 * XXX we should really send this event from dns_resolver_fetch(),
	 * after we've unlocked the fetch's lock, otherwise the other task
	 * could well block on the lock we're about to release.
	 */
	event = &fctx->start_event;
	ISC_EVENT_INIT(event, sizeof *event, 0, 0, DNS_EVENT_FETCH,
		       fctx_start, fctx, (void *)fctx_create, NULL, NULL);
	iresult = isc_task_send(worker, &event);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_task_send: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_timer;
	}

	return (DNS_R_SUCCESS);

 cleanup_timer:
	isc_timer_detach(&fctx->timer);

 cleanup_message:
	dns_message_destroy(&fctx->message);

 cleanup_name:
	dns_name_free(&fctx->name, res->mctx);

 cleanup_fetch:
	isc_mem_put(res->mctx, fctx, sizeof *fctx);

	return (result);
}

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


/*
 * Handle Responses
 */

static inline dns_result_t
same_question(fetchctx_t *fctx) {
	dns_result_t result;
	dns_message_t *message = fctx->message;
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
	if (result != DNS_R_SUCCESS)
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
	
	return (DNS_R_SUCCESS);
}

static void
fctx_response(isc_task_t *task, isc_event_t *event) {
	dns_result_t result;
	fetchctx_t *fctx = event->arg;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	isc_boolean_t bad_sender = ISC_FALSE;
	dns_message_t *message;

	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(event->type == DNS_EVENT_DISPATCH);

	LOCK(&fctx->res->lock);
	INSIST(fctx->state == fetchstate_active);

	message = fctx->message;
	result = dns_message_parse(message, &devent->buffer);
	if (result != DNS_R_SUCCESS) {
		switch (result) {
		case DNS_R_FORMERR:
		case DNS_R_UNEXPECTEDEND:
			bad_sender = ISC_TRUE;
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
		bad_sender = ISC_TRUE;
		goto done;
	}

	/*
	 * Is the remote server broken, or does it dislike us?
	 */
	if (message->rcode != dns_rcode_noerror &&
	    message->rcode != dns_rcode_nxdomain) {
		bad_sender = ISC_TRUE;
		/*
		 * XXXRTH If we want to catch a FORMERR caused by an EDNS0
		 *        OPT RR, this is the place to do it.
		 */
		goto done;
	}

	/*
	 * Does the it answer the question we asked?
	 */
	result = same_question(fctx);
	if (result != DNS_R_SUCCESS) {
		/* XXXRTH Log */
		if (result == DNS_R_FORMERR)
			bad_sender = ISC_TRUE;
		goto done;
	}

	result = DNS_R_SUCCESS;

 done:
	/*
	 * XXXRTH  Record round-trip statistics here.
	 */
	if (bad_sender) {
		/*
		 * XXXRTH  We will mark the sender as bad here instead
		 *         of doing the printf().
		 */
		printf("bad sender\n");
		/*
		 * Keep trying.
		 */
		fctx_restart(fctx);
	} else {
		/*
		 * All is well, or we got an error fatal to the fetch.
		 * In either case, we're done.
		 */
		fctx_done(fctx, result);
	}

	UNLOCK(&fctx->res->lock);

	isc_event_free(&event);
}


/***
 *** Resolver Methods
 ***/

static void
destroy(dns_resolver_t *res) {
	unsigned int i;

	REQUIRE(res->exiting);
	REQUIRE(res->references == 0);
	REQUIRE(ISC_LIST_EMPTY(res->fctxs));

	RTRACE("destroy");

	isc_mutex_destroy(&res->lock);
	for (i = 0; i < res->ntasks; i++) {
		isc_task_shutdown(res->tasks[i]);
		isc_task_detach(&res->tasks[i]);
	}
	isc_mem_put(res->mctx, res->tasks,
		    res->ntasks * sizeof (isc_task_t *));
	res->magic = 0;
	isc_mem_put(res->mctx, res, sizeof *res);
}

dns_result_t
dns_resolver_create(isc_mem_t *mctx,
		    isc_taskmgr_t *taskmgr, unsigned int ntasks,
		    isc_timermgr_t *timermgr,
		    dns_rdataclass_t rdclass,
		    dns_dispatch_t *dispatcher,
		    dns_resolver_t **resp)
{
	dns_resolver_t *res;
	dns_result_t result = DNS_R_SUCCESS;
	isc_result_t iresult;
	unsigned int i, tasks_created = 0;

	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(ntasks > 0);

	res = isc_mem_get(mctx, sizeof *res);
	if (res == NULL)
		return (DNS_R_NOMEMORY);
	RTRACE("create");
	res->mctx = mctx;
	res->rdclass = rdclass;
	res->timermgr = timermgr;
	res->ntasks = ntasks;
	res->next_task = 0;
	res->shared_dispatcher = dispatcher;		/* XXXRTH: attach! */
	res->tasks = isc_mem_get(mctx, ntasks * sizeof (isc_task_t *));
	if (res->tasks == NULL) {
		result = DNS_R_NOMEMORY;
		goto cleanup_res;
	}
	for (i = 0; i < ntasks; i++) {
		res->tasks[i] = NULL;
		iresult = isc_task_create(taskmgr, mctx, 0, &res->tasks[i]);
		if (iresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_task_create() failed: %s",
					 isc_result_totext(iresult));
			result = DNS_R_UNEXPECTED;
			goto cleanup_tasks;
		}
		tasks_created++;
	}
	
	res->references = 1;
	res->exiting = ISC_FALSE;

	iresult = isc_mutex_init(&res->lock);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(iresult));
		result = DNS_R_UNEXPECTED;
		goto cleanup_tasks;
	}

	ISC_LIST_INIT(res->fctxs);

	res->magic = RES_MAGIC;
	
	*resp = res;

	return (DNS_R_SUCCESS);

 cleanup_tasks:
	for (i = 0; i < tasks_created; i++) {
		isc_task_shutdown(res->tasks[i]);
		isc_task_detach(&res->tasks[i]);
	}
	isc_mem_put(mctx, res->tasks, res->ntasks * sizeof (isc_task_t *));

 cleanup_res:
	isc_mem_put(mctx, res, sizeof *res);

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
	fetchctx_t *fctx;

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
		for (fctx = ISC_LIST_HEAD(res->fctxs);
		     fctx != NULL;
		     fctx = ISC_LIST_NEXT(fctx, link))
			fctx_cancel(fctx);
		if (ISC_LIST_EMPTY(res->fctxs))
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

dns_result_t
dns_resolver_createfetch(dns_resolver_t *res, dns_name_t *name,
			 dns_rdatatype_t type,
			 dns_delegation_t *delegation,
			 dns_forwarders_t *forwarders,
			 unsigned int options, isc_task_t *task,
			 isc_taskaction_t action, void *arg,
			 dns_fetch_t **fetchp)
{
	dns_fetch_t *fetch;
	fetchctx_t *fctx = NULL;
	dns_result_t result;
	isc_task_t *worker;

	(void)delegation;
	(void)forwarders;

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(fetchp != NULL && *fetchp == NULL);
	/*
	 * We require !res->exiting, since if it were exiting, that would
	 * mean that the reference count was wrong!
	 */
	REQUIRE(!res->exiting);

	RTRACE("createfetch");

	/* XXXRTH */
	if ((options & DNS_FETCHOPT_TCP) != 0)
		return (DNS_R_NOTIMPLEMENTED);

	fetch = isc_mem_get(res->mctx, sizeof *fetch);
	if (fetch == NULL)
		return (DNS_R_NOMEMORY);

	LOCK(&res->lock);

	/*
	 * XXXRTH This is for correctness, and doesn't represent the final
	 * way of assigning tasks, or the final form of the fetch table.
	 */

	worker = res->tasks[res->next_task];
	res->next_task++;
	if (res->next_task == res->ntasks)
		res->next_task = 0;

	if ((options & DNS_FETCHOPT_UNSHARED) == 0) {
		for (fctx = ISC_LIST_HEAD(res->fctxs);
		     fctx != NULL;
		     fctx = ISC_LIST_NEXT(fctx, link)) {
			if (fctx_match(fctx, name, type, options))
				break;
		}
	}

	if (fctx == NULL || fctx->state == fetchstate_done) {
		result = fctx_create(res,
				     name, type, options,
				     worker,
				     task, action, arg,
				     fetch);
		if (result == DNS_R_SUCCESS) {
			fctx = fetch->private;
			ISC_LIST_APPEND(res->fctxs, fctx, link);
		}
	} else
		result = fctx_join(fctx, task, action, arg, fetch);

	UNLOCK(&res->lock);

	if (result == DNS_R_SUCCESS) {
		FTRACE("created");
		*fetchp = fetch;
	} else
		isc_mem_put(res->mctx, fetch, sizeof *fetch);

	return (result);
}

void
dns_resolver_destroyfetch(dns_fetch_t **fetchp, isc_task_t *task) {
	dns_fetch_t *fetch;
	dns_fetchdoneevent_t *event, *next_event;
	fetchctx_t *fctx;
	dns_resolver_t *res;
	isc_boolean_t need_fctx_destroy = ISC_FALSE;
	isc_boolean_t need_resolver_destroy = ISC_FALSE;
	isc_task_t *etask;

	/*
	 * XXXRTH  We could make it so that even if all the clients detach
	 * from the fetch, the fctx keeps going.  Perhaps this should be
	 * a resolver option?  Right now if they all go away the fctx will
	 * be destroyed too.
	 */

	REQUIRE(fetchp != NULL);
	fetch = *fetchp;
	REQUIRE(DNS_FETCH_VALID(fetch));
	res = fetch->res;
	fctx = fetch->private;

	FTRACE("destroyfetch");

	LOCK(&res->lock);

	event = NULL;
	if (fctx->state != fetchstate_done) {
		for (event = ISC_LIST_HEAD(fctx->events);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, link);
			if (event->tag == fetch->tag) {
				ISC_LIST_UNLINK(fctx->events, event, link);
				FTRACE("found");
				break;
			}
		}
	} else if (task != NULL)
		(void)isc_task_purge(task, fctx, DNS_EVENT_FETCHDONE,
				     fetch->tag);

	INSIST(fctx->references > 0);
	fctx->references--;
	if (fctx->references == 0) {
		ISC_LIST_UNLINK(res->fctxs, fctx, link);
		if (fctx->state == fetchstate_init) {
			/*
			 * The fctx is still initializing, which means that
			 * the start event either hasn't been delivered, or
			 * is being processed right now, but is blocked waiting
			 * for the lock.
			 *
			 * Rather than try to purge the event, we simply
			 * wait for it to happen, deferring further destruction
			 * until it has been processed.
			 */
			fctx->state = fetchstate_exiting;
		} else {
			need_fctx_destroy = ISC_TRUE;
			if (res->exiting && ISC_LIST_EMPTY(res->fctxs))
				need_resolver_destroy = ISC_TRUE;
		}
	}

	UNLOCK(&res->lock);

	if (event != NULL) {
		etask = event->sender;
		isc_task_detach(&etask);
		isc_event_free((isc_event_t **)&event);
	}
	if (need_fctx_destroy)
		fctx_destroy(fctx);
	if (need_resolver_destroy)
		destroy(res);

	isc_mem_put(res->mctx, fetch, sizeof *fetch);

	*fetchp = NULL;
}
