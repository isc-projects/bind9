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

#include <isc/mem.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/request.h>
#include <dns/result.h>
#include <dns/tsig.h>

#define REQUESTMGR_MAGIC 0x5271754dU		/* RquM */
#define VALID_REQUESTMGR(mgr) ((mgr) != NULL && \
			(mgr)->magic == REQUESTMGR_MAGIC)

#define REQUEST_MAGIC 0x52717521U		/* Rqu! */
#define VALID_REQUEST(request) ((request) != NULL && \
				(request)->magic == REQUEST_MAGIC)

typedef ISC_LIST(dns_request_t) dns_requestlist_t;

#define DNS_REQUEST_NLOCKS 7

struct dns_requestmgr {
	isc_int32_t			magic;
	isc_mutex_t			lock;
	isc_mem_t		       *mctx;

	/* locked */
	isc_int32_t			eref;
	isc_int32_t			iref;
	isc_timermgr_t		       *timermgr;
	isc_socketmgr_t		       *socketmgr;
	isc_taskmgr_t		       *taskmgr;
	dns_dispatchmgr_t	       *dispatchmgr;
	dns_dispatch_t		       *dispatchv4;
	dns_dispatch_t		       *dispatchv6;
	isc_boolean_t			exiting;
	isc_eventlist_t			whenshutdown;
	unsigned int			hash;
	isc_mutex_t			locks[DNS_REQUEST_NLOCKS];
	dns_requestlist_t 		requests;
};

struct dns_request {
	isc_int32_t			magic;
	unsigned int			hash;
	isc_mem_t		       *mctx;
	isc_int32_t			flags;
	ISC_LINK(dns_request_t) 	link;
	isc_buffer_t		       *query;
	isc_buffer_t		       *answer;
	dns_requestevent_t	       *event;
	dns_dispatch_t		       *dispatch;
	dns_dispentry_t		       *dispentry;
	isc_timer_t		       *timer;
	dns_requestmgr_t	       *requestmgr;
	isc_buffer_t		       *tsig;
	dns_tsigkey_t		       *tsigkey;

};

#define DNS_REQUEST_F_CONNECTING 0x0001
#define DNS_REQUEST_F_CANCELED 0x0002
#define DNS_REQUEST_F_TCP 0x0008		/* This request used TCP */
#define DNS_REQUEST_CANCELED(r) \
	(((r)->flags & DNS_REQUEST_F_CANCELED) != 0)
#define DNS_REQUEST_CONNECTING(r) \
	(((r)->flags & DNS_REQUEST_F_CONNECTING) != 0)

/***
 *** Forward
 ***/

static void mgr_destroy(dns_requestmgr_t *requestmgr);
static void mgr_shutdown(dns_requestmgr_t *requestmgr);
static unsigned int mgr_gethash(dns_requestmgr_t *requestmgr);
static void send_shutdown_events(dns_requestmgr_t *requestmgr);

static isc_result_t req_render(dns_message_t *message, isc_buffer_t **buffer,
			       isc_mem_t *mctx);
static void req_senddone(isc_task_t *task, isc_event_t *event);
static void req_response(isc_task_t *task, isc_event_t *event);
static void req_timeout(isc_task_t *task, isc_event_t *event);
static void req_connected(isc_task_t *task, isc_event_t *event);
static void req_sendevent(dns_request_t *request, isc_result_t result);
static void req_cancel(dns_request_t *request);
static void req_destroy(dns_request_t *request);
static void req_log(int level, const char *fmt, ...);

/***
 *** Public
 ***/

isc_result_t
dns_requestmgr_create(isc_mem_t *mctx,
		      isc_timermgr_t *timermgr,
		      isc_socketmgr_t *socketmgr,
		      isc_taskmgr_t *taskmgr,
		      dns_dispatchmgr_t *dispatchmgr,
		      dns_dispatch_t *dispatchv4,
		      dns_dispatch_t *dispatchv6,
		      dns_requestmgr_t **requestmgrp)
{
	dns_requestmgr_t *requestmgr;
	isc_socket_t *socket;
	isc_result_t result;
	int i;

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_create");

	REQUIRE(requestmgrp != NULL && *requestmgrp == NULL);
	REQUIRE(timermgr != NULL);
	REQUIRE(socketmgr != NULL);
	REQUIRE(taskmgr != NULL);
	REQUIRE(dispatchmgr != NULL);
	if (dispatchv4 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv4);
		REQUIRE(isc_socket_gettype(socket) == isc_sockettype_udp);
	}
	if (dispatchv6 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv6);
		REQUIRE(isc_socket_gettype(socket) == isc_sockettype_udp);
	}

	requestmgr = isc_mem_get(mctx, sizeof(*requestmgr));
	if (requestmgr == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&requestmgr->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, requestmgr, sizeof(*requestmgr));
		return (result);
	}
	for (i = 0; i < DNS_REQUEST_NLOCKS; i++) {
		result = isc_mutex_init(&requestmgr->locks[i]);
		if (result != ISC_R_SUCCESS) {
			while (--i >= 0)
				isc_mutex_destroy(&requestmgr->locks[i]);
			isc_mutex_destroy(&requestmgr->lock);
			isc_mem_put(mctx, requestmgr, sizeof(*requestmgr));
			return (result);
		}
	}
	requestmgr->timermgr = timermgr;
	requestmgr->socketmgr = socketmgr;
	requestmgr->taskmgr = taskmgr;
	requestmgr->dispatchmgr = dispatchmgr;
	requestmgr->dispatchv4 = NULL;
	if (dispatchv4 != NULL)
		dns_dispatch_attach(dispatchv4, &requestmgr->dispatchv4);
	requestmgr->dispatchv6 = NULL;
	if (dispatchv6 != NULL)
		dns_dispatch_attach(dispatchv6, &requestmgr->dispatchv6);
	requestmgr->mctx = NULL;
	isc_mem_attach(mctx, &requestmgr->mctx);
	requestmgr->eref = 1;	/* implict attach */
	requestmgr->iref = 0;
	ISC_LIST_INIT(requestmgr->whenshutdown);
	ISC_LIST_INIT(requestmgr->requests);
	requestmgr->exiting = ISC_FALSE;
	requestmgr->hash = 0;
	requestmgr->magic = REQUESTMGR_MAGIC;

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_create: %p", requestmgr);

	*requestmgrp = requestmgr;
	return (ISC_R_SUCCESS);
}

void
dns_requestmgr_whenshutdown(dns_requestmgr_t *requestmgr, isc_task_t *task,
			    isc_event_t **eventp)
{
        isc_task_t *clone;
        isc_event_t *event;

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_whenshutdown");

        REQUIRE(VALID_REQUESTMGR(requestmgr));
        REQUIRE(eventp != NULL);

        event = *eventp;
        *eventp = NULL;

        LOCK(&requestmgr->lock);

        if (requestmgr->exiting) {
                /*
                 * We're already shutdown.  Send the event.
                 */
                event->ev_sender = requestmgr;
                isc_task_send(task, &event);
        } else {
                clone = NULL;
                isc_task_attach(task, &clone);
                event->ev_sender = clone;
                ISC_LIST_APPEND(requestmgr->whenshutdown, event, ev_link);
	}
	UNLOCK(&requestmgr->lock);
}

void
dns_requestmgr_shutdown(dns_requestmgr_t *requestmgr) {

        REQUIRE(VALID_REQUESTMGR(requestmgr));

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_shutdown: %p", requestmgr);

	LOCK(&requestmgr->lock);
	mgr_shutdown(requestmgr);
	UNLOCK(&requestmgr->lock);
}

static void 
mgr_shutdown(dns_requestmgr_t *requestmgr) {
	dns_request_t *request;

	req_log(ISC_LOG_DEBUG(3), "mgr_shutdown: %p", requestmgr);

	/*
	 * Caller holds lock.
	 */
	if (!requestmgr->exiting) {
		requestmgr->exiting = ISC_TRUE;
		for (request = ISC_LIST_HEAD(requestmgr->requests);
		     request != NULL;
		     request = ISC_LIST_NEXT(request, link)) {
			dns_request_cancel(request);
		}
		if (requestmgr->iref == 0) {
			INSIST(ISC_LIST_EMPTY(requestmgr->requests));
			send_shutdown_events(requestmgr);
		}
	}
}

static void
requestmgr_attach(dns_requestmgr_t *source, dns_requestmgr_t **targetp) {

	/*
	 * Locked by caller.
	 */

        REQUIRE(VALID_REQUESTMGR(source));
        REQUIRE(targetp != NULL && *targetp == NULL);

	REQUIRE(!source->exiting);

	source->iref++;
	*targetp = source;

	req_log(ISC_LOG_DEBUG(3), "requestmgr_attach: %p: eref %d iref %d",
		source, source->eref, source->iref);
}

static void
requestmgr_detach(dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_boolean_t need_destroy  =ISC_FALSE;

	REQUIRE(requestmgrp != NULL);
	requestmgr = *requestmgrp;
	REQUIRE(VALID_REQUESTMGR(requestmgr));

	*requestmgrp = NULL;
	LOCK(&requestmgr->lock);
	INSIST(requestmgr->iref > 0);
	requestmgr->iref--;

	req_log(ISC_LOG_DEBUG(3), "requestmgr_detach: %p: eref %d iref %d",
		requestmgr, requestmgr->eref, requestmgr->iref);

	if (requestmgr->iref == 0 && requestmgr->exiting) {
		INSIST(ISC_LIST_HEAD(requestmgr->requests) == NULL);
		send_shutdown_events(requestmgr);
		if (requestmgr->eref == 0)
			need_destroy = ISC_TRUE;
	}
	UNLOCK(&requestmgr->lock);

	if (need_destroy)
		mgr_destroy(requestmgr);
}

void
dns_requestmgr_attach(dns_requestmgr_t *source, dns_requestmgr_t **targetp) {

        REQUIRE(VALID_REQUESTMGR(source));
        REQUIRE(targetp != NULL && *targetp == NULL);
	REQUIRE(!source->exiting);

	LOCK(&source->lock);
	source->eref++;
	*targetp = source;
	UNLOCK(&source->lock);

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_attach: %p: eref %d iref %d",
		source, source->eref, source->iref);
}

void
dns_requestmgr_detach(dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_boolean_t need_destroy = ISC_FALSE;

	REQUIRE(requestmgrp != NULL);
	requestmgr = *requestmgrp;
	REQUIRE(VALID_REQUESTMGR(requestmgr));

	LOCK(&requestmgr->lock);
	INSIST(requestmgr->eref > 0);
	requestmgr->eref--;

	req_log(ISC_LOG_DEBUG(3), "dns_requestmgr_detach: %p: eref %d iref %d",
		requestmgr, requestmgr->eref, requestmgr->iref);

	if (requestmgr->eref == 0 && requestmgr->iref == 0) {
		INSIST(requestmgr->exiting &&
		       ISC_LIST_HEAD(requestmgr->requests) == NULL);
		need_destroy = ISC_TRUE;
	}
	UNLOCK(&requestmgr->lock);

	if (need_destroy)
		mgr_destroy(requestmgr);

	*requestmgrp = NULL;
}

static void
send_shutdown_events(dns_requestmgr_t *requestmgr) {
	isc_event_t *event, *next_event;
	isc_task_t *etask;

	req_log(ISC_LOG_DEBUG(3), "send_shutdown_events: %p", requestmgr);

	/*
	 * Caller must be holding the manager lock.
	 */
	for (event = ISC_LIST_HEAD(requestmgr->whenshutdown);
	     event != NULL;
	     event = next_event) {
		next_event = ISC_LIST_NEXT(event, ev_link);
		ISC_LIST_UNLINK(requestmgr->whenshutdown, event, ev_link);
		etask = event->ev_sender;
		event->ev_sender = requestmgr;
		isc_task_sendanddetach(&etask, &event);
	}
}

static void
mgr_destroy(dns_requestmgr_t *requestmgr) {
	int i;
	isc_mem_t *mctx;

	req_log(ISC_LOG_DEBUG(3), "mgr_destroy");

	REQUIRE(requestmgr->eref == 0);
	REQUIRE(requestmgr->iref == 0);

	isc_mutex_destroy(&requestmgr->lock);
	for (i = 0; i < DNS_REQUEST_NLOCKS; i++)
		isc_mutex_destroy(&requestmgr->locks[i]);
	if (requestmgr->dispatchv4 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv4);
	if (requestmgr->dispatchv6 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv6);
	requestmgr->magic = 0;
	mctx = requestmgr->mctx;
	isc_mem_put(mctx, requestmgr, sizeof *requestmgr);
	isc_mem_detach(&mctx);
}

static unsigned int
mgr_gethash(dns_requestmgr_t *requestmgr) {
	req_log(ISC_LOG_DEBUG(3), "mgr_gethash");
	/*
	 * Locked by caller.
	 */
	requestmgr->hash++;
	return(requestmgr->hash % DNS_REQUEST_NLOCKS);
}

static inline isc_result_t
req_send(dns_request_t *request, isc_task_t *task, isc_sockaddr_t *address) {
	isc_region_t r;
	isc_socket_t *socket;

	req_log(ISC_LOG_DEBUG(3), "req_send: request %p", request);

	REQUIRE(VALID_REQUEST(request));
	socket = dns_dispatch_getsocket(request->dispatch);
	isc_buffer_usedregion(request->query, &r);
	return (isc_socket_sendto(socket, &r, task, req_senddone,
				  request, address, NULL));
}

isc_result_t
dns_request_create(dns_requestmgr_t *requestmgr, dns_message_t *message,
		   isc_sockaddr_t *address, unsigned int options,
		   dns_tsigkey_t *key,
		   unsigned int timeout, isc_task_t *task,
		   isc_taskaction_t action, void *arg,
		   dns_request_t **requestp)
{
	dns_request_t *request = NULL;
	isc_task_t *tclone = NULL;
	isc_socket_t *socket = NULL;
	isc_result_t result;
	isc_mem_t *mctx;
	isc_sockaddr_t bind_any;
	isc_interval_t interval;
	dns_messageid_t	id;
	isc_time_t expires;
	unsigned int attrs;

	REQUIRE(VALID_REQUESTMGR(requestmgr));
	REQUIRE(message != NULL);
	REQUIRE(address != NULL);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);
	REQUIRE(requestp != NULL && *requestp == NULL);
	REQUIRE(timeout > 0);

	mctx = requestmgr->mctx;

	req_log(ISC_LOG_DEBUG(3), "dns_request_create");

	request = isc_mem_get(mctx, sizeof(*request));
	if (request == NULL) {
		return (ISC_R_NOMEMORY);
	}
	/*
	 * Zero structure.
	 */
	request->magic = 0;
	request->mctx = NULL;
	request->flags = 0;
	ISC_LINK_INIT(request, link);
	request->query = NULL;
	request->answer = NULL;
	request->event = NULL;
	request->dispatch = NULL;
	request->dispentry = NULL;
	request->timer = NULL;
	request->requestmgr = NULL;
	request->tsig = NULL;
	request->tsigkey = NULL;

	/*
	 * Create timer now.  We will set it below once.
	 */
	result = isc_timer_create(requestmgr->timermgr, isc_timertype_inactive,
				  NULL, NULL, task, req_timeout, request,
				  &request->timer);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	request->event = (dns_requestevent_t *)
		isc_event_allocate(mctx, task, DNS_EVENT_REQUESTDONE,
				   action, arg, sizeof (dns_requestevent_t));
	if (request->event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	isc_task_attach(task, &tclone);
	request->event->ev_sender = task;
	request->event->request = request;
	request->event->result = ISC_R_FAILURE;
	request->tsigkey = key;
	
 use_tcp:
	if ((options & DNS_REQUESTOPT_TCP) != 0) {
		result = isc_socket_create(requestmgr->socketmgr,
					   isc_sockaddr_pf(address),
					   isc_sockettype_tcp, &socket);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		isc_sockaddr_any(&bind_any);
		result = isc_socket_bind(socket, &bind_any);
		if (result != ISC_R_SUCCESS) {
			isc_socket_detach(&socket);
			goto cleanup;
		}
		attrs = 0;
		attrs |= DNS_DISPATCHATTR_TCP;
		attrs |= DNS_DISPATCHATTR_PRIVATE;
		if (isc_sockaddr_pf(address) == AF_INET)
			attrs |= DNS_DISPATCHATTR_IPV4;
		else
			attrs |= DNS_DISPATCHATTR_IPV6;
		attrs |= DNS_DISPATCHATTR_MAKEQUERY;
		result = dns_dispatch_createtcp(requestmgr->dispatchmgr,
						socket, requestmgr->taskmgr,
						4096, 2, 1, 1, 3, attrs,
						&request->dispatch);
		isc_socket_detach(&socket);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	} else {
		switch (isc_sockaddr_pf(address)) {
		case PF_INET:
			dns_dispatch_attach(requestmgr->dispatchv4,
					    &request->dispatch);
			break;
		case PF_INET6:
			dns_dispatch_attach(requestmgr->dispatchv6,
					    &request->dispatch);
			break;
		default:
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		}
	}
	socket = dns_dispatch_getsocket(request->dispatch);
	INSIST(socket != NULL);
	result = dns_dispatch_addresponse(request->dispatch, address, task,
					  req_response, request, &id,
					  &request->dispentry);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	message->id = id;
	dns_message_settsigkey(message, request->tsigkey);
	result = req_render(message, &request->query, mctx);
	if (result == DNS_R_USETCP &&
	    (options & DNS_REQUESTOPT_TCP) == 0) {
		/*
		 * Try again using TCP.
		 */
		dns_message_renderreset(message);
		dns_dispatch_removeresponse(&request->dispentry, NULL);
		dns_dispatch_detach(&request->dispatch);
		socket = NULL;
		isc_buffer_free(&request->query);
		options |= DNS_REQUESTOPT_TCP;
		goto use_tcp;
	}
	if (result != ISC_R_SUCCESS && result != DNS_R_USETCP)
		goto cleanup;

	result = dns_message_getquerytsig(message, mctx, &request->tsig);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	isc_mem_attach(mctx, &request->mctx);
	LOCK(&requestmgr->lock);
	if (requestmgr->exiting) {
		UNLOCK(&requestmgr->lock);
		result = ISC_R_SHUTTINGDOWN;
		goto cleanup;
	}
	requestmgr_attach(requestmgr, &request->requestmgr);
	request->hash = mgr_gethash(requestmgr);
	request->magic = REQUEST_MAGIC;
	ISC_LIST_APPEND(requestmgr->requests, request, link);
	UNLOCK(&requestmgr->lock);

	isc_interval_set(&interval, timeout, 0);
	result = isc_time_nowplusinterval(&expires, &interval);
	if (result != ISC_R_SUCCESS)
		goto unlink;

	result = isc_timer_reset(request->timer, isc_timertype_once,
				 &expires, NULL, ISC_FALSE);
	if (result != ISC_R_SUCCESS)
		goto unlink;

	if ((options & DNS_REQUESTOPT_TCP) != 0) {
		result = isc_socket_connect(socket, address, task,
					    req_connected, request);
		if (result != ISC_R_SUCCESS)
			goto unlink;
		request->flags |= DNS_REQUEST_F_CONNECTING|DNS_REQUEST_F_TCP;
	} else {
		result = req_send(request, task, address);
		if (result != ISC_R_SUCCESS)
			goto unlink;
	}

	req_log(ISC_LOG_DEBUG(3), "dns_request_create: request %p", request);
	*requestp = request;
	return (ISC_R_SUCCESS);

 unlink:
	LOCK(&requestmgr->lock);
	ISC_LIST_UNLINK(requestmgr->requests, request, link);
	UNLOCK(&requestmgr->lock);

 cleanup:
	if (request->requestmgr != NULL)
		requestmgr_detach(&request->requestmgr);
	if (request->dispentry != NULL)
		dns_dispatch_removeresponse(&request->dispentry, NULL);
	if (request->dispatch != NULL)
		dns_dispatch_detach(&request->dispatch);
	if (request->event != NULL)
		isc_event_free((isc_event_t **)&request->event);
	if (request->query != NULL)
		isc_buffer_free(&request->query);
	if (request->timer != NULL)
		isc_timer_detach(&request->timer);
	if (tclone != NULL)
		isc_task_detach(&tclone);
	if (request->mctx != NULL)
		isc_mem_detach(&request->mctx);
	isc_mem_put(mctx, request, sizeof *request);
	req_log(ISC_LOG_DEBUG(3), "dns_request_create: failed %s", 
		dns_result_totext(result));
	return (result);
}

static isc_result_t
req_render(dns_message_t *message, isc_buffer_t **bufferp, isc_mem_t *mctx) {
	isc_buffer_t *buf1 = NULL;
	isc_buffer_t *buf2 = NULL;
	isc_result_t result;
	isc_region_t r;

	REQUIRE(bufferp != NULL && *bufferp == NULL);

	req_log(ISC_LOG_DEBUG(3), "request_render");

	/*
	 * Create buffer able to hold largest possible message.
	 */
	result = isc_buffer_allocate(mctx, &buf1, 65535);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Render message.
	 */
	result = dns_message_renderbegin(message, buf1);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_QUESTION, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_ANSWER, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_AUTHORITY, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_ADDITIONAL, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_renderend(message);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Copy rendered message to exact sized buffer.
	 */
	isc_buffer_usedregion(buf1, &r);
	result = isc_buffer_allocate(mctx, &buf2, r.length +
				     ((r.length > 512) ? 2 : 0));
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	if (r.length > 512) {
		isc_buffer_putuint16(buf2, (isc_uint16_t)r.length);
	}
	result = isc_buffer_copyregion(buf2, &r);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Cleanup and return.
	 */
	isc_buffer_free(&buf1);
	*bufferp = buf2;
	return (ISC_R_SUCCESS);

 cleanup:
	dns_message_renderreset(message);
	if (buf1 != NULL)
		isc_buffer_free(&buf1);
	if (buf2 != NULL)
		isc_buffer_free(&buf2);
	return (result);
}

isc_result_t
dns_request_cancel(dns_request_t *request) {
	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "dns_request_cancel: request %p", request);

	REQUIRE(VALID_REQUEST(request));

	LOCK(&request->requestmgr->locks[request->hash]);
	if (!DNS_REQUEST_CANCELED(request)) {
		req_cancel(request);
		req_sendevent(request, ISC_R_CANCELED);
	}
	UNLOCK(&request->requestmgr->locks[request->hash]);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_request_getresponse(dns_request_t *request, dns_message_t *message,
			isc_boolean_t preserve_order)
{
	REQUIRE(VALID_REQUEST(request));
	REQUIRE(request->answer != NULL);

	req_log(ISC_LOG_DEBUG(3), "dns_request_getresponse: request %p",
		request);

	dns_message_setquerytsig(message, request->tsig);
	dns_message_settsigkey(message, request->tsigkey);
	return (dns_message_parse(message, request->answer, preserve_order));
}

isc_boolean_t
dns_request_usedtcp(dns_request_t *request) {
	REQUIRE(VALID_REQUEST(request));

	return (ISC_TF((request->flags & DNS_REQUEST_F_TCP) != 0));
}

void
dns_request_destroy(dns_request_t **requestp) {
	dns_request_t *request;
	isc_boolean_t need_destroy = ISC_FALSE;
	
	REQUIRE(requestp != NULL && VALID_REQUEST(*requestp));

	request = *requestp;

	req_log(ISC_LOG_DEBUG(3), "dns_request_destroy: request %p", request);

	LOCK(&request->requestmgr->locks[request->hash]);
	LOCK(&request->requestmgr->lock);
	ISC_LIST_UNLINK(request->requestmgr->requests, request, link);
	UNLOCK(&request->requestmgr->lock);
	if (!DNS_REQUEST_CONNECTING(request))
		need_destroy = ISC_TRUE;
	UNLOCK(&request->requestmgr->locks[request->hash]);

	if (need_destroy)
		req_destroy(request);

	*requestp = NULL;
}

/***
 *** Private: request.
 ***/

static void
req_connected(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	isc_result_t result;
	dns_request_t *request = event->ev_arg;

	REQUIRE(event->ev_type == ISC_SOCKEVENT_CONNECT);
	REQUIRE(VALID_REQUEST(request));
	REQUIRE(DNS_REQUEST_CONNECTING(request));

	req_log(ISC_LOG_DEBUG(3), "req_connected: request %p", request);

	request->flags &= ~DNS_REQUEST_F_CONNECTING;

	if (DNS_REQUEST_CANCELED(request)) {
		req_destroy(request);
	} else {
		result = sevent->result;
		if (result == ISC_R_SUCCESS)
			result = req_send(request, task, NULL);
			
		if (sevent->result != ISC_R_SUCCESS)
			dns_request_cancel(request);
	}
	isc_event_free(&event);
}

static void
req_senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	dns_request_t *request = event->ev_arg;

	REQUIRE(event->ev_type == ISC_SOCKEVENT_SENDDONE);
	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "req_senddone: request %p", request);

	(void)task;

	if (sevent->result != ISC_R_SUCCESS)
		dns_request_cancel(request);

	isc_event_free(&event);
}

static void
req_response(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	dns_request_t *request = event->ev_arg;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	isc_region_t r;

	REQUIRE(VALID_REQUEST(request));
	REQUIRE(event->ev_type == DNS_EVENT_DISPATCH);

	UNUSED(task);
	
	req_log(ISC_LOG_DEBUG(3), "req_response: request %p: %s", request,
		dns_result_totext(devent->result));

	LOCK(&request->requestmgr->locks[request->hash]);
	result = devent->result;
	if (result != ISC_R_SUCCESS)
		goto done;

	/*
	 * Copy buffer to request.
	 */
	isc_buffer_usedregion(&devent->buffer, &r);
	result = isc_buffer_allocate(request->mctx, &request->answer,
				     r.length);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = isc_buffer_copyregion(request->answer, &r);
	if (result != ISC_R_SUCCESS)
		isc_buffer_free(&request->answer);
 done:
	/*
	 * Cleanup.
	 */
	dns_dispatch_removeresponse(&request->dispentry, &devent);
	req_cancel(request);
	/*
	 * Send completion event.
	 */
	req_sendevent(request, result);
	UNLOCK(&request->requestmgr->locks[request->hash]);
}

static void
req_timeout(isc_task_t *task, isc_event_t *event) {
	dns_request_t *request = event->ev_arg;
	
	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "req_timeout: request %p", request);

	UNUSED(task);
	LOCK(&request->requestmgr->locks[request->hash]);
	req_cancel(request);
	req_sendevent(request, ISC_R_TIMEDOUT);
	UNLOCK(&request->requestmgr->locks[request->hash]);
	isc_event_free(&event);
}

static void
req_sendevent(dns_request_t *request, isc_result_t result) {
	isc_task_t *task;

	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "req_sendevent: request %p", request);

	/*
	 * Lock held by caller.
	 */
	task = request->event->ev_sender;
	request->event->ev_sender = request;
	request->event->result = result;
	isc_task_sendanddetach(&task, (isc_event_t **)&request->event);
}

static void
req_destroy(dns_request_t *request) {
	isc_mem_t *mctx;

	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "req_destroy: request %p", request);

	request->magic = 0;
	if (request->query != NULL)
		isc_buffer_free(&request->query);
	if (request->answer != NULL)
		isc_buffer_free(&request->answer);
	if (request->event != NULL)
		isc_event_free((isc_event_t **)&request->event);
	if (request->dispentry != NULL)
		dns_dispatch_removeresponse(&request->dispentry, NULL);
	if (request->dispatch != NULL)
		dns_dispatch_detach(&request->dispatch);
	if (request->timer != NULL)
		isc_timer_detach(&request->timer);
	if (request->tsig != NULL)
		isc_buffer_free(&request->tsig);
	requestmgr_detach(&request->requestmgr);
	mctx = request->mctx;
	isc_mem_put(mctx, request, sizeof(*request));
	isc_mem_detach(&mctx);
}

static void
req_cancel(dns_request_t *request) {
	isc_socket_t *socket;

	REQUIRE(VALID_REQUEST(request));

	req_log(ISC_LOG_DEBUG(3), "req_cancel: request %p", request);

	/*
	 * Lock held by caller.
	 */
	request->flags |= DNS_REQUEST_F_CANCELED;

	if (request->timer != NULL)
		isc_timer_detach(&request->timer);
	if (request->dispentry != NULL)
		dns_dispatch_removeresponse(&request->dispentry, NULL);
	if (DNS_REQUEST_CONNECTING(request)) {
		socket = dns_dispatch_getsocket(request->dispatch);
		isc_socket_cancel(socket, NULL, ISC_SOCKCANCEL_CONNECT);
	}
	dns_dispatch_detach(&request->dispatch);
}

static void
req_log(int level, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		       DNS_LOGMODULE_REQUEST, level, fmt, ap);
	va_end(ap);
}
