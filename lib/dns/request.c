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

#include <dns/request.h>

#define REQUESTMGR_MAGIC 0x12341234U		/* XXX MPA */
#define VALID_REQUESTMGR(mgr) ((mgr) != NULL && \
			(mgr)->magic == REQUESTMGR_MAGIC)

#define REQUEST_MAGIC 0x12341235U		/* XXX MPA */
#define VALID_REQUEST(request) ((request) != NULL && \
				(request)->magic == REQUEST_MAGIC)

struct dns_requestmgr {
	isc_int32_t	magic;
	isc_mutex_t     lock;
	isc_mem_t	*mctx;

	/* locked */
	isc_int32_t	references;
	isc_timermgr_t	*timermgr;
	dns_dispatch_t	*dispatchv4;
	dns_dispatch_t  *dispatchv6;
	isc_boolean_t	exiting;
	isc_eventlist_t whenshutdown;
};

struct dns_request {
	isc_int32_t	magic;
	dns_message_t	*qmessage;
	dns_message_t	*rmessage;
	isc_task_t	task;
	isc_action_t	action;
	void *		action_arg;
}

/***
 *** Forward
 ***/

static void send_shutdown_events(dns_requestmgr_t *requestmgr);

/***
 *** Public
 ***/

isc_result_t
dns_requestmgr_create(isc_mem_t *mctx, isc_timermgr_t *timermgr,
		      dns_dispatch_t *dispatchv4, dns_dispatch_t *dispatchv6,
		      dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_socket_t socket;

	REQUIRE(requestmgrp != NULL && *requestmgrp == NULL);
	if (dispatchv4 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv4);
		REQUIRE(isc_socket_gettype(socket) == INET);
	}
	if (dispatchv6 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv6);
		REQUIRE(isc_socket_gettype(socket) == INET6);
	}
	REQUIRE(timermgr != NULL);

	requestmgr = isc_mem_get(mctx, sizeof(*requestmgr));
	if (requestmgr == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&zone->lock);
	if (result != DNS_R_SUCCESS) {
		isc_mem_put(mctx, requestmgr, sizeof(*requestmgr));
		return (result);
	}
	requestmgr->timermgr = timermgr;
	requestmgr->dispatchv4 = NULL;
	if (dispatchv4 != NULL);
		isc_dispatch_attach(dispatchv4, &requestmgr->dispatchv4);
	requestmgr->dispatchv6 = NULL;
	if (dispatchv6 != NULL)
		isc_dispatch_attach(dispatchv6, &requestmgr->dispatchv6);
	requestmgr->mctx = mctx;
	requestmgr->references = 1;	/* implict attach */
	ISC_LIST_INIT(requestmgr->whenshutdown);
	requestmgr->exiting = ISC_FALSE;
	requestmgr->magic = REQUESTMGR_MAGIC;
	*requestmgrp = requestmgr;

	return (ISC_R_SUCCESS);
}

void
dns_requestmgr_whenshutdown(dns_requestmgr_t *requestmgr, isc_task_t *task,
			    isc_event_t **eventp)
{
        isc_task_t *clone;
        isc_event_t *event;

        REQUIRE(VALID_REQUESTMGR(requestmgr));
        REQUIRE(eventp != NULL);

        event = *eventp;
        *eventp = NULL;

        LOCK(&requestmgr->lock);

        if (requestmgr->exiting) {
                /*
                 * We're already shutdown.  Send the event.
                 */
                event->sender = requestmgr;
                isc_task_send(task, &event);
        } else {
                clone = NULL;
                isc_task_attach(task, &clone);
                event->sender = clone;
                ISC_LIST_APPEND(requestmgr->whenshutdown, event, link);
	}
	UNLOCK(&requestmgr->lock);
}

void
dns_requestmgr_shutdown(dns_requestmgr_t *requestmgr) {

        REQUIRE(VALID_REQUESTMGR(requestmgr));

	LOCK(&requestmgr->lock);
	if (!requestmgr->exiting) {
		requestmgr->exiting = ISC_TRUE;
		/* XXXMPA shutdown existing requests */
		send_shutdown_events(requestmgr);
	}
	UNLOCK(&requestmgr->lock);
}

void
dns_requestmgr_attach(dns_requestmgr_t *source, dns_requestmgr_t **targetp) {

        REQUIRE(VALID_REQUESTMGR(source));
        REQUIRE(targetp != NULL && *targetp == NULL);

	LOCK(&requestmgr->lock);
	REQUIRE(!requestmgr->exiting);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);
	UNLOCK(&requestmgr->lock);

	*targetp = source;
}

void
dns_requestmgr_detach(dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_boolean_t need_destroy = ISC_FALSE;

	REQUIRE(requestmgrp != NULL);
	requestmgr = *requestmgr;
	REQUIRE(VALID_REQUESTMGR(requestmgr));

	LOCK(&requestmgr->lock);
	INSIST(requestmgr->references > 0);
	requestmgr->references--;
	if (res->references == 0) {
		INSIST(requestmgr->exiting);
		need_destroy = ISC_TRUE;
	}
	UNLOCK(&res->lock);

	if (need_destroy)
		destroy(requestmgr);

	*requestmgrp = NULL;
}

static void
send_shutdown_events(dns_requestmgr_t *requestmgr) {
	isc_event_t *event, *next_event;
	isc_task_t *etask;

	/*
	 * Caller must be holding the manager lock.
	 */
	for (event = ISC_LIST_HEAD(requestmgr->whenshutdown);
	     event != NULL;
	     event = next_event) {
		next_event = ISC_LIST_NEXT(event, link);
		ISC_LIST_UNLINK(res->whenshutdown, event, link);
		etask = event->sender;
		event->sender = requestmgr;
		isc_task_sendanddetach(&etask, &event);
	}
}

static void
destroy(dns_requestmgr_t *requestmgr) {
	REQUIRE(requestmgr->references == 0)
	isc_mutex_destroy(&requestmgr->lock);
	if (requestmgr->dispatchv4 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv4);
	if (requestmgr->dispatchv4 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv4);
	res->magic = 0;
	isc_mem_put(requestmgr->mctx, requestmgr, sizeof *requestmgr);
}

isc_result_t
dns_request_create(dns_requestmgr_t *requestmgr, dns_message_t *message,
		   isc_sockaddr_t *address, unsigned int options,
		   unsigned int timeout, isc_task_t *task,
		   isc_taskaction_t action, void *arg,
		   dns_request_t **requestp)
{
	dns_request_t *request;

	REQUIRE(VALID_REQUESTMGR(requestmgr));
	REQUIRE(message != NULL);
	REQUIRE(isc_sockaddr_t != NULL);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);
	REQUIRE(requestp != NULL && *requestp == NULL);
	REQUIRE(timeout > 0);

	request = isc_mem_get(dns_requestmgr_t->mctx, sizeof(*request));
	if (request == NULL)
		return (ISC_R_NOMEMORY);
	request->qmessage = NULL;
	request->rmessage = NULL;
	request->task = NULL;
	isc_task_attach(task, &request->task);
	request->action = action;
	request->action_arg = arg;
	request->magic = REQUEST_MAGIC;
	return (ISC_R_SUCCESS);
}

/*
 * Create and send a request.
 *
 * Notes:
 *
 *	'message' will be rendered and sent to 'address'.  If the
 *	DNS_REQUESTOPT_TCP option is set, TCP will be used.  The request
 *	will timeout after 'timeout' seconds.
 *
 *	When the request completes, successfully, due to a timeout, or
 *	because it was canceled, a completion event will be sent to 'task'.
 *
 * Requires:
 *
 *	'message' is a valid DNS message.
 *
 *	'address' is a valid sockaddr.
 *
 *	'timeout' > 0
 *
 *	'task' is a valid task.
 *
 *	requestp != NULL && *requestp == NULL
 */

isc_result_t
dns_request_cancel(dns_request_t *request) {
}
/*
 * Cancel 'request'.
 *
 * Requires:
 *
 *	'request' is a valid request.
 *
 * Ensures:
 *
 *	If the completion event for 'request' has not yet been sent, it
 *	will be sent, and the result code will be ISC_R_CANCELED.
 */

isc_result_t
dns_request_getresponse(dns_request_t *request, dns_message_t *message) {
}
/*
 * Get the response to 'request'.
 *
 * Requires:
 *
 *	'request' is a valid request for which the caller has received the
 *	completion event.
 *
 *	The result code of the completion event was ISC_R_SUCCESS.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *
 *	Any result that dns_message_parse() can return.
 */

void
dns_request_destroy(dns_request_t **requestp) {
}
/*
 * Destroy 'request'.
 *
 * Requires:
 *
 *	'request' is a valid request for which the caller has received the
 *	completion event.
 *
 * Ensures:
 *
 *	*requestp == NULL
 */
