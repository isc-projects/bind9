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

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/event.h>
#include <isc/net.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/message.h>
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
	isc_int32_t		magic;
	isc_mem_t		*mctx;
	isc_task_t		*task;
	isc_taskaction_t	action;
	void			*action_arg;
	isc_buffer_t		*query;
	isc_buffer_t		*answer;
	dns_requestevent_t	*event;
	dns_dispentry_t		*dispentry;
	dns_messageid_t		id;
};

/***
 *** Forward
 ***/

static void destroy(dns_requestmgr_t *requestmgr);
static void send_shutdown_events(dns_requestmgr_t *requestmgr);
static isc_result_t render(dns_message_t *message, isc_buffer_t **buffer,
			   isc_mem_t *mctx);
static void senddone(isc_task_t *task, isc_event_t *event);
static void response(isc_task_t *task, isc_event_t *event);

/***
 *** Public
 ***/

isc_result_t
dns_requestmgr_create(isc_mem_t *mctx, isc_timermgr_t *timermgr,
		      dns_dispatch_t *dispatchv4, dns_dispatch_t *dispatchv6,
		      dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_socket_t *socket;
	isc_result_t result;

	REQUIRE(requestmgrp != NULL && *requestmgrp == NULL);
	if (dispatchv4 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv4);
		REQUIRE(isc_socket_gettype(socket) == PF_INET);
	}
	if (dispatchv6 != NULL) {
		socket = dns_dispatch_getsocket(dispatchv6);
		REQUIRE(isc_socket_gettype(socket) == PF_INET6);
	}
	REQUIRE(timermgr != NULL);

	requestmgr = isc_mem_get(mctx, sizeof(*requestmgr));
	if (requestmgr == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&requestmgr->lock);
	if (result != DNS_R_SUCCESS) {
		isc_mem_put(mctx, requestmgr, sizeof(*requestmgr));
		return (result);
	}
	requestmgr->timermgr = timermgr;
	requestmgr->dispatchv4 = NULL;
	if (dispatchv4 != NULL)
		dns_dispatch_attach(dispatchv4, &requestmgr->dispatchv4);
	requestmgr->dispatchv6 = NULL;
	if (dispatchv6 != NULL)
		dns_dispatch_attach(dispatchv6, &requestmgr->dispatchv6);
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

	LOCK(&source->lock);
	REQUIRE(!source->exiting);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);
	UNLOCK(&source->lock);

	*targetp = source;
}

void
dns_requestmgr_detach(dns_requestmgr_t **requestmgrp) {
	dns_requestmgr_t *requestmgr;
	isc_boolean_t need_destroy = ISC_FALSE;

	REQUIRE(requestmgrp != NULL);
	requestmgr = *requestmgrp;
	REQUIRE(VALID_REQUESTMGR(requestmgr));

	LOCK(&requestmgr->lock);
	INSIST(requestmgr->references > 0);
	requestmgr->references--;
	if (requestmgr->references == 0) {
		INSIST(requestmgr->exiting);
		need_destroy = ISC_TRUE;
	}
	UNLOCK(&requestmgr->lock);

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
		ISC_LIST_UNLINK(requestmgr->whenshutdown, event, link);
		etask = event->sender;
		event->sender = requestmgr;
		isc_task_sendanddetach(&etask, &event);
	}
}

static void
destroy(dns_requestmgr_t *requestmgr) {
	REQUIRE(requestmgr->references == 0);
	isc_mutex_destroy(&requestmgr->lock);
	if (requestmgr->dispatchv4 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv4);
	if (requestmgr->dispatchv4 != NULL)
		dns_dispatch_detach(&requestmgr->dispatchv4);
	requestmgr->magic = 0;
	isc_mem_put(requestmgr->mctx, requestmgr, sizeof *requestmgr);
}

isc_result_t
dns_request_create(dns_requestmgr_t *requestmgr, dns_message_t *message,
		   isc_sockaddr_t *address, unsigned int options,
		   unsigned int timeout, isc_task_t *task,
		   isc_taskaction_t action, void *arg,
		   dns_request_t **requestp)
{
	dns_request_t *request = NULL;
	dns_requestevent_t *event = NULL;
	dns_message_t *answer = NULL;
	dns_dispatch_t *dispatch = NULL;
	isc_buffer_t *query = NULL;
	isc_task_t *tclone = NULL;
	isc_socket_t *socket = NULL;
	isc_result_t result;
	isc_mem_t *mctx;
	isc_region_t r;

	REQUIRE(VALID_REQUESTMGR(requestmgr));
	REQUIRE(message != NULL);
	REQUIRE(address != NULL);
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);
	REQUIRE(requestp != NULL && *requestp == NULL);
	REQUIRE(timeout > 0);

	mctx = requestmgr->mctx;

	request = isc_mem_get(mctx, sizeof(*request));
	if (request == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	event = (dns_requestevent_t *)
		isc_event_allocate(mctx, task, DNS_EVENT_REQUESTDONE,
				   action, arg, sizeof (dns_requestevent_t));
	if (event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	isc_task_attach(task, &tclone);
	event->sender = task;
	event->request = request;
	event->result = ISC_R_FAILURE;

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &answer);
	if (result == DNS_R_USETCP) {
		options |= DNS_REQUESTOPT_USETCP;
		result = ISC_R_SUCCESS;
	}
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	
	if ((options & DNS_REQUESTOPT_USETCP) != 0) {
		/* result = isc_socket_create(requestmgr->socketmgr,
					   isc_sockaddr_pf(address),
					   isc_sockettype_tcp, &socket); */
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		result = dns_dispatch_create(mctx, socket, task,
					     4096, 2, 1, 1, 3, NULL,
					     &dispatch);
		isc_socket_detach(&socket);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	} else {
		switch (isc_sockaddr_pf(address)) {
		case PF_INET:
			dns_dispatch_attach(requestmgr->dispatchv4, &dispatch);
			break;
		case PF_INET6:
			dns_dispatch_attach(requestmgr->dispatchv6, &dispatch);
			break;
		default:
			result = DNS_R_NOTIMPLEMENTED;
			goto cleanup;
		}
	}
	result = dns_dispatch_addresponse(dispatch, address, task,
					  response, request, &request->id,
					  &request->dispentry);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	message->id = request->id;
	result = render(message, &query, mctx);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	request->mctx = mctx;
	request->query = query;
	request->answer = NULL;
	request->event = event;
	request->magic = REQUEST_MAGIC;

	isc_buffer_used(query, &r);
	result = isc_socket_sendto(socket, &r, task, senddone,
				   request, address, NULL);
						
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	return (ISC_R_SUCCESS);

 cleanup:
	if (request != NULL)
		isc_mem_put(mctx, request, sizeof *request);
	if (event != NULL)
		isc_event_free((isc_event_t **)&event);
	if (query != NULL)
		isc_buffer_free(&query);
	if (answer != NULL)
		dns_message_destroy(&answer);
	if (tclone != NULL)
		isc_task_detach(&tclone);
	return (result);
}

static isc_result_t
render(dns_message_t *message, isc_buffer_t **bufferp, isc_mem_t *mctx) {
	isc_buffer_t *buf1 = NULL;
	isc_buffer_t *buf2 = NULL;
	isc_result_t result;
	isc_region_t r;

	REQUIRE(bufferp != NULL && *bufferp == NULL);

	/*
	 * Create buffer able to hold largest possible message.
	 */
	result = isc_buffer_allocate(mctx, &buf1, 65535,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Render message.
	 */
	result = dns_message_renderbegin(message, buf1);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_QUESTION, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_ANSWER, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_AUTHORITY, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(message, DNS_SECTION_ADDITIONAL, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_renderend(message);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	/*
	 * Copy rendered message to exact sized buffer.
	 */
	isc_buffer_used(buf1, &r);
	result = isc_buffer_allocate(mctx, &buf2, r.length +
				     ((r.length > 512) ? 2 : 0),
				     ISC_BUFFERTYPE_BINARY);
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
	if (buf1 != NULL)
		isc_buffer_free(&buf1);
	if (buf2 != NULL)
		isc_buffer_free(&buf2);
	return (result);
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
	UNUSED(request);

	return (ISC_R_NOTIMPLEMENTED);
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
	REQUIRE(VALID_REQUEST(request));
	REQUIRE(request->answer != NULL);

	return (dns_message_parse(message, request->answer, ISC_TRUE));
}

void
dns_request_destroy(dns_request_t **requestp) {
	UNUSED(requestp);
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

static void
senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	dns_request_t *request = event->arg;

	REQUIRE(event->type == ISC_SOCKEVENT_SENDDONE);

	(void)task;

	/*
	if (sevent->result != ISC_R_SUCCESS)
		fctx_cancelquery(&query, NULL, NULL, ISC_FALSE);
	 */

	isc_event_free(&event);
}

static void
response(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	dns_request_t *request = event->arg;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	dns_message_t *message;

	REQUIRE(VALID_REQUEST(request));
	REQUIRE(event->type == DNS_EVENT_DISPATCH);

	(void)task;
	if (devent->result != ISC_R_SUCCESS)
		goto done;

	/*
	 * copy buffer
	 */

 done:
	return;
}


static void
timeout(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	dns_request_t *request = event->arg;
	
	if (event->type == ISC_TIMEREVENT_LIFE) {
	} else {
	}

	isc_event_free(&event);
}
