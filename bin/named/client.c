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
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/message.h>

#include <named/client.h>
#include <named/query.h>

#include "../../isc/util.h"		/* XXX */

#define NS_CLIENT_TRACE
#ifdef NS_CLIENT_TRACE
#include <stdio.h>
#define CTRACE(m)	printf("client %p: %s\n", client, (m))
#define MTRACE(m)	printf("clientmgr %p: %s\n", manager, (m))
#else
#define CTRACE(m)
#define MTRACE(m)
#endif

#define SEND_BUFFER_SIZE		512

struct ns_clientmgr {
	/* Unlocked. */
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_taskmgr_t *			taskmgr;
	isc_timermgr_t *		timermgr;
	isc_mutex_t			lock;
	/* Locked by lock. */
	isc_boolean_t			exiting;
	unsigned int			nclients;
	ISC_LIST(ns_client_t)		clients;
};

#define MANAGER_MAGIC			0x4E53436DU	/* NSCm */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == MANAGER_MAGIC)


static void clientmgr_destroy(ns_clientmgr_t *manager);


/***
 *** Client
 ***/

/*
 * Important note!
 *
 * All client state changes, other than that from idle to listening, occur
 * as a result of events.  This guarantees serialization and avoids the
 * need for locking.
 *
 * If a routine is ever created that allows someone other than the client's
 * task to change the client, then the client will have to be locked.
 */

static inline void
client_free(ns_client_t *client) {
	dns_dispatchevent_t **deventp;

	CTRACE("free");

	isc_mempool_destroy(&client->sendbufs);
	dns_message_destroy(&client->message);
	isc_timer_detach(&client->timer);
	if (client->dispentry != NULL) {
		if (client->dispevent != NULL)
			deventp = &client->dispevent;
		else
			deventp = NULL;
		dns_dispatch_removerequest(client->dispatch,
					   &client->dispentry,
					   deventp);
	}
	if (client->dispatch != NULL)
		dns_dispatch_detach(&client->dispatch);
	isc_task_detach(&client->task);
	client->magic = 0;

	isc_mem_put(client->manager->mctx, client, sizeof *client);
}

void
ns_client_destroy(ns_client_t *client) {
	ns_clientmgr_t *manager;
	isc_boolean_t need_clientmgr_destroy = ISC_FALSE;
	
	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("destroy");

	manager = client->manager;

	LOCK(&manager->lock);

	INSIST(manager->nclients > 0);
	manager->nclients--;
	if (manager->nclients == 0 && manager->exiting)
		need_clientmgr_destroy = ISC_TRUE;
	ISC_LIST_UNLINK(manager->clients, client, link);

	UNLOCK(&manager->lock);

	client_free(client);

	if (need_clientmgr_destroy)
		clientmgr_destroy(manager);
}

static void
client_shutdown(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;

	REQUIRE(event != NULL);
	REQUIRE(event->type == ISC_TASKEVENT_SHUTDOWN);
	client = event->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);

	CTRACE("shutdown");

	ns_client_destroy(client);

	isc_event_free(&event);
}

void
ns_client_next(ns_client_t *client, isc_result_t result) {

	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(client->state == ns_clientstate_listening ||
		client->state == ns_clientstate_working);

	CTRACE("next");

	/*
	 * XXXRTH  If result != ISC_R_SUCCESS:
	 * 		Log result if there is interest in doing so.
	 *		If this is a TCP client, close the connection.
	 */
	(void)result;

	dns_message_reset(client->message, DNS_MESSAGE_INTENTPARSE);
	if (client->dispevent != NULL) {
		dns_dispatch_freeevent(client->dispatch, client->dispentry,
				       &client->dispevent);
		client->state = ns_clientstate_listening;
	}
}

static void client_send(ns_client_t *client);

static void
client_senddone(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->common.type == ISC_SOCKEVENT_SENDDONE);
	client = sevent->common.arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);

	CTRACE("senddone");

	INSIST(client->nsends > 0);
	client->nsends--;
	isc_mempool_put(client->sendbufs, sevent->region.base);

	isc_event_free(&event);

	/*
	 * If all of its sendbufs buffers were busy, the client might be
	 * waiting for one to become available.
	 */
	if (client->state == ns_clientstate_waiting) {
		client->state = ns_clientstate_working;
		client_send(client);
		return;
	}
	/* XXXRTH need to add exit draining mode. */
}

static void
client_send(ns_client_t *client) {
	isc_result_t result;
	unsigned char *data;
	isc_buffer_t buffer;
	isc_region_t r;

	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("send");

	data = isc_mempool_get(client->sendbufs);
	if (data == NULL) {
		CTRACE("no buffers available");
		if (client->nsends > 0) {
			/*
			 * We couldn't get memory, but there is at least one
			 * send outstanding.  We arrange to be restarted when a
			 * send completes.
			 */
			CTRACE("waiting");
			INSIST(client->state == ns_clientstate_working);
			client->state = ns_clientstate_waiting;
		} else
			ns_client_next(client, ISC_R_NOMEMORY);
		return;
	}

	isc_buffer_init(&buffer, data, SEND_BUFFER_SIZE,
			ISC_BUFFERTYPE_BINARY);
	result = dns_message_renderbegin(client->message, &buffer);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_rendersection(client->message,
					   DNS_SECTION_QUESTION, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_renderend(client->message);
	if (result != ISC_R_SUCCESS)
		goto done;
	isc_buffer_used(&buffer, &r);
	/* XXXRTH this only works for UDP clients. */
	CTRACE("sendto");
	result = isc_socket_sendto(dns_dispatch_getsocket(client->dispatch),
				   &r, client->task, client_senddone, client,
				   &client->dispevent->addr);
	if (result == ISC_R_SUCCESS)
		client->nsends++;

 done:
	if (result != ISC_R_SUCCESS)
		isc_mempool_put(client->sendbufs, data);

	ns_client_next(client, result);
}
	
void
ns_client_error(ns_client_t *client, isc_result_t result) {
	dns_rcode_t rcode;

	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("error");

	rcode = dns_result_torcode(result);

	result = dns_message_reply(client->message, ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		ns_client_next(client, result);
		return;
	}
	client->message->rcode = rcode;
	client_send(client);
}

static void
client_recv(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	isc_result_t result;

	REQUIRE(devent != NULL);
	REQUIRE(devent->type == DNS_EVENT_DISPATCH);
	client = devent->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);
	REQUIRE(client->dispentry != NULL);

	CTRACE("recv");

	client->dispevent = devent;
	if (devent->result != ISC_R_SUCCESS) {
		ns_client_destroy(client);
		return;
	}

	client->state = ns_clientstate_working;
	result = dns_message_parse(client->message, &devent->buffer);
	if (result != ISC_R_SUCCESS) {
		ns_client_error(client, result);
		return;
	}
	INSIST((client->message->flags & DNS_MESSAGEFLAG_QR) == 0);

	/*
	 * Dispatch the request.
	 */
	switch (client->message->opcode) {
#if 0
	case dns_opcode_query:
		CTRACE("query");
		ns_query_start(client);
		break;
#endif
	case dns_opcode_iquery:
		CTRACE("iquery");
		ns_client_error(client, DNS_R_REFUSED);
	default:
		CTRACE("unknown opcode");
		ns_client_error(client, DNS_R_NOTIMP);
	}
}

static void
client_timeout(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;

	REQUIRE(event != NULL);
	REQUIRE(event->type == ISC_TIMEREVENT_LIFE ||
		event->type == ISC_TIMEREVENT_IDLE);
	client = event->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);
	REQUIRE(client->timer != NULL);

	CTRACE("timeout");

	isc_event_free(&event);

	ns_client_next(client, ISC_R_TIMEDOUT);
}

static isc_result_t
client_create(ns_clientmgr_t *manager, ns_clienttype_t type,
	      ns_client_t **clientp)
{
	ns_client_t *client;
	isc_result_t result;

	/*
	 * Caller must be holding the manager lock.
	 *
	 * Note: creating a client does not add the client to the manager's
	 * client list.  The caller is responsible for that.
	 */

	REQUIRE(clientp != NULL && *clientp == NULL);

	client = isc_mem_get(manager->mctx, sizeof *client);
	if (client == NULL)
		return (ISC_R_NOMEMORY);

	client->task = NULL;
	result = isc_task_create(manager->taskmgr, manager->mctx, 0,
				 &client->task);
	if (result != ISC_R_SUCCESS)
		goto cleanup_client;
	result = isc_task_onshutdown(client->task, client_shutdown, client);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	client->timer = NULL;
	result = isc_timer_create(manager->timermgr, isc_timertype_inactive,
				  NULL, NULL, client->task, client_timeout,
				  client, &client->timer);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	client->message = NULL;
	result = dns_message_create(manager->mctx, DNS_MESSAGE_INTENTPARSE,
				    &client->message);
	if (result != ISC_R_SUCCESS)
		goto cleanup_timer;

	/* XXXRTH  Hardwired constants */
	client->sendbufs = NULL;
	result = isc_mempool_create(manager->mctx, SEND_BUFFER_SIZE,
				    &client->sendbufs);
	if (result != ISC_R_SUCCESS)
		goto cleanup_message;
	isc_mempool_setfreemax(client->sendbufs, 3);
	isc_mempool_setmaxalloc(client->sendbufs, 3);

	client->manager = manager;
	client->type = type;
	client->state = ns_clientstate_idle;
	client->attributes = 0;
	client->dispatch = NULL;
	client->dispentry = NULL;
	client->dispevent = NULL;
	client->nsends = 0;
	ISC_LINK_INIT(client, link);
	client->magic = NS_CLIENT_MAGIC;

	CTRACE("create");

	*clientp = client;

	return (ISC_R_SUCCESS);

 cleanup_message:
	dns_message_destroy(&client->message);

 cleanup_timer:
	isc_timer_detach(&client->timer);

 cleanup_task:
	isc_task_detach(&client->task);

 cleanup_client:
	isc_mem_put(manager->mctx, client, sizeof *client);

	return (result);
}


/***
 *** Client Manager
 ***/

static void
clientmgr_destroy(ns_clientmgr_t *manager) {
	REQUIRE(manager->nclients == 0);
	REQUIRE(ISC_LIST_EMPTY(manager->clients));

	MTRACE("clientmgr_destroy");

	manager->magic = 0;
	isc_mem_put(manager->mctx, manager, sizeof *manager);
}

isc_result_t
ns_clientmgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		    isc_timermgr_t *timermgr, ns_clientmgr_t **managerp)
{
	ns_clientmgr_t *manager;
	isc_result_t result;

	manager = isc_mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&manager->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_manager;
	
	manager->mctx = mctx;
	manager->taskmgr = taskmgr;
	manager->timermgr = timermgr;
	manager->exiting = ISC_FALSE;
	manager->nclients = 0;
	ISC_LIST_INIT(manager->clients);
	manager->magic = MANAGER_MAGIC;

	MTRACE("create");

	*managerp = manager;

	return (ISC_R_SUCCESS);

 cleanup_manager:
	isc_mem_put(manager->mctx, manager, sizeof *manager);

	return (result);
}

void
ns_clientmgr_destroy(ns_clientmgr_t **managerp) {
	ns_clientmgr_t *manager;
	ns_client_t *client;
	isc_boolean_t need_destroy = ISC_FALSE;
	
	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	MTRACE("destroy");

	LOCK(&manager->lock);

	manager->exiting = ISC_TRUE;

	for (client = ISC_LIST_HEAD(manager->clients);
	     client != NULL;
	     client = ISC_LIST_NEXT(client, link))
		isc_task_shutdown(client->task);

	if (ISC_LIST_EMPTY(manager->clients))
		need_destroy = ISC_TRUE;

	UNLOCK(&manager->lock);

	if (need_destroy)
		clientmgr_destroy(manager);

	*managerp = NULL;
}

isc_result_t
ns_clientmgr_addtodispatch(ns_clientmgr_t *manager, ns_clienttype_t type,
			   unsigned int n,
			   dns_dispatch_t *dispatch)
{
	isc_result_t result = ISC_R_SUCCESS;
	unsigned int i;
	ns_client_t *client;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(n > 0);

	MTRACE("addtodispatch");

	/*
	 * We MUST lock the manager lock for the entire client creation
	 * process.  If we didn't do this, then a client could get a
	 * shutdown event and disappear out from under us.
	 */

	LOCK(&manager->lock);

	for (i = 0; i < n; i++) {
		client = NULL;
		result = client_create(manager, type, &client);
		if (result != ISC_R_SUCCESS)
			break;
		dns_dispatch_attach(dispatch, &client->dispatch);
		result = dns_dispatch_addrequest(dispatch, client->task,
						 client_recv,
						 client, &client->dispentry);
		if (result != ISC_R_SUCCESS) {
			client_free(client);
			break;
		}
		client->state = ns_clientstate_listening;
		manager->nclients++;
		ISC_LIST_APPEND(manager->clients, client, link);
	}
	if (i != 0) {
		/*
		 * We managed to create at least one client, so we
		 * declare victory.
		 */
		result = ISC_R_SUCCESS;
	}

	UNLOCK(&manager->lock);

	return (result);
}
