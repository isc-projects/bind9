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

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/view.h>
#include <dns/xfrin.h>
#include <dns/zone.h>

#include <named/globals.h>
#include <named/client.h>
#include <named/log.h>
#include <named/query.h>
#include <named/server.h>
#include <named/update.h>
#include <named/notify.h>
#include <named/interfacemgr.h>

#define NS_CLIENT_TRACE
#ifdef NS_CLIENT_TRACE
#define CTRACE(m)	isc_log_write(ns_g_lctx, \
				      NS_LOGCATEGORY_CLIENT, \
				      NS_LOGMODULE_CLIENT, \
				      ISC_LOG_DEBUG(3), \
				      "client %p: %s", client, (m))
#define MTRACE(m)	isc_log_write(ns_g_lctx, \
				      NS_LOGCATEGORY_GENERAL, \
				      NS_LOGMODULE_CLIENT, \
				      ISC_LOG_DEBUG(3), \
				      "clientmgr %p: %s", manager, (m))
#endif

#define TCP_CLIENT(c)	(((c)->attributes & NS_CLIENTATTR_TCP) != 0)

#define SEND_BUFFER_SIZE		2048

struct ns_clientmgr {
	/* Unlocked. */
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_taskmgr_t *			taskmgr;
	isc_timermgr_t *		timermgr;
	isc_mutex_t			lock;
	/* Locked by lock. */
	isc_boolean_t			exiting;
	client_list_t			active; 	/* Active clients */
	client_list_t 			inactive;	/* Recycling center */
};

#define MANAGER_MAGIC			0x4E53436DU	/* NSCm */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == MANAGER_MAGIC)


static void client_read(ns_client_t *client);
static void client_accept(ns_client_t *client);
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

static void
release_quotas(ns_client_t *client) {
	if (client->tcpquota != NULL)
		isc_quota_detach(&client->tcpquota);
	if (client->recursionquota != NULL)
		isc_quota_detach(&client->recursionquota);
}

/*
 * Enter an inactive state identical to that of a newly created client.
 */
static void
deactivate(ns_client_t *client)
{
	CTRACE("deactivate");
	
	if (client->interface)
		ns_interface_detach(&client->interface);

	if (client->dispentry != NULL) {
		dns_dispatchevent_t **deventp;
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

	INSIST(client->naccepts == 0);	
	if (client->tcplistener != NULL)
		isc_socket_detach(&client->tcplistener);

	if (client->tcpmsg_valid) {
		dns_tcpmsg_invalidate(&client->tcpmsg);
		client->tcpmsg_valid = ISC_FALSE;
	}
	if (client->tcpsocket != NULL)
		isc_socket_detach(&client->tcpsocket);
	
	client->attributes = 0;	
	client->mortal = ISC_FALSE;
}

/*
 * Free a client immediately if possible, otherwise start
 * shutting it down and postpone freeing to later.
 */
static void
maybe_free(ns_client_t *client) {
	isc_boolean_t need_clientmgr_destroy = ISC_FALSE;
	ns_clientmgr_t *manager = NULL;
	
	REQUIRE(NS_CLIENT_VALID(client));

	/*
	 * When "shuttingdown" is true, either the task has received
	 * its shutdown event or no shutdown event has ever been
	 * set up.  Thus, we have no outstanding shutdown
	 * event at this point.
	 */
	REQUIRE(client->shuttingdown == ISC_TRUE);

	if (client->naccepts > 0)
		isc_socket_cancel(client->tcplistener, client->task,
				  ISC_SOCKCANCEL_ACCEPT);
	if (client->nreads > 0)
		dns_tcpmsg_cancelread(&client->tcpmsg);
	if (client->nsends > 0) {
		isc_socket_t *socket;
		if (TCP_CLIENT(client))
			socket = client->tcpsocket;
		else
			socket = dns_dispatch_getsocket(client->dispatch);
		isc_socket_cancel(socket, client->task, ISC_SOCKCANCEL_SEND);
	}

	/*
	 * We need to detach from the view early, because when shutting
	 * down the server, resolver shutdown does not begin until
	 * the view refcount goes to zero. 
	 */
	if (client->view != NULL)
		dns_view_detach(&client->view);

	if (!(client->nreads == 0 && client->naccepts == 0 &&
	      client->nsends == 0 && client->nwaiting == 0)) {
		/* Still waiting for events. */
		return;
	}
	
	/* We have received our last event. */

	deactivate(client);
	
	ns_query_free(client);
	isc_mem_put(client->mctx, client->sendbuf, SEND_BUFFER_SIZE);
	isc_timer_detach(&client->timer);
	
	if (client->opt != NULL) {
		INSIST(dns_rdataset_isassociated(client->opt));
		dns_rdataset_disassociate(client->opt);
		dns_message_puttemprdataset(client->message, &client->opt);
	}
	dns_message_destroy(&client->message);
	if (client->task != NULL)
		isc_task_detach(&client->task);
	if (client->manager != NULL) {
		manager = client->manager;
		LOCK(&manager->lock);
		ISC_LIST_UNLINK(*client->list, client, link);
		client->list = NULL;
		if (manager->exiting &&
		    (ISC_LIST_EMPTY(manager->active) &&
		     ISC_LIST_EMPTY(manager->inactive))) 
		    need_clientmgr_destroy = ISC_TRUE;
		UNLOCK(&manager->lock);
	}

	release_quotas(client);
	
	CTRACE("free");
	client->magic = 0;
	isc_mem_put(client->mctx, client, sizeof *client);
	
	if (need_clientmgr_destroy)
		clientmgr_destroy(manager);
}

/*
 * The client's task has received a shutdown event.
 */
static void
client_shutdown(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;

	REQUIRE(event != NULL);
	REQUIRE(event->type == ISC_TASKEVENT_SHUTDOWN);
	client = event->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);

	CTRACE("shutdown");

	client->shuttingdown = ISC_TRUE;
	
	if (client->shutdown != NULL)
		(client->shutdown)(client->shutdown_arg);

	maybe_free(client);

	isc_event_free(&event);
}

/*
 * Wrap up after a finished client request and prepare for
 * handling the next one.
 */
void
ns_client_next(ns_client_t *client, isc_result_t result) {

	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("next");
	INSIST(client->naccepts == 0);
	INSIST(client->nreads == 0);
	INSIST(client->nsends == 0);
	INSIST(client->lockview == NULL);

	if (client->next != NULL) {
		(client->next)(client, result);
		client->next = NULL;
	}

	/*
	 * XXXRTH  If result != ISC_R_SUCCESS:
	 * 		Log result if there is interest in doing so.
	 */

	if (client->view != NULL)
		dns_view_detach(&client->view);
	if (client->opt != NULL) {
		INSIST(dns_rdataset_isassociated(client->opt));
		dns_rdataset_disassociate(client->opt);
		dns_message_puttemprdataset(client->message, &client->opt);
	}

	client->udpsize = 512;
	dns_message_reset(client->message, DNS_MESSAGE_INTENTPARSE);

	release_quotas(client);

	if (client->mortal) {
		/*
		 * This client object is supposed to die now, but if we
		 * have fewer client objects than planned due to
		 * quota exhaustion, don't.
		 */
		isc_boolean_t need_another_client = ISC_FALSE;
		if (TCP_CLIENT(client)) {
			LOCK(&client->interface->lock);
			if (client->interface->ntcpcurrent <
			    client->interface->ntcptarget) 
				need_another_client = ISC_TRUE;
			UNLOCK(&client->interface->lock);
		} else {
			/*
			 * The UDP client quota is enforced by making
			 * requests fail rather than by not listening
			 * for new ones.  Therefore, there is always a
			 * full set of UDP clients listening.
			 */
		}
		if (! need_another_client) {
			/*
			 * We don't need this client object.  Recycle it.
			 */
			LOCK(&client->manager->lock);
			ISC_LIST_UNLINK(client->manager->active, client, link);
			deactivate(client);
			ISC_LIST_APPEND(client->manager->inactive, client, link);
			client->list = &client->manager->inactive;
			UNLOCK(&client->manager->lock);			
			return;
		}
		client->mortal = ISC_FALSE;
	}

	if (client->dispevent != NULL) {
		/*
		 * Give the processed dispatch event back to the dispatch.
		 * This tells the dispatch that we are ready to receive
		 * the next event.
		 */
		dns_dispatch_freeevent(client->dispatch, client->dispentry,
				       &client->dispevent);
	} else if (TCP_CLIENT(client)) {
		if (result == ISC_R_SUCCESS) {
			client_read(client);
		} else {
			/*
			 * There was an error processing a TCP request.
			 * It may have have left the connection out of
			 * sync.  Close the connection and listen for a
			 * new one.
			 */
			if (client->tcpsocket != NULL) {
				/*
				 * There should be no outstanding read
				 * request on the TCP socket at this point,
				 * therefore invalidating the tcpmsg is safe.
				 */
				INSIST(client->nreads == 0);
				INSIST(client->tcpmsg_valid == ISC_TRUE);
				dns_tcpmsg_invalidate(&client->tcpmsg);
				client->tcpmsg_valid = ISC_FALSE;
				isc_socket_detach(&client->tcpsocket);
			}
			client_accept(client);
		}
	}
}

static void
client_senddone(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;
	isc_socketevent_t *sevent = (isc_socketevent_t *) event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->type == ISC_SOCKEVENT_SENDDONE);
	client = sevent->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);

	CTRACE("senddone");

	INSIST(client->nsends > 0);
	client->nsends--;

	isc_event_free(&event);

	if (client->shuttingdown) {
		maybe_free(client);
		return;
	}

	ns_client_next(client, ISC_R_SUCCESS);
}

void
ns_client_send(ns_client_t *client) {
	isc_result_t result;
	unsigned char *data;
	isc_buffer_t buffer;
	isc_buffer_t tcpbuffer;
	isc_region_t r;
	isc_socket_t *socket;
	isc_sockaddr_t *address;
	unsigned int bufsize = 512;

	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("send");

	if ((client->attributes & NS_CLIENTATTR_RA) != 0)
		client->message->flags |= DNS_MESSAGEFLAG_RA;
	
	data = client->sendbuf;
	/*
	 * XXXRTH  The following doesn't deal with TSIGs, TCP buffer resizing,
	 *         or ENDS1 more data packets.
	 */
	if (TCP_CLIENT(client)) {
		/*
		 * XXXRTH  "tcpbuffer" is a hack to get things working.
		 */
		isc_buffer_init(&tcpbuffer, data, SEND_BUFFER_SIZE,
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_init(&buffer, data + 2, SEND_BUFFER_SIZE - 2,
				ISC_BUFFERTYPE_BINARY);
	} else {
		if (client->udpsize < SEND_BUFFER_SIZE)
			bufsize = client->udpsize;
		else
			bufsize = SEND_BUFFER_SIZE;
		isc_buffer_init(&buffer, data, bufsize, ISC_BUFFERTYPE_BINARY);
	}

	result = dns_message_renderbegin(client->message, &buffer);
	if (result != ISC_R_SUCCESS)
		goto done;
	if (client->opt != NULL) {
		result = dns_message_setopt(client->message, client->opt);
		if (result != ISC_R_SUCCESS)
			goto done;
		/*
		 * XXXRTH dns_message_setopt() should probably do this...
		 */
		client->opt = NULL;
	}
	result = dns_message_rendersection(client->message,
					   DNS_SECTION_QUESTION, 0);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_rendersection(client->message,
					   DNS_SECTION_ANSWER, 0);
	if (result == ISC_R_NOSPACE) {
		client->message->flags |= DNS_MESSAGEFLAG_TC;
		goto renderend;
	}
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_rendersection(client->message,
					   DNS_SECTION_AUTHORITY, 0);
	if (result == ISC_R_NOSPACE) {
		client->message->flags |= DNS_MESSAGEFLAG_TC;
		goto renderend;
	}
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_rendersection(client->message,
					   DNS_SECTION_ADDITIONAL, 0);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOSPACE)
		goto done;
 renderend:
	result = dns_message_renderend(client->message);
	if (result != ISC_R_SUCCESS)
		goto done;

	if (TCP_CLIENT(client)) {
		socket = client->tcpsocket;
		address = NULL;
		isc_buffer_used(&buffer, &r);
		isc_buffer_putuint16(&tcpbuffer, (isc_uint16_t)r.length);
		isc_buffer_add(&tcpbuffer, r.length);
		isc_buffer_used(&tcpbuffer, &r);
	} else {
		socket = dns_dispatch_getsocket(client->dispatch);
		address = &client->dispevent->addr;
		isc_buffer_used(&buffer, &r);
	}
	CTRACE("sendto");
	result = isc_socket_sendto(socket, &r, client->task, client_senddone,
				   client, address, NULL);
	if (result == ISC_R_SUCCESS) {
		client->nsends++;
		return;
	}
 done:
	ns_client_next(client, result);
}
	
void
ns_client_error(ns_client_t *client, isc_result_t result) {
	dns_rcode_t rcode;
	dns_message_t *message;

	REQUIRE(NS_CLIENT_VALID(client));

	CTRACE("error");

	message = client->message;
	rcode = dns_result_torcode(result);

	/*
	 * message may be an in-progress reply that we had trouble
	 * with, in which case QR will be set.  We need to clear QR before
	 * calling dns_message_reply() to avoid triggering an assertion.
	 */
	message->flags &= ~DNS_MESSAGEFLAG_QR;
	/*
	 * AA and AD shouldn't be set.
	 */
	message->flags &= ~(DNS_MESSAGEFLAG_AA | DNS_MESSAGEFLAG_AD);
	result = dns_message_reply(message, ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		/*
		 * It could be that we've got a query with a good header,
		 * but a bad question section, so we try again with
		 * want_question_section set to ISC_FALSE.
		 */
		result = dns_message_reply(message, ISC_FALSE);
		if (result != ISC_R_SUCCESS) {
			/*
			 * There's no hope of replying to this request.
			 *
			 * XXXRTH  Mark this client to that if it is a
			 * TCP session, the session will be closed.
			 */
			ns_client_next(client, result);
			return;
		}
	}
	message->rcode = rcode;
	ns_client_send(client);
}

static inline isc_result_t
client_addopt(ns_client_t *client) {
	dns_rdataset_t *rdataset;
	dns_rdatalist_t *rdatalist;
	dns_rdata_t *rdata;
	isc_result_t result;

	REQUIRE(client->opt == NULL);	/* XXXRTH free old. */

	rdatalist = NULL;
	result = dns_message_gettemprdatalist(client->message, &rdatalist);
	if (result != ISC_R_SUCCESS)
		return (result);
	rdata = NULL;
	result = dns_message_gettemprdata(client->message, &rdata);
	if (result != ISC_R_SUCCESS)
		return (result);
	rdataset = NULL;
	result = dns_message_gettemprdataset(client->message, &rdataset);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_rdataset_init(rdataset);

	rdatalist->type = dns_rdatatype_opt;
	rdatalist->covers = 0;

	/*
	 * Set Maximum UDP buffer size.
	 */
	rdatalist->rdclass = SEND_BUFFER_SIZE;

	/*
	 * Set EXTENDED-RCODE, VERSION, and Z to 0.
	 */
	rdatalist->ttl = 0;

	/*
	 * No ENDS options.
	 */
	rdata->data = NULL;
	rdata->length = 0;

	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdatalist_tordataset(rdatalist, rdataset);
	
	client->opt = rdataset;

	return (ISC_R_SUCCESS);
}

/*
 * Handle an incoming request event from the dispatch (UDP case)
 * or tcpmsg (TCP case).
 */
static void
client_request(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client;
	dns_dispatchevent_t *devent;
	isc_result_t result;
	isc_buffer_t *buffer;
	dns_view_t *view;
	dns_rdataset_t *opt;
	isc_boolean_t ra; 	/* Recursion available. */

	REQUIRE(event != NULL);
	client = event->arg;
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(task == client->task);

	INSIST(client->recursionquota == NULL);

	RWLOCK(&ns_g_server->conflock, isc_rwlocktype_read);
	dns_zonemgr_lockconf(ns_g_server->zonemgr, isc_rwlocktype_read);
	
	if (event->type == DNS_EVENT_DISPATCH) {
		devent = (dns_dispatchevent_t *)event;
		REQUIRE(client->dispentry != NULL);
		client->dispevent = devent;
		buffer = &devent->buffer;
		result = devent->result;
	} else {
		REQUIRE(event->type == DNS_EVENT_TCPMSG);
		REQUIRE(event->sender == &client->tcpmsg);
		buffer = &client->tcpmsg.buffer;
		result = client->tcpmsg.result;
		INSIST(client->nreads == 1);
		client->nreads--;
	}

	CTRACE("request");

	if (client->shuttingdown) {
		maybe_free(client);
		goto cleanup_serverlock;
	}
		
	isc_stdtime_get(&client->requesttime);
	client->now = client->requesttime;

	if (result != ISC_R_SUCCESS) {
		if (TCP_CLIENT(client))
			ns_client_next(client, result);
		else
			isc_task_shutdown(client->task);
		goto cleanup_serverlock;
	}

	result = dns_message_parse(client->message, buffer, ISC_FALSE);
	if (result != ISC_R_SUCCESS) {
		ns_client_error(client, result);
		goto cleanup_serverlock;
	}

	/*
	 * We expect a query, not a response.  Unexpected UDP responses
	 * are discarded early by the dispatcher, but TCP responses
	 * bypass the dispatcher and must be discarded here.
	 */
	if ((client->message->flags & DNS_MESSAGEFLAG_QR) != 0) {
		CTRACE("unexpected response");
		ns_client_next(client, DNS_R_FORMERR);
		goto cleanup_serverlock;
	}

	/*
	 * Deal with EDNS.
	 */
	opt = dns_message_getopt(client->message);
	if (opt != NULL) {
		unsigned int version;

		/*
		 * Set the client's UDP buffer size.
		 */
		client->udpsize = opt->rdclass;

		/*
		 * Create an OPT for our reply.
		 */
		result = client_addopt(client);
		if (result != ISC_R_SUCCESS) {
			ns_client_error(client, result);
			goto cleanup_serverlock;
		}

		/*
		 * Do we understand this version of ENDS?
		 *
		 * XXXRTH need library support for this!
		 */
		version = (opt->ttl & 0x00FF0000) >> 16;
		if (version != 0) {
			ns_client_error(client, DNS_R_BADVERS);
			goto cleanup_serverlock;
		}
	}

	/*
	 * XXXRTH  View list management code will be moving to its own module
	 *         soon.
	 */
	for (view = ISC_LIST_HEAD(ns_g_server->viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link)) {
		/*
		 * XXXRTH  View matching will become more powerful later.
		 */
		if (client->message->rdclass == view->rdclass ||
		    client->message->rdclass == dns_rdataclass_any)
		{
			dns_view_attach(view, &client->view);
			break;
		}
	}

	if (view == NULL) {
		CTRACE("no view");
		ns_client_error(client, DNS_R_REFUSED);
		goto cleanup_serverlock;
	}

	/*
	 * Lock the view's configuration data for reading.
	 * We must attach a separate view reference for this
	 * purpose instad of using client->view, because
	 * client->view may or may not be detached at the point
	 * when whe return from this event handler depending
	 * on whether the request handler causes ns_client_next()
	 * to be called or not.
	 */
	dns_view_attach(client->view, &client->lockview);
	RWLOCK(&client->lockview->conflock, isc_rwlocktype_read);

	/*
	 * Check for a signature.  We log bad signatures regardless of 
	 * whether they ultimately cause the request to be rejected or
	 * not.  We do not log the lack of a signature unless we are
	 * debugging.
	 */
	result = dns_message_checksig(client->message, client->view);
	if (result != ISC_R_SUCCESS) {
		ns_client_error(client, result);
		goto cleanup_viewlock;
	}

	client->signer = NULL;
	dns_name_init(&client->signername, NULL);
	result = dns_message_signer(client->message, &client->signername);
	if (result == DNS_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      NS_LOGMODULE_CLIENT, ISC_LOG_DEBUG(3),
			      "request has valid signature");
		client->signer = &client->signername;
	} else if (result == DNS_R_NOTFOUND) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      NS_LOGMODULE_CLIENT, ISC_LOG_DEBUG(3),
			      "request is not signed");
	} else if (result == DNS_R_NOIDENTITY) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      NS_LOGMODULE_CLIENT, ISC_LOG_DEBUG(3),
			      "request is signed by a nonauthoritative key");
	} else {
		/* There is a signature, but it is bad. */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      NS_LOGMODULE_CLIENT, ISC_LOG_ERROR,
			      "request has invalid signature: %s",
			      isc_result_totext(result));
	}

	/*
	 * Decide whether recursive service is available to this client.
	 * We do this here rather than in the query code so that we can
	 * set the RA bit correctly on all kinds of responses, not just
	 * responses to ordinary queries.
	 */
	if (client->view->resolver == NULL) {
		ra = ISC_FALSE;
	} else {
		ra = ISC_TRUE;
		if (ns_g_server->recursion == ISC_TRUE) {
			/* XXX ACL should be view specific. */
			/* XXX this will log too much too early */
			result = dns_acl_checkrequest(client->signer,
					      ns_client_getsockaddr(client),
					      "recursion",
					      ns_g_server->recursionacl,
					      NULL, ISC_TRUE);
			if (result != DNS_R_SUCCESS)
				ra = ISC_FALSE;
		}
	}
	if (ra == ISC_TRUE)
		client->attributes |= NS_CLIENTATTR_RA;

	/*
	 * Dispatch the request.
	 */
	switch (client->message->opcode) {
	case dns_opcode_query:
		CTRACE("query");
		ns_query_start(client);
		break;
	case dns_opcode_update:
		CTRACE("update");
		ns_update_start(client);
		break;
	case dns_opcode_notify:
		CTRACE("notify");
		ns_notify_start(client);
		break;
	case dns_opcode_iquery:
		CTRACE("iquery");
		ns_client_error(client, DNS_R_NOTIMP);
		break;
	default:
		CTRACE("unknown opcode");
		ns_client_error(client, DNS_R_NOTIMP);
	}

 cleanup_viewlock:
	RWUNLOCK(&client->lockview->conflock, isc_rwlocktype_read);
	dns_view_detach(&client->lockview);
 cleanup_serverlock:
	dns_zonemgr_unlockconf(ns_g_server->zonemgr, isc_rwlocktype_read);
	RWUNLOCK(&ns_g_server->conflock, isc_rwlocktype_read);
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
client_create(ns_clientmgr_t *manager, ns_client_t **clientp)
{
	ns_client_t *client;
	isc_result_t result;

	/*
	 * Caller must be holding the manager lock.
	 *
	 * Note: creating a client does not add the client to the 
	 * manager's client list or set the client's manager pointer.
	 * The caller is responsible for that.
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
	isc_task_setname(client->task, "client", client);
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
	client->sendbuf = isc_mem_get(manager->mctx, SEND_BUFFER_SIZE);
	if  (client->sendbuf == NULL)
		goto cleanup_message;

	client->magic = NS_CLIENT_MAGIC;
	client->mctx = manager->mctx;
	client->manager = NULL;
	client->shuttingdown = ISC_FALSE;
	client->naccepts = 0;
	client->nreads = 0;
	client->nsends = 0;
	client->nwaiting = 0;
	client->attributes = 0;
	client->view = NULL;
	client->lockview = NULL;
	client->dispatch = NULL;
	client->dispentry = NULL;
	client->dispevent = NULL;
	client->tcplistener = NULL;
	client->tcpsocket = NULL;
	client->tcpmsg_valid = ISC_FALSE;
	client->opt = NULL;
	client->udpsize = 512;
	client->next = NULL;
	client->shutdown = NULL;
	client->shutdown_arg = NULL;
	dns_name_init(&client->signername, NULL);
	client->mortal = ISC_FALSE;
	client->tcpquota = NULL;
	client->recursionquota = NULL;
	client->interface = NULL;
	ISC_LINK_INIT(client, link);
	client->list = NULL;

	/*
	 * We call the init routines for the various kinds of client here,
	 * after we have created an otherwise valid client, because some
	 * of them call routines that REQUIRE(NS_CLIENT_VALID(client)).
	 */
	result = ns_query_init(client);
	if (result != ISC_R_SUCCESS)
		goto cleanup_sendbuf;

	CTRACE("create");

	*clientp = client;

	return (ISC_R_SUCCESS);

 cleanup_sendbuf:
	isc_mem_put(manager->mctx, client->sendbuf, SEND_BUFFER_SIZE);

	client->magic = 0;

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

static void
client_read(ns_client_t *client) {
	isc_result_t result;

	CTRACE("read");

	result = dns_tcpmsg_readmessage(&client->tcpmsg, client->task,
					client_request, client);
	if (result != ISC_R_SUCCESS)
		ns_client_next(client, result);
	INSIST(client->nreads == 0);
	client->nreads++;
}

static void
client_newconn(isc_task_t *task, isc_event_t *event) {
	ns_client_t *client = event->arg;
	isc_socket_newconnev_t *nevent = (isc_socket_newconnev_t *)event;
	isc_result_t result;

	REQUIRE(event->type == ISC_SOCKEVENT_NEWCONN);
	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(client->task == task);

	CTRACE("newconn");

	INSIST(client->naccepts == 1);
	client->naccepts--;

	LOCK(&client->interface->lock);
	INSIST(client->interface->ntcpcurrent > 0);
	client->interface->ntcpcurrent--;
	UNLOCK(&client->interface->lock);

	if (client->shuttingdown) {
		maybe_free(client);
	} else if (nevent->result == ISC_R_SUCCESS) {
		client->tcpsocket = nevent->newsocket;
		INSIST(client->tcpmsg_valid == ISC_FALSE);
		dns_tcpmsg_init(client->mctx, client->tcpsocket,
				&client->tcpmsg);
		client->tcpmsg_valid = ISC_TRUE;

		/*
		 * Let a new client take our place immediately, before
		 * we wait for a request packet.  If we don't,
		 * telnetting to port 35 (once per CPU) will
		 * deny service to legititmate TCP clients.
		 */
		result = isc_quota_attach(&ns_g_server->tcpquota,
					  &client->tcpquota);
		if (result == ISC_R_SUCCESS)
			result = ns_client_replace(client);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_CLIENT,
				      NS_LOGMODULE_CLIENT, ISC_LOG_WARNING,
				      "no more TCP clients: %s",
				      isc_result_totext(result));
		}
		client_read(client);
	} else {
		/*
		 * XXXRTH  What should we do?  We're trying to accept but
		 *         it didn't work.  If we just give up, then TCP
		 *	   service may eventually stop.
		 *
		 *	   For now, we just go idle.
		 *
		 *	   Going idle is probably the right thing if the
		 *	   I/O was canceled.
		 */
	}
	isc_event_free(&event);
}

static void
client_accept(ns_client_t *client) {
	isc_result_t result;

	CTRACE("accept");

	result = isc_socket_accept(client->tcplistener, client->task,
				   client_newconn, client);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socket_accept() failed: %s",
				 isc_result_totext(result));
		/*
		 * XXXRTH  What should we do?  We're trying to accept but
		 *         it didn't work.  If we just give up, then TCP
		 *	   service may eventually stop.
		 *
		 *	   For now, we just go idle.
		 */
		return;
	}
	INSIST(client->naccepts == 0);
	client->naccepts++;
	LOCK(&client->interface->lock);
	client->interface->ntcpcurrent++;
	UNLOCK(&client->interface->lock);
}

void
ns_client_wait(ns_client_t *client) {
	client->nwaiting++;
}

isc_boolean_t
ns_client_shuttingdown(ns_client_t *client) {
	return (client->shuttingdown);
}

void
ns_client_unwait(ns_client_t *client) {
	client->nwaiting--;
	INSIST(client->nwaiting >= 0);
	if (client->shuttingdown)
		maybe_free(client);
}

isc_result_t
ns_client_replace(ns_client_t *client) {
	isc_result_t result;
	CTRACE("replace");

	result = ns_clientmgr_createclients(client->manager,
					    1, client->interface,
					    (TCP_CLIENT(client) ?
					     ISC_TRUE : ISC_FALSE));
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * The responsibility for listening for new requests is hereby 
	 * transferred to the new client.  Therefore, the old client 
	 * should refrain from listening for any more requests.
	 */
	client->mortal = ISC_TRUE;

	return (ISC_R_SUCCESS);
}

/***
 *** Client Manager
 ***/

static void
clientmgr_destroy(ns_clientmgr_t *manager) {
	REQUIRE(ISC_LIST_EMPTY(manager->active));
	REQUIRE(ISC_LIST_EMPTY(manager->inactive));

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
	ISC_LIST_INIT(manager->active);
	ISC_LIST_INIT(manager->inactive);
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

	for (client = ISC_LIST_HEAD(manager->active);
	     client != NULL;
	     client = ISC_LIST_NEXT(client, link))
		isc_task_shutdown(client->task);

	for (client = ISC_LIST_HEAD(manager->inactive);
	     client != NULL;
	     client = ISC_LIST_NEXT(client, link))
		isc_task_shutdown(client->task);

	if (ISC_LIST_EMPTY(manager->active) &&
	    ISC_LIST_EMPTY(manager->inactive))
		need_destroy = ISC_TRUE;

	UNLOCK(&manager->lock);

	if (need_destroy)
		clientmgr_destroy(manager);

	*managerp = NULL;
}

isc_result_t
ns_clientmgr_createclients(ns_clientmgr_t *manager, unsigned int n,
			   ns_interface_t *ifp, isc_boolean_t tcp)
{
	isc_result_t result = ISC_R_SUCCESS;
	unsigned int i;
	ns_client_t *client;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(n > 0);

	MTRACE("createclients");

	/*
	 * We MUST lock the manager lock for the entire client creation
	 * process.  If we didn't do this, then a client could get a
	 * shutdown event and disappear out from under us.
	 */

	LOCK(&manager->lock);

	for (i = 0; i < n; i++) {
		/*
		 * Allocate a client.  First try to get a recycled one;
		 * if that fails, make a new one.
		 */
		client = ISC_LIST_HEAD(manager->inactive);
		if (client != NULL) {
			MTRACE("recycle");
			ISC_LIST_UNLINK(manager->inactive, client, link);
			client->list = NULL;
		} else {
			MTRACE("create new");
			result = client_create(manager, &client);
			if (result != ISC_R_SUCCESS)
				break;
		}

		ns_interface_attach(ifp, &client->interface);

		if (tcp) {
			client->attributes |= NS_CLIENTATTR_TCP;
			isc_socket_attach(ifp->tcpsocket, &client->tcplistener);
			client_accept(client);
		} else {
			dns_dispatch_attach(ifp->udpdispatch, &client->dispatch);
			result = dns_dispatch_addrequest(client->dispatch,
							 client->task,
							 client_request,
							 client, &client->dispentry);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
					      NS_LOGMODULE_CLIENT, ISC_LOG_DEBUG(3),
					      "dns_dispatch_addrequest() failed: %s",
					      isc_result_totext(result));
				isc_task_shutdown(client->task);
				break;
			}
		}
		client->manager = manager;
		ISC_LIST_APPEND(manager->active, client, link);
		client->list = &manager->active;
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

isc_sockaddr_t *
ns_client_getsockaddr(ns_client_t *client) {
	if (TCP_CLIENT(client))
		return (&client->tcpmsg.address);
	else
		return (&client->dispevent->addr);
}
