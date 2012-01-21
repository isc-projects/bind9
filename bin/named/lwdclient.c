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

/* $Id: lwdclient.c,v 1.3.2.1 2000/06/26 21:47:32 gson Exp $ */

#include <config.h>

#include <isc/socket.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/view.h>
#include <dns/log.h>

#include <named/types.h>
#include <named/lwdclient.h>

void
ns_lwdclient_log(int level, const char *format, ...) {
	va_list args;

	va_start(args, format);
	isc_log_vwrite(dns_lctx,
		       DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_ADB,
		       ISC_LOG_DEBUG(level), format, args);
	va_end(args);
}

static void
clientmgr_can_die(ns_lwdclientmgr_t *cm) {
	if ((cm->flags & NS_LWDCLIENTMGR_FLAGSHUTTINGDOWN) == 0)
		return;

	if (ISC_LIST_HEAD(cm->running) != NULL)
		return;

	lwres_context_destroy(&cm->lwctx);
	isc_socket_detach(&cm->sock);
	dns_view_detach(&cm->view);
	isc_task_detach(&cm->task);
}

static void
process_request(ns_lwdclient_t *client) {
	lwres_buffer_t b;
	isc_result_t result;

	lwres_buffer_init(&b, client->buffer, client->recvlength);
	lwres_buffer_add(&b, client->recvlength);

	result = lwres_lwpacket_parseheader(&b, &client->pkt);
	if (result != ISC_R_SUCCESS) {
		ns_lwdclient_log(50, "invalid packet header received");
		goto restart;
	}

	ns_lwdclient_log(50, "opcode %08x", client->pkt.opcode);

	switch (client->pkt.opcode) {
	case LWRES_OPCODE_GETADDRSBYNAME:
		ns_lwdclient_processgabn(client, &b);
		return;
	case LWRES_OPCODE_GETNAMEBYADDR:
		ns_lwdclient_processgnba(client, &b);
		return;
	case LWRES_OPCODE_NOOP:
		ns_lwdclient_processnoop(client, &b);
		return;
	default:
		ns_lwdclient_log(50, "unknown opcode %08x", client->pkt.opcode);
		goto restart;
	}

	/*
	 * Drop the packet.
	 */
 restart:
	ns_lwdclient_log(50, "restarting client %p...", client);
	ns_lwdclient_stateidle(client);
}

void
ns_lwdclient_recv(isc_task_t *task, isc_event_t *ev) {
	ns_lwdclient_t *client = ev->ev_arg;
	ns_lwdclientmgr_t *cm = client->clientmgr;
	isc_socketevent_t *dev = (isc_socketevent_t *)ev;

	INSIST(dev->region.base == client->buffer);
	INSIST(NS_LWDCLIENT_ISRECV(client));

	NS_LWDCLIENT_SETRECVDONE(client);

	INSIST((cm->flags & NS_LWDCLIENTMGR_FLAGRECVPENDING) != 0);
	cm->flags &= ~NS_LWDCLIENTMGR_FLAGRECVPENDING;

	ns_lwdclient_log(50,
			 "event received: task %p, length %u, result %u (%s)",
			 task, dev->n, dev->result,
			 isc_result_totext(dev->result));

	if (dev->result != ISC_R_SUCCESS) {
		isc_event_free(&ev);
		dev = NULL;

		/*
		 * Go idle.
		 */
		ns_lwdclient_stateidle(client);

		return;
	}

	/*
	 * XXXMLG If we wanted to run on ipv6 as well, we'd need the pktinfo
	 * bits.  Right now we don't, so don't remember them.
	 */
	client->recvlength = dev->n;
	client->address = dev->address;
	isc_event_free(&ev);
	dev = NULL;

	ns_lwdclient_startrecv(cm);

	process_request(client);
}

/*
 * This function will start a new recv() on a socket for this client manager.
 */
isc_result_t
ns_lwdclient_startrecv(ns_lwdclientmgr_t *cm) {
	ns_lwdclient_t *client;
	isc_result_t result;
	isc_region_t r;

	if ((cm->flags & NS_LWDCLIENTMGR_FLAGSHUTTINGDOWN) != 0)
		return (ISC_R_SUCCESS);

	/*
	 * If a recv is already running, don't bother.
	 */
	if ((cm->flags & NS_LWDCLIENTMGR_FLAGRECVPENDING) != 0)
		return (ISC_R_SUCCESS);

	/*
	 * If we have no idle slots, just return success.
	 */
	client = ISC_LIST_HEAD(cm->idle);
	if (client == NULL)
		return (ISC_R_SUCCESS);
	INSIST(NS_LWDCLIENT_ISIDLE(client));

	/*
	 * Issue the recv.  If it fails, return that it did.
	 */
	r.base = client->buffer;
	r.length = LWRES_RECVLENGTH;
	result = isc_socket_recv(cm->sock, &r, 0, cm->task, ns_lwdclient_recv,
				 client);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Set the flag to say we've issued a recv() call.
	 */
	cm->flags |= NS_LWDCLIENTMGR_FLAGRECVPENDING;

	/*
	 * Remove the client from the idle list, and put it on the running
	 * list.
	 */
	NS_LWDCLIENT_SETRECV(client);
	ISC_LIST_UNLINK(cm->idle, client, link);
	ISC_LIST_APPEND(cm->running, client, link);

	return (ISC_R_SUCCESS);
}

void
ns_lwdclient_shutdown(isc_task_t *task, isc_event_t *ev) {
	ns_lwdclientmgr_t *cm = ev->ev_arg;

	REQUIRE((cm->flags & NS_LWDCLIENTMGR_FLAGSHUTTINGDOWN) == 0);

	ns_lwdclient_log(50, "got shutdown event, task %p", task);

	/*
	 * Cancel any pending I/O.
	 */
	if ((cm->flags & NS_LWDCLIENTMGR_FLAGRECVPENDING) != 0)
		isc_socket_cancel(cm->sock, task, ISC_SOCKCANCEL_ALL);

	/*
	 * Run through the running client list and kill off any finds
	 * in progress.
	 */
	/* XXXMLG */

	cm->flags |= NS_LWDCLIENTMGR_FLAGSHUTTINGDOWN;

	isc_event_free(&ev);
}

/*
 * Do all the crap needed to move a client from the run queue to the idle
 * queue.
 */
void
ns_lwdclient_stateidle(ns_lwdclient_t *client) {
	ns_lwdclientmgr_t *cm;

	cm = client->clientmgr;

	INSIST(client->sendbuf == NULL);
	INSIST(client->sendlength == 0);
	INSIST(client->arg == NULL);
	INSIST(client->v4find == NULL);
	INSIST(client->v6find == NULL);

	ISC_LIST_UNLINK(cm->running, client, link);
	ISC_LIST_PREPEND(cm->idle, client, link);

	NS_LWDCLIENT_SETIDLE(client);

	clientmgr_can_die(cm);

	ns_lwdclient_startrecv(cm);
}

void
ns_lwdclient_send(isc_task_t *task, isc_event_t *ev) {
	ns_lwdclient_t *client = ev->ev_arg;
	ns_lwdclientmgr_t *cm = client->clientmgr;
	isc_socketevent_t *dev = (isc_socketevent_t *)ev;

	UNUSED(task);
	UNUSED(dev);
	
	INSIST(NS_LWDCLIENT_ISSEND(client));
	INSIST(client->sendbuf == dev->region.base);

	ns_lwdclient_log(50, "task %p for client %p got send-done event",
			 task, client);

	if (client->sendbuf != client->buffer)
		lwres_context_freemem(cm->lwctx, client->sendbuf,
				      client->sendlength);
	client->sendbuf = NULL;
	client->sendlength = 0;

	ns_lwdclient_stateidle(client);

	isc_event_free(&ev);
}

void
ns_lwdclient_initialize(ns_lwdclient_t *client, ns_lwdclientmgr_t *cmgr) {
	client->clientmgr = cmgr;
	ISC_LINK_INIT(client, link);
	NS_LWDCLIENT_SETIDLE(client);
	client->arg = NULL;

	client->recvlength = 0;

	client->sendbuf = NULL;
	client->sendlength = 0;

	client->find = NULL;
	client->v4find = NULL;
	client->v6find = NULL;
	client->find_wanted = 0;

	client->options = 0;
	client->byaddr = NULL;
	client->addrinfo = NULL;

	ISC_LIST_APPEND(cmgr->idle, client, link);
}
