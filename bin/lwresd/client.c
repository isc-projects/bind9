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

#include <sys/types.h>

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <lwres/lwres.h>

#include "client.h"

static void
hexdump(char *msg, void *base, size_t len)
{
	unsigned char *p;
	unsigned int cnt;

	p = base;
	cnt = 0;

	printf("*** %s (%u bytes @ %p)\n", msg, len, base);

	while (cnt < len) {
		if (cnt % 16 == 0)
			printf("%p: ", p);
		else if (cnt % 8 == 0)
			printf(" |");
		printf(" %02x", *p++);
		cnt++;

		if (cnt % 16 == 0)
			printf("\n");
	}

	if (cnt % 16 != 0)
		printf("\n");
}

static void
clientmgr_can_die(clientmgr_t *cm)
{
	if ((cm->flags & CLIENTMGR_FLAG_SHUTTINGDOWN) == 0)
		return;

	if (ISC_LIST_HEAD(cm->running) != NULL)
		return;

	lwres_context_destroy(&cm->lwctx);
	dns_view_detach(&cm->view);
	isc_task_detach(&cm->task);
}

static void
process_request(client_t *client)
{
	lwres_buffer_t b;
	isc_result_t result;

	hexdump("client request", client->buffer, client->recvlength);

	lwres_buffer_init(&b, client->buffer, client->recvlength);
	lwres_buffer_add(&b, client->recvlength);

	result = lwres_lwpacket_parseheader(&b, &client->pkt);
	if (result != ISC_R_SUCCESS) {
		printf("Invalid packet header received\n");
		goto restart;
	}

	printf("OPCODE %08x\n", client->pkt.opcode);

	switch (client->pkt.opcode) {
	case LWRES_OPCODE_GETADDRSBYNAME:
		process_gabn(client, &b);
		return;
	case LWRES_OPCODE_GETNAMEBYADDR:
		process_gnba(client, &b);
		return;
	case LWRES_OPCODE_NOOP:
		process_noop(client, &b);
		return;
	default:
		printf("Unknown opcode %08x\n", client->pkt.opcode);
		goto restart;
	}

	/*
	 * Drop the packet.
	 */
 restart:
	printf("restarting client %p...\n", client);
	client_state_idle(client);
}

void
client_recv(isc_task_t *task, isc_event_t *ev)
{
	client_t *client = ev->arg;
	clientmgr_t *cm = client->clientmgr;
	isc_socketevent_t *dev = (isc_socketevent_t *)ev;

	INSIST(dev->region.base == client->buffer);
	INSIST(CLIENT_ISRECV(client));

	CLIENT_SETRECVDONE(client);

	INSIST((cm->flags & CLIENTMGR_FLAG_RECVPENDING) != 0);
	cm->flags &= ~CLIENTMGR_FLAG_RECVPENDING;

	printf("Event received! Task %p, length %u, result %u (%s)\n",
	       task, dev->n, dev->result, isc_result_totext(dev->result));

	if (dev->result != ISC_R_SUCCESS) {
		isc_event_free(&ev);
		dev = NULL;

		/*
		 * Go idle.
		 */
		client_state_idle(client);

		return;
	}

	/*
	 * XXXMLG If we wanted to run on ipv6 as well, we'd need the pktinfo
	 * bits.  Right now we don't, so don't remember them.
	 */
	client->recvlength = dev->n;
	client->address = dev->address;
	client_start_recv(cm);

	process_request(client);

	isc_event_free(&ev);
}

/*
 * This function will start a new recv() on a socket for this client manager.
 */
isc_result_t
client_start_recv(clientmgr_t *cm)
{
	client_t *client;
	isc_result_t result;
	isc_region_t r;

	if ((cm->flags & CLIENTMGR_FLAG_SHUTTINGDOWN) != 0)
		return (ISC_R_SUCCESS);

	/*
	 * If a recv is already running, don't bother.
	 */
	if ((cm->flags & CLIENTMGR_FLAG_RECVPENDING) != 0)
		return (ISC_R_SUCCESS);

	/*
	 * If we have no idle slots, just return success.
	 */
	client = ISC_LIST_HEAD(cm->idle);
	if (client == NULL)
		return (ISC_R_SUCCESS);
	INSIST(CLIENT_ISIDLE(client));

	/*
	 * Issue the recv.  If it fails, return that it did.
	 */
	r.base = client->buffer;
	r.length = LWRES_RECVLENGTH;
	result = isc_socket_recv(cm->sock, &r, 0, cm->task, client_recv,
				 client);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Set the flag to say we've issued a recv() call.
	 */
	cm->flags |= CLIENTMGR_FLAG_RECVPENDING;

	/*
	 * Remove the client from the idle list, and put it on the running
	 * list.
	 */
	CLIENT_SETRECV(client);
	ISC_LIST_UNLINK(cm->idle, client, link);
	ISC_LIST_APPEND(cm->running, client, link);

	return (ISC_R_SUCCESS);
}

void
client_shutdown(isc_task_t *task, isc_event_t *ev)
{
	clientmgr_t *cm = ev->arg;

	REQUIRE(task == cm->task);
	REQUIRE(ev->type == LWRD_SHUTDOWN);
	REQUIRE((cm->flags & CLIENTMGR_FLAG_SHUTTINGDOWN) == 0);

	printf("Got shutdown event, task %p\n", task);

	/*
	 * Cancel any pending I/O.
	 */
	if ((cm->flags & CLIENTMGR_FLAG_RECVPENDING) != 0)
		isc_socket_cancel(cm->sock, task, ISC_SOCKCANCEL_ALL);

	/*
	 * Run through the running client list and kill off any finds
	 * in progress.
	 */
	/* XXXMLG */

	cm->flags |= CLIENTMGR_FLAG_SHUTTINGDOWN;
}

/*
 * Do all the crap needed to move a client from the run queue to the idle
 * queue.
 */
void
client_state_idle(client_t *client)
{
	clientmgr_t *cm;

	cm = client->clientmgr;

	INSIST(client->sendbuf == NULL);
	INSIST(client->sendlength == 0);
	INSIST(client->arg == NULL);
	INSIST(client->v4find == NULL);
	INSIST(client->v6find == NULL);

	ISC_LIST_UNLINK(cm->running, client, link);
	ISC_LIST_PREPEND(cm->idle, client, link);

	CLIENT_SETIDLE(client);

	clientmgr_can_die(cm);

	client_start_recv(cm);
}

void
client_send(isc_task_t *task, isc_event_t *ev)
{
	client_t *client = ev->arg;
	clientmgr_t *cm = client->clientmgr;
	isc_socketevent_t *dev = (isc_socketevent_t *)ev;

	UNUSED(task);

	INSIST(CLIENT_ISSEND(client));
	INSIST(client->sendbuf == dev->region.base);

	if (client->sendbuf != client->buffer)
		lwres_context_freemem(cm->lwctx, client->sendbuf,
				      client->sendlength);
	client->sendbuf = NULL;

	client_state_idle(client);
}

void
client_initialize(client_t *client, clientmgr_t *cmgr)
{
	int i;

	client->clientmgr = cmgr;
	ISC_LINK_INIT(client, link);
	CLIENT_SETIDLE(client);
	client->arg = NULL;

	client->recvlength = 0;

	client->sendbuf = NULL;
	client->sendlength = 0;

	client->v4find = NULL;
	client->v6find = NULL;

	client->find_pending = 0;
	client->find_wanted = 0;

	for (i = 0 ; i < LWRES_MAX_ALIASES ; i++)
		client->aliases[i] = NULL;
	client->naliases = 0;

	ISC_LIST_APPEND(cmgr->idle, client, link);
}
