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
clientmgr_can_die(clientmgr_t *cm)
{
	if (ISC_LIST_HEAD(cm->running) != NULL)
		return;

	isc_task_detach(&cm->task);
}

void
client_recv(isc_task_t *task, isc_event_t *ev)
{
	client_t *client = ev->arg;
	clientmgr_t *cm = client->clientmgr;
	isc_socketevent_t *dev = (isc_socketevent_t *)ev;

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
		ISC_LIST_UNLINK(cm->running, client, link);
		ISC_LIST_APPEND(cm->idle, client, link);

		clientmgr_can_die(cm);
		return;
	}

	/*
	 * XXXMLG Nothing to do right now, just go idle.
	 */
	ISC_LIST_UNLINK(cm->running, client, link);
	ISC_LIST_APPEND(cm->idle, client, link);

	client_start_recv(cm);

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

	REQUIRE((cm->flags & CLIENTMGR_FLAG_SHUTTINGDOWN) == 0);
	REQUIRE((cm->flags & CLIENTMGR_FLAG_RECVPENDING) == 0);

	/*
	 * If we have no idle slots, just return success.
	 */
	client = ISC_LIST_HEAD(cm->idle);
	if (client == NULL)
		return (ISC_R_SUCCESS);

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

