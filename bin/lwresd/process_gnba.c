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

#include <string.h>

#include <sys/types.h>

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/byaddr.h>

#include <lwres/lwres.h>
#include <lwres/result.h>

#include "client.h"

static void start_byaddr(client_t *);

static void
byaddr_done(isc_task_t *task, isc_event_t *event)
{
	client_t *client;
	dns_byaddrevent_t *bevent;
	int lwres;
	lwres_buffer_t lwb;
	dns_name_t *name;
	isc_result_t result;
	isc_region_t r;
	isc_buffer_t b;
	lwres_gnbaresponse_t *gnba;
	isc_uint16_t naliases;

	(void)task;

	client = event->arg;
	INSIST(client->byaddr == event->sender);

	bevent = (dns_byaddrevent_t *)event;
	gnba = &client->gnba;

	DP(50, "byaddr event result = %s",
	   isc_result_totext(bevent->result));

	if (bevent->result != ISC_R_SUCCESS) {
		dns_byaddr_destroy(&client->byaddr);
		isc_event_free(&event);

		if ((client->options & DNS_BYADDROPT_IPV6NIBBLE) == 0) {
			error_pkt_send(client, LWRES_R_FAILURE);
			return;
		}

		client->options &= ~DNS_BYADDROPT_IPV6NIBBLE;
		
		start_byaddr(client);
		return;
	}

	name = ISC_LIST_HEAD(bevent->names);
	while (name != NULL) {
		b = client->recv_buffer;

		result = dns_name_totext(name, ISC_TRUE, &client->recv_buffer);
		DP(50, "***** Found name %.*s",
		   client->recv_buffer.used - b.used,
		   (char *)(b.base) + b.used);
		if (result != ISC_R_SUCCESS)
			goto out;
		if (gnba->realname == NULL) {
			gnba->realname = (char *)(b.base) + b.used;
			gnba->realnamelen = client->recv_buffer.used - b.used;
		} else {
			naliases = gnba->naliases;
			if (naliases < LWRES_MAX_ALIASES) {
				gnba->aliases[naliases] =
					(char *)(b.base) + b.used;
				gnba->aliaslen[naliases] =
					client->recv_buffer.used - b.used;
				gnba->naliases++;
			}
		}
	     name = ISC_LIST_NEXT(name, link);
	}

	dns_byaddr_destroy(&client->byaddr);

	/*
	 * Render the packet.
	 */
	client->pkt.recvlength = LWRES_RECVLENGTH;
	client->pkt.authtype = 0; /* XXXMLG */
	client->pkt.authlength = 0;
	client->pkt.result = LWRES_R_SUCCESS;

	lwres_buffer_init(&lwb, client->buffer, LWRES_RECVLENGTH);
	lwres = lwres_gnbaresponse_render(client->clientmgr->lwctx,
					  gnba, &client->pkt, &lwb);

	hexdump("Sending to client", lwb.base, lwb.used);

	if (lwres != LWRES_R_SUCCESS)
		goto out;

	r.base = lwb.base;
	r.length = lwb.used;
	client->sendbuf = r.base;
	client->sendlength = r.length;
	result = isc_socket_sendto(client->clientmgr->sock, &r,
				   client->clientmgr->task, client_send,
				   client, &client->address, NULL);
	if (result != ISC_R_SUCCESS)
		goto out;

	CLIENT_SETSEND(client);

 out:
	if (client->byaddr != NULL)
		dns_byaddr_destroy(&client->byaddr);
	isc_event_free(&event);
}

static void
start_byaddr(client_t *client)
{
	isc_result_t result;
	clientmgr_t *cm;

	cm = client->clientmgr;

	INSIST(client->byaddr == NULL);

	result = dns_byaddr_create(cm->mctx, &client->na, cm->view,
				   client->options, cm->task, byaddr_done,
				   client, &client->byaddr);
	if (result != ISC_R_SUCCESS) {
		error_pkt_send(client, LWRES_R_FAILURE);
		return;
	}
}

void
process_gnba(client_t *client, lwres_buffer_t *b)
{
	lwres_gnbarequest_t *req;
	isc_result_t result;

	REQUIRE(CLIENT_ISRECVDONE(client));
	INSIST(client->byaddr == NULL);

	req = NULL;

	result = lwres_gnbarequest_parse(client->clientmgr->lwctx,
					 b, &client->pkt, &req);
	if (result != LWRES_R_SUCCESS)
		goto out;
	if (req->addr.address == NULL)
		goto out;

	client->options = 0;
	if (req->addr.family == LWRES_ADDRTYPE_V4) {
		client->na.family = AF_INET;
		if (req->addr.length != 4)
			goto out;
		memcpy(&client->na.type.in, req->addr.address, 4);
	} else if (req->addr.family == LWRES_ADDRTYPE_V6) {
		client->na.family = AF_INET6;
		if (req->addr.length != 16)
			goto out;
		memcpy(&client->na.type.in6, req->addr.address, 16);
	} else {
		goto out;
	}

	DP(50, "Client %p looking for addrtype %08x",
	   client, req->addr.family);

	/*
	 * We no longer need to keep this around.
	 */
	lwres_gnbarequest_free(client->clientmgr->lwctx, &req);

	/*
	 * Initialize the real name and alias arrays in the reply we're
	 * going to build up.
	 */
	client_init_gnba(client);

	/*
	 * Start the find.
	 */
	client->options = DNS_BYADDROPT_IPV6NIBBLE;
	start_byaddr(client);

	return;

	/*
	 * We're screwed.  Return an error packet to our caller.
	 */
 out:
	if (req != NULL)
		lwres_gnbarequest_free(client->clientmgr->lwctx, &req);

	error_pkt_send(client, LWRES_R_FAILURE);

	return;
}
