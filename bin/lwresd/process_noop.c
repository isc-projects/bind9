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

#include <isc/socket.h>
#include <isc/util.h>

#include "client.h"

void
process_noop(client_t *client, lwres_buffer_t *b) {
	lwres_nooprequest_t *req;
	lwres_noopresponse_t resp;
	isc_result_t result;
	lwres_result_t lwres;
	isc_region_t r;
	lwres_buffer_t lwb;

	REQUIRE(CLIENT_ISRECVDONE(client));
	INSIST(client->byaddr == NULL);

	req = NULL;

	result = lwres_nooprequest_parse(client->clientmgr->lwctx,
					 b, &client->pkt, &req);
	if (result != LWRES_R_SUCCESS)
		goto out;

	client->pkt.recvlength = LWRES_RECVLENGTH;
	client->pkt.authtype = 0; /* XXXMLG */
	client->pkt.authlength = 0;
	client->pkt.result = LWRES_R_SUCCESS;

	resp.datalength = req->datalength;
	resp.data = req->data;

	lwres = lwres_noopresponse_render(client->clientmgr->lwctx, &resp,
					  &client->pkt, &lwb);
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

	/*
	 * We can now destroy request.
	 */
	lwres_nooprequest_free(client->clientmgr->lwctx, &req);

	CLIENT_SETSEND(client);

	return;

 out:
	if (req != NULL)
		lwres_nooprequest_free(client->clientmgr->lwctx, &req);

	if (lwb.base != NULL)
		lwres_context_freemem(client->clientmgr->lwctx,
				      lwb.base, lwb.length);

	error_pkt_send(client, LWRES_R_FAILURE);
}
