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

#include <dns/fixedname.h>

#include <lwres/lwres.h>
#include <lwres/result.h>

#include "client.h"

static void
process_gabn_finddone(isc_task_t *task, isc_event_t *ev)
{
}

static isc_result_t
start_v4find(client_t *client)
{
	unsigned int options;
	isc_result_t result;
	dns_fixedname_t cname;

	/*
	 * Issue a find for the name contained in the request.  We won't
	 * set the bit that says "anything is good enough" -- we want it
	 * all.
	 */
	options = 0;
	options |= DNS_ADBFIND_WANTEVENT;
	options |= DNS_ADBFIND_INET;

	/*
	 * Set the bits up here to mark that we want this address family
	 * and that we do not currently have a find pending.  We will
	 * set that bit again below if it turns out we will get an event.
	 */
	INSIST((client->find_wanted & LWRES_ADDRTYPE_V4) != 0);
	client->find_pending &= LWRES_ADDRTYPE_V4;

	dns_fixedname_init(&cname);

	if (client->v4find != NULL)
		dns_adb_destroyfind(&client->v4find);

	result = dns_adb_createfind(client->clientmgr->view->adb,
				    client->clientmgr->task,
				    process_gabn_finddone, client,
				    dns_fixedname_name(&client->target_name),
				    dns_rootname, options, 0,
				    dns_fixedname_name(&cname),
				    &client->v4find);

	/*
	 * If we're going to get an event, set our internal pending flag.
	 */
	if ((client->v4find->options & DNS_ADBFIND_WANTEVENT) != 0)
		client->find_pending |= LWRES_ADDRTYPE_V4;

	/*
	 * If we get here, we either have a find pending, or we have
	 * data.  If we have all the data there is to be had, mark us as done.
	 * Otherwise, leave us running and let our event callback call
	 * us again.
	 *
	 * Eventually we'll get a valid result, either a list of addresses
	 * or failure.
	 */
	switch (result) {
	}

	/*
	 * If there is an event pending, wait for it.  The event callback
	 * will kill this fetch and reissue it.
	 */
	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
start_v6find(client_t *client)
{
	unsigned int options;
	isc_result_t result;

	/*
	 * Issue a find for the name contained in the request.  We won't
	 * set the bit that says "anything is good enough" -- we want it
	 * all.
	 */
	options = 0;
	options |= DNS_ADBFIND_WANTEVENT;
	options |= DNS_ADBFIND_INET6;

	/*
	 * If there is an event pending, wait for it.  The event callback
	 * will kill this fetch and reissue it.
	 */
	return (ISC_R_NOTIMPLEMENTED);
}


/*
 * When we are called, we can be assured that:
 *
 *	client->sockaddr contains the address we need to reply to,
 *
 *	client->pkt contains the packet header data,
 *
 *	the packet "checks out" overall -- any MD5 hashes or crypto
 *	bits have been verified,
 *
 *	"b" points to the remaining data after the packet header
 *	was parsed off.
 *
 *	We are in a the RECVDONE state.
 *
 * From this state we will enter the SEND state if we happen to have
 * everything we need or we need to return an error packet, or to the
 * FINDWAIT state if we need to look things up.
 */
void
process_gabn(client_t *client, lwres_buffer_t *b)
{
	isc_result_t result;
	lwres_gabnrequest_t *req;
	isc_buffer_t namebuf;

	REQUIRE(CLIENT_ISRECVDONE(client));

	req = NULL;

	result = lwres_gabnrequest_parse(client->clientmgr->lwctx,
					 b, &client->pkt, &req);
	if (result != ISC_R_SUCCESS)
		goto out;

	isc_buffer_init(&namebuf, req->name, req->namelen,
			ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&namebuf, req->namelen);

	dns_fixedname_init(&client->target_name);
	result = dns_name_fromtext(dns_fixedname_name(&client->target_name),
				   &namebuf, dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS)
		goto out;

	client->find_pending = 0;
	client->find_wanted = req->addrtypes;

	if ((req->addrtypes & LWRES_ADDRTYPE_V4) != 0) {
		result = start_v4find(client);
		if (result != ISC_R_SUCCESS)
			goto out;
	}

	if ((req->addrtypes & LWRES_ADDRTYPE_V6) != 0) {
		result = start_v6find(client);
		if (result != ISC_R_SUCCESS)
			goto out;
	}

	/*
	 * We no longer need to keep this around.  Return success, and
	 * let the find*() functions drive us from now on.
	 */
	lwres_gabnrequest_free(client->clientmgr->lwctx, &req);

	return;

	/*
	 * We're screwed.  Return an error packet to our caller.
	 */
 out:
	if (req != NULL)
		lwres_gabnrequest_free(client->clientmgr->lwctx, &req);

	error_pkt_send(client, LWRES_R_FAILURE);

	return;
}
