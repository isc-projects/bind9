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

#include "client.h"

static void
process_gabn_finddone(isc_task_t *task, isc_event_t *ev)
{
}

isc_result_t
process_gabn(client_t *client, lwres_buffer_t *b, lwres_lwpacket_t *pkt)
{
	isc_result_t result;
	lwres_lwpacket_t rpkt;
	lwres_gabnrequest_t *req;
	lwres_gabnresponse_t resp;
	unsigned int options;
	dns_fixedname_t name;
	isc_buffer_t namebuf;

	req = NULL;

	result = lwres_gabnrequest_parse(client->clientmgr->lwctx,
					 b, pkt, &req);
	if (result != ISC_R_SUCCESS)
		goto out;

	isc_buffer_init(&namebuf, req->name, req->namelen,
			ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&namebuf, req->namelen);

	dns_fixedname_init(&name);
	result = dns_name_fromtext(dns_fixedname_name(&name), &namebuf,
				   dns_rootname, ISC_FALSE, NULL);

	/*
	 * Issue a find for the name contained in the request.  We won't
	 * set the bit that says "anything is good enough" -- we want it
	 * all.
	 */
	options = 0;
	options |= DNS_ADBFIND_WANTEVENT;

	if ((req->addrtypes & LWRES_ADDRTYPE_V4) != 0) {
		result = dns_adb_createfind(client->clientmgr->view->adb,
					    client->clientmgr->task,
					    process_gabn_finddone, client,
					    dns_fixedname_name(&name),
					    dns_rootname,
					    options | DNS_ADBFIND_INET,
					    0, &client->v4find);
	}

	if ((req->addrtypes & LWRES_ADDRTYPE_V6) != 0) {
		result = dns_adb_createfind(client->clientmgr->view->adb,
					    client->clientmgr->task,
					    process_gabn_finddone, client,
					    dns_fixedname_name(&name),
					    dns_rootname,
					    options | DNS_ADBFIND_INET6,
					    0, &client->v6find);
	}

	return (ISC_R_SUCCESS);

 out:
	if (req != NULL)
		lwres_gabnrequest_free(client->clientmgr->lwctx, &req);

	return (result);
}

isc_result_t
process_gnba(client_t *client, lwres_buffer_t *b, lwres_lwpacket_t *pkt)
{
	lwres_lwpacket_t rpkt;
	lwres_gnbarequest_t *req;
	lwres_gnbaresponse_t resp;

	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
process_noop(client_t *client, lwres_buffer_t *b, lwres_lwpacket_t *pkt)
{
	lwres_lwpacket_t rpkt;
	lwres_nooprequest_t *req;
	lwres_noopresponse_t resp;

	return (ISC_R_NOTIMPLEMENTED);
}
