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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwpacket.h>
#include <lwres/lwres.h>

#include "context_p.h"
#include "assert_p.h"

int
lwres_nooprequest_render(lwres_context_t *ctx, lwres_nooprequest_t *req,
			 isc_uint32_t maxrecv, lwres_buffer_t *b)
{
	lwres_lwpacket_t pkt;
	unsigned char *buf;
	size_t buflen;
	int ret;
	size_t payload_length;

	REQUIRE(ctx != NULL);
	REQUIRE(req != NULL);
	REQUIRE(b != NULL);

	payload_length = sizeof(isc_uint16_t) + req->datalength;

	buflen = sizeof(lwres_lwpacket_t) + payload_length;
	buf = CTXMALLOC(buflen);
	if (buf == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	lwres_buffer_init(b, buf, buflen);

	pkt.length = buflen;
	pkt.version = LWRES_LWPACKETVERSION_0;
	pkt.flags = 0;
	pkt.serial = req->serial;
	pkt.opcode = LWRES_OPCODE_NOOP;
	pkt.result = 0;
	pkt.recvlength = maxrecv;
	pkt.authtype = 0;
	pkt.authlength = 0;

	ret = lwres_lwpacket_renderheader(b, &pkt);
	if (ret != 0) {
		lwres_buffer_invalidate(b);
		CTXFREE(buf, buflen);
		return (ret);
	}

	INSIST(SPACE_OK(b, payload_length));

	/*
	 * Put the length and the data.  We know this will fit because we
	 * just checked for it.
	 */
	lwres_buffer_putuint16(b, req->datalength);
	lwres_buffer_putmem(b, req->data, req->datalength);

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_noopresponse_render(lwres_context_t *ctx, lwres_noopresponse_t *req,
			  isc_uint32_t maxrecv, lwres_buffer_t *b)
{
	lwres_lwpacket_t pkt;
	unsigned char *buf;
	size_t buflen;
	int ret;
	size_t payload_length;

	REQUIRE(ctx != NULL);
	REQUIRE(req != NULL);
	REQUIRE(b != NULL);

	payload_length = sizeof(isc_uint16_t) + req->datalength;

	buflen = sizeof(lwres_lwpacket_t) + payload_length;
	buf = CTXMALLOC(buflen);
	if (buf == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	lwres_buffer_init(b, buf, buflen);

	pkt.length = buflen;
	pkt.version = LWRES_LWPACKETVERSION_0;
	pkt.flags = LWRES_LWPACKETFLAG_RESPONSE;
	pkt.serial = req->serial;
	pkt.opcode = LWRES_OPCODE_NOOP;
	pkt.result = req->result;
	pkt.recvlength = maxrecv;
	pkt.authtype = 0;
	pkt.authlength = 0;

	ret = lwres_lwpacket_renderheader(b, &pkt);
	if (ret != 0) {
		lwres_buffer_invalidate(b);
		CTXFREE(buf, buflen);
		return (ret);
	}

	INSIST(SPACE_OK(b, payload_length));

	/*
	 * Put the length and the data.  We know this will fit because we
	 * just checked for it.
	 */
	lwres_buffer_putuint16(b, req->datalength);
	lwres_buffer_putmem(b, req->data, req->datalength);

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_nooprequest_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			lwres_nooprequest_t **structp)
{
	lwres_lwpacket_t pkt;
	int ret;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp == NULL);
	REQUIRE(b != NULL);

	/*
	 * First, parse out the header.
	 */
	ret = lwres_lwpacket_parseheader(&pkt, b);
	if (ret != 0)
		return (ret);

	
}

int
lwres_noopresponse_parse(lwres_context_t *ctx, lwres_noopresponse_t **structp)
{
	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

}

void
lwres_noopresponse_free(lwres_context_t *ctx, lwres_noopresponse_t **structp)
{
	lwres_noopresponse_t *noop;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	noop = *structp;
	*structp = NULL;

	if (noop->buffer != NULL)
		CTXFREE(noop->buffer, noop->buflen);
	CTXFREE(noop, sizeof(lwres_noopresponse_t));
}

void
lwres_nooprequest_free(lwres_context_t *ctx, lwres_nooprequest_t **structp)
{
	lwres_nooprequest_t *noop;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	noop = *structp;
	*structp = NULL;

	if (noop->buffer != NULL)
		CTXFREE(noop->buffer, noop->buflen);
	CTXFREE(noop, sizeof(lwres_nooprequest_t));
}
