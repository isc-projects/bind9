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
lwres_gabnrequest_render(lwres_context_t *ctx, lwres_gabnrequest_t *req,
			 lwres_lwpacket_t *pkt, lwres_buffer_t *b)
{
	unsigned char *buf;
	size_t buflen;
	int ret;
	size_t payload_length;
	isc_uint16_t datalen;

	REQUIRE(ctx != NULL);
	REQUIRE(req != NULL);
	REQUIRE(req->name != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);

	datalen = strlen(req->name);

	payload_length = LWRES_STRING_LENGTH(req->name);

	buflen = LWRES_LWPACKET_LENGTH + payload_length;
	buf = CTXMALLOC(buflen);
	if (buf == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	lwres_buffer_init(b, buf, buflen);

	pkt->length = buflen;
	pkt->version = LWRES_LWPACKETVERSION_0;
	pkt->flags &= ~LWRES_LWPACKETFLAG_RESPONSE;
	pkt->opcode = LWRES_OPCODE_GETADDRSBYNAME;
	pkt->result = 0;
	pkt->authtype = 0;
	pkt->authlength = 0;

	ret = lwres_lwpacket_renderheader(b, pkt);
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
	lwres_buffer_putuint16(b, datalen);
	lwres_buffer_putmem(b, req->name, datalen + 1); /* trailing NUL */

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_gabnresponse_render(lwres_context_t *ctx, lwres_gabnresponse_t *req,
			  lwres_lwpacket_t *pkt, lwres_buffer_t *b)
{
	unsigned char *buf;
	size_t buflen;
	int ret;
	size_t payload_length;
	isc_uint16_t datalen;
	int x;

	REQUIRE(ctx != NULL);
	REQUIRE(req != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);

	/* naliases, naddrs */
	payload_length = sizeof(isc_uint16_t) * 2;
	/* real name encoding */
	payload_length += LWRES_STRING_LENGTH(req->real_name);
	/* each alias */
	for (x = 0 ; x < req->naliases ; x++)
		payload_length += LWRES_STRING_LENGTH(req->aliases[x]);
	/* each address */
	for (x = 0 ; x < req->naddrs ; x++) {
		payload_length += sizeof(isc_uint32_t) + sizeof(isc_uint16_t);
		payload_length += req->addrs[x].length;
	}

	buflen = LWRES_LWPACKET_LENGTH + payload_length;
	buf = CTXMALLOC(buflen);
	if (buf == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	lwres_buffer_init(b, buf, buflen);

	pkt->length = buflen;
	pkt->version = LWRES_LWPACKETVERSION_0;
	pkt->flags |= LWRES_LWPACKETFLAG_RESPONSE;
	pkt->opcode = LWRES_OPCODE_GETADDRSBYNAME;
	pkt->authtype = 0;
	pkt->authlength = 0;

	ret = lwres_lwpacket_renderheader(b, pkt);
	if (ret != 0) {
		lwres_buffer_invalidate(b);
		CTXFREE(buf, buflen);
		return (ret);
	}

	/* encode naliases and naddrs */

	INSIST(SPACE_OK(b, sizeof(isc_uint16_t) * 2));
	lwres_buffer_putuint16(b, req->naliases);
	lwres_buffer_putuint16(b, req->naddrs);

	/* encode the real name */
	datalen = strlen(req->real_name);
	INSIST(SPACE_OK(b, LWRES_STRING_LENGTH(req->real_name)));
	lwres_buffer_putuint16(b, datalen);
	lwres_buffer_putmem(b, req->real_name, datalen + 1);

	/* encode the aliases */
	for (x = 0 ; x < req->naliases ; x++) {
		datalen = strlen(req->aliases[x]);
		INSIST(SPACE_OK(b, LWRES_STRING_LENGTH(req->aliases[x])));
		lwres_buffer_putuint16(b, datalen);
		lwres_buffer_putmem(b, req->aliases[x], datalen + 1);
	}

	/* encode the addresses */
	for (x = 0 ; x < req->naddrs ; x++) {
		datalen = req->addrs[x].length + sizeof(isc_uint16_t)
			+ sizeof(isc_uint32_t);
		INSIST(SPACE_OK(b, datalen));
		lwres_buffer_putuint32(b, req->addrs[x].family);
		lwres_buffer_putuint16(b, req->addrs[x].length);
		lwres_buffer_putmem(b, req->addrs[x].address,
				    req->addrs[x].length);
	}

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_gabnrequest_parse(lwres_context_t *ctx, lwres_lwpacket_t *pkt,
			lwres_buffer_t *b, lwres_gabnrequest_t **structp)
{
	int ret;
	char *name;
	lwres_gabnrequest_t *gabn;

	REQUIRE(ctx != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	if ((pkt->flags & LWRES_LWPACKETFLAG_RESPONSE) == 0)
		return (-1);

	/*
	 * Pull off the name itself
	 */
	ret = lwres_string_parse(b, &name, NULL);
	if (ret != 0)
		return (ret);

	gabn = CTXMALLOC(sizeof(lwres_gabnrequest_t));
	if (gabn == NULL)
		return (-1);

	gabn->name = name;

	*structp = gabn;
	return (0);
}

int
lwres_gabnresponse_parse(lwres_context_t *ctx, lwres_lwpacket_t *pkt,
			 lwres_buffer_t *b, lwres_gabnresponse_t **structp)
{
	int ret;
	unsigned int x;
	isc_uint16_t naliases;
	isc_uint16_t naddrs;
	lwres_gabnresponse_t *gabn;

	REQUIRE(ctx != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	gabn = NULL;

	if ((pkt->flags & LWRES_LWPACKETFLAG_RESPONSE) == 0)
		return (-1);

	/*
	 * Pull off the name itself
	 */
	if (!SPACE_REMAINING(b, sizeof(isc_uint16_t) * 2))
		return (-1);
	naliases = lwres_buffer_getuint16(b);
	naddrs = lwres_buffer_getuint16(b);

	gabn = CTXMALLOC(sizeof(lwres_gabnresponse_t));
	if (gabn == NULL)
		return (-1);
	gabn->naliases = 0;
	gabn->naddrs = 0;

	gabn->aliases = CTXMALLOC(sizeof(char *) * naliases);
	if (gabn->aliases == NULL) {
		ret = -1;
		goto out;
	}
	gabn->naliases = naliases;

	gabn->addrs = CTXMALLOC(sizeof(lwres_addr_t) * naddrs);
	if (gabn->addrs == NULL) {
		ret = -1;
		goto out;
	}
	gabn->naddrs = naddrs;

	/*
	 * Now, pull off the real name.
	 */
	ret = lwres_string_parse(b, &gabn->real_name, NULL);
	if (ret != 0)
		goto out;

	/*
	 * Pull off the addresses.
	 */
	for (x = 0 ; x < gabn->naddrs ; x++) {
		ret = lwres_addr_parse(b, &gabn->addrs[x]);
		if (ret != 0)
			goto out;
	}

	/*
	 * Parse off the aliases.
	 */
	for (x = 0 ; x < gabn->naliases ; x++) {
		ret = lwres_string_parse(b, &gabn->aliases[x], NULL);
		if (ret != 0)
			goto out;
	}

	/* XXXMLG Should check for trailing bytes */

	*structp = gabn;
	return (0);

 out:
	if (gabn != NULL)
		lwres_gabnresponse_free(ctx, &gabn);

	return (ret);
}

void
lwres_gabnrequest_free(lwres_context_t *ctx, lwres_gabnrequest_t **structp)
{
	lwres_gabnrequest_t *gabn;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	gabn = *structp;
	*structp = NULL;

	CTXFREE(gabn, sizeof(lwres_gabnrequest_t));
}

void
lwres_gabnresponse_free(lwres_context_t *ctx, lwres_gabnresponse_t **structp)
{
	lwres_gabnresponse_t *gabn;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	gabn = *structp;
	*structp = NULL;

	if (gabn->naliases > 0)
		CTXFREE(gabn->aliases, sizeof(char *) * gabn->naliases);
	if (gabn->naddrs > 0)
		CTXFREE(gabn->addrs, sizeof(lwres_addr_t *) * gabn->naddrs);
	CTXFREE(gabn, sizeof(lwres_gabnresponse_t));
}
