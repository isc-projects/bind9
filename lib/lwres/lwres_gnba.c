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
lwres_gnbarequest_render(lwres_context_t *ctx, lwres_gnbarequest_t *req,
			 lwres_lwpacket_t *pkt, lwres_buffer_t *b)
{
	unsigned char *buf;
	size_t buflen;
	int ret;
	size_t payload_length;

	REQUIRE(ctx != NULL);
	REQUIRE(req != NULL);
	REQUIRE(req->addr.family != 0);
	REQUIRE(req->addr.length != 0);
	REQUIRE(req->addr.address != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);

	payload_length = sizeof(isc_uint32_t) + sizeof(isc_uint16_t)
		+ req->addr.length;

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
	pkt->opcode = LWRES_OPCODE_GETNAMEBYADDR;
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
	lwres_buffer_putuint32(b, req->addr.family);
	lwres_buffer_putuint16(b, req->addr.length);
	lwres_buffer_putmem(b, req->addr.address, req->addr.length);

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_gnbaresponse_render(lwres_context_t *ctx, lwres_gnbaresponse_t *req,
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

	/* naliases */
	payload_length = sizeof(isc_uint16_t);
	/* real name encoding */
	payload_length += LWRES_STRING_LENGTH(req->real_name);
	/* each alias */
	for (x = 0 ; x < req->naliases ; x++)
		payload_length += LWRES_STRING_LENGTH(req->aliases[x]);

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
	pkt->opcode = LWRES_OPCODE_GETNAMEBYADDR;
	pkt->authtype = 0;
	pkt->authlength = 0;

	ret = lwres_lwpacket_renderheader(b, pkt);
	if (ret != 0) {
		lwres_buffer_invalidate(b);
		CTXFREE(buf, buflen);
		return (ret);
	}

	/* encode naliases */
	INSIST(SPACE_OK(b, sizeof(isc_uint16_t) * 2));
	lwres_buffer_putuint16(b, req->naliases);

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

	INSIST(LWRES_BUFFER_AVAILABLECOUNT(b) == 0);

	return (0);
}

int
lwres_gnbarequest_parse(lwres_context_t *ctx, lwres_lwpacket_t *pkt,
			lwres_buffer_t *b, lwres_gnbarequest_t **structp)
{
	int ret;
	lwres_gnbarequest_t *gnba;

	REQUIRE(ctx != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	if ((pkt->flags & LWRES_LWPACKETFLAG_RESPONSE) == 0)
		return (-1);

	gnba = CTXMALLOC(sizeof(lwres_gnbarequest_t));
	if (gnba == NULL)
		return (-1);

	ret = lwres_addr_parse(b, &gnba->addr);
	if (ret != 0)
		goto out;

	if (LWRES_BUFFER_REMAINING(b) != 0) {
		ret = -1;
		goto out;
	}

	*structp = gnba;
	return (0);

 out:
	if (gnba != NULL)
		lwres_gnbarequest_free(ctx, &gnba);

	return (ret);
}

int
lwres_gnbaresponse_parse(lwres_context_t *ctx, lwres_lwpacket_t *pkt,
			 lwres_buffer_t *b, lwres_gnbaresponse_t **structp)
{
	int ret;
	unsigned int x;
	isc_uint16_t naliases;
	lwres_gnbaresponse_t *gnba;

	REQUIRE(ctx != NULL);
	REQUIRE(pkt != NULL);
	REQUIRE(b != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	gnba = NULL;

	if ((pkt->flags & LWRES_LWPACKETFLAG_RESPONSE) == 0)
		return (-1);

	/*
	 * Pull off the name itself
	 */
	if (!SPACE_REMAINING(b, sizeof(isc_uint16_t)))
		return (-1);
	naliases = lwres_buffer_getuint16(b);

	gnba = CTXMALLOC(sizeof(lwres_gnbaresponse_t));
	if (gnba == NULL)
		return (-1);
	gnba->naliases = 0;
	gnba->base = NULL;

	gnba->aliases = CTXMALLOC(sizeof(char *) * naliases);
	if (gnba->aliases == NULL) {
		ret = -1;
		goto out;
	}
	gnba->naliases = naliases;

	/*
	 * Now, pull off the real name.
	 */
	ret = lwres_string_parse(b, &gnba->real_name, NULL);
	if (ret != 0)
		goto out;

	/*
	 * Parse off the aliases.
	 */
	for (x = 0 ; x < gnba->naliases ; x++) {
		ret = lwres_string_parse(b, &gnba->aliases[x], NULL);
		if (ret != 0)
			goto out;
	}

	if (LWRES_BUFFER_REMAINING(b) != 0) {
		ret = -1;
		goto out;
	}

	*structp = gnba;
	return (0);

 out:
	if (gnba != NULL)
		lwres_gnbaresponse_free(ctx, &gnba);

	return (ret);
}

void
lwres_gnbarequest_free(lwres_context_t *ctx, lwres_gnbarequest_t **structp)
{
	lwres_gnbarequest_t *gnba;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	gnba = *structp;
	*structp = NULL;

	CTXFREE(gnba, sizeof(lwres_gnbarequest_t));
}

void
lwres_gnbaresponse_free(lwres_context_t *ctx, lwres_gnbaresponse_t **structp)
{
	lwres_gnbaresponse_t *gnba;

	REQUIRE(ctx != NULL);
	REQUIRE(structp != NULL && *structp != NULL);

	gnba = *structp;
	*structp = NULL;

	if (gnba->naliases > 0)
		CTXFREE(gnba->aliases, sizeof(char *) * gnba->naliases);
	if (gnba->base != NULL)
		CTXFREE(gnba->base, gnba->baselen);
	CTXFREE(gnba, sizeof(lwres_gnbaresponse_t));
}
