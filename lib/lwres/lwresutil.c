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
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwres.h>

#include "assert_p.h"
#include "context_p.h"

/*
 * Requires:
 *
 *	The "current" pointer in "b" point to an encoded string.
 *
 * Ensures:
 *
 *	The address of the first byte of the string is returned via "c",
 *	and the length is returned via "len".  If NULL, they are not
 *	set.
 *
 *	On return, the current pointer of "b" will point to the character
 *	following the string length, the stirng, and the trailing NUL.
 *
 */
int
lwres_string_parse(lwres_buffer_t *b, char **c, isc_uint16_t *len)
{
	isc_uint16_t datalen;
	char *string;

	REQUIRE(b != NULL);

	if (!SPACE_REMAINING(b, sizeof(isc_uint16_t)))
		return (-1);
	datalen = lwres_buffer_getuint16(b);
	datalen++;
	if (!SPACE_REMAINING(b, datalen))
		return (-1);

	string = b->base + b->current;

	lwres_buffer_forward(b, datalen);

	if (len != NULL)
		*len = datalen - 1;
	if (c != NULL)
		*c = string;

	return (0);
}

int
lwres_addr_parse(lwres_buffer_t *b, lwres_addr_t *addr)
{
	REQUIRE(addr != NULL);

	if (!SPACE_REMAINING(b, sizeof(isc_uint32_t) + sizeof(isc_uint16_t)))
		return (-1);
	addr->family = lwres_buffer_getuint32(b);
	addr->length = lwres_buffer_getuint16(b);
	if (!SPACE_REMAINING(b, addr->length))
		return (-1);
	addr->address = b->base + b->current;
	lwres_buffer_forward(b, addr->length);

	return (0);
}

int
lwres_getaddrsbyname(lwres_context_t *ctx, const char *name,
		     isc_uint32_t addrtypes, lwres_gabnresponse_t **structp)
{
	lwres_gabnrequest_t request;
	lwres_gabnresponse_t *response;
	int ret;
	int free_b;
	lwres_buffer_t b;
	lwres_lwpacket_t pkt;
	isc_uint32_t serial;
	char *buffer;

	REQUIRE(ctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(addrtypes != 0);
	REQUIRE(structp != NULL && *structp == NULL);

	response = NULL;
	free_b = 0;
	buffer = NULL;
	serial = (isc_uint32_t)name;

	buffer = CTXMALLOC(LWRES_RECVLENGTH);
	if (buffer == NULL) {
		ret = -1;
		goto out;
	}

	/*
	 * Set up our request and render it to a buffer.
	 */
	request.addrtypes = addrtypes;
	request.name = (char *)name;
	pkt.flags = 0;
	pkt.serial = serial;
	pkt.result = 0;
	pkt.recvlength = LWRES_RECVLENGTH;

	ret = lwres_gabnrequest_render(ctx, &request, &pkt, &b);
	if (ret != 0)
		goto out;
	free_b = 1;

	ret = lwres_context_sendrecv(ctx, b.base, b.length, buffer,
				     LWRES_RECVLENGTH);
	if (ret < 0)
		goto out;

	CTXFREE(b.base, b.length);
	free_b = 0;

	lwres_buffer_init(&b, buffer, ret);

	/*
	 * Parse the packet header.
	 */
	ret = lwres_lwpacket_parseheader(&b, &pkt);
	if (ret != 0)
		goto out;

	/*
	 * Sanity check.
	 */
	if (pkt.serial != serial) {
		ret = -1;
		goto out;
	}
	if (pkt.opcode != LWRES_OPCODE_GETADDRSBYNAME) {
		ret = -1;
		goto out;
	}

	/*
	 * Parse the response.
	 */
	ret = lwres_gabnresponse_parse(ctx, &b, &pkt, &response);
	if (ret != 0)
		goto out;
	response->base = buffer;
	response->baselen = LWRES_RECVLENGTH;
	buffer = NULL; /* don't free this below */

	*structp = response;
	return (0);

 out:
	if (free_b != 0)
		CTXFREE(b.base, b.length);
	if (buffer != NULL)
		CTXFREE(buffer, LWRES_RECVLENGTH);
	if (response != NULL)
		lwres_gabnresponse_free(ctx, &response);

	return (ret);
}


int
lwres_getnamebyaddr(lwres_context_t *ctx, isc_uint32_t addrtype,
		    isc_uint16_t addrlen, unsigned char *addr,
		    lwres_gnbaresponse_t **structp)
{
	lwres_gnbarequest_t request;
	lwres_gnbaresponse_t *response;
	int ret;
	int free_b;
	lwres_buffer_t b;
	lwres_lwpacket_t pkt;
	isc_uint32_t serial;
	char *buffer;

	REQUIRE(ctx != NULL);
	REQUIRE(addrtype != 0);
	REQUIRE(addrlen != 0);
	REQUIRE(addr != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	response = NULL;
	free_b = 0;
	buffer = NULL;
	serial = (isc_uint32_t)addr;

	buffer = CTXMALLOC(LWRES_RECVLENGTH);
	if (buffer == NULL) {
		ret = -1;
		goto out;
	}

	/*
	 * Set up our request and render it to a buffer.
	 */
	request.addr.family = addrtype;
	request.addr.length = addrlen;
	request.addr.address = addr;
	pkt.flags = 0;
	pkt.serial = serial;
	pkt.result = 0;
	pkt.recvlength = LWRES_RECVLENGTH;

	ret = lwres_gnbarequest_render(ctx, &request, &pkt, &b);
	if (ret != 0)
		goto out;
	free_b = 1;

	ret = lwres_context_sendrecv(ctx, b.base, b.length, buffer,
				     LWRES_RECVLENGTH);
	if (ret < 0)
		goto out;

	CTXFREE(b.base, b.length);
	free_b = 0;

	lwres_buffer_init(&b, buffer, ret);

	/*
	 * Parse the packet header.
	 */
	ret = lwres_lwpacket_parseheader(&b, &pkt);
	if (ret != 0)
		goto out;

	/*
	 * Sanity check.
	 */
	if (pkt.serial != serial) {
		ret = -1;
		goto out;
	}
	if (pkt.opcode != LWRES_OPCODE_GETNAMEBYADDR) {
		ret = -1;
		goto out;
	}

	/*
	 * Parse the response.
	 */
	ret = lwres_gnbaresponse_parse(ctx, &b, &pkt, &response);
	if (ret != 0)
		goto out;
	response->base = buffer;
	response->baselen = LWRES_RECVLENGTH;
	buffer = NULL; /* don't free this below */

	*structp = response;
	return (0);

 out:
	if (free_b != 0)
		CTXFREE(b.base, b.length);
	if (buffer != NULL)
		CTXFREE(buffer, LWRES_RECVLENGTH);
	if (response != NULL)
		lwres_gnbaresponse_free(ctx, &response);

	return (ret);
}
