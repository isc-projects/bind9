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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwres.h>
#include <lwres/result.h>

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
 *	following the string length, the string, and the trailing NULL.
 *
 */
lwres_result_t
lwres_string_parse(lwres_buffer_t *b, char **c, lwres_uint16_t *len)
{
	lwres_uint16_t datalen;
	char *string;

	REQUIRE(b != NULL);

	/*
	 * Pull off the length (2 bytes)
	 */
	if (!SPACE_REMAINING(b, 2))
		return (LWRES_R_UNEXPECTEDEND);
	datalen = lwres_buffer_getuint16(b);

	/*
	 * Set the pointer to this string to the right place, then
	 * advance the buffer pointer.
	 */
	if (!SPACE_REMAINING(b, datalen))
		return (LWRES_R_UNEXPECTEDEND);
	string = (char *)b->base + b->current;
	lwres_buffer_forward(b, datalen);

	/*
	 * Skip the "must be zero" byte.
	 */
	if (!SPACE_REMAINING(b, 1))
		return (LWRES_R_UNEXPECTEDEND);
	if (0 != lwres_buffer_getuint8(b))
		return (LWRES_R_FAILURE);

	if (len != NULL)
		*len = datalen;
	if (c != NULL)
		*c = string;

	return (LWRES_R_SUCCESS);
}

lwres_result_t
lwres_addr_parse(lwres_buffer_t *b, lwres_addr_t *addr)
{
	REQUIRE(addr != NULL);

	if (!SPACE_REMAINING(b, 6))
		return (LWRES_R_UNEXPECTEDEND);

	addr->family = lwres_buffer_getuint32(b);
	addr->length = lwres_buffer_getuint16(b);

	if (!SPACE_REMAINING(b, addr->length))
		return (LWRES_R_UNEXPECTEDEND);
	if (addr->length > LWRES_ADDR_MAXLEN)
		return (LWRES_R_FAILURE);

	lwres_buffer_getmem(b, addr->address, addr->length);

	return (LWRES_R_SUCCESS);
}

static void
count_dots(const char *name, unsigned int *ndots, unsigned int *last_was_dot)
{
	const char *p;

	p = name;
	*ndots = 0;
	*last_was_dot = 0;

	while (*p != 0) {
		if (*p++ == '.') {
			(*ndots)++;
			*last_was_dot = 1;
		} else {
			*last_was_dot = 0;
		}
	}
}

lwres_result_t
lwres_getaddrsbyname(lwres_context_t *ctx, const char *name,
		     lwres_uint32_t addrtypes, lwres_gabnresponse_t **structp)
{
	lwres_gabnrequest_t request;
	lwres_gabnresponse_t *response;
	int ret;
	int recvlen;
	lwres_buffer_t b_in, b_out;
	lwres_lwpacket_t pkt;
	lwres_uint32_t serial;
	char *buffer;
	int current_suffix;
	unsigned int ndots;
	unsigned int last_was_dot;
	unsigned int exact_first;
	char target_name[1024];
	unsigned int target_length;
	unsigned int tried_exact;
	unsigned int tried_search;

	REQUIRE(ctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(addrtypes != 0);
	REQUIRE(structp != NULL && *structp == NULL);

	count_dots(name, &ndots, &last_was_dot);
	if (last_was_dot || (ndots >= ctx->confdata.ndots))
		exact_first = 1;
	else
		exact_first = 0;
	
	current_suffix = 0;
	tried_exact = 0;
	tried_search = 0;

	b_in.base = NULL;
	b_out.base = NULL;
	response = NULL;
	buffer = NULL;
	serial = (lwres_uint32_t)name;

	buffer = CTXMALLOC(LWRES_RECVLENGTH);
	if (buffer == NULL) {
		ret = LWRES_R_NOMEMORY;
		goto out;
	}

 next_suffix:

	/*
	 * First, if the name ends in a dot, do an exact search.  Lie and
	 * pretend we have already done a search.
	 */
	if (last_was_dot)
		tried_search = 1;

	if (tried_exact && tried_search) {
		ret = LWRES_R_NOTFOUND;
		goto out;
	}

	/*
	 * Try the exact search first.  If this fails, try the
	 * search list.
	 */
	if (exact_first && !tried_exact) {
		tried_exact = 1;
		target_length = strlen(name);
		if (target_length >= sizeof(target_name))
			goto next_suffix;
		strcpy(target_name, name); /* strcpy is safe */
	} else {
		INSIST(!tried_search);
		if (current_suffix >= ctx->confdata.searchnxt) {
			tried_search = 1;
			exact_first = 1;
			goto next_suffix;
		}

		target_length = strlen(name)
			+ strlen(ctx->confdata.search[current_suffix])
			+ 1;
		if (target_length >= sizeof(target_name)) {
			current_suffix++;
			goto next_suffix;  /* XXXMLG */
		}
		sprintf(target_name, "%s.%s", /* sprintf is safe */
			name, ctx->confdata.search[current_suffix]);
		current_suffix++;
	}

	/*
	 * Set up our request and render it to a buffer.
	 */
	request.addrtypes = addrtypes;
	request.name = target_name;
	request.namelen = target_length;
	pkt.flags = 0;
	pkt.serial = serial;
	pkt.result = 0;
	pkt.recvlength = LWRES_RECVLENGTH;

 again:
	ret = lwres_gabnrequest_render(ctx, &request, &pkt, &b_out);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	ret = lwres_context_sendrecv(ctx, b_out.base, b_out.length, buffer,
				     LWRES_RECVLENGTH, &recvlen);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	lwres_buffer_init(&b_in, buffer, recvlen);
	b_in.used = recvlen;

	/*
	 * Parse the packet header.
	 */
	ret = lwres_lwpacket_parseheader(&b_in, &pkt);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	/*
	 * Sanity check.
	 */
	if (pkt.serial != serial)
		goto again;
	if (pkt.opcode != LWRES_OPCODE_GETADDRSBYNAME)
		goto again;

	/*
	 * Free what we've transmitted
	 */
	CTXFREE(b_out.base, b_out.length);
	b_out.base = NULL;
	b_out.length = 0;

	if (pkt.result == LWRES_R_NOTFOUND)
		goto next_suffix;

	if (pkt.result != LWRES_R_SUCCESS) {
		ret = pkt.result;
		goto out;
	}

	/*
	 * Parse the response.
	 */
	ret = lwres_gabnresponse_parse(ctx, &b_in, &pkt, &response);
	if (ret != LWRES_R_SUCCESS)
		goto out;
	response->base = buffer;
	response->baselen = LWRES_RECVLENGTH;
	buffer = NULL; /* don't free this below */

	*structp = response;
	return (LWRES_R_SUCCESS);

 out:
	if (b_out.base != NULL)
		CTXFREE(b_out.base, b_out.length);
	if (buffer != NULL)
		CTXFREE(buffer, LWRES_RECVLENGTH);
	if (response != NULL)
		lwres_gabnresponse_free(ctx, &response);

	return (ret);
}


lwres_result_t
lwres_getnamebyaddr(lwres_context_t *ctx, lwres_uint32_t addrtype,
		    lwres_uint16_t addrlen, const unsigned char *addr,
		    lwres_gnbaresponse_t **structp)
{
	lwres_gnbarequest_t request;
	lwres_gnbaresponse_t *response;
	int ret;
	int recvlen;
	lwres_buffer_t b_in, b_out;
	lwres_lwpacket_t pkt;
	lwres_uint32_t serial;
	char *buffer;

	REQUIRE(ctx != NULL);
	REQUIRE(addrtype != 0);
	REQUIRE(addrlen != 0);
	REQUIRE(addr != NULL);
	REQUIRE(structp != NULL && *structp == NULL);

	b_in.base = NULL;
	b_out.base = NULL;
	response = NULL;
	buffer = NULL;
	serial = (lwres_uint32_t)addr;

	buffer = CTXMALLOC(LWRES_RECVLENGTH);
	if (buffer == NULL) {
		ret = LWRES_R_NOMEMORY;
		goto out;
	}

	/*
	 * Set up our request and render it to a buffer.
	 */
	request.addr.family = addrtype;
	request.addr.length = addrlen;
	memcpy(request.addr.address, addr, addrlen);
	pkt.flags = 0;
	pkt.serial = serial;
	pkt.result = 0;
	pkt.recvlength = LWRES_RECVLENGTH;

 again:
	ret = lwres_gnbarequest_render(ctx, &request, &pkt, &b_out);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	ret = lwres_context_sendrecv(ctx, b_out.base, b_out.length, buffer,
				     LWRES_RECVLENGTH, &recvlen);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	lwres_buffer_init(&b_in, buffer, recvlen);
	b_in.used = recvlen;

	/*
	 * Parse the packet header.
	 */
	ret = lwres_lwpacket_parseheader(&b_in, &pkt);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	/*
	 * Sanity check.
	 */
	if (pkt.serial != serial)
		goto again;
	if (pkt.opcode != LWRES_OPCODE_GETNAMEBYADDR)
		goto again;

	/*
	 * Free what we've transmitted
	 */
	CTXFREE(b_out.base, b_out.length);
	b_out.base = NULL;
	b_out.length = 0;

	if (pkt.result != LWRES_R_SUCCESS) {
		ret = pkt.result;
		goto out;
	}

	/*
	 * Parse the response.
	 */
	ret = lwres_gnbaresponse_parse(ctx, &b_in, &pkt, &response);
	if (ret != LWRES_R_SUCCESS)
		goto out;
	response->base = buffer;
	response->baselen = LWRES_RECVLENGTH;
	buffer = NULL; /* don't free this below */

	*structp = response;
	return (LWRES_R_SUCCESS);

 out:
	if (b_out.base != NULL)
		CTXFREE(b_out.base, b_out.length);
	if (buffer != NULL)
		CTXFREE(buffer, LWRES_RECVLENGTH);
	if (response != NULL)
		lwres_gnbaresponse_free(ctx, &response);

	return (ret);
}
