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
#include <lwres/lwres.h>

#include "assert_p.h"

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

