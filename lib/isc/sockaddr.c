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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/sockaddr.h>

isc_boolean_t
isc_sockaddr_equal(isc_sockaddr_t *a, isc_sockaddr_t *b)
{
	struct sockaddr *sa, *sb;

	sa = (struct sockaddr *)&a->type;
	sb = (struct sockaddr *)&b->type;

	if (sa->sa_family != sb->sa_family)
		return (ISC_FALSE);

#ifdef HAVE_SA_LEN
	if (sa->sa_len != sb->sa_len)
		return (ISC_FALSE);
	if (memcmp(sa->sa_data, sb->sa_data, sa->sa_len) != 0)
		return (ISC_FALSE);
#else
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sina, *sinb;

		sina = (struct sockaddr_in)sa;
		sinb = (struct sockaddr_in)sb;

		if (sina->sin_port != sinb->sin_port)
			return (ISC_FALSE);
		if (memcmp(&sina->sin_addr, &sinb->sin_addr, 4) != 0)
			return (ISC_FALSE);

		return (ISC_TRUE);
	}
	default:
		INSIST("Unknown socket protocol");
		break;
	}

#endif

	UNEXPECTED_ERROR(__FILE__, __LINE__, "Cannot happen");
	return (ISC_FALSE);
}
