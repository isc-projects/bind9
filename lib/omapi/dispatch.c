/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
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

/* $Id: dispatch.c,v 1.8 2000/01/17 18:02:05 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * I/O dispatcher.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/int.h>

#include <omapi/private.h>

isc_result_t
omapi_dispatch(struct timeval *t) {
	/*
	 * XXXDCL sleep forever?  The socket thread will be doing all the work.
	 */

	select(0, NULL, NULL, NULL, t ? t : NULL);
	return (ISC_R_SUCCESS);
}
