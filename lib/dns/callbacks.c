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

 /* $Id: callbacks.c,v 1.2 1999/03/06 04:08:29 halley Exp $ */

#include <config.h>

#include <stdarg.h>

#include <isc/assertions.h>
#include <dns/callbacks.h>

static void default_error_warn_callback(dns_rdatacallbacks_t *, char *, ...);

/*
 * Public.
 */

void
dns_rdatacallbacks_init(dns_rdatacallbacks_t *callbacks) {

	REQUIRE(callbacks != NULL);

	callbacks->commit = NULL;
	callbacks->error = default_error_warn_callback;
	callbacks->warn = default_error_warn_callback;
	callbacks->commit_private = NULL;
	callbacks->error_private = NULL;
	callbacks->warn_private = NULL;
}

/*
 * Private
 */

static void
default_error_warn_callback(dns_rdatacallbacks_t *callbacks, char *fmt, ...) {
	va_list ap;

	callbacks = callbacks; /*unused*/

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
