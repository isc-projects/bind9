/*
 * Copyright (C) 1997, 1998, 1999, 2000  Internet Software Consortium.
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

#include <stdio.h>
#include <stdlib.h>

#include <isc/assertions.h>

/*
 * Forward.
 */

static void
default_callback(const char *, int, isc_assertiontype_t, const char *);

/*
 * Public.
 */

isc_assertioncallback_t isc_assertion_failed = default_callback;

void
isc_assertion_setcallback(isc_assertioncallback_t cb) {
	if (cb == NULL)
		isc_assertion_failed = default_callback;
	else
		isc_assertion_failed = cb;
}

const char *
isc_assertion_typetotext(isc_assertiontype_t type) {
	const char *result;

	switch (type) {
	case isc_assertiontype_require:
		result = "REQUIRE";
		break;
	case isc_assertiontype_ensure:
		result = "ENSURE";
		break;
	case isc_assertiontype_insist:
		result = "INSIST";
		break;
	case isc_assertiontype_invariant:
		result = "INVARIANT";
		break;
	default:
		result = NULL;
	}
	return (result);
}

/*
 * Private.
 */

static void
default_callback(const char *file, int line, isc_assertiontype_t type,
		 const char *cond)
{
	fprintf(stderr, "%s:%d: %s(%s) failed.\n",
		file, line, isc_assertion_typetotext(type), cond);
	fflush(stderr);
	abort();
	/* NOTREACHED */
}
