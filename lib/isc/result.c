/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <isc/result.h>

static char *text_table[ISC_R_LASTENTRY + 1] = {
	"success",				/*  0 */
	"out of memory",			/*  1 */
	"timed out",				/*  2 */
	"no available threads",			/*  3 */
	"address not available",		/*  4 */
	"address in use",			/*  5 */
	"permission denied",			/*  6 */
	"no pending connections",		/*  7 */
	"network unreachable",			/*  8 */
	"host unreachable",			/*  9 */
	"network down",				/* 10 */
	"host down",				/* 11 */
	"connection refused",			/* 12 */
	"not enough free resources",		/* 13 */
	"end of file",				/* 14 */
	"socket already bound",			/* 15 */
	"task is done",				/* 16 */
	"lock busy",				/* 17 */
	"already exists",			/* 18 */
	"ran out of space",			/* 19 */
	"operation canceled",			/* 20 */
	"sending events is not allowed",	/* 21 */
	"task is shutting down",		/* 22 */
	"not found",				/* 23 */
	"unexpected end of input",		/* 24 */
	"failure",				/* 25 */
	"I/O error",				/* 26 */
	"not implemented",			/* 27 */
	"unbalanced parentheses",		/* 28 */
	"no more",				/* 29 */
	"invalid file",				/* 30 */
	"bad base64 encoding",			/* 31 */
	"unexpected token",			/* 32 */
};

char *
isc_result_totext(isc_result_t result) {
	if (result == ISC_R_UNEXPECTED)
		return ("unexpected error");
	if (result > ISC_R_LASTENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
