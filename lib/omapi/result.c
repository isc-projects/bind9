/* result.c

   Cheap knock-off of libisc result table code.   This is just a place-holder
   until the actual libisc merge. */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#include <omapip/omapip_p.h>

static const char *text[ISC_R_NRESULTS] = {
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
	"shutting down",			/* 22 */
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
	"quota reached",			/* 33 */
	"unexpected error",			/* 34 */
	"already running",			/* 35 */
	"host unknown",				/* 36 */
	"protocol version mismatch",		/* 37 */
	"protocol error",			/* 38 */
	"invalid argument",			/* 39 */
	"not connected",			/* 40 */
	"data not yet available",		/* 41 */
	"object unchanged",			/* 42 */
	"more than one object matches key",	/* 43 */
	"key conflict",				/* 44 */
	"parse error(s) occurred",		/* 45 */
	"no key specified",			/* 46 */
};

const char *isc_result_totext (isc_result_t result)
{
	if (result >= ISC_R_SUCCESS && result < ISC_R_NRESULTS)
		return text [result];
	return "unknown error.";
}
