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

#include <stddef.h>

#include <isc/resultclass.h>
#include <isc/once.h>
#include <isc/error.h>
#include <dns/result.h>

static char *text[DNS_R_NRESULTS] = {
	"success",				/*  0 */
	"out of memory",			/*  1 */
	"ran out of space",			/*  2 */
	"label too long",			/*  3 */
	"bad escape",				/*  4 */
	"bad bitstring",			/*  5 */
	"bitstring too long",			/*  6 */
	"empty label",				/*  7 */
	"bad dotted quad",			/*  8 */
	"unexpected end of input",		/*  9 */
	"not implemented",			/* 10 */
	"unknown class/type",			/* 11 */
	"bad label type",			/* 12 */
	"bad compression pointer",		/* 13 */
	"too many hops",			/* 14 */
	"disallowed (by application policy)",	/* 15 */
	"no more list elements",		/* 16 */
	"extra input text",			/* 17 */
	"extra input data",			/* 18 */
	"text too long",			/* 19 */
	"out of range",				/* 20 */
	"already exists",			/* 21 */
	"not found",				/* 22 */
	"syntax error",				/* 23 */
	"bad checksum",				/* 24 */
	"bad IPv6 address",			/* 25 */
	"no owner",				/* 26 */
	"no ttl",				/* 27 */
	"bad class",				/* 28 */
	"unexpected token",			/* 29 */
	"bad base64 encoding",			/* 30 */
	"partial match",			/* 31 */
	"new origin",				/* 32 */
	"unchanged",				/* 33 */
	"bad ttl",				/* 34 */
	"more data needed/to be rendered",	/* 35 */
	"continue",				/* 36 */
	"delegation",				/* 37 */
	"glue",					/* 38 */
	"dname",				/* 39 */
	"cname",				/* 40 */
	"nxdomain",				/* 41 */
	"nxrdataset",				/* 42 */
	"bad database",				/* 43 */
	"zonecut",				/* 44 */
	"format error in packet",		/* 45 */
	"bad zone",				/* 46 */
	"timed out",				/* 47 */
	"canceled",				/* 48 */
	"unexpected error",			/* 49 */
};

static isc_once_t		once = ISC_ONCE_INIT;
static isc_msgcat_t *		dns_msgcat = NULL;

static void
initialize_action(void) {
	isc_result_t result;

	isc_msgcat_open("libdns.cat", &dns_msgcat);
	result = isc_result_register(ISC_RESULTCLASS_DNS, DNS_R_NRESULTS,
				     text, dns_msgcat, 2);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_result_register() failed: %u", result);
}

static void
initialize(void) {
	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);
}

char *
dns_result_totext(dns_result_t result) {
	initialize();

	return (isc_result_totext(result));
}

void
dns_result_register(void) {
	initialize();
}
