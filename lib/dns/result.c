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
#include <dns/lib.h>

static char *text[DNS_R_NRESULTS] = {
	"label too long",			/*  0 */
	"bad escape",				/*  1 */
	"bad bitstring",			/*  2 */
	"bitstring too long",			/*  3 */
	"empty label",				/*  4 */
	"bad dotted quad",			/*  5 */
	"unexpected end of input",		/*  6 */
	"unknown class/type",			/*  7 */
	"bad label type",			/*  8 */
	"bad compression pointer",		/*  9 */
	"too many hops",			/* 10 */
	"disallowed (by application policy)",	/* 11 */
	"extra input text",			/* 12 */
	"extra input data",			/* 13 */
	"text too long",			/* 14 */
	"out of range",				/* 15 */
	"syntax error",				/* 16 */
	"bad checksum",				/* 17 */
	"bad IPv6 address",			/* 18 */
	"no owner",				/* 19 */
	"no ttl",				/* 20 */
	"bad class",				/* 21 */
	"unexpected token",			/* 22 */
	"partial match",			/* 23 */
	"new origin",				/* 24 */
	"unchanged",				/* 25 */
	"bad ttl",				/* 26 */
	"more data needed/to be rendered",	/* 27 */
	"continue",				/* 28 */
	"delegation",				/* 29 */
	"glue",					/* 30 */
	"dname",				/* 31 */
	"cname",				/* 32 */
	"nxdomain",				/* 33 */
	"nxrdataset",				/* 34 */
	"bad database",				/* 35 */
	"zonecut",				/* 36 */
	"format error in packet",		/* 37 */
	"bad zone",				/* 38 */
	"more data",				/* 39 */
};

#define DNS_RESULT_RESULTSET			2

static isc_once_t		once = ISC_ONCE_INIT;

static void
initialize_action(void) {
	isc_result_t result;

	result = isc_result_register(ISC_RESULTCLASS_DNS, DNS_R_NRESULTS,
				     text, dns_msgcat, DNS_RESULT_RESULTSET);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_result_register() failed: %u", result);
}

static void
initialize(void) {
	dns_lib_initmsgcat();
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
