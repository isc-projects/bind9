/*
 * Copyright (C) 1998-2000  Internet Software Consortium.
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

/* $Id: result.c,v 1.63.2.1 2000/07/05 20:49:04 gson Exp $ */

#include <config.h>

#include <isc/once.h>
#include <isc/util.h>

#include <dns/result.h>
#include <dns/lib.h>

static const char *text[DNS_R_NRESULTS] = {
	"label too long",			/*  0 */
	"bad escape",				/*  1 */
	"bad bitstring",			/*  2 */
	"bitstring too long",			/*  3 */
	"empty label",				/*  4 */
	"bad dotted quad",			/*  5 */
	"invalid NS owner name (wildcard)",	/*  6 */
	"unknown class/type",			/*  7 */
	"bad label type",			/*  8 */
	"bad compression pointer",		/*  9 */
	"too many hops",			/* 10 */
	"disallowed (by application policy)",	/* 11 */
	"extra input text",			/* 12 */
	"extra input data",			/* 13 */
	"text too long",			/* 14 */
	"not at top of zone",			/* 15 */
	"syntax error",				/* 16 */
	"bad checksum",				/* 17 */
	"bad IPv6 address",			/* 18 */
	"no owner",				/* 19 */
	"no ttl",				/* 20 */
	"bad class",				/* 21 */
	"UNUSED22",				/* 22 */
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
	"bad database",				/* 33 */
	"zonecut",				/* 34 */
	"bad zone",				/* 35 */
	"more data",				/* 36 */
	"up to date",				/* 37 */
	"tsig verify failure",			/* 38 */
	"tsig error set in query",		/* 39 */
	"SIG failed to verify",			/* 40 */
	"SIG has expired",			/* 41 */
	"SIG validity period has not begun",	/* 42 */
	"key is unauthorized to sign data",	/* 43 */
	"invalid time",				/* 44 */
	"expected a TSIG",			/* 45 */
	"did not expect a TSIG",		/* 46 */
	"TKEY is unacceptable",			/* 47 */
	"hint",					/* 48 */
	"drop",					/* 49 */
	"zone not loaded",			/* 50 */
	"ncache nxdomain",			/* 51 */
	"ncache nxrrset",			/* 52 */
	"wait",					/* 53 */
	"not verified yet",			/* 54 */
	"no identity",				/* 55 */
	"no journal",				/* 56 */
	"alias",				/* 57 */
	"use TCP",				/* 58 */
	"no valid SIG",				/* 59 */
	"no valid NXT",				/* 60 */
	"not insecure"				/* 61 */
};

static const char *rcode_text[DNS_R_NRCODERESULTS] = {
	"NOERROR",				/* 0 */
	"FORMERR",				/* 1 */
	"SERVFAIL",				/* 2 */
	"NXDOMAIN",				/* 3 */
	"NOTIMP",				/* 4 */
	"REFUSED",				/* 5 */
	"YXDOMAIN",				/* 6 */
	"YXRRSET",				/* 7 */
	"NXRRSET",				/* 8 */
	"NOTAUTH",				/* 9 */
	"NOTZONE",				/* 10 */
	"<rcode 11>",				/* 11 */
	"<rcode 12>",				/* 12 */
	"<rcode 13>",				/* 13 */
	"<rcode 14>",				/* 14 */
	"<rcode 15>",				/* 15 */
	"BADVERS",				/* 16 */
};

#define DNS_RESULT_RESULTSET			2
#define DNS_RESULT_RCODERESULTSET		3

static isc_once_t		once = ISC_ONCE_INIT;

static void
initialize_action(void) {
	isc_result_t result;

	result = isc_result_register(ISC_RESULTCLASS_DNS, DNS_R_NRESULTS,
				     text, dns_msgcat, DNS_RESULT_RESULTSET);
	if (result == ISC_R_SUCCESS)
		result = isc_result_register(ISC_RESULTCLASS_DNSRCODE,
					     DNS_R_NRCODERESULTS,
					     rcode_text, dns_msgcat,
					     DNS_RESULT_RCODERESULTSET);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_result_register() failed: %u", result);
}

static void
initialize(void) {
	dns_lib_initmsgcat();
	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);
}

const char *
dns_result_totext(isc_result_t result) {
	initialize();

	return (isc_result_totext(result));
}

void
dns_result_register(void) {
	initialize();
}

dns_rcode_t
dns_result_torcode(isc_result_t result) {
	dns_rcode_t rcode = dns_rcode_servfail;

	if (DNS_RESULT_ISRCODE(result)) {
		/*
		 * Rcodes can't be bigger than 12 bits, which is why we
		 * AND with 0xFFF instead of 0xFFFF.
		 */
		return ((dns_rcode_t)((result) & 0xFFF));
	}
	/*
	 * Try to supply an appropriate rcode.
	 */
	switch (result) {
	case ISC_R_SUCCESS:
		rcode = dns_rcode_noerror;
		break;
	case ISC_R_BADBASE64:
	case ISC_R_NOSPACE:
	case ISC_R_RANGE:
	case ISC_R_UNEXPECTEDEND:
	case DNS_R_BADAAAA:
	case DNS_R_BADBITSTRING:
	case DNS_R_BADCKSUM:
	case DNS_R_BADCLASS:
	case DNS_R_BADLABELTYPE:
	case DNS_R_BADPOINTER:
	case DNS_R_BADTTL:
	case DNS_R_BADZONE:
	case DNS_R_BITSTRINGTOOLONG:
	case DNS_R_EXTRADATA:
	case DNS_R_LABELTOOLONG:
	case DNS_R_NOREDATA:
	case DNS_R_SYNTAX:
	case DNS_R_TEXTTOOLONG:
	case DNS_R_TOOMANYHOPS:
	case DNS_R_TSIGERRORSET:
	case DNS_R_UNKNOWN:
		rcode = dns_rcode_formerr;
		break;
	case DNS_R_DISALLOWED:
		rcode = dns_rcode_refused;
		break;
	case DNS_R_TSIGVERIFYFAILURE:
		rcode = dns_rcode_notauth;
		break;
	default:
		rcode = dns_rcode_servfail;
	}

	return (rcode);
}
