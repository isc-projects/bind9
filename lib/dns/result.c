/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <isc/once.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/result.h>

#define DNS_RESULT_ISRCODE(result) (DNS_R_NOERROR == ((result)&0xFFFF0000))

dns_rcode_t
dns_result_torcode(isc_result_t result) {
	dns_rcode_t rcode = dns_rcode_servfail;

	if (DNS_RESULT_ISRCODE(result)) {
		/*
		 * Rcodes can't be bigger than 12 bits, which is why we
		 * AND with 0xFFF instead of 0xFFFF.
		 */
		return ((dns_rcode_t)((result)&0xFFF));
	}

	/*
	 * Try to supply an appropriate rcode.
	 */
	switch (result) {
	case ISC_R_SUCCESS:
		rcode = dns_rcode_noerror;
		break;
	case ISC_R_BADBASE64:
	case ISC_R_RANGE:
	case ISC_R_UNEXPECTEDEND:
	case DNS_R_BADAAAA:
	/* case DNS_R_BADBITSTRING: deprecated */
	case DNS_R_BADCKSUM:
	case DNS_R_BADCLASS:
	case DNS_R_BADLABELTYPE:
	case DNS_R_BADPOINTER:
	case DNS_R_BADTTL:
	case DNS_R_BADZONE:
	/* case DNS_R_BITSTRINGTOOLONG: deprecated */
	case DNS_R_EXTRADATA:
	case DNS_R_LABELTOOLONG:
	case DNS_R_NOREDATA:
	case DNS_R_SYNTAX:
	case DNS_R_TEXTTOOLONG:
	case DNS_R_TOOMANYHOPS:
	case DNS_R_TSIGERRORSET:
	case DNS_R_UNKNOWN:
	case DNS_R_NAMETOOLONG:
	case DNS_R_OPTERR:
		rcode = dns_rcode_formerr;
		break;
	case DNS_R_DISALLOWED:
		rcode = dns_rcode_refused;
		break;
	case DNS_R_TSIGVERIFYFAILURE:
	case DNS_R_CLOCKSKEW:
		rcode = dns_rcode_notauth;
		break;
	default:
		rcode = dns_rcode_servfail;
	}

	return (rcode);
}

isc_result_t
dns_result_fromrcode(dns_rcode_t rcode) {
	/*
	 * Rcodes can't be bigger than 12 bits, which is why we
	 * AND with 0xFFF instead of 0xFFFF.
	 */
	REQUIRE((rcode & 0xFFF) == rcode);

	return ((isc_result_t)rcode + DNS_R_NOERROR);
}
