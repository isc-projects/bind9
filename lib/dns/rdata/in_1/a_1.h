/*
 * Copyright (C) 1998  Internet Software Consortium.
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

 /* $Id: a_1.h,v 1.5 1999/01/20 05:20:24 marka Exp $ */

#ifndef RDATA_IN_1_A_1_H
#define RDATA_IN_1_A_1_H

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>

static dns_result_t
fromtext_in_a(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	struct in_addr addr;
	isc_region_t region;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;

	REQUIRE(type == 1);
	REQUIRE(class == 1);

	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	if (isc_lex_gettoken(lexer, options, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNEXPECTED);
	if (token.type != isc_tokentype_string) {
		isc_lex_ungettoken(lexer, &token);
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof)
			return(DNS_R_UNEXPECTEDEND);
		return (DNS_R_UNEXPECTED);
	}

	if (inet_aton(token.value.as_pointer , &addr) != 1)
		return (DNS_R_UNEXPECTED);
	isc_buffer_available(target, &region);
	if (region.length < 4)
		return (DNS_R_NOSPACE);
	memcpy(region.base, &addr, 4);
	isc_buffer_add(target, 4);
	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_in_a(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;

	REQUIRE(rdata->type == 1);
	REQUIRE(rdata->class == 1);
	REQUIRE(rdata->length == 4);

	origin = origin;	/* unused */

	isc_buffer_available(target, &region);
	if (inet_ntop(AF_INET, rdata->data,
		      region.base, region.length) == NULL)
		return (DNS_R_NOSPACE);

	isc_buffer_add(target, strlen(region.base));
	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_in_a(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(type == 1);
	REQUIRE(class == 1);

	dctx = dctx;		/* unused */
	downcase = downcase;	/* unused */


	isc_buffer_active(source, &sregion);
	isc_buffer_available(target, &tregion);
	if (sregion.length < 4)
		return (DNS_R_UNEXPECTEDEND);
	if (tregion.length < 4)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 4);
	isc_buffer_forward(source, 4);
	isc_buffer_add(target, 4);
	return (DNS_R_SUCCESS);
}

static dns_result_t
towire_in_a(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;

	REQUIRE(rdata->type == 1);
	REQUIRE(rdata->class == 1);

	cctx = cctx;	/*unused*/

	isc_buffer_available(target, &region);
	if (region.length < rdata->length)
		return (DNS_R_NOSPACE);
	memcpy(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 4);
	return (DNS_R_SUCCESS);
}

static int
compare_in_a(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->type);
	REQUIRE(rdata1->type == 1);
	REQUIRE(rdata1->class == 1);

	result = memcmp(rdata1->data, rdata2->data, 4);
	if (result != 0)
		result = (result < 0) ? -1 : 1;

	return (result);
}

static dns_result_t
fromstruct_in_a(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 1);
	REQUIRE(class == 1);

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_in_a(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 1);
	REQUIRE(rdata->class == 1);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_IN_1_A_1_H */
