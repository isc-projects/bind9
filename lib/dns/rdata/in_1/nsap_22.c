/*
 * Copyright (C) 1999 Internet Software Consortium.
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

 /* $Id: nsap_22.c,v 1.1 1999/01/27 13:38:21 marka Exp $ */

 /* RFC 1706 */

#ifndef RDATA_IN_1_NSAP_22_H
#define RDATA_IN_1_NSAP_22_H

#include <string.h>

static dns_result_t
fromtext_in_nsap(dns_rdataclass_t class, dns_rdatatype_t type,
	         isc_lex_t *lexer, dns_name_t *origin,
	         isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	isc_textregion_t *sr;
	int n;
	int digits;
	unsigned char c;

	REQUIRE(type == 22);
	REQUIRE(class == 1);

	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	/* 0x<hex.string.with.periods> */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	sr = &token.value.as_textregion;
	if (sr->length < 2)
		return (DNS_R_UNEXPECTEDEND);
	if (sr->base[0] != '0' || (sr->base[1] != 'x' && sr->base[1] != 'X'))
		return (DNS_R_SYNTAX);
	isc_textregion_consume(sr, 2);
	digits = 0;
	n = 0;
	while (sr->length > 1) {
		if (sr->base[0] == '.') {
			isc_textregion_consume(sr, 1);
			continue;
		}
		if ((n = hexvalue(sr->base[0])) == -1)
			return (DNS_R_SYNTAX);
		c <<= 4;
		c += n;
		if (++digits == 2) {
			RETERR(mem_tobuffer(target, &n, 1));
			digits = 0;
		}
	}
	if (digits) {
		c <<= 4;
		return (mem_tobuffer(target, &c, 1));
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_in_nsap(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	char buf[sizeof "xx"];

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->class == 1);
	REQUIRE(rdata->length == 4);

	origin = origin;	/* unused */

	dns_rdata_toregion(rdata, &region);
	RETERR(str_totext("0x", target));
	while (region.length) {
		sprintf(buf, "%02x", region.base[0]);
		isc_region_consume(&region, 1);
		RETERR(str_totext(buf, target));
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_in_nsap(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t region;

	REQUIRE(type == 22);
	REQUIRE(class == 1);

	dctx = dctx;		/* unused */
	downcase = downcase;	/* unused */


	isc_buffer_active(source, &region);
	if (region.length < 1)
		return (DNS_R_UNEXPECTEDEND);

	return (mem_tobuffer(target, region.base, region.length));
}

static dns_result_t
towire_in_nsap(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->class == 1);

	cctx = cctx;	/*unused*/

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static int
compare_in_nsap(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->type);
	REQUIRE(rdata1->type == 22);
	REQUIRE(rdata1->class == 1);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static dns_result_t
fromstruct_in_nsap(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 22);
	REQUIRE(class == 1);

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_in_nsap(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->class == 1);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_IN_1_NSAP_22_H */
