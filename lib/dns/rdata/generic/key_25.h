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

 /* $Id: key_25.h,v 1.2 1999/02/04 00:03:29 marka Exp $ */

 /* RFC 2065 */

#ifndef RDATA_GENERIC_KEY_25_H
#define RDATA_GENERIC_KEY_25_H

static dns_result_t
fromtext_key(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	unsigned char c; 
	unsigned int flags;

	REQUIRE(type == 25);

	class = class;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));
	flags = token.value.as_ulong;

	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xff)
		return (DNS_R_RANGE);
	c = token.value.as_ulong;
	RETERR(mem_tobuffer(target, &c, 1));

	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xff)
		return (DNS_R_RANGE);
	c = token.value.as_ulong;
	RETERR(mem_tobuffer(target, &c, 1));
	
	/* No Key? */
	if ((flags & 0xc000) == 0xc000)
		return (DNS_R_SUCCESS);

	return (base64_tobuffer(lexer, target, -1));
}

static dns_result_t
totext_key(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t sr;
	char buf[sizeof "64000"];
	unsigned int flags;

	REQUIRE(rdata->type == 25);

	origin = origin;	/*unused*/

	dns_rdata_toregion(rdata, &sr);

	/* flags */
	flags = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u", flags);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* protocol */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* algorithm */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));

	/* No Key? */
	if ((flags & 0xc000) == 0xc00)
		return (DNS_R_SUCCESS);

	/* key */
	RETERR(str_totext(" ", target));
	return (base64_totext(&sr, target));
}

static dns_result_t
fromwire_key(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_buffer_t *source, dns_decompress_t *dctx,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t sr;

	REQUIRE(type == 25);
	
	class = class;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/

	isc_buffer_active(source, &sr);
	if (sr.length < 4)
		return (DNS_R_UNEXPECTEDEND);

	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static dns_result_t
towire_key(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;

	REQUIRE(rdata->type == 25);

	cctx = cctx;	/*unused*/

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static int
compare_key(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 25);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static dns_result_t
fromstruct_key(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 25);
	
	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_key(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 25);
	
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_KEY_25_H */
