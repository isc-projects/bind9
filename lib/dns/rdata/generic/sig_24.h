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

 /* $Id: sig_24.h,v 1.3 1999/02/02 01:43:47 halley Exp $ */

 /* RFC 2065 */

#ifndef RDATA_GENERIC_SIG_24_H
#define RDATA_GENERIC_SIG_24_H

static dns_result_t
fromtext_sig(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	unsigned char c; 
	dns_rdatatype_t covered;
	isc_textregion_t *tsr;
	char *e;
	dns_result_t result;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == 24);

	class = class;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	/* type covered */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	tsr = &token.value.as_textregion;
	result = dns_rdatatype_fromtext(&covered, tsr);
	if (result != DNS_R_SUCCESS && result != DNS_R_NOTIMPLEMENTED) {
		covered = strtol(token.value.as_pointer, &e, 10);
		if (e != NULL)
			return (result);
	}
	RETERR(uint16_tobuffer(covered, target));

	/* algorithm */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xff)
		return (DNS_R_RANGE);
	c = token.value.as_ulong;
	RETERR(mem_tobuffer(target, &c, 1));

	/* labels */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xff)
		return (DNS_R_RANGE);
	c = token.value.as_ulong;
	RETERR(mem_tobuffer(target, &c, 1));

	/* original ttl */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* signature expiration */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(time_tobuffer(token.value.as_pointer, target));

	/* time signed */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(time_tobuffer(token.value.as_pointer, target));

	/* key footprint */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));
	
	/* signer */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	/* sig */
	return (base64_tobuffer(lexer, target));
}

static dns_result_t
totext_sig(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t sr;
	char buf[sizeof "4294967295"];
	dns_rdatatype_t covered;
	unsigned long ttl;
	unsigned long when;
	unsigned long exp;
	unsigned long foot;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 24);

	origin = origin;	/*unused*/

	dns_rdata_toregion(rdata, &sr);

	/* type covered */
	covered = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	RETERR(dns_rdatatype_totext(covered, target));
	RETERR(str_totext(" ", target));

	/* algorithm */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* labels */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* ttl */
	ttl = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu", ttl); 
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* sig exp */
	exp = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	RETERR(time_totext(exp, target));
	RETERR(str_totext(" ", target));

	/* time signed */
	when = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	RETERR(time_totext(when, target));
	RETERR(str_totext(" ", target));

	/* footprint */
	foot = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu", ttl); 
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* signer */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	sub = name_prefix(&name, origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));
	RETERR(str_totext(" ", target));

	/* sig */
	return (base64_totext(&sr, target));
}

static dns_result_t
fromwire_sig(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_buffer_t *source, dns_decompress_t *dctx,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(type == 24);
	
	class = class;	/*unused*/

	isc_buffer_active(source, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	if (sr.length < 18)
		return (DNS_R_UNEXPECTEDEND);

	isc_buffer_forward(source, 18);
	RETERR(mem_tobuffer(target, sr.base, 18));

	/* signer */
	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	/* sig */
	isc_buffer_active(source, &sr);
	isc_buffer_forward(source, sr.length);
	return(mem_tobuffer(target, sr.base, sr.length));
}

static dns_result_t
towire_sig(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 24);

	dns_rdata_toregion(rdata, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	RETERR(mem_tobuffer(target, sr.base, 18));
	isc_region_consume(&sr, 18);

	/* signer */
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));        
	RETERR(dns_name_towire(&name, cctx, target));

	/* signature */
	return (mem_tobuffer(target, sr.base, sr.length));
}

static int
compare_sig(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 24);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);

	INSIST(r1.length > 18);
	INSIST(r2.length > 18);
	r1.length = 18;
	r2.length = 18;
	result = compare_region(&r1, &r2);
	if (result != 0)
		return (result);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	isc_region_consume(&r1, 18);
	isc_region_consume(&r2, 18);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	result = dns_name_compare(&name1, &name2);
	if (result != 0)
		return (result);
	isc_region_consume(&r1, name_length(&name1));
	isc_region_consume(&r2, name_length(&name2));

	return (compare_region(&r1, &r2));
}

static dns_result_t
fromstruct_sig(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 24);
	
	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_sig(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 24);
	
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_SIG_24_H */
