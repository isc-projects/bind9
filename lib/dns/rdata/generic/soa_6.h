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

 /* $Id: soa_6.h,v 1.6 1999/01/20 05:20:23 marka Exp $ */

#ifndef RDATA_GENERIC_SOA_6_H
#define RDATA_GENERIC_SOA_6_H

static dns_result_t
fromtext_soa(dns_rdataclass_t class, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	dns_result_t result;
	int i;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;

	REQUIRE(type == 6);

	class = class;	/*unused*/

	if (isc_lex_gettoken(lexer, options, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNEXPECTED);
	if (token.type != isc_tokentype_string) {
		isc_lex_ungettoken(lexer, &token);
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof)
			return(DNS_R_UNEXPECTEDEND);
		return (DNS_R_UNEXPECTED);
	}

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	result = dns_name_fromtext(&name, &buffer, origin, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	if (isc_lex_gettoken(lexer, options, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNEXPECTED);
	if (token.type != isc_tokentype_string) {
		isc_lex_ungettoken(lexer, &token);
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof)
			return(DNS_R_UNEXPECTEDEND);
		return (DNS_R_UNEXPECTED);
	}

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	result = dns_name_fromtext(&name, &buffer, origin, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	options |= ISC_LEXOPT_NUMBER;
	for (i = 0; i < 5; i++) {
		if (isc_lex_gettoken(lexer, options, &token) != ISC_R_SUCCESS)
			return (DNS_R_UNEXPECTED);
		if (token.type != isc_tokentype_number) {
			isc_lex_ungettoken(lexer, &token);
			if (token.type == isc_tokentype_eol ||
			    token.type == isc_tokentype_eof)
				return(DNS_R_UNEXPECTEDEND);
			return (DNS_R_UNEXPECTED);
		}

		result = uint32_fromtext(token.value.as_ulong, target);
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_soa(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t dregion;
	dns_name_t mname;
	dns_name_t rname;
	dns_name_t prefix;
	dns_result_t result;
	isc_boolean_t sub;
	int i;

	REQUIRE(rdata->type == 6);

	dns_name_init(&mname, NULL);
	dns_name_init(&rname, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &dregion);

	dns_name_fromregion(&mname, &dregion);
	isc_region_consume(&dregion, name_length(&mname));

	dns_name_fromregion(&rname, &dregion);
	isc_region_consume(&dregion, name_length(&rname));

	sub = name_prefix(&mname, origin, &prefix);
	result = dns_name_totext(&prefix, sub, target);
	if (result != DNS_R_SUCCESS)
		return (result);
	
	result = str_totext(" ", target);
	if (result != DNS_R_SUCCESS)
		return (result);

	sub = name_prefix(&rname, origin, &prefix);
	result = dns_name_totext(&prefix, sub, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	for (i = 0; i < 5 ; i++) {
		char buf[sizeof "2147483647"];
		unsigned long num;

		result = str_totext(" ", target);
		if (result != DNS_R_SUCCESS)
			return (result);

		num = uint32_fromregion(&dregion);
		isc_region_consume(&dregion, 4); 
		sprintf(buf, "%lu", num);
		result = str_totext(buf, target);
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_soa(dns_rdataclass_t class, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target) {
        dns_name_t mname;
        dns_name_t rname;
	dns_result_t result;
	isc_region_t sregion;
	isc_region_t tregion;
        
	REQUIRE(type == 6);

	class = class;	/*unused*/

        dns_name_init(&mname, NULL);
        dns_name_init(&rname, NULL);

        result = dns_name_fromwire(&mname, source, dctx, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

        result = dns_name_fromwire(&rname, source, dctx, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	isc_buffer_active(source, &sregion);
	isc_buffer_available(target, &tregion);

	if (sregion.length < 20)
		return (DNS_R_UNEXPECTEDEND);
	if (tregion.length < 20)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 20);
	isc_buffer_forward(source, 20);
	isc_buffer_add(target, 20);
	return (DNS_R_SUCCESS);
}

static dns_result_t
towire_soa(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t mname;
	dns_name_t rname;
	dns_result_t result;

	REQUIRE(rdata->type == 6);

	dns_name_init(&mname, NULL);
	dns_name_init(&rname, NULL);

	dns_rdata_toregion(rdata, &sregion);
	dns_name_fromregion(&mname, &sregion);
	isc_region_consume(&sregion, name_length(&mname));
	result = dns_name_towire(&mname, cctx, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	dns_name_fromregion(&rname, &sregion);
	isc_region_consume(&sregion, name_length(&rname));
	result = dns_name_towire(&rname, cctx, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	isc_buffer_available(target, &tregion);
	if (tregion.length < 20)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 20);
	isc_buffer_add(target, 20);
	return (DNS_R_SUCCESS);
}

static int
compare_soa(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 6);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region1);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	result = dns_name_compare(&name1, &name2);
	if (result != 0)
		return (result);

	isc_region_consume(&region1, name1.length);
	isc_region_consume(&region2, name2.length);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	result = dns_name_compare(&name1, &name2);
	if (result != 0)
		return (result);

	isc_region_consume(&region1, name1.length);
	isc_region_consume(&region2, name2.length);

	result = memcmp(region1.base, region2.base, 12);
	if (result != 0)
		return ((result < 0) ? -1 : 1);

	return (0);
}

static dns_result_t
fromstruct_soa(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 6);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_soa(dns_rdata_t *rdata, void *target) {
	
	REQUIRE(rdata->type == 6);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_SOA_6_H */
