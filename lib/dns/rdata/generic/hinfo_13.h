/*
 * Copyright (C) 1998 Internet Software Consortium.
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

 /* $Id: hinfo_13.h,v 1.5 1999/01/20 05:20:20 marka Exp $ */

#ifndef RDATA_GENERIC_HINFO_13_H
#define RDATA_GENERIC_HINFO_13_H

static dns_result_t
fromtext_hinfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_result_t result;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;

	REQUIRE(type == 13);

	class = class;		/*unused*/
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

	result = txt_fromtext(&token.value.as_textregion, target);
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
	return (txt_fromtext(&token.value.as_textregion, target));
}

static dns_result_t
totext_hinfo(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	dns_result_t result;

	REQUIRE(rdata->type == 13);

	origin = origin;	/*unused*/

	dns_rdata_toregion(rdata, &region);

	result = txt_totext(&region, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = str_totext(" ", target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = txt_totext(&region, target);
	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_hinfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target) {
	dns_result_t result;

	REQUIRE(type == 13);

	dctx = dctx;		/* unused */
	class = class;		/* unused */
	downcase = downcase;	/* unused */

	result = txt_fromwire(source, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	return (txt_fromwire(source, target));
}

static dns_result_t
towire_hinfo(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;

	REQUIRE(rdata->type == 13);

	cctx = cctx;

	isc_buffer_available(target, &region);
	if (region.length < rdata->length)
		return (DNS_R_NOSPACE);

	memcpy(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, rdata->length);

	return (DNS_R_SUCCESS);
}

static int
compare_hinfo(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int l;
	int result;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 13);

	l = (rdata1->length < rdata2->length) ? rdata1->length : rdata2->length;
	result = memcmp(rdata1->data, rdata2->data, l);

	if (result != 0)
		result = (result < 0) ? -1 : 1;
	else if (rdata1->length != rdata2->length)
			result = (rdata1->length < rdata2->length) ? -1 : 1;

	return (result);
}

static dns_result_t
fromstruct_hinfo(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 13);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_hinfo(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 13);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_HINFO_13_H */
