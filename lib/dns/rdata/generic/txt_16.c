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

 /* $Id: txt_16.c,v 1.4 1999/01/19 06:49:33 marka Exp $ */

#ifndef RDATA_GENERIC_TXT_16_H
#define RDATA_GENERIC_TXT_16_H

static dns_result_t
fromtext_txt(dns_rdataclass_t class, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_result_t result;

	INSIST(type == 16);

	class = class;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	if (isc_lex_gettoken(lexer, 0, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNKNOWN);
	while (token.type == isc_tokentype_string) {
		result = txt_fromtext(&token.value.as_textregion, target);
		if (result != DNS_R_SUCCESS)
			return (result);
		if (isc_lex_gettoken(lexer, ISC_LEXOPT_EOL | ISC_LEXOPT_EOF,
				     &token) != ISC_R_SUCCESS)
			return (DNS_R_UNKNOWN);
	}
	/* Let upper layer handle eol/eof. */
	isc_lex_ungettoken(lexer, &token);
	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_txt(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	dns_result_t result;

	INSIST(rdata->type == 16);

	origin = origin;	/*unused*/

	dns_rdata_toregion(rdata, &region);

	while (region.length) {
		result = txt_totext(&region, target);
		if (result != DNS_R_SUCCESS)
			return (result);
		if (region.length) {
			result = str_totext(" ", target);
			if (result != DNS_R_SUCCESS)
				return (result);
		}
	}

	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_txt(dns_rdataclass_t class, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target) {
	dns_result_t result;

	INSIST(type == 16);

	dctx = dctx;		/*unused*/
	class = class;		/*unused*/
	downcase = downcase;	/*unused*/

	while (!buffer_empty(source)) {
		result = txt_fromwire(source, target);
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
towire_txt(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;

	INSIST(rdata->type == 16);

	cctx = cctx;	/*unused*/

	isc_buffer_available(target, &region);
	if (region.length < rdata->length)
		return (DNS_R_NOSPACE);

	memcpy(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, rdata->length);
	return (DNS_R_SUCCESS);
}

static int
compare_txt(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int l;
	int result;
	
	INSIST(rdata1->type == rdata2->type);
	INSIST(rdata1->class == rdata2->class);
	INSIST(rdata1->class == 16);

	l = (rdata1->length < rdata2->length) ? rdata1->length : rdata2->length;
	result = memcmp(rdata1->data, rdata2->data, l);

	if (result != 0)
		result = (result < 0) ? -1 : 1;
	else if (rdata1->length != rdata2->length)
			result = (rdata1->length < rdata2->length) ? -1 : 1;

	return (result);
}

static dns_result_t
fromstruct_txt(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	INSIST(type == 16);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_txt(dns_rdata_t *rdata, void *target) {

	INSIST(rdata->type == 16);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_TXT_16_H */
