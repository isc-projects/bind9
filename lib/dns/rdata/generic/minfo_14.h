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

 /* $Id: minfo_14.h,v 1.2 1999/01/19 05:38:33 marka Exp $ */

#ifndef RDATA_TYPE_14_MINFO_H
#define RDATA_TYPE_14_MINFO_H

static dns_result_t
fromtext_minfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_result_t result;
	dns_name_t name;
	isc_buffer_t buffer;

	class = class;	/*unused*/
	
	if (isc_lex_gettoken(lexer, 0, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNKNOWN);
	if (token.type != isc_tokentype_string)
		return (DNS_R_UNKNOWN);

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	result = dns_name_fromtext(&name, &buffer, origin, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	if (isc_lex_gettoken(lexer, 0, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNKNOWN);
	if (token.type != isc_tokentype_string)
		return (DNS_R_UNKNOWN);

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static dns_result_t
totext_minfo(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;
	dns_name_t prefix;
	dns_result_t result;
	isc_boolean_t sub;

	INSIST(rdata->type == 14);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	dns_name_fromregion(&email, &region);
	isc_region_consume(&region, email.length);

	sub = name_prefix(&rmail, origin, &prefix);

	result = dns_name_totext(&prefix, sub, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = str_totext(" ", target);
	if (result != DNS_R_SUCCESS)
		return (result);

	sub = name_prefix(&email, origin, &prefix);
	result = dns_name_totext(&prefix, sub, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_minfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target) {
        dns_name_t rmail;
        dns_name_t email;
	dns_result_t result;
        
	INSIST(type == 14);
	class = class;		/*unused*/

        dns_name_init(&rmail, NULL);
        dns_name_init(&email, NULL);

        result = dns_name_fromwire(&rmail, source, dctx, downcase, target);
	if (result != DNS_R_SUCCESS)
		return (result);

        return (dns_name_fromwire(&email, source, dctx, downcase, target));
}

static dns_result_t
towire_minfo(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;
	dns_result_t result;

	INSIST(rdata->type == 14);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	result = dns_name_towire(&rmail, cctx, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	result = dns_name_towire(&rmail, cctx, target);

	return (DNS_R_SUCCESS);
}

static int
compare_minfo(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	INSIST(rdata1->type == 14);
	INSIST(rdata2->type == 14);

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
	return (result);
}

static dns_result_t
fromstruct_minfo(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {
	class = class;
	type = type;
	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_minfo(dns_rdata_t *rdata, void *target) {
	
	rdata = rdata;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif
