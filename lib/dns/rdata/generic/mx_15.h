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

 /* $Id: mx_15.h,v 1.4 1999/01/19 06:49:31 marka Exp $ */

#ifndef RDATA_GENERIC_MX_15_H
#define RDATA_GENERIC_MX_15_H

static dns_result_t
fromtext_mx(dns_rdataclass_t class, dns_rdatatype_t type,
	    isc_lex_t *lexer, dns_name_t *origin,
	    isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	dns_result_t result;

	INSIST(type == 15);

	class = class;	/*unused*/

	if (isc_lex_gettoken(lexer, ISC_LEXOPT_NUMBER, &token) != ISC_R_SUCCESS)
		return (DNS_R_UNKNOWN);
	if (token.type != isc_tokentype_number)
		return (DNS_R_UNKNOWN);
	
	result = uint16_fromtext(token.value.as_ulong, target);
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
totext_mx(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	dns_result_t result;
	char buf[sizeof "64000"];
	unsigned short num;

	INSIST(rdata->type == 15);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u", num);
	result = str_totext(buf, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = str_totext(" ", target);
	if (result != DNS_R_SUCCESS)
		return (result);

	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static dns_result_t
fromwire_mx(dns_rdataclass_t class, dns_rdatatype_t type,
	    isc_buffer_t *source, dns_decompress_t *dctx,
	    isc_boolean_t downcase, isc_buffer_t *target) {
        dns_name_t name;
	isc_region_t sregion;
	isc_region_t tregion;

	INSIST(type == 15);
	class = class;		/* unused */
        
        dns_name_init(&name, NULL);

	isc_buffer_remaining(source, &sregion);
	isc_buffer_available(target, &tregion);
	if (tregion.length < 2)
		return (DNS_R_NOSPACE);
	if (sregion.length < 2)
		return (DNS_R_WIRE);
	memcpy(tregion.base, sregion.base, 2);
	isc_buffer_forward(source, 2);
	isc_buffer_add(target, 2);
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static dns_result_t
towire_mx(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	dns_name_t name;
	isc_region_t region;
	dns_result_t result;
	isc_region_t tr;

	INSIST(rdata->type == 15);

	isc_buffer_available(target, &tr);
	dns_rdata_toregion(rdata, &region);
	if (tr.length < 2)
		return (DNS_R_NOSPACE);
	memcpy(tr.base, region.base, 2);
	isc_region_consume(&region, 2);
	isc_buffer_add(target, 2);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);

	result = dns_name_towire(&name, cctx, target);
	return (result);
}

static int
compare_mx(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int result;

	INSIST(rdata1->type == rdata2->type);
	INSIST(rdata1->class == rdata2->class);
	INSIST(rdata1->type == 15);

	result = memcmp(rdata1->data, rdata2->data, 2);
	if (result != 0)
		return (result < 0 ? -1 : 1);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	isc_region_consume(&region1, 2);
	isc_region_consume(&region2, 2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_compare(&name1, &name2));
}

static dns_result_t
fromstruct_mx(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	INSIST(type == 15);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_mx(dns_rdata_t *rdata, void *target) {

	INSIST(rdata->type == 15);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_MX_15_H */
