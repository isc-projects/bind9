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

 /* $Id: minfo_14.c,v 1.5 1999/01/22 00:36:56 marka Exp $ */

#ifndef RDATA_GENERIC_MINFO_14_H
#define RDATA_GENERIC_MINFO_14_H

static dns_result_t
fromtext_minfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	int i;

	REQUIRE(type == 14);

	class = class;	/*unused*/
	
	for (i = 0; i < 2 ; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));
		dns_name_init(&name, NULL);
		buffer_fromregion(&buffer, &token.value.as_region,
				  ISC_BUFFERTYPE_TEXT);
		origin = (origin != NULL) ? origin : dns_rootname;
		RETERR(dns_name_fromtext(&name, &buffer, origin,
					 downcase, target));
	}
	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_minfo(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 14);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	dns_name_fromregion(&email, &region);
	isc_region_consume(&region, email.length);

	sub = name_prefix(&rmail, origin, &prefix);

	RETERR(dns_name_totext(&prefix, sub, target));

	RETERR(str_totext(" ", target));

	sub = name_prefix(&email, origin, &prefix);
	return (dns_name_totext(&prefix, sub, target));
}

static dns_result_t
fromwire_minfo(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target) {
        dns_name_t rmail;
        dns_name_t email;
        
	REQUIRE(type == 14);

	class = class;	/*unused*/

        dns_name_init(&rmail, NULL);
        dns_name_init(&email, NULL);

        RETERR(dns_name_fromwire(&rmail, source, dctx, downcase, target));
        return (dns_name_fromwire(&email, source, dctx, downcase, target));
}

static dns_result_t
towire_minfo(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;

	REQUIRE(rdata->type == 14);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return (dns_name_towire(&rmail, cctx, target));
}

static int
compare_minfo(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 14);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	result = dns_name_compare(&name1, &name2);
	if (result != 0)
		return (result);

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

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

	REQUIRE(type == 14);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_minfo(dns_rdata_t *rdata, void *target) {
	
	REQUIRE(rdata->type == 14);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_MINFO_14_H */
