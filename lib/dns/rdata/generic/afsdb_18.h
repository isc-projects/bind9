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

 /* $Id: afsdb_18.h,v 1.4 1999/02/22 07:23:59 marka Exp $ */

 /* RFC 1183 */

#ifndef RDATA_GENERIC_AFSDB_18_H
#define RDATA_GENERIC_AFSDB_18_H

static dns_result_t
fromtext_afsdb(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) 
{
	isc_token_t token;
	isc_buffer_t buffer;
	dns_name_t name;

	REQUIRE(type == 18);

	class = class;	/*unused*/

	/* subtype */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));
	
	/* hostname */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static dns_result_t
totext_afsdb(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	dns_name_t name;
	dns_name_t prefix;
	isc_region_t region;
	char buf[sizeof "64000 "];
	isc_boolean_t sub;
	unsigned int num;


	REQUIRE(rdata->type == 18);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u ", num);
	RETERR(str_totext(buf, target));
	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static dns_result_t
fromwire_afsdb(dns_rdataclass_t class, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target)
{
	dns_name_t name;
	isc_region_t sr;
	isc_region_t tr;

	REQUIRE(type == 18);
	
	class = class;	/*unused*/

	dns_name_init(&name, NULL);

	isc_buffer_active(source, &sr);
	isc_buffer_available(target, &tr);
	if (tr.length < 2)
		return (DNS_R_NOSPACE);
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	memcpy(tr.base, sr.base, 2);
	isc_buffer_forward(source, 2);
	isc_buffer_add(target, 2);
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static dns_result_t
towire_afsdb(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t tr;
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 18);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	isc_buffer_available(target, &tr);
	dns_rdata_toregion(rdata, &sr);
	if (tr.length < 2)
		return (DNS_R_NOSPACE);
	memcpy(tr.base, sr.base, 2);
	isc_region_consume(&sr, 2);
	isc_buffer_add(target, 2);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);

	return (dns_name_towire(&name, cctx, target));
}

static int
compare_afsdb(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 18);

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

	return (dns_name_rdatacompare(&name1, &name2));
}

static dns_result_t
fromstruct_afsdb(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
		 isc_buffer_t *target)
{

	REQUIRE(type == 18);
	
	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_afsdb(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 18);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_AFSDB_18_H */
