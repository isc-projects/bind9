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

 /* $Id: nxt_30.h,v 1.1 1999/01/29 08:04:13 marka Exp $ */

 /* RFC 2065 */

#ifndef RDATA_GENERIC_NXT_30_H
#define RDATA_GENERIC_NXT_30_H

static dns_result_t
fromtext_nxt(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	char *e;
	unsigned char bm[8*1024]; /* 64k bits */
	dns_rdatatype_t covered;
	long maxcovered = -1;
	unsigned int n;

	REQUIRE(type == 30);

	class = class;	/*unused*/
	
	/* next domain */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	memset(bm, 0, sizeof bm);
	while (1) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				  ISC_TRUE));
		if (token.type != isc_tokentype_string)
			break;
		covered = strtol(token.value.as_pointer, &e, 10);
		if (*e == '\0')
			(void) NULL;
		else if (dns_rdatatype_fromtext(&covered, 
				&token.value.as_textregion) == DNS_R_UNKNOWN)
			return (DNS_R_UNKNOWN);
		if (covered > maxcovered)
			maxcovered = covered;
		bm[covered/8] |= (0x80>>(covered%8));
	}
	isc_lex_ungettoken(lexer, &token);
	n = (maxcovered + 8) / 8;
	return (mem_tobuffer(target, bm, n));
}

static dns_result_t
totext_nxt(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t sr;
	char buf[sizeof "65535"];
	unsigned int i, j;
	dns_name_t name;
	dns_name_t prefix;
	dns_result_t result;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 30);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	sub = name_prefix(&name, origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	RETERR(str_totext(" ( ", target));

	for (i = 0 ; i < sr.length ; i++) {
		if (sr.base[i] != 0)
			for (j = 0; j < 8; j++)
				if ((sr.base[i] & (0x80>>j)) != 0) {
					result = dns_rdatatype_totext(
							i * 8 + j, target);
					if (result == DNS_R_SUCCESS) {
						RETERR(str_totext(" ",
								  target));
						continue;
					}
					if (result != DNS_R_UNKNOWN)
						return (result);
					sprintf(buf, "%u", i * 8 + j);
					RETERR(str_totext(" ", target));
					RETERR(str_totext(buf, target));
				}
	}
	return (str_totext(")", target));
}

static dns_result_t
fromwire_nxt(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_buffer_t *source, dns_decompress_t *dctx,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(type == 30);

	class = class;	/*unused*/

	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));
	
	isc_buffer_active(source, &sr);
	if (sr.length > 8 * 1024)
		return (DNS_R_EXTRADATA);
	RETERR(mem_tobuffer(target, sr.base, sr.length));
	isc_buffer_forward(source, sr.length);
	return (DNS_R_SUCCESS);
}

static dns_result_t
towire_nxt(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 30);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	return (mem_tobuffer(target, sr.base, sr.length));
}

static int
compare_nxt(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 30);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	result = dns_name_compare(&name1, &name2);
	if (result != 0)
		return (result);

	return (compare_region(&r1, &r2));
}

static dns_result_t
fromstruct_nxt(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 30);

	class = class; 	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_nxt(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 30);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_NXT_30_H */
