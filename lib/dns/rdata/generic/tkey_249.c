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

 /* $Id: tkey_249.c,v 1.14 1999/08/12 01:32:32 halley Exp $ */

 /* draft-ietf-dnssec-tkey-01.txt */

#ifndef RDATA_GENERIC_TKEY_249_C
#define RDATA_GENERIC_TKEY_249_C

static inline dns_result_t
fromtext_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_lex_t *lexer, dns_name_t *origin,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_rcode_t rcode;
	dns_name_t name;
	isc_buffer_t buffer;
	char *e;

	REQUIRE(type == 249);
	
	rdclass = rdclass;		/*unused*/


	/* Algorithm */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));


	/* Inception */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Expiration */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Mode */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Error */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	if (dns_rcode_fromtext(&rcode, &token.value.as_textregion)
				!= DNS_R_SUCCESS) {
		rcode = strtol(token.value.as_pointer, &e, 10);
		if (*e != 0)
			return (DNS_R_UNKNOWN);
		if (rcode > 0xffff)
			return (DNS_R_RANGE);
	}
	RETERR(uint16_tobuffer(rcode, target));

	/* Signature Size */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Signature */
	RETERR(isc_base64_tobuffer(lexer, target, token.value.as_ulong));

	/* Other Len */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Other Data */
	return (isc_base64_tobuffer(lexer, target, token.value.as_ulong));
}

static inline dns_result_t
totext_tkey(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	    isc_buffer_t *target) 
{
	isc_region_t sr;
	isc_region_t sigr;
	char buf[sizeof "4294967295 "];	
	unsigned long n;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 249);

	dns_rdata_toregion(rdata, &sr);

	/* Algorithm */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));
	RETERR(str_totext(" ", target));
	isc_region_consume(&sr, name_length(&name));

	/* Inception */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Expiration */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Mode */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Error */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	if (dns_rcode_totext(n, target) == DNS_R_SUCCESS)
		RETERR(str_totext(" ", target));
	else {
		sprintf(buf, "%lu ", n);
		RETERR(str_totext(buf, target));
	}

	/* Signature Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu", n);
	RETERR(str_totext(buf, target));

	/* Signature */
	REQUIRE(n <= sr.length);
	sigr = sr;
	sigr.length = n;
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sigr, tctx->width - 2,
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" ) ", target));
	else
		RETERR(str_totext(" ", target));		
	isc_region_consume(&sr, n);

	/* Other Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Other */
	return (isc_base64_totext(&sr, 60, " ", target));
}

static inline dns_result_t
fromwire_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_buffer_t *source, dns_decompress_t *dctx,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	unsigned long n;
	dns_name_t name;

	REQUIRE(type == 249);
	
	rdclass = rdclass;		/*unused*/

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);
	
	/* Algorithm */
	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	/* 
	 * Inception: 4
	 * Expiration: 4
	 * Mode: 2
	 * Error: 2
	 */
	isc_buffer_active(source, &sr);
	if (sr.length < 12)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 12));
	isc_region_consume(&sr, 12);
	isc_buffer_forward(source, 12);

	/* Signature Length + Signature */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, n + 2));
	isc_region_consume(&sr, n + 2);
	isc_buffer_forward(source, n + 2);

	/* Other Length + Other */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	isc_buffer_forward(source, n + 2);
	return (mem_tobuffer(target, sr.base, n + 2));
}

static inline dns_result_t
towire_tkey(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 249);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	/* Algorithm */
	dns_rdata_toregion(rdata, &sr);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&sr, name_length(&name));

	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_tkey(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 249);
	
	/* Algorithm */
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	if ((result = dns_name_rdatacompare(&name1, &name2)) != 0)
		return (result);
	isc_region_consume(&r1, name_length(&name1));
	isc_region_consume(&r2, name_length(&name2));
	return (compare_region(&r1, &r2));
}

static inline dns_result_t
fromstruct_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		    void *source, isc_buffer_t *target) {

	REQUIRE(type == 249);
	
	rdclass = rdclass;	/*unused*/
	
	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline dns_result_t
tostruct_tkey(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 249);
	
	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_tkey(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline dns_result_t
additionaldata_tkey(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	REQUIRE(rdata->type == 249);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

#endif	/* RDATA_GENERIC_TKEY_249_C */
