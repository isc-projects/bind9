/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: nsap_22.c,v 1.14 2000/03/20 18:03:53 gson Exp $ */

/* Reviewed: Fri Mar 17 10:41:07 PST 2000 by gson */

/* RFC 1706 */

#ifndef RDATA_IN_1_NSAP_22_C
#define RDATA_IN_1_NSAP_22_C

#include <string.h>

static inline isc_result_t
fromtext_in_nsap(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	         isc_lex_t *lexer, dns_name_t *origin,
	         isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;
	isc_textregion_t *sr;
	int n;
	int digits;
	unsigned char c = 0;

	REQUIRE(type == 22);
	REQUIRE(rdclass == 1);

	UNUSED(origin);
	UNUSED(downcase);

	/* 0x<hex.string.with.periods> */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	sr = &token.value.as_textregion;
	if (sr->length < 2)
		return (DNS_R_UNEXPECTEDEND);
	if (sr->base[0] != '0' || (sr->base[1] != 'x' && sr->base[1] != 'X'))
		return (DNS_R_SYNTAX);
	isc_textregion_consume(sr, 2);
	digits = 0;
	n = 0;
	while (sr->length > 0) {
		if (sr->base[0] == '.') {
			isc_textregion_consume(sr, 1);
			continue;
		}
		if ((n = hexvalue(sr->base[0])) == -1)
			return (DNS_R_SYNTAX);
		c <<= 4;
		c += n;
		if (++digits == 2) {
			RETERR(mem_tobuffer(target, &c, 1));
			digits = 0;
		}
		isc_textregion_consume(sr, 1);
	}
	if (digits) {
		return (DNS_R_UNEXPECTEDEND);
	}
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
totext_in_nsap(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	       isc_buffer_t *target) 
{
	isc_region_t region;
	char buf[sizeof "xx"];

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->rdclass == 1);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	RETERR(str_totext("0x", target));
	while (region.length != 0) {
		sprintf(buf, "%02x", region.base[0]);
		isc_region_consume(&region, 1);
		RETERR(str_totext(buf, target));
	}
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_nsap(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_buffer_t *source, dns_decompress_t *dctx,
		 isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t region;

	REQUIRE(type == 22);
	REQUIRE(rdclass == 1);

	UNUSED(dctx);
	UNUSED(downcase);

	isc_buffer_active(source, &region);
	if (region.length < 1)
		return (DNS_R_UNEXPECTEDEND);

	RETERR(mem_tobuffer(target, region.base, region.length));
	isc_buffer_forward(source, region.length);
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_in_nsap(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->rdclass == 1);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_in_nsap(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 22);
	REQUIRE(rdata1->rdclass == 1);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_in_nsap(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		   void *source, isc_buffer_t *target)
{

	REQUIRE(type == 22);
	REQUIRE(rdclass == 1);

	UNUSED(source);
	UNUSED(target);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_in_nsap(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->rdclass == 1);

	UNUSED(target);
	UNUSED(mctx);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_in_nsap(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);
}

static inline isc_result_t
additionaldata_in_nsap(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		       void *arg)
{
	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->rdclass == 1);

	UNUSED(add);
	UNUSED(arg);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_in_nsap(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 22);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_IN_1_NSAP_22_C */
