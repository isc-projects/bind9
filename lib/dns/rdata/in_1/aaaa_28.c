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

/* $Id: aaaa_28.c,v 1.24 2000/05/22 12:38:07 marka Exp $ */

/* Reviewed: Thu Mar 16 16:52:50 PST 2000 by bwelling */

/* RFC 1886 */

#ifndef RDATA_IN_1_AAAA_28_C
#define RDATA_IN_1_AAAA_28_C

#include <isc/net.h>

#define RRTYPE_AAAA_ATTRIBUTES (0)

static inline isc_result_t
fromtext_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_lex_t *lexer, dns_name_t *origin,
		 isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	unsigned char addr[16];
	isc_region_t region;

	UNUSED(origin);
	UNUSED(downcase);

	REQUIRE(type == 28);
	REQUIRE(rdclass == 1);

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));

	if (inet_pton(AF_INET6, token.value.as_pointer, addr) != 1)
		return (DNS_R_BADAAAA);
	isc_buffer_availableregion(target, &region);
	if (region.length < 16)
		return (ISC_R_NOSPACE);
	memcpy(region.base, addr, 16);
	isc_buffer_add(target, 16);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_in_aaaa(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	       isc_buffer_t *target) 
{
	isc_region_t region;

	UNUSED(tctx);

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);
	REQUIRE(rdata->length == 16);

	isc_buffer_availableregion(target, &region);
	if (inet_ntop(AF_INET6, rdata->data,
		      (char *)region.base, region.length) == NULL)
		return (ISC_R_NOSPACE);

	isc_buffer_add(target, strlen((char *)region.base));
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_buffer_t *source, dns_decompress_t *dctx,
		 isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sregion;
	isc_region_t tregion;

	UNUSED(dctx);
	UNUSED(downcase);

	REQUIRE(type == 28);
	REQUIRE(rdclass == 1);

	isc_buffer_activeregion(source, &sregion);
	isc_buffer_availableregion(target, &tregion);
	if (sregion.length < 16)
		return (ISC_R_UNEXPECTEDEND);
	if (tregion.length < 16)
		return (ISC_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 16);
	isc_buffer_forward(source, 16);
	isc_buffer_add(target, 16);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_in_aaaa(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;

	UNUSED(cctx);

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	isc_buffer_availableregion(target, &region);
	if (region.length < rdata->length)
		return (ISC_R_NOSPACE);
	memcpy(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 16);
	return (ISC_R_SUCCESS);
}

static inline int
compare_in_aaaa(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 28);
	REQUIRE(rdata1->rdclass == 1);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		   void *source, isc_buffer_t *target)
{
	dns_rdata_in_aaaa_t *aaaa = source;

	REQUIRE(type == 28);
	REQUIRE(rdclass == 1);
	REQUIRE(source != NULL);
	REQUIRE(aaaa->common.rdtype == type);
	REQUIRE(aaaa->common.rdclass == rdclass);

	return (mem_tobuffer(target, aaaa->in6_addr.s6_addr, 16));
}

static inline isc_result_t
tostruct_in_aaaa(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_in_aaaa_t *aaaa = target;
	isc_region_t r;

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);
	REQUIRE(target != NULL);

	UNUSED(mctx);

	aaaa->common.rdclass = rdata->rdclass;
	aaaa->common.rdtype = rdata->type;
	ISC_LINK_INIT(&aaaa->common, link);

	dns_rdata_toregion(rdata, &r);
	INSIST(r.length == 16);
	memcpy(aaaa->in6_addr.s6_addr, r.base, 16);

	return (ISC_R_SUCCESS);
}

static inline void
freestruct_in_aaaa(void *source) {
	dns_rdata_in_aaaa_t *aaaa = source;

	REQUIRE(source != NULL);
	REQUIRE(aaaa->common.rdclass == 1);
	REQUIRE(aaaa->common.rdtype == 28);
}

static inline isc_result_t
additionaldata_in_aaaa(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		       void *arg)
{
	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_in_aaaa(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_IN_1_AAAA_28_C */
