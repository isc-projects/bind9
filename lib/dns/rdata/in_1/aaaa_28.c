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

 /* $Id: aaaa_28.c,v 1.16 2000/02/03 23:43:17 halley Exp $ */

 /* RFC 1886 */

#ifndef RDATA_IN_1_AAAA_28_C
#define RDATA_IN_1_AAAA_28_C

#include <string.h>

#include <isc/net.h>

static inline isc_result_t
fromtext_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_lex_t *lexer, dns_name_t *origin,
		 isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	unsigned char addr[16];
	isc_region_t region;

	REQUIRE(type == 28);
	REQUIRE(rdclass == 1);

	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));

	if (inet_pton(AF_INET6, token.value.as_pointer, addr) != 1)
		return (DNS_R_BADAAAA);
	isc_buffer_available(target, &region);
	if (region.length < 16)
		return (DNS_R_NOSPACE);
	memcpy(region.base, addr, 16);
	isc_buffer_add(target, 16);
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
totext_in_aaaa(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	       isc_buffer_t *target) 
{
	isc_region_t region;

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);
	REQUIRE(rdata->length == 16);

	tctx = tctx;	/* unused */

	isc_buffer_available(target, &region);
	if (inet_ntop(AF_INET6, rdata->data,
		      (char *)region.base, region.length) == NULL)
		return (DNS_R_NOSPACE);

	isc_buffer_add(target, strlen((char *)region.base));
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_buffer_t *source, dns_decompress_t *dctx,
		 isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(type == 28);
	REQUIRE(rdclass == 1);

	dctx = dctx;		/* unused */
	downcase = downcase;	/* unused */


	isc_buffer_active(source, &sregion);
	isc_buffer_available(target, &tregion);
	if (sregion.length < 16)
		return (DNS_R_UNEXPECTEDEND);
	if (tregion.length < 16)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 16);
	isc_buffer_forward(source, 16);
	isc_buffer_add(target, 16);
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_in_aaaa(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t region;

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	cctx = cctx;	/*unused*/

	isc_buffer_available(target, &region);
	if (region.length < rdata->length)
		return (DNS_R_NOSPACE);
	memcpy(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 16);
	return (DNS_R_SUCCESS);
}

static inline int
compare_in_aaaa(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 28);
	REQUIRE(rdata1->rdclass == 1);

	result = memcmp(rdata1->data, rdata2->data, 16);
	if (result != 0)
		result = (result < 0) ? -1 : 1;

	return (result);
}

static inline isc_result_t
fromstruct_in_aaaa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		   void *source, isc_buffer_t *target)
{

	REQUIRE(type == 1);
	REQUIRE(rdclass == 1);

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_in_aaaa(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_in_aaaa(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_in_aaaa(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		       void *arg)
{
	REQUIRE(rdata->type == 28);
	REQUIRE(rdata->rdclass == 1);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
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
