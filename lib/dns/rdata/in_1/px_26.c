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

 /* $Id: px_26.c,v 1.14 2000/02/03 23:43:19 halley Exp $ */

 /* RFC 2163 */

#ifndef RDATA_IN_1_PX_26_C
#define RDATA_IN_1_PX_26_C

static inline isc_result_t
fromtext_in_px(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == 26);
	REQUIRE(rdclass == 1);

	/* preference */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* MAP822 */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	/* MAPX400 */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static inline isc_result_t
totext_in_px(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	      isc_buffer_t *target) 
{
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	char buf[sizeof "64000"];
	unsigned short num;

	REQUIRE(rdata->type == 26);
	REQUIRE(rdata->rdclass == 1);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	/* preference */
	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* MAP822 */
	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, tctx->origin, &prefix);
	isc_region_consume(&region, name_length(&name));
	RETERR(dns_name_totext(&prefix, sub, target));
	RETERR(str_totext(" ", target));

	/* MAPX400 */
	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, tctx->origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_in_px(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target)
{
        dns_name_t name;
	isc_region_t sregion;

	REQUIRE(type == 26);
	REQUIRE(rdclass == 1);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);
        
        dns_name_init(&name, NULL);

	/* preference */
	isc_buffer_active(source, &sregion);
	if (sregion.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sregion.base, 2));
	isc_buffer_forward(source, 2);

	/* MAP822 */
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	/* MAPX400 */
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static inline isc_result_t
towire_in_px(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == 26);
	REQUIRE(rdata->rdclass == 1);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	/* preference */
	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	/* MAP822 */
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&region, name_length(&name));

	/* MAPX400 */
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	return (dns_name_towire(&name, cctx, target));
}

static inline int
compare_in_px(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 26);
	REQUIRE(rdata1->rdclass == 1);

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

	result = dns_name_rdatacompare(&name1, &name2);
	if (result != 0)
		return (result);

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_rdatacompare(&name1, &name2));
}

static inline isc_result_t
fromstruct_in_px(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		 isc_buffer_t *target)
{
	dns_rdata_in_px_t *px = source;
	isc_region_t region;

	REQUIRE(type == 26);
	REQUIRE(rdclass == 1);
	REQUIRE(source != NULL);
	REQUIRE(px->common.rdtype == type);
	REQUIRE(px->common.rdclass == rdclass);

	RETERR(uint16_tobuffer(px->preference, target));
	dns_name_toregion(&px->map822, &region);
	RETERR(isc_buffer_copyregion(target, &region));
	dns_name_toregion(&px->mapx400, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t
tostruct_in_px(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	isc_region_t region;
	isc_region_t nr;
	dns_rdata_in_px_t *px = target;
	dns_name_t name;
	isc_result_t result;

	REQUIRE(rdata->type == 26);
	REQUIRE(rdata->rdclass == 1);
	REQUIRE(target != NULL);
	REQUIRE(mctx != NULL);

	px->common.rdclass = rdata->rdclass;
	px->common.rdtype = rdata->type;
	ISC_LINK_INIT(&px->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);

	px->preference = uint16_fromregion(&region);
	isc_region_consume(&region, 2);

	dns_name_fromregion(&name, &region);
	dns_name_toregion(&name, &nr);
	isc_region_consume(&region, nr.length);
	px->mctx = mctx;
	dns_name_init(&px->map822, NULL);
	result = dns_name_dup(&name, px->mctx, &px->map822);
	if (result != ISC_R_SUCCESS) {
		px->mctx = NULL;
		return (result);
	}

	dns_name_init(&px->mapx400, NULL);
	result = dns_name_dup(&name, px->mctx, &px->map822);
	if (result != ISC_R_SUCCESS) {
		dns_name_free(&px->map822, px->mctx);
		px->mctx = NULL;
	}
	return (result);
}

static inline void
freestruct_in_px(void *source) {
	dns_rdata_in_px_t *px = source;

	REQUIRE(source != NULL);

	dns_name_free(&px->map822, px->mctx);
	dns_name_free(&px->mapx400, px->mctx);
	px->mctx = NULL;
}

static inline isc_result_t
additionaldata_in_px(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		     void *arg)
{
	REQUIRE(rdata->type == 26);
	REQUIRE(rdata->rdclass == 1);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_in_px(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r1, r2;
	dns_name_t name;
	isc_result_t result;

	REQUIRE(rdata->type == 26);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &r1);
	r2 = r1;
	isc_region_consume(&r2, 2);
	r1.length = 2;
	result = (digest)(arg, &r1);
	if (result != DNS_R_SUCCESS)
		return (result);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r2);
	result = dns_name_digest(&name, digest, arg);
	if (result != DNS_R_SUCCESS)
		return (result);
	isc_region_consume(&r2, name_length(&name));
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r2);

	return (dns_name_digest(&name, digest, arg));
}

#endif	/* RDATA_IN_1_PX_26_C */
