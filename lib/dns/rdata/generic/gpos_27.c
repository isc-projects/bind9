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

/* $Id: gpos_27.c,v 1.20 2000/05/22 12:37:33 marka Exp $ */

/* reviewed: Wed Mar 15 16:48:45 PST 2000 by brister */

/* RFC 1712 */

#ifndef RDATA_GENERIC_GPOS_27_C
#define RDATA_GENERIC_GPOS_27_C

#define RRTYPE_GPOS_ATTRIBUTES (0)

static inline isc_result_t
fromtext_gpos(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	int i;

	REQUIRE(type == 27);

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(downcase);

	for (i = 0; i < 3 ; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_qstring,
				ISC_FALSE));
		RETERR(txt_fromtext(&token.value.as_textregion, target));
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_gpos(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	    isc_buffer_t *target) 
{
	isc_region_t region;
	int i;

	REQUIRE(rdata->type == 27);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);

	for (i = 0; i < 3 ; i++) {
		RETERR(txt_totext(&region, target));
		if (i != 2)
			RETERR(str_totext(" ", target));
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_gpos(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	int i;

	REQUIRE(type == 27);

	UNUSED(dctx);
	UNUSED(rdclass);
	UNUSED(downcase);

	for (i = 0 ; i < 3; i++)
		RETERR(txt_fromwire(source, target));
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_gpos(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target)
{

	REQUIRE(rdata->type == 27);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_gpos(dns_rdata_t *rdata1, dns_rdata_t *rdata2)
{
	isc_region_t r1;
	isc_region_t r2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 27);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_gpos(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		isc_buffer_t *target)
{
	dns_rdata_gpos_t *gpos = source;

	REQUIRE(type == 27);
	REQUIRE(source != NULL);
	REQUIRE(gpos->common.rdtype == type);
	REQUIRE(gpos->common.rdclass == rdclass);

	RETERR(uint8_tobuffer(gpos->long_len, target));
	RETERR(mem_tobuffer(target, gpos->longitude, gpos->long_len));
	RETERR(uint8_tobuffer(gpos->lat_len, target));
	RETERR(mem_tobuffer(target, gpos->latitude, gpos->lat_len));
	RETERR(uint8_tobuffer(gpos->alt_len, target));
	return (mem_tobuffer(target, gpos->altitude, gpos->alt_len));
}

static inline isc_result_t
tostruct_gpos(dns_rdata_t *rdata, void *target, isc_mem_t *mctx)
{
	dns_rdata_gpos_t *gpos = target;
	isc_region_t region;

	REQUIRE(rdata->type == 27);
	REQUIRE(target != NULL);

	gpos->common.rdclass = rdata->rdclass;
	gpos->common.rdtype = rdata->type;
	ISC_LINK_INIT(&gpos->common, link);

	dns_rdata_toregion(rdata, &region);
	gpos->long_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (gpos->long_len != 0) {
		gpos->longitude = mem_maybedup(mctx, region.base,
					       gpos->long_len);
		if (gpos->longitude == NULL)
			return (ISC_R_NOMEMORY);
		isc_region_consume(&region, gpos->long_len);
	} else
		gpos->longitude = NULL;

	gpos->lat_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (gpos->lat_len > 0) {
		gpos->latitude = mem_maybedup(mctx, region.base, gpos->lat_len);
		if (gpos->latitude == NULL)
			goto cleanup_longitude;
		isc_region_consume(&region, gpos->lat_len);
	} else
		gpos->latitude = NULL;

	gpos->alt_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (gpos->lat_len > 0) {
		gpos->altitude = mem_maybedup(mctx, region.base, gpos->alt_len);
		if (gpos->altitude == NULL)
			goto cleanup_latitude;
	} else 
		gpos->altitude = NULL;

	gpos->mctx = mctx;
	return (ISC_R_SUCCESS);

 cleanup_latitude:
	if (mctx != NULL && gpos->longitude != NULL)
		isc_mem_free(mctx, gpos->longitude);

 cleanup_longitude:
	if (mctx != NULL && gpos->latitude != NULL)
		isc_mem_free(mctx, gpos->latitude);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_gpos(void *source)
{
	dns_rdata_gpos_t *gpos = source;

	REQUIRE(source != NULL);
	REQUIRE(gpos->common.rdtype == 27);

	if (gpos->mctx == NULL)
		return;

	if (gpos->longitude != NULL)
		isc_mem_free(gpos->mctx, gpos->longitude);
	if (gpos->latitude != NULL)
		isc_mem_free(gpos->mctx, gpos->latitude);
	if (gpos->altitude != NULL)
		isc_mem_free(gpos->mctx, gpos->altitude);
	gpos->mctx = NULL;
}

static inline isc_result_t
additionaldata_gpos(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	REQUIRE(rdata->type == 27);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_gpos(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg)
{
	isc_region_t r;

	REQUIRE(rdata->type == 27);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_GPOS_27_C */
