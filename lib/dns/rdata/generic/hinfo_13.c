/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

/* $Id: hinfo_13.c,v 1.25 2000/05/22 12:37:34 marka Exp $ */

/*
 * Reviewed: Wed Mar 15 16:47:10 PST 2000 by halley.
 */

#ifndef RDATA_GENERIC_HINFO_13_C
#define RDATA_GENERIC_HINFO_13_C

#define RRTYPE_HINFO_ATTRIBUTES (0)

static inline isc_result_t
fromtext_hinfo(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	int i;

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(downcase);

	REQUIRE(type == 13);

	for (i = 0; i < 2 ; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_qstring,
				ISC_FALSE));
		RETERR(txt_fromtext(&token.value.as_textregion, target));
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_hinfo(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	     isc_buffer_t *target) 
{
	isc_region_t region;

	UNUSED(tctx);

	REQUIRE(rdata->type == 13);

	dns_rdata_toregion(rdata, &region);
	RETERR(txt_totext(&region, target));
	RETERR(str_totext(" ", target));
	return (txt_totext(&region, target));
}

static inline isc_result_t
fromwire_hinfo(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	       isc_buffer_t *source, dns_decompress_t *dctx,
	       isc_boolean_t downcase, isc_buffer_t *target)
{

	UNUSED(dctx);
	UNUSED(rdclass);
	UNUSED(downcase);

	REQUIRE(type == 13);

	RETERR(txt_fromwire(source, target));
	return (txt_fromwire(source, target));
}

static inline isc_result_t
towire_hinfo(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	UNUSED(cctx);

	REQUIRE(rdata->type == 13);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_hinfo(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 13);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_hinfo(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		 isc_buffer_t *target)
{
	dns_rdata_hinfo_t *hinfo = source;

	REQUIRE(type == 13);
	REQUIRE(source != NULL);
	REQUIRE(hinfo->common.rdtype == type);
	REQUIRE(hinfo->common.rdclass == rdclass);

	RETERR(uint8_tobuffer(hinfo->cpu_len, target));
	RETERR(mem_tobuffer(target, hinfo->cpu, hinfo->cpu_len));
	RETERR(uint8_tobuffer(hinfo->os_len, target));
	return (mem_tobuffer(target, hinfo->os, hinfo->os_len));
}

static inline isc_result_t
tostruct_hinfo(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_hinfo_t *hinfo = target;
	isc_region_t region;

	REQUIRE(rdata->type == 13);
	REQUIRE(target != NULL);

	hinfo->common.rdclass = rdata->rdclass;
	hinfo->common.rdtype = rdata->type;
	ISC_LINK_INIT(&hinfo->common, link);

	dns_rdata_toregion(rdata, &region);
	hinfo->cpu_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (hinfo->cpu_len > 0) {
		hinfo->cpu = mem_maybedup(mctx, region.base, hinfo->cpu_len);
		if (hinfo->cpu == NULL)
			return (ISC_R_NOMEMORY);
		isc_region_consume(&region, hinfo->cpu_len);
	} else
		hinfo->cpu = NULL;

	hinfo->os_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (hinfo->os_len > 0) {
		hinfo->os = mem_maybedup(mctx, region.base, hinfo->os_len);
		if (hinfo->os == NULL)
			goto cleanup;
	} else
		hinfo->os = NULL;
	hinfo->mctx = mctx;
	return (ISC_R_SUCCESS);

 cleanup:
	if (mctx != NULL && hinfo->cpu != NULL)
		isc_mem_free(mctx, hinfo->cpu);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_hinfo(void *source) {
	dns_rdata_hinfo_t *hinfo = source;

	REQUIRE(source != NULL);

	if (hinfo->mctx == NULL)
		return;

	if (hinfo->cpu != NULL)
		isc_mem_free(hinfo->mctx, hinfo->cpu);
	if (hinfo->os != NULL)
		isc_mem_free(hinfo->mctx, hinfo->os);
	hinfo->mctx = NULL;
}

static inline isc_result_t
additionaldata_hinfo(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		     void *arg)
{
	REQUIRE(rdata->type == 13);

	UNUSED(add);
	UNUSED(arg);
	UNUSED(rdata);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_hinfo(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 13);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_HINFO_13_C */
