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

/* $Id: mx_15.c,v 1.36 2000/05/22 12:37:47 marka Exp $ */

/* reviewed: Wed Mar 15 18:05:46 PST 2000 by brister */

#ifndef RDATA_GENERIC_MX_15_C
#define RDATA_GENERIC_MX_15_C

#define RRTYPE_MX_ATTRIBUTES (0)

static inline isc_result_t
fromtext_mx(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	    isc_lex_t *lexer, dns_name_t *origin,
	    isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == 15);

	UNUSED(rdclass);

	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (ISC_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static inline isc_result_t
totext_mx(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	  isc_buffer_t *target) 
{
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	char buf[sizeof "64000"];
	unsigned short num;

	REQUIRE(rdata->type == 15);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u", num);
	RETERR(str_totext(buf, target));

	RETERR(str_totext(" ", target));

	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, tctx->origin, &prefix);
	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_mx(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	    isc_buffer_t *source, dns_decompress_t *dctx,
	    isc_boolean_t downcase, isc_buffer_t *target)
{
        dns_name_t name;
	isc_region_t sregion;

	REQUIRE(type == 15);

	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);
        
        dns_name_init(&name, NULL);

	isc_buffer_activeregion(source, &sregion);
	if (sregion.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sregion.base, 2));
	isc_buffer_forward(source, 2);
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static inline isc_result_t
towire_mx(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == 15);

	dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);

	return (dns_name_towire(&name, cctx, target));
}

static inline int
compare_mx(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 15);

	order = memcmp(rdata1->data, rdata2->data, 2);
	if (order != 0)
		return (order < 0 ? -1 : 1);

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

static inline isc_result_t
fromstruct_mx(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	      isc_buffer_t *target)
{
	dns_rdata_mx_t *mx = source;
	isc_region_t region;

	REQUIRE(type == 15);
	REQUIRE(source != NULL);
	REQUIRE(mx->common.rdtype == type);
	REQUIRE(mx->common.rdclass == rdclass);

	RETERR(uint16_tobuffer(mx->pref, target));
	dns_name_toregion(&mx->mx, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t
tostruct_mx(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	isc_region_t region;
	dns_rdata_mx_t *mx = target;
	dns_name_t name;

	REQUIRE(rdata->type == 15);
	REQUIRE(target != NULL);

	mx->common.rdclass = rdata->rdclass;
	mx->common.rdtype = rdata->type;
	ISC_LINK_INIT(&mx->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	mx->pref = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);
	dns_name_init(&mx->mx, NULL);
	RETERR(name_duporclone(&name, mctx, &mx->mx));
	mx->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_mx(void *source) {
	dns_rdata_mx_t *mx = source;

	REQUIRE(source != NULL);
	REQUIRE(mx->common.rdtype == 15);

	if (mx->mctx == NULL)
		return;

	dns_name_free(&mx->mx, mx->mctx);
	mx->mctx = NULL;
}

static inline isc_result_t
additionaldata_mx(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		  void *arg)
{
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == 15);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);

	return ((add)(arg, &name, dns_rdatatype_a));
}

static inline isc_result_t
digest_mx(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r1, r2;
	dns_name_t name;

	REQUIRE(rdata->type == 15);

	dns_rdata_toregion(rdata, &r1);
	r2 = r1;
	isc_region_consume(&r2, 2);
	r1.length = 2;
	RETERR((digest)(arg, &r1));
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r2);
	return (dns_name_digest(&name, digest, arg));
}

#endif	/* RDATA_GENERIC_MX_15_C */
