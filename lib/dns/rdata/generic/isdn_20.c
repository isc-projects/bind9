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

/* $Id: isdn_20.c,v 1.19 2000/05/22 12:37:36 marka Exp $ */

/* Reviewed: Wed Mar 15 16:53:11 PST 2000 by bwelling */

/* RFC 1183 */

#ifndef RDATA_GENERIC_ISDN_20_C
#define RDATA_GENERIC_ISDN_20_C

#define RRTYPE_ISDN_ATTRIBUTES (0)

static inline isc_result_t
fromtext_isdn(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(downcase);

	REQUIRE(type == 20);

	/* ISDN-address */
	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_FALSE));
	RETERR(txt_fromtext(&token.value.as_textregion, target));

	/* sa: optional */
	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_TRUE));
	if (token.type != isc_tokentype_string &&
	    token.type != isc_tokentype_qstring) {
		isc_lex_ungettoken(lexer, &token);
		return (ISC_R_SUCCESS);
	}
	return (txt_fromtext(&token.value.as_textregion, target));
}

static inline isc_result_t
totext_isdn(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	    isc_buffer_t *target) 
{
	isc_region_t region;

	UNUSED(tctx);

	REQUIRE(rdata->type == 20);

	dns_rdata_toregion(rdata, &region);
	RETERR(txt_totext(&region, target));
	if (region.length == 0)
		return (ISC_R_SUCCESS);
	RETERR(str_totext(" ", target));
	return (txt_totext(&region, target));
}

static inline isc_result_t
fromwire_isdn(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	UNUSED(dctx);
	UNUSED(rdclass);
	UNUSED(downcase);

	REQUIRE(type == 20);

	RETERR(txt_fromwire(source, target));
	if (buffer_empty(source))
		return (ISC_R_SUCCESS);
	return (txt_fromwire(source, target));
}

static inline isc_result_t
towire_isdn(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	UNUSED(cctx);

	REQUIRE(rdata->type == 20);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_isdn(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 20);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_isdn(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		isc_buffer_t *target)
{
	dns_rdata_isdn_t *isdn = source;

	REQUIRE(type == 20);
	REQUIRE(source != NULL);
	REQUIRE(isdn->common.rdtype == type);
	REQUIRE(isdn->common.rdclass == rdclass);

	RETERR(uint8_tobuffer(isdn->isdn_len, target));
	RETERR(mem_tobuffer(target, isdn->isdn, isdn->isdn_len));
	RETERR(uint8_tobuffer(isdn->subaddress_len, target));
	return (mem_tobuffer(target, isdn->subaddress, isdn->subaddress_len));
}

static inline isc_result_t
tostruct_isdn(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_isdn_t *isdn = target;
	isc_region_t r;

	REQUIRE(rdata->type == 20);
	REQUIRE(target != NULL);

	isdn->common.rdclass = rdata->rdclass;
	isdn->common.rdtype = rdata->type;
	ISC_LINK_INIT(&isdn->common, link);

	dns_rdata_toregion(rdata, &r);

	isdn->isdn_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	if (isdn->isdn_len > 0) {
		isdn->isdn = mem_maybedup(mctx, r.base, isdn->isdn_len);
		if (isdn->isdn == NULL)
			return (ISC_R_NOMEMORY);
		isc_region_consume(&r, isdn->isdn_len);
	} else
		isdn->isdn = NULL;

	isdn->subaddress_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	if (isdn->subaddress_len > 0) {
		isdn->subaddress = mem_maybedup(mctx, r.base,
						isdn->subaddress_len);
		if (isdn->subaddress == NULL)
			goto cleanup;
	} else
		isdn->subaddress = NULL;

	isdn->mctx = mctx;
	return (ISC_R_SUCCESS);

 cleanup:
	if (mctx != NULL && isdn->isdn != NULL)
		isc_mem_free(mctx, isdn->isdn);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_isdn(void *source) {
	dns_rdata_isdn_t *isdn = source;

	REQUIRE(source != NULL);
	
	if (isdn->mctx == NULL)
		return;

	if (isdn->isdn != NULL)
		isc_mem_free(isdn->mctx, isdn->isdn);
	if (isdn->subaddress != NULL)
		isc_mem_free(isdn->mctx, isdn->subaddress);
	isdn->mctx = NULL;
}

static inline isc_result_t
additionaldata_isdn(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	REQUIRE(rdata->type == 20);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_isdn(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 20);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_ISDN_20_C */
