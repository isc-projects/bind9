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

/* $Id: cert_37.c,v 1.20 2000/03/16 02:15:52 tale Exp $ */

/* Reviewed: Wed Mar 15 21:14:32 EST 2000 by tale */

/* RFC 2538 */

#ifndef RDATA_GENERIC_CERT_37_C
#define RDATA_GENERIC_CERT_37_C

static inline isc_result_t
fromtext_cert(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_secalg_t secalg;
	dns_cert_t cert;

	REQUIRE(type == 37);

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(downcase);

	/* cert type */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_cert_fromtext(&cert, &token.value.as_textregion));
	RETERR(uint16_tobuffer(cert, target));
	
	/* key tag */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* algorithm */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_secalg_fromtext(&secalg, &token.value.as_textregion));
	RETERR(mem_tobuffer(target, &secalg, 1));

	return (isc_base64_tobuffer(lexer, target, -1));
}

static inline isc_result_t
totext_cert(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	    isc_buffer_t *target) 
{
	isc_region_t sr;
	char buf[sizeof "64000 "];
	unsigned int n;

	REQUIRE(rdata->type == 37);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &sr);

	/* type */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	RETERR(dns_cert_totext((dns_cert_t)n, target));
	RETERR(str_totext(" ", target));

	/* key tag */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u ", n);
	RETERR(str_totext(buf, target));

	/* algorithm */
	RETERR(dns_secalg_totext(sr.base[0], target));
	isc_region_consume(&sr, 1);

	/* cert */
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sr, tctx->width - 2,
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" )", target));
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_cert(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;

	REQUIRE(type == 37);
	
	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(downcase);

	isc_buffer_active(source, &sr);
	if (sr.length < 5)
		return (DNS_R_UNEXPECTEDEND);

	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_cert(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;

	REQUIRE(rdata->type == 37);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_cert(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 37);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_cert(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		isc_buffer_t *target)
{

	REQUIRE(type == 37);
	
	UNUSED(rdclass);
	UNUSED(source);
	UNUSED(target);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_cert(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 37);
	REQUIRE(target != NULL && target == NULL);
	
	UNUSED(target);
	UNUSED(mctx);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_cert(void *target) {
	REQUIRE(target != NULL && target != NULL);
	REQUIRE(ISC_FALSE);	/* XXX */
}

static inline isc_result_t
additionaldata_cert(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	REQUIRE(rdata->type == 37);

	UNUSED(add);
	UNUSED(arg);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_cert(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 37);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_CERT_37_C */
