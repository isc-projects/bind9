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

 /* $Id: proforma.c,v 1.17 2000/02/03 23:43:05 halley Exp $ */

#ifndef RDATA_GENERIC_#_#_C
#define RDATA_GENERIC_#_#_C

static inline isc_result_t
fromtext_#(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	isc_token_t token;

	REQUIRE(type == #);
	REQUIRE(rdclass == #);

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
totext_#(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	 isc_buffer_t *target) 
{

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->rdclass == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
fromwire_#(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	   isc_buffer_t *source, dns_decompress_t *dctx,
	   isc_boolean_t downcase, isc_buffer_t *target) {

	REQUIRE(type == #);
	REQUIRE(rdclass == #);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_LOCAL);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
towire_#(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->rdclass == #);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL):
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_LOCAL);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline int
compare_#(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == #);
	REQUIRE(rdata1->rdclass == #);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_#(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == #);
	REQUIRE(rdclass == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_#(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->rdclass == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_#(void *source) {
	dns_rdata_#_t *# = source;

	REQUIRE(source != NULL);
	REQUIRE(#->common.rdtype == #);
	REQUIRE(#->common.rdclass == #);
	
}

static inline isc_result_t
additionaldata_#(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		 void *arg)
{
	REQUIRE(rdata->type == #);
	REQUIRE(rdata->rdclass == #);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_#(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->rdclass == #);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_#_#_C */
