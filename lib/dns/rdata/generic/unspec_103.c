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

/* $Id: unspec_103.c,v 1.12 2000/03/20 22:48:59 gson Exp $ */

#ifndef RDATA_GENERIC_UNSPEC_103_C
#define RDATA_GENERIC_UNSPEC_103_C

static inline isc_result_t
fromtext_unspec(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		isc_lex_t *lexer, dns_name_t *origin,
		isc_boolean_t downcase, isc_buffer_t *target)
{

	REQUIRE(type == 103);

	rdclass = rdclass;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	return (atob_tobuffer(lexer, target));
}

static inline isc_result_t
totext_unspec(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	      isc_buffer_t *target) 
{
	

	REQUIRE(rdata->type == 103);

	tctx = tctx;	/*unused*/

	return (btoa_totext(rdata->data, rdata->length, target));
}

static inline isc_result_t
fromwire_unspec(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		isc_buffer_t *source, dns_decompress_t *dctx,
		isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;

	REQUIRE(type == 103);

	rdclass = rdclass;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/
	isc_buffer_active(source, &sr);
	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_unspec(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 103);

	cctx = cctx;		/*unused*/

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_unspec(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata1->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 103);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_unspec(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		  isc_buffer_t *target)
{

	REQUIRE(type == 103);

	rdclass = rdclass;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_unspec(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 103);

	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_unspec(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_unspec(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		      void *arg)
{
	REQUIRE(rdata->type == 103);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_unspec(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 103);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_UNSPEC_103_C */
