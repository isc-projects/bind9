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

/* $Id: opt_41.c,v 1.5 2000/03/16 22:42:10 gson Exp $ */

/* Reviewed: Thu Mar 16 14:06:44 PST 2000 by gson */

/* RFC 2671 */

#ifndef RDATA_GENERIC_OPT_41_C
#define RDATA_GENERIC_OPT_41_C

static inline isc_result_t
fromtext_opt(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	/*
	 * OPT records do not have a text format.
	 */

	REQUIRE(type == 41);

	UNUSED(rdclass);
	UNUSED(lexer);
	UNUSED(origin);
	UNUSED(downcase);
	UNUSED(target);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
totext_opt(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	   isc_buffer_t *target) 
{
	/*
	 * OPT records do not have a text format.
	 */

	REQUIRE(rdata->type == 41);

	UNUSED(tctx);
	UNUSED(target);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
fromwire_opt(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sregion;
	isc_region_t tregion;
	isc_uint16_t option, length;
	unsigned int total;

	REQUIRE(type == 41);

	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(downcase);

	isc_buffer_active(source, &sregion);
	total = 0;
	while (sregion.length != 0) {
		if (sregion.length < 4)
			return (DNS_R_UNEXPECTEDEND);
		option = uint16_fromregion(&sregion);
		isc_region_consume(&sregion, 2);
		length = uint16_fromregion(&sregion);
		isc_region_consume(&sregion, 2);
		total += 4;
		if (sregion.length < length)
			return (DNS_R_UNEXPECTEDEND);
		isc_region_consume(&sregion, length);
		total += length;
	}

	isc_buffer_active(source, &sregion);
	isc_buffer_available(target, &tregion);
	if (tregion.length < total)
		return (DNS_R_NOSPACE);
	memcpy(tregion.base, sregion.base, total);
	isc_buffer_forward(source, total);
	isc_buffer_add(target, total);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_opt(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 41);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_opt(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 41);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_opt(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	       isc_buffer_t *target)
{
	REQUIRE(type == 41);

	UNUSED(rdclass);
	UNUSED(source);
	UNUSED(target);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_opt(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 41);

	UNUSED(target);
	UNUSED(mctx);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_opt(void *source) {
	UNUSED(source);
}

static inline isc_result_t
additionaldata_opt(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	REQUIRE(rdata->type == 41);

	UNUSED(add);
	UNUSED(arg);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_opt(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {

	/*
	 * OPT records are not digested.
	 */

	REQUIRE(rdata->type == 41);

	UNUSED(digest);
	UNUSED(arg);

	return (DNS_R_NOTIMPLEMENTED);
}

#endif	/* RDATA_GENERIC_OPT_41_C */
