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

 /* $Id: null_10.c,v 1.16 2000/02/03 23:43:04 halley Exp $ */

#ifndef RDATA_GENERIC_NULL_10_C
#define RDATA_GENERIC_NULL_10_C

static inline isc_result_t
fromtext_null(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target)
{

	REQUIRE(type == 10);

	rdclass = rdclass;		/*unused*/
	type = type;		/*unused*/
	lexer = lexer;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
totext_null(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	    isc_buffer_t *target) 
{
	

	REQUIRE(rdata->type == 10);
	REQUIRE(rdata->length == 0);

	tctx = tctx;	/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_null(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target)
{

	REQUIRE(type == 10);

	rdclass = rdclass;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/
	target = target;	/*unused*/
	source = source;	/*unused*/

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_null(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 10);

	cctx = cctx;		/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static inline int
compare_null(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {

	REQUIRE(rdata1->type == rdata1->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 10);

	return (0);
}

static inline isc_result_t
fromstruct_null(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	        isc_buffer_t *target)
{

	REQUIRE(type == 10);

	rdclass = rdclass;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_null(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_null_t *null = target;

	REQUIRE(rdata->type == 10);
	REQUIRE(target != NULL);

	mctx = mctx;

	null->common.rdtype = rdata->type;
	null->common.rdclass = rdata->rdclass;
	ISC_LINK_INIT(&null->common, link);

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_null(void *source) {
	REQUIRE(source != NULL);
	/* No action required. */
}

static inline isc_result_t
additionaldata_null(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	REQUIRE(rdata->type == 10);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_null(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {

	REQUIRE(rdata->type == 10);

	(void)digest;
	(void)arg;

	return (DNS_R_SUCCESS);
}

#endif	/* RDATA_GENERIC_NULL_10_C */
