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

 /* $Id: x25_19.c,v 1.11 2000/02/03 23:43:09 halley Exp $ */

 /* RFC 1183 */

#ifndef RDATA_GENERIC_X25_19_C
#define RDATA_GENERIC_X25_19_C

#include <ctype.h>

static inline isc_result_t
fromtext_x25(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	unsigned int i;

	REQUIRE(type == 19);

	rdclass = rdclass;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_FALSE));
	for (i = 0; i < token.value.as_textregion.length; i++)
		if (!isascii(token.value.as_textregion.base[i]&0xff) ||
		    !isdigit(token.value.as_textregion.base[i]&0xff))
			return (DNS_R_RANGE);
	return (txt_fromtext(&token.value.as_textregion, target));
}

static inline isc_result_t
totext_x25(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	   isc_buffer_t *target) 
{
	isc_region_t region;

	REQUIRE(rdata->type == 19);

	tctx = tctx;	/*unused*/

	dns_rdata_toregion(rdata, &region);
	return (txt_totext(&region, target));
}

static inline isc_result_t
fromwire_x25(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{

	REQUIRE(type == 19);

	dctx = dctx;		/* unused */
	rdclass = rdclass;		/* unused */
	downcase = downcase;	/* unused */

	return (txt_fromwire(source, target));
}

static inline isc_result_t
towire_x25(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 19);

	cctx = cctx;

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_x25(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int l;
	int result;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 19);

	l = (rdata1->length < rdata2->length) ? rdata1->length : rdata2->length;
	result = memcmp(rdata1->data, rdata2->data, l);

	if (result != 0)
		result = (result < 0) ? -1 : 1;
	else if (rdata1->length != rdata2->length)
			result = (rdata1->length < rdata2->length) ? -1 : 1;

	return (result);
}

static inline isc_result_t
fromstruct_x25(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	       isc_buffer_t *target)
{

	REQUIRE(type == 19);

	rdclass = rdclass;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_x25(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 19);

	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_x25(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_x25(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	REQUIRE(rdata->type == 19);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_x25(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 19);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_X25_19_C */
