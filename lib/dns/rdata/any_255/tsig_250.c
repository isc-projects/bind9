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

 /* $Id: tsig_250.c,v 1.22 2000/02/03 23:43:20 halley Exp $ */

 /* draft-ietf-dnsind-tsig-07.txt */

#ifndef RDATA_ANY_255_TSIG_250_C
#define RDATA_ANY_255_TSIG_250_C
#include <isc/str.h>

static inline isc_result_t
fromtext_any_tsig(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_lex_t *lexer, dns_name_t *origin,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_uint64_t sigtime;
	isc_buffer_t buffer;
	char *e;

	REQUIRE(type == 250);
	REQUIRE(rdclass == 255);

	/* Algorithm Name */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	/* Time Signed: 48 bits */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	sigtime = isc_strtouq(token.value.as_pointer, &e, 10);
	if (*e != 0)
		return (DNS_R_SYNTAX);
	if ((sigtime >> 48) != 0)
		return(DNS_R_RANGE);
	RETERR(uint16_tobuffer((isc_uint16_t)(sigtime >> 32), target));
	RETERR(uint32_tobuffer((isc_uint32_t)(sigtime & 0xffffffff), target));

	/* Fudge */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Signature Size */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Signature */
	RETERR(isc_base64_tobuffer(lexer, target, token.value.as_ulong));

	/* Original ID */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Error */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Other Len */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Other Data */
	return (isc_base64_tobuffer(lexer, target, token.value.as_ulong));
}

static inline isc_result_t
totext_any_tsig(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
		isc_buffer_t *target) 
{
	isc_region_t sr;
	isc_region_t sigr;
	char buf[sizeof "281474976710655 "];	
	char *bufp;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	isc_uint64_t sigtime;
	unsigned short n;

	REQUIRE(rdata->type == 250);
	REQUIRE(rdata->rdclass == 255);

	dns_rdata_toregion(rdata, &sr);
	/* Algorithm Name */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));
	RETERR(str_totext(" ", target));
	isc_region_consume(&sr, name_length(&name));

	/* Time Signed */
	sigtime = ((isc_uint64_t)sr.base[0] << 40) |
		  ((isc_uint64_t)sr.base[1] << 32) |
		  (sr.base[2] << 24) | (sr.base[3] << 16) |
		  (sr.base[4] << 8) | sr.base[5];
	isc_region_consume(&sr, 6);
	bufp = &buf[sizeof buf - 1];
	*bufp-- = 0;
	*bufp-- = ' ';
	do {
		*bufp-- = decdigits[sigtime % 10];
		sigtime /= 10;
	} while (sigtime != 0);
	bufp++;
	RETERR(str_totext(bufp, target));

	/* Fudge */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u ", n);
	RETERR(str_totext(buf, target));

	/* Signature Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u", n);
	RETERR(str_totext(buf, target));

	/* Signature */
	REQUIRE(n <= sr.length);
	sigr = sr;
	sigr.length = n;
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)	
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sigr, tctx->width - 2, 
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" ) ", target));
	else
		RETERR(str_totext(" ", target));		
	isc_region_consume(&sr, n);

	/* Original ID */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u ", n);
	RETERR(str_totext(buf, target));

	/* Error */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u ", n);
	RETERR(str_totext(buf, target));

	/* Other Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u ", n);
	RETERR(str_totext(buf, target));

	/* Other */
	return (isc_base64_totext(&sr, 60, " ", target));
}

static inline isc_result_t
fromwire_any_tsig(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_buffer_t *source, dns_decompress_t *dctx,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	dns_name_t name;
	unsigned long n;

	REQUIRE(type == 250);
	REQUIRE(rdclass == 255);
	
	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	/* Algorithm Name */
	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	isc_buffer_active(source, &sr);
	/* Time Signed + Fudge */
	if (sr.length < 8)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 8));
	isc_region_consume(&sr, 8);
	isc_buffer_forward(source, 8);

	/* Signature Length + Signature */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, n + 2));
	isc_region_consume(&sr, n + 2);
	isc_buffer_forward(source, n + 2);

	/* Original ID + Error */
	if (sr.length < 4)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base,  4));
	isc_region_consume(&sr, 4);
	isc_buffer_forward(source, 4);

	/* Other Length + Other */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	isc_buffer_forward(source, n + 2);
	return (mem_tobuffer(target, sr.base, n + 2));
}

static inline isc_result_t
towire_any_tsig(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 250);
	REQUIRE(rdata->rdclass == 255);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	dns_rdata_toregion(rdata, &sr);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&sr, name_length(&name));
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_any_tsig(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 250);
	REQUIRE(rdata1->rdclass == 255);
	
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	result = dns_name_rdatacompare(&name1, &name2);
	if (result != 0)
		return (result);
	isc_region_consume(&r1, name_length(&name1));
	isc_region_consume(&r2, name_length(&name2));
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_any_tsig(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		    void *source, isc_buffer_t *target)
{
	isc_region_t tr;
	dns_rdata_any_tsig_t *tsig;
	dns_compress_t cctx;

	REQUIRE(type == 250);
	REQUIRE(rdclass == 255);
	
	source = source;
	target = target;

	tsig = (dns_rdata_any_tsig_t *) source;
	REQUIRE(tsig->mctx != NULL);

	/* Algorithm Name */
	RETERR(dns_compress_init(&cctx, -1, tsig->mctx));
	dns_compress_setmethods(&cctx, DNS_COMPRESS_NONE);
	RETERR(dns_name_towire(&tsig->algorithm, &cctx, target));
	dns_compress_invalidate(&cctx);

	isc_buffer_available(target, &tr);
	if (tr.length < 6 + 2 + 2)
		return (DNS_R_NOSPACE);

	/* Time Signed: 48 bits */
	RETERR(uint16_tobuffer((isc_uint16_t)(tsig->timesigned >> 32),target));
	RETERR(uint32_tobuffer((isc_uint32_t)(tsig->timesigned & 0xffffffff),
			       target));

	/* Fudge */
	RETERR(uint16_tobuffer(tsig->fudge, target));

	/* Signature Size */
	RETERR(uint16_tobuffer(tsig->siglen, target));

	/* Signature */
	if (tsig->siglen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < tsig->siglen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, tsig->signature, tsig->siglen);
		isc_buffer_add(target, tsig->siglen);
	}

	isc_buffer_available(target, &tr);
	if (tr.length < 2 + 2 + 2)
		return (DNS_R_NOSPACE);

	/* Original ID */
	RETERR(uint16_tobuffer(tsig->originalid, target));

	/* Error */
	RETERR(uint16_tobuffer(tsig->error, target));

	/* Other Len */
	RETERR(uint16_tobuffer(tsig->otherlen, target));

	/* Other Data */
	if (tsig->otherlen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < tsig->otherlen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, tsig->other, tsig->otherlen);
		isc_buffer_add(target, tsig->otherlen);
	}

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
tostruct_any_tsig(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_any_tsig_t *tsig;
	dns_name_t alg;
	isc_region_t sr;

	REQUIRE(rdata->type == 250);
	REQUIRE(rdata->rdclass == 255);
	
	target = target;
	mctx = mctx;

	tsig = (dns_rdata_any_tsig_t *) target;
	tsig->common.rdclass = rdata->rdclass;
	tsig->common.rdtype = rdata->type;
	ISC_LINK_INIT(&tsig->common, link);
	tsig->mctx = mctx;
	dns_rdata_toregion(rdata, &sr);

	/* Algorithm Name */
	dns_name_init(&alg, NULL);
	dns_name_fromregion(&alg, &sr);
	dns_name_init(&tsig->algorithm, NULL);
	RETERR(dns_name_dup(&alg, mctx, &tsig->algorithm));
	
	isc_region_consume(&sr, name_length(&tsig->algorithm));

	/* Time Signed */
	if (sr.length < 6)
		return (ISC_R_UNEXPECTEDEND);
	tsig->timesigned = ((isc_uint64_t)sr.base[0] << 40) |
			   ((isc_uint64_t)sr.base[1] << 32) |
			   (sr.base[2] << 24) | (sr.base[3] << 16) |
			   (sr.base[4] << 8) | sr.base[5];
	isc_region_consume(&sr, 6);

	/* Fudge */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tsig->fudge = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Signature Size */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tsig->siglen = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Signature */
	if (tsig->siglen > 0) {
		if (sr.length < tsig->siglen)
			return (ISC_R_UNEXPECTEDEND);
		tsig->signature = isc_mem_get(mctx, tsig->siglen);
		if (tsig->signature == NULL)
			return (DNS_R_NOMEMORY);
		memcpy(tsig->signature, sr.base, tsig->siglen);
		isc_region_consume(&sr, tsig->siglen);
	}
	else
		tsig->signature = NULL;

	/* Original ID */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tsig->originalid = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Error */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tsig->error = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Other Size */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tsig->otherlen = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Other */
	if (tsig->otherlen > 0) {
		if (sr.length < tsig->otherlen)
			return (ISC_R_UNEXPECTEDEND);
		tsig->other = isc_mem_get(mctx, tsig->otherlen);
		if (tsig->other == NULL)
			return (DNS_R_NOMEMORY);
		memcpy(tsig->other, sr.base, tsig->otherlen);
		isc_region_consume(&sr, tsig->otherlen);
	}
	else
		tsig->other = NULL;

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_any_tsig(void *source) {
	dns_rdata_any_tsig_t *tsig = (dns_rdata_any_tsig_t *) source;

	REQUIRE(source != NULL);
	REQUIRE(tsig->common.rdclass == 255);
	REQUIRE(tsig->common.rdtype == 250);

	dns_name_free(&tsig->algorithm, tsig->mctx);	
	if (tsig->siglen > 0)
		isc_mem_put(tsig->mctx, tsig->signature, tsig->siglen);
	if (tsig->otherlen > 0)
		isc_mem_put(tsig->mctx, tsig->other, tsig->otherlen);
}

static inline isc_result_t
additionaldata_any_tsig(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
			void *arg)
{
	REQUIRE(rdata->type == 250);
	REQUIRE(rdata->rdclass == 255);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_any_tsig(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {

	REQUIRE(rdata->type == 250);
	REQUIRE(rdata->rdclass == 255);

	(void)digest;
	(void)arg;

	return (DNS_R_NOTIMPLEMENTED);
}


#endif	/* RDATA_ANY_255_TSIG_250_C */
