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

/* $Id: sig_24.c,v 1.30 2000/03/17 21:43:46 gson Exp $ */

/* Reviewed: Fri Mar 17 09:05:02 PST 2000 by gson */

/* RFC 2535 */

#ifndef RDATA_GENERIC_SIG_24_C
#define RDATA_GENERIC_SIG_24_C

static inline isc_result_t
fromtext_sig(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	unsigned char c; 
	long i;
	dns_rdatatype_t covered;
	char *e;
	isc_result_t result;
	dns_name_t name;
	isc_buffer_t buffer;
	isc_uint32_t time_signed, time_expire;

	REQUIRE(type == 24);

	UNUSED(rdclass);

	/* type covered */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	result = dns_rdatatype_fromtext(&covered, &token.value.as_textregion);
	if (result != DNS_R_SUCCESS && result != DNS_R_NOTIMPLEMENTED) {
		i = strtol(token.value.as_pointer, &e, 10);
		if (i < 0 || i > 65535)
			return (DNS_R_RANGE);
		if (*e != 0)
			return (result);
		covered = (dns_rdatatype_t)i;
	}
	RETERR(uint16_tobuffer(covered, target));

	/* algorithm */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_secalg_fromtext(&c, &token.value.as_textregion));
	RETERR(mem_tobuffer(target, &c, 1));

	/* labels */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xff)
		return (DNS_R_RANGE);
	c = (unsigned char)token.value.as_ulong;
	RETERR(mem_tobuffer(target, &c, 1));

	/* original ttl */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* signature expiration */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_time32_fromtext(token.value.as_pointer, &time_expire));
	RETERR(uint32_tobuffer(time_expire, target));

	/* time signed */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_time32_fromtext(token.value.as_pointer, &time_signed));
	RETERR(uint32_tobuffer(time_signed, target));

	/* key footprint */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));
	
	/* signer */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	/* sig */
	return (isc_base64_tobuffer(lexer, target, -1));
}

static inline isc_result_t
totext_sig(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	      isc_buffer_t *target) 
{
	isc_region_t sr;
	char buf[sizeof "4294967295"];
	dns_rdatatype_t covered;
	unsigned long ttl;
	unsigned long when;
	unsigned long exp;
	unsigned long foot;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 24);

	dns_rdata_toregion(rdata, &sr);

	/* type covered */
	covered = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	RETERR(dns_rdatatype_totext(covered, target));
	RETERR(str_totext(" ", target));

	/* algorithm */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* labels */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* ttl */
	ttl = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu", ttl); 
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* sig exp */
	exp = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	RETERR(dns_time32_totext(exp, target));

	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));

	/* time signed */
	when = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	RETERR(dns_time32_totext(when, target));
	RETERR(str_totext(" ", target));

	/* footprint */
	foot = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu", foot); 
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* signer */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	/* sig */
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sr, tctx->width - 2,
				    tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" )", target));
	
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_sig(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(type == 24);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);
	
	UNUSED(rdclass);

	isc_buffer_active(source, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	if (sr.length < 18)
		return (DNS_R_UNEXPECTEDEND);

	isc_buffer_forward(source, 18);
	RETERR(mem_tobuffer(target, sr.base, 18));

	/* signer */
	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	/* sig */
	isc_buffer_active(source, &sr);
	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_sig(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 24);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	dns_rdata_toregion(rdata, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	RETERR(mem_tobuffer(target, sr.base, 18));
	isc_region_consume(&sr, 18);

	/* signer */
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));        
	RETERR(dns_name_towire(&name, cctx, target));

	/* signature */
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_sig(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 24);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);

	INSIST(r1.length > 18);
	INSIST(r2.length > 18);
	r1.length = 18;
	r2.length = 18;
	order = compare_region(&r1, &r2);
	if (order != 0)
		return (order);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	isc_region_consume(&r1, 18);
	isc_region_consume(&r2, 18);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0)
		return (order);

	isc_region_consume(&r1, name_length(&name1));
	isc_region_consume(&r2, name_length(&name2));

	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_sig(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	       isc_buffer_t *target)
{
	isc_region_t tr;
	dns_rdata_generic_sig_t *sig;
	dns_compress_t cctx;

	REQUIRE(type == 24);
	
	UNUSED(rdclass);

	sig = (dns_rdata_generic_sig_t *) source;
	REQUIRE(sig->mctx != NULL);

	/* Type covered */
	RETERR(uint16_tobuffer(sig->covered, target));

	/* Algorithm */
	RETERR(uint8_tobuffer(sig->algorithm, target));

	/* Labels */
	RETERR(uint8_tobuffer(sig->labels, target));

	/* Original TTL */
	RETERR(uint32_tobuffer(sig->originalttl, target));

	/* Expire time */
	RETERR(uint32_tobuffer(sig->timeexpire, target));

	/* Time signed */
	RETERR(uint32_tobuffer(sig->timesigned, target));

	/* Key ID */
	RETERR(uint16_tobuffer(sig->keyid, target));

	/* Signer name */
	RETERR(dns_compress_init(&cctx, -1, sig->mctx));
	dns_compress_setmethods(&cctx, DNS_COMPRESS_NONE);
	RETERR(dns_name_towire(&sig->signer, &cctx, target));
	dns_compress_invalidate(&cctx);

	/* Signature */
	if (sig->siglen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < sig->siglen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, sig->signature, sig->siglen);
		isc_buffer_add(target, sig->siglen);
	}

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
tostruct_sig(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	isc_region_t sr;
	dns_rdata_generic_sig_t *sig;
	dns_name_t signer;

	REQUIRE(rdata->type == 24);
	
	sig = (dns_rdata_generic_sig_t *) target;
	sig->common.rdclass = rdata->rdclass;
	sig->common.rdtype = rdata->type;
	ISC_LINK_INIT(&sig->common, link);
	sig->mctx = mctx;
	dns_rdata_toregion(rdata, &sr);

	/* Type covered */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	sig->covered = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Algorithm */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	sig->algorithm = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);

	/* Labels */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	sig->labels = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);

	/* Original TTL */
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	sig->originalttl = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	/* Expire time */
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	sig->timeexpire = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	/* Time signed */
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	sig->timesigned = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	/* Key ID */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	sig->keyid = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	dns_name_init(&signer, NULL);
	dns_name_fromregion(&signer, &sr);
	dns_name_init(&sig->signer, NULL);
	RETERR(dns_name_dup(&signer, mctx, &sig->signer));
	isc_region_consume(&sr, name_length(&sig->signer));

	/* Signature */
	sig->siglen = sr.length;
	sig->signature = isc_mem_get(mctx, sig->siglen);
	if (sig->signature == NULL)
		return (DNS_R_NOMEMORY);
	memcpy(sig->signature, sr.base, sig->siglen);
	isc_region_consume(&sr, sig->siglen);

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_sig(void *source) {
	dns_rdata_generic_sig_t *sig = (dns_rdata_generic_sig_t *) source;

	REQUIRE(source != NULL);
	REQUIRE(sig->common.rdtype == 24);

	dns_name_free(&sig->signer, sig->mctx);
	if (sig->signature != NULL)
		isc_mem_put(sig->mctx, sig->signature, sig->siglen);
}

static inline isc_result_t
additionaldata_sig(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	REQUIRE(rdata->type == 24);

	UNUSED(add);
	UNUSED(arg);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_sig(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {

	REQUIRE(rdata->type == 24);

	UNUSED(digest);
	UNUSED(arg);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline dns_rdatatype_t
covers_sig(dns_rdata_t *rdata) {
	dns_rdatatype_t type;
	isc_region_t r;

	REQUIRE(rdata->type == 24);

	dns_rdata_toregion(rdata, &r);
	type = uint16_fromregion(&r);

	return (type);
}

#endif	/* RDATA_GENERIC_SIG_24_C */
