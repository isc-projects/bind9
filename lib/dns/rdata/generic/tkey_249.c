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

/* $Id: tkey_249.c,v 1.23 2000/03/20 22:44:35 gson Exp $ */

/*
 * Reviewed: Thu Mar 16 17:35:30 PST 2000 by halley.
 */

/* draft-ietf-dnsext-tkey-01.txt */

#ifndef RDATA_GENERIC_TKEY_249_C
#define RDATA_GENERIC_TKEY_249_C

static inline isc_result_t
fromtext_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_lex_t *lexer, dns_name_t *origin,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_rcode_t rcode;
	dns_name_t name;
	isc_buffer_t buffer;
	long i;
	char *e;

	UNUSED(rdclass);

	REQUIRE(type == 249);

	/* Algorithm */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETERR(dns_name_fromtext(&name, &buffer, origin, downcase, target));


	/* Inception */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Expiration */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Mode */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Error */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	if (dns_rcode_fromtext(&rcode, &token.value.as_textregion)
				!= DNS_R_SUCCESS) {
		i = strtol(token.value.as_pointer, &e, 10);
		if (*e != 0)
			return (DNS_R_UNKNOWN);
		if (i < 0 || i > 0xffff)
			return (DNS_R_RANGE);
		rcode = (dns_rcode_t)i;
	}
	RETERR(uint16_tobuffer(rcode, target));

	/* Key Size */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Key Data */
	RETERR(isc_base64_tobuffer(lexer, target, token.value.as_ulong));

	/* Other Size */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Other Data */
	return (isc_base64_tobuffer(lexer, target, token.value.as_ulong));
}

static inline isc_result_t
totext_tkey(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	    isc_buffer_t *target) 
{
	isc_region_t sr, dr;
	char buf[sizeof "4294967295 "];	
	unsigned long n;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 249);

	dns_rdata_toregion(rdata, &sr);

	/* Algorithm */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));
	RETERR(str_totext(" ", target));
	isc_region_consume(&sr, name_length(&name));

	/* Inception */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Expiration */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Mode */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Error */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	if (dns_rcode_totext((dns_rcode_t)n, target) == DNS_R_SUCCESS)
		RETERR(str_totext(" ", target));
	else {
		sprintf(buf, "%lu ", n);
		RETERR(str_totext(buf, target));
	}

	/* Key Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu", n);
	RETERR(str_totext(buf, target));

	/* Key Data */
	REQUIRE(n <= sr.length);
	dr = sr;
	dr.length = n;
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&dr, tctx->width - 2,
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" ) ", target));
	else
		RETERR(str_totext(" ", target));		
	isc_region_consume(&sr, n);

	/* Other Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu", n);
	RETERR(str_totext(buf, target));

	/* Other Data */
	REQUIRE(n <= sr.length);
	if (n != 0) {
	    dr = sr;
	    dr.length = n;
	    if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		    RETERR(str_totext(" (", target));
	    RETERR(str_totext(tctx->linebreak, target));
	    RETERR(isc_base64_totext(&dr, tctx->width - 2,
				     tctx->linebreak, target));
	    if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		    RETERR(str_totext(" )", target));
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_buffer_t *source, dns_decompress_t *dctx,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	unsigned long n;
	dns_name_t name;

	UNUSED(rdclass);

	REQUIRE(type == 249);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);
	
	/* Algorithm */
	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	/* 
	 * Inception: 4
	 * Expiration: 4
	 * Mode: 2
	 * Error: 2
	 */
	isc_buffer_active(source, &sr);
	if (sr.length < 12)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 12));
	isc_region_consume(&sr, 12);
	isc_buffer_forward(source, 12);

	/* Key Length + Key Data */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, n + 2));
	isc_region_consume(&sr, n + 2);
	isc_buffer_forward(source, n + 2);

	/* Other Length + Other Data */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	isc_buffer_forward(source, n + 2);
	return (mem_tobuffer(target, sr.base, n + 2));
}

static inline isc_result_t
towire_tkey(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == 249);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	/* Algorithm */
	dns_rdata_toregion(rdata, &sr);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&sr, name_length(&name));

	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_tkey(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;
	dns_name_t name1;
	dns_name_t name2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 249);
	
	/* Algorithm */
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_name_fromregion(&name1, &r1);
	dns_name_fromregion(&name2, &r2);
	if ((order = dns_name_rdatacompare(&name1, &name2)) != 0)
		return (order);
	isc_region_consume(&r1, name_length(&name1));
	isc_region_consume(&r2, name_length(&name2));
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_tkey(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		void *source, isc_buffer_t *target)
{
	isc_region_t tr;
	dns_rdata_generic_tkey_t *tkey;
	dns_compress_t cctx;

	UNUSED(rdclass);
	UNUSED(source);
	UNUSED(target);

	REQUIRE(type == 249);
	
	tkey = (dns_rdata_generic_tkey_t *) source;
	REQUIRE(tkey->mctx != NULL);

	/* Algorithm Name */
	RETERR(dns_compress_init(&cctx, -1, tkey->mctx));
	dns_compress_setmethods(&cctx, DNS_COMPRESS_NONE);
	RETERR(dns_name_towire(&tkey->algorithm, &cctx, target));
	dns_compress_invalidate(&cctx);

	/* Inception: 32 bits */
	RETERR(uint32_tobuffer(tkey->inception, target));

	/* Expire: 32 bits */
	RETERR(uint32_tobuffer(tkey->expire, target));

	/* Mode: 16 bits */
	RETERR(uint16_tobuffer(tkey->mode, target));

	/* Error: 16 bits */
	RETERR(uint16_tobuffer(tkey->error, target));

	/* Key size: 16 bits */
	RETERR(uint16_tobuffer(tkey->keylen, target));

	/* Key */
	if (tkey->keylen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < tkey->keylen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, tkey->key, tkey->keylen);
		isc_buffer_add(target, tkey->keylen);
	}

	/* Other size: 16 bits */
	RETERR(uint16_tobuffer(tkey->otherlen, target));

	/* Other data */
	if (tkey->otherlen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < tkey->otherlen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, tkey->other, tkey->otherlen);
		isc_buffer_add(target, tkey->otherlen);
	}

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
tostruct_tkey(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_generic_tkey_t *tkey;
	dns_name_t alg;
	isc_region_t sr;

	UNUSED(target);
	UNUSED(mctx);

	REQUIRE(rdata->type == 249);

	tkey = (dns_rdata_generic_tkey_t *) target;

	tkey->common.rdclass = rdata->rdclass;
	tkey->common.rdtype = rdata->type;
	ISC_LINK_INIT(&tkey->common, link);
	tkey->mctx = mctx;
	dns_rdata_toregion(rdata, &sr);

	/* Algorithm Name */
	dns_name_init(&alg, NULL);
	dns_name_fromregion(&alg, &sr);
	dns_name_init(&tkey->algorithm, NULL);
	RETERR(dns_name_dup(&alg, mctx, &tkey->algorithm));
	isc_region_consume(&sr, name_length(&tkey->algorithm));

	/* Inception */
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	tkey->inception = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	/* Expire */
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	tkey->expire = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);

	/* Mode */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tkey->mode = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Error */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tkey->error = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Key size */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tkey->keylen = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Key */
	tkey->key = isc_mem_get(mctx, tkey->keylen);
	if (tkey->key == NULL)
		return (DNS_R_NOMEMORY);
	memcpy(tkey->key, sr.base, tkey->keylen);
	isc_region_consume(&sr, tkey->keylen);

	/* Other size */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	tkey->otherlen = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Other */
	tkey->other = isc_mem_get(mctx, tkey->otherlen);
	if (tkey->other == NULL)
		return (DNS_R_NOMEMORY);
	memcpy(tkey->other, sr.base, tkey->otherlen);
	isc_region_consume(&sr, tkey->otherlen);

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_tkey(void *source) {
	dns_rdata_generic_tkey_t *tkey = (dns_rdata_generic_tkey_t *) source;

	REQUIRE(source != NULL);

	dns_name_free(&tkey->algorithm, tkey->mctx);
	if (tkey->key != NULL)
		isc_mem_put(tkey->mctx, tkey->key, tkey->keylen);
	if (tkey->other != NULL)
		isc_mem_put(tkey->mctx, tkey->other, tkey->otherlen);
}

static inline isc_result_t
additionaldata_tkey(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		    void *arg)
{
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == 249);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_tkey(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg)
{
	UNUSED(digest);
	UNUSED(arg);

	REQUIRE(rdata->type == 249);

	return (DNS_R_NOTIMPLEMENTED);
}

#endif	/* RDATA_GENERIC_TKEY_249_C */
