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

/* $Id: soa_6.c,v 1.30 2000/03/18 00:19:25 explorer Exp $ */

/* Reviewed: Thu Mar 16 15:18:32 PST 2000 by explorer */

#ifndef RDATA_GENERIC_SOA_6_C
#define RDATA_GENERIC_SOA_6_C

static inline isc_result_t
fromtext_soa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	int i;
	isc_uint32_t n;

	UNUSED(rdclass);

	REQUIRE(type == 6);

	origin = (origin != NULL) ? origin : dns_rootname;

	for (i = 0 ; i < 2 ; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));

		dns_name_init(&name, NULL);
		buffer_fromregion(&buffer, &token.value.as_region,
				  ISC_BUFFERTYPE_TEXT);
		RETERR(dns_name_fromtext(&name, &buffer, origin,
					 downcase, target));
	}

	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	for (i = 0; i < 4; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));
		RETERR(dns_counter_fromtext(&token.value.as_textregion, &n));
		RETERR(uint32_tobuffer(n, target));
	}

	return (DNS_R_SUCCESS);
}

static char *soa_fieldnames[5] = {
	"serial", "refresh", "retry", "expire", "minimum"
};

static inline isc_result_t
totext_soa(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	   isc_buffer_t *target) 
{
	isc_region_t dregion;
	dns_name_t mname;
	dns_name_t rname;
	dns_name_t prefix;
	isc_boolean_t sub;
	int i;

	REQUIRE(rdata->type == 6);

	dns_name_init(&mname, NULL);
	dns_name_init(&rname, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &dregion);

	dns_name_fromregion(&mname, &dregion);
	isc_region_consume(&dregion, name_length(&mname));

	dns_name_fromregion(&rname, &dregion);
	isc_region_consume(&dregion, name_length(&rname));

	sub = name_prefix(&mname, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));
	
	RETERR(str_totext(" ", target));

	sub = name_prefix(&rname, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	RETERR(str_totext(" (" , target));
	RETERR(str_totext(tctx->linebreak, target));

	for (i = 0; i < 5 ; i++) {
		char buf[sizeof "2147483647"];
		unsigned long num;
		unsigned int numlen;
		num = uint32_fromregion(&dregion);
		isc_region_consume(&dregion, 4);
		numlen = sprintf(buf, "%lu", num);
		INSIST(numlen > 0 && numlen < sizeof "2147483647");
		RETERR(str_totext(buf, target));
		if ((tctx->flags & (DNS_STYLEFLAG_MULTILINE |
				    DNS_STYLEFLAG_COMMENT)) ==
				   (DNS_STYLEFLAG_MULTILINE |
				    DNS_STYLEFLAG_COMMENT)) {
			RETERR(str_totext("           ; " + numlen, target));
			RETERR(str_totext(soa_fieldnames[i], target));
			/* Print times in week/day/hour/minute/second form */
			if (i >= 1) {
				RETERR(str_totext(" (", target));
				RETERR(dns_ttl_totext(num, ISC_TRUE, target));
				RETERR(str_totext(")", target));
			}
			RETERR(str_totext(tctx->linebreak, target));
		} else {
			RETERR(str_totext(" ", target));
		}
	}

	RETERR(str_totext(")", target));

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_soa(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
        dns_name_t mname;
        dns_name_t rname;
	isc_region_t sregion;
	isc_region_t tregion;

	UNUSED(rdclass);
       
	REQUIRE(type == 6);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

        dns_name_init(&mname, NULL);
        dns_name_init(&rname, NULL);

        RETERR(dns_name_fromwire(&mname, source, dctx, downcase, target));
        RETERR(dns_name_fromwire(&rname, source, dctx, downcase, target));

	isc_buffer_active(source, &sregion);
	isc_buffer_available(target, &tregion);

	if (sregion.length < 20)
		return (DNS_R_UNEXPECTEDEND);
	if (tregion.length < 20)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 20);
	isc_buffer_forward(source, 20);
	isc_buffer_add(target, 20);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_soa(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target)
{
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t mname;
	dns_name_t rname;

	REQUIRE(rdata->type == 6);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&mname, NULL);
	dns_name_init(&rname, NULL);

	dns_rdata_toregion(rdata, &sregion);

	dns_name_fromregion(&mname, &sregion);
	isc_region_consume(&sregion, name_length(&mname));
	RETERR(dns_name_towire(&mname, cctx, target));

	dns_name_fromregion(&rname, &sregion);
	isc_region_consume(&sregion, name_length(&rname));
	RETERR(dns_name_towire(&rname, cctx, target));

	isc_buffer_available(target, &tregion);
	if (tregion.length < 20)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, 20);
	isc_buffer_add(target, 20);
	return (DNS_R_SUCCESS);
}

static inline int
compare_soa(dns_rdata_t *rdata1, dns_rdata_t *rdata2)
{
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 6);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0)
		return (order);

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0)
		return (order);

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	return (compare_region(&region1, &region2));
}

static inline isc_result_t
fromstruct_soa(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	       isc_buffer_t *target)
{
	UNUSED(rdclass);
	UNUSED(source);
	UNUSED(target);

	REQUIRE(type == 6);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_soa(dns_rdata_t *rdata, void *target, isc_mem_t *mctx)
{
	isc_region_t region;
	dns_rdata_soa_t *soa = target;
	dns_name_t name;

	REQUIRE(rdata->type == 6);
	REQUIRE(target != NULL);

	soa->common.rdclass = rdata->rdclass;
	soa->common.rdtype = rdata->type;
	ISC_LINK_INIT(&soa->common, link);

	soa->mctx = mctx;

	dns_rdata_toregion(rdata, &region);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	dns_name_init(&soa->origin, NULL);
	RETERR(dns_name_dup(&name, soa->mctx, &soa->origin));

	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	dns_name_init(&soa->mname, NULL);
	RETERR(dns_name_dup(&name, soa->mctx, &soa->mname));

	soa->serial = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->refresh = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->retry = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->expire = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->minimum = uint32_fromregion(&region);

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_soa(void *source)
{
	dns_rdata_soa_t *soa = source;

	REQUIRE(source != NULL);
	REQUIRE(soa->common.rdtype == 6);

	dns_name_free(&soa->origin, soa->mctx);
	dns_name_free(&soa->mname, soa->mctx);
	soa->mctx = NULL;
}

static inline isc_result_t
additionaldata_soa(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == 6);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_soa(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg)
{
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == 6);

	dns_rdata_toregion(rdata, &r);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);
	RETERR(dns_name_digest(&name, digest, arg));
	isc_region_consume(&r, name_length(&name));

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);
	RETERR(dns_name_digest(&name, digest, arg));
	isc_region_consume(&r, name_length(&name));

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_SOA_6_C */
