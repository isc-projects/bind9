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

/* $Id: rp_17.c,v 1.17 2000/03/20 22:48:59 gson Exp $ */

/* RFC 1183 */

#ifndef RDATA_GENERIC_RP_17_C
#define RDATA_GENERIC_RP_17_C

static inline isc_result_t
fromtext_rp(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	    isc_lex_t *lexer, dns_name_t *origin,
	    isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	int i;

	UNUSED(rdclass);

	REQUIRE(type == 17);

	origin = (origin != NULL) ? origin : dns_rootname;

	for (i = 0; i < 2 ; i++) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));
		dns_name_init(&name, NULL);
		buffer_fromregion(&buffer, &token.value.as_region,
				  ISC_BUFFERTYPE_TEXT);
		RETERR(dns_name_fromtext(&name, &buffer, origin,
					 downcase, target));
	}
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
totext_rp(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	  isc_buffer_t *target) 
{
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 17);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	dns_name_fromregion(&email, &region);
	isc_region_consume(&region, email.length);

	sub = name_prefix(&rmail, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	RETERR(str_totext(" ", target));

	sub = name_prefix(&email, tctx->origin, &prefix);
	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_rp(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	    isc_buffer_t *source, dns_decompress_t *dctx,
	    isc_boolean_t downcase, isc_buffer_t *target)
{
        dns_name_t rmail;
        dns_name_t email;

	UNUSED(rdclass);
        
	REQUIRE(type == 17);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

        dns_name_init(&rmail, NULL);
        dns_name_init(&email, NULL);

        RETERR(dns_name_fromwire(&rmail, source, dctx, downcase, target));
        return (dns_name_fromwire(&email, source, dctx, downcase, target));
}

static inline isc_result_t
towire_rp(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target)
{
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;

	REQUIRE(rdata->type == 17);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	dns_name_init(&rmail, NULL);
	dns_name_init(&email, NULL);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return (dns_name_towire(&rmail, cctx, target));
}

static inline int
compare_rp(dns_rdata_t *rdata1, dns_rdata_t *rdata2)
{
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 17);

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

	return (dns_name_rdatacompare(&name1, &name2));
}

static inline isc_result_t
fromstruct_rp(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	      isc_buffer_t *target)
{
	UNUSED(rdclass);
	UNUSED(source);
	UNUSED(target);

	REQUIRE(type == 17);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_rp(dns_rdata_t *rdata, void *target, isc_mem_t *mctx)
{
	UNUSED(target);
	UNUSED(mctx);

	REQUIRE(rdata->type == 17);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_rp(void *source)
{
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_rp(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		  void *arg)
{
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == 17);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_rp(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg)
{
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == 17);

	dns_rdata_toregion(rdata, &r);
	dns_name_init(&name, NULL);

	dns_name_fromregion(&name, &r);
	RETERR(dns_name_digest(&name, digest, arg));
	isc_region_consume(&r, name_length(&name));

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);

	return (dns_name_digest(&name, digest, arg));
}

#endif	/* RDATA_GENERIC_RP_17_C */
