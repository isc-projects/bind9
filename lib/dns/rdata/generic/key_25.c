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

/* $Id: key_25.c,v 1.25 2000/05/22 12:37:37 marka Exp $ */

/*
 * Reviewed: Wed Mar 15 16:47:10 PST 2000 by halley.
 */

/* RFC 2535 */

#ifndef RDATA_GENERIC_KEY_25_C
#define RDATA_GENERIC_KEY_25_C

#define RRTYPE_KEY_ATTRIBUTES (DNS_RDATATYPEATTR_DNSSEC)

static inline isc_result_t
fromtext_key(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_secalg_t alg;
	dns_secproto_t proto;
	dns_keyflags_t flags;

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(downcase);

	REQUIRE(type == 25);

	/* flags */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_keyflags_fromtext(&flags, &token.value.as_textregion));
	RETERR(uint16_tobuffer(flags, target));

	/* protocol */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_secproto_fromtext(&proto, &token.value.as_textregion));
	RETERR(mem_tobuffer(target, &proto, 1));

	/* algorithm */	
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	RETERR(dns_secalg_fromtext(&alg, &token.value.as_textregion));
	RETERR(mem_tobuffer(target, &alg, 1));
	
	/* No Key? */
	if ((flags & 0xc000) == 0xc000)
		return (ISC_R_SUCCESS);

	return (isc_base64_tobuffer(lexer, target, -1));
}

static inline isc_result_t
totext_key(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	   isc_buffer_t *target) 
{
	isc_region_t sr;
	char buf[sizeof "64000"];
	unsigned int flags;

	UNUSED(tctx);

	REQUIRE(rdata->type == 25);

	dns_rdata_toregion(rdata, &sr);

	/* flags */
	flags = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%u", flags);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* protocol */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* algorithm */
	sprintf(buf, "%u", sr.base[0]);
	isc_region_consume(&sr, 1);
	RETERR(str_totext(buf, target));

	/* No Key? */
	if ((flags & 0xc000) == 0xc00)
		return (ISC_R_SUCCESS);

	/* key */
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sr, tctx->width - 2,
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" )", target));

	return ISC_R_SUCCESS;
}

static inline isc_result_t
fromwire_key(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;

	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(downcase);

	REQUIRE(type == 25);

	isc_buffer_activeregion(source, &sr);
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);

	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_key(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;

	UNUSED(cctx);

	REQUIRE(rdata->type == 25);

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_key(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 25);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_key(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
	       isc_buffer_t *target)
{
	dns_rdata_key_t *key = source;

	REQUIRE(type == 25);
	REQUIRE(source != NULL);
	REQUIRE(key->common.rdtype == type);
	REQUIRE(key->common.rdclass == rdclass);

	/* Flags */
	RETERR(uint16_tobuffer(key->flags, target));

	/* Protocol */
	RETERR(uint8_tobuffer(key->protocol, target));

	/* Algorithm */
	RETERR(uint8_tobuffer(key->algorithm, target));

	/* Data */
	return (mem_tobuffer(target, key->data, key->datalen));
}

static inline isc_result_t
tostruct_key(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_key_t *key = target;
	isc_region_t sr;

	REQUIRE(rdata->type == 25);
	REQUIRE(target != NULL);

	key->common.rdclass = rdata->rdclass;
	key->common.rdtype = rdata->type;
	ISC_LINK_INIT(&key->common, link);

	dns_rdata_toregion(rdata, &sr);

	/* Flags */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	key->flags = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/* Protocol */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	key->flags = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);

	/* Algorithm */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	key->flags = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);

	/* Data */
	key->datalen = sr.length;
	if (key->datalen > 0) {
		key->data = mem_maybedup(mctx, sr.base, key->datalen);
		if (key->data == NULL)
			return (ISC_R_NOMEMORY);
	} else
		key->data = NULL;

	key->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_key(void *source) {
	dns_rdata_key_t *key = (dns_rdata_key_t *) source;

	REQUIRE(source != NULL);
	REQUIRE(key->common.rdtype == 25);

	if (key->mctx == NULL)
		return;

	if (key->data != NULL)
		isc_mem_free(key->mctx, key->data);
	key->mctx = NULL;
}

static inline isc_result_t
additionaldata_key(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	REQUIRE(rdata->type == 25);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_key(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 25);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_KEY_25_C */
