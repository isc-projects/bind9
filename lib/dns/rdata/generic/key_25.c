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

 /* $Id: key_25.c,v 1.16 2000/02/03 23:43:00 halley Exp $ */

 /* RFC 2065 */

#ifndef RDATA_GENERIC_KEY_25_C
#define RDATA_GENERIC_KEY_25_C

static inline isc_result_t
fromtext_key(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_lex_t *lexer, dns_name_t *origin,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_secalg_t alg;
	dns_secproto_t proto;
	dns_keyflags_t flags;

	REQUIRE(type == 25);

	rdclass = rdclass;	/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/

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
		return (DNS_R_SUCCESS);

	return (isc_base64_tobuffer(lexer, target, -1));
}

static inline isc_result_t
totext_key(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	   isc_buffer_t *target) 
{
	isc_region_t sr;
	char buf[sizeof "64000"];
	unsigned int flags;

	REQUIRE(rdata->type == 25);

	tctx = tctx;	/*unused*/

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
		return (DNS_R_SUCCESS);

	/* key */
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&sr, tctx->width - 2,
				 tctx->linebreak, target));
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" )", target));

	return DNS_R_SUCCESS;
}

static inline isc_result_t
fromwire_key(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	     isc_buffer_t *source, dns_decompress_t *dctx,
	     isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;

	REQUIRE(type == 25);
	
	rdclass = rdclass;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/

	isc_buffer_active(source, &sr);
	if (sr.length < 4)
		return (DNS_R_UNEXPECTEDEND);

	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_key(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;

	REQUIRE(rdata->type == 25);

	cctx = cctx;	/*unused*/

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
	dns_rdata_generic_key_t *key;
	isc_region_t tr;

	REQUIRE(type == 25);
	
	rdclass = rdclass;	/*unused*/

	source = source;
	target = target;

	key = (dns_rdata_generic_key_t *) source;
	REQUIRE(key->mctx != NULL);

	/* Flags */
	RETERR(uint16_tobuffer(key->flags, target));

	/* Protocol */
	RETERR(uint8_tobuffer(key->protocol, target));

	/* Algorithm */
	RETERR(uint8_tobuffer(key->algorithm, target));

	/* Data */
	if (key->datalen > 0) {
		isc_buffer_available(target, &tr);
		if (tr.length < key->datalen)
			return (DNS_R_NOSPACE);
		memcpy(tr.base, key->data, key->datalen);
		isc_buffer_add(target, key->datalen);
	}

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
tostruct_key(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	dns_rdata_generic_key_t *key;
	isc_region_t sr;

	REQUIRE(rdata->type == 25);
	
	target = target;
	mctx = mctx;

	key = (dns_rdata_generic_key_t *) target;
	key->common.rdclass = rdata->rdclass;
	key->common.rdtype = rdata->type;
	ISC_LINK_INIT(&key->common, link);
	key->mctx = mctx;
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
		key->data = isc_mem_get(mctx, key->datalen);
		if (key->data == NULL)
			return (DNS_R_NOMEMORY);
		memcpy(key->data, sr.base, key->datalen);
		isc_region_consume(&sr, key->datalen);
	}
	else
		key->data = NULL;

	return (DNS_R_SUCCESS);
}

static inline void
freestruct_key(void *source) {
	dns_rdata_generic_key_t *key = (dns_rdata_generic_key_t *) source;

	REQUIRE(source != NULL);
	REQUIRE(key->common.rdtype == 25);

	if (key->datalen > 0)
		isc_mem_put(key->mctx, key->data, key->datalen);
}

static inline isc_result_t
additionaldata_key(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		   void *arg)
{
	REQUIRE(rdata->type == 25);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_key(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r;

	REQUIRE(rdata->type == 25);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_KEY_25_C */
