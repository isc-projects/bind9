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

 /* $Id: a6_38.c,v 1.20 2000/02/03 23:43:16 halley Exp $ */

 /* draft-ietf-ipngwg-dns-lookups-03.txt */

#ifndef RDATA_IN_1_A6_28_C
#define RDATA_IN_1_A6_28_C

#include <string.h>

#include <isc/net.h>

static inline isc_result_t
fromtext_in_a6(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	       isc_lex_t *lexer, dns_name_t *origin,
	       isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	unsigned char addr[16];
	unsigned char prefixlen;
	unsigned char octets;
	unsigned char mask;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == 38);
	REQUIRE(rdclass == 1);

	/* prefix length */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 128)
		return (DNS_R_RANGE);

	prefixlen = (unsigned char)token.value.as_ulong;
	RETERR(mem_tobuffer(target, &prefixlen, 1));

	/* suffix */
	if (prefixlen != 128) {
		/* prefix 0..127 */
		octets = prefixlen/8;
		/* octets 0..15 */
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));
		if (inet_pton(AF_INET6, token.value.as_pointer, addr) != 1)
			return (DNS_R_BADAAAA);
		mask = 0xff >> (prefixlen % 8);
		addr[octets] &= mask;
		RETERR(mem_tobuffer(target, &addr[octets], 16 - octets));
	}

	if (prefixlen == 0)
		return (DNS_R_SUCCESS);

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static inline isc_result_t
totext_in_a6(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	     isc_buffer_t *target) 
{
	isc_region_t tr;
	isc_region_t sr;
	unsigned char addr[16];
	unsigned char prefixlen;
	unsigned char octets;
	unsigned char mask;
	char buf[sizeof "128"];
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &sr);
	prefixlen = sr.base[0];
	INSIST(prefixlen <= 128);
	isc_region_consume(&sr, 1);
	sprintf(buf, "%u", prefixlen);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	if (prefixlen != 128) {
		octets = prefixlen/8;
		memset(addr, 0, sizeof addr);
		memcpy(&addr[octets], sr.base, 16 - octets);
		mask = 0xff >> (prefixlen % 8);
		addr[octets] &= mask;
		isc_buffer_available(target, &tr);
		if (inet_ntop(AF_INET6, addr,
			      (char *)tr.base, tr.length) == NULL)
			return (DNS_R_NOSPACE);

		isc_buffer_add(target, strlen((char *)tr.base));
		isc_region_consume(&sr, 16 - octets);
	}

	if (prefixlen == 0)
		return (DNS_R_SUCCESS);

	RETERR(str_totext(" ", target));
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_fromregion(&name, &sr);
	sub = name_prefix(&name, tctx->origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_in_a6(dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	unsigned char prefixlen;
	unsigned char octets;
	unsigned char mask;
	dns_name_t name;

	REQUIRE(type == 38);
	REQUIRE(rdclass == 1);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	isc_buffer_active(source, &sr);
	/* prefix length */
	if (sr.length < 1)
		return (DNS_R_UNEXPECTEDEND);
	prefixlen = sr.base[0];
	if (prefixlen > 128)
		return (DNS_R_RANGE);
	isc_region_consume(&sr, 1);
	RETERR(mem_tobuffer(target, &prefixlen, 1));
	isc_buffer_forward(source, 1);

	/* suffix */
	if (prefixlen != 128) {
		octets = 16 - prefixlen / 8;
		if (sr.length < octets)
			return (DNS_R_UNEXPECTEDEND);
		mask = 0xff >> (prefixlen % 8);
		sr.base[0] &= mask;	/* ensure pad bits are zero */
		RETERR(mem_tobuffer(target, sr.base, octets));
		isc_buffer_forward(source, octets);
	}

	if (prefixlen == 0)
		return (DNS_R_SUCCESS);

	dns_name_init(&name, NULL);
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static inline isc_result_t
towire_in_a6(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;
	unsigned char prefixlen;
	unsigned char octets;

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->rdclass == 1);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	dns_rdata_toregion(rdata, &sr);
	prefixlen = sr.base[0];
	INSIST(prefixlen <= 128);

	octets = 1 + 16 - prefixlen / 8;
	RETERR(mem_tobuffer(target, sr.base, octets));
	isc_region_consume(&sr, octets);

	if (prefixlen == 0)
		return (DNS_R_SUCCESS);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	return (dns_name_towire(&name, cctx, target));
}

static inline int
compare_in_a6(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	unsigned char prefixlen1, prefixlen2;
	unsigned char octets;
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 38);
	REQUIRE(rdata1->rdclass == 1);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);
	prefixlen1 = region1.base[0];
	prefixlen2 = region2.base[0];
	isc_region_consume(&region1, 1);
	isc_region_consume(&region2, 1);
	if (prefixlen1 < prefixlen2)
		return (-1);
	else if (prefixlen1 > prefixlen2)
		return (1);
	/*
	 * Prefix lengths are equal.
	 */
	octets = 16 - prefixlen1 / 8;

	if (octets > 0) {
		result = memcmp(region1.base, region2.base, octets);
		if (result < 0)
			return (-1);
		else if (result > 0)
			return (1);
		/*
		 * Address suffixes are equal.
		 */
		if (prefixlen1 == 0)
			return (result);
		isc_region_consume(&region1, octets);
		isc_region_consume(&region2, octets);
	}

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);
	return (dns_name_rdatacompare(&name1, &name2));
}

static inline isc_result_t
fromstruct_in_a6(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		 isc_buffer_t *target)
{
	dns_rdata_in_a6_t *a6 = source;
	unsigned char prefixlen;
	unsigned char octets;

	REQUIRE(type == 1);
	REQUIRE(rdclass == 1);
	REQUIRE(source != NULL);
	REQUIRE(a6->common.rdtype == type);
	REQUIRE(a6->common.rdclass == rdclass);

	if (a6->prefixlen > 128)
		return (DNS_R_RANGE);

	prefixlen = a6->prefixlen;
	RETERR(mem_tobuffer(target, &prefixlen, 1));

	if (a6->prefixlen != 128) {

	}

	octets = 16 - prefixlen / 8;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_in_a6(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->rdclass == 1);

	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_in_a6(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_in_a6(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		     void *arg)
{
	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->rdclass == 1);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_in_a6(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_region_t r1, r2;
	unsigned char prefixlen, octets;
	isc_result_t result;
	dns_name_t name;

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &r1);
	r2 = r1;
	prefixlen = r1.base[0];
	octets = 1 + 16 - prefixlen / 8;

	r1.length = octets;
	result = (digest)(arg, &r1);
	if (result != DNS_R_SUCCESS)
		return (result);
	if (prefixlen == 0)
		return (DNS_R_SUCCESS);

	isc_region_consume(&r2, octets);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r2);
	return (dns_name_digest(&name, digest, arg));
}

#endif	/* RDATA_IN_1_A6_38_C */
