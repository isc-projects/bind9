/*
 * Copyright (C) 1999 Internet Software Consortium.
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

 /* $Id: a6_38.h,v 1.1 1999/02/02 04:52:31 marka Exp $ */

 /* draft-ietf-ipngwg-dns-lookups-03.txt */

#ifndef RDATA_IN_1_A6_28_H
#define RDATA_IN_1_A6_28_H

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <isc/inet.h>

#ifndef MAX
#define MAX(A, B) ((A > B) ? (A) : (B))
#endif

static dns_result_t
fromtext_in_a6(dns_rdataclass_t class, dns_rdatatype_t type,
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
	REQUIRE(class == 1);

	/* prefix length */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 128)
		return (DNS_R_RANGE);

	prefixlen = token.value.as_ulong;
	RETERR(mem_tobuffer(target, &prefixlen, 1));

	/* suffix */
	if (prefixlen != 128) {
		/* prefix 0..127 */
		octets = prefixlen/8;
		/* octets 0..15 */
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				ISC_FALSE));
		if (isc_inet_pton(AF_INET6, token.value.as_pointer, &addr) != 1)
			return (DNS_R_UNEXPECTED);
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

static dns_result_t
totext_in_a6(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
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
	REQUIRE(rdata->class == 1);

	dns_rdata_toregion(rdata, &sr);
	prefixlen = sr.base[0];
	INSIST(prefixlen <= 128);
	isc_region_consume(&sr, 1);
	sprintf(buf, "%u", prefixlen);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	if (prefixlen != 128) {
		octets = prefixlen/8;
		memset(&addr, 0, sizeof addr);
		memcpy(&addr[octets], sr.base, 16 - octets);
		mask = 0xff >> (prefixlen % 8);
		addr[octets] &= mask;
		isc_buffer_available(target, &tr);
		if (isc_inet_ntop(AF_INET6, &addr,
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
	sub = name_prefix(&name, origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static dns_result_t
fromwire_in_a6(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target) {
	isc_region_t sr;
	unsigned char prefixlen;
	unsigned char octets;
	unsigned char mask;
	dns_name_t name;

	REQUIRE(type == 38);
	REQUIRE(class == 1);

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

static dns_result_t
towire_in_a6(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;
	dns_name_t name;
	unsigned char prefixlen;
	unsigned char octets;

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->class == 1);

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

static int
compare_in_a6(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	unsigned char prefixlen;
	unsigned char octets;
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 38);
	REQUIRE(rdata1->class == 1);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);
	prefixlen = MAX(region1.base[0], region2.base[0]);
	octets = 1 + 16 - prefixlen / 8;

	result = memcmp(region1.base, region2.base, octets);
	if (result != 0)
		result = (result < 0) ? -1 : 1;

	isc_region_consume(&region1, octets);
	isc_region_consume(&region2, octets);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);
	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);
	return (dns_name_compare(&name1, &name2));
}

static dns_result_t
fromstruct_in_a6(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 1);
	REQUIRE(class == 1);

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_in_a6(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 38);
	REQUIRE(rdata->class == 1);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_IN_1_A6_38_H */
