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

/* $Id: wks_11.c,v 1.22 2000/03/20 19:29:44 gson Exp $ */

/* Reviewed: Fri Mar 17 15:01:49 PST 2000 by explorer */

#ifndef RDATA_IN_1_WKS_11_C
#define RDATA_IN_1_WKS_11_C

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <isc/net.h>
#include <isc/netdb.h>

static inline isc_result_t
fromtext_in_wks(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		isc_lex_t *lexer, dns_name_t *origin,
		isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	isc_region_t region;
	struct in_addr addr;
	struct protoent *pe;
	struct servent *se;
	char *e;
	long proto;
	unsigned char bm[8*1024]; /* 64k bits */
	long port;
	long maxport = -1;
	char *ps = NULL;
	unsigned int n;

	UNUSED(origin);
	UNUSED(downcase);

	REQUIRE(type == 11);
	REQUIRE(rdclass == 1);
	
	/* IPv4 dotted quad */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));

	isc_buffer_available(target, &region);
	if (inet_aton(token.value.as_pointer, &addr) != 1)
		return (DNS_R_BADDOTTEDQUAD);
	if (region.length < 4)
		return (DNS_R_NOSPACE);
	memcpy(region.base, &addr, 4);
	isc_buffer_add(target, 4);

	/* protocol */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));

	proto = strtol(token.value.as_pointer, &e, 10);
	if (*e == 0)
		;
	else if ((pe = getprotobyname(token.value.as_pointer)) != NULL)
		proto = pe->p_proto;
	else
		return (DNS_R_UNEXPECTED);
	if (proto < 0 || proto > 0xff)
		return (DNS_R_RANGE);

	if (proto == IPPROTO_TCP)
		ps = "tcp";
	else if (proto == IPPROTO_UDP)
		ps = "udp";

	RETERR(uint8_tobuffer(proto, target));

	memset(bm, 0, sizeof bm);
	do {
		RETERR(gettoken(lexer, &token, isc_tokentype_string,
				  ISC_TRUE));
		if (token.type != isc_tokentype_string)
			break;
		port = strtol(token.value.as_pointer, &e, 10);
		if (*e == 0)
			;
		else if ((se = getservbyname(token.value.as_pointer, ps))
			  != NULL)
			port = ntohs(se->s_port);
		else
			return (DNS_R_UNEXPECTED);
		if (port < 0 || port > 0xffff)
			return (DNS_R_RANGE);
		if (port > maxport)
			maxport = port;
		bm[port / 8] |= (0x80 >> (port % 8));
	} while (1);

	/* Let upper layer handle eol/eof. */
	isc_lex_ungettoken(lexer, &token);

	n = (maxport + 8) / 8;
	return (mem_tobuffer(target, bm, n));
}

static inline isc_result_t
totext_in_wks(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
	      isc_buffer_t *target) 
{
	isc_region_t sr;
	isc_region_t tr;
	unsigned short proto;
	char buf[sizeof "65535"];
	unsigned int i, j;

	UNUSED(tctx);

	REQUIRE(rdata->type == 11);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &sr);
	isc_buffer_available(target, &tr);
	if (inet_ntop(AF_INET, sr.base, (char *)tr.base, tr.length) == NULL)
		return (DNS_R_NOSPACE);
	isc_buffer_add(target, strlen((char *)tr.base));
	isc_region_consume(&sr, 4);

	proto = uint8_fromregion(&sr);
	sprintf(buf, "%u", proto);
	RETERR(str_totext(" ", target));
	RETERR(str_totext(buf, target));
	isc_region_consume(&sr, 1);
	RETERR(str_totext(" (", target));

	for (i = 0 ; i < sr.length ; i++) {
		if (sr.base[i] != 0)
			for (j = 0 ; j < 8 ; j++)
				if ((sr.base[i] & (0x80 >> j)) != 0) {
					sprintf(buf, "%u", i * 8 + j);
					RETERR(str_totext(" ", target));
					RETERR(str_totext(buf, target));
				}
	}

	RETERR(str_totext(" )", target));
	return (DNS_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_wks(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		isc_buffer_t *source, dns_decompress_t *dctx,
		isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	isc_region_t tr;

	UNUSED(dctx);
	UNUSED(downcase);

	REQUIRE(type == 11);
	REQUIRE(rdclass == 1);

	isc_buffer_active(source, &sr);
	isc_buffer_available(target, &tr);

	if (sr.length < 5)
		return (DNS_R_UNEXPECTEDEND);
	if (sr.length > 8 * 1024 + 5)
		return (DNS_R_EXTRADATA);
	if (tr.length < sr.length)
		return (DNS_R_NOSPACE);

	memcpy(tr.base, sr.base, sr.length);
	isc_buffer_add(target, sr.length);
	isc_buffer_forward(source, sr.length);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
towire_in_wks(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target)
{
	isc_region_t sr;

	UNUSED(cctx);

	REQUIRE(rdata->type == 11);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_in_wks(dns_rdata_t *rdata1, dns_rdata_t *rdata2)
{
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 11);
	REQUIRE(rdata1->rdclass == 1);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static inline isc_result_t
fromstruct_in_wks(dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source,
		  isc_buffer_t *target)
{
	UNUSED(source);
	UNUSED(target);

	REQUIRE(type == 11);
	REQUIRE(rdclass == 1);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline isc_result_t
tostruct_in_wks(dns_rdata_t *rdata, void *target, isc_mem_t *mctx)
{
	UNUSED(target);
	UNUSED(mctx);

	REQUIRE(rdata->type == 11);
	REQUIRE(rdata->rdclass == 1);

	return (DNS_R_NOTIMPLEMENTED);
}

static inline void
freestruct_in_wks(void *source)
{
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);	/*XXX*/
}

static inline isc_result_t
additionaldata_in_wks(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
		      void *arg)
{
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == 11);
	REQUIRE(rdata->rdclass == 1);

	return (DNS_R_SUCCESS);
}

static inline isc_result_t
digest_in_wks(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg)
{
	isc_region_t r;

	REQUIRE(rdata->type == 11);
	REQUIRE(rdata->rdclass == 1);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

#endif	/* RDATA_IN_1_WKS_11_C */
