/*
 * Copyright (C) 1999-2002  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: nsec_47.c,v 1.2 2003/09/30 06:00:40 marka Exp $ */

/* reviewed: Wed Mar 15 18:21:15 PST 2000 by brister */

/* RFC 2535 */

#ifndef RDATA_GENERIC_NSEC_47_C
#define RDATA_GENERIC_NSEC_47_C

/*
 * The attributes do not include DNS_RDATATYPEATTR_SINGLETON
 * because we must be able to handle a parent/child NSEC pair.
 */
#define RRTYPE_NSEC_ATTRIBUTES (DNS_RDATATYPEATTR_DNSSEC)

static inline isc_result_t
fromtext_nsec(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	char *e;
	unsigned char bm[8*1024]; /* 64k bits */
	dns_rdatatype_t covered;
	dns_rdatatype_t maxcovered = 0;
	isc_boolean_t first = ISC_TRUE;
	long n;

	REQUIRE(type == 47);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/*
	 * Next domain.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	origin = (origin != NULL) ? origin : dns_rootname;
	RETTOK(dns_name_fromtext(&name, &buffer, origin, downcase, target));

	memset(bm, 0, sizeof(bm));
	do {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, ISC_TRUE));
		if (token.type != isc_tokentype_string)
			break;
		n = strtol(DNS_AS_STR(token), &e, 10);
		if (e != DNS_AS_STR(token) && *e == '\0') {
			covered = (dns_rdatatype_t)n;
		} else if (dns_rdatatype_fromtext(&covered,
				&token.value.as_textregion) == DNS_R_UNKNOWN)
			RETTOK(DNS_R_UNKNOWN);
		/*
		 * NSEC is only specified for types 1..127.
		 */
		if (covered < 1 || covered > 127)
			return (ISC_R_RANGE);
		if (first || covered > maxcovered)
			maxcovered = covered;
		first = ISC_FALSE;
		bm[covered/8] |= (0x80>>(covered%8));
	} while (1);
	isc_lex_ungettoken(lexer, &token);
	if (first)
		return (ISC_R_SUCCESS);
	n = (maxcovered + 8) / 8;
	return (mem_tobuffer(target, bm, n));
}

static inline isc_result_t
totext_nsec(ARGS_TOTEXT) {
	isc_region_t sr;
	unsigned int i, j;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == 47);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	for (i = 0; i < sr.length; i++) {
		if (sr.base[i] != 0)
			for (j = 0; j < 8; j++)
				if ((sr.base[i] & (0x80 >> j)) != 0) {
					dns_rdatatype_t t = i * 8 + j;
					RETERR(str_totext(" ", target));
					if (dns_rdatatype_isknown(t)) {
						RETERR(dns_rdatatype_totext(t,
								      target));
					} else {
						char buf[sizeof("65535")];
						sprintf(buf, "%u", t);
						RETERR(str_totext(buf,
								  target));
					}
				}
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_nsec(ARGS_FROMWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(type == 47);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	dns_name_init(&name, NULL);
	RETERR(dns_name_fromwire(&name, source, dctx, downcase, target));

	isc_buffer_activeregion(source, &sr);
	/* XXXRTH  Enforce RFC 2535 length rules if bit 0 is not set. */
	if (sr.length > 8 * 1024)
		return (DNS_R_EXTRADATA);
	RETERR(mem_tobuffer(target, sr.base, sr.length));
	isc_buffer_forward(source, sr.length);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_nsec(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;
	dns_offsets_t offsets;

	REQUIRE(rdata->type == 47);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);
	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_nsec(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 47);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_nsec(ARGS_FROMSTRUCT) {
	dns_rdata_nsec_t *nsec = source;
	isc_region_t region;

	REQUIRE(type == 47);
	REQUIRE(source != NULL);
	REQUIRE(nsec->common.rdtype == type);
	REQUIRE(nsec->common.rdclass == rdclass);
	REQUIRE(nsec->typebits != NULL || nsec->len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&nsec->next, &region);
	RETERR(isc_buffer_copyregion(target, &region));

	return (mem_tobuffer(target, nsec->typebits, nsec->len));
}

static inline isc_result_t
tostruct_nsec(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_nsec_t *nsec = target;
	dns_name_t name;

	REQUIRE(rdata->type == 47);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	nsec->common.rdclass = rdata->rdclass;
	nsec->common.rdtype = rdata->type;
	ISC_LINK_INIT(&nsec->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	dns_name_init(&nsec->next, NULL);
	RETERR(name_duporclone(&name, mctx, &nsec->next));

	nsec->len = region.length;
	nsec->typebits = mem_maybedup(mctx, region.base, region.length);
	if (nsec->typebits == NULL)
		goto cleanup;

	nsec->mctx = mctx;
	return (ISC_R_SUCCESS);

 cleanup:
	if (mctx != NULL)
		dns_name_free(&nsec->next, mctx);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_nsec(ARGS_FREESTRUCT) {
	dns_rdata_nsec_t *nsec = source;

	REQUIRE(source != NULL);
	REQUIRE(nsec->common.rdtype == 47);

	if (nsec->mctx == NULL)
		return;

	dns_name_free(&nsec->next, nsec->mctx);
	if (nsec->typebits != NULL)
		isc_mem_free(nsec->mctx, nsec->typebits);
	nsec->mctx = NULL;
}

static inline isc_result_t
additionaldata_nsec(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == 47);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_nsec(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == 47);

	dns_rdata_toregion(rdata, &r);
	return ((digest)(arg, &r));
}

#endif	/* RDATA_GENERIC_NSEC_47_C */
