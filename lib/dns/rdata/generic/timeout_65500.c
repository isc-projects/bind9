/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* draft-pusateri-dnsop-update-timeout */

#include <isc/time.h>

#ifndef RDATA_GENERIC_TIMEOUT_C
#define RDATA_GENERIC_TIMEOUT_C

#define RRTYPE_TIMEOUT_ATTRIBUTES (0)

static inline isc_result_t
fromtext_timeout(ARGS_FROMTEXT) {
	isc_time_t isc_time;
	isc_token_t token;
	unsigned int count;
	unsigned int alg;
	unsigned int timeouts = 0;
	int64_t expire;

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	do {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_number, true));
		if (token.type == isc_tokentype_eol) {
			break;
		}
		if (token.value.as_ulong > 0xffffU) {
			RETTOK(ISC_R_RANGE);
		}
		count = token.value.as_ulong;
		RETERR(uint16_tobuffer(token.value.as_ulong, target));

		RETERR(isc_lex_getmastertoken(lexer, &token,
					       isc_tokentype_number, false));
		if (token.value.as_ulong > 0xffffU)
			RETTOK(ISC_R_RANGE);
		alg = token.value.as_ulong;
		RETERR(uint16_tobuffer(token.value.as_ulong, target));

		if (alg == 0 && count != 0) {
			RETTOK(DNS_R_SYNTAX);
		}

		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, false));
		RETERR(isc_time_ISO8601fromtext(&isc_time, DNS_AS_STR(token)));
		if (isc_time_nanoseconds(&isc_time) != 0) {
			RETTOK(DNS_R_SYNTAX);
		}
		expire = isc_time_seconds(&isc_time);
		RETERR(uint32_tobuffer((uint32_t)(expire >> 32), target));
		RETERR(uint32_tobuffer((uint32_t)(expire & 0xffffffffU),
				       target));

		while (count-- > 0) {
			switch (alg) {
			case 1:
				RETERR(isc_base64_tobuffer(lexer, target, 16));
				break;
			default:
				RETERR(ISC_R_NOTIMPLEMENTED);
			}
		}
		timeouts++;
	} while (1);

	return (timeouts > 0 ? ISC_R_SUCCESS : ISC_R_UNEXPECTEDEND);
}

static inline isc_result_t
totext_timeout(ARGS_TOTEXT) {
	isc_region_t sr;
	isc_time_t isc_time;
	unsigned int count;
	unsigned int alg;
	bool first = true;
	char buf[sizeof("yyyy-mm-ddTHH:MM:SSZ")];
	int64_t expire;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &sr);

	while (sr.length != 0) {
		count = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);
		snprintf(buf, sizeof(buf), "%u", count);
		RETERR(str_totext(buf, target));
		RETERR(str_totext(" ", target));

		alg = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);
		snprintf(buf, sizeof(buf), "%u", alg);
		RETERR(str_totext(buf, target));
		RETERR(str_totext(" ", target));

		if (alg > 1) {
			RETERR(ISC_R_NOTIMPLEMENTED);
		}

		expire = uint32_fromregion(&sr);
		expire <<= 32;
		expire += uint32_fromregion(&sr);
		isc_region_consume(&sr, 8);

		isc_time_set(&isc_time, expire, 0);
		isc_time_formatISO8601(&isc_time, buf, sizeof(buf));
		RETERR(str_totext(buf, target));
		RETERR(str_totext(" ", target));

		if (first && (count != 0 || sr.length != 0) &&
		    (tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0) {
			RETERR(str_totext(" (", target));
			RETERR(str_totext(tctx->linebreak, target));
			first = false;
		} else if (count != 0) {
			RETERR(str_totext(tctx->linebreak, target));
		}

		while (count-- != 0) {
			unsigned int length = sr.length;
			unsigned int hashlen = 0;
			switch (alg) {
			case 1:
				INSIST(sr.length >= 16);
				hashlen = 16;
				break;
			default:
				INSIST(0);
			}
			sr.length = hashlen;
			if (tctx->width == 0)   /* No splitting */
				RETERR(isc_base64_totext(&sr, 60, "", target));
			else
				RETERR(isc_base64_totext(&sr, tctx->width - 2,
							 tctx->linebreak,
							 target));
			if (count != 0) {
				RETERR(str_totext(tctx->linebreak, target));
			}
			sr.length = length;
			isc_region_consume(&sr, hashlen);
		}
		if (sr.length != 0) {
			RETERR(str_totext(tctx->linebreak, target));
		}
	}

	if (!first) {
		RETERR(str_totext(" )", target));
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_timeout(ARGS_FROMWIRE) {
	isc_region_t sr;
	unsigned int count;
	unsigned int alg;

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(options);

	/*
	 * There must be at least one timout block.
	 */
	isc_buffer_activeregion(source, &sr);
	if (sr.length < 12)
		return (ISC_R_UNEXPECTEDEND);

	while (sr.length != 0) {
		if (sr.length < 12) {
			return (ISC_R_UNEXPECTEDEND);
		}
		isc_buffer_forward(source, 8);
		RETERR(mem_tobuffer(target, sr.base, 8));

		count = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);

		alg = uint16_fromregion(&sr);
		isc_region_consume(&sr, 2);

		if (alg == 0 && count != 0) {
			return (DNS_R_FORMERR);
		}

		isc_region_consume(&sr, 8);

		while (count-- != 0) {
			unsigned int hashlen = 0;
			switch (alg) {
			case 1:
				hashlen = 16;
				break;
			default:
				return (ISC_R_NOTIMPLEMENTED);
			}
			if (sr.length < hashlen) {
				return (ISC_R_UNEXPECTEDEND);
			}
			RETERR(mem_tobuffer(target, sr.base, hashlen));
			isc_region_consume(&sr, hashlen);
		}
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_timeout(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline int
compare_timeout(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_timeout);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_timeout(ARGS_FROMSTRUCT) {
	dns_rdata_timeout_t *timeout = source;

	REQUIRE(timeout != NULL);
	REQUIRE(type == dns_rdatatype_timeout);
	REQUIRE(timeout->common.rdtype == type);
	REQUIRE(timeout->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	return (mem_tobuffer(target, timeout->data, timeout->length));
}

static inline isc_result_t
tostruct_timeout(ARGS_TOSTRUCT) {
	dns_rdata_timeout_t *timeout = target;
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);
	REQUIRE(rdata->length != 0);

	REQUIRE(timeout != NULL);
	REQUIRE(timeout->common.rdclass == rdata->rdclass);
	REQUIRE(timeout->common.rdtype == rdata->type);
	REQUIRE(!ISC_LINK_LINKED(&timeout->common, link));

	dns_rdata_toregion(rdata, &sr);

	timeout->length = sr.length;
	timeout->data = mem_maybedup(mctx, sr.base, timeout->length);
	if (timeout->data == NULL)
		return (ISC_R_NOMEMORY);

	timeout->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_timeout(ARGS_FREESTRUCT) {
	dns_rdata_timeout_t *timeout = (dns_rdata_timeout_t *) source;

	REQUIRE(timeout != NULL);
	REQUIRE(timeout->common.rdtype == dns_rdatatype_timeout);

	if (timeout->mctx == NULL)
		return;

	if (timeout->data != NULL)
		isc_mem_free(timeout->mctx, timeout->data);
	timeout->mctx = NULL;
}

static inline isc_result_t
additionaldata_timeout(ARGS_ADDLDATA) {

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_timeout(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

static inline bool
checkowner_timeout(ARGS_CHECKOWNER) {

	REQUIRE(type == dns_rdatatype_timeout);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
checknames_timeout(ARGS_CHECKNAMES) {

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_timeout);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (true);
}

static inline int
casecompare_timeout(ARGS_COMPARE) {
	return (compare_timeout(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_TIMEOUT_C */
