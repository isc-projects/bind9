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

#ifndef RDATA_GENERIC_ANAME_65532_C
#define RDATA_GENERIC_ANAME_65532_C

#define RRTYPE_ANAME_ATTRIBUTES \
	(DNS_RDATATYPEATTR_EXCLUSIVE | DNS_RDATATYPEATTR_SINGLETON)

static inline isc_result_t
fromtext_aname(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == dns_rdatatype_aname);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      ISC_FALSE));

	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL)
		origin = dns_rootname;
	RETTOK(dns_name_fromtext(&name, &buffer, origin, options, target));
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_aname(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == dns_rdatatype_aname);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	sub = name_prefix(&name, tctx->origin, &prefix);

	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_aname(ARGS_FROMWIRE) {
	dns_name_t name;

	REQUIRE(type == dns_rdatatype_aname);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, NULL);
	return (dns_name_fromwire(&name, source, dctx, options, target));
}

static inline isc_result_t
towire_aname(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_aname);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return (dns_name_towire(&name, cctx, target));
}

static inline int
compare_aname(ARGS_COMPARE) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_aname);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_rdatacompare(&name1, &name2));
}

static inline isc_result_t
fromstruct_aname(ARGS_FROMSTRUCT) {
	dns_rdata_aname_t *aname = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_aname);
	REQUIRE(source != NULL);
	REQUIRE(aname->common.rdtype == type);
	REQUIRE(aname->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&aname->target, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t
tostruct_aname(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_aname_t *aname = target;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_aname);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	aname->common.rdclass = rdata->rdclass;
	aname->common.rdtype = rdata->type;
	ISC_LINK_INIT(&aname->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);
	dns_name_init(&aname->target, NULL);
	RETERR(name_duporclone(&name, mctx, &aname->target));
	aname->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_aname(ARGS_FREESTRUCT) {
	dns_rdata_aname_t *aname = source;

	REQUIRE(source != NULL);

	if (aname->mctx == NULL)
		return;

	dns_name_free(&aname->target, aname->mctx);
	aname->mctx = NULL;
}

static inline isc_result_t
additionaldata_aname(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_aname);

	return ((add)(arg, dns_rootname, dns_rdatatype_aname));
}

static inline isc_result_t
digest_aname(ARGS_DIGEST) {
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_aname);

	dns_rdata_toregion(rdata, &r);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);

	return (dns_name_digest(&name, digest, arg));
}

static inline isc_boolean_t
checkowner_aname(ARGS_CHECKOWNER) {

	REQUIRE(type == dns_rdatatype_aname);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (ISC_TRUE);
}

static inline isc_boolean_t
checknames_aname(ARGS_CHECKNAMES) {

	REQUIRE(rdata->type == dns_rdatatype_aname);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (ISC_TRUE);
}

static inline int
casecompare_aname(ARGS_COMPARE) {
	return (compare_aname(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_ANAME_65532_C */
