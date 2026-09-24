/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/types.h>

static unsigned int
name_length(const dns_name_t *name) {
	return name->length;
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	if (length == 0U) {
		return ISC_R_SUCCESS;
	}

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length) {
		return ISC_R_NOSPACE;
	}
	if (tr.base != base) {
		memmove(tr.base, base, length);
	}
	isc_buffer_add(target, length);
	return ISC_R_SUCCESS;
}

#define ARGS_TOWIRE \
	dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target

#define TOWIRE_NAME_REST ((unsigned int)-1)

static isc_result_t
towire_name(ARGS_TOWIRE, bool compress, unsigned int prefix_len,
	    unsigned int suffix_len) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, compress);
	dns_rdata_toregion(rdata, &region);
	REQUIRE(region.length >= prefix_len);

	RETERR(mem_tobuffer(target, region.base, prefix_len));
	isc_region_consume(&region, prefix_len);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	if (suffix_len == TOWIRE_NAME_REST) {
		suffix_len = region.length;
	} else {
		REQUIRE(region.length >= suffix_len);
	}
	return mem_tobuffer(target, region.base, suffix_len);
}

static isc_result_t
towire_minfo(ARGS_TOWIRE) {
	isc_region_t region;
	dns_name_t rmail;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&rmail);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, name_length(&rmail));

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return dns_name_towire(&rmail, cctx, target);
}

static isc_result_t
towire_naptr(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	/*
	 * Order, preference.
	 */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_region_consume(&sr, 4);

	/*
	 * Flags.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Service.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Regexp.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Replacement.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	return dns_name_towire(&name, cctx, target);
}

static isc_result_t
towire_rp(ARGS_TOWIRE) {
	isc_region_t region;
	dns_name_t rmail;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&rmail);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return dns_name_towire(&rmail, cctx, target);
}

static isc_result_t
towire_soa(ARGS_TOWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t mname;
	dns_name_t rname;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&mname);
	dns_name_init(&rname);

	dns_rdata_toregion(rdata, &sregion);

	dns_name_fromregion(&mname, &sregion);
	isc_region_consume(&sregion, name_length(&mname));
	RETERR(dns_name_towire(&mname, cctx, target));

	dns_name_fromregion(&rname, &sregion);
	isc_region_consume(&sregion, name_length(&rname));
	RETERR(dns_name_towire(&rname, cctx, target));

	isc_buffer_availableregion(target, &tregion);
	if (tregion.length < 20) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 20);
	isc_buffer_add(target, 20);
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_talink(ARGS_TOWIRE) {
	isc_region_t sregion;
	dns_name_t prev;
	dns_name_t next;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);

	dns_name_init(&prev);
	dns_name_init(&next);

	dns_rdata_toregion(rdata, &sregion);

	dns_name_fromregion(&prev, &sregion);
	isc_region_consume(&sregion, name_length(&prev));
	RETERR(dns_name_towire(&prev, cctx, target));

	dns_name_fromregion(&next, &sregion);
	isc_region_consume(&sregion, name_length(&next));
	return dns_name_towire(&next, cctx, target);
}

static isc_result_t
towire_in_a6(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;
	unsigned char prefixlen;
	unsigned char octets;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_rdata_toregion(rdata, &sr);
	prefixlen = sr.base[0];
	INSIST(prefixlen <= 128);

	octets = 1 + 16 - prefixlen / 8;
	RETERR(mem_tobuffer(target, sr.base, octets));
	isc_region_consume(&sr, octets);

	if (prefixlen == 0) {
		return ISC_R_SUCCESS;
	}

	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	return dns_name_towire(&name, cctx, target);
}

static isc_result_t
towire_in_px(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	/*
	 * Preference.
	 */
	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	/*
	 * MAP822.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&region, name_length(&name));

	/*
	 * MAPX400.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	return dns_name_towire(&name, cctx, target);
}

#define RDATA_KEY(rdclass, rdtype) \
	(((uint32_t)(rdclass) << 16) | (uint32_t)(rdtype))

isc_result_t
dns_rdata_towire(dns_rdata_t *rdata, dns_compress_t *cctx,
		 isc_buffer_t *target) {
	isc_result_t result;
	isc_buffer_t st;

	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	/*
	 * Some DynDNS meta-RRs have empty rdata.
	 */
	if ((rdata->flags & DNS_RDATA_UPDATE) != 0) {
		INSIST(rdata->length == 0);
		return ISC_R_SUCCESS;
	}

	st = *target;

	switch (RDATA_KEY(rdata->rdclass, rdata->type)) {
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_ns):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_md):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_mf):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_cname):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_soa):
		result = towire_soa(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_mb):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_mg):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_mr):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_ptr):
		result = towire_name(rdata, cctx, target, true, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_minfo):
		result = towire_minfo(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_mx):
		result = towire_name(rdata, cctx, target, true, 2, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_rp):
		result = towire_rp(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_afsdb):
		result = towire_name(rdata, cctx, target, false, 2, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_rt):
		result = towire_name(rdata, cctx, target, false, 2, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_nsap_ptr):
		result = towire_name(rdata, cctx, target, false, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_sig):
		result = towire_name(rdata, cctx, target, false, 18,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_px):
		result = towire_in_px(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_nxt):
		result = towire_name(rdata, cctx, target, false, 0,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_srv):
		result = towire_name(rdata, cctx, target, false, 6, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_naptr):
		result = towire_naptr(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_kx):
		result = towire_name(rdata, cctx, target, false, 2, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_a6):
		result = towire_in_a6(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_dname):
		result = towire_name(rdata, cctx, target, false, 0, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_rrsig):
		result = towire_name(rdata, cctx, target, false, 18,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_nsec):
		result = towire_name(rdata, cctx, target, false, 0,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_talink):
		result = towire_talink(rdata, cctx, target);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_svcb):
		result = towire_name(rdata, cctx, target, false, 2,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_https):
		result = towire_name(rdata, cctx, target, false, 2,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_dsync):
		result = towire_name(rdata, cctx, target, false, 5, 0);
		break;
	case RDATA_KEY(dns_rdataclass_in, dns_rdatatype_tkey):
		result = towire_name(rdata, cctx, target, false, 0,
				     TOWIRE_NAME_REST);
		break;
	case RDATA_KEY(dns_rdataclass_any, dns_rdatatype_tsig):
		result = towire_name(rdata, cctx, target, false, 0,
				     TOWIRE_NAME_REST);
		break;
	default:
		result = mem_tobuffer(target, rdata->data, rdata->length);
		break;
	}

	if (result != ISC_R_SUCCESS) {
		*target = st;
		dns_compress_rollback(cctx, target->used);
	}
	return result;
}
