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

#include <dns/name.h>
#include <dns/compress.h>
#include <dns/rdata.h>

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


#define CALL_TOWIRE rdata, cctx, target

#define ARGS_TOWIRE \
	dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target

static isc_result_t
generic_towire_in_svcb(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);

	/*
	 * SvcPriority.
	 */
	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	/*
	 * TargetName.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&region, name_length(&name));

	/*
	 * SvcParams.
	 */
	return mem_tobuffer(target, region.base, region.length);
}

static isc_result_t
towire_any_tsig(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_tsig);
	REQUIRE(rdata->rdclass == dns_rdataclass_any);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_rdata_toregion(rdata, &sr);
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&sr, name_length(&name));
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_afsdb(ARGS_TOWIRE) {
	isc_region_t tr;
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_afsdb);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	isc_buffer_availableregion(target, &tr);
	dns_rdata_toregion(rdata, &sr);
	if (tr.length < 2) {
		return ISC_R_NOSPACE;
	}
	memmove(tr.base, sr.base, 2);
	isc_region_consume(&sr, 2);
	isc_buffer_add(target, 2);

	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_amtrelay(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_amtrelay);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_avc(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_avc);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_brid(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_brid);
	REQUIRE(rdata->length > 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_caa(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_caa);
	REQUIRE(rdata->length >= 3U);
	REQUIRE(rdata->data != NULL);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_cdnskey(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_cdnskey);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_cds(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_cds);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_cert(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_cert);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_cname(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_cname);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_csync(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(rdata->length >= 6);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_dlv(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_dlv);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_dname(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_dname);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_dnskey(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_dnskey);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_doa(ARGS_TOWIRE) {
	isc_region_t region;

	UNUSED(cctx);

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_doa);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_ds(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_ds);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_dsync(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_dsync);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);

	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 5));
	isc_region_consume(&region, 5);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_eui48(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_eui48);
	REQUIRE(rdata->length == 6);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_eui64(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_eui64);
	REQUIRE(rdata->length == 8);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_gpos(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_gpos);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_hhit(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_hhit);
	REQUIRE(rdata->length > 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_hinfo(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_hinfo);
	REQUIRE(rdata->length != 0);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_hip(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_hip);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_ipseckey(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_ipseckey);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_isdn(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_isdn);
	REQUIRE(rdata->length != 0);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_key(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_key);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_keydata(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_keydata);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_l32(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_l32);
	REQUIRE(rdata->length == 6);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_l64(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_l64);
	REQUIRE(rdata->length == 10);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_loc(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_loc);
	REQUIRE(rdata->length != 0);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_lp(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_lp);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_mb(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mb);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_md(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_md);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_mf(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_mg(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mg);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_minfo(ARGS_TOWIRE) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;

	REQUIRE(rdata->type == dns_rdatatype_minfo);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&rmail);
	dns_name_init(&email);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, name_length(&rmail));

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return dns_name_towire(&rmail, cctx, target);
}


static isc_result_t
towire_mr(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mr);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_mx(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mx);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_naptr(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_naptr);
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
towire_nid(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_nid);
	REQUIRE(rdata->length == 10);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_ninfo(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_ninfo);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_ns(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_ns);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_nsec3(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_nsec3);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_nsec3param(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_nsec3param);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_nsec(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_nsec);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&name);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_null(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_null);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_nxt(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_nxt);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&name);
	dns_rdata_toregion(rdata, &sr);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_openpgpkey(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_openpgpkey);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_opt(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_opt);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_ptr(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_ptr);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_resinfo(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_resinfo);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_rkey(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_rkey);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_rp(ARGS_TOWIRE) {
	isc_region_t region;
	dns_name_t rmail;
	dns_name_t email;

	REQUIRE(rdata->type == dns_rdatatype_rp);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&rmail);
	dns_name_init(&email);

	dns_rdata_toregion(rdata, &region);

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	RETERR(dns_name_towire(&rmail, cctx, target));

	dns_name_fromregion(&rmail, &region);
	isc_region_consume(&region, rmail.length);

	return dns_name_towire(&rmail, cctx, target);
}


static isc_result_t
towire_rrsig(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_rrsig);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_rdata_toregion(rdata, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	RETERR(mem_tobuffer(target, sr.base, 18));
	isc_region_consume(&sr, 18);

	/*
	 * Signer.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	/*
	 * Signature.
	 */
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_rt(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;
	isc_region_t tr;

	REQUIRE(rdata->type == dns_rdatatype_rt);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	isc_buffer_availableregion(target, &tr);
	dns_rdata_toregion(rdata, &region);
	if (tr.length < 2) {
		return ISC_R_NOSPACE;
	}
	memmove(tr.base, region.base, 2);
	isc_region_consume(&region, 2);
	isc_buffer_add(target, 2);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_sig(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_sig);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_rdata_toregion(rdata, &sr);
	/*
	 * type covered: 2
	 * algorithm: 1
	 * labels: 1
	 * original ttl: 4
	 * signature expiration: 4
	 * time signed: 4
	 * key footprint: 2
	 */
	RETERR(mem_tobuffer(target, sr.base, 18));
	isc_region_consume(&sr, 18);

	/*
	 * Signer.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	isc_region_consume(&sr, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	/*
	 * Signature.
	 */
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_sink(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_sink);
	REQUIRE(rdata->length >= 3);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_smimea(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_smimea);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_soa(ARGS_TOWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t mname;
	dns_name_t rname;

	REQUIRE(rdata->type == dns_rdatatype_soa);
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
towire_spf(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_spf);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_sshfp(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_sshfp);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_ta(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_ta);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_talink(ARGS_TOWIRE) {
	isc_region_t sregion;
	dns_name_t prev;
	dns_name_t next;

	REQUIRE(rdata->type == dns_rdatatype_talink);
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
towire_tkey(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_tkey);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	/*
	 * Algorithm.
	 */
	dns_rdata_toregion(rdata, &sr);
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&sr, name_length(&name));

	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_tlsa(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_tlsa);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_txt(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_txt);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_uri(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_uri);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}


static isc_result_t
towire_wallet(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_wallet);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_x25(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_x25);
	REQUIRE(rdata->length != 0);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_zonemd(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_zonemd);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_in_a6(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_name_t name;
	unsigned char prefixlen;
	unsigned char octets;

	REQUIRE(rdata->type == dns_rdatatype_a6);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
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
towire_in_a(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length == 4);

	UNUSED(cctx);

	isc_buffer_availableregion(target, &region);
	if (region.length < rdata->length) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}


static isc_result_t
towire_in_aaaa(ARGS_TOWIRE) {
	isc_region_t region;

	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_aaaa);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length == 16);

	isc_buffer_availableregion(target, &region);
	if (region.length < rdata->length) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 16);
	return ISC_R_SUCCESS;
}


static isc_result_t
towire_in_apl(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_apl);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_in_atma(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_atma);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_in_dhcid(ARGS_TOWIRE) {
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_dhcid);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}


static isc_result_t
towire_in_eid(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_eid);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_in_https(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_https);
	REQUIRE(rdata->length != 0);

	return generic_towire_in_svcb(CALL_TOWIRE);
}


static isc_result_t
towire_in_kx(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_kx);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_in_nimloc(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_nimloc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_in_nsap_ptr(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_nsap_ptr);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_in_nsap(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}


static isc_result_t
towire_in_px(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_px);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
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


static isc_result_t
towire_in_srv(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_srv);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	/*
	 * Priority, weight, port.
	 */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 6));
	isc_region_consume(&sr, 6);

	/*
	 * Target.
	 */
	dns_name_init(&name);
	dns_name_fromregion(&name, &sr);
	return dns_name_towire(&name, cctx, target);
}


static isc_result_t
towire_in_svcb(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->length != 0);

	return generic_towire_in_svcb(CALL_TOWIRE);
}


static isc_result_t
towire_in_wks(ARGS_TOWIRE) {
	isc_region_t sr;

	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_wks);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &sr);
	return mem_tobuffer(target, sr.base, sr.length);
}

#define TOWIRESWITCH \
	switch (rdata->type) { \
	case 1: switch (rdata->rdclass) { \
		case 1: result = towire_in_a(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 2: result = towire_ns(rdata, cctx, target); break; \
	case 3: result = towire_md(rdata, cctx, target); break; \
	case 4: result = towire_mf(rdata, cctx, target); break; \
	case 5: result = towire_cname(rdata, cctx, target); break; \
	case 6: result = towire_soa(rdata, cctx, target); break; \
	case 7: result = towire_mb(rdata, cctx, target); break; \
	case 8: result = towire_mg(rdata, cctx, target); break; \
	case 9: result = towire_mr(rdata, cctx, target); break; \
	case 10: result = towire_null(rdata, cctx, target); break; \
	case 11: switch (rdata->rdclass) { \
		case 1: result = towire_in_wks(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 12: result = towire_ptr(rdata, cctx, target); break; \
	case 13: result = towire_hinfo(rdata, cctx, target); break; \
	case 14: result = towire_minfo(rdata, cctx, target); break; \
	case 15: result = towire_mx(rdata, cctx, target); break; \
	case 16: result = towire_txt(rdata, cctx, target); break; \
	case 17: result = towire_rp(rdata, cctx, target); break; \
	case 18: result = towire_afsdb(rdata, cctx, target); break; \
	case 19: result = towire_x25(rdata, cctx, target); break; \
	case 20: result = towire_isdn(rdata, cctx, target); break; \
	case 21: result = towire_rt(rdata, cctx, target); break; \
	case 22: switch (rdata->rdclass) { \
		case 1: result = towire_in_nsap(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 23: switch (rdata->rdclass) { \
		case 1: result = towire_in_nsap_ptr(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 24: result = towire_sig(rdata, cctx, target); break; \
	case 25: result = towire_key(rdata, cctx, target); break; \
	case 26: switch (rdata->rdclass) { \
		case 1: result = towire_in_px(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 27: result = towire_gpos(rdata, cctx, target); break; \
	case 28: switch (rdata->rdclass) { \
		case 1: result = towire_in_aaaa(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 29: result = towire_loc(rdata, cctx, target); break; \
	case 30: result = towire_nxt(rdata, cctx, target); break; \
	case 31: switch (rdata->rdclass) { \
		case 1: result = towire_in_eid(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 32: switch (rdata->rdclass) { \
		case 1: result = towire_in_nimloc(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 33: switch (rdata->rdclass) { \
		case 1: result = towire_in_srv(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 34: switch (rdata->rdclass) { \
		case 1: result = towire_in_atma(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 35: result = towire_naptr(rdata, cctx, target); break; \
	case 36: switch (rdata->rdclass) { \
		case 1: result = towire_in_kx(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 37: result = towire_cert(rdata, cctx, target); break; \
	case 38: switch (rdata->rdclass) { \
		case 1: result = towire_in_a6(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 39: result = towire_dname(rdata, cctx, target); break; \
	case 40: result = towire_sink(rdata, cctx, target); break; \
	case 41: result = towire_opt(rdata, cctx, target); break; \
	case 42: switch (rdata->rdclass) { \
		case 1: result = towire_in_apl(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 43: result = towire_ds(rdata, cctx, target); break; \
	case 44: result = towire_sshfp(rdata, cctx, target); break; \
	case 45: result = towire_ipseckey(rdata, cctx, target); break; \
	case 46: result = towire_rrsig(rdata, cctx, target); break; \
	case 47: result = towire_nsec(rdata, cctx, target); break; \
	case 48: result = towire_dnskey(rdata, cctx, target); break; \
	case 49: switch (rdata->rdclass) { \
		case 1: result = towire_in_dhcid(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 50: result = towire_nsec3(rdata, cctx, target); break; \
	case 51: result = towire_nsec3param(rdata, cctx, target); break; \
	case 52: result = towire_tlsa(rdata, cctx, target); break; \
	case 53: result = towire_smimea(rdata, cctx, target); break; \
	case 55: result = towire_hip(rdata, cctx, target); break; \
	case 56: result = towire_ninfo(rdata, cctx, target); break; \
	case 57: result = towire_rkey(rdata, cctx, target); break; \
	case 58: result = towire_talink(rdata, cctx, target); break; \
	case 59: result = towire_cds(rdata, cctx, target); break; \
	case 60: result = towire_cdnskey(rdata, cctx, target); break; \
	case 61: result = towire_openpgpkey(rdata, cctx, target); break; \
	case 62: result = towire_csync(rdata, cctx, target); break; \
	case 63: result = towire_zonemd(rdata, cctx, target); break; \
	case 64: switch (rdata->rdclass) { \
		case 1: result = towire_in_svcb(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 65: switch (rdata->rdclass) { \
		case 1: result = towire_in_https(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 66: result = towire_dsync(rdata, cctx, target); break; \
	case 67: result = towire_hhit(rdata, cctx, target); break; \
	case 68: result = towire_brid(rdata, cctx, target); break; \
	case 99: result = towire_spf(rdata, cctx, target); break; \
	case 104: result = towire_nid(rdata, cctx, target); break; \
	case 105: result = towire_l32(rdata, cctx, target); break; \
	case 106: result = towire_l64(rdata, cctx, target); break; \
	case 107: result = towire_lp(rdata, cctx, target); break; \
	case 108: result = towire_eui48(rdata, cctx, target); break; \
	case 109: result = towire_eui64(rdata, cctx, target); break; \
	case 249: result = towire_tkey(rdata, cctx, target); break; \
	case 250: switch (rdata->rdclass) { \
		case 255: result = towire_any_tsig(rdata, cctx, target); break; \
		default: use_default = true; break; \
		} \
		break; \
	case 256: result = towire_uri(rdata, cctx, target); break; \
	case 257: result = towire_caa(rdata, cctx, target); break; \
	case 258: result = towire_avc(rdata, cctx, target); break; \
	case 259: result = towire_doa(rdata, cctx, target); break; \
	case 260: result = towire_amtrelay(rdata, cctx, target); break; \
	case 261: result = towire_resinfo(rdata, cctx, target); break; \
	case 262: result = towire_wallet(rdata, cctx, target); break; \
	case 32768: result = towire_ta(rdata, cctx, target); break; \
	case 32769: result = towire_dlv(rdata, cctx, target); break; \
	case 65533: result = towire_keydata(rdata, cctx, target); break; \
	default: use_default = true; break; \
	}

isc_result_t
dns_rdata_towire(dns_rdata_t *rdata, dns_compress_t *cctx,
		 isc_buffer_t *target) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;
	isc_region_t tr;
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

	TOWIRESWITCH

	if (use_default) {
		isc_buffer_availableregion(target, &tr);
		if (tr.length < rdata->length) {
			return ISC_R_NOSPACE;
		}
		memmove(tr.base, rdata->data, rdata->length);
		isc_buffer_add(target, rdata->length);
		return ISC_R_SUCCESS;
	}
	if (result != ISC_R_SUCCESS) {
		*target = st;
		dns_compress_rollback(cctx, target->used);
	}
	return result;
}
