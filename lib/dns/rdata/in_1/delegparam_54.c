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

#pragma once

#include <stdbool.h>

#include <isc/result.h>

#define RRTYPE_DELEGPARAM_ATTRIBUTES (DNS_RDATATYPEATTR_FOLLOWADDITIONAL)

static isc_result_t
fromtext_in_delegparam(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_delegparam);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromtext_in_deleg(CALL_FROMTEXT);
}

static isc_result_t
totext_in_delegparam(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_delegparam);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	return generic_totext_in_deleg(CALL_TOTEXT);
}

static isc_result_t
fromwire_in_delegparam(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_delegparam);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromwire_in_deleg(CALL_FROMWIRE);
}

static int
compare_in_delegparam(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_delegparam);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	return isc_region_compare(&region1, &region2);
}

static isc_result_t
fromstruct_in_delegparam(ARGS_FROMSTRUCT) {
	dns_rdata_in_delegparam_t *delegparam = source;

	REQUIRE(type == dns_rdatatype_delegparam);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(delegparam != NULL);
	REQUIRE(delegparam->common.rdtype == type);
	REQUIRE(delegparam->common.rdclass == rdclass);

	return generic_fromstruct_in_deleg(CALL_FROMSTRUCT);
}

static isc_result_t
tostruct_in_delegparam(ARGS_TOSTRUCT) {
	dns_rdata_in_delegparam_t *delegparam = target;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_delegparam);
	REQUIRE(delegparam != NULL);
	REQUIRE(rdata->length != 0);

	return generic_tostruct_in_deleg(CALL_TOSTRUCT);
}

static isc_result_t
additionaldata_in_delegparam(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_delegparam);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_in_delegparam(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_delegparam);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return (digest)(arg, &region1);
}

static bool
checkowner_in_delegparam(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_delegparam);
	REQUIRE(rdclass == dns_rdataclass_in);

	return true;
}

static bool
checknames_in_delegparam(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_delegparam);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return generic_checknames_in_deleg(CALL_CHECKNAMES);
}

static int
casecompare_in_delegparam(ARGS_COMPARE) {
	return compare_in_delegparam(rdata1, rdata2);
}

isc_result_t
dns_rdata_in_delegparam_first(dns_rdata_in_delegparam_t *delegparam) {
	REQUIRE(delegparam != NULL);
	REQUIRE(delegparam->common.rdtype == dns_rdatatype_delegparam);
	REQUIRE(delegparam->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_first(delegparam);
}

isc_result_t
dns_rdata_in_delegparam_next(dns_rdata_in_delegparam_t *delegparam) {
	REQUIRE(delegparam != NULL);
	REQUIRE(delegparam->common.rdtype == dns_rdatatype_delegparam);
	REQUIRE(delegparam->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_next(delegparam);
}

void
dns_rdata_in_delegparam_current(dns_rdata_in_delegparam_t *delegparam,
				isc_region_t *region) {
	REQUIRE(delegparam != NULL);
	REQUIRE(delegparam->common.rdtype == dns_rdatatype_delegparam);
	REQUIRE(delegparam->common.rdclass == dns_rdataclass_in);
	REQUIRE(region != NULL);

	generic_rdata_in_deleg_current(delegparam, region);
}
