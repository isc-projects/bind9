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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/rdatavec.h>

#include <tests/dns.h>
#include <tests/isc.h>

/* Helper function to create a vecheader directly */
static isc_result_t
create_vecheader(isc_mem_t *mctx, dns_rdatatype_t type,
		 dns_rdataclass_t rdclass, dns_ttl_t ttl,
		 const char *rdata_text, dns_vecheader_t **headerp) {
	dns_rdataset_t rdataset;
	dns_rdatalist_t *rdatalist;
	dns_rdata_t *rdata;
	unsigned char *data;
	isc_region_t region;
	isc_result_t result;

	/* Allocate temporary structures */
	data = isc_mem_get(mctx, 256);
	rdatalist = isc_mem_get(mctx, sizeof(*rdatalist));
	rdata = isc_mem_get(mctx, sizeof(*rdata));

	/* Initialize rdataset and rdatalist */
	dns_rdataset_init(&rdataset);
	dns_rdatalist_init(rdatalist);
	rdatalist->type = type;
	rdatalist->rdclass = rdclass;
	rdatalist->ttl = ttl;

	/* Create rdata */
	dns_rdata_init(rdata);
	CHECK(dns_test_rdatafromstring(rdata, rdclass, type, data, 256,
				       rdata_text, false));

	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdatalist_tordataset(rdatalist, &rdataset);

	/* Convert to vecheader */
	CHECK(dns_rdatavec_fromrdataset(&rdataset, mctx, &region, 0));
	*headerp = (dns_vecheader_t *)region.base;

	/* Cleanup rdataset */
	dns_rdataset_disassociate(&rdataset);

cleanup:
	/* Cleanup temporary structures */
	isc_mem_put(mctx, rdata, sizeof(*rdata));
	isc_mem_put(mctx, rdatalist, sizeof(*rdatalist));
	isc_mem_put(mctx, data, 256);

	return result;
}

/* Helper function to create an rdataset from a vecheader */
static void
create_rdataset_from_vecheader(dns_vecheader_t *header,
			       dns_rdataclass_t rdclass, dns_rdatatype_t type,
			       dns_rdataset_t *rdataset) {
	dns_rdataset_init(rdataset);
	rdataset->methods = &dns_rdatavec_rdatasetmethods;
	rdataset->rdclass = rdclass;
	rdataset->type = type;
	rdataset->vec.header = header;
}

/* Test merging two headers */
ISC_RUN_TEST_IMPL(merge_headers) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header1 = NULL, *header2 = NULL, *merged_header = NULL;
	unsigned int size1, size2, merged_size, expected_size;
	unsigned int count1, count2, merged_count, expected_count;
	isc_result_t result;

	/* Create vecheaders with A records */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header1));

	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.2", &header2));

	/* Get sizes and counts before merging */
	size1 = dns_rdatavec_size(header1);
	size2 = dns_rdatavec_size(header2);
	count1 = dns_rdatavec_count(header1);
	count2 = dns_rdatavec_count(header2);

	/* Merge headers */
	CHECK(dns_rdatavec_merge(header1, header2, mctx, dns_rdataclass_in,
				 dns_rdatatype_a, 0, 0, &merged_header));
	assert_non_null(merged_header);

	/* Get merged size and count */
	merged_size = dns_rdatavec_size(merged_header);
	merged_count = dns_rdatavec_count(merged_header);

	/* Test: merged size should be first_size + second_size - sizeof(header)
	 * - count_field_size */
	expected_size = size1 + size2 - sizeof(dns_vecheader_t) - 2;
	assert_int_equal(merged_size, expected_size);

	/* Test: merged count should be first_count + second_count */
	expected_count = count1 + count2;
	assert_int_equal(merged_count, expected_count);

cleanup:
	/* Cleanup */
	if (header1 != NULL) {
		size1 = dns_rdatavec_size(header1);
		isc_mem_put(mctx, header1, size1);
	}
	if (header2 != NULL) {
		size2 = dns_rdatavec_size(header2);
		isc_mem_put(mctx, header2, size2);
	}
	if (merged_header != NULL) {
		merged_size = dns_rdatavec_size(merged_header);
		isc_mem_put(mctx, merged_header, merged_size);
	}
}

/* Test case preservation during merge */
ISC_RUN_TEST_IMPL(merge_case_preservation) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header1 = NULL, *header2 = NULL, *merged_header = NULL;
	dns_fixedname_t fname1, fname2, fmerged_name;
	dns_name_t *name1 = dns_fixedname_initname(&fname1);
	dns_name_t *name2 = dns_fixedname_initname(&fname2);
	dns_name_t *merged_name = dns_fixedname_initname(&fmerged_name);
	unsigned int size1, size2, merged_size;
	isc_result_t result;

	dns_test_namefromstring("Example.COM", &fname1);
	dns_test_namefromstring("example.com", &fname2);

	/* Create vecheaders */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header1));

	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.2", &header2));

	/* Set case on first header */
	dns_vecheader_setownercase(header1, name1);

	/* Set case on second header */
	dns_vecheader_setownercase(header2, name2);

	/* Merge headers */
	CHECK(dns_rdatavec_merge(header1, header2, mctx, dns_rdataclass_in,
				 dns_rdatatype_a, 0, 0, &merged_header));
	assert_non_null(merged_header);

	/* Test: case should be the same as the first header */
	/* Copy the name for testing */
	dns_name_copy(name1, merged_name);

	/* Create a test rdataset from merged header to test case */
	dns_rdataset_t test_rdataset;
	create_rdataset_from_vecheader(merged_header, dns_rdataclass_in,
				       dns_rdatatype_a, &test_rdataset);

	/* Apply case from merged header */
	dns_rdataset_getownercase(&test_rdataset, merged_name);

	/* The case should match the original first name */
	assert_true(dns_name_caseequal(name1, merged_name));

cleanup:
	/* Cleanup */
	if (header1 != NULL) {
		size1 = dns_rdatavec_size(header1);
		isc_mem_put(mctx, header1, size1);
	}
	if (header2 != NULL) {
		size2 = dns_rdatavec_size(header2);
		isc_mem_put(mctx, header2, size2);
	}
	if (merged_header != NULL) {
		merged_size = dns_rdatavec_size(merged_header);
		isc_mem_put(mctx, merged_header, merged_size);
	}
}

/* Test size consistency after setting case */
ISC_RUN_TEST_IMPL(setcase_size_consistency) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header = NULL;
	dns_fixedname_t fname, flower_fname, fretrieved_fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_name_t *lower_name = dns_fixedname_initname(&flower_fname);
	dns_name_t *retrieved_name = dns_fixedname_initname(&fretrieved_fname);
	unsigned int original_size, cased_size;
	dns_rdataset_t test_rdataset;
	isc_result_t result;

	/* Initialize name */
	dns_test_namefromstring("Example.COM", &fname);

	/* Create vecheader */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header));

	/* Get original size */
	original_size = dns_rdatavec_size(header);

	/* Set case */
	dns_vecheader_setownercase(header, name);

	/* Get size after setting case */
	cased_size = dns_rdatavec_size(header);

	/* Test: size should be the same after setting case */
	assert_int_equal(cased_size, original_size);

	/* Create lowercase version of the original name */
	dns_test_namefromstring("example.com", &flower_fname);

	/* Copy lowercase name to retrieved_name for testing */
	dns_name_copy(lower_name, retrieved_name);

	/* Create a test rdataset from cased header */
	create_rdataset_from_vecheader(header, dns_rdataclass_in,
				       dns_rdatatype_a, &test_rdataset);

	/* Apply case from cased header to retrieved_name */
	dns_rdataset_getownercase(&test_rdataset, retrieved_name);

	/* Test: retrieved case should match the original mixed case */
	assert_true(dns_name_caseequal(name, retrieved_name));

cleanup:
	/* Cleanup */
	if (header != NULL) {
		cased_size = dns_rdatavec_size(header);
		isc_mem_put(mctx, header, cased_size);
	}
}

/* Test case where dns_rdatavec_subtract causes assertion failure */
ISC_RUN_TEST_IMPL(rdatavec_subtract_assertion_failure) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *original_header = NULL, *subtract_header = NULL,
			*result_header = NULL;
	dns_rdataset_t original_rdataset, subtract_rdataset;
	dns_rdatalist_t *original_rdatalist = NULL, *subtract_rdatalist = NULL;
	dns_rdata_t *original_rdata1 = NULL, *original_rdata2 = NULL,
		    *subtract_rdata = NULL;
	unsigned char *original_data1 = NULL, *original_data2 = NULL,
		      *subtract_data = NULL;
	isc_region_t original_region, subtract_region;
	isc_result_t result;

	/* Allocate temporary structures for original rdatalist with 2 records
	 */
	original_data1 = isc_mem_get(mctx, 256);
	original_data2 = isc_mem_get(mctx, 256);
	original_rdatalist = isc_mem_get(mctx, sizeof(*original_rdatalist));
	original_rdata1 = isc_mem_get(mctx, sizeof(*original_rdata1));
	original_rdata2 = isc_mem_get(mctx, sizeof(*original_rdata2));

	/* Allocate temporary structures for subtract rdatalist with 1 record */
	subtract_data = isc_mem_get(mctx, 256);
	subtract_rdatalist = isc_mem_get(mctx, sizeof(*subtract_rdatalist));
	subtract_rdata = isc_mem_get(mctx, sizeof(*subtract_rdata));

	/*
	 * Both rdatasets are inspected by the cleanup path below, so they
	 * have to be initialized before the first CHECK() can jump there.
	 */
	dns_rdataset_init(&original_rdataset);
	dns_rdataset_init(&subtract_rdataset);

	/* Initialize original rdatalist with 2 A records */
	dns_rdatalist_init(original_rdatalist);
	original_rdatalist->type = dns_rdatatype_a;
	original_rdatalist->rdclass = dns_rdataclass_in;
	original_rdatalist->ttl = 300;

	/* Create first rdata: 192.168.1.1 */
	dns_rdata_init(original_rdata1);
	CHECK(dns_test_rdatafromstring(original_rdata1, dns_rdataclass_in,
				       dns_rdatatype_a, original_data1, 256,
				       "192.168.1.1", false));
	ISC_LIST_APPEND(original_rdatalist->rdata, original_rdata1, link);

	/* Create second rdata: 192.168.1.2 */
	dns_rdata_init(original_rdata2);
	CHECK(dns_test_rdatafromstring(original_rdata2, dns_rdataclass_in,
				       dns_rdatatype_a, original_data2, 256,
				       "192.168.1.2", false));
	ISC_LIST_APPEND(original_rdatalist->rdata, original_rdata2, link);

	dns_rdatalist_tordataset(original_rdatalist, &original_rdataset);

	/* Initialize subtract rdatalist with 1 A record */
	dns_rdatalist_init(subtract_rdatalist);
	subtract_rdatalist->type = dns_rdatatype_a;
	subtract_rdatalist->rdclass = dns_rdataclass_in;
	subtract_rdatalist->ttl = 300;

	/* Create subtract rdata: 192.168.1.1 (same as first record) */
	dns_rdata_init(subtract_rdata);
	CHECK(dns_test_rdatafromstring(subtract_rdata, dns_rdataclass_in,
				       dns_rdatatype_a, subtract_data, 256,
				       "192.168.1.1", false));
	ISC_LIST_APPEND(subtract_rdatalist->rdata, subtract_rdata, link);

	dns_rdatalist_tordataset(subtract_rdatalist, &subtract_rdataset);

	/* Convert to vecheaders (each starts with refcount = 1) */
	CHECK(dns_rdatavec_fromrdataset(&original_rdataset, mctx,
					&original_region, 0));
	original_header = (dns_vecheader_t *)original_region.base;

	CHECK(dns_rdatavec_fromrdataset(&subtract_rdataset, mctx,
					&subtract_region, 0));
	subtract_header = (dns_vecheader_t *)subtract_region.base;

	/*
	 * This should cause assertion failure because dns_rdatavec_subtract()
	 * copies the original header (including its mctx) with memmove(), then
	 * tries to call isc_mem_attach() on the already-attached mctx field.
	 * Since we're subtracting 1 record from 2, it should create a new
	 * header and hit the problematic code path at rdatavec.c:759
	 */
	result = dns_rdatavec_subtract(original_header, subtract_header, mctx,
				       dns_rdataclass_in, dns_rdatatype_a, 0,
				       &result_header);

	/* If we get here without assertion failure, the bug has been fixed */
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(result_header);

	/* Result should contain only the second record (192.168.1.2) */
	unsigned int result_count = dns_rdatavec_count(result_header);
	assert_int_equal(result_count, 1);

cleanup:
	/* Cleanup rdatasets */
	if (DNS_RDATASET_VALID(&original_rdataset)) {
		dns_rdataset_disassociate(&original_rdataset);
	}
	if (DNS_RDATASET_VALID(&subtract_rdataset)) {
		dns_rdataset_disassociate(&subtract_rdataset);
	}

	/* Cleanup vecheaders */
	if (original_header != NULL) {
		dns_vecheader_unref(original_header);
	}
	if (subtract_header != NULL) {
		dns_vecheader_unref(subtract_header);
	}
	if (result_header != NULL) {
		dns_vecheader_unref(result_header);
	}

	/* Cleanup temporary structures for original */
	if (original_rdata1 != NULL) {
		isc_mem_put(mctx, original_rdata1, sizeof(*original_rdata1));
	}
	if (original_rdata2 != NULL) {
		isc_mem_put(mctx, original_rdata2, sizeof(*original_rdata2));
	}
	if (original_rdatalist != NULL) {
		isc_mem_put(mctx, original_rdatalist,
			    sizeof(*original_rdatalist));
	}
	if (original_data1 != NULL) {
		isc_mem_put(mctx, original_data1, 256);
	}
	if (original_data2 != NULL) {
		isc_mem_put(mctx, original_data2, 256);
	}

	/* Cleanup temporary structures for subtract */
	if (subtract_rdata != NULL) {
		isc_mem_put(mctx, subtract_rdata, sizeof(*subtract_rdata));
	}
	if (subtract_rdatalist != NULL) {
		isc_mem_put(mctx, subtract_rdatalist,
			    sizeof(*subtract_rdatalist));
	}
	if (subtract_data != NULL) {
		isc_mem_put(mctx, subtract_data, 256);
	}
}

/* Test refcount functionality with merge and cleanup */
ISC_RUN_TEST_IMPL(rdatavec_refcount_merge) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header1 = NULL, *header2 = NULL, *merged_header = NULL;
	dns_rdataset_t rdataset1, rdataset2;
	dns_rdatalist_t *rdatalist1 = NULL, *rdatalist2 = NULL;
	dns_rdata_t *rdata1 = NULL, *rdata2 = NULL;
	unsigned char *data1 = NULL, *data2 = NULL;
	isc_region_t region1, region2;
	isc_result_t result;

	/* Allocate temporary structures for first rdatalist */
	data1 = isc_mem_get(mctx, 256);
	rdatalist1 = isc_mem_get(mctx, sizeof(*rdatalist1));
	rdata1 = isc_mem_get(mctx, sizeof(*rdata1));

	/* Allocate temporary structures for second rdatalist */
	data2 = isc_mem_get(mctx, 256);
	rdatalist2 = isc_mem_get(mctx, sizeof(*rdatalist2));
	rdata2 = isc_mem_get(mctx, sizeof(*rdata2));

	/*
	 * Both rdatasets are inspected by the cleanup path below, so they
	 * have to be initialized before the first CHECK() can jump there.
	 */
	dns_rdataset_init(&rdataset1);
	dns_rdataset_init(&rdataset2);

	/* Initialize first rdatalist */
	dns_rdatalist_init(rdatalist1);
	rdatalist1->type = dns_rdatatype_a;
	rdatalist1->rdclass = dns_rdataclass_in;
	rdatalist1->ttl = 300;

	/* Create first rdata */
	dns_rdata_init(rdata1);
	CHECK(dns_test_rdatafromstring(rdata1, dns_rdataclass_in,
				       dns_rdatatype_a, data1, 256,
				       "192.168.1.1", false));

	ISC_LIST_APPEND(rdatalist1->rdata, rdata1, link);
	dns_rdatalist_tordataset(rdatalist1, &rdataset1);

	/* Initialize second rdatalist */
	dns_rdatalist_init(rdatalist2);
	rdatalist2->type = dns_rdatatype_a;
	rdatalist2->rdclass = dns_rdataclass_in;
	rdatalist2->ttl = 300;

	/* Create second rdata */
	dns_rdata_init(rdata2);
	CHECK(dns_test_rdatafromstring(rdata2, dns_rdataclass_in,
				       dns_rdatatype_a, data2, 256,
				       "192.168.1.2", false));

	ISC_LIST_APPEND(rdatalist2->rdata, rdata2, link);
	dns_rdatalist_tordataset(rdatalist2, &rdataset2);

	/* Convert to vecheaders (each starts with refcount = 1) */
	CHECK(dns_rdatavec_fromrdataset(&rdataset1, mctx, &region1, 0));
	header1 = (dns_vecheader_t *)region1.base;

	CHECK(dns_rdatavec_fromrdataset(&rdataset2, mctx, &region2, 0));
	header2 = (dns_vecheader_t *)region2.base;

	/* Merge headers (this will create a new header with refcount = 1) */
	CHECK(dns_rdatavec_merge(header1, header2, mctx, dns_rdataclass_in,
				 dns_rdatatype_a, 0, 0, &merged_header));
	assert_non_null(merged_header);

	/* Test: merged header should have expected count */
	unsigned int merged_count = dns_rdatavec_count(merged_header);
	assert_int_equal(merged_count, 2);

	/* Test: merged header should have expected size */
	unsigned int merged_size = dns_rdatavec_size(merged_header);
	assert_true(merged_size > sizeof(dns_vecheader_t));

cleanup:
	/* Cleanup rdatasets */
	if (DNS_RDATASET_VALID(&rdataset1)) {
		dns_rdataset_disassociate(&rdataset1);
	}
	if (DNS_RDATASET_VALID(&rdataset2)) {
		dns_rdataset_disassociate(&rdataset2);
	}

	/* Cleanup using refcount - each header should be unreferenced once */
	if (header1 != NULL) {
		dns_vecheader_unref(header1);
	}
	if (header2 != NULL) {
		dns_vecheader_unref(header2);
	}
	if (merged_header != NULL) {
		dns_vecheader_unref(merged_header);
	}

	/* Cleanup temporary structures */
	if (rdata1 != NULL) {
		isc_mem_put(mctx, rdata1, sizeof(*rdata1));
	}
	if (rdatalist1 != NULL) {
		isc_mem_put(mctx, rdatalist1, sizeof(*rdatalist1));
	}
	if (data1 != NULL) {
		isc_mem_put(mctx, data1, 256);
	}
	if (rdata2 != NULL) {
		isc_mem_put(mctx, rdata2, sizeof(*rdata2));
	}
	if (rdatalist2 != NULL) {
		isc_mem_put(mctx, rdatalist2, sizeof(*rdatalist2));
	}
	if (data2 != NULL) {
		isc_mem_put(mctx, data2, 256);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(merge_headers, setup_mctx, teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(merge_case_preservation, setup_mctx, teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(setcase_size_consistency, setup_mctx, teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(rdatavec_subtract_assertion_failure, setup_mctx,
		      teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(rdatavec_refcount_merge, setup_mctx, teardown_mctx)
ISC_TEST_LIST_END

ISC_TEST_MAIN
