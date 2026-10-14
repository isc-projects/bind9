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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/formatcheck.h>
#include <isc/lib.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/diff.h>
#include <dns/dnssec.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>

#include <dst/dst.h>

#include <tests/dns.h>

static char report_output[BUFSIZ];

static void
ISC_FORMAT_PRINTF(1, 2) report(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(report_output, sizeof(report_output), fmt, ap);
	va_end(ap);
}

/*
 * remove_key() must report the full 16-bit DST algorithm; private
 * algorithms used to be truncated to their 8-bit DNSSEC algorithm octet.
 */
ISC_RUN_TEST_IMPL(updatekeys_remove_privateoid) {
	isc_result_t result;
	dst_key_t *key = NULL;
	dst_key_t *pubkey = NULL;
	dns_dnsseckey_t *zonekey = NULL;
	dns_dnsseckey_t *newkey = NULL;
	dns_dnsseckeylist_t keys;
	dns_dnsseckeylist_t newkeys;
	dns_diff_t diff;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t buf;
	unsigned char keydata[1024];

	UNUSED(state);

	if (!dst_algorithm_supported(DST_ALG_RSASHA256PRIVATEOID)) {
		skip();
		return;
	}

	dns_test_namefromstring("example.", &fname);
	name = dns_fixedname_name(&fname);

	result = dst_key_generate(name, DST_ALG_RSASHA256PRIVATEOID, 2048, 0,
				  DNS_KEYOWNER_ZONE, DNS_KEYPROTO_DNSSEC,
				  dns_rdataclass_in, NULL, isc_g_mctx, &key,
				  NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Public copy of the same key, as if found in the zone. */
	isc_buffer_init(&buf, keydata, sizeof(keydata));
	result = dst_key_todns(key, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromdns(name, dns_rdataclass_in, &buf, isc_g_mctx,
				 &pubkey);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(dst_key_alg(pubkey), DST_ALG_RSASHA256PRIVATEOID);

	ISC_LIST_INIT(keys);
	dns_dnsseckey_create(isc_g_mctx, &pubkey, &zonekey);
	ISC_LIST_APPEND(keys, zonekey, link);

	/* The key metadata says the key must be removed. */
	ISC_LIST_INIT(newkeys);
	dns_dnsseckey_create(isc_g_mctx, &key, &newkey);
	newkey->hint_remove = true;
	ISC_LIST_APPEND(newkeys, newkey, link);

	dns_diff_init(isc_g_mctx, &diff);
	report_output[0] = '\0';
	result = dns_dnssec_updatekeys(&keys, &newkeys, NULL, name, 3600, &diff,
				       isc_g_mctx, report);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_non_null(strstr(report_output, "Removing expired key"));
	assert_non_null(strstr(report_output, "/RSASHA256OID"));
	assert_true(ISC_LIST_EMPTY(keys));

	dns_diff_clear(&diff);
	while (!ISC_LIST_EMPTY(newkeys)) {
		dns_dnsseckey_t *dk = ISC_LIST_HEAD(newkeys);
		ISC_LIST_UNLINK(newkeys, dk, link);
		dns_dnsseckey_destroy(isc_g_mctx, &dk);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(updatekeys_remove_privateoid)
ISC_TEST_LIST_END

ISC_TEST_MAIN
