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
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/dnssec.h>
#include <dns/kasp.h>
#include <dns/keymgr.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>

#include <dst/dst.h>

#include <tests/dns.h>

/*
 * dns_keymgr_status() must report the full 16-bit DST algorithm; private
 * algorithms used to be truncated to their 8-bit DNSSEC algorithm octet.
 */
ISC_RUN_TEST_IMPL(keymgr_status_privateoid) {
	isc_result_t result;
	dns_kasp_t *kasp = NULL;
	dns_dnsseckeylist_t keyring;
	dns_dnsseckey_t *dkey = NULL;
	dst_key_t *key = NULL;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t buf;
	char output[BUFSIZ] = { 0 };
	isc_stdtime_t now = isc_stdtime_now();

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

	/* Make the key an in-use ZSK so its status is reported. */
	dst_key_setbool(key, DST_BOOL_KSK, false);
	dst_key_setbool(key, DST_BOOL_ZSK, true);
	dst_key_settime(key, DST_TIME_PUBLISH, now);
	dst_key_settime(key, DST_TIME_ACTIVATE, now);
	dst_key_setstate(key, DST_KEY_GOAL, DST_KEY_STATE_OMNIPRESENT);
	dst_key_setstate(key, DST_KEY_DNSKEY, DST_KEY_STATE_RUMOURED);
	dst_key_setstate(key, DST_KEY_ZRRSIG, DST_KEY_STATE_RUMOURED);

	ISC_LIST_INIT(keyring);
	dns_dnsseckey_create(isc_g_mctx, &key, &dkey);
	ISC_LIST_APPEND(keyring, dkey, link);

	dns_kasp_create(isc_g_mctx, "test", &kasp);
	dns_kasp_freeze(kasp);

	isc_buffer_init(&buf, output, sizeof(output) - 1);
	result = dns_keymgr_status(kasp, &keyring, &buf, now, false, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_non_null(strstr(output, "(RSASHA256OID)"));

	dns_kasp_detach(&kasp);
	ISC_LIST_UNLINK(keyring, dkey, link);
	dns_dnsseckey_destroy(isc_g_mctx, &dkey);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(keymgr_status_privateoid)
ISC_TEST_LIST_END

ISC_TEST_MAIN
