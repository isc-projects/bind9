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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/crypto.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/kasp.h>
#include <dns/keystore.h>

#include <isccfg/cfg.h>
#include <isccfg/kaspconf.h>
#include <isccfg/namedconf.h>

#include <tests/isc.h>

ISC_SETUP_TEST_IMPL(group) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	return 0;
}

/* Parse a dnssec-policy statement and configure a kasp from it. */
static isc_result_t
kasp_fromtext(const char *conftext) {
	isc_result_t result;
	isc_buffer_t b;
	cfg_obj_t *config = NULL;
	const cfg_obj_t *kasps = NULL;
	dns_kasp_t *kasp = NULL;
	dns_kasplist_t kasplist;
	dns_keystorelist_t keystores;

	ISC_LIST_INIT(kasplist);
	ISC_LIST_INIT(keystores);

	/* Add default key-store "key-directory". */
	result = cfg_keystore_fromconfig(NULL, isc_g_mctx, &keystores, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_constinit(&b, conftext, strlen(conftext));
	isc_buffer_add(&b, strlen(conftext));
	result = cfg_parse_buffer(&b, "text", 0, &cfg_type_namedconf, 0,
				  &config);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = cfg_map_get(config, "dnssec-policy", &kasps);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = cfg_kasp_fromconfig(cfg_listelt_value(cfg_list_first(kasps)),
				     NULL, 0, isc_g_mctx, &keystores, &kasplist,
				     &kasp);
	if (kasp != NULL) {
		dns_kasp_detach(&kasp);
	}

	ISC_LIST_FOREACH(kasplist, k, link) {
		ISC_LIST_UNLINK(kasplist, k, link);
		dns_kasp_detach(&k);
	}
	ISC_LIST_FOREACH(keystores, ks, link) {
		ISC_LIST_UNLINK(keystores, ks, link);
		dns_keystore_detach(&ks);
	}
	cfg_obj_detach(&config);

	return result;
}

#define CSK_POLICY(alg)                                              \
	"dnssec-policy \"p\" {\n"                                    \
	"	keys {\n"                                                  \
	"		csk lifetime unlimited algorithm " alg ";\n" \
	"	};\n"                                                      \
	"};\n"

ISC_RUN_TEST_IMPL(kaspkey_rsa_length) {
	struct {
		const char *conftext;
		isc_result_t expected;
	} testcases[] = {
		/* The minimum for RSASHA512 based algorithms is 1024... */
		{ CSK_POLICY("rsasha512 512"), ISC_R_RANGE },
		{ CSK_POLICY("rsasha512 1024"), ISC_R_SUCCESS },
		{ CSK_POLICY("rsasha512oid 512"), ISC_R_RANGE },
		{ CSK_POLICY("rsasha512oid 1024"), ISC_R_SUCCESS },
		/* ...but 512 for the other RSA algorithms. */
		{ CSK_POLICY("rsasha256 512"), ISC_R_SUCCESS },
		{ CSK_POLICY("rsasha256 511"), ISC_R_RANGE },
		{ CSK_POLICY("rsasha256oid 512"), ISC_R_SUCCESS },
		{ CSK_POLICY("rsasha1 512"), ISC_R_SUCCESS },
		/* The maximum is 4096 for all of them. */
		{ CSK_POLICY("rsasha256 4097"), ISC_R_RANGE },
	};

	if (isc_crypto_fips_mode()) {
		skip();
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		isc_result_t result = kasp_fromtext(testcases[i].conftext);
		assert_int_equal(result, testcases[i].expected);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(kaspkey_rsa_length)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, NULL)
