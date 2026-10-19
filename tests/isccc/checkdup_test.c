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
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/symtab.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccc/alist.h>
#include <isccc/cc.h>
#include <isccc/sexpr.h>

#include <tests/isc.h>

ISC_SETUP_TEST_IMPL(group) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	return 0;
}

/* test isccc_cc_checkdup() */
ISC_RUN_TEST_IMPL(checkdup) {
	isc_symtab_t *symtab = NULL;
	const isc_stdtime_t start = isc_stdtime_now();
	const uint32_t lifetime = 5;
	const uint32_t serial = 0xdeadcafe;
	bool first = true;

	isccc_cc_createsymtab(isc_g_mctx, &symtab);

	while (true) {
		isc_stdtime_t now = isc_stdtime_now();
		isccc_sexpr_t *request = isccc_alist_create();
		isc_result_t result;

		assert_non_null(request);

		isccc_sexpr_t *_ctrl = isccc_alist_create();
		assert_non_null(_ctrl);
		assert_non_null(isccc_alist_define(request, "_ctrl", _ctrl));
		assert_non_null(isccc_cc_defineuint32(_ctrl, "_ser", serial));
		assert_non_null(isccc_cc_defineuint32(_ctrl, "_tim", start));

		isccc_cc_cleansymtab(symtab, now);
		result = isccc_cc_checkdup(symtab, request, now + lifetime);

		isccc_sexpr_free(&request);

		if (first) {
			first = false;
			/* First one should go in successfully. */
			assert_true(result == ISC_R_SUCCESS);
		} else if (now - start < lifetime) {
			/*
			 * Until the lifetime of the inserted entry has passed,
			 * it should live and no new entry should enter.
			 */
			assert_true(result == ISC_R_EXISTS);
		} else {
			/*
			 * When lifetime has passed, the isccc_cc_cleansymtab()
			 * call above should have cleaned up the entry, so the
			 * new one should enter successfully again, and the test
			 * is over.
			 */
			assert_true(result == ISC_R_SUCCESS);
			break;
		}

		uv_sleep(10);
	}

	isc_symtab_destroy(&symtab);
}

/*
 * Model control_recvmessage duplicate detection using a
 * smaller clock skew (5 seconds).
 */
ISC_RUN_TEST_IMPL(model_duplicate_protection) {
	isc_symtab_t *symtab = NULL;
	isccc_sexpr_t *request = isccc_alist_create();
	isccc_sexpr_t *_ctrl = isccc_alist_create();
	isc_stdtime_t now = isc_stdtime_now();
	const uint32_t lifetime = 5;
	const isc_stdtime_t sent = now + lifetime + 1;
	const isc_stdtime_t end = now + 2 * lifetime + 3;
	const uint32_t serial = 0xdeadcafe;
	bool accepted = false;

	isccc_cc_createsymtab(isc_g_mctx, &symtab);

	/*
	 * Create a synthetic request that will be replayed.
	 */
	assert_non_null(request);
	assert_non_null(_ctrl);
	assert_non_null(isccc_alist_define(request, "_ctrl", _ctrl));
	assert_non_null(isccc_cc_defineuint32(_ctrl, "_ser", serial));
	assert_non_null(isccc_cc_defineuint32(_ctrl, "_tim", sent));

	while (now < end) {
		isc_result_t result;

		if ((sent + lifetime) < now || (sent - lifetime) > now) {
			if (debug) {
				fprintf(stderr, "# clock skew\n");
			}
			goto again;
		}

		isccc_cc_cleansymtab(symtab, now);
		result = isccc_cc_checkdup(symtab, request,
					   now + 2 * lifetime + 1);
		if (result == ISC_R_SUCCESS) {
			/*
			 * Check if we haven't already accepted this
			 * request.
			 */
			assert_false(accepted);
			accepted = true;
		} else if (debug) {
			fprintf(stderr, "# duplicate\n");
		}

	again:
		uv_sleep(10);
		now = isc_stdtime_now();
	}

	/*
	 * Check that we accepted a request.
	 */
	assert_true(accepted);

	isc_symtab_destroy(&symtab);
	isccc_sexpr_free(&request);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(checkdup)
ISC_TEST_ENTRY(model_duplicate_protection)

ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, NULL)
