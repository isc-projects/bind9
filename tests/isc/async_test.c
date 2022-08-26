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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/loop.h>
#include <isc/os.h>
#include <isc/result.h>
#include <isc/tid.h>
#include <isc/util.h>

#include "async.c"

#include <tests/isc.h>

static atomic_uint scheduled = 0;

static void
async_cb(void *arg) {
	UNUSED(arg);
	uint32_t tid = isc_tid();

	atomic_fetch_add(&scheduled, 1);

	if (tid > 0) {
		isc_loop_t *loop = isc_loop_get(loopmgr, tid - 1);
		isc_async_run(loop, async_cb, loopmgr);
	} else {
		isc_loopmgr_shutdown(loopmgr);
	}
}

static void
async_setup_cb(void *arg) {
	UNUSED(arg);
	uint32_t tid = isc_loopmgr_nloops(loopmgr) - 1;

	isc_loop_t *loop = isc_loop_get(loopmgr, tid);

	isc_async_run(loop, async_cb, loopmgr);
}

ISC_RUN_TEST_IMPL(isc_async_run) {
	isc_loop_setup(isc_loop_main(loopmgr), async_setup_cb, loopmgr);
	isc_loopmgr_run(loopmgr);
	assert_int_equal(atomic_load(&scheduled), loopmgr->nloops);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(isc_async_run, setup_loopmgr, teardown_loopmgr)
ISC_TEST_LIST_END

ISC_TEST_MAIN
