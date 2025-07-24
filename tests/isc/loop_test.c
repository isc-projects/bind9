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
#include <sys/types.h>
#include <unistd.h>

#include "isc/attributes.h"

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/os.h>
#include <isc/result.h>
#include <isc/util.h>

/*
 * Prevent the odr-violation by renaming isc__loopmgr when including loop.c for
 * the second time.
 */
#define isc__loopmgr isc___loopmgr
#include "loop.c"

#include <tests/isc.h>

static atomic_uint scheduled = 0;

static void
count(void *arg ISC_ATTR_UNUSED) {
	atomic_fetch_add(&scheduled, 1);
}

static void
shutdown_loopmgr(void *arg ISC_ATTR_UNUSED) {
	while (atomic_load(&scheduled) != isc_loopmgr_nloops()) {
		isc_thread_yield();
	}

	isc_loopmgr_shutdown();
}

ISC_RUN_TEST_IMPL(isc_loopmgr) {
	atomic_store(&scheduled, 0);

	isc_loopmgr_setup(count, NULL);
	isc_loop_setup(isc_loop_main(), shutdown_loopmgr, NULL);

	isc_loopmgr_run();

	assert_int_equal(atomic_load(&scheduled), isc_loopmgr_nloops());
}

static void
runjob(void *arg ISC_ATTR_UNUSED) {
	isc_async_current(count, NULL);
	if (isc_tid() == 0) {
		isc_async_current(shutdown_loopmgr, NULL);
	}
}

ISC_RUN_TEST_IMPL(isc_loopmgr_runjob) {
	atomic_store(&scheduled, 0);

	isc_loopmgr_setup(runjob, NULL);
	isc_loopmgr_run();
	assert_int_equal(atomic_load(&scheduled), isc_loopmgr_nloops());
}

static void
pause_loopmgr(void *arg ISC_ATTR_UNUSED) {
	isc_loopmgr_pause();

	assert_true(isc_loopmgr_paused());

	for (size_t i = 0; i < isc_loopmgr_nloops(); i++) {
		isc_loop_t *loop = isc_loop_get(i);

		assert_true(loop->paused);
	}

	atomic_init(&scheduled, isc_loopmgr_nloops());

	isc_loopmgr_resume();
}

ISC_RUN_TEST_IMPL(isc_loopmgr_pause) {
	isc_loop_setup(isc_loop_main(), pause_loopmgr, NULL);
	isc_loop_setup(isc_loop_main(), shutdown_loopmgr, NULL);
	isc_loopmgr_run();
}

static void
send_sigint(void *arg ISC_ATTR_UNUSED) {
	kill(getpid(), SIGINT);
}

ISC_RUN_TEST_IMPL(isc_loopmgr_sigint) {
	isc_loop_setup(isc_loop_main(), send_sigint, NULL);
	isc_loopmgr_run();
}

static void
send_sigterm(void *arg ISC_ATTR_UNUSED) {
	kill(getpid(), SIGINT);
}

ISC_RUN_TEST_IMPL(isc_loopmgr_sigterm) {
	isc_loop_setup(isc_loop_main(), send_sigterm, NULL);
	isc_loopmgr_run();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(isc_loopmgr, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(isc_loopmgr_pause, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(isc_loopmgr_runjob, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(isc_loopmgr_sigint, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(isc_loopmgr_sigterm, setup_loopmgr, teardown_loopmgr)
ISC_TEST_LIST_END

ISC_TEST_MAIN
