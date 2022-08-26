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

#include <isc/atomic.h>
#include <isc/job.h>
#include <isc/loop.h>
#include <isc/os.h>
#include <isc/result.h>
#include <isc/util.h>

#include "job.c"

#include <tests/isc.h>

static atomic_uint scheduled;
static atomic_uint executed;

#define MAX_EXECUTED 1000000

static void
shutdown_cb(void *arg) {
	UNUSED(arg);

	isc_loopmgr_shutdown(loopmgr);
}

static void
job_cb(void *arg __attribute__((__unused__))) {
	unsigned int n = atomic_fetch_add(&executed, 1);

	if (n <= MAX_EXECUTED) {
		atomic_fetch_add(&scheduled, 1);
		isc_job_run(loopmgr, job_cb, loopmgr);
	} else {
		isc_job_run(loopmgr, shutdown_cb, loopmgr);
	}
}

static void
job_run_cb(void *arg __attribute__((__unused__))) {
	atomic_fetch_add(&scheduled, 1);

	isc_job_run(loopmgr, job_cb, loopmgr);
}

ISC_RUN_TEST_IMPL(isc_job_run) {
	atomic_init(&scheduled, 0);
	atomic_init(&executed, 0);

	isc_loopmgr_setup(loopmgr, job_run_cb, loopmgr);

	isc_loopmgr_run(loopmgr);

	assert_int_equal(atomic_load(&scheduled), atomic_load(&executed));
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(isc_job_run, setup_loopmgr, teardown_loopmgr)
ISC_TEST_LIST_END

ISC_TEST_MAIN
