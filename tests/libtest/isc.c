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

/*! \file */

#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/loop.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <tests/isc.h>

isc_mem_t *mctx = NULL;
isc_log_t *lctx = NULL;
isc_loop_t *mainloop = NULL;
isc_loopmgr_t *loopmgr = NULL;
isc_taskmgr_t *taskmgr = NULL;
isc_nm_t *netmgr = NULL;
unsigned int workers = -1;

static void
adjustnofile(void) {
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		if (rl.rlim_cur != rl.rlim_max) {
			rl.rlim_cur = rl.rlim_max;
			setrlimit(RLIMIT_NOFILE, &rl);
		}
	}
}

int
setup_mctx(void **state __attribute__((__unused__))) {
	isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
	isc_mem_create(&mctx);

	return (0);
}

int
teardown_mctx(void **state __attribute__((__unused__))) {
	isc_mem_destroy(&mctx);

	return (0);
}

int
setup_loopmgr(void **state __attribute__((__unused__))) {
	char *env_workers = NULL;

	REQUIRE(mctx != NULL);

	env_workers = getenv("ISC_TASK_WORKERS");
	if (env_workers != NULL) {
		workers = atoi(env_workers);
	} else {
		/* We always need at least two loops for some of the tests */
		workers = isc_os_ncpus() + 1;
	}
	INSIST(workers != 0);

	isc_loopmgr_create(mctx, workers, &loopmgr);
	mainloop = isc_loop_main(loopmgr);

	return (0);
}

int
teardown_loopmgr(void **state __attribute__((__unused__))) {
	REQUIRE(taskmgr == NULL);
	REQUIRE(netmgr == NULL);

	mainloop = NULL;
	isc_loopmgr_destroy(&loopmgr);

	return (0);
}

int
setup_taskmgr(void **state __attribute__((__unused__))) {
	REQUIRE(loopmgr != NULL);

	isc_taskmgr_create(mctx, loopmgr, &taskmgr);

	return (0);
}

int
teardown_taskmgr(void **state __attribute__((__unused__))) {
	isc_taskmgr_destroy(&taskmgr);

	return (0);
}

int
setup_netmgr(void **state __attribute__((__unused__))) {
	REQUIRE(loopmgr != NULL);

	adjustnofile();

	isc_netmgr_create(mctx, loopmgr, &netmgr);

	return (0);
}

int
teardown_netmgr(void **state __attribute__((__unused__))) {
	REQUIRE(loopmgr != NULL);

	isc_netmgr_destroy(&netmgr);

	return (0);
}

int
setup_managers(void **state) {
	setup_loopmgr(state);
	setup_taskmgr(state);
	setup_netmgr(state);

	return (0);
}

int
teardown_managers(void **state) {
	teardown_netmgr(state);
	teardown_taskmgr(state);
	teardown_loopmgr(state);

	return (0);
}
