/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <isc/hp.h>
#include <isc/managers.h>
#include <isc/util.h>

#include "netmgr_p.h"
#include "socket_p.h"
#include "task_p.h"
#include "timer_p.h"

isc_result_t
isc_managers_create(isc_mem_t *mctx, size_t workers, size_t quantum,
		    size_t sockets, isc_nm_t **netmgrp,
		    isc_taskmgr_t **taskmgrp, isc_timermgr_t **timermgrp,
		    isc_socketmgr_t **socketmgrp) {
	isc_result_t result;
	isc_nm_t *netmgr = NULL;
	isc_socketmgr_t *socketmgr = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	isc_timermgr_t *timermgr = NULL;

	/*
	 * We have ncpus network threads, ncpus old network threads - make
	 * it 4x just to be on the safe side.
	 */
	isc_hp_init(4 * workers);

	REQUIRE(netmgrp != NULL && *netmgrp == NULL);
	isc__netmgr_create(mctx, workers, &netmgr);
	*netmgrp = netmgr;
	INSIST(netmgr != NULL);

	REQUIRE(taskmgrp == NULL || *taskmgrp == NULL);
	if (taskmgrp != NULL) {
		INSIST(netmgr != NULL);
		result = isc__taskmgr_create(mctx, quantum, netmgr, &taskmgr);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_taskmgr_create() failed: %s",
					 isc_result_totext(result));
			goto fail;
		}
		*taskmgrp = taskmgr;
	}

	REQUIRE(timermgrp == NULL || *timermgrp == NULL);
	if (timermgrp != NULL) {
		result = isc__timermgr_create(mctx, &timermgr);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_timermgr_create() failed: %s",
					 isc_result_totext(result));
			goto fail;
		}
		*timermgrp = timermgr;
	}

	REQUIRE(socketmgrp == NULL || *socketmgrp == NULL);
	if (socketmgrp != NULL) {
		result = isc__socketmgr_create(mctx, &socketmgr, sockets,
					       workers);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_socketmgr_create() failed: %s",
					 isc_result_totext(result));
			goto fail;
		}
		*socketmgrp = socketmgr;
	}

	return (ISC_R_SUCCESS);
fail:
	isc_managers_destroy(netmgrp, taskmgrp, timermgrp, socketmgrp);

	return (result);
}

void
isc_managers_destroy(isc_nm_t **netmgrp, isc_taskmgr_t **taskmgrp,
		     isc_timermgr_t **timermgrp, isc_socketmgr_t **socketmgrp) {
	/*
	 * If we have a taskmgr to clean up, then we must also have a netmgr.
	 */
	REQUIRE(taskmgrp != NULL || netmgrp == NULL);

	/*
	 * The sequence of operations here is important:
	 *
	 * 1. Initiate shutdown of the taskmgr, sending shutdown events to
	 * all tasks that are not already shutting down.
	 */
	if (taskmgrp != NULL) {
		INSIST(*taskmgrp != NULL);
		isc__taskmgr_shutdown(*taskmgrp);
	}

	/*
	 * 2. Initiate shutdown of the network manager, freeing clients
	 * and other resources and preventing new connections, but do
	 * not stop processing of existing events.
	 */
	if (netmgrp != NULL) {
		INSIST(*netmgrp != NULL);
		isc__netmgr_shutdown(*netmgrp);
	}

	/*
	 * 3. Finish destruction of the task manager when all tasks
	 * have completed.
	 */
	if (taskmgrp != NULL) {
		isc__taskmgr_destroy(taskmgrp);
	}

	/*
	 * 4. Finish destruction of the netmgr, and wait until all
	 * references have been released.
	 */
	if (netmgrp != NULL) {
		isc__netmgr_destroy(netmgrp);
	}

	/*
	 * 5. Clean up the remaining managers.
	 */
	if (timermgrp != NULL) {
		INSIST(*timermgrp != NULL);
		isc__timermgr_destroy(timermgrp);
	}
	if (socketmgrp != NULL) {
		INSIST(*socketmgrp != NULL);
		isc__socketmgr_destroy(socketmgrp);
	}
}
