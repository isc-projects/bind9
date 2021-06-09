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

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/socket.h>

isc_result_t
isc__socketmgr_create(isc_mem_t *mctx, isc_socketmgr_t **managerp,
		      unsigned int maxsocks, int nthreads);
/*%<
 * Create a socket manager.  If "maxsocks" is non-zero, it specifies the
 * maximum number of sockets that the created manager should handle.
 *
 * Notes:
 *
 *\li	All memory will be allocated in memory context 'mctx'.
 *
 * Requires:
 *
 *\li	'mctx' is a valid memory context.
 *
 *\li	'managerp' points to a NULL isc_socketmgr_t.
 *
 * Ensures:
 *
 *\li	'*managerp' is a valid isc_socketmgr_t.
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	#ISC_R_UNEXPECTED
 *\li	#ISC_R_NOTIMPLEMENTED
 */

void
isc__socketmgr_destroy(isc_socketmgr_t **managerp);
/*%<
 * Destroy a socket manager.
 *
 * Notes:
 *
 *\li	This routine blocks until there are no sockets left in the manager,
 *	so if the caller holds any socket references using the manager, it
 *	must detach them before calling isc_socketmgr_destroy() or it will
 *	block forever.
 *
 * Requires:
 *
 *\li	'*managerp' is a valid isc_socketmgr_t.
 *
 *\li	All sockets managed by this manager are fully detached.
 *
 * Ensures:
 *
 *\li	*managerp == NULL
 *
 *\li	All resources used by the manager have been freed.
 */

#include <sys/time.h>

typedef struct isc_socketwait isc_socketwait_t;
int
isc__socketmgr_waitevents(isc_socketmgr_t *, struct timeval *,
			  isc_socketwait_t **);
isc_result_t
isc__socketmgr_dispatch(isc_socketmgr_t *, isc_socketwait_t *);
