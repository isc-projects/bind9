/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007-2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: socket_p.h,v 1.15 2009/09/02 23:48:03 tbox Exp $ */

#ifndef ISC_SOCKET_P_H
#define ISC_SOCKET_P_H

/*! \file */

#ifdef ISC_PLATFORM_NEEDSYSSELECTH
#include <sys/select.h>
#endif

typedef struct isc_socketwait isc_socketwait_t;
int isc__socketmgr_waitevents(isc_socketmgr_t *, struct timeval *,
			      isc_socketwait_t **);
isc_result_t isc__socketmgr_dispatch(isc_socketmgr_t *, isc_socketwait_t *);
#endif /* ISC_SOCKET_P_H */
