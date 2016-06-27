/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: timer_p.h,v 1.12 2009/09/02 23:48:02 tbox Exp $ */

#ifndef ISC_TIMER_P_H
#define ISC_TIMER_P_H

/*! \file */

isc_result_t
isc__timermgr_nextevent(isc_timermgr_t *timermgr, isc_time_t *when);

void
isc__timermgr_dispatch(isc_timermgr_t *timermgr);

#endif /* ISC_TIMER_P_H */
