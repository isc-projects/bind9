/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id$ */

#ifndef ISC_TASK_P_H
#define ISC_TASK_P_H

/*! \file */

#if defined(ISC_PLATFORM_USETHREADS)
void
isc__taskmgr_pause(isc_taskmgr_t *taskmgr);

void
isc__taskmgr_resume(isc_taskmgr_t *taskmgr);
#else
bool
isc__taskmgr_ready(isc_taskmgr_t *taskmgr);

isc_result_t
isc__taskmgr_dispatch(isc_taskmgr_t *taskmgr);
#endif /* !ISC_PLATFORM_USETHREADS */

#endif /* ISC_TASK_P_H */
