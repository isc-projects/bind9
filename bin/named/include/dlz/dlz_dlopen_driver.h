/*
 * Copyright (C) 2011, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: dlz_dlopen_driver.h,v 1.4 2011/03/17 09:25:53 fdupont Exp $ */

#ifndef DLZ_DLOPEN_DRIVER_H
#define DLZ_DLOPEN_DRIVER_H

isc_result_t
dlz_dlopen_init(isc_mem_t *mctx);

void
dlz_dlopen_clear(void);
#endif
