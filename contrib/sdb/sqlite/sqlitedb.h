/*
 * Copyright (C) 2000-2002, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: sqlitedb.h,v 1.1 2007/03/05 05:30:22 marka Exp $ */

#include <isc/types.h>

isc_result_t sqlitedb_init(void);

void sqlitedb_clear(void);

