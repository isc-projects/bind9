/*
 * Copyright (C) 1999-2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ntservice.h,v 1.6 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NTSERVICE_H
#define NTSERVICE_H

#include <winsvc.h>

#define BIND_DISPLAY_NAME "ISC BIND"
#define BIND_SERVICE_NAME "named"

void
ntservice_init();
void UpdateSCM(DWORD);
void ServiceControl(DWORD dwCtrlCode);
void
ntservice_shutdown();
BOOL ntservice_isservice();
#endif
