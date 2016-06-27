/*
 * Copyright (C) 2000-2002, 2004, 2007, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: os.c,v 1.8 2007/06/19 23:47:19 tbox Exp $ */

#include <windows.h>

#include <isc/os.h>

static BOOL bInit = FALSE;
static SYSTEM_INFO SystemInfo;

static void
initialize_action(void) {
	if (bInit)
		return;

	GetSystemInfo(&SystemInfo);
	bInit = TRUE;
}

unsigned int
isc_os_ncpus(void) {
	long ncpus;
	initialize_action();
	ncpus = SystemInfo.dwNumberOfProcessors;
	if (ncpus <= 0)
		ncpus = 1;

	return ((unsigned int)ncpus);
}
