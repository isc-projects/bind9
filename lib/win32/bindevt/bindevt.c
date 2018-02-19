/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: bindevt.c,v 1.5 2007/06/19 23:47:24 tbox Exp $ */

/*
 * bindevt.c : Defines the entry point for event log viewer DLL.
 */

#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call,
		      LPVOID lpReserved)
{
	return (TRUE);
}

