/*
 * Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: os.c,v 1.4.2.1 2004/03/09 06:12:19 marka Exp $ */

#include <windows.h>

static BOOL bInit = FALSE;
static SYSTEM_INFO SystemInfo;
static OSVERSIONINFO osVer;

static void
initialize_action(void) {
	BOOL bSuccess;

	if (bInit)
		return;
	
	GetSystemInfo(&SystemInfo);
	osVer.dwOSVersionInfoSize = sizeof(osVer);
	bSuccess = GetVersionEx(&osVer);
	bInit = TRUE;
}

unsigned int
isc_os_ncpus(void) {
	long ncpus = 1;
	initialize_action();
	ncpus = SystemInfo.dwNumberOfProcessors;
	if (ncpus <= 0)
		ncpus = 1;

	return ((unsigned int)ncpus);
}

unsigned int
isc_os_majorversion(void) {
	initialize_action();
	return ((unsigned int)osVer.dwMajorVersion);
}

unsigned int
isc_os_minorversion(void) {
	initialize_action();
	return ((unsigned int)osVer.dwMinorVersion);
}
