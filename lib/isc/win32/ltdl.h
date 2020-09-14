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

#pragma once

#include <windows.h>

#define lt_dlhandle    HMODULE
#define lt_dlinit()    ISC_R_SUCCESS
#define lt_dlopen(f)   LoadLibraryW(f)
#define lt_dlsym(h, s) GetProcAddress(h, s)
#define lt_dlclose(h)  FreeLibrary(h)

__declspec(thread) LPSTR __dlerror_message[1024] = { 0 };

static const char *
lt_dlerror(void) {
	DWORD errorMessageID = GetLastError();
	if (errorMessageID == 0) {
		return (NULL);
	}

	LPSTR messageBuffer = NULL;
	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&messageBuffer, 0, NULL);

	strlcpy(__dlerror_message, messageBuffer, sizeof(__dlerror_message));

	LocalFree(messageBuffer);

	return ((const char *)__dlerror_message);
}
