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

/*! \file */

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_BACKTRACE_SYMBOLS
#include <execinfo.h>
#endif /* HAVE_BACKTRACE_SYMBOLS */

#include <isc/backtrace.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>

#if defined(_WIN32) && defined(_DEBUG)

#include <dbghelp.h>

int
isc_backtrace(void **addrs, int maxaddrs, int *nframes) {
	USHORT n = CaptureStackBackTrace(1, maxaddrs, addrs, NULL);

	return (n);
}

#define TRACE_MAX_DEPTH		       128
#define TRACE_MAX_FUNCTION_NAME_LENGTH 1024

int
vasprintf(char **strp, const char *format, va_list ap) {
	int len, retval;
	char *str = NULL;

	len = _vscprintf(format, ap);
	if (len == -1) {
		return (-1);
	}

	str = malloc((size_t)len + 1);
	if (str == NULL) {
		return (-1);
	}

	retval = vsnprintf(str, len + 1, format, ap);
	if (retval == -1) {
		free(str);
		return (-1);
	}

	*strp = str;
	return (retval);
}

int
asprintf(char **strp, const char *format, ...) {
	va_list ap;
	int retval;

	va_start(ap, format);
	retval = vasprintf(strp, format, ap);
	va_end(ap);

	return (retval);
}

static char **
_backtrace_symbols(void *const *buffer, size_t size, bool add_cr) {
	HANDLE process = GetCurrentProcess();
	DWORD displacement;
	uint8_t symbol_storage[sizeof(SYMBOL_INFO) +
			       (TRACE_MAX_FUNCTION_NAME_LENGTH - 1) *
				       sizeof(TCHAR)];
	SYMBOL_INFO *symbol = (SYMBOL_INFO *)symbol_storage;
	uint8_t line_storage[sizeof(IMAGEHLP_LINE64)];
	IMAGEHLP_LINE64 *line = (IMAGEHLP_LINE64 *)line_storage;
	char **lines = NULL;
	char **outbuf = NULL;
	char *cur = NULL;
	size_t outsize = 0;

	if (buffer == NULL || size <= 0) {
		return (NULL);
	}

	lines = malloc(size * sizeof(*lines));
	if (lines == NULL) {
		return (NULL);
	}

	/* Initialize symbol_info */
	symbol->MaxNameLen = TRACE_MAX_FUNCTION_NAME_LENGTH;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

	line->SizeOfStruct = sizeof(IMAGEHLP_LINE64);

	SymInitialize(process, NULL, TRUE);

	/* adjust for the char ** array size */
	outsize = size * sizeof(char *);
	for (size_t i = 0; i < size; i++) {
		DWORD64 address = (DWORD64)(buffer[i]);
		BOOL r;
		char *file = NULL;
		unsigned int lineno;
		int len;

		if (SymFromAddr(process, address, NULL, symbol) &&
		    SymGetLineFromAddr64(process, address, &displacement, line))
		{
			file = line->FileName;
			lineno = line->LineNumber;
		} else {
			file = "??";
			lineno = 0;
		}

		len = asprintf(&lines[i], "#%-2d %p in %s at %s:%lu%s", i,
			       (void *)symbol->Address, symbol->Name,
			       line->FileName, line->LineNumber,
			       (add_cr) ? "\n" : "");
		if (len == -1) {
			goto cleanup;
		}

		outsize += strlen(lines[i]) + 1;
	}

	outbuf = malloc(outsize);
	if (outbuf == NULL) {
		goto cleanup;
	}

	cur = (char *)&outbuf[size];
	for (size_t i = 0; i < size; i++) {
		size_t remaining = outsize - (cur - (char *)outbuf);
		size_t copied = strlcpy(cur, lines[i], remaining);
		if (copied >= remaining) {
			free(outbuf);
			outbuf = NULL;
			goto cleanup;
		}

		outbuf[i] = cur;
		cur += copied + 1;
	}

cleanup:
	for (size_t i = 0; i < size; i++) {
		free(lines[i]);
	}
	free(lines);

	return (outbuf);
}

char **
isc_backtrace_symbols(void *const *buffer, int size) {
	if (buffer == NULL || size <= 0) {
		return (NULL);
	}
	return (_backtrace_symbols(buffer, size, false));
}

void
isc_backtrace_symbols_fd(void *const *buffer, int size, int fd) {
	char **strings = NULL;
	size_t sz;

	strings = _backtrace_symbols(buffer, size, true);
	if (strings == NULL) {
		return;
	}

	for (size_t i = 0; i < (size_t)size; i++) {
		sz = strlen(strings[i]);
		if (write(fd, strings[i], sz) == -1) {
			return;
		}
	}

	free(strings);
}

#elif HAVE_BACKTRACE_SYMBOLS
int
isc_backtrace(void **addrs, int maxaddrs) {
	int n;

	/*
	 * Validate the arguments: intentionally avoid using REQUIRE().
	 * See notes in backtrace.h.
	 */
	if (addrs == NULL || maxaddrs <= 0) {
		return (-1);
	}

	/*
	 * backtrace(3) includes this function itself in the address array,
	 * which should be eliminated from the returned sequence.
	 */
	n = backtrace(addrs, maxaddrs);
	if (n < 2) {
		return (-1);
	}
	n--;
	memmove(addrs, &addrs[1], sizeof(addrs[0]) * n);

	return (n);
}

char **
isc_backtrace_symbols(void *const *buffer, int size) {
	return (backtrace_symbols(buffer, size));
}

void
isc_backtrace_symbols_fd(void *const *buffer, int size, int fd) {
	backtrace_symbols_fd(buffer, size, fd);
}

#else /* HAVE_BACKTRACE_SYMBOLS */

int
isc_backtrace(void **addrs, int maxaddrs) {
	UNUSED(addrs);
	UNUSED(maxaddrs);

	return (-1);
}

char **
isc_backtrace_symbols(void *const *buffer, int size) {
	UNUSED(buffer);
	UNUSED(size);

	return (NULL);
}

void
isc_backtrace_symbols_fd(void *const *buffer, int size, int fd) {
	UNUSED(buffer);
	UNUSED(size);
	UNUSED(fd);
}

#endif /* HAVE_BACKTRACE_SYMBOLS */
