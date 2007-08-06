/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: ntpaths.h,v 1.3 2001/07/09 21:34:44 gson Exp $ */

/*
 * Windows-specific path definitions
 * These routines are used to set up and return system-specific path
 * information about the files enumerated in NtPaths
 */

#ifndef ISC_NTPATHS_H
#define ISC_NTPATHS_H

/*
 * Index of paths needed
 */
enum NtPaths {
	NAMED_CONF_PATH,
	LWRES_CONF_PATH,
	RESOLV_CONF_PATH,
	RNDC_CONF_PATH,
	NAMED_PID_PATH,
	LWRESD_PID_PATH
};

void
isc_ntpaths_init(void);

char *
isc_ntpaths_get(int);

#endif /* ISC_NTPATHS_H */
