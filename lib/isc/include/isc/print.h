/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef ISC_PRINT_H
#define ISC_PRINT_H

/***
 *** Imports
 ***/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <isc/lang.h>
#include <isc/platform.h>

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

#ifdef ISC_PLATFORM_NEEDVSNPRINTF
int
isc_print_vsnprintf(char *str, size_t size, const char *format, va_list ap);
#define vsnprintf isc_print_vsnprintf

int
isc_print_snprintf(char *str, size_t size, const char *format, ...);
#define snprintf isc_print_snprintf
#endif

ISC_LANG_ENDDECLS

#endif /* ISC_PRINT_H */
