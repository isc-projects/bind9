/*
 * Copyright (C) 2003  Internet Software Consortium.
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

/* $Id: stdlib.h,v 1.1 2003/06/24 05:10:33 marka Exp $ */

#ifndef ISC_STDLIB_H
#define ISC_STDLIB_H 1

#include <stdlib.h>

#include <isc/lang.h>
#include <isc/platform.h>

#ifdef ISC_PLATFORM_NEEDSTRTOUL
#define strtoul isc_strtoul
#endif

ISC_LANG_BEGINDECLS

unsigned long isc_strtoul(const char *, char **, int);

ISC_LANG_ENDDECLS

#endif
