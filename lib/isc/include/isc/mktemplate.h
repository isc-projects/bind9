/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#ifndef ISC_MKTEMPLATE_H
#define ISC_MKTEMPLATE_H

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

isc_result_t
isc_mktemplate(const char *name, char *buf, size_t buflen);

/*
 * create a template file name suitable for isc_ufile() such
 * that it could be renamed to 'name'.
 *
 * Requires:
 * 	'name' to be non null.
 *	'buf' to be non null.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_MKTEMPLATE_H */
