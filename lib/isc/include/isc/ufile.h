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

#ifndef ISC_UFILE_H
#define ISC_UFILE_H

#include <stdio.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

FILE * isc_ufile(char *template);

/*
 * Create and open a file with a unique name based on 'template'.
 * 
 * Requires:
 *	'template' to be non-NULL string containing a trailing
 *	string of X's.
 *
 * Returns:
 *	A file handle opened for 'w+' on success.  'template'
 *	will contain the file name associated with this handle.
 *	NULL if a unique name could not be generate or an other
 *	error occured when opening.  'template' may or may not
 *	have been destroyed.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_UFILE_H */
