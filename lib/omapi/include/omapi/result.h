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

#ifndef OMAPI_RESULT_H
#define DNS_RESULT_H 1

#include <isc/lang.h>
#include <isc/result.h>
#include <isc/resultclass.h>

ISC_LANG_BEGINDECLS

#define OMAPI_R_NOTYET			(ISC_RESULTCLASS_OMAPI + 0)
#define OMAPI_R_NOTCONNECTED		(ISC_RESULTCLASS_OMAPI + 1)
#define OMAPI_R_NOKEYS			(ISC_RESULTCLASS_OMAPI + 2)
#define OMAPI_R_INVALIDARG		(ISC_RESULTCLASS_OMAPI + 3)
#define OMAPI_R_VERSIONMISMATCH		(ISC_RESULTCLASS_OMAPI + 4)
#define OMAPI_R_PROTOCOLERROR		(ISC_RESULTCLASS_OMAPI + 5)

#define OMAPI_R_NRESULTS		6	/* Number of results */

char *				omapi_result_totext(isc_result_t);
void				omapi_result_register(void);

ISC_LANG_ENDDECLS

#endif /* DNS_RESULT_H */
