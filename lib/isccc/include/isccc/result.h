/*
 * Copyright (C) 2001  Internet Software Consortium.
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

/* $Id: result.h,v 1.1 2001/03/27 00:44:51 bwelling Exp $ */

#ifndef ISCCC_RESULT_H
#define ISCCC_RESULT_H 1

#include <isc/lang.h>
#include <isc/resultclass.h>
#include <isc/result.h>

#include <isccc/types.h>

#define ISCCC_R_UNKNOWNVERSION		(ISC_RESULTCLASS_ISCCC + 0)
#define ISCCC_R_SYNTAX			(ISC_RESULTCLASS_ISCCC + 1)
#define ISCCC_R_BADAUTH			(ISC_RESULTCLASS_ISCCC + 2)

#define ISCCC_R_NRESULTS 		3	/* Number of results */

#define ISCCC_RESULT_OSBASE		0x01000000
#define ISCCC_RESULT_OSMASK		0x00ffffff

ISC_LANG_BEGINDECLS

const char *
isccc_result_totext(isc_result_t result);
/*
 * Convert a isccc_result_t into a string message describing the result.
 */

void
isccc_result_register(void);

isc_result_t
isccc_result_fromerrno(int ecode);
/*
 * Convert a UNIX errno into a isc_result_t.
 */

ISC_LANG_ENDDECLS

#endif /* ISCCC_RESULT_H */
