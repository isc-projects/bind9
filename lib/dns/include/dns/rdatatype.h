/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef DNS_RDATATYPE_H
#define DNS_RDATATYPE_H 1

#include <isc/lang.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

isc_result_t dns_rdatatype_fromtext(dns_rdatatype_t *typep,
				    isc_textregion_t *source);
/*
 * Convert the text 'source' refers to into a DNS rdata type.
 *
 * Requires:
 *	'typep' is a valid pointer.
 *
 *	'source' is a valid text region.
 *
 * Returns:
 *	ISC_R_SUCCESS			on success
 *	DNS_R_UNKNOWN			type is unknown
 *	ISC_R_NOTIMPLEMENTED		type is known, but not implemented
 */

isc_result_t dns_rdatatype_totext(dns_rdatatype_t type,
				  isc_buffer_t *target);
/*
 * Put a textual representation of type 'type' into 'target'.
 *
 * Requires:
 *	'type' is a valid type.
 *
 *	'target' is a valid text buffer.
 *
 * Ensures:
 *	If the result is success:
 *		The used space in 'target' is updated.
 *
 * Returns:
 *	ISC_R_SUCCESS			on success
 *	ISC_R_NOSPACE			target buffer is too small
 */

ISC_LANG_ENDDECLS

#endif /* DNS_RDATATYPE_H */
