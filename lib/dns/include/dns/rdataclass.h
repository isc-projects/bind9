/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#ifndef DNS_RDATACLASS_H
#define DNS_RDATACLASS_H 1

#include <dns/types.h>

dns_result_t dns_rdataclass_fromtext(dns_rdataclass_t *class,
				     dns_region_t *source);
/*
 * Convert the text 'source' refers to into a DNS class.
 *
 * Requires:
 *	'class' is a valid pointer.
 *
 *	'region' is a valid region.
 *
 * Returns:
 *	DNS_R_SUCCESS			on success
 *	DNS_R_UNKNOWN			class is unknown
 *	DNS_R_NOTIMPLEMENTED		class is known, but not implemented
 */

dns_result_t dns_rdataclass_totext(dns_rdataclass_t class,
				   dns_region_t *target, unsigned int *bytesp);
/*
 * Put a textual representation of class 'class' into 'target'.
 *
 * Requires:
 *	'class' is a valid pointer.
 *
 *	'region' is a valid region.
 *
 * Ensures:
 *	If the result is success:
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Returns:
 *	DNS_R_SUCCESS			on success
 *	DNS_R_NOSPACE			target region is too small
 */

#endif /* DNS_RDATACLASS_H */
