/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef ISC_LFSR_H
#define ISC_LFSR_H 1

#include <isc/types.h>

/*
 * The members of this structure can be used by the application, but care
 * needs to be taken to not change state once the lfsr is in operation.
 */
typedef struct {
	isc_uint32_t	state;	/* previous state */
	isc_uint32_t	bits;	/* length */
	isc_uint32_t	tap;	/* bit taps */
} isc_lfsr_t;

/*
 * This structure contains some standard LFSR values that can be used.
 * One can use the isc_lfsr_findlfsr() to search for one with at least
 * a certain number of bits.
 */
extern isc_lfsr_t isc_lfsr_standard[];

ISC_LANG_BEGINDECLS

isc_uint32_t isc_lfsr_generate(isc_lfsr_t *lfsr);
isc_uint32_t isc_lfsr_skipgenerate(isc_lfsr_t *lfsr, unsigned int skip);
isc_uint32_t isc_lfsr_lfsrskipgenerate(isc_lfsr_t *lfsr1, isc_lfsr_t *lfsr2,
				       unsigned int skipbits);

ISC_LANG_ENDDECLS

#endif /* ISC_LFSR_H */
