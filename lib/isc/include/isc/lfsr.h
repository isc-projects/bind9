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
	unsigned int	bits;	/* length */
	isc_uint32_t	tap;	/* bit taps */
} isc_lfsr_t;

/*
 * This structure contains some standard LFSR values that can be used.
 * One can use the isc_lfsr_findlfsr() to search for one with at least
 * a certain number of bits.
 */
extern isc_lfsr_t isc_lfsr_standard[];

ISC_LANG_BEGINDECLS

/*
 * In all these functions it is important that the caller only use as many
 * bits as the LFSR has state.  Also, it isn't guaranteed that an LFSR of
 * bit length 32 will have 2^32 unique states before repeating.
 */

isc_lfsr_t *isc_lfsr_findlfsr(unsigned int bits);
/*
 * Find an LFSR that has at least "bits" of state.
 *
 * Requires:
 *
 *	8 <= bits <= 32
 *
 * Returns:
 *
 *	NULL if no LFSR can be found.
 *
 *	If NON-null, it points to the first LFSR in the standard LFSR table
 *	that satisfies the requirements.
 */

void isc_lfsr_init(isc_lfsr_t *lfsr, isc_uint32_t state, unsigned int bits,
		   isc_uint32_t tap);
/*
 * Initialize an LFSR.
 *
 * Note:
 *
 *	Putting untrusted values into this function will cause the LFSR to
 *	generate (perhaps) non-maximal length sequences.
 *
 * Requires:
 *
 *	lfsr != NULL
 *
 *	8 <= bits <= 32
 *
 *	tap != 0
 */

isc_uint32_t isc_lfsr_generate(isc_lfsr_t *lfsr);
/*
 * Return the next state in the LFSR.
 *
 * Requires:
 *
 *	lfsr be valid.
 */

isc_uint32_t isc_lfsr_skipgenerate(isc_lfsr_t *lfsr, unsigned int skip);
/*
 * Skip "skip" states, then return the next state after that.
 *
 * Requiremens are the same as for isc_lfsr_generate(), above.
 */

isc_uint32_t isc_lfsr_lfsrskipgenerate(isc_lfsr_t *lfsr1, isc_lfsr_t *lfsr2,
				       unsigned int skipbits);
/*
 * Given two LFSRs, use the current state from each to skip entries in the
 * other.  The next states are then xor'd together and returned.
 *
 * Notes:
 *
 *	Since the current state from each of the LFSRs is used to skip
 *	state in the other, it is important that no state be leaked
 *	from either LFSR.
 *
 * Requires:
 *
 *	lfsr1 and lfsr2 be valid.
 *
 *	1 <= skipbits <= 31
 */

ISC_LANG_ENDDECLS

#endif /* ISC_LFSR_H */
