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

#ifndef ISC_BITSTRING_H
#define ISC_BITSTRING_H 1

/*****
 ***** Module Info
 *****/

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/***
 *** Types
 ***/

struct isc_bitstring {
	unsigned int		magic;
	unsigned char *		data;
	unsigned int		length;
	unsigned int		size;
	isc_boolean_t		lsb0;
};

/***
 *** Functions
 ***/

void
isc_bitstring_init(isc_bitstring_t *bitstring, unsigned char *data,
		   unsigned int length, unsigned int size, isc_boolean_t lsb0);
/*
 * Make 'bitstring' refer to the bitstring of 'size' bits starting
 * at 'data'.  'length' bits of the bitstring are valid.  If 'lsb0'
 * is set then, bit 0 refers to the least significant bit of the
 * bitstring.  Otherwise bit 0 is the most significant bit.
 *
 * Requires:
 *
 *	'bitstring' points to a isc_bitstring_t.
 *
 *	'data' points to an array of unsigned char large enough to hold
 *	'size' bits.
 *
 *	'length' <= 'size'.
 *
 * Ensures:
 *
 *	'bitstring' is a valid bitstring.
 */

void
isc_bitstring_invalidate(isc_bitstring_t *bitstring);
/*
 * Invalidate 'bitstring'.
 *
 * Requires:
 *
 *	'bitstring' is a valid bitstring.
 *
 * Ensures:
 *
 *	'bitstring' is not a valid bitstring.
 */

void
isc_bitstring_copy(isc_bitstring_t *source, unsigned int sbitpos,
		   isc_bitstring_t *target, unsigned int tbitpos,
		   unsigned int n);
/*
 * Starting at bit 'sbitpos', copy 'n' bits from 'source' to
 * the 'n' bits of 'target' starting at 'tbitpos'.
 *
 * Requires:
 *
 *	'source' and target are valid bitstring.
 *
 *	'sbitpos' + 'n' is less than or equal to the length of 'source'.
 *
 *	'tbitpos' + 'n' is less than or equal to the size of 'target'.
 *
 * Ensures:
 *
 *	The specified bits have been copied, and the length of 'target'
 *	adjusted (if required).
 */

ISC_LANG_ENDDECLS

#endif /* ISC_BITSTRING_H */
