/*
 * Portions Copyright (c) 1995-1999 by Network Associates, Inc.
 * Portions Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM AND
 * NETWORK ASSOCIATES DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE CONSORTIUM OR NETWORK
 * ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: dst_support.c,v 1.5 2000/05/15 21:02:34 bwelling Exp $
 */

#include <config.h>

#include <stdio.h>

#include <isc/string.h>

#include "dst_internal.h"

/*
 * dst_s_calculate_bits
 *	Given a binary number represented by a u_char[], determine
 *	the number of significant bits used.
 * Parameters
 *	str		An input character string containing a binary number.
 *	max_bits	The maximum possible significant bits.
 * Return
 *	N		The number of significant bits in str.
 */

int
dst_s_calculate_bits(const unsigned char *str, const int max_bits) {
	const unsigned char *p = str;
	unsigned char i, j = 0x80;
	int bits;
	for (bits = max_bits; *p == 0x00 && bits > 0; p++)
		bits -= 8;
	for (i = *p; (i & j) != j; j >>= 1)
		bits--;
	return (bits);
}


/*
 * dst_s_id_calc
 *	Calculates the checksum used by DNS as a key id.
 * Parameters
 *	key	The key in DNS format
 *	length	The length of the array
 * Return
 *	N	the 16 bit checksum.
 */
isc_uint16_t
dst_s_id_calc(const unsigned char *key, const int keysize) {
	isc_uint32_t ac;
	const unsigned char *kp = key;
	int size = keysize;

	if (key == NULL || (keysize <= 0))
		return (-1);
 
	for (ac = 0; size > 1; size -= 2, kp += 2)
		ac += ((*kp) << 8) + *(kp + 1);

	if (size > 0)
		ac += ((*kp) << 8);
	ac += (ac >> 16) & 0xffff;

	return ((isc_uint16_t)(ac & 0xffff));
}
