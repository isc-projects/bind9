/*
 * Portions Copyright (C) 1999, 2000  Internet Software Consortium.
 * Portions Copyright (C) 1995-2000 by Network Associates, Inc.
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
 * $Id: dst_support.c,v 1.7 2000/06/09 20:58:35 gson Exp $
 */

#include <config.h>

#include <stdlib.h>

#include "dst_internal.h"

/*
 * dst__id_calc
 *	Calculates the checksum used by DNS as a key id.
 * Parameters
 *	key	The key in DNS format
 *	length	The length of the array
 * Return
 *	N	the 16 bit checksum.
 */
isc_uint16_t
dst__id_calc(const unsigned char *key, const int keysize) {
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
