/*
 * Portions Copyright (c) 1995-1999 by Network Associates, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND NETWORK ASSOCIATES
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * NETWORK ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: dst_support.c,v 1.3 1999/11/02 19:52:29 bwelling Exp $
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <isc/int.h>

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
dst_s_calculate_bits(const unsigned char *str, const int max_bits)
{
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
dst_s_id_calc(const unsigned char *key, const int keysize)
{
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

/*
 *  dst_s_build_filename
 *	Builds a key filename from the key name, its id, and a
 *	suffix.  '\', '/' and ':' are not allowed. fA filename is of the
 *	form:  K<keyname><id>.<suffix>
 *	form: K<keyname>+<alg>+<id>.<suffix>
 *
 *	Returns -1 if the conversion fails:
 *	  if the filename would be too long for space allotted
 *	  if the filename would contain a '\', '/' or ':'
 *	Returns 0 on success
 */

int
dst_s_build_filename(char *filename, const char *name, isc_uint16_t id,
		     int alg, const char *suffix, size_t filename_length)
{
	isc_uint32_t my_id;
	char *dot;
	if (filename == NULL)
		return (-1);
	memset(filename, 0, filename_length);
	if (name == NULL)
		return (-1);
	if (suffix == NULL)
		return (-1);
	if (filename_length < 1 + strlen(name) + 1 + 4 + 6 + 1 + strlen(suffix))
		return (-1);
	my_id = id;
	if (name[strlen(name) - 1] == '.')
		dot = "";
	else
		dot = ".";
	sprintf(filename, "K%s%s+%03d+%05d.%s", name, dot, alg, my_id,
		(char *) suffix);
	if (strrchr(filename, '/'))
		return (-1);
	if (strrchr(filename, '\\'))
		return (-1);
	if (strrchr(filename, ':'))
		return (-1);
	return (0);
}
