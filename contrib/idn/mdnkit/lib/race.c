#ifndef lint
static char *rcsid = "$Id: race.c,v 1.1 2002/01/02 02:46:46 marka Exp $";
#endif

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/utf8.h>
#include <mdn/debug.h>
#include <mdn/race.h>
#include <mdn/ace.h>
#include <mdn/util.h>

#ifndef MDN_RACE_PREFIX
#define MDN_RACE_PREFIX		"bq--"
#endif
#define RACE_2OCTET_MODE	0xd8
#define RACE_ESCAPE		0xff
#define RACE_ESCAPE_2ND		0x99

#define RACE_BUF_SIZE		128		/* more than enough */

/*
 * Unicode surrogate pair.
 */
#define IS_SURROGATE_HIGH(v)	(0xd800 <= (v) && (v) <= 0xdbff)
#define IS_SURROGATE_LOW(v)	(0xdc00 <= (v) && (v) <= 0xdfff)
#define SURROGATE_HIGH(v)	(SURROGATE_H_OFF + (((v) - 0x10000) >> 10))
#define SURROGATE_LOW(v)	(SURROGATE_L_OFF + ((v) & 0x3ff))
#define SURROGATE_BASE		0x10000
#define SURROGATE_H_OFF		0xd800
#define SURROGATE_L_OFF		0xdc00
#define COMBINE_SURROGATE(h, l) \
	(SURROGATE_BASE + (((h)-SURROGATE_H_OFF)<<10) + ((l)-SURROGATE_L_OFF))

/*
 * Compression type.
 */
enum {
	compress_one,	/* all characters are in a single row */
	compress_two,	/* row 0 and another row */
	compress_none	/* nope */
};

static mdn_result_t	race_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	race_decode_decompress(const char *from,
					       size_t fromlen,
					       unsigned short *buf,
					       size_t *lenp);
static mdn_result_t	race_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	race_compress_encode(const unsigned short *p,
					     size_t len, int compress_mode,
					     char *to, size_t tolen);
static int		get_compress_mode(unsigned short *p, size_t len);

static mdn__ace_t race_ctx = {
	mdn__ace_prefix,
	MDN_RACE_PREFIX,
	race_encode,
	race_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__race_open(mdn_converter_t ctx, mdn_converter_dir_t dir, void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__race_close(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__race_convert(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir,
		  const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__race_convert(dir=%s,from=\"%s\")\n",
	      dir == mdn_converter_l2u ? "l2u" : "u2l",
	      mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&race_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__race_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
race_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[RACE_BUF_SIZE];
	size_t len, reslen;
	mdn_result_t r;

	/*
	 * Allocate sufficient buffer.
	 */
	if (fromlen + 1 > RACE_BUF_SIZE) {
		if ((buf = malloc(sizeof(*buf) * (fromlen + 1))) == NULL)
			return (mdn_nomemory);
	} else {
		/* Use local buffer. */
		buf = local_buf;
	}

	/*
	 * Decode base32 and decompress.
	 */
	r = race_decode_decompress(from, fromlen, buf, &len);
	if (r != mdn_success)
		goto ret;

	/*
	 * Now 'buf' points the decompressed string, which must contain
	 * UTF-16 characters.
	 */

	/*
	 * Convert to UTF-8.
	 */
	r = mdn_util_utf16toutf8(buf, len, to, tolen, &reslen);
	if (r != mdn_success)
		goto ret;

	if (tolen <= reslen) {
		r = mdn_buffer_overflow;
		goto ret;
	}
	*(to + reslen) = '\0';

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
race_decode_decompress(const char *from, size_t fromlen,
		       unsigned short *buf, size_t *lenp)
{
	unsigned short *p = buf;
	unsigned int bitbuf = 0;
	int bitlen = 0;
	int i, j;
	size_t len;

	while (fromlen-- > 0) {
		int c = *from++;
		int x;

		if ('a' <= c && c <= 'z')
			x = c - 'a';
		else if ('A' <= c && c <= 'Z')
			x = c - 'A';
		else if ('2' <= c && c <= '7')
			x = c - '2' + 26;
		else
			return (mdn_invalid_encoding);

		bitbuf = (bitbuf << 5) + x;
		bitlen += 5;
		if (bitlen >= 8) {
			*p++ = (bitbuf >> (bitlen - 8)) & 0xff;
			bitlen -= 8;
		}
	}
	len = p - buf;

	/*
	 * The number of unused bits MUST be 4 or less, and all the
	 * bits MUST be zero.
	 */
	if (bitlen >= 5 || (bitbuf & ((1 << bitlen) - 1)) != 0)
		return (mdn_invalid_encoding);

	/*
	 * Now 'buf' holds the decoded string.
	 */

	/*
	 * RACE doesn't permit an input string with only one octet
	 * (RACE_2OCTET_MODE or a higher octet only).
	 */
	if (len <= 1)
		return (mdn_invalid_encoding);

	/*
	 * Decompress.
	 */
	if (buf[0] == RACE_2OCTET_MODE) {
		if ((len - 1) % 2 != 0)
			return (mdn_invalid_encoding);
		for (i = 1, j = 0; i < len; i += 2, j++)
			buf[j] = (buf[i] << 8) + buf[i + 1];
		len = j;
	} else {
		unsigned short c = buf[0] << 8;	/* higher octet */

		for (i = 1, j = 0; i < len; j++) {
			if (buf[i] == RACE_ESCAPE) {
				if (i + 1 >= len)
					return (mdn_invalid_encoding);
				else if (buf[i + 1] == RACE_ESCAPE_2ND)
					buf[j] = c | 0xff;
				else
					buf[j] = buf[i + 1];
				i += 2;

			} else if (buf[i] == 0x99 && c == 0x00) {
				/*
				 * The RACE specification says this is error.
				 */
				return (mdn_invalid_encoding);
				 
			} else {
				buf[j] = c | buf[i++];
			}
		}
		len = j;
	}
	*lenp = len;
	return (mdn_success);
}

static mdn_result_t
race_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *p, *buf;
	unsigned short local_buf[RACE_BUF_SIZE];	/* UTF-16 */
	mdn_result_t r;
	size_t len, buflen;
	int compress_mode;
	int i;

	/*
	 * Convert to UTF-16.
	 * Preserve space for a character at the top of the buffer.
	 */
	buf = local_buf;
	buflen = RACE_BUF_SIZE;
	for (;;) {
		r = mdn_util_utf8toutf16(from, fromlen,
					 buf + 1, buflen - 1, &len);
		if (r == mdn_buffer_overflow) {
			buflen *= 2;
			if (buf == local_buf)
				buf = malloc(sizeof(*buf) * buflen);
			else
				buf = realloc(buf, sizeof(*buf) * buflen);
			if (buf == NULL)
				return (mdn_nomemory);
		} else if (r == mdn_success) {
			break;
		} else {
			goto ret;
		}
	}
	p = buf + 1;

	/*
	 * Now 'p' contains UTF-16 encoded string.
	 */

	/*
	 * Check U+0099. 
	 * RACE doesn't permit U+0099 in an input string.
	 */
	for (i = 0; i < len; i++) {
		if (p[i] == 0x0099) {
			r = mdn_invalid_encoding;
			goto ret;
		}
	}

	/*
	 * Compress, encode in base-32 and output.
	 */
	compress_mode = get_compress_mode(p, len);
	r = race_compress_encode(buf, len + 1, compress_mode, to, tolen);

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
race_compress_encode(const unsigned short *p, size_t len, int compress_mode,
		     char *to, size_t tolen)
{
	unsigned long bitbuf = 0;	/* bit stream buffer */
	int bitlen = 0;			/* # of bits in 'bitbuf' */
	int i;

	for (i = 0; i <= len; i++) {
		if (i == len) {
			/* End of data.  Flush. */
			if (bitlen == 0)
				break;
			bitbuf <<= (5 - bitlen);
			bitlen = 5;
		} else if (i == 0) {
			/* Output the first octet (U1 or 0xd8). */
			bitbuf = p[0];
			bitlen = 8;
		} else if (compress_mode == compress_none) {
			/* Push 16 bit data. */
			bitbuf = (bitbuf << 16) | p[i];
			bitlen += 16;
		} else {/* compress_mode == compress_one/compress_two */
			/* Push 8 or 16 bit data. */
			if (compress_mode == compress_two &&
			    (p[i] & 0xff00) == 0) {
				/* Upper octet is zero (and not U1). */
				bitbuf = (bitbuf << 16) | 0xff00 | p[i];
				bitlen += 16;
			} else if ((p[i] & 0xff) == 0xff) {
				/* Lower octet is 0xff. */
				bitbuf = (bitbuf << 16) |
					(RACE_ESCAPE << 8) | RACE_ESCAPE_2ND;
				bitlen += 16;
			} else {
				/* Just output lower octet. */
				bitbuf = (bitbuf << 8) | (p[i] & 0xff);
				bitlen += 8;
			}
		}

		/*
		 * Output bits in 'bitbuf' in 5-bit unit.
		 */
		while (bitlen >= 5) {
			int x;

			/* Get top 5 bits. */
			x = (bitbuf >> (bitlen - 5)) & 0x1f;
			bitlen -= 5;

			/* Encode. */
			if (x < 26)
				x += 'a';
			else
				x = (x - 26) + '2';

			if (tolen < 1)
				return (mdn_buffer_overflow);

			*to++ = x;
			tolen--;
		}
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static int
get_compress_mode(unsigned short *p, size_t len) {
	int zero = 0;
	unsigned int upper = 0;
	int i;

	for (i = 0; i < len; i++) {
		unsigned int hi = p[i] & 0xff00;

		if (hi == 0) {
			zero++;
		} else if (hi == upper) {
			;
		} else if (upper == 0) {
			upper = hi;
		} else {
			p[-1] = RACE_2OCTET_MODE;
			return (compress_none);
		}
	}
	p[-1] = upper >> 8;
	if (upper > 0 && zero > 0)
		return (compress_two);
	else
		return (compress_one);
}


