#ifndef lint
static char *rcsid = "$Id: utf6.c,v 1.1.2.1 2002/02/08 12:14:35 marka Exp $";
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
#include <mdn/utf6.h>
#include <mdn/ace.h>
#include <mdn/util.h>

#ifndef MDN_UTF6_PREFIX
#define MDN_UTF6_PREFIX		"wq--"
#endif

#define UTF6_SAME_BYTE_MASK	0x00ff
#define UTF6_SAME_NIBBLE_MASK	0x0fff
#define UTF6_PLAIN_MASK		0xffff

#define UTF6_BUF_SIZE		128		/* more than enough */

/*
 * Compression type.
 */
enum {
	same_byte_mode,		/* the most significant byte of all non
				   '-' characters is the same value */
	same_nibble_mode,	/* the most significant nibble of all non
				   '-' characters is the same value */
	plain_mode		/* not compressed */
};

static mdn_result_t	utf6_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	utf6_decode_utf16(const char *from, size_t fromlen,
					  unsigned short *buf, size_t *lenp);
static mdn_result_t	utf6_decode_vlhex(const char *from, size_t len,
					  size_t *reslen,
					  unsigned short *value);
static mdn_result_t	utf6_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	utf6_encode_utf16(const unsigned short *p,
					  size_t len, char *to, size_t tolen,
					  int compress);
static mdn_result_t	utf6_encode_vlhex(unsigned short value, char *to,
					  size_t tolen, size_t *reslen);
static int		get_compress_mode(const unsigned short *p, size_t len);

static mdn__ace_t utf6_ctx = {
	mdn__ace_prefix,
	MDN_UTF6_PREFIX,
	utf6_encode,
	utf6_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__utf6_open(mdn_converter_t ctx, mdn_converter_dir_t dir, void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__utf6_close(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__utf6_convert(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir,
		    const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__utf6_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&utf6_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__utf6_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
utf6_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[UTF6_BUF_SIZE];
	size_t len, reslen;
	mdn_result_t r;

	/*
	 * Allocate sufficient buffer.
	 */
	if (fromlen > UTF6_BUF_SIZE) {
		if ((buf = malloc(sizeof(*buf) * fromlen)) == NULL)
			return (mdn_nomemory);
	} else {
		/* Use local buffer. */
		buf = local_buf;
	}

	/*
	 * Decode base32 and decompress.
	 */
	r = utf6_decode_utf16(from, fromlen, buf, &len);
	if (r != mdn_success)
		goto ret;

	/*
	 * Now 'buf' holds the decompressed string, which must contain
	 * UTF-16 characters.  Convert them into UTF-8.
	 */
	r = mdn_util_utf16toutf8(buf, len, to, tolen, &reslen);
	if (r != mdn_success)
		goto ret;

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= reslen) {
		r = mdn_buffer_overflow;
		goto ret;
	}

	to += reslen;
	*to = '\0';
	tolen -= reslen;

	r = mdn_success;

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
utf6_decode_utf16(const char *from, size_t fromlen,
		  unsigned short *buf, size_t *lenp)
{
	mdn_result_t r;
	unsigned short value;
	unsigned short cpart;
	unsigned short vmax;
	size_t len;
	size_t reslen;

	/*
	 * Decode Base32 and put the result bytes to 'buf'.
	 * Since decoded string will be shorter in length, and
	 * the caller allocated 'buf' so that its length is not
	 * less than 'fromlen', we don't have to worry about overflow.
	 */

	if (fromlen <= 0)
	    return mdn_success;

	switch (*from) {
	case 'y':
	case 'Y':
		/*
		 * same_byte_mode.
		 */
		fromlen--;
		from++;
		r = utf6_decode_vlhex(from, fromlen, &reslen, &value);
		if (r != mdn_success)
			return (mdn_invalid_encoding);
		from += reslen;
		fromlen -= reslen;

		cpart = value * 0x0100;
		vmax = 0x00ff;
		break;

	case 'z':
	case 'Z':
		/*
		 * same_nibble_mode.
		 */
		fromlen--;
		from++;
		r = utf6_decode_vlhex(from, fromlen, &reslen, &value);
		if (r != mdn_success)
			return (mdn_invalid_encoding);
		from += reslen;
		fromlen -= reslen;

		cpart = value * 0x1000;
		vmax = 0x0fff;
		break;

	default:
		/*
		 * plain_mode.
		 */
		cpart = 0x0000;
		vmax = 0xffff;
		break;
	}

	
	for (len = 0; fromlen > 0; len++) {
		if (*from == '-') {
			*buf++ = '-';
			from++;
			fromlen--;
		} else {
			r = utf6_decode_vlhex(from, fromlen, &reslen, &value);
			if (r != mdn_success)
				return (mdn_invalid_encoding);
			if (value > vmax)
				return (mdn_invalid_encoding);
			*buf++ = cpart + value;
			from += reslen;
			fromlen -= reslen;
		}
	}

	*buf = '\0';
	*lenp = len;
	return (mdn_success);
}

static mdn_result_t
utf6_decode_vlhex(const char *from, size_t len, size_t *reslen,
		  unsigned short *value) {
	unsigned short v;
	int i;

	/*
	 * Decode the first character of a variable length HEX string.
	 * The character must be in set of [ghijklmnopqrstuv].
	 */
	if (len <= 0)
		return (mdn_invalid_encoding);

	if ('G' <= *from && *from <= 'V')
		v = *from - 'G';
	else if ('g' <= *from && *from <= 'v')
		v = *from - 'g';
	else
		return (mdn_invalid_encoding);
	from++;
	len--;
	i = 1;

	/*
	 * Decode the rest characters of a variable length HEX string.
	 * The every character must be in set of [0123456789abcdef].
	 */
	for (;;) {
		if (len <= 0)
			break;
		if ('0' <= *from && *from <= '9')
			v = (v << 4) + (*from - '0');
		else if ('A' <= *from && *from <= 'F')
			v = (v << 4) + 0x0a + (*from - 'A');
		else if ('a' <= *from && *from <= 'f')
			v = (v << 4) + 0x0a + (*from - 'a');
		else
			break;
		from++;
		len--;
		i++;
	}

	*value = v;
	*reslen = i;
	return (mdn_success);
}

static mdn_result_t
utf6_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[UTF6_BUF_SIZE];	/* UTF-16 */
	mdn_result_t r;
	size_t buflen, len;

	/*
	 * Convert to UTF-16.
	 */
	buf = local_buf;
	buflen = UTF6_BUF_SIZE;
	for (;;) {
		r = mdn_util_utf8toutf16(from, fromlen,
					 buf, buflen, &len);
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

	/*
	 * Compress, encode in base-32 and output.
	 */
	r = utf6_encode_utf16(buf, len, to, tolen,
			      get_compress_mode(buf, len));

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
utf6_encode_utf16(const unsigned short *p, size_t len,
		  char *to, size_t tolen, int compress_mode)
{
	mdn_result_t r;
	unsigned short mask;
	size_t reslen;
	int i;

	if (len <= 0)
	    return mdn_success;

	switch (compress_mode) {
	case same_byte_mode:
		mask = UTF6_SAME_BYTE_MASK;

		if (tolen < 1)
			return (mdn_buffer_overflow);
		*to++ = 'y';
		tolen--;
		r = utf6_encode_vlhex((p[0] >> 8) & 0x00ff, to, tolen,
				      &reslen);
		if (r != mdn_success)
			return (r);
		to += reslen;
		tolen -= reslen;

		break;

	case same_nibble_mode:
		mask = UTF6_SAME_NIBBLE_MASK;

		if (tolen < 1)
			return (mdn_buffer_overflow);
		*to++ = 'z';
		tolen--;
		r = utf6_encode_vlhex((p[0] >> 4) & 0x0fff, to, tolen,
				      &reslen);
		if (r != mdn_success)
			return (r);
		to += reslen;
		tolen -= reslen;

		break;

	default:
		mask = UTF6_PLAIN_MASK;
		break;
	}

	for (i = 0; i < len; i++) {
		if (p[i] == '-') {
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to++ = '-';
			tolen--;
			
		} else {
			r = utf6_encode_vlhex(p[i] & mask, to, tolen, &reslen);
			if (r != mdn_success)
				return (r);
			to += reslen;
			tolen -= reslen;
		}
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
utf6_encode_vlhex(unsigned short value, char *to, size_t tolen,
		  size_t *reslen) {

	static const char *vlhex_string1 = "ghijklmnopqrstuv";
	static const char *vlhex_string2 = "0123456789abcdef";

	/*
	 * Encode an integer in the range of 0x000 - 0xffff as variable
	 * length HEX string.
	 */
	if (value <= 0x000f) {
		if (tolen < 1)
			return (mdn_buffer_overflow);
		*to++ = vlhex_string1[ value        & 0x0f];
		*reslen = 1;

	} else if (value <= 0x00ff) {
		if (tolen < 2)
			return (mdn_buffer_overflow);
		*to++ = vlhex_string1[(value >> 4)  & 0x0f];
		*to++ = vlhex_string2[ value        & 0x0f];
		*reslen = 2;

	} else if (value <= 0x0fff) {
		if (tolen < 3)
			return (mdn_buffer_overflow);
		*to++ = vlhex_string1[(value >> 8)  & 0x0f];
		*to++ = vlhex_string2[(value >> 4)  & 0x0f];
		*to++ = vlhex_string2[ value        & 0x0f];
		*reslen = 3;

	} else {
		if (tolen < 4)
			return (mdn_buffer_overflow);
		*to++ = vlhex_string1[(value >> 12) & 0x0f];
		*to++ = vlhex_string2[(value >> 8)  & 0x0f];
		*to++ = vlhex_string2[(value >> 4)  & 0x0f];
		*to++ = vlhex_string2[ value        & 0x0f];
		*reslen = 4;
	}

	return (mdn_success);
}

static int
get_compress_mode(const unsigned short *p, size_t len) {
	int non_hyphens = 0;
	unsigned short same_bytes = 0;
	unsigned short same_nibbles = 0;
	int i;

	if (len <= 0)
		return plain_mode;

	for (i = 0; i < len; i++) {
		if (p[i] != '-') {
			non_hyphens++;
			if ((p[0] & 0xff00) == (p[i] & 0xff00))
				same_bytes++;
			else if ((p[0] & 0xf000) == (p[i] & 0xf000))
				same_nibbles++;
		}
	}

	if (non_hyphens < 2) {
		/*
		 * The number of non '-' characters is less than 2.
		 */
		return plain_mode;
	} else if (same_bytes == non_hyphens) {
		/*
		 * The same most significant byte of the every non '-'
		 * character is the same value.
		 */
		return same_byte_mode;
	} else if (same_nibbles == non_hyphens) {
		/*
		 * The same most significant nibble of the every non '-'
		 * character is the same value.
		 */
		return same_nibble_mode;
	} else {
		/*
		 * Not matched above.
		 */
		return plain_mode;
	}

	/* Not reached */	
}
