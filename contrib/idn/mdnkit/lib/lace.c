#ifndef lint
static char *rcsid = "$Id: lace.c,v 1.4 2000/11/22 01:52:18 ishisone Exp $";
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
 * a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
 * Tokyo, Japan.
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
#include <mdn/lace.h>
#include <mdn/util.h>

#ifdef DEBUG
/* Be paranoid. */
#define PARANOID
#endif

#ifndef MDN_LACE_PREFIX
#define MDN_LACE_PREFIX		"bq--"
#endif
#define LACE_PREFIX_LEN		(strlen(MDN_LACE_PREFIX))

#define LACE_BUF_SIZE		128		/* more than enough */

static mdn_result_t	lace_l2u(const char *from, const char *end,
				 char *to, size_t tolen, size_t *clenp);
static mdn_result_t	lace_u2l(const char *from, const char *end,
				 char *to, size_t tolen, size_t *clenp);
static mdn_result_t	lace_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	lace_decode_utf16(const char *from, size_t fromlen,
					  unsigned short *buf, size_t *lenp);
static mdn_result_t	lace_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	lace_encode_utf16(const unsigned short *p,
					  size_t len, char *to, size_t tolen,
					  int compress);
static int		is_compress_effective(unsigned short *p, size_t len);

/* ARGSUSED */
mdn_result_t
mdn__lace_open(mdn_converter_t ctx, mdn_converter_dir_t dir) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__lace_close(mdn_converter_t ctx, mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__lace_convert(mdn_converter_t ctx, mdn_converter_dir_t dir,
		    const char *from, char *toorg, size_t tolen)
{
	char *to = toorg;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__lace_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	for (;;) {
		const char *end;
		size_t convlen;
		mdn_result_t r;

		/*
		 * Find the end of this component (label).
		 */
		if ((end = strchr(from, '.')) == NULL)
			end = from + strlen(from);

		/*
		 * Convert it.
		 */
		if (dir == mdn_converter_l2u)
			r = lace_l2u(from, end, to, tolen, &convlen);
		else
			r = lace_u2l(from, end, to, tolen, &convlen);
		if (r != mdn_success)
			return (r);

		/*
		 * Copy '.' or NUL.
		 */
		if (tolen <= convlen)
			return (mdn_buffer_overflow);

		to += convlen;
		*to++ = *end;
		tolen -= convlen + 1;

		if (*end == '\0')
			break;

		from = end + 1;
	}

	DUMP(("mdn__lace_convert: \"%s\"\n", mdn_debug_xstring(toorg, 70)));

	return (mdn_success);
}

static mdn_result_t
lace_l2u(const char *from, const char *end,
	 char *to, size_t tolen, size_t *clenp)
{
	size_t len = end - from;
	size_t prefix_len = LACE_PREFIX_LEN;

	if (len >= prefix_len &&
	    mdn_util_casematch(from, MDN_LACE_PREFIX, prefix_len)) {
		/*
		 * LACE encoding prefix found.
		 */
		mdn_result_t r;

		r = lace_decode(from + prefix_len,
				len - prefix_len, to, tolen);
		if (r == mdn_invalid_encoding)
			goto copy;
		else if (r != mdn_success)
			return (r);

		len = strlen(to);
	} else {
		/*
		 * Not LACE encoded.  Copy verbatim.
		 */
	copy:
		if (mdn_util_domainspan(from, end) < end) {
			/* invalid character found */
			return (mdn_invalid_encoding);
		}

		if (tolen < len)
			return (mdn_buffer_overflow);

		(void)memcpy(to, from, len);
	}
	*clenp = len;
	return (mdn_success);
}

static mdn_result_t
lace_u2l(const char *from, const char *end,
	   char *to, size_t tolen, size_t *clenp) {
	size_t len = end - from;
	size_t prefix_len = LACE_PREFIX_LEN;

	/*
	 * See if encoding is necessary.
	 */
	if (mdn_util_domainspan(from, end) < end) {
		/*
		 * Conversion is necessary.
		 */
		mdn_result_t r;

		/* Set prefix. */
		if (tolen < prefix_len)
			return (mdn_buffer_overflow);
		(void)memcpy(to, MDN_LACE_PREFIX, prefix_len);
		to += prefix_len;
		tolen -= prefix_len;

		r = lace_encode(from, len, to, tolen);
		if (r != mdn_success)
			return (r);

		len = prefix_len + strlen(to);
	} else {
		/*
		 * Conversion is NOT necessary.
		 * Copy verbatim.
		 */
		if (tolen < len)
			return (mdn_buffer_overflow);

		(void)memcpy(to, from, len);
	}
	*clenp = len;
	return (mdn_success);
}

static mdn_result_t
lace_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[LACE_BUF_SIZE];
	size_t len, reslen;
	mdn_result_t r;

	/*
	 * Allocate sufficient buffer.
	 */
	if (fromlen > LACE_BUF_SIZE) {
		if ((buf = malloc(sizeof(*buf) * fromlen)) == NULL)
			return (mdn_nomemory);
	} else {
		/* Use local buffer. */
		buf = local_buf;
	}

	/*
	 * Decode base32 and decompress.
	 */
	r = lace_decode_utf16(from, fromlen, buf, &len);
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
lace_decode_utf16(const char *from, size_t fromlen,
		  unsigned short *buf, size_t *lenp)
{
	unsigned short *p, *q;
	unsigned int bitbuf = 0;
	int bitlen = 0;
	size_t len;

	/*
	 * Decode Base32 and put the result bytes to 'buf'.
	 * Since decoded string will be shorter in length, and
	 * the caller allocated 'buf' so that its length is not
	 * less than 'fromlen', we don't have to worry about overflow.
	 */
	p = buf;
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
#ifdef PARANOID
	/* Check if the padding bits are all zero. */
	if (bitlen > 0 && (bitbuf & ((1 << bitlen) - 1)) != 0) {
		WARNING(("mdn__lace_convert: non-zero padding\n"));
		return (mdn_invalid_encoding);
	}
#endif
	len = p - buf;

	if (len == 0)
		return (mdn_invalid_encoding);

	/*
	 * Now 'buf' holds the decoded bytes.  Rebuild the
	 * original UTF-16 string.
	 */
	if (buf[0] == 0xff) {
		/*
		 * Not compressed.
		 */
		len--;	/* skip first byte (0xff) */
		if (len % 2 != 0) {
			/* number of bytes must be even. */
			return (mdn_invalid_encoding);
		}
		for (p = buf + 1, q = buf; len > 0; p += 2, q++, len -= 2) {
			*q = (p[0] << 8) | p[1];
		}
#ifdef PARANOID
		if (is_compress_effective(buf, q - buf)) {
			/*
			 * This string must have been compressed.
			 */
			WARNING(("mdn__lace_convert: decoded string is not "
				 "compressed, though it should be.\n"));
			return (mdn_invalid_encoding);
		}
#endif
	} else {
		/*
		 * Compressed.
		 */
		int count = 0;
		unsigned short high = 0;	/* initialize for lint */

		for (p = q = buf; len > 0; p++, q++, len--) {
			if (count == 0) {
				if (len < 3 || p[0] == 0)
					return (mdn_invalid_encoding);
				/* Get COUNT and HIGH. */
				count = p[0];
				high = p[1] << 8;
				p += 2;
				len -= 2;
			}
			*q = high | *p;
			count--;
		}
		if (count != 0)
			return (mdn_invalid_encoding);
#ifdef PARANOID
		if (!is_compress_effective(buf, q - buf)) {
			/*
			 * This string must not have been compressed.
			 */
			WARNING(("mdn__lace_convert: decoded string is "
				 "compressed, though it shouldn't.\n"));
			return (mdn_invalid_encoding);
		}
#endif
	}

	*lenp = q - buf;
	return (mdn_success);
}

static mdn_result_t
lace_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[LACE_BUF_SIZE];	/* UTF-16 */
	mdn_result_t r;
	size_t buflen, len;

	/*
	 * Convert to UTF-16.
	 */
	buf = local_buf;
	buflen = LACE_BUF_SIZE;
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
	r = lace_encode_utf16(buf, len, to, tolen,
			      is_compress_effective(buf, len));

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
lace_encode_utf16(const unsigned short *p, size_t len,
		  char *to, size_t tolen, int compress)
{
	unsigned long bitbuf = 0;	/* bit stream buffer */
	int bitlen = 0;			/* # of bits in 'bitbuf' */
	int compress_count = 0;
	int i, j;

	if (!compress) {
		/* prepend non-compression mark */
		bitbuf = 0xff;
		bitlen = 8;
	}

	for (i = 0; i <= len; i++) {
		if (i == len) {
			/*
			 * End of data.  Flush.  The current draft (-00)
			 * doesn't seem to define which value to use for
			 * padding (which it should).  We assume zero.
			 */
			if (bitlen % 5 == 0)
				break;
			bitbuf <<= 5 - (bitlen % 5);	/* padding with zero */
			bitlen += 5 - (bitlen % 5);
		} else if (compress) {
			if (compress_count == 0) {
				/*
				 * Get the number of consecutive characters
				 * with the same high byte.
				 */
				unsigned short high = p[i] & 0xff00;

				compress_count = 1;
				for (j = i + 1; j < len; j++) {
					if ((p[j] & 0xff00) != high)
						break;
					compress_count++;
				}
				bitbuf = (bitbuf << 16) |
					(compress_count << 8) |
					(high >> 8);
				bitlen += 16;
			}
			bitbuf = (bitbuf << 8) | (p[i] & 0xff);
			bitlen += 8;
			compress_count--;
		} else {
			bitbuf = (bitbuf << 16) | p[i];
			bitlen += 16;
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
is_compress_effective(unsigned short *p, size_t len) {
	unsigned short last_high = 0x1;	/* initialize with an invalid value */
	int nhigh = 0;
	int i;

	/*
	 * Find the number of HIGH value in the compressed string.
	 */
	for (i = 0; i < len; i++) {
		unsigned short high = p[i] & 0xff00;
		if (high != last_high)
			nhigh++;
		last_high = high;
	}

	/*
	 * Compressed string would take 2 * 'nhigh' + 'len' bytes,
	 * while the original (uncomressed) string would take 2 * 'len'.
	 * So the difference is 2 * 'nhigh' - len.
	 */
	if (2 * nhigh <= len)
		return (1);	/* Compression is effective. */
	else
		return (0);	/* Nope. */
}
