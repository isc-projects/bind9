#ifndef lint
static char *rcsid = "$Id: lace.c,v 1.1 2002/01/02 02:46:42 marka Exp $";
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
#include <mdn/lace.h>
#include <mdn/ace.h>
#include <mdn/util.h>

#ifndef MDN_LACE_PREFIX
#define MDN_LACE_PREFIX		"lq--"
#endif

#define LACE_MAX_COMPRESS_LEN	254		/* max run length */
#define LACE_BUF_SIZE		128		/* more than enough */

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

static mdn__ace_t lace_ctx = {
	mdn__ace_prefix,
	MDN_LACE_PREFIX,
	lace_encode,
	lace_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__lace_open(mdn_converter_t ctx, mdn_converter_dir_t dir, void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__lace_close(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__lace_convert(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir,
		  const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__lace_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&lace_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__lace_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
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
	if (fromlen + 1 > LACE_BUF_SIZE) {
		if ((buf = malloc(sizeof(*buf) * (fromlen + 1))) == NULL)
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
	*(to + reslen) = '\0';

	/*
	 * Encode the result, and compare the result with `from', in
	 * order to test whether an input string is encoded correctly.
	 * If `from' was encoded with wrong compression mode, we return
	 * `mdn_invalid_encoding'.
	 */
	r = lace_encode(to, reslen, (char *)buf, fromlen + 1);
	if (r != mdn_success)
		goto ret;
	if (!mdn_util_casematch((char *)buf, from, fromlen)) {
		r = mdn_invalid_encoding;
		goto ret;
	}

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

	len = p - buf;

	if (len == 0)
		return (mdn_invalid_encoding);

	/*
	 * The number of unused bits MUST be 4 or less, and all the
	 * bits MUST be zero.
	 */
	if (bitlen >= 5 || (bitbuf & ((1 << bitlen) - 1)) != 0)
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
				if (count == 0 ||
				    count > LACE_MAX_COMPRESS_LEN)
					return (mdn_invalid_encoding);
				high = p[1] << 8;
				p += 2;
				len -= 2;
			}
			*q = high | *p;
			count--;
		}
		if (count != 0)
			return (mdn_invalid_encoding);
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
	int count = 0;
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
			if (count == 0) {
				/*
				 * Get the number of consecutive characters
				 * with the same high byte.
				 */
				unsigned short high = p[i] & 0xff00;

				count = 1;
				for (j = i + 1;
				     j < len && count < LACE_MAX_COMPRESS_LEN;
				     j++) {
					if ((p[j] & 0xff00) != high)
						break;
					count++;
				}
				bitbuf = (bitbuf << 16) | (count << 8) |
					(high >> 8);
				bitlen += 16;
			}
			bitbuf = (bitbuf << 8) | (p[i] & 0xff);
			bitlen += 8;
			count--;
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
