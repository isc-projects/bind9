#ifndef lint
static char *rcsid = "$Id: brace.c,v 1.1 2002/01/02 02:46:40 marka Exp $";
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
#include <mdn/brace.h>
#include <mdn/ace.h>
#include <mdn/util.h>

#ifndef MDN_BRACE_SUFFIX
#define MDN_BRACE_SUFFIX		"-8q9"
#endif
#define BRACE_BUF_SIZE		128		/* more than enough */
#define BRACE_BASE32(n)		(brace_base32[n])
#define BRACE_RBASE32(c)	(brace_rbase32(c))

#define IS_LDH(c) \
	(('a' <= (c) && (c) <= 'z') || ('A' <= (c) && (c) <= 'Z') || \
	 ('0' <= (c) && (c) <= '9') || (c) == '-')

/*
 * Encoding Styles.
 */
enum {
	half_row_style,	/* all non-LDH characters are in a single half row */
	full_row_style,	/* all non-LDH characters are in a single row */
	mixed_style,	
	no_row_style
};

/*
 * Base-32 encoding array.
 */
static char brace_base32[] = "23456789abcdefghijkmnpqrstuvwxyz";

static mdn_result_t	brace_decode(const char *from, size_t fromlen,
				     char *to, size_t tolen);
static mdn_result_t	brace_decode_utf16(const char *from,
					   size_t fromlen,
					   unsigned short *buf,
					   size_t *lenp);
static mdn_result_t	brace_encode(const char *from, size_t fromlen,
				     char *to, size_t tolen);
static mdn_result_t	brace_encode_utf16(const unsigned short *p, size_t len,
					   char *to, size_t tolen,
					   int encoding_style,
					   unsigned short row);
static mdn_result_t	get_encoding_style(unsigned short *p, size_t len,
					   int *stylep, unsigned short *rowp);
static int		brace_rbase32(int c);

static mdn__ace_t brace_ctx = {
	mdn__ace_suffix,
	MDN_BRACE_SUFFIX,
	brace_encode,
	brace_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__brace_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__brace_close(mdn_converter_t ctx, void *privdata,
		 mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__brace_convert(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir, const char *from, char *to,
		   size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__brace_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&brace_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__brace_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
brace_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[BRACE_BUF_SIZE];
	size_t len, reslen;
	mdn_result_t r;

	/*
	 * Allocate sufficient buffer.
	 */
	if (fromlen > BRACE_BUF_SIZE) {
		if ((buf = malloc(sizeof(*buf) * fromlen)) == NULL)
			return (mdn_nomemory);
	} else {
		/* Use local buffer. */
		buf = local_buf;
	}

	/*
	 * Decode into UTF-16 string.
	 */
	r = brace_decode_utf16(from, fromlen, buf, &len);
	if (r != mdn_success)
		goto ret;

	/*
	 * Now 'buf' points the decompressed string, which must contain
	 * UTF-16 characters.
	 */

	/*
	 * Convert to utf-8.
	 */
	r = mdn_util_utf16toutf8(buf, len, to, tolen, &reslen);
	if (r != mdn_success)
		goto ret;
	if (reslen >= tolen) {
		r = mdn_buffer_overflow;
		goto ret;
	}
	to[reslen] = '\0';

	r = mdn_success;

ret:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
brace_decode_utf16(const char *from, size_t fromlen,
		   unsigned short *buf, size_t *lenp)
{
	int encoding_style;
	unsigned short row;
	unsigned long bitbuf = 0;
	int bitlen = 0;
	int literal_mode;
	int i;

#define READ_BITS(n) \
	do { \
		int len = (n); \
		while (bitlen < len) { \
			int x; \
			if (fromlen-- <= 0) \
				return (mdn_invalid_encoding); \
			if ((x = BRACE_RBASE32(*from++)) < 0) \
				return (mdn_invalid_encoding); \
			bitbuf = (bitbuf << 5) | x; \
			bitlen += 5; \
		} \
	} while (0)
#define EXTRACT_BITS(n) \
		(bitlen -= (n), ((bitbuf >> bitlen) & ((1<<(n)) - 1)))

	READ_BITS(2);
	switch (EXTRACT_BITS(2)) {
	case 0:
		encoding_style = half_row_style;
		READ_BITS(9);
		row = EXTRACT_BITS(9) << 7;
		break;
	case 1:
		encoding_style = full_row_style;
		READ_BITS(8);
		row = EXTRACT_BITS(8) << 8;
		break;
	case 2:
		encoding_style = mixed_style;
		READ_BITS(9);
		row = EXTRACT_BITS(9) << 7;
		break;
	case 3:
		encoding_style = no_row_style;
		row = 0;		/* to keep lint happy */
		break;
	default:
		FATAL(("brace_decode_utf16: internal error\n"));
		abort();
		return (mdn_failure);	/* to keep lint happy */
	}

	i = 0;
	literal_mode = 0;
	while (fromlen > 0) {
		int c = *from;	/* peek */

		if (c == '-') {
			if (fromlen > 0 && from[1] == '-') {
				buf[i++] = '-';
				from += 2;
				fromlen -= 2;
			} else {
				literal_mode = !literal_mode;
				from++;
				fromlen--;
			}
		} else if (literal_mode) {
			buf[i++] = c;
			from++;
			fromlen--;
		} else {
			switch (encoding_style) {
			case half_row_style:
				READ_BITS(7);
				buf[i++] = row | EXTRACT_BITS(7);
				break;
			case full_row_style:
				READ_BITS(8);
				buf[i++] = row | EXTRACT_BITS(8);
				break;
			case mixed_style:
				READ_BITS(2);
				if (EXTRACT_BITS(1)) {
					if (EXTRACT_BITS(1)) {
						READ_BITS(16);
						buf[i++] = EXTRACT_BITS(16);
					} else {
						READ_BITS(7);
						buf[i++] = (row ^ 0x80) |
							EXTRACT_BITS(7);
					}
				} else {
					READ_BITS(7);
					buf[i++] = row | EXTRACT_BITS(7);
				}
				break;
			case no_row_style:
				READ_BITS(16);
				buf[i++] = EXTRACT_BITS(16);
				break;
			}
		}
	}

	if (bitlen > 4)
		return (mdn_invalid_encoding);

	*lenp = i;
	return (mdn_success);
#undef READ_BITS
#undef EXTRACT_BITS
}

static mdn_result_t
brace_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned short *buf;
	unsigned short local_buf[BRACE_BUF_SIZE];	/* UTF-16 */
	unsigned short row;
	mdn_result_t r;
	size_t buflen, len;
	int encoding_style;

	/*
	 * Convert to UTF-16.
	 */
	buf = local_buf;
	buflen = BRACE_BUF_SIZE;
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
			goto finish;
		}
	}

	/*
	 * Now 'buf' contains UTF-16 encoded string consisting of
	 * 'len' characters.
	 */

	/*
	 * Choose encoding style.
	 */
	r = get_encoding_style(buf, len, &encoding_style, &row);
	if (r != mdn_success)
		goto finish;

	r = brace_encode_utf16(buf, len, to, tolen, encoding_style, row);

finish:
	if (buf != local_buf)
		free(buf);
	return (r);
}

static mdn_result_t
brace_encode_utf16(const unsigned short *p, size_t len,
		   char *to, size_t tolen,
		   int encoding_style, unsigned short row)
{
	unsigned long bitbuf = 0;	/* bit stream buffer */
	char *save_to;
	int bitlen = 0;			/* # of bits in 'bitbuf' */
	int nonhyphen;
	int i;

#define FLUSH_BITS_1(p) \
	do { \
	        int x = (bitbuf >> (bitlen - 5)) & 0x1f; \
		bitlen -= 5; \
		*p = BRACE_BASE32(x); \
	} while (0)
#define FLUSH_BITS \
	do { \
		while (bitlen >= 5) { \
			if (tolen < 1) \
				return (mdn_buffer_overflow); \
			FLUSH_BITS_1(to); \
			to++, tolen--; \
		} \
	} while (0)
#define PUT(c) \
	do { \
		if (tolen-- < 1) \
			return (mdn_buffer_overflow); \
		*to++ = c; \
	} while (0)

	switch (encoding_style) {
	case half_row_style:
		/* 00xxxxxxxxx */
		bitbuf = row >> 7;
		bitlen = 2 + 9;
		break;
	case full_row_style:
		/* 01xxxxxxxx */
		bitbuf = (1 << 8) | (row >> 8);
		bitlen = 2 + 8;
		break;
	case mixed_style:
		/* 10xxxxxxxxx */
		bitbuf = (1 << 10) | (row >> 7);
		bitlen = 2 + 9;
		break;
	case no_row_style:
		/* 11 */
		bitbuf = 3;
		bitlen = 2;
		break;
	default:
		FATAL(("brace_compress_encode: internal error "
		       "invalid encoding_style\n"));
		abort();
		break;
	}

	FLUSH_BITS;

	if (bitlen > 0) {
		save_to = to++;
		if (tolen-- < 1)
			return (mdn_buffer_overflow);
	} else {
		save_to = NULL;
	}

	nonhyphen = 0;
	for (i = 0; i < len; i++) {
		if (p[i] == 0x2d) {
			PUT('-');
			PUT('-');
		} else if (IS_LDH(p[i])) {
			if (!nonhyphen)
				PUT('-');
			PUT(p[i]);
			nonhyphen = 1;
		} else {
			if (nonhyphen) {
				PUT('-');
			}
			nonhyphen = 0;
			switch (encoding_style) {
			case half_row_style:
				bitlen += 7;
				bitbuf = (bitbuf << 7) | (p[i] & 0x7f);
				break;
			case full_row_style:
				bitlen += 8;
				bitbuf = (bitbuf << 8) | (p[i] & 0xff);
				break;
			case mixed_style:
				if ((p[i] & 0xff80) == row) {
					bitlen += 8;
					bitbuf = (bitbuf << 8) | (p[i] & 0x7f);
				} else if ((p[i] & 0xff80) == (row ^ 0x80)) {
					bitlen += 9;
					bitbuf = (bitbuf << 9) | (1 << 8) |
						(p[i] & 0x7f);
				} else {
					bitlen += 18;
					bitbuf = (bitbuf << 18) | (3 << 16) |
						p[i];
				}
				break;
			case no_row_style:
				bitlen += 16;
				bitbuf = (bitbuf << 16) | p[i];
				break;
			}
			if (save_to != NULL)
				FLUSH_BITS_1(save_to);
			FLUSH_BITS;
			if (bitlen > 0) {
				save_to = to++;
				if (tolen-- < 1)
					return (mdn_buffer_overflow);
			} else {
				save_to = NULL;
			}
		}
	}
	if (bitlen > 0) {
		assert(save_to != NULL && bitlen < 5);
		bitbuf <<= 5 - bitlen;
		bitlen = 5;
		FLUSH_BITS_1(save_to);
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
#undef FLUSH_BITS_1
#undef FLUSH_BITS
#undef PUT
}

static mdn_result_t
get_encoding_style(unsigned short *p, size_t len,
		   int *stylep, unsigned short *rowp)
{
	struct row {
		unsigned short upper;
		unsigned short num;
		unsigned short cmpl;
	} *row_cands, row_cands_buf[64];	/* usually 64 is enough */
	int cands_size = 64;
	int num_cands = 0;
	int num_nonldh = 0;
	int style = no_row_style;		/* to keep lint happy */
	int best;
	int m, m_prime;
	int i, j;

	row_cands = row_cands_buf;

	for (i = 0; i < len; i++) {
		unsigned int upper;

		/* Ignore LDH characters. */
		if (IS_LDH(p[i]))
			continue;

		num_nonldh++;
		upper = p[i] & 0xff80;		/* upper 9bits */

		for (j = 0; j < num_cands; j++) {
			if (upper == row_cands[j].upper) {
				row_cands[j].num++;
				goto found;
			}
		}
		if (num_cands >= cands_size) {
			/* Make the row buffer bigger. */
			cands_size *= 2;
			if (row_cands == row_cands_buf)
				row_cands = malloc(sizeof(struct row) *
						   cands_size);
			else
				row_cands = realloc(row_cands,
						    sizeof(struct row) *
						    cands_size);
			if (row_cands == NULL)
				return (mdn_nomemory);
		}
		row_cands[num_cands].upper = upper;
		row_cands[num_cands].num = 1;
		row_cands[num_cands].cmpl = 0;
		num_cands++;
	found:
		;
	}

	if (num_cands == 0) {
		/*
		 * There is no non-LDH characters.  Draft is not clear on
		 * this case, but the sample implementation uses no-row style.
		 */
		style = no_row_style;
		goto ret;
	}
	if (num_cands == 1) {
		/*
		 * Choose half-row style.
		 */
		*rowp = row_cands[0].upper;
		style = half_row_style;
		goto ret;
	}
	if (num_cands == 2 &&
	    (row_cands[0].upper ^ row_cands[1].upper) == 0x80) {
		/*
		 * All the non-LDH characters are in the same row.
		 * Choose full-row style.
		 */
		*rowp = row_cands[0].upper & ~0x80;
		style = full_row_style;
		goto ret;
	}

	/*
	 * Get the number of characters in the complementary half-row.
	 */
	for (i = 1; i < num_cands; i++) {
		unsigned int upper = row_cands[i].upper;

		for (j = 0; j < i; j++) {
			if ((row_cands[j].upper ^ upper) == 0x80) {
				row_cands[i].cmpl = row_cands[j].num;
				row_cands[j].cmpl = row_cands[i].num;
				break;
			}
		}
	}

	/*
	 * Choose the best M.
	 */
#define M(i) \
    (3 + (num_nonldh * 18 - row_cands[i].num * 10 - row_cands[i].cmpl * 9) / 5)
	for (best = 0, m = M(0), i = 1; i < num_cands; i++) {
		int m_i = M(i);
		if (m_i < m ||
		    (m_i == m && row_cands[i].upper < row_cands[best].upper)) {
			best = i;
			m = m_i;
		}
	}
#undef M
	m_prime = (6 + num_nonldh * 16) / 5;
	if (m_prime <= m) {
		style = no_row_style;
	} else {
		*rowp = row_cands[best].upper;
		style = mixed_style;
	}
 ret:
	if (row_cands != row_cands_buf)
		free(row_cands);
	*stylep = style;
	return (mdn_success);
}

static int
brace_rbase32(int c) {
	if ('A' <= c && c <= 'Z')
		c = 'a' + (c - 'A');
	if ('2' <= c && c <= '9')
		return (c - '2');
	else if ('a' <= c && c <= 'k')
		return (c - 'a' + 8);
	else if ('m' <= c && c <= 'n')
		return (c - 'm' + 19);
	else if ('p' <= c && c <= 'z')
		return (c - 'p' + 21);
	else
		return (-1);
}
