#ifndef lint
static char *rcsid = "$Id: amcacem.c,v 1.1.2.1 2002/02/08 12:13:39 marka Exp $";
#endif

/*
 * Copyright (c) 2001 Japan Network Information Center.
 * All rights reserved.
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
#include <mdn/amcacem.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * The current draft, there is discrepancy between the spec and the
 * sample implementation/examples.  Defining the following symbol
 * makes this code agree with the sample code.
 */
/* #define CONFORM_TO_SAMPLE */

/*
 * Although draft-ietf-idn-amc-ace-m-00.txt doesn't specify the ACE
 * signature, we have to choose one.
 */
#if !defined(MDN_AMCACEM_PREFIX) && !defined(MDN_AMCACEM_SUFFIX)
#define MDN_AMCACEM_SUFFIX	"-amc1"
#endif

#define AMCACEM_MAX_CODEPOINT	0x10ffff

enum { amcacem_narrow_style, amcacem_wide_style };

#define UCSBUF_LOCAL_SIZE	40

typedef struct ucsbuf {
	unsigned long *ucs;
	size_t size;
	size_t len;
	unsigned long local[UCSBUF_LOCAL_SIZE];
} ucsbuf_t;

static const char *base32encode = "abcdefghijkmnpqrstuvwxyz23456789";
static const int base32decode_ascii[26] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
};
static const int base32decode_digit[10] = {
	-1, -1, 24, 25, 26, 27, 28, 29, 30, 31,
};

#define AMCACEM_SPECIAL_RANGE_FIRST	0x20
#define AMCACEM_SPECIAL_RANGE_END	0x36f
unsigned long acem_special_row[8] = {
	0x020, 0x05b, 0x07b, 0x0a0, 0x0c0, 0x0df, 0x134, 0x270,
};

static mdn_result_t	amcacem_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	amcacem_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static int		most_populous_row(const unsigned long *ucs,
					  size_t len);
static int		most_populous_16win(const unsigned long *ucs,
					    size_t len, unsigned long base);
static int		most_populous_20kwin(const unsigned long *ucs,
					     size_t len, unsigned long base);
static unsigned long	row_offset(int row);
static int		choose_style(const unsigned long *ucs, size_t len,
				     int a, int b, int c);
static int		estimate(int style, const unsigned long *ucs,
				 size_t ulen, int a, int b, int c);
static unsigned long	base32decode(const char *s, int len, int *err);
static mdn_result_t	utf8_to_ucs4(const char *utf8, size_t fromlen,
				     ucsbuf_t *b);
static void		ucsbuf_init(ucsbuf_t *b);
static mdn_result_t	ucsbuf_grow(ucsbuf_t *b);
static mdn_result_t	ucsbuf_append(ucsbuf_t *b, unsigned long v);
static void		ucsbuf_free(ucsbuf_t *b);
static int		is_ldh(unsigned long v);

static mdn__ace_t amcacem_ctx = {
#ifdef MDN_AMCACEM_PREFIX
	mdn__ace_prefix,
	MDN_AMCACEM_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACEM_SUFFIX,
#endif
	amcacem_encode,
	amcacem_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__amcacem_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcacem_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcacem_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcaceo_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcacem_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcacem_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcacem_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	int literal_mode = 0;
	int a, b, c;
	unsigned long offseta, offsetb, offsetc;
	int style;
	int err = 0;

	/*
	 * Decode header.
	 */
	if (fromlen < 3)
		return (mdn_invalid_encoding);

	a = b = c = 0;			/* for lint */
	style = amcacem_narrow_style;	/* for lint */

	switch (base32decode(from, 1, &err) & 0x18) {
	case 0:
		style = amcacem_narrow_style;
		b = base32decode(from, 2, &err);
		a = base32decode(from + 2, 1, &err);
		from += 3;
		fromlen -= 3;
		break;
	case 0x8:
		if (fromlen < 4)
			return (mdn_invalid_encoding);
		style = amcacem_narrow_style;
		b = base32decode(from, 3, &err) & 0x1fff;
		a = base32decode(from + 3, 1, &err);
		from += 4;
		fromlen -= 4;
		break;
	case 0x10:
		style = amcacem_wide_style;
		b = base32decode(from, 2, &err) & 0xff;
		c = base32decode(from + 2, 1, &err);
		from += 3;
		fromlen -= 3;
		break;
	case 0x18:
		if (fromlen < 5)
			return (mdn_invalid_encoding);
		style = amcacem_wide_style;
		b = base32decode(from, 3, &err) & 0x1fff;
		c = base32decode(from + 3, 2, &err);
		from += 5;
		fromlen -= 5;
		break;
	}
	if (err)
		return (mdn_invalid_encoding);

	offsetb = row_offset(b);
	offseta = ((offsetb >> 3) + a) << 3;
	if (style == amcacem_narrow_style)
		offsetc = (offsetb >> 12) << 12;
	else
		offsetc = c << 11;

	while (fromlen > 0) {
		unsigned long v;

		if (from[0] == '-') {
			if (fromlen > 1 && from[1] == '-') {
				v = '-';
				from += 2;
				fromlen -= 2;
			} else {
				literal_mode = !literal_mode;
				from++;
				fromlen--;
				continue;
			}
		} else if (literal_mode) {
			v = from[0];
			from++;
			fromlen--;
		} else {
			v = base32decode(from, 1, &err);
			if (err)
				return (mdn_invalid_encoding);
			if (v < 16) {
				if (style == amcacem_narrow_style) {
					v += offseta;
					len = 1;
				} else {
					if (fromlen < 3)
						return (mdn_invalid_encoding);
					v = base32decode(from, 3, &err)
						+ offsetc + 0x1000;
					if (err)
						return (mdn_invalid_encoding);
					len = 3;
				}
			} else {
				v = 0;
				for (len = 0; len < 5; len++) {
					int x;
					if (tolen <= len)
						return (mdn_invalid_encoding);
					x = base32decode(from + len, 1, &err);
					v = (v << 4) + (x & 0xf);
					if (x < 16)
						break;
				}
				if (err)
					return (mdn_invalid_encoding);
					
				switch (++len) {
				case 2:
					v += offsetb;
					break;
				case 3:
					v += offsetc;
					break;
				case 4:
					break;
				case 5:
					v += 0x10000;
					break;
				default:
					return (mdn_invalid_encoding);
				}
			}
			from += len;
			fromlen -= len;
		}
		len = mdn_utf8_putwc(to, tolen, v);
		if (len == 0)
			return (mdn_buffer_overflow);
		to += len;
		tolen -= len;
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';

	return (mdn_success);
}

static mdn_result_t
amcacem_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	ucsbuf_t ucsb;
	unsigned long *buf;
	size_t len;
	int literal_mode = 0;
	int a, b, c;
	unsigned long offseta, offsetb, offsetc;
	mdn_result_t r;
	int style;
	int i;

	/*
	 * Convert input string to UCS-4.
	 */
	ucsbuf_init(&ucsb);
	if ((r = utf8_to_ucs4(from, fromlen, &ucsb)) != mdn_success)
		return (r);

	buf = ucsb.ucs;
	len = ucsb.len;

	/*
	 * Now 'buf' contains UCS-4 string consisting of 'len' characters.
	 */

	/*
	 * Make sure all the codepoints are below 0x110000.
	 */
	for (i = 0; i < len; i++) {
		if (buf[i] > AMCACEM_MAX_CODEPOINT)
			return (mdn_invalid_encoding);
	}

	b = most_populous_row(buf, len);
	offsetb = row_offset(b);
	a = most_populous_16win(buf, len, offsetb);
	offseta = ((offsetb >> 3) + a) << 3;
	c = most_populous_20kwin(buf, len, offsetb);

	style = choose_style(buf, len, a, b, c);

	if (style == amcacem_narrow_style) {
		if (b <= 0xff) {
			if (tolen < 3)
				goto overflow;
			to[0] = base32encode[b >> 5];
			to[1] = base32encode[b & 0x1f];
			to[2] = base32encode[a];
			to += 3;
			tolen -= 3;
		} else {
			if (tolen < 4)
				goto overflow;
			to[0] = base32encode[8 + (b >> 10)];
			to[1] = base32encode[(b >> 5) & 0x1f];
			to[2] = base32encode[b & 0x1f];
			to[3] = base32encode[a];
			to += 4;
			tolen -= 4;
		}
		offsetc = (offsetb >> 12) << 12;
	} else {
		if (b <= 0xff && c <= 0x1f) {
			if (tolen < 3)
				goto overflow;
			to[0] = base32encode[0x10 + (b >> 5)];
			to[1] = base32encode[b & 0x1f];
			to[2] = base32encode[c];
			to += 3;
			tolen -= 3;
		} else {
			if (tolen < 5)
				goto overflow;
			to[0] = base32encode[0x18 + (b >> 10)];
			to[1] = base32encode[(b >> 5) & 0x1f];
			to[2] = base32encode[b & 0x1f];
			to[3] = base32encode[c >> 5];
			to[4] = base32encode[c & 0x1f];
			to += 5;
			tolen -= 5;
		}
		offsetc = c << 11;
	}

	for (i = 0; i < len; i++) {
		unsigned long c = buf[i];

		if (c == '-') {
			/*
			 * Convert "-" to "--".
			 */
			if (tolen < 2)
				return (mdn_buffer_overflow);
			to[0] = to[1] = '-';
			to += 2;
			tolen -= 2;
		} else if (is_ldh(c)) {
			/*
			 * LDH characters.
			 */
			if (literal_mode == 0) {
				/*
				 * Go into literal mode.
				 */
				if (tolen < 1)
					goto overflow;
				*to++ = '-';
				tolen--;
				literal_mode = 1;
			}
			if (tolen < 1)
				goto overflow;
			*to++ = c;
			tolen--;
		} else {
			/*
			 * Non-LDH characters.
			 */
			if (literal_mode != 0) {
				/*
				 * Get out of literal mode.
				 */
				if (tolen < 1)
					goto overflow;
				*to++ = '-';
				tolen--;
				literal_mode = 0;

			}
			if (style == amcacem_narrow_style &&
			    offseta <= c && c <= offseta + 0xf) {
				if (tolen < 1)
					goto overflow;
				*to++ = base32encode[c - offseta];
				tolen--;
			} else if (offsetb <= c && c <= offsetb + 0xff) {
				if (tolen < 2)
					goto overflow;
				c -= offsetb;
				to[0] = base32encode[0x10 + (c >> 4)];
				to[1] = base32encode[c & 0xf];
				to += 2;
				tolen -= 2;
			} else if (offsetc <= c && c <= offsetc + 0xfff) {
				if (tolen < 3)
					goto overflow;
				c -= offsetc;
				to[0] = base32encode[0x10 + (c >> 8)];
				to[1] = base32encode[0x10 + ((c >> 4) & 0xf)];
				to[2] = base32encode[c & 0xf];
				to += 3;
				tolen -= 3;
			} else if (style == amcacem_wide_style &&
				   offsetc +0x1000 <= c &&
				   c <= offsetc + 0x4fff) {
				if (tolen < 3)
					goto overflow;
				c -= offsetc + 0x1000;
				to[0] = base32encode[c >> 10];
				to[1] = base32encode[(c >> 5) & 0x1f];
				to[2] = base32encode[c & 0x1f];
				to += 3;
				tolen -= 3;
			} else if (c <= 0xffff) {
				if (tolen < 4)
					goto overflow;
				to[0] = base32encode[0x10 + (c >> 12)];
				to[1] = base32encode[0x10 + ((c >> 8) & 0xf)];
				to[2] = base32encode[0x10 + ((c >> 4) & 0xf)];
				to[3] = base32encode[c & 0xf];
				to += 4;
				tolen -= 4;
			} else {
				if (tolen < 5)
					goto overflow;
				c -= 0x10000;
				to[0] = base32encode[0x10 + (c >> 16)];
				to[1] = base32encode[0x10 + ((c >> 12) & 0xf)];
				to[2] = base32encode[0x10 + ((c >> 8) & 0xf)];
				to[3] = base32encode[0x10 + ((c >> 4) & 0xf)];
				to[4] = base32encode[c & 0xf];
				to += 5;
				tolen -= 5;
			}
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';

	ucsbuf_free(&ucsb);
	return (mdn_success);

 overflow:
	ucsbuf_free(&ucsb);
	return (mdn_buffer_overflow);
}

static int
most_populous_row(const unsigned long *ucs, size_t len) {
	int pop[256];
	int bestpop;
	int bestrow;
	int i, j;

	memset(pop, 0, sizeof(pop));
	for (i = 0; i < len; i++) {
		unsigned long c = ucs[i];

		if (is_ldh(c))
			continue;

		pop[c >> 8]++;

		if (c >= AMCACEM_SPECIAL_RANGE_FIRST &&
		    c <= AMCACEM_SPECIAL_RANGE_END) {
			for (j = 0; j < 8; j++) {
				if (c >= acem_special_row[j] &&
				    c < acem_special_row[j] + 256) {
					pop[0xd8 + j]++;
				}
			}
		}
	}

	bestpop = -1;
	bestrow = 0;		/* for lint */
	for (i = 0; i < 256; i++) {
		if (pop[i] > bestpop) {
			bestpop = pop[i];
			bestrow = i;
		}
	}
	return (bestrow);
}

static int
most_populous_16win(const unsigned long *ucs, size_t len,
		    unsigned long base)
{
	unsigned long hi, lo;
	int i;
	int pop[32];
	int bestpop;
	int bestwin;

	memset(pop, 0, sizeof(pop));

	lo = (base >> 3) << 3;
	hi = (((base >> 3) + 31) << 3) + 16;

	for (i = 0; i < len; i++) {
		int blk;

		if (ucs[i] < lo || ucs[i] >= hi || is_ldh(ucs[i]))
			continue;

		blk = (ucs[i] - lo) / 8;
		if (blk < 32)
			pop[blk]++;
		if (blk > 0)
			pop[blk - 1]++;
	}

	bestpop = -1;
	bestwin = 0;		/* for lint */
	for (i = 0; i < 32; i++) {
		if (pop[i] > bestpop) {
			bestpop = pop[i];
			bestwin = i;
		}
	}
	return (bestwin);
}

static int
most_populous_20kwin(const unsigned long *ucs, size_t len,
		     unsigned long base)
{
	int i, j;
	int bestcnt = -1;
	int bestwin = 0;

	for (i = 0; i < len; i++) {
		unsigned long c = ucs[i];
		unsigned long n, lo, hi;
		int count;

		count = 0;
		n = c >> 11;
		lo = n << 11;
		hi = lo + 0x4fff;

		for (j = 0; j < len; j++) {
			unsigned long v = ucs[j];
#ifndef CONFORM_TO_SAMPLE
			/*
			 * The draft says not to count code points in row B,
			 * but the sample code does, and example encoding 
			 * agrees with the sample code.
			 */
			if ((base <= v && v < base + 256) || is_ldh(v))
#else
			if (is_ldh(v))
#endif
				continue;
			if (lo <= v && v <= hi)
				count++;
		}
		if (count > bestcnt || (count == bestcnt && n < bestwin)) {
			bestcnt = count;
			bestwin = n;
		}
	}
	return (bestwin);
}

static unsigned long
row_offset(int row) {
	assert (0 <= row && row < 256);

	if (0xd8 <= row && row <= 0xdf) {
		return (acem_special_row[row - 0xd8]);
	} else {
		return (row << 8);
	}
}

static int
choose_style(const unsigned long *ucs, size_t len, int a, int b, int c) {
	int narrow = estimate(amcacem_narrow_style, ucs, len, a, b, c);
	int wide = estimate(amcacem_wide_style, ucs, len, a, b, c);

	if (narrow <= wide)
		return (amcacem_narrow_style);
	else
		return (amcacem_wide_style);
}

static int
estimate(int style, const unsigned long *ucs, size_t ulen,
	 int a, int b, int c)
{
	unsigned long offseta, offsetb, offsetc;
	int i;
	int len;

	offsetb = row_offset(b);
	offseta = ((offsetb >> 3) + a) << 3;

	if (style == amcacem_narrow_style) {
		offsetc = (offsetb >> 12) << 12;
		if (b <= 0xff)
			len = 3;
		else
			len = 4;
	} else {
		offsetc = c << 11;
		if (b <= 0xff && c <= 0x1f)
			len = 3;
		else
			len = 5;
	}

	for (i = 0; i < ulen; i++) {
		unsigned long c = ucs[i];

		if (is_ldh(c))
			continue;
		if (style == amcacem_narrow_style &&
		    offseta <= c && c <= offseta + 0xf)
			len++;
		else if (offsetb <= c && c <= offsetb + 0xff)
			len += 2;
		else if (offsetc <= c && c <= offsetc + 0xfff)
			len += 3;
		else if (style == amcacem_wide_style &&
			   offsetc +0x1000 <= c && c <= offsetc + 0x4fff)
			len += 3;
		else if (c <= 0xffff)
			len += 4;
		else
			len += 5;
	}
	return (len);
}

static unsigned long
base32decode(const char *s, int len, int *err) {
	long v = 0;

	while (len-- > 0) {
		int c = *s++;
		if ('a' <= c && c <= 'z') {
			c = base32decode_ascii[c - 'a'];
		} else if ('A' <= c && c <= 'Z') {
			c = base32decode_ascii[c - 'A'];
		} else if ('0' <= c && c <= '9') {
			c = base32decode_digit[c - '0'];
		} else {
			*err = 1;
			return (0);
		}
		v = (v << 5) + c;
	}
	return (v);
}

/*
 * Common Utility Functions.
 */

static mdn_result_t
utf8_to_ucs4(const char *utf8, size_t fromlen, ucsbuf_t *b) {
	mdn_result_t r;

	while (fromlen > 0) {
		unsigned long c;
		int w;

		if ((w = mdn_utf8_getwc(utf8, fromlen, &c)) == 0)
			return (mdn_invalid_encoding);
		utf8 += w;
		fromlen -= w;

		if ((r = ucsbuf_append(b, c)) != mdn_success)
			return (r);
	}
	return (mdn_success);
}

static void
ucsbuf_init(ucsbuf_t *b) {
	b->ucs = b->local;
	b->size = UCSBUF_LOCAL_SIZE;
	b->len = 0;
}

static mdn_result_t
ucsbuf_grow(ucsbuf_t *b) {
	if (b->ucs == b->local)
		b->ucs = NULL;
	b->size *= 2;
	b->ucs = realloc(b->ucs, sizeof(unsigned long) * b->size);
	if (b->ucs == NULL)
		return (mdn_nomemory);
	return (mdn_success);
}

static mdn_result_t
ucsbuf_append(ucsbuf_t *b, unsigned long v) {
	mdn_result_t r;

	if (b->len + 1 > b->size) {
		r = ucsbuf_grow(b);
		if (r != mdn_success)
			return (r);
	}
	b->ucs[b->len++] = v;
	return (mdn_success);
}

static void
ucsbuf_free(ucsbuf_t *b) {
	if (b->ucs != b->local) {
		free(b->ucs);
		b->ucs = b->local;
	}
}

static int
is_ldh(unsigned long v) {
	if (('a' <= v && v <= 'z') || ('A' <= v && v <= 'Z') ||
	    ('0' <= v && v <= '9') || v == '-')
		return (1);
	else
		return (0);
}
