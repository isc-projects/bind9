#ifndef lint
static char *rcsid = "$Id: mace.c,v 1.1.2.1 2002/02/08 12:14:01 marka Exp $";
#endif

/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
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
#include <mdn/mace.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * MACE
 */

#ifndef MDN_MACE_PREFIX
#define MDN_MACE_PREFIX		"mq--"
#endif

/* Mode switcher */
#define MACE_MODE_SWITCH	'-'	/* Literal/Non-Literal switching */

/* Submode introducer */
#define MACE_SUBMODE_BMP_A	'w'	/* U+0000-U+1FFF, U+A000-U+FFFF */
#define MACE_SUBMODE_BMP_B	'x'	/* U+2000-U+9FFF */
#define MACE_SUBMODE_NONBMP	'y'	/* U+10000-U+10FFFF */
#define MACE_SUBMODE_COMP	'z'	/* 4/9bit differential encoding */

/* Initial state */
#define MACE_SUBMODE_INIT	MACE_SUBMODE_BMP_A
#define MACE_PREV_INIT		0

#define MACE_COMP_BITS_1	4
#define MACE_COMP_BITS_2	9
#define MACE_COMP_MASK		((1 << MACE_COMP_BITS_2) - 1)
#define MACE_SAME_PREFIX(b, c1, c2) (((c1) ^ (c2)) < (1 << (b)))

#define MACE_INVALID_CHAR	0x80000000

static mdn_result_t	mace_decode(const char *from, size_t fromlen,
				     char *to, size_t tolen);
static mdn_result_t	mace_encode(const char *from, size_t fromlen,
				     char *to, size_t tolen);
static int		mace_get_submode(int submode, unsigned long c,
					  unsigned long prev,
					  const char *rest, size_t rlen);
static int		mace_getbase32(const char *s, int w,
					unsigned long *vp);
static int		mace_encodelength(int submode);
static int		mace_getwc(const char *s, size_t len, int mode,
				    unsigned long ref, unsigned long *vp);
static int		mace_putwc(char *s, size_t len, int mode,
				    unsigned long ref, unsigned long v);
static int		peek_next_nonldh(const char *rest, size_t rlen,
					 unsigned long *cp);
static int		letter_or_digit(unsigned long v);

static mdn__ace_t mace_ctx = {
	mdn__ace_prefix,
	MDN_MACE_PREFIX,
	mace_encode,
	mace_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__mace_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
	       void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__mace_close(mdn_converter_t ctx, void *privdata,
		mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__mace_convert(mdn_converter_t ctx, void *privdata,
		  mdn_converter_dir_t dir,
		  const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__mace_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&mace_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__mace_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
mace_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal = 0;
	int submode = MACE_SUBMODE_INIT;
	unsigned long prev = MACE_PREV_INIT;

	while (fromlen > 0) {
		int consume = 1;	/* # of input octets consumed */
		unsigned long c = MACE_INVALID_CHAR;

		if (from[0] == MACE_MODE_SWITCH) {
			/*
			 * LD/non-LD mode switcher or just a hyphen.
			 */
			if (fromlen > 1 && from[1] == MACE_MODE_SWITCH) {
				c = MACE_MODE_SWITCH;
				consume = 2;
			} else {
				literal = !literal;
			}
		} else if (literal) {
			/*
			 * Now in LD mode.  Just output literally.
			 */
			if (tolen < 1)
				return (mdn_buffer_overflow);
			c = from[0];
		} else if (from[0] == 'w' || from[0] == 'W') {
			submode = MACE_SUBMODE_BMP_A;
		} else if (from[0] == 'x' || from[0] == 'X') {
			submode = MACE_SUBMODE_BMP_B;
		} else if (from[0] == 'y' || from[0] == 'Y') {
				submode = MACE_SUBMODE_NONBMP;
		} else if (from[0] == 'z' || from[0] == 'Z') {
			submode = MACE_SUBMODE_COMP;
		} else {
			/*
			 * Must be base32-format string.
			 */
			consume = mace_getwc(from, fromlen, submode,
					      prev, &c);
			if (consume == 0)
				return (mdn_invalid_encoding);
			prev = c;
		}

		/* Output decoded character. */
		if (c != MACE_INVALID_CHAR) {
			size_t len = mdn_utf8_putwc(to, tolen, c);
			if (len == 0)
				return (mdn_buffer_overflow);
			to += len;
			tolen -= len;
		}

		from += consume;
		fromlen -= consume;
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
mace_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal = 0;
	int submode = MACE_SUBMODE_INIT;
	unsigned long prev = MACE_PREV_INIT;

	while (fromlen > 0) {
		unsigned long c;
		size_t len;

		/* Get next character. */
		len = mdn_utf8_getwc(from, fromlen, &c);
		if (len == 0 || c > 0x10ffff)
			return (mdn_invalid_encoding);
		from += len;
		fromlen -= len;

		if (c == '-') {
			/*
			 * Hyphen.  Always encode as `--'.
			 */
			if (tolen < 2)
				return (mdn_buffer_overflow);
			to[0] = to[1] = '-';
			to += 2;
			tolen -= 2;
		} else if (letter_or_digit(c)) {
			/*
			 * Letter or digit.
			 * Shift to Literal mode if necessary, then
			 * encode it as it is.
			 */
			if (!literal) {
				if (tolen < 1)
					return (mdn_buffer_overflow);
				*to++ = MACE_MODE_SWITCH;
				tolen--;
				literal = 1;
			}
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to++ = c;
			tolen--;
		} else {
			/*
			 * Non-LDH character.
			 */
			int new_submode;

			/* Move back from LD mode if necessary. */
			if (literal) {
				if (tolen < 1)
					return (mdn_buffer_overflow);
				*to++ = MACE_MODE_SWITCH;
				tolen--;
				literal = 0;
			}

			/* Determine the new submode and shift to it. */
			new_submode = mace_get_submode(submode, c, prev,
						       from, fromlen);
			if (new_submode != submode) {
				if (tolen < 1)
					return (mdn_buffer_overflow);
				*to++ = new_submode;	/* introducer */
				tolen--;
				submode = new_submode;
			}

			/* Encode and output the character. */
			len = mace_putwc(to, tolen, submode, prev, c);
			if (len == 0)
				return (mdn_buffer_overflow);
			to += len;
			tolen -= len;

			prev = c;
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen < 1)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static int
mace_get_submode(int submode, unsigned long c, unsigned long prev,
		  const char *rest, size_t rlen)
{
	/*
	 * Determine the submode.
	 */
	unsigned long nxt;

	/*
	 * First, check if we should use Compress submode.
	 */
	if (MACE_SAME_PREFIX(MACE_COMP_BITS_2, prev, c) &&
	    (submode == MACE_SUBMODE_COMP ||
	     c > 0xffff ||
	     MACE_SAME_PREFIX(MACE_COMP_BITS_1, prev, c) ||
	     (peek_next_nonldh(rest, rlen, &nxt) &&
	      MACE_SAME_PREFIX(MACE_COMP_BITS_2, c, nxt))))
		return (MACE_SUBMODE_COMP);

	/*
	 * Then, determine the submode based on the code point.
	 */
	if (c > 0xffff)
		return (MACE_SUBMODE_NONBMP);
	else if (0x2000 <= c && c <= 0x9fff)
		return (MACE_SUBMODE_BMP_B);
	else
		return (MACE_SUBMODE_BMP_A);

}

static int
mace_encodelength(int submode) {
	switch (submode) {
	case MACE_SUBMODE_BMP_A:
	case MACE_SUBMODE_BMP_B:
		return (3);
	case MACE_SUBMODE_NONBMP:
		return (4);
	default: /* MACE_SUBMODE_COMP */
		return (1);	/* actually 1 or 2. caller must decide. */
	}
}

static int
mace_getbase32(const char *s, int w, unsigned long *vp) {
	unsigned long v = 0;

	while (w-- > 0) {
		int c = *s++;

		if ('a' <= c && c <= 'v')
			c = c - 'a' + 10;
		else if ('A' <= c && c <= 'V')
			c = c - 'A' + 10;
		else if ('0' <= c && c <= '9')
			c = c - '0';
		else
			return (0);	/* invalid character */
		v = (v << 5) + (c & 0x1f);
	}
	*vp = v;
	return (1);
}

static int
mace_getwc(const char *s, size_t len, int submode,
	   unsigned long prev, unsigned long *vp)
{
	unsigned long v = 0;
	int w = mace_encodelength(submode);

	if (len < w || !mace_getbase32(s, w, &v))
		return (0);

	switch (submode) {
	case MACE_SUBMODE_BMP_A:
		if (v >= 0x2000)
			v += 0x8000;
		break;
	case MACE_SUBMODE_BMP_B:
		v += 0x2000;
		break;
	case MACE_SUBMODE_NONBMP:
		v += 0x10000;
		break;
	case MACE_SUBMODE_COMP:
		if (v > 0xf) {
			w = 2;
			if (len < w || !mace_getbase32(s, w, &v))
				return (0);
		}
		v = prev ^ (v & MACE_COMP_MASK);
		break;
	default:
		FATAL(("mace_getwc: internal error"));
		break;
	}
	*vp = v;

	return (w);
}

static int
mace_putwc(char *s, size_t len, int submode,
	   unsigned long prev, unsigned long v)
{
	static const char *base32encode = "0123456789abcdefghijklmnopqrstuv";
	int w = mace_encodelength(submode);
	int i;

	switch (submode) {
	case MACE_SUBMODE_BMP_A:
		if (v >= 0xa000)
			v -= 0x8000;
		break;
	case MACE_SUBMODE_BMP_B:
		v -= 0x2000;
		break;
	case MACE_SUBMODE_NONBMP:
		v -= 0x10000;
		break;
	case MACE_SUBMODE_COMP:
		v = (prev ^ v) & MACE_COMP_MASK;
		if (v > 0xf) {
			v |= 0x200;
			w++;
		}
		break;
	default:
		FATAL(("mace_putwc: internal error"));
		break;
	}

	if (len < w)
		return (0);

	for (i = w - 1; i >= 0; i--) {
		s[i] = base32encode[v & 0x1f];
		v >>= 5;
	}
	return (w);
}

static int
peek_next_nonldh(const char *rest, size_t rlen, unsigned long *cp) {
	/*
	 * Get the next non-LDH character from 'rest', store its
	 * code point to '*cp' and return 1.  If there are no
	 * such character, return 0.
	 */
	while (rlen > 0) {
		unsigned long v;
		size_t len;

		if ((len = mdn_utf8_getwc(rest, rlen, &v)) == 0) {
			break;
		} else if (v != '-' && !letter_or_digit(v)) {
			*cp = v;
			return (1);
		}
		rest += len;
		rlen -= len;
	}
	return (0);
}

static int
letter_or_digit(unsigned long v) {
	if (('a' <= v && v <= 'z') ||
	    ('A' <= v && v <= 'Z') ||
	    ('0' <= v && v <= '9'))
		return (1);
	else
		return (0);
}
