#ifndef lint
static char *rcsid = "$Id: altdude.c,v 1.1.2.1 2002/02/08 12:13:38 marka Exp $";
#endif

/*
 * Copyright (c) 2000,2001 Japan Network Information Center.
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
#include <mdn/altdude.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-altdude-00.txt doesn't specify the ACE
 * signature for ALTDUDE, we have to choose one.
 */
#if !defined(MDN_ALTDUDE_PREFIX) && !defined(MDN_ALTDUDE_SUFFIX)
#define MDN_ALTDUDE_PREFIX		"a---"
#endif

static const char *base32encode = "abcdefghijkmnpqrstuvwxyz23456789";
static const int base32decode_ascii[26] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
};
static const int base32decode_digit[10] = {
	-1, -1, 24, 25, 26, 27, 28, 29, 30, 31,
};

static mdn_result_t	altdude_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	altdude_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static int		get_nibblelength(unsigned long v);
static int		altdude_getwc(const char *s, size_t len,
				   unsigned long *vp);
static int		altdude_putwc(char *s, size_t len, unsigned long v);

static mdn__ace_t altdude_ctx = {
#ifdef MDN_ALTDUDE_PREFIX
	mdn__ace_prefix,
	MDN_ALTDUDE_PREFIX,
#else
	mdn__ace_suffix,
	MDN_ALTDUDE_SUFFIX,
#endif
	altdude_encode,
	altdude_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__altdude_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__altdude_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__altdude_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__altdude_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&altdude_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__altdude_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
altdude_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	unsigned long prev, v;

	prev = 96;
	while (fromlen > 0) {
		if (from[0] == '-') {
			v = '-';
			from++;
			fromlen--;
		} else {
			len = altdude_getwc(from, fromlen, &v);
			if (len == 0)
				return (mdn_invalid_encoding);
			from += len;
			fromlen -= len;
			v = prev ^ v;

			/*
			 * Since round-trip check is performed later
			 * by mdn__ace_convert(), we don't need the
			 * following sanity checking.
			 *
			 * if (v == '-' || get_nibblelength(v) != len)
			 * 	return (mdn_invalid_encoding);
			 */

			prev = v;
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
altdude_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	unsigned long prev, c;

	prev = 96;
	while (fromlen > 0) {
		len = mdn_utf8_getwc(from, fromlen, &c);
		from += len;
		fromlen -= len;
		if (len == 0)
			return (mdn_invalid_encoding);
		if (c == '-') {
			/*
			 * Hyphens are treated specially.
			 */
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to++ = '-';
			tolen--;
		} else {
			len = altdude_putwc(to, tolen, prev ^ c);
			if (len == 0)
				return (mdn_buffer_overflow);
			prev = c;
			to += len;
			tolen -= len;
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';

	return (mdn_success);
}

static int
get_nibblelength(unsigned long v) {
	assert(v <= 0x7fffffff);

	if (v < (1<<16)) {			/* v <= 16bit */
		if (v < (1<<8))			/* v <= 8bit */
			return ((v < (1<<4)) ? 1 : 2);
		else				/* 8bit < v <= 16bit */
			return ((v < (1<<12)) ? 3 : 4);
	} else {				/* 16bit < c */
		if (v < (1<<24))		/* 16bit < c <= 24bit */
			return ((v < (1<<20)) ? 5 : 6);
		else				/* 24bit < c <= 31bit */
			return ((v < (1<<28)) ? 7 : 8);
	}
}

static int
altdude_getwc(const char *s, size_t len, unsigned long *vp) {
	size_t orglen = len;
	unsigned long v = 0;

	while (len > 0) {
		int c = *s++;

		if ('a' <= c && c <= 'z')
			c = base32decode_ascii[c - 'a'];
		else if ('A' <= c && c <= 'Z')
			c = base32decode_ascii[c - 'A'];
		else if ('0' <= c && c <= '9')
			c = base32decode_digit[c - '0'];
		else
			c = -1;

		if (c < 0)
			return (0);	/* invalid character */

		v = (v << 4) + (c & 0xf);

		len--;
		if ((c & 0x10) == 0) {
			*vp = v;
			return (orglen - len);
		}
	}
	return (0);	/* final character missing */
}

static int
altdude_putwc(char *s, size_t len, unsigned long v) {
	int i, w, shift;

	if ((w = get_nibblelength(v)) > len)
		return (0);

	for (shift = 0, i = w - 1; i >= 0; i--) {
		s[i] = base32encode[(v & 0xf) + shift];
		v >>= 4;
		shift = 16;
	}
	return (w);
}
