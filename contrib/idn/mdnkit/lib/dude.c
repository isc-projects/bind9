#ifndef lint
static char *rcsid = "$Id: dude.c,v 1.1 2001/06/09 00:30:15 tale Exp $";
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
#include <mdn/dude.h>
#include <mdn/ace.h>
#include <mdn/util.h>

#ifndef MDN_DUDE_PREFIX
#define MDN_DUDE_PREFIX		"dq--"
#endif

static unsigned long nibble_mask[] = {
	0,		/* dummy: this element is never referenced. */
	0xf,
	0xff,
	0xfff,
	0xffff,
	0xfffff,
};

static mdn_result_t	dude_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	dude_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static int		get_nibblelength(unsigned long v);
static int		dude_getwc(const char *s, size_t len,
				   unsigned long *vp);
static int		dude_putwc(char *s, size_t len, unsigned long v,
				   int w);

static mdn__ace_t dude_ctx = {
	mdn__ace_prefix,
	MDN_DUDE_PREFIX,
	dude_encode,
	dude_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__dude_open(mdn_converter_t ctx, mdn_converter_dir_t dir, void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__dude_close(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir) {
	return (mdn_success);
}

mdn_result_t
mdn__dude_convert(mdn_converter_t ctx, void *privdata, mdn_converter_dir_t dir,
		  const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__dude_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&dude_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__dude_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
dude_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	unsigned long prev, v, mask;

	prev = 0;
	while (fromlen > 0) {
		if (from[0] == '-') {
			v = '-';
			from++;
			fromlen--;
		} else {
			len = dude_getwc(from, fromlen, &v);
			if (len == 0)
				return (mdn_invalid_encoding);
			from += len;
			fromlen -= len;
			mask = nibble_mask[len];
			v = (prev & ~mask) | v;

			/*
			 * Perform extra sanity checks.
			 */
			if (v == '-' || get_nibblelength(prev ^ v) != len)
				return (mdn_invalid_encoding);

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
dude_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	unsigned long prev, c, v, mask;

	prev = 0;
	while (fromlen > 0) {
		len = mdn_utf8_getwc(from, fromlen, &c);
		from += len;
		fromlen -= len;
		if (len == 0 || c >= 0x100000)
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
			int nlen = get_nibblelength(prev ^ c);
			mask = nibble_mask[nlen];
			v = c & mask;
			prev = c;
			len = dude_putwc(to, tolen, v, nlen);
			if (len == 0)
				return (mdn_buffer_overflow);
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
	assert(v < 0x100000);

	if (v <= 0xf)
		return 1;
	else if (v <= 0xff)
		return 2;
	else if (v <= 0xfff)
		return 3;
	else if (v <= 0xffff)
		return 4;
	else
		return 5;
}

static int
dude_getwc(const char *s, size_t len, unsigned long *vp) {
	size_t orglen = len;
	unsigned long v = 0;
	int c;

	if (len < 1)
		return (0);

	c = *s++;
	len--;

	if ('G' <= c && c <= 'V')
		v = c - 'G';
	else if ('g' <= c && c <= 'v')
		v = c - 'g';
	else	/* invalid character */
		return (0);

	while (len > 0) {
		c = *s++;
		if ('0' <= c && c <= '9')
			c = c - '0';
		else if ('A' <= c && c <= 'F')
			c = c - 'A' + 10;
		else if ('a' <= c && c <= 'f')
			c = c - 'a' + 10;
		else
			break;
		v = (v << 4) + c;
		len--;
	}
	len = orglen - len;

	if (len > 5)
		return (0);

	*vp = v;
	return (len);
}

static int
dude_putwc(char *s, size_t len, unsigned long v, int w) {
	int i;

	assert(v < 0x100000);
	assert(w > 0 && w < 6 && v <= nibble_mask[w]);

	if (len < w)
		return (0);

	for (i = w - 1; i >= 0; i--) {
		int x = v & 0xf;

		if (i == 0)
			s[i] = 'g' + x;
		else if (x < 10)
			s[i] = '0' + x;
		else
			s[i] = 'a' + x - 10;
		v >>= 4;
	}

	return (w);
}
