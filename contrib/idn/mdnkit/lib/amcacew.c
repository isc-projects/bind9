#ifndef lint
static char *rcsid = "$Id: amcacew.c,v 1.1.2.1 2002/02/08 12:13:44 marka Exp $";
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
#include <mdn/amcacew.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-amc-ace-w-00.txt doesn't specify the ACE
 * signature, we have to choose one.  In order to prevent the converted
 * name from beginning with a hyphen, we should choose a prefix rather
 * than a suffix.
 */
#if !defined(MDN_AMCACEW_PREFIX) && !defined(MDN_AMCACEW_SUFFIX)
#define MDN_AMCACEW_PREFIX	"amc5-"
#endif

#define MAX_UCS		0x10FFFF

typedef struct {
	int style;			/* 0 or 1 */
	unsigned long refpoint[6];	/* refpoint[0] is not used. */
} amcacew_ctx;

static const unsigned long amcacew_refpoint_initial[6] = {
	0, 0xe0, 0xa0, 0, 0, 0x10000,
};

static const char *base32encode = "abcdefghijkmnpqrstuvwxyz23456789";
static const int base32decode_ascii[26] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
};
static const int base32decode_digit[10] = {
	-1, -1, 24, 25, 26, 27, 28, 29, 30, 31,
};

static mdn_result_t	amcacew_decode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static mdn_result_t	amcacew_encode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static void		amcacew_init_ctx(amcacew_ctx *ctx);
static void		amcacew_update_ctx(amcacew_ctx *ctx, unsigned long v,
					   int sz);
static unsigned long	amcacew_encode_delta(unsigned long v,
					     amcacew_ctx *ctx, int *szp);
static int		amcacew_getwc(const char *s, size_t len, int style,
				      unsigned long *vp);
static int		amcacew_putwc(char *s, size_t len,
				      unsigned long delta, int w);
static int		is_ldh(unsigned long v);

static mdn__ace_t amcacew_profile = {
#ifdef MDN_AMCACEW_PREFIX
	mdn__ace_prefix,
	MDN_AMCACEW_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACEW_SUFFIX,
#endif
	amcacew_encode,
	amcacew_decode,
};



/* ARGSUSED */
mdn_result_t
mdn__amcacew_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcacew_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcacew_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcacew_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcacew_profile, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcacew_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcacew_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacew_ctx ctx;

	/* Initialize refpoints. */
	amcacew_init_ctx(&ctx);

	while (fromlen > 0) {
		unsigned long v;
		int len;

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
			len = amcacew_getwc(from, fromlen, ctx.style, &v);
			if (len == 0)
				return (mdn_invalid_encoding);
			from += len;
			fromlen -= len;

			v += ctx.refpoint[len];

			amcacew_update_ctx(&ctx, v, len);
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
amcacew_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacew_ctx ctx;

	/* Initialize refpoints. */
	amcacew_init_ctx(&ctx);

	while (fromlen > 0) {
		unsigned long c;
		size_t len;

		len = mdn_utf8_getwc(from, fromlen, &c);
		from += len;
		fromlen -= len;
		if (len == 0)
			return (mdn_invalid_encoding);

		if (c > MAX_UCS) {
			/*
			 * Invalid Unicode code point.
			 */
			return (mdn_invalid_encoding);
		} else if (c == '-') {
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
					return (mdn_buffer_overflow);
				*to++ = '-';
				tolen--;
				literal_mode = 1;
			}
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to++ = c;
			tolen--;
		} else {
			/*
			 * Non-LDH characters.
			 */
			int sz;
			unsigned long delta;

			if (literal_mode != 0) {
				/*
				 * Get out of literal mode.
				 */
				if (tolen < 1)
					return (mdn_buffer_overflow);
				*to++ = '-';
				tolen--;
				literal_mode = 0;
			}
			delta = amcacew_encode_delta(c, &ctx, &sz);
			sz = amcacew_putwc(to, tolen, delta, sz);
			if (sz == 0)
				return (mdn_buffer_overflow);
			to += sz;
			tolen -= sz;
			amcacew_update_ctx(&ctx, c, sz);
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

static void
amcacew_init_ctx(amcacew_ctx *ctx) {
	ctx->style = 0;
	(void)memcpy(ctx->refpoint, amcacew_refpoint_initial,
		     sizeof(ctx->refpoint));
}

static void
amcacew_update_ctx(amcacew_ctx *ctx, unsigned long v, int sz) {
	if (sz != 3)
		ctx->style = (sz < 3) ? 0 : 1;

#define ROUND_BITS(v, b)	(((v) >> (b)) << (b))
	/* Update refpoint[1] */
	ctx->refpoint[1] = ROUND_BITS(v, 4);

	/* Update refpoint[2] */
	if (sz > 2) {
		if (0xa0 <= v && v <= 0x17f)
			ctx->refpoint[2] = 0xa0;
		else
			ctx->refpoint[2] = ROUND_BITS(v, 8);
	}

	/* Update refpoint[3] */
	if (sz > 3) {
		if (0x3000 <= v && v <= 0x9fff)
			ctx->refpoint[3] = 0x4e00;
		else if (0xa000 <= v && v <= 0xd7ff && ctx->style == 1)
			ctx->refpoint[3] = 0x8800;
		else
			ctx->refpoint[3] = ROUND_BITS(v, 12);
	}
#undef ROUND_BITS
}

static unsigned long
amcacew_encode_delta(unsigned long v, amcacew_ctx *ctx, int *szp) {
	int sz, szinit;
	unsigned long *maxdelta;
	unsigned long *refpoint = ctx->refpoint;
	static unsigned long maxdelta_style0[6] = {
		0, 0xf, 0xff, 0xfff, 0xffff, 0xfffff,
	};
	static unsigned long maxdelta_style1[6] = {
		0, 0, 0xff, 0x4fff, 0xffff, 0xfffff,
	};
	
	if (ctx->style == 0) {
		szinit = 1;
		maxdelta = maxdelta_style0;
	} else {
		szinit = 2;
		maxdelta = maxdelta_style1;
	}
	for (sz = szinit; sz < 6; sz++) {
		if (v >= refpoint[sz] && v - refpoint[sz] <= maxdelta[sz]) {
			*szp = sz;
			return (v - refpoint[sz]);
		}
	}
	FATAL(("amcacew_encode_mode: internal error\n"));
	return (0);	/* for lint */
}

static int
amcacew_getwc(const char *s, size_t len, int style, unsigned long *vp) {
	size_t orglen = len;
	unsigned long v = 0;
	int style1_special = 0;

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

		if (style == 1 && len == orglen && (c & 0x10) == 0)
			style1_special = 3;

		len--;
		if (style1_special != 0) {
			v = (v << 5) + (c & 0x1f);
			if (--style1_special == 0) {
				*vp = v + 0x1000;
				return (3);
			}
		} else {
			v = (v << 4) + (c & 0xf);

			if ((c & 0x10) == 0) {
				*vp = v;
				return (orglen - len);
			}
		}
	}
	return (0);	/* final character missing */
}

static int
amcacew_putwc(char *s, size_t len, unsigned long delta, int w) {
	if (len < w)
		return (0);

	if (w == 3 && delta >= 0x1000) {
		delta -= 0x1000;
		s[0] = base32encode[(delta >> 10) & 0x1f];
		s[1] = base32encode[(delta >> 5) & 0x1f];
		s[2] = base32encode[delta & 0x1f];
	} else {
		int i, shift;

		for (shift = 0, i = w - 1; i >= 0; i--) {
			s[i] = base32encode[(delta & 0xf) + shift];
			delta >>= 4;
			shift = 16;
		}
	}
	return (w);
}

static int
is_ldh(unsigned long v) {
	if (('a' <= v && v <= 'z') || ('A' <= v && v <= 'Z') ||
	    ('0' <= v && v <= '9') || v == '-')
		return (1);
	else
		return (0);
}
