#ifndef lint
static char *rcsid = "$Id: amcacev.c,v 1.1.2.1 2002/02/08 12:13:42 marka Exp $";
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
#include <mdn/amcacev.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-amc-ace-v-00.txt doesn't specify the ACE
 * signature, we have to choose one.  In order to prevent the converted
 * name from beginning with a hyphen, we should choose a prefix rather
 * than a suffix.
 */
#if !defined(MDN_AMCACEV_PREFIX) && !defined(MDN_AMCACEV_SUFFIX)
#define MDN_AMCACEV_PREFIX	"amc4-"
#endif

#define MAX_UCS		0x10FFFF
#define AMCACEV_BUFSIZE	64

typedef struct {
	unsigned long *history;	       	/* history of non-LDH characters */
	unsigned long local_buf[AMCACEV_BUFSIZE];
	int cur;			/* current index */
	int style;			/* 0 or 1 */
	unsigned long refpoint[2][6];	/* refpoint[0] is not used. */
} amcacev_ctx;

#define IN_WINDOW(ctx, c, st, win) \
	((c) >= (ctx)->refpoint[st][win] && \
	 ((c) - (ctx)->refpoint[st][win]) <= amcacev_winsize[st][win])

static const unsigned long amcacev_refpoint_initial[2][6] = {
	{ 0, 0xe0, 0xa0, 0, 0, 0x10000 },
	{ 0,    0,    0, 0, 0, 0x10000 },
};
static const unsigned long amcacev_winsize[2][6] = {
	{ 0, 0xf, 0xff,  0xfff, 0xffff, 0xfffff },
	{ 0,   0, 0xff, 0x4fff, 0xffff, 0xfffff },
};

static const char *base32encode = "abcdefghijkmnpqrstuvwxyz23456789";
static const int base32decode_ascii[26] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
};
static const int base32decode_digit[10] = {
	-1, -1, 24, 25, 26, 27, 28, 29, 30, 31,
};

static mdn_result_t	amcacev_decode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static mdn_result_t	amcacev_encode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static mdn_result_t	init_ctx(amcacev_ctx *ctx, size_t len);
static void		release_ctx(amcacev_ctx *ctx);
static void		update_ctx(amcacev_ctx *ctx, unsigned long v);
static unsigned long	get_refpoint(unsigned long v, int st, int win);
static int		eval_compression(amcacev_ctx *ctx);
static unsigned long	encode_delta(unsigned long v,
				     amcacev_ctx *ctx, int *szp);
static int		amcacev_getwc(const char *s, size_t len, int style,
				      unsigned long *vp);
static int		amcacev_putwc(char *s, size_t len,
				      unsigned long delta, int w);
static int		is_ldh(unsigned long v);

static mdn__ace_t amcacev_profile = {
#ifdef MDN_AMCACEV_PREFIX
	mdn__ace_prefix,
	MDN_AMCACEV_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACEV_SUFFIX,
#endif
	amcacev_encode,
	amcacev_decode,
};



/* ARGSUSED */
mdn_result_t
mdn__amcacev_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcacev_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcacev_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcacev_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcacev_profile, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcacev_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcacev_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacev_ctx ctx;
	mdn_result_t r;

	/* Initialize context. */
	if ((r = init_ctx(&ctx, fromlen)) != mdn_success)
		return (r);

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
			len = amcacev_getwc(from, fromlen, ctx.style, &v);
			if (len == 0)
				goto invalid_encoding;
			from += len;
			fromlen -= len;

			v += ctx.refpoint[ctx.style][len];

			/* Update refpoints. */
			update_ctx(&ctx, v);
		}

		len = mdn_utf8_putwc(to, tolen, v);
		if (len == 0)
			goto overflow;
		to += len;
		tolen -= len;
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		goto overflow;
	*to = '\0';

 ret:
	release_ctx(&ctx);
	return (r);

 invalid_encoding:
	r = mdn_invalid_encoding;
	goto ret;
 overflow:
	r = mdn_buffer_overflow;
	goto ret;
}

static mdn_result_t
amcacev_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacev_ctx ctx;
	mdn_result_t r;

	/* Initialize context. */
	if ((r = init_ctx(&ctx, fromlen)) != mdn_success)
		return (r);

	while (fromlen > 0) {
		unsigned long c;
		size_t len;

		len = mdn_utf8_getwc(from, fromlen, &c);
		from += len;
		fromlen -= len;
		if (len == 0)
			goto invalid_encoding;

		if (c >= MAX_UCS) {
			/*
			 * Invalid Unicode code point.
			 */
			goto invalid_encoding;
		} else if (c == '-') {
			/*
			 * Convert "-" to "--".
			 */
			if (tolen < 2)
				goto overflow;
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
			int sz;
			unsigned long delta;

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
			delta = encode_delta(c, &ctx, &sz);
			sz = amcacev_putwc(to, tolen, delta, sz);
			if (sz == 0)
				goto overflow;
			to += sz;
			tolen -= sz;

			/* Add to the history, and update refpoints. */
			update_ctx(&ctx, c);
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		goto overflow;

	*to = '\0';

 ret:
	release_ctx(&ctx);
	return (r);

 invalid_encoding:
	r = mdn_invalid_encoding;
	goto ret;
 overflow:
	r = mdn_buffer_overflow;
	goto ret;
}

static mdn_result_t
init_ctx(amcacev_ctx *ctx, size_t len) {
	if (len <= AMCACEV_BUFSIZE) {
		ctx->history = ctx->local_buf;
	} else {
		ctx->history = malloc(sizeof(ctx->history[0]) * len);
		if (ctx->history == NULL)
			return (mdn_nomemory);
	}
	ctx->cur = 0;
	ctx->style = 0;
	(void)memcpy(ctx->refpoint, amcacev_refpoint_initial,
		     sizeof(ctx->refpoint));
	return (mdn_success);
}

static void
release_ctx(amcacev_ctx *ctx) {
	if (ctx->history != ctx->local_buf)
		free(ctx->history);
	ctx->history = NULL;
}

static void
update_ctx(amcacev_ctx *ctx, unsigned long v) {
	int st, win;

	/* Get style */
	if (IN_WINDOW(ctx, v, 0, 1))
		ctx->style = 0;
	else if (!IN_WINDOW(ctx, v, 0, 1) &&
		 !IN_WINDOW(ctx, v, 0, 2) &&
		 !IN_WINDOW(ctx, v, 0, 3))
		ctx->style = 1;

	/* Add the character to the history. */
	ctx->history[ctx->cur++] = v;

	for (st = 0; st < 2; st++) {
		for (win = (st == 0) ? 1 : 2; win < 4; win++) {
			unsigned long oldref = ctx->refpoint[st][win];
			unsigned long newref = get_refpoint(v, st, win);
			int enclen1, enclen2;

			if (newref == oldref)
				continue;

			enclen1 = eval_compression(ctx);
			ctx->refpoint[st][win] = newref;
			enclen2 = eval_compression(ctx);
			if (enclen2 > enclen1)
				ctx->refpoint[st][win] = oldref;
		}
	}
}

static unsigned long
get_refpoint(unsigned long v, int st, int win) {
#define ROUND_BITS(v, b)	(((v) >> (b)) << (b))
	if (win == 1) {
		return (ROUND_BITS(v, 3));
	} else if (win == 2) {
		if (0xa0 <= v && v <= 0x17f)
			return (0xa0);
		else
			return (ROUND_BITS(v, 8));
	} else if (win == 3) {
		if (0x3000 <= v && v <= 0x9ffff)
			return (0x4e00);
		else if (st == 1 && 0xa000 <= v && v <= 0xd7ff)
			return (0x8800);
		else
			return (ROUND_BITS(v, (st == 0) ? 19 : 20));
	} else {
		FATAL(("get_refpoint: internal error\n"));
		return (0);	/* for lint */
	}
#undef ROUND_BITS
}

static int
eval_compression(amcacev_ctx *ctx) {
	int i;
	int len = 0;
	int cur = ctx->cur;
	unsigned long *p = ctx->history;

	for (i = 0; i < cur; i++) {
		if (!is_ldh(p[i])) {
			int sz;
			(void)encode_delta(p[i], ctx, &sz);
			len += sz;
		}
	}
	return (len);
}

static unsigned long
encode_delta(unsigned long v, amcacev_ctx *ctx, int *szp) {
	int sz;
	
	for (sz = (ctx->style == 0) ? 1 : 2; sz < 6; sz++) {
		if (IN_WINDOW(ctx, v, ctx->style, sz)) {
			*szp = sz;
			return (v - ctx->refpoint[ctx->style][sz]);
		}
	}
	FATAL(("amcacev_encode_mode: internal error\n"));
	return (0);	/* for lint */
}

static int
amcacev_getwc(const char *s, size_t len, int style, unsigned long *vp) {
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
amcacev_putwc(char *s, size_t len, unsigned long delta, int w) {
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
