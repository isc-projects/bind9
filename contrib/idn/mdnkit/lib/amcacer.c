#ifndef lint
static char *rcsid = "$Id: amcacer.c,v 1.1.2.1 2002/02/08 12:13:41 marka Exp $";
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
#include <mdn/amcacer.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-amc-ace-r-01.txt doesn't specify the ACE
 * signature, we have to choose one.  In order to prevent the converted
 * name from beginning with a hyphen, we should choose a prefix rather
 * than a suffix.
 */
#if !defined(MDN_AMCACER_PREFIX) && !defined(MDN_AMCACER_SUFFIX)
#define MDN_AMCACER_PREFIX	"amc3-"
#endif

#define MAX_UCS		0x10FFFF
#define AMCACER_BUFSIZE	64

typedef struct {
	unsigned long *history;
	unsigned long local_buf[AMCACER_BUFSIZE];
	int history_len;
	unsigned long refpoint[6];
	int updated;
} amcacer_encode_ctx;

static const char *base32encode = "abcdefghijkmnpqrstuvwxyz23456789";
static const int base32decode_ascii[26] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
};
static const int base32decode_digit[10] = {
	-1, -1, 24, 25, 26, 27, 28, 29, 30, 31,
};

static mdn_result_t	amcacer_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	amcacer_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	amcacer_init_ctx(amcacer_encode_ctx *ctx, size_t len);
static void		amcacer_free_ctx(amcacer_encode_ctx *ctx);
static void		amcacer_update_refpoints(amcacer_encode_ctx *ctx,
						 unsigned long c);
static int		amcacer_getwc(const char *s, size_t len,
				      unsigned long *vp);
static int		amcacer_putwc(char *s, size_t len,
				      unsigned long v, int w);
static int		is_ldh(unsigned long v);

static mdn__ace_t amcacer_ctx = {
#ifdef MDN_AMCACER_PREFIX
	mdn__ace_prefix,
	MDN_AMCACER_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACER_SUFFIX,
#endif
	amcacer_encode,
	amcacer_decode,
};

static const unsigned long amcacer_refpoint_initial[6] = {
	0, 0xe0, 0xa0, 0, 0, 0x10000,
};


/* ARGSUSED */
mdn_result_t
mdn__amcacer_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcacer_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcacer_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcacer_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcacer_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcacer_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcacer_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacer_encode_ctx ctx;
	mdn_result_t r;

	/* Initialize context. */
	if ((r = amcacer_init_ctx(&ctx, fromlen)) != mdn_success)
		return (r);

	while (fromlen > 0) {
		size_t len;
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
			len = amcacer_getwc(from, fromlen, &v);
			if (len == 0) {
				r = mdn_invalid_encoding;
				goto finish;
			}
			from += len;
			fromlen -= len;
			v = ctx.refpoint[len] + v;
			amcacer_update_refpoints(&ctx, v);
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

 finish:
	amcacer_free_ctx(&ctx);
	return (r);

 overflow:
	r = mdn_buffer_overflow;
	goto finish;
}

static mdn_result_t
amcacer_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	int literal_mode = 0;
	amcacer_encode_ctx ctx;
	mdn_result_t r;

	/* Initialize context. */
	if ((r = amcacer_init_ctx(&ctx, fromlen)) != mdn_success)
		return (r);

	while (fromlen > 0) {
		unsigned long c;
		size_t len;

		len = mdn_utf8_getwc(from, fromlen, &c);
		from += len;
		fromlen -= len;

		if (len == 0 || c >= MAX_UCS) {
			/*
			 * Invalid Unicode code point.
			 */
			r = mdn_invalid_encoding;
			goto ret;
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
			unsigned long *refpoint = ctx.refpoint;
			int k;

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
			for (k = 1; k < 6; k++) {
				if (c >= refpoint[k] &&
				    c - refpoint[k] < (1 << (4 * k)))
					break;
			}
			k = amcacer_putwc(to, tolen, c - refpoint[k], k);
			if (k == 0)
				goto overflow;
			to += k;
			tolen -= k;
			amcacer_update_refpoints(&ctx, c);
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		goto overflow;

	*to = '\0';
	r = mdn_success;
 ret:
	amcacer_free_ctx(&ctx);
	return (r);

 overflow:
	r = mdn_buffer_overflow;
	goto ret;
}

static mdn_result_t
amcacer_init_ctx(amcacer_encode_ctx *ctx, size_t len) {
	if (len > AMCACER_BUFSIZE) {
		ctx->history = malloc(sizeof(ctx->history[0]) * len);
		if (ctx->history == NULL)
			return (mdn_nomemory);
	} else {
		ctx->history = ctx->local_buf;
	}
	ctx->history_len = 0;
	(void)memcpy(ctx->refpoint, amcacer_refpoint_initial,
		     sizeof(ctx->refpoint));
	ctx->updated = 0;
	return (mdn_success);
}

static void
amcacer_free_ctx(amcacer_encode_ctx *ctx) {
	if (ctx->history != ctx->local_buf)
		free(ctx->history);
	ctx->history = NULL;
}

static void
amcacer_update_refpoints(amcacer_encode_ctx *ctx, unsigned long c) {
	unsigned long *refpoint = ctx->refpoint;
	unsigned long *history = ctx->history;
	int k;

	history[ctx->history_len++] = c;

#define MAX_K(k)	(1 << (4 * (k)))
#define ROUND_K(v, k)	(((v) >> (4 * (k))) << (4 * (k)))
	if (!ctx->updated) {
		for (k = 1; k < 4; k++)
			refpoint[k] = ROUND_K(c, k);
		ctx->updated = 1;
		return;
	}

	for (k = 1; k < 4; k++) {
		unsigned long max = MAX_K(k);
		int i;

		for (i = ctx->history_len - 2; i >= 0; i--) {
			if ((refpoint[k] ^ history[i]) < max)
				break;
			if ((c ^ history[i]) < max) {
				refpoint[k] = ROUND_K(c, k);
				return;
			}
		}
	}
#undef MAX_K
#undef ROUND_K
}

static int
amcacer_getwc(const char *s, size_t len, unsigned long *vp) {
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
amcacer_putwc(char *s, size_t len, unsigned long v, int w) {
	int i, shift;

	for (shift = 0, i = w - 1; i >= 0; i--) {
		s[i] = base32encode[(v & 0xf) + shift];
		v >>= 4;
		shift = 16;
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
