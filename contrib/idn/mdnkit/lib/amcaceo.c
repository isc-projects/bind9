#ifndef lint
static char *rcsid = "$Id: amcaceo.c,v 1.1.2.1 2002/02/08 12:13:40 marka Exp $";
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
#include <mdn/amcaceo.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-amc-ace-o-00.txt doesn't specify the ACE
 * signature, we have to choose one.
 */
#if !defined(MDN_AMCACEO_PREFIX) && !defined(MDN_AMCACEO_SUFFIX)
#define MDN_AMCACEO_SUFFIX		"-amc2"
#endif

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
static const unsigned long special_refpoint[] = {
	0x20, 0x50, 0x70, 0xa0, 0xc0, 0xe0, 0x140, 0x270,
};

typedef struct {
	unsigned long refpoint[5];
	unsigned long prefix[3];
	int best_count;
	unsigned long best_refpoint;
	unsigned long best_prefix;
	unsigned long *input;
	size_t input_len;
} amcaceo_encode_ctx;

typedef struct {
	unsigned long refpoint[5];
} amcaceo_decode_ctx;

static mdn_result_t	amcaceo_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	amcaceo_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static void		init_encode_ctx(amcaceo_encode_ctx *ctx);
static void		choose_refpoints(amcaceo_encode_ctx *ctx);
static unsigned long	prefix_to_refpoint(int k, unsigned long prefix);
static void		census(amcaceo_encode_ctx *ctx, int k,
			       unsigned long prefix);
static int		find_refpoint(unsigned long *refpoint,
				      int start, unsigned long v);
static int		encode_refpoints(amcaceo_encode_ctx *ctx,
					 char *to, size_t tolen);
static int		encode_point(unsigned long *refpoint,
				     unsigned long v, char *to, size_t tolen);
static int		decode_point(unsigned long *refpoint,
				     const char *from, size_t fromlen,
				     unsigned long *vp);
static void		bootstrap(unsigned long *refpoint,
				  int k, unsigned long prefix);
static int		amcaceo_getwc(const char *s, size_t len,
				      unsigned long *vp);
static int		amcaceo_putwc(char *s, size_t len,
				      unsigned long v, int w);

static mdn_result_t	utf8_to_ucs4(const char *utf8, size_t fromlen,
				     ucsbuf_t *b);
static void		ucsbuf_init(ucsbuf_t *b);
static mdn_result_t	ucsbuf_grow(ucsbuf_t *b);
static mdn_result_t	ucsbuf_append(ucsbuf_t *b, unsigned long v);
static void		ucsbuf_free(ucsbuf_t *b);
static int		is_ldh(unsigned long v);

static mdn__ace_t amcaceo_ctx = {
#ifdef MDN_AMCACEO_PREFIX
	mdn__ace_prefix,
	MDN_AMCACEO_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACEO_SUFFIX,
#endif
	amcaceo_encode,
	amcaceo_decode,
};

/* ARGSUSED */
mdn_result_t
mdn__amcaceo_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcaceo_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcaceo_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcaceo_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcaceo_ctx, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcaceo_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcaceo_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	size_t len;
	int k;
	int literal_mode = 0;
	unsigned long v;
	unsigned long refpoint[5];
	static unsigned long refpoint_initial[5] = {
		0, 0x10, 0, 0, 0x10000,
	};

	memcpy(refpoint, refpoint_initial, sizeof(refpoint));
	for (k = 2; k >= 0; k--) {
		len = decode_point(refpoint, from, fromlen, &v);
		if (len == 0)
			return (mdn_invalid_encoding);
		from += len;
		fromlen -= len;
		bootstrap(refpoint, k, v);
	}

	while (fromlen > 0) {
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
			len = decode_point(refpoint, from, fromlen, &v);
			if (len == 0)
				return (mdn_invalid_encoding);
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
amcaceo_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	ucsbuf_t ucsb;
	amcaceo_encode_ctx ctx;
	size_t len;
	mdn_result_t r;
	int literal_mode = 0;
	int i;

	/*
	 * Convert to UCS-4.
	 */
	ucsbuf_init(&ucsb);
	if ((r = utf8_to_ucs4(from, fromlen, &ucsb)) != mdn_success)
		return (r);

	/*
	 * Verify that all the code points are within 0-0x10FFFF range.
	 */
	for (i = 0; i < ucsb.len; i++) {
		if (ucsb.ucs[i] > 0x10FFFF) {
			ucsbuf_free(&ucsb);
			return (mdn_invalid_encoding);
		}
	}

	init_encode_ctx(&ctx);
	ctx.input = ucsb.ucs;
	ctx.input_len = ucsb.len;
	choose_refpoints(&ctx);
	if ((len = encode_refpoints(&ctx, to, tolen)) == 0)
		goto overflow;

	to += len;
	tolen -= len;

	for (i = 0; i < ctx.input_len; i++) {
		unsigned long v = ctx.input[i];

		if (v == '-') {
			/*
			 * Convert "-" to "--".
			 */
			if (tolen < 2)
				goto overflow;
			to[0] = to[1] = '-';
			to += 2;
			tolen -= 2;
		} else if (is_ldh(v)) {
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
			*to++ = v;
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
			len = encode_point(ctx.refpoint, v, to, tolen);
			if (len == 0)
				goto overflow;
			to += len;
			tolen -= len;
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen < 1)
		return (mdn_buffer_overflow);

	to[0] = '\0';

	ucsbuf_free(&ucsb);
	return (mdn_success);

 overflow:
	ucsbuf_free(&ucsb);
	return (mdn_buffer_overflow);
}

static void
init_encode_ctx(amcaceo_encode_ctx *ctx) {
	ctx->refpoint[0] = 0;
	ctx->refpoint[1] = 0;
	ctx->refpoint[2] = 0;
	ctx->refpoint[3] = 0;
	ctx->refpoint[4] = 0x10000;
	ctx->prefix[0] = 0;
	ctx->prefix[1] = 0;
	ctx->prefix[2] = 0;
	ctx->best_count = 0;
	ctx->best_refpoint = 0;
	ctx->input = NULL;
	ctx->input_len = 0;
}

static void
choose_refpoints(amcaceo_encode_ctx *ctx) {
	unsigned long *v = ctx->input;
	size_t len = ctx->input_len;
	int k, i;

	for (k = 0; k < 3; k++) {
		unsigned long prefix;

		ctx->best_count = 0;
		ctx->best_refpoint = 0;
		ctx->best_prefix = 0;

		/*
		 * Try various prefixes and choose the best one.
		 */
		for (i = 0; i < len; i++) {
			prefix = v[i] >> ((k + 1) * 4);
			census(ctx, k, prefix);
		}
		if (k == 1) {
			for (i = 0; i < 8; i++) {
				prefix = 0xd8 + i;
				census(ctx, k, prefix);
			}
		} else if (k == 2) {
			prefix = 0xd;
			census(ctx, k, prefix);
		}
		ctx->refpoint[k] = ctx->best_refpoint;
		ctx->prefix[k] = ctx->best_prefix;
	}
}

static unsigned long
prefix_to_refpoint(int k, unsigned long prefix) {
	if (k == 1 && 0xd8 <= prefix && prefix <= 0xdf)
		return (special_refpoint[prefix - 0xd8]);
	else
		return (prefix << ((k + 1) * 4));
}

static void
census(amcaceo_encode_ctx *ctx, int k, unsigned long prefix) {
	unsigned long *v = ctx->input;
	size_t len = ctx->input_len;
	int count;
	int i;
	unsigned long *refpoint = ctx->refpoint;

	ctx->refpoint[k] = prefix_to_refpoint(k, prefix);

	count = 0;
	for (i = 0; i < len; i++) {
		if (!is_ldh(v[i]) && find_refpoint(refpoint, 0, v[i]) == k)
			count++;
	}
	for (i = 0; i < k; i++) {	/* draft say until i <= k */
		if (find_refpoint(refpoint, i + 1,
				  ctx->prefix[i] << (4 * (i + 1))) == k)
			count++;
	}
	if (count > ctx->best_count) {
		ctx->best_count = count;
		ctx->best_refpoint = refpoint[k];
		ctx->best_prefix = prefix;
	}
}

static int
find_refpoint(unsigned long *refpoint, int start, unsigned long v) {
	int i;
	static unsigned long window_size[] = {
		0x10, 0x100, 0x1000, 0x10000, 0x100000,
	};

	for (i = start; i < 5; i++) {
		if (v >= refpoint[i] && (v - refpoint[i]) < window_size[i])
			return (i);
	}
	return (-1);
}

static int
encode_refpoints(amcaceo_encode_ctx *ctx, char *to, size_t tolen) {
	int len;
	int total = 0;
	int k;

	/*
	 * No, despite the name, we are encoding prefixes, not refpoints.
	 */

	/*
	 * Set initial fixed refpoints.  Otherwise decoder cannot guess
	 * what they are.  The initial value is chosen so that prefix can
	 * be encoded efficiently.
	 */
	ctx->refpoint[0] = 0;
	ctx->refpoint[1] = 0x10;

	for (k = 2; k >= 0; k--) {
		len = encode_point(ctx->refpoint, ctx->prefix[k], to, tolen);
		if (len == 0)
			return (0);
		to += len;
		tolen -= len;
		total += len;
		bootstrap(ctx->refpoint, k, ctx->prefix[k]);
	}

	/*
	 * Here, all the refpoints is automagically restored to the
	 * original value.
	 */
	return (total);
}

static int
encode_point(unsigned long *refpoint, unsigned long v, char *to, size_t tolen)
{
	int k = find_refpoint(refpoint, 0, v);
	unsigned long delta = v - refpoint[k];

	return (amcaceo_putwc(to, tolen, delta, k + 1));
}

static int
decode_point(unsigned long *refpoint, const char *from, size_t fromlen,
	     unsigned long *vp)
{
	unsigned long delta;
	int w;

	w = amcaceo_getwc(from, fromlen, &delta);
	if (w > 0)
		*vp = refpoint[w - 1] + delta;

	return (w);
}

static void
bootstrap(unsigned long *refpoint, int k, unsigned long prefix) {
	int i;

	for (i = 3; i > 0; i--)
		refpoint[i] = refpoint[i - 1] << 4;
	if (k == 1 && 0xd8 <= prefix && prefix <= 0xdf)
		refpoint[0] = special_refpoint[prefix - 0xd8] >> 4;
	else
		refpoint[0] = prefix << 4;
}

static int
amcaceo_getwc(const char *s, size_t len, unsigned long *vp) {
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
amcaceo_putwc(char *s, size_t len, unsigned long v, int w) {
	int i, shift;

	if (len < w)
		return (0);

	for (shift = 0, i = w - 1; i >= 0; i--) {
		s[i] = base32encode[(v & 0xf) + shift];
		v >>= 4;
		shift = 16;
	}
	return (w);
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
