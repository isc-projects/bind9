#ifndef lint
static char *rcsid = "$Id: normalizer.c,v 1.16 2000/11/17 06:00:02 ishisone Exp $";
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
#include <ctype.h>

#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/result.h>
#include <mdn/normalizer.h>
#include <mdn/strhash.h>
#include <mdn/unormalize.h>
#include <mdn/unicode.h>
#include <mdn/utf8.h>
#include <mdn/debug.h>

#define UNICODE_IDEOGRAPHIC_FULL_STOP				0x3002
#define UNICODE_FULLWIDTH_FULL_STOP				0xff0e
#define UNICODE_HALFWIDTH_IDEOGRAPHIC_FULL_STOP			0xff61
#define UNICODE_HALFWIDTH_KATAKANA_SEMI_VOICED_SOUND_MARK	0xff9f
#define UNICODE_MINUS_SIGN					0x2212
#define UNICODE_FULLWIDTH_DIGIT_ZERO				0xff10
#define UNICODE_FULLWIDTH_DIGIT_NINE				0xff19
#define UNICODE_FULLWIDTH_LATIN_CAPITAL_LETTER_A		0xff21
#define UNICODE_FULLWIDTH_LATIN_CAPITAL_LETTER_Z		0xff3a
#define UNICODE_FULLWIDTH_LATIN_SMALL_LETTER_A			0xff41
#define UNICODE_FULLWIDTH_LATIN_SMALL_LETTER_Z			0xff5a
#define UNICODE_KATAKANA_HIRAGANA_VOICED_SOUND_MARK		0x309b
#define UNICODE_KATAKANA_HIRAGANA_SEMI_VOICED_SOUND_MARK	0x309c
#define UNICODE_VOICED_SOUND_CANDIDATE_BEGIN			0x304b /* ka */
#define UNICODE_VOICED_SOUND_CANDIDATE_END			0x30dd /* ho */

#define MAX_LOCAL_SCHEME	3

#define INITIALIZED		(scheme_hash != NULL)

typedef struct {
	char *name;
	mdn_normalizer_proc_t proc;
} normalize_scheme_t;

struct mdn_normalizer {
	int nschemes;
	int scheme_size;
	normalize_scheme_t **schemes;
	normalize_scheme_t *local_buf[MAX_LOCAL_SCHEME];
};

static unsigned long ja_half_to_full[] = {
	0x3002, 0x300c, 0x300d, 0x3001, 0x30fb, 0x30f2,
	0x30a1, 0x30a3, 0x30a5, 0x30a7, 0x30a9, 0x30e3,
	0x30e5, 0x30e7, 0x30c3, 0x30fc, 0x30a2, 0x30a4,
	0x30a6, 0x30a8, 0x30aa, 0x30ab, 0x30ad, 0x30af,
	0x30b1, 0x30b3, 0x30b5, 0x30b7, 0x30b9, 0x30bb,
	0x30bd, 0x30bf, 0x30c1, 0x30c4, 0x30c6, 0x30c8,
	0x30ca, 0x30cb, 0x30cc, 0x30cd, 0x30ce, 0x30cf,
	0x30d2, 0x30d5, 0x30d8, 0x30db, 0x30de, 0x30df,
	0x30e0, 0x30e1, 0x30e2, 0x30e4, 0x30e6, 0x30e8,
	0x30e9, 0x30ea, 0x30eb, 0x30ec, 0x30ed, 0x30ef,
	0x30f3, 0x309b, 0x309c,
};

typedef struct {
	unsigned long ucs;
	unsigned long composed_ucs;
} voiced_sound_tbl_t;

static voiced_sound_tbl_t ja_voiced_sound[] = {
	{ 0x304b, 0x304c }, { 0x304d, 0x304e }, 
	{ 0x304f, 0x3050 }, { 0x3051, 0x3052 }, 
	{ 0x3053, 0x3054 }, { 0x3055, 0x3056 }, 
	{ 0x3057, 0x3058 }, { 0x3059, 0x305a }, 
	{ 0x305b, 0x305c }, { 0x305d, 0x305e }, 
	{ 0x305f, 0x3060 }, { 0x3061, 0x3062 }, 
	{ 0x3064, 0x3065 }, { 0x3066, 0x3067 }, 
	{ 0x3068, 0x3069 }, { 0x306f, 0x3070 }, 
	{ 0x3072, 0x3073 }, { 0x3075, 0x3076 }, 
	{ 0x3078, 0x3079 }, { 0x307b, 0x307c }, 
	{ 0x30a6, 0x30f4 }, { 0x30ab, 0x30ac }, 
	{ 0x30ad, 0x30ae }, { 0x30af, 0x30b0 }, 
	{ 0x30b1, 0x30b2 }, { 0x30b3, 0x30b4 }, 
	{ 0x30b5, 0x30b6 }, { 0x30b7, 0x30b8 }, 
	{ 0x30b9, 0x30ba }, { 0x30bb, 0x30bc }, 
	{ 0x30bd, 0x30be }, { 0x30bf, 0x30c0 }, 
	{ 0x30c1, 0x30c2 }, { 0x30c4, 0x30c5 }, 
	{ 0x30c6, 0x30c7 }, { 0x30c8, 0x30c9 }, 
	{ 0x30cf, 0x30d0 }, { 0x30d2, 0x30d3 }, 
	{ 0x30d5, 0x30d6 }, { 0x30d8, 0x30d9 }, 
	{ 0x30db, 0x30dc }, 
};

static voiced_sound_tbl_t ja_semi_voiced_sound[] = {
	{ 0x306f, 0x3071 }, { 0x3072, 0x3074 }, 
	{ 0x3075, 0x3077 }, { 0x3078, 0x307a }, 
	{ 0x307b, 0x307d }, { 0x30cf, 0x30d1 }, 
	{ 0x30d2, 0x30d4 }, { 0x30d5, 0x30d7 }, 
	{ 0x30d8, 0x30da }, { 0x30db, 0x30dd }, 
};

static mdn_strhash_t scheme_hash;

static mdn_result_t	expand_schemes(mdn_normalizer_t ctx);
static mdn_result_t	register_standard_normalizers(void);
static mdn_result_t	normalizer_ascii_lowercase(const char *from,
						  char *to, size_t tolen);
static mdn_result_t	normalizer_ascii_uppercase(const char *from,
						  char *to, size_t tolen);
static mdn_result_t	normalizer_unicode_lowercase(const char *from,
						     char *to, size_t tolen);
static mdn_result_t	normalizer_unicode_uppercase(const char *from,
						     char *to, size_t tolen);
static mdn_result_t	normalizer_unicode_caseconv(mdn_result_t (*caseconv)(),
						    const char *from,
						    char *to, size_t tolen);
static mdn__unicode_context_t	get_casemap_context(const char *from,
						    size_t fromlen);
static mdn_result_t	normalizer_ja_minus_hack(const char *from,
						 char *to, size_t tolen);
static mdn_result_t	normalizer_ja_delimiter_hack(const char *from,
						     char *to, size_t tolen);
static mdn_result_t	normalizer_ja_fullwidth(const char *from,
						char *to, size_t tolen);
static mdn_result_t	normalizer_ja_alnum_halfwidth(const char *from,
						      char *to, size_t tolen);
static mdn_result_t	normalizer_ja_voicedsound(const char *from,
						  char *to, size_t tolen);
static int		compose_voicedsound(unsigned long ucs1,
					    unsigned long ucs2,
					    unsigned long *composed);

static struct standard_normalizer {
	char *name;
	mdn_normalizer_proc_t proc;
} standard_normalizer[] = {
	{ "ascii-lowercase", normalizer_ascii_lowercase },
	{ "ascii-uppercase", normalizer_ascii_uppercase },
	{ "unicode-lowercase", normalizer_unicode_lowercase },
	{ "unicode-uppercase", normalizer_unicode_uppercase },
	{ "unicode-form-c", mdn__unormalize_formc },
	{ "unicode-form-d", mdn__unormalize_formd },
	{ "unicode-form-kc", mdn__unormalize_formkc },
	{ "unicode-form-kd", mdn__unormalize_formkd },
	{ "ja-minus-hack", normalizer_ja_minus_hack },
	{ "ja-delimiter-hack", normalizer_ja_delimiter_hack },
	{ "ja-fullwidth", normalizer_ja_fullwidth },
	{ "ja-kana-fullwidth", normalizer_ja_fullwidth },
	{ "ja-alnum-halfwidth", normalizer_ja_alnum_halfwidth },
	{ "ja-compose-voiced-sound", normalizer_ja_voicedsound },
	{ NULL, NULL },
};

mdn_result_t
mdn_normalizer_initialize(void) {
	mdn_strhash_t hash;
	mdn_result_t r;

	if (scheme_hash != NULL)
		return (mdn_success);	/* already initialized */

	if ((r = mdn_strhash_create(&hash)) != mdn_success) {
		WARNING(("mdn_normalizer_initialize: "
			"hash table creation failed\n"));
		return (r);
	}
	scheme_hash = hash;

	/* Register standard normalizers */
	return (register_standard_normalizers());
}

mdn_result_t
mdn_normalizer_create(mdn_normalizer_t *ctxp) {
	mdn_normalizer_t ctx;

	assert(ctxp != NULL);
	TRACE(("mdn_normalizer_create()\n"));

	if ((ctx = malloc(sizeof(struct mdn_normalizer))) == NULL) {
		WARNING(("mdn_normalizer_create: malloc failed\n"));
		return (mdn_nomemory);
	}

	ctx->nschemes = 0;
	ctx->scheme_size = MAX_LOCAL_SCHEME;
	ctx->schemes = ctx->local_buf;
	*ctxp = ctx;

	return (mdn_success);
}

void
mdn_normalizer_destroy(mdn_normalizer_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_normalizer_destroy()\n"));

	if (ctx->schemes != ctx->local_buf)
		free(ctx->schemes);

	free(ctx);
}

mdn_result_t
mdn_normalizer_add(mdn_normalizer_t ctx, const char *scheme_name) {
	mdn_result_t r;
	void *v;
	normalize_scheme_t *scheme;

	assert(ctx != NULL && scheme_name != NULL);

	TRACE(("mdn_normalizer_add(scheme_name=%s)\n", scheme_name));

	assert(INITIALIZED);

	if (mdn_strhash_get(scheme_hash, scheme_name, &v) != mdn_success) {
		WARNING(("mdn_normalizer_add: invalid scheme %s\n",
			 scheme_name));
		return (mdn_invalid_name);
	}

	scheme = v;

	assert(ctx->nschemes <= ctx->scheme_size);

	if (ctx->nschemes == ctx->scheme_size &&
	    (r = expand_schemes(ctx)) != mdn_success) {
		WARNING(("mdn_normalizer_add: malloc failed\n"));
		return (r);
	}

	ctx->schemes[ctx->nschemes++] = scheme;
	return (mdn_success);
}


mdn_result_t
mdn_normalizer_normalize(mdn_normalizer_t ctx, const char *from,
			 char *to, size_t tolen)
{
	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn_normalizer_normalize(from=\"%s\")\n",
	       mdn_debug_xstring(from, 20)));

	if (ctx->nschemes == 0) {
		/* No normalization needed. */
		size_t flen = strlen(from);

		if (tolen < flen + 1)
			return (mdn_buffer_overflow);
		memcpy(to, from, flen + 1);	/* +1 for NUL */
		return (mdn_success);
	} else if (ctx->nschemes == 1) {
		/* No temporary buffer needed. */
		TRACE(("mdn_normalizer_normalize: nomalization %s\n",
		       ctx->schemes[0]->name));
		return ((*ctx->schemes[0]->proc)(from, to, tolen));
	} else {
		/*
		 * Allocate two intermediate buffers.
		 */
		char *buffer[2];
		char local_buf[2][1024];	/* usually big enough */
		size_t buffer_size[2];
		mdn_result_t r = mdn_success;
		int i;

		/*
		 * Initialize the buffers to use the local
		 * storage (stack memory).
		 */
		buffer[0] = local_buf[0];
		buffer[1] = local_buf[1];
		buffer_size[0] = sizeof(local_buf[0]);
		buffer_size[1] = sizeof(local_buf[1]);

		for (i = 0; i < ctx->nschemes; i++) {
			const char *f;
			char *t;
			size_t len;
			int f_idx = i % 2;
			int t_idx = !f_idx;

			TRACE(("mdn_normalizer_normalize: nomalization %s\n",
			       ctx->schemes[i]->name));

			/*
			 * Set up from/to buffers.
			 */
		retry:
			if (i == 0)
				f = from;
			else
				f = buffer[f_idx];
			if (i == ctx->nschemes - 1) {
				t = to;
				len = tolen;
			} else {
				t = buffer[t_idx];
				len = buffer_size[t_idx];
			}

			/*
			 * Call the normalize procedure.
			 */
			r = (*ctx->schemes[i]->proc)(f, t, len);

			if (r == mdn_buffer_overflow && t != to) {
				/*
				 * Temporary buffer is too small.
				 * Make it bigger.
				 */
				char *p;

				TRACE(("mdn_normalizer_normalize: "
				       "allocating temporary buffer\n"));

				/* Make it double. */
				buffer_size[t_idx] *= 2;

				if (buffer[t_idx] == local_buf[t_idx]) {
					size_t flen = strlen(f) + 100;
					if (buffer_size[t_idx] < flen)
						buffer_size[t_idx] = flen;
					p = malloc(buffer_size[t_idx]);
				} else {
					p = realloc(buffer[t_idx],
						    buffer_size[t_idx]);
				}
				if (p == NULL) {
					WARNING(("mdn_normalizer_normalize: "
						 "malloc failed\n"));
					r = mdn_nomemory;
					goto ret;
				}
				buffer[t_idx] = p;
				/* Start it over again. */
				goto retry;
			} else if (r != mdn_success) {
				break;
			}
		}

	ret:
		if (buffer[0] != local_buf[0])
			free(buffer[0]);
		if (buffer[1] != local_buf[1])
			free(buffer[1]);

		return (r);
	}
}

mdn_result_t
mdn_normalizer_register(const char *scheme_name, mdn_normalizer_proc_t proc) {
	mdn_result_t r;
	normalize_scheme_t *scheme;

	assert(scheme_name != NULL && proc != NULL);

	TRACE(("mdn_normalizer_register(scheme_name=%s)\n", scheme_name));

	assert(INITIALIZED);

	scheme = malloc(sizeof(*scheme) + strlen(scheme_name) + 1);
	if (scheme == NULL) {
		WARNING(("mdn_normalizer_register: malloc failed\n"));
		return (mdn_nomemory);
	}
	scheme->name = (char *)(scheme + 1);
	(void)strcpy(scheme->name, scheme_name);
	scheme->proc = proc;

	r = mdn_strhash_put(scheme_hash, scheme_name, scheme);
	if (r != mdn_success)
		WARNING(("mdn_normalizer_register: registration failed\n"));

	return (r);
}

static mdn_result_t
expand_schemes(mdn_normalizer_t ctx) {
	normalize_scheme_t **new_schemes;
	int new_size = ctx->scheme_size * 2;

	if (ctx->schemes == ctx->local_buf) {
		new_schemes = malloc(sizeof(normalize_scheme_t) * new_size);
	} else {
		new_schemes = realloc(ctx->schemes,
				      sizeof(normalize_scheme_t) * new_size);
	}
	if (new_schemes == NULL)
		return (mdn_nomemory);

	if (ctx->schemes == ctx->local_buf)
		memcpy(new_schemes, ctx->local_buf, sizeof(ctx->local_buf));

	ctx->schemes = new_schemes;
	ctx->scheme_size = new_size;

	return (mdn_success);
}

static mdn_result_t
register_standard_normalizers(void) {
	int i;
	int failed = 0;

	for (i = 0; standard_normalizer[i].name != NULL; i++) {
		mdn_result_t r;
		r = mdn_normalizer_register(standard_normalizer[i].name,
					    standard_normalizer[i].proc);
		if (r != mdn_success) {
			WARNING(("mdn_normalizer_initialize: "
				"failed to register \"%-.100s\"\n",
				standard_normalizer[i].name));
			failed++;
		}
	}
	if (failed > 0)
		return (mdn_failure);
	else
		return (mdn_success);
}

/*
 * Standard Normalizer
 */

static mdn_result_t
normalizer_ascii_lowercase(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		int w = mdn_utf8_mblen(from);

		if (w == 0 || fromlen < w)
			return (mdn_invalid_encoding);
		else if (tolen < w)
			return (mdn_buffer_overflow);

		if (w == 1 && isupper((unsigned char)*from)) {
			*to++ = tolower((unsigned char)(*from++));
		} else {
			int i = w;
			while (i-- > 0)
				*to++ = *from++;
		}
		fromlen -= w;
		tolen -= w;
	}
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_ascii_uppercase(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		int w = mdn_utf8_mblen(from);

		if (w == 0 || fromlen < w)
			return (mdn_invalid_encoding);
		else if (tolen < w)
			return (mdn_buffer_overflow);

		if (w == 1 && islower((unsigned char)*from)) {
			*to++ = toupper((unsigned char)(*from++));
		} else {
			int i = w;
			while (i-- > 0)
				*to++ = *from++;
		}
		fromlen -= w;
		tolen -= w;
	}
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_unicode_lowercase(const char *from, char *to, size_t tolen) {
	return (normalizer_unicode_caseconv(mdn__unicode_tolower,
					    from, to, tolen));
}

static mdn_result_t
normalizer_unicode_uppercase(const char *from, char *to, size_t tolen) {
	return (normalizer_unicode_caseconv(mdn__unicode_toupper,
					    from, to, tolen));
}

static mdn_result_t
normalizer_unicode_caseconv(mdn_result_t (*caseconv)(),
			    const char *from, char *to, size_t tolen)
{
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
#define CASEMAPBUFSZ	4
		unsigned long c;
		unsigned long v[CASEMAPBUFSZ];
		mdn_result_t r;
		mdn__unicode_context_t ctx = mdn__unicode_context_unknown;
		size_t vlen;
		int w;
		int i;

		if ((w = mdn_utf8_getwc(from, fromlen, &c)) == 0)
			return (mdn_invalid_encoding);
		from += w;
		fromlen -= w;

	redo:
		r = (*caseconv)(c, ctx, v, CASEMAPBUFSZ, &vlen);
		switch (r) {
		case mdn_success:
			break;
		case mdn_context_required:
			ctx = get_casemap_context(from, fromlen);
			goto redo;
		case mdn_buffer_overflow:
			FATAL(("mdn_normalizer_normalize: "
			       "internal buffer overflow\n"));
			break;
		default:
			return (r);
		}

		for (i = 0; i < vlen; i++) {
			if ((w = mdn_utf8_putwc(to, tolen, v[i])) == 0)
				return (mdn_buffer_overflow);
			to += w;
			tolen -= w;
		}
	}
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn__unicode_context_t
get_casemap_context(const char *from, size_t fromlen) {
	while (fromlen > 0) {
		unsigned long v;
		mdn__unicode_context_t ctx;
		int w;

		if ((w = mdn_utf8_getwc(from, fromlen, &v)) == 0)
			return (mdn_invalid_encoding);
		from += w;
		fromlen -= w;
		ctx = mdn__unicode_getcontext(v);
		if (ctx == mdn__unicode_context_nonfinal ||
		    ctx == mdn__unicode_context_final)
			return (ctx);
	}
	return (mdn__unicode_context_final);
}

static mdn_result_t
normalizer_ja_minus_hack(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		unsigned long ucs;
		int width;

		if ((width = mdn_utf8_getwc(from, fromlen, &ucs)) == 0)
			return (mdn_invalid_encoding);
		from += width;
		fromlen -= width;

		if (ucs == UNICODE_MINUS_SIGN)
			ucs = '-';

		if ((width = mdn_utf8_putwc(to, tolen, ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_ja_delimiter_hack(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		unsigned long ucs;
		int width;

		if ((width = mdn_utf8_getwc(from, fromlen, &ucs)) == 0)
			return (mdn_invalid_encoding);
		from += width;
		fromlen -= width;

		if (ucs == UNICODE_IDEOGRAPHIC_FULL_STOP ||
		    ucs == UNICODE_FULLWIDTH_FULL_STOP)
			ucs = '.';

		if ((width = mdn_utf8_putwc(to, tolen, ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_ja_fullwidth(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		unsigned long ucs;
		int width;

		if ((width = mdn_utf8_getwc(from, fromlen, &ucs)) == 0)
			return (mdn_invalid_encoding);
		from += width;
		fromlen -= width;

		if (UNICODE_HALFWIDTH_IDEOGRAPHIC_FULL_STOP <= ucs &&
		    ucs <= UNICODE_HALFWIDTH_KATAKANA_SEMI_VOICED_SOUND_MARK) {
			ucs = ja_half_to_full[ucs - UNICODE_HALFWIDTH_IDEOGRAPHIC_FULL_STOP];
		}

		if ((width = mdn_utf8_putwc(to, tolen, ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_ja_alnum_halfwidth(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	while (fromlen > 0 && tolen > 0) {
		unsigned long ucs;
		int width;

		if ((width = mdn_utf8_getwc(from, fromlen, &ucs)) == 0)
			return (mdn_invalid_encoding);
		from += width;
		fromlen -= width;

		if (ucs >= UNICODE_FULLWIDTH_DIGIT_ZERO &&
		    ucs <= UNICODE_FULLWIDTH_DIGIT_NINE) {
			ucs -= UNICODE_FULLWIDTH_DIGIT_ZERO;
			ucs += '0';
		} else if (ucs >= UNICODE_FULLWIDTH_LATIN_CAPITAL_LETTER_A &&
			   ucs <= UNICODE_FULLWIDTH_LATIN_CAPITAL_LETTER_Z) {
			ucs -= UNICODE_FULLWIDTH_LATIN_CAPITAL_LETTER_A;
			ucs += 'A';
		} else if (ucs >= UNICODE_FULLWIDTH_LATIN_SMALL_LETTER_A &&
			   ucs <= UNICODE_FULLWIDTH_LATIN_SMALL_LETTER_Z) {
			ucs -= UNICODE_FULLWIDTH_LATIN_SMALL_LETTER_A;
			ucs += 'a';
		} else if (ucs == UNICODE_MINUS_SIGN) {
			ucs = '-';
		}

		if ((width = mdn_utf8_putwc(to, tolen, ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}

	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';
	return (mdn_success);
}

static mdn_result_t
normalizer_ja_voicedsound(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);
	unsigned long ucs, last_ucs;
	int width;

#define VOID_UCS	  0xffffffff	/* not a valid UCS-4 character. */

	for (last_ucs = VOID_UCS; fromlen > 0 && tolen > 0; last_ucs = ucs) {
		unsigned long composed_ucs;

		if ((width = mdn_utf8_getwc(from, fromlen, &ucs)) == 0)
			return (mdn_invalid_encoding);
		from += width;
		fromlen -= width;

		if (last_ucs == VOID_UCS)
			continue;

		/*
		 * See if 'ucs' can be composed with the previous character
		 * 'last_ucs'.
		 */
		if ((ucs == UNICODE_KATAKANA_HIRAGANA_SEMI_VOICED_SOUND_MARK ||
		     ucs == UNICODE_KATAKANA_HIRAGANA_VOICED_SOUND_MARK) &&
		    compose_voicedsound(last_ucs, ucs, &composed_ucs)) {
			/*
			 * They can be composed.  Replace 'last_ucs'
			 * with the composed character, and void 'ucs'.
			 */
			last_ucs = composed_ucs;
			ucs = VOID_UCS;
		}

		/*
		 * Append 'last_ucs' to the result buffer.
		 */
		if ((width = mdn_utf8_putwc(to, tolen, last_ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}

	/*
	 * If there is non-void 'last_ucs' character, append it to
	 * the result buffer.
	 */
	if (last_ucs != VOID_UCS) {
		if ((width = mdn_utf8_putwc(to, tolen, last_ucs)) == 0)
			return (mdn_buffer_overflow);
		to += width;
		tolen -= width;
	}
#undef VOID_UCS

	/*
	 * Terminate the result buffer with NUL.
	 */
	if (tolen <= 0)
		return (mdn_buffer_overflow);
	*to = '\0';

	return (mdn_success);
}

static int
compose_voicedsound(unsigned long ucs1, unsigned long ucs2,
		    unsigned long *composed)
{
	voiced_sound_tbl_t *tbl;
	size_t tblsize;
	int top, end;

	assert(ucs2 == UNICODE_KATAKANA_HIRAGANA_VOICED_SOUND_MARK ||
	       ucs2 == UNICODE_KATAKANA_HIRAGANA_SEMI_VOICED_SOUND_MARK);

	if (ucs1 < UNICODE_VOICED_SOUND_CANDIDATE_BEGIN ||
	    ucs1 > UNICODE_VOICED_SOUND_CANDIDATE_END)
		return (0);

	if (ucs2 == UNICODE_KATAKANA_HIRAGANA_VOICED_SOUND_MARK) {
		tbl = ja_voiced_sound;
		tblsize = sizeof(ja_voiced_sound) / sizeof(tbl[0]);
	} else {
		tbl = ja_semi_voiced_sound;
		tblsize = sizeof(ja_semi_voiced_sound) / sizeof(tbl[0]);
	}

	for (top = 0, end = tblsize - 1; top <= end;) {
		int mid = (top + end) / 2;
		unsigned long miducs = tbl[mid].ucs;

		if (ucs1 == miducs) {
			*composed = tbl[mid].composed_ucs;
			return (1);
		} else if (ucs1 < miducs) {
			end = mid - 1;
		} else {
			top = mid + 1;
		}
	}
	return (0);
}
