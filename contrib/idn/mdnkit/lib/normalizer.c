#ifndef lint
static char *rcsid = "$Id: normalizer.c,v 1.1 2002/01/02 02:46:46 marka Exp $";
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

#define MAX_LOCAL_SCHEME	3

#define INITIALIZED		(scheme_hash != NULL)

typedef struct {
	char *name;
	mdn_normalizer_proc_t proc;
} normalize_scheme_t;

typedef mdn_result_t (*caseconv_proc_t)(mdn__unicode_version_t,
					unsigned long, mdn__unicode_context_t,
					unsigned long *, size_t, int *);

struct mdn_normalizer {
	int nschemes;
	int scheme_size;
	normalize_scheme_t **schemes;
	normalize_scheme_t *local_buf[MAX_LOCAL_SCHEME];
	int reference_count;
};

static mdn_strhash_t scheme_hash;

static mdn__unicode_version_t vcur = NULL;
static mdn__unicode_version_t v301 = NULL;
static mdn__unicode_version_t v310 = NULL;
#define INIT_VERSION(version, var) \
	if (var == NULL) { \
		mdn_result_t r = mdn__unicode_create(version, &var); \
		if (r != mdn_success) \
			return (r); \
	}

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
static mdn_result_t	normalizer_unicode_caseconv(caseconv_proc_t caseconv,
						    const char *from,
						    char *to, size_t tolen);
static mdn__unicode_context_t	get_casemap_context(mdn__unicode_version_t ver,
						    const char *from,
						    size_t fromlen);
static mdn_result_t	normalizer_unicode_casefold(const char *from,
						    char *to, size_t tolen);
static mdn_result_t	normalizer_formc(const char *from,
					 char *to, size_t tolen);
static mdn_result_t	normalizer_formd(const char *from,
					 char *to, size_t tolen);
static mdn_result_t	normalizer_formkc(const char *from,
					  char *to, size_t tolen);
static mdn_result_t	normalizer_formkd(const char *from,
					  char *to, size_t tolen);
static mdn_result_t	normalizer_formc_v301(const char *from,
					      char *to, size_t tolen);
static mdn_result_t	normalizer_formd_v301(const char *from,
					      char *to, size_t tolen);
static mdn_result_t	normalizer_formkc_v301(const char *from,
					       char *to, size_t tolen);
static mdn_result_t	normalizer_formkd_v301(const char *from,
					       char *to, size_t tolen);
static mdn_result_t	normalizer_formc_v310(const char *from,
					      char *to, size_t tolen);
static mdn_result_t	normalizer_formd_v310(const char *from,
					      char *to, size_t tolen);
static mdn_result_t	normalizer_formkc_v310(const char *from,
					       char *to, size_t tolen);
static mdn_result_t	normalizer_formkd_v310(const char *from,
					       char *to, size_t tolen);

static struct standard_normalizer {
	char *name;
	mdn_normalizer_proc_t proc;
} standard_normalizer[] = {
	{ "ascii-lowercase", normalizer_ascii_lowercase },
	{ "ascii-uppercase", normalizer_ascii_uppercase },
	{ "unicode-lowercase", normalizer_unicode_lowercase },
	{ "unicode-uppercase", normalizer_unicode_uppercase },
	{ "unicode-foldcase", normalizer_unicode_casefold },
	{ "unicode-form-c", normalizer_formc },
	{ "unicode-form-d", normalizer_formd },
	{ "unicode-form-kc", normalizer_formkc },
	{ "unicode-form-kd", normalizer_formkd },
	{ "unicode-form-c/3.0.1", normalizer_formc_v301 },
	{ "unicode-form-d/3.0.1", normalizer_formd_v301 },
	{ "unicode-form-kc/3.0.1", normalizer_formkc_v301 },
	{ "unicode-form-kd/3.0.1", normalizer_formkd_v301 },
	{ "unicode-form-c/3.1.0", normalizer_formc_v310 },
	{ "unicode-form-d/3.1.0", normalizer_formd_v310 },
	{ "unicode-form-kc/3.1.0", normalizer_formkc_v310 },
	{ "unicode-form-kd/3.1.0", normalizer_formkd_v310 },
	{ "nameprep-03", normalizer_formkc_v301 },
	{ "nameprep-05", normalizer_formkc_v310 },
	{ "nameprep-06", normalizer_formkc_v310 },
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
	ctx->reference_count = 1;
	*ctxp = ctx;

	return (mdn_success);
}

void
mdn_normalizer_destroy(mdn_normalizer_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_normalizer_destroy()\n"));
	TRACE(("mdn_normalizer_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_normalizer_destroy: the object is destroyed\n"));
		if (ctx->schemes != ctx->local_buf)
			free(ctx->schemes);
		free(ctx);
	}
}

void
mdn_normalizer_incrref(mdn_normalizer_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_normalizer_incrref()\n"));
	TRACE(("mdn_normalizer_incrref: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
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
mdn_normalizer_addall(mdn_normalizer_t ctx, const char **scheme_names,
		      int nschemes) {
	mdn_result_t r;
	int i;

	assert(ctx != NULL && scheme_names != NULL);

	TRACE(("mdn_normalizer_addall(nschemes=%d)\n", nschemes));

	for (i = 0; i < nschemes; i++) {
		r = mdn_normalizer_add(ctx, (const char *)*scheme_names);
		if (r != mdn_success)
			return (r);
		scheme_names++;
	}

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
normalizer_unicode_caseconv(caseconv_proc_t caseconv,
			    const char *from, char *to, size_t tolen)
{
	size_t fromlen = strlen(from);

	INIT_VERSION(NULL, vcur);

	while (fromlen > 0 && tolen > 0) {
#define CASEMAPBUFSZ	4
		unsigned long c;
		unsigned long v[CASEMAPBUFSZ];
		mdn_result_t r;
		mdn__unicode_context_t ctx = mdn__unicode_context_unknown;
		int vlen;
		int w;
		int i;

		if ((w = mdn_utf8_getwc(from, fromlen, &c)) == 0)
			return (mdn_invalid_encoding);
		from += w;
		fromlen -= w;

	redo:
		r = (*caseconv)(vcur, c, ctx, v, CASEMAPBUFSZ, &vlen);
		switch (r) {
		case mdn_success:
			break;
		case mdn_context_required:
			ctx = get_casemap_context(vcur, from, fromlen);
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
get_casemap_context(mdn__unicode_version_t ver,
		    const char *from, size_t fromlen) {
	while (fromlen > 0) {
		unsigned long v;
		mdn__unicode_context_t ctx;
		int w;

		if ((w = mdn_utf8_getwc(from, fromlen, &v)) == 0)
			return (mdn_invalid_encoding);
		from += w;
		fromlen -= w;
		ctx = mdn__unicode_getcontext(ver, v);
		if (ctx == mdn__unicode_context_nonfinal ||
		    ctx == mdn__unicode_context_final)
			return (ctx);
	}
	return (mdn__unicode_context_final);
}

static mdn_result_t
normalizer_unicode_casefold(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	INIT_VERSION(NULL, vcur);

	while (fromlen > 0 && tolen > 0) {
#define CASEFOLDBUFSZ	4
		unsigned long c;
		unsigned long v[CASEFOLDBUFSZ];
		mdn_result_t r;
		int vlen;
		int w;
		int i;

		if ((w = mdn_utf8_getwc(from, fromlen, &c)) == 0)
			return (mdn_invalid_encoding);
		from += w;
		fromlen -= w;

		r = mdn__unicode_casefold(vcur, c, v, CASEFOLDBUFSZ, &vlen);
		switch (r) {
		case mdn_success:
			break;
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

/*
 * Unicode Normalization Forms -- latest version
 */

static mdn_result_t
normalizer_formc(const char *from, char *to, size_t tolen) {
	INIT_VERSION(NULL, vcur);
	return (mdn__unormalize_formc(vcur, from, to, tolen));
}

static mdn_result_t
normalizer_formd(const char *from, char *to, size_t tolen) {
	INIT_VERSION(NULL, vcur);
	return (mdn__unormalize_formd(vcur, from, to, tolen));
}

static mdn_result_t
normalizer_formkc(const char *from, char *to, size_t tolen) {
	INIT_VERSION(NULL, vcur);
	return (mdn__unormalize_formkc(vcur, from, to, tolen));
}

static mdn_result_t
normalizer_formkd(const char *from, char *to, size_t tolen) {
	INIT_VERSION(NULL, vcur);
	return (mdn__unormalize_formkd(vcur, from, to, tolen));
}

/*
 * Unicode Normalization Forms -- version 3.0.1
 */

static mdn_result_t
normalizer_formc_v301(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.0.1", v301);
	return (mdn__unormalize_formc(v301, from, to, tolen));
}

static mdn_result_t
normalizer_formd_v301(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.0.1", v301);
	return (mdn__unormalize_formd(v301, from, to, tolen));
}

static mdn_result_t
normalizer_formkc_v301(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.0.1", v301);
	return (mdn__unormalize_formkc(v301, from, to, tolen));
}

static mdn_result_t
normalizer_formkd_v301(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.0.1", v301);
	return (mdn__unormalize_formkd(v301, from, to, tolen));
}

/*
 * Unicode Normalization Forms -- version 3.1.0
 */

static mdn_result_t
normalizer_formc_v310(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.1.0", v310);
	return (mdn__unormalize_formc(v310, from, to, tolen));
}

static mdn_result_t
normalizer_formd_v310(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.1.0", v310);
	return (mdn__unormalize_formd(v310, from, to, tolen));
}

static mdn_result_t
normalizer_formkc_v310(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.1.0", v310);
	return (mdn__unormalize_formkc(v310, from, to, tolen));
}

static mdn_result_t
normalizer_formkd_v310(const char *from, char *to, size_t tolen) {
	INIT_VERSION("3.1.0", v310);
	return (mdn__unormalize_formkd(v310, from, to, tolen));
}

