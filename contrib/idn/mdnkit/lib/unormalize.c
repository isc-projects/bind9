#ifndef lint
static char *rcsid = "$Id: unormalize.c,v 1.1 2002/01/02 02:46:50 marka Exp $";
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
#include <mdn/utf8.h>
#include <mdn/unicode.h>
#include <mdn/unormalize.h>
#include <mdn/debug.h>

#if !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
#define memmove(a,b,c)	bcopy((char *)(b),(char *)(a),(int)(c))
#endif

#define WORKBUF_SIZE		128
#define WORKBUF_SIZE_MAX	10000

typedef struct {
	mdn__unicode_version_t version; /* Unicode version */
	int cur;		/* pointing now processing character */
	int last;		/* pointing just after the last character */
	int size;		/* size of UCS and CLASS array */
	unsigned long *ucs;	/* UCS-4 characters */
	int *class;		/* and their canonical classes */
	unsigned long ucs_buf[WORKBUF_SIZE];	/* local buffer */
	int class_buf[WORKBUF_SIZE];		/* ditto */
} workbuf_t;

static mdn_result_t	normalize(mdn__unicode_version_t version,
				  int do_composition, int compat,
				  const char *from, char *to, size_t tolen);
static mdn_result_t	decompose(workbuf_t *wb, unsigned long c, int compat);
static void		get_class(workbuf_t *wb);
static void		reorder(workbuf_t *wb);
static void		compose(workbuf_t *wb);
static mdn_result_t	flush_before_cur(workbuf_t *wb,
					 char **top, size_t *tolenp);
static void		workbuf_init(workbuf_t *wb);
static void		workbuf_free(workbuf_t *wb);
static mdn_result_t	workbuf_extend(workbuf_t *wb);
static mdn_result_t	workbuf_append(workbuf_t *wb, unsigned long c);
static void		workbuf_shift(workbuf_t *wb, int shift);
static void		workbuf_removevoid(workbuf_t *wb);


mdn_result_t
mdn__unormalize_formc(mdn__unicode_version_t version,
		      const char *from, char *to, size_t tolen)
{
	assert(version != NULL && from != NULL && to != NULL && tolen >= 0);
	TRACE(("mdn__unormalize_formc(from=\"%s\", tolen=%d)\n",
	       mdn_debug_xstring(from, 20), tolen));
	return (normalize(version, 1, 0, from, to, tolen));
}

mdn_result_t
mdn__unormalize_formd(mdn__unicode_version_t version,
		      const char *from, char *to, size_t tolen)
{
	assert(version != NULL && from != NULL && to != NULL && tolen >= 0);
	TRACE(("mdn__unormalize_formd(from=\"%s\", tolen=%d)\n",
	       mdn_debug_xstring(from, 20), tolen));
	return (normalize(version, 0, 0, from, to, tolen));
}

mdn_result_t
mdn__unormalize_formkc(mdn__unicode_version_t version,
		       const char *from, char *to, size_t tolen)
{
	assert(version != NULL && from != NULL && to != NULL && tolen >= 0);
	TRACE(("mdn__unormalize_formkc(from=\"%s\", tolen=%d)\n",
	       mdn_debug_xstring(from, 20), tolen));
	return (normalize(version, 1, 1, from, to, tolen));
}

mdn_result_t
mdn__unormalize_formkd(mdn__unicode_version_t version,
		       const char *from, char *to, size_t tolen)
{
	assert(version != NULL && from != NULL && to != NULL && tolen >= 0);
	TRACE(("mdn__unormalize_formkd(from=\"%s\", tolen=%d)\n",
	       mdn_debug_xstring(from, 20), tolen));
	return (normalize(version, 0, 1, from, to, tolen));
}

static mdn_result_t
normalize(mdn__unicode_version_t version, int do_composition, int compat,
	  const char *from, char *to, size_t tolen)
{
	workbuf_t wb;
	size_t fromlen = strlen(from);
	mdn_result_t r = mdn_success;

	/*
	 * Initialize working buffer.
	 */
	workbuf_init(&wb);
	wb.version = version;

	while (fromlen > 0) {
		unsigned long c;
		int mblen;

		assert(wb.cur == wb.last);

		/*
		 * Get one character from 'from'.
		 */
		if ((mblen = mdn_utf8_getwc(from, fromlen, &c)) == 0) {
			r = mdn_invalid_encoding;
			break;
		}
		from += mblen;
		fromlen -= mblen;

		/*
		 * Decompose it.
		 */
		if ((r = decompose(&wb, c, compat)) != mdn_success)
			break;

		/*
		 * Get canonical class.
		 */
		get_class(&wb);

		/*
		 * Reorder & compose.
		 */
		for (; wb.cur < wb.last; wb.cur++) {
			if (wb.cur == 0) {
				continue;
			} else if (wb.class[wb.cur] > 0) {
				/*
				 * This is not a starter. Try reordering.
				 * Note that characters up to it are
				 * already in canonical order.
				 */
				reorder(&wb);
				continue;
			}

			/*
			 * This is a starter character, and there are
			 * some characters before it.  Those characters
			 * have been reordered properly, and
			 * ready for composition.
			 */
			if (do_composition && wb.class[0] == 0)
				compose(&wb);

			/*
			 * If CUR points to a starter character,
			 * then process of characters before CUR are
			 * already finished, because any further
			 * reordering/composition for them are blocked
			 * by the starter CUR points.
			 */
			if (wb.cur > 0 && wb.class[wb.cur] == 0) {
				/* Flush everything before CUR. */
				r = flush_before_cur(&wb, &to, &tolen);
				if (r != mdn_success)
					break;
			}
		}
	}

	if (r == mdn_success) {
		if (do_composition && wb.cur > 0 && wb.class[0] == 0) {
			/*
			 * There is some characters left in WB.
			 * They are ordered, but not composed yet.
			 * Now CUR points just after the last character in WB,
			 * and since compose() tries to compose characters
			 * between top and CUR inclusive, we must make CUR
			 * one character back during compose().
			 */
			wb.cur--;
			compose(&wb);
			wb.cur++;
		}
		/*
		 * Call this even when WB.CUR == 0, to make TO
		 * NUL-terminated.
		 */
		r = flush_before_cur(&wb, &to, &tolen);
	}

	workbuf_free(&wb);
	return (r);
}

static mdn_result_t
decompose(workbuf_t *wb, unsigned long c, int compat) {
	mdn_result_t r;
	int dec_len;

again:
	r = mdn__unicode_decompose(wb->version, compat, wb->ucs + wb->last,
				   wb->size - wb->last, c, &dec_len);
	switch (r) {
	case mdn_success:
		wb->last += dec_len;
		return (mdn_success);
	case mdn_notfound:
		return (workbuf_append(wb, c));
	case mdn_buffer_overflow:
		if ((r = workbuf_extend(wb)) != mdn_success)
			return (r);
		if (wb->size > WORKBUF_SIZE_MAX) {
			WARNING(("mdn__unormalize_form*: "
				"working buffer too large\n"));
			return (mdn_nomemory);
		}
		goto again;
	default:
		return (r);
	}
	/* NOTREACHED */
}

static void		
get_class(workbuf_t *wb) {
	int i;

	for (i = wb->cur; i < wb->last; i++)
		wb->class[i] = mdn__unicode_canonicalclass(wb->version,
							   wb->ucs[i]);
}

static void
reorder(workbuf_t *wb) {
	unsigned long c;
	int i;
	int class;

	assert(wb != NULL);

	i = wb->cur;
	c = wb->ucs[i];
	class = wb->class[i];

	while (i > 0 && wb->class[i - 1] > class) {
		wb->ucs[i] = wb->ucs[i - 1];
		wb->class[i] =wb->class[i - 1];
		i--;
		wb->ucs[i] = c;
		wb->class[i] = class;
	}
}

static void
compose(workbuf_t *wb) {
	int cur;
	unsigned long *ucs;
	int *class;
	int last_class;
	int nvoids;
	int i;
	mdn__unicode_version_t ver;

	assert(wb != NULL && wb->class[0] == 0);

	cur = wb->cur;
	ucs = wb->ucs;
	class = wb->class;
	ver = wb->version;

	/*
	 * If there are no decomposition sequence that begins with
	 * the top character, composition is impossible.
	 */
	if (!mdn__unicode_iscompositecandidate(ver, ucs[0]))
		return;

	last_class = 0;
	nvoids = 0;
	for (i = 1; i <= cur; i++) {
		unsigned long c;
		int cl = class[i];

		if ((last_class < cl || cl == 0) &&
		    mdn__unicode_compose(ver, ucs[0], ucs[i],
					 &c) == mdn_success) {
			/*
			 * Replace the top character with the composed one.
			 */
			ucs[0] = c;
			class[0] = mdn__unicode_canonicalclass(ver, c);

			class[i] = -1;	/* void this character */
			nvoids++;
		} else {
			last_class = cl;
		}
	}

	/* Purge void characters, if any. */
	if (nvoids > 0)
		workbuf_removevoid(wb);
}

static mdn_result_t
flush_before_cur(workbuf_t *wb, char **top, size_t *tolenp) {
	int cur = wb->cur;
	char *to = *top;
	size_t tolen = *tolenp;
	int i;

	for (i = 0; i < cur; i++) {
		int len = mdn_utf8_putwc(to, tolen, wb->ucs[i]);
		if (len == 0)
			return (mdn_buffer_overflow);
		to += len;
		tolen -= len;
	}
	if (tolen < 1)
		return (mdn_buffer_overflow);
	*to = '\0';

	*top = to;
	*tolenp = tolen;

	workbuf_shift(wb, cur);

	return (mdn_success);
}

static void
workbuf_init(workbuf_t *wb) {
	wb->cur = 0;
	wb->last = 0;
	wb->size = WORKBUF_SIZE;
	wb->ucs = wb->ucs_buf;
	wb->class = wb->class_buf;
}

static void
workbuf_free(workbuf_t *wb) {
	if (wb->ucs != wb->ucs_buf) {
		free(wb->ucs);
		free(wb->class);
	}
}

static mdn_result_t
workbuf_extend(workbuf_t *wb) {
	int newsize = wb->size * 3;

	if (wb->ucs == wb->ucs_buf) {
		wb->ucs = malloc(sizeof(wb->ucs[0]) * newsize);
		wb->class = malloc(sizeof(wb->class[0]) * newsize);
	} else {
		wb->ucs = realloc(wb->ucs, sizeof(wb->ucs[0]) * newsize);
		wb->class = realloc(wb->class, sizeof(wb->class[0]) * newsize);
	}
	if (wb->ucs == NULL || wb->class == NULL)
		return (mdn_nomemory);
	else
		return (mdn_success);
}

static mdn_result_t
workbuf_append(workbuf_t *wb, unsigned long c) {
	mdn_result_t r;

	if (wb->last >= wb->size && (r = workbuf_extend(wb)) != mdn_success)
		return (r);
	wb->ucs[wb->last++] = c;
	return (mdn_success);
}

static void
workbuf_shift(workbuf_t *wb, int shift) {
	int nmove;

	assert(wb != NULL && wb->cur >= shift);

	nmove = wb->last - shift;
	(void)memmove(&wb->ucs[0], &wb->ucs[shift],
		      nmove * sizeof(wb->ucs[0]));
	(void)memmove(&wb->class[0], &wb->class[shift],
		      nmove * sizeof(wb->class[0]));
	wb->cur -= shift;
	wb->last -= shift;
}

static void
workbuf_removevoid(workbuf_t *wb) {
	int i, j;
	int last = wb->last;

	for (i = j = 0; i < last; i++) {
		if (wb->class[i] >= 0) {
			if (j < i) {
				wb->ucs[j] = wb->ucs[i];
				wb->class[j] = wb->class[i];
			}
			j++;
		}
	}
	wb->cur -= last - j;
	wb->last = j;
}
