#ifndef lint
static char *rcsid = "$Id: unicode.c,v 1.11 2000/10/16 07:50:53 ishisone Exp $";
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
#ifdef DEBUG_HASHSTAT
#include <stdio.h>
#endif

#include <mdn/result.h>
#include <mdn/logmacro.h>
#include <mdn/assert.h>
#include <mdn/unicode.h>

#ifndef CANON_CLASS_NBUCKETS
#define CANON_CLASS_NBUCKETS	121
#endif
#ifndef COMPOSITION_NBUCKETS
#define COMPOSITION_NBUCKETS	332
#endif
#ifndef DECOMPOSITION_NBUCKETS
#define DECOMPOSITION_NBUCKETS	731
#endif
#ifndef CASEMAP_NBUCKETS
#define CASEMAP_NBUCKETS	269
#endif

/*
 * Some constants for Hangul decomposition/composition.
 */
#define SBase		0xac00
#define LBase		0x1100
#define VBase		0x1161
#define TBase		0x11a7
#define LCount		19
#define VCount		21
#define TCount		28
#define SLast		(SBase + LCount * VCount * TCount)

typedef unsigned short unicode_t;	/* 16bit unsigned integer is suffice */

struct canon_class {
	unicode_t c;
	unsigned short class;
	struct canon_class *next;
};

struct composition {
	unicode_t c1;
	unicode_t c2;
	unicode_t composed;
	struct composition *next;
};

struct decomposition {
	unicode_t c;
	unsigned short offset;
	unsigned short length;
	struct decomposition *next;
};

struct casemap {
	unicode_t c;
	unicode_t map;
	unsigned short flags;
	unsigned short length;
	struct casemap *next;
};

#include "unicodedata.c"

/*
 * Hash tables.
 */

static struct canon_class	*canon_class_hash[CANON_CLASS_NBUCKETS];
static struct composition	*composition_hash[COMPOSITION_NBUCKETS];
static struct decomposition	*canon_decomposition_hash[DECOMPOSITION_NBUCKETS];
static struct decomposition	*compat_decomposition_hash[DECOMPOSITION_NBUCKETS];
static struct casemap		*toupper_hash[CASEMAP_NBUCKETS];
static struct casemap		*tolower_hash[CASEMAP_NBUCKETS];

static int	initialized = 0;

static mdn_result_t	casemap(unsigned long c, mdn__unicode_context_t ctx,
				unsigned long *v, size_t vlen, int *convlenp,
				unsigned long *bitmap, struct casemap **hash);
static int		canon_class_hashval(unicode_t c);
static int		composition_hashval(unicode_t c1, unicode_t c2);
static int		decomposition_hashval(unicode_t c);
static int		casemap_hashval(unicode_t c);
static void		initialize(void);


#define CHECKBIT(v, bitmap, shift) \
	(((bitmap)[((v)>>(shift)) / 32] & (1 << (((v)>>(shift)) & 31))) != 0)

int
mdn__unicode_canonicalclass(unsigned long c) {
	struct canon_class *hp;

#if 0
	TRACE(("mdn__unicode_canonicalclass(c=%lx)\n", c));
#endif

	initialize();

	if (c > 0xffff)
		return (0);

	if (!CHECKBIT(c, canon_class_bitmap, CANON_CLASS_BM_SHIFT))
		return (0);

	hp = canon_class_hash[canon_class_hashval((unicode_t)c)];
	while (hp != NULL) {
		if (hp->c == c)
			return (hp->class);
		hp = hp->next;
	}
	return 0;
}

mdn_result_t
mdn__unicode_decompose(int compat, unsigned long *v, size_t vlen,
		       unsigned long c, int *decomp_lenp)
{
	unsigned long *vorg = v;
	int h;
	struct decomposition *hp;
	unicode_t *base;
	int i;

	assert(v != NULL && vlen >= 0 && decomp_lenp != NULL);

#if 0
	TRACE(("mdn__unicode_decompose(compat=%d,vlen=%d,c=%lx)\n",
	      compat, vlen, c));
#endif

	initialize();

	/*
	 * First, check for Hangul.
	 */
	if (SBase <= c && c < SLast) {
		int idx, t_offset, v_offset, l_offset;

		idx = c - SBase;
		t_offset = idx % TCount;
		idx /= TCount;
		v_offset = idx % VCount;
		l_offset = idx / VCount;
		if ((t_offset == 0 && vlen < 2) || (t_offset > 0 && vlen < 3))
			return (mdn_buffer_overflow);
		*v++ = LBase + l_offset;
		*v++ = VBase + v_offset;
		if (t_offset > 0)
			*v++ = TBase + t_offset;
		*decomp_lenp = v - vorg;
		return (mdn_success);
	}

	/*
	 * Check bitmap.
	 */
	if (c > 0xffff ||
	    (compat &&
	     !CHECKBIT(c, compat_decompose_bitmap, DECOMPOSE_BM_SHIFT)) ||
	    (!compat &&
	     !CHECKBIT(c, canon_decompose_bitmap, DECOMPOSE_BM_SHIFT)))
		return (mdn_notfound);

	/*
	 * Now, C is a decomposition candidate.
	 * Search the hash tables.
	 */
	h = decomposition_hashval((unicode_t)c);

	/*
	 * First, look for canonical decomposition.
	 */
	base = canon_decompose_data;
	hp = canon_decomposition_hash[h];
	while (hp != NULL) {
		if (hp->c == c)
			goto found;
		hp = hp->next;
	}

	if (!compat)
		return (mdn_notfound);

	/*
	 * Then, compatibility decomposition.
	 */
	base = compat_decompose_data;
	hp = compat_decomposition_hash[h];
	while (hp != NULL) {
		if (hp->c == c)
			goto found;
		hp = hp->next;
	}

	return (mdn_notfound);

found:
	/* Do we have enough space? */
	if (vlen < hp->length)
		return (mdn_buffer_overflow);

	base += hp->offset;
	for (i = 0; i < hp->length; i++) {
		mdn_result_t r;
		int len;

		/* Decompose recursively. */
		r = mdn__unicode_decompose(compat, v, vlen, base[i], &len);

		if (r == mdn_success) {
			v += len;
			vlen -= len;
		} else {
			*v++ = base[i];
			vlen--;
		}
	}
	*decomp_lenp = v - vorg;

	return (mdn_success);
}

int
mdn__unicode_iscompositecandidate(unsigned long c) {
#if 0
	TRACE(("mdn__unicode_iscompositecandidate(c=%lx)\n", c));
#endif
	return (c <= 0xffff &&
		((LBase <= c && c < LBase + LCount) ||
		 (SBase <= c && c < SLast) ||
		 CHECKBIT(c, compose_bitmap, COMPOSE_BM_SHIFT)));
}

mdn_result_t
mdn__unicode_compose(unsigned long c1, unsigned long c2, unsigned long *compp)
{
	struct composition *hp;

	assert(compp != NULL);

#if 0
	TRACE(("mdn__unicode_compose(c1=%lx,c2=%lx)\n", c1, c2));
#endif

	initialize();

	/*
	 * Check for Hangul.
	 */
	if (LBase <= c1 && c1 < LBase + LCount &&
	    VBase <= c2 && c2 < VBase + VCount) {
		/*
		 * Hangul L and V.
		 */
		*compp = SBase +
			((c1 - LBase) * VCount + (c2 - VBase)) * TCount;
		return (mdn_success);
	} else if (SBase <= c1 && c1 < SLast &&
		   TBase <= c2 && c2 < TBase + TCount &&
		   (c1 - SBase) % TCount == 0) {
		/*
		 * Hangul LV and T.
		 */
		*compp = c1 + (c2 - TBase);
		return (mdn_success);
	}

	/*
	 * Check bitmap.
	 */
	if (c1 > 0xffff || c2 > 0xffff ||
	    !CHECKBIT(c1, compose_bitmap, COMPOSE_BM_SHIFT))
		return (mdn_notfound);

	/*
	 * Composition candidate.  Search the hash table.
	 */
	hp = composition_hash[composition_hashval((unicode_t)c1,
						  (unicode_t)c2)];
	while (hp != NULL) {
		if (hp->c1 == c1 && hp->c2 == c2) {
			*compp = hp->composed;
			return (mdn_success);
		}
		hp = hp->next;
	}
	return (mdn_notfound);
}

mdn_result_t
mdn__unicode_toupper(unsigned long c, mdn__unicode_context_t ctx,
		     unsigned long *v, size_t vlen, int *convlenp)
{
#if 0
	TRACE(("mdn__unicode_toupper(c=%lx)\n", c));
#endif
	initialize();
	return (casemap(c, ctx, v, vlen, convlenp,
			toupper_bitmap, toupper_hash));
}

mdn_result_t
mdn__unicode_tolower(unsigned long c, mdn__unicode_context_t ctx,
		     unsigned long *v, size_t vlen, int *convlenp)
{
#if 0
	TRACE(("mdn__unicode_tolower(c=%lx)\n", c));
#endif
	initialize();
	return (casemap(c, ctx, v, vlen, convlenp,
			tolower_bitmap, tolower_hash));
}

static mdn_result_t
casemap(unsigned long c, mdn__unicode_context_t ctx,
	unsigned long *v, size_t vlen, int *convlenp,
	unsigned long *bitmap, struct casemap **hash)
{
	struct casemap *hp;

	if (vlen < 1)
		return (mdn_buffer_overflow);

	if (c > 0xffff)
		goto one_to_one;

	if (!CHECKBIT(c, bitmap, CASEMAP_BM_SHIFT))
		goto one_to_one;

	hp = hash[casemap_hashval((unicode_t)c)];
	while (hp != NULL) {
		if (hp->c == c) {
			if ((hp->flags & CMF_CTXDEP) == 0) {
			found:
				if (hp->flags & CMF_MULTICHAR) {
					int len = hp->length;
					unicode_t *up;

					if (vlen < hp->length)
						return (mdn_buffer_overflow);
					up = multichar_casemap_data +
						(unsigned int)hp->map;
					*convlenp = len;
					while (len-- > 0)
						*v++ = (unsigned long)*up++;
					return (mdn_success);
				} else {
					c = hp->map;
					goto one_to_one;
				}
			} else if (ctx == mdn__unicode_context_unknown) {
				return (mdn_context_required);
			} else if (((hp->flags & CMF_FINAL) &&
				    ctx == mdn__unicode_context_final) ||
				   ((hp->flags & CMF_NONFINAL) &&
				    ctx == mdn__unicode_context_nonfinal)) {
				goto found;
			}
		}
		hp = hp->next;
	}

 one_to_one:
	*convlenp = 1;
	*v = c;
	return (mdn_success);
}

mdn__unicode_context_t
mdn__unicode_getcontext(unsigned long c) {
	int idx;
	int offset;
	unsigned long *bm;
	int v;

#if 0
	TRACE(("mdn__unicode_getcontext(c=%lx)\n", c));
#endif

	if (c > 0xffff) {
		return (mdn__unicode_context_final);
	}
	idx = c / CTX_BLOCK_SZ;
	offset = c % CTX_BLOCK_SZ;
	if ((bm = casemap_ctx_sections[idx]) == NULL) {
		return (mdn__unicode_context_final);
	}
	v = (bm[(offset * 2) / 32] >> ((offset * 2) % 32)) & 3;
	if (v & CTX_NSM)
		return (mdn__unicode_context_unknown);
	else if (v & CTX_CASED)
		return (mdn__unicode_context_nonfinal);
	else
		return (mdn__unicode_context_final);
}

static int
canon_class_hashval(unicode_t c) {
	return c % CANON_CLASS_NBUCKETS;
}

static int
composition_hashval(unicode_t c1, unicode_t c2) {
	return (c1 * 11 + c2) % COMPOSITION_NBUCKETS;
}

static int
decomposition_hashval(unicode_t c) {
	return c % DECOMPOSITION_NBUCKETS;
}

static int
casemap_hashval(unicode_t c) {
	return c % CASEMAP_NBUCKETS;
}

static void
initialize(void) {
	int i;

	if (initialized)
		return;

#define ARRAYSIZE(var)	(sizeof(var) / sizeof((var)[0]))
#define INSERT(tbl, h, what) \
	(what).next = (tbl)[h]; \
	(tbl)[h] = &(what)

	for (i = 0; i < ARRAYSIZE(canon_class); i++) {
		int h = canon_class_hashval(canon_class[i].c);
		INSERT(canon_class_hash, h, canon_class[i]);
	}
	for (i = 0; i < ARRAYSIZE(compose_seq); i++) {
		int h = composition_hashval(compose_seq[i].c1,
					    compose_seq[i].c2);
		INSERT(composition_hash, h, compose_seq[i]);
	}
	for (i = 0; i < ARRAYSIZE(canon_decompose_seq); i++) {
		int h = decomposition_hashval(canon_decompose_seq[i].c);
		INSERT(canon_decomposition_hash, h, canon_decompose_seq[i]);
	}
	for (i = 0; i < ARRAYSIZE(compat_decompose_seq); i++) {
		int h = decomposition_hashval(compat_decompose_seq[i].c);
		INSERT(compat_decomposition_hash, h, compat_decompose_seq[i]);
	}
	for (i = 0; i < ARRAYSIZE(toupper_map); i++) {
		int h = casemap_hashval(toupper_map[i].c);
		INSERT(toupper_hash, h, toupper_map[i]);
	}
	for (i = 0; i < ARRAYSIZE(tolower_map); i++) {
		int h = casemap_hashval(tolower_map[i].c);
		INSERT(tolower_hash, h, tolower_map[i]);
	}
#undef ARRAYSIZE
#undef INSERT

	initialized = 1;
}

#ifdef DEBUG_HASHSTAT

#define DEFINE_GETLENGTH(name, type) \
static int				\
name(type p) {				\
	int len = 0;			\
	while (p != NULL) {		\
		len++;			\
		p = p->next;		\
	}				\
	return (len);			\
}

DEFINE_GETLENGTH(getlength_canon_class, struct canon_class *)
DEFINE_GETLENGTH(getlength_composition, struct composition *)
DEFINE_GETLENGTH(getlength_decomposition, struct decomposition *)
DEFINE_GETLENGTH(getlength_casemap, struct casemap *)

static void
print_hash_stat(void) {
	int i;
	int len;
	int total, max;

#define LENGTH(n) total += (n); if ((n) > max) {max = (n);}
#define PRINT(nb) \
	printf("\n nbuckets=%d, total=%d, max=%d (avr=%f)\n", \
	       nb, total, max, (double)total / nb)

#if 1
	printf("canon_class hash:\n  ");
	for (i = total = max = 0; i < CANON_CLASS_NBUCKETS; i++) {
		len = getlength_canon_class(canon_class_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(CANON_CLASS_NBUCKETS);
#endif

#if 1
	printf("composition hash:\n  ");
	for (i = total = max = 0; i < COMPOSITION_NBUCKETS; i++) {
		len = getlength_composition(composition_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(COMPOSITION_NBUCKETS);
#endif

#if 1
	printf("canonical decomposition hash:\n  ");
	for (i = total = max = 0; i < DECOMPOSITION_NBUCKETS; i++) {
		len = getlength_decomposition(canon_decomposition_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(DECOMPOSITION_NBUCKETS);
#endif

#if 1
	printf("compatibility decomposition hash:\n  ");
	for (i = total = max = 0; i < DECOMPOSITION_NBUCKETS; i++) {
		len = getlength_decomposition(compat_decomposition_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(DECOMPOSITION_NBUCKETS);
#endif

#if 1
	printf("toupper hash:\n  ");
	for (i = total = max = 0; i < CASEMAP_NBUCKETS; i++) {
		len = getlength_casemap(toupper_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(CASEMAP_NBUCKETS);
#endif

#if 1
	printf("tolower hash:\n  ");
	for (i = total = max = 0; i < CASEMAP_NBUCKETS; i++) {
		len = getlength_casemap(tolower_hash[i]);
		LENGTH(len);
		printf("%d ", len);
	}
	PRINT(CASEMAP_NBUCKETS);
#endif
}

int
main(int ac, char **av) {
	initialize();
	print_hash_stat();
}
#endif /* DEBUG_HASHSTAT */
