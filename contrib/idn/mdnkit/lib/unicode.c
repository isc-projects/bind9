#ifndef lint
static char *rcsid = "$Id: unicode.c,v 1.13 2001/02/14 02:16:15 ishisone Exp $";
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

#include <mdn/result.h>
#include <mdn/logmacro.h>
#include <mdn/assert.h>
#include <mdn/unicode.h>

#define UCS_MAX		0x10ffff
#define END_BIT		0x80000000

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

#include "unicodedata.c"

/*
 * Macro for multi-level index table.
 */
#define LOOKUPTBL(vprefix, mprefix, v) \
	DMAP(vprefix)[\
		IMAP(vprefix)[\
			IMAP(vprefix)[IDX0(mprefix, v)] + IDX1(mprefix, v)\
		]\
	].tbl[IDX2(mprefix, v)]

#define IDX0(mprefix, v) IDX_0(v, BITS1(mprefix), BITS2(mprefix))
#define IDX1(mprefix, v) IDX_1(v, BITS1(mprefix), BITS2(mprefix))
#define IDX2(mprefix, v) IDX_2(v, BITS1(mprefix), BITS2(mprefix))

#define IDX_0(v, bits1, bits2)	((v) >> ((bits1) + (bits2)))
#define IDX_1(v, bits1, bits2)	(((v) >> (bits2)) & ((1 << (bits1)) - 1))
#define IDX_2(v, bits1, bits2)	((v) & ((1 << (bits2)) - 1))

#define BITS1(mprefix)	mprefix ## _BITS_1
#define BITS2(mprefix)	mprefix ## _BITS_2

#define IMAP(vprefix)	vprefix ## _imap
#define DMAP(vprefix)	vprefix ## _table

static mdn_result_t	casemap(unsigned long c, mdn__unicode_context_t ctx,
				unsigned long *v, size_t vlen, int *convlenp,
				int do_uppercase);

int
mdn__unicode_canonicalclass(unsigned long c) {
#if 0
	TRACE(("mdn__unicode_canonicalclass(c=%lx)\n", c));
#endif

	if (c > UCS_MAX)
		return (0);

	return (LOOKUPTBL(canon_class, CANON_CLASS, c));
}

mdn_result_t
mdn__unicode_decompose(int compat, unsigned long *v, size_t vlen,
		       unsigned long c, int *decomp_lenp)
{
	unsigned long *vorg = v;
	int seqidx;
	unsigned long *seq;

	assert(v != NULL && vlen >= 0 && decomp_lenp != NULL);

#if 0
	TRACE(("mdn__unicode_decompose(compat=%d,vlen=%d,c=%lx)\n",
	      compat, vlen, c));
#endif

	if (c > UCS_MAX)
		return (mdn_notfound);

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
	 * Look up decomposition table.  If no decomposition is defined
	 * or if it is a compatibility decomosition when canonical
	 * decomposition requested, return 'mdn_notfound'.
	 */
	seqidx = LOOKUPTBL(decompose, DECOMP, c);
	if (seqidx == 0 || (compat == 0 && (seqidx & DECOMP_COMPAT) != 0))
		return (mdn_notfound);
	
	/*
	 * Copy the decomposed sequence.  The end of the sequence are
	 * marked with END_BIT.
	 */
	seq = &decompose_seq[seqidx & ~DECOMP_COMPAT];
	do {
		unsigned long c;
		size_t dlen;
		mdn_result_t r;

		c = *seq & ~END_BIT;

		/* Decompose recursively. */
		r = mdn__unicode_decompose(compat, v, vlen, c, &dlen);
		if (r == mdn_success) {
			v += dlen;
			vlen -= dlen;
		} else if (r == mdn_notfound) {
			if (vlen < 1)
				return (mdn_buffer_overflow);
			*v++ = c;
			vlen--;
		} else {
			return (r);
		}

	} while ((*seq++ & END_BIT) == 0);
	
	*decomp_lenp = v - vorg;

	return (mdn_success);
}

int
mdn__unicode_iscompositecandidate(unsigned long c) {
#if 0
	TRACE(("mdn__unicode_iscompositecandidate(c=%lx)\n", c));
#endif

	if (c > UCS_MAX)
		return (0);

	/* Check for Hangul */
	if ((LBase <= c && c < LBase + LCount) || (SBase <= c && c < SLast))
		return (1);

	/*
	 * Look up composition table.  If there are no composition
	 * that begins with the given character, it is not a
	 * composition candidate.
	 */
	if (LOOKUPTBL(compose, CANON_COMPOSE, c) == 0)
		return (0);
	else
		return (1);
}

mdn_result_t
mdn__unicode_compose(unsigned long c1, unsigned long c2, unsigned long *compp)
{
	unsigned long x;
	int n;
	int seqidx, lo, hi;

	assert(compp != NULL);

#if 0
	TRACE(("mdn__unicode_compose(c1=%lx,c2=%lx)\n", c1, c2));
#endif

	if (c1 > UCS_MAX || c2 > UCS_MAX)
		return (mdn_notfound);

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
	 * Look up composition table.  If the result is 0, no composition
	 * is defined.  Otherwise, upper 16bits of the result contains
	 * the number of composition that begins with 'c1', and the lower
	 * 16bits is the offset in 'compose_seq'.
	 */
	if ((x = LOOKUPTBL(compose, CANON_COMPOSE, c1)) == 0)
		return (mdn_notfound);
	n = x >> 16;
	seqidx = x & 0xffff;

	/*
	 * The composite sequences are sorted by the 2nd character 'c2'.
	 * So we can use binary search.
	 */
	lo = seqidx;
	hi = seqidx + n - 1;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;

		if (compose_seq[mid].c2 < c2) {
			lo = mid + 1;
		} else if (compose_seq[mid].c2 > c2) {
			hi = mid - 1;
		} else {
			*compp = compose_seq[mid].comp;
			return (mdn_success);
		}
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
	return (casemap(c, ctx, v, vlen, convlenp, 1));
}

mdn_result_t
mdn__unicode_tolower(unsigned long c, mdn__unicode_context_t ctx,
		     unsigned long *v, size_t vlen, int *convlenp)
{
#if 0
	TRACE(("mdn__unicode_tolower(c=%lx)\n", c));
#endif
	return (casemap(c, ctx, v, vlen, convlenp, 0));
}

static mdn_result_t
casemap(unsigned long c, mdn__unicode_context_t ctx,
	unsigned long *v, size_t vlen, int *convlenp, int do_uppercase)
{
	unsigned long *seq;
	int seqidx;

	if (vlen < 1)
		return (mdn_buffer_overflow);

	if (c > UCS_MAX)
		goto nomap;

	/*
	 * Look up toupper/tolower mapping table.
	 */
	if (do_uppercase) {
		seq = toupper_seq;
		seqidx = LOOKUPTBL(toupper, CASEMAP, c);
	} else {
		seq = tolower_seq;
		seqidx = LOOKUPTBL(tolower, CASEMAP, c);
	}

	/* Zero means there are no mapping. */
	if (seqidx == 0)
		goto nomap;

	/*
	 * There are two kinds of mapping, context-dependent and
	 * context-independent.  It is possible that both mappings
	 * are defined for a single character, so we have to loop
	 * through all the mappings.
	 */
	seq += seqidx;
	for (;;) {
		int found = 0;
		unsigned long flags = *seq++;

		if (flags & CMF_CTXDEP) {
			/*
			 * This is a context-dependent mapping.
			 * Check the specified context.
			 */
			switch (ctx) {
			case mdn__unicode_context_final:
				if (flags & CMF_FINAL)
					found = 1;
				break;
			case mdn__unicode_context_nonfinal:
				if (flags & CMF_NONFINAL)
					found = 1;
				break;
			default: /* mdn__unicode_context_unknown */
				/*
				 * Request context information.
				 */
				return (mdn_context_required);
			}
		} else {
			/*
			 * This is an ordinary, context-independent
			 * mapping.
			 */
			found = 1;
		}

		if (found) {
			/*
			 * Mapping found. Copy it.
			 */
			int i = 0;

			do {
				if (vlen-- < 1)
					return (mdn_buffer_overflow);
				*v++ = seq[i] & ~END_BIT;
			} while ((seq[i++] & END_BIT) == 0);

			*convlenp = i;
			return (mdn_success);
		} else {
			/*
			 * This entry doesn't match.  Try next etnry.
			 */
			if (flags & CMF_LAST) {
				/* This is the last entry. */
				break;
			} else {
				/* Skip this entry. */
				while ((*seq++ & END_BIT) == 0)
					/* do nothing */;
			}
		}
	}

 nomap:
	*convlenp = 1;
	*v = c;
	return (mdn_success);
}

mdn__unicode_context_t
mdn__unicode_getcontext(unsigned long c) {
#if 0
	TRACE(("mdn__unicode_getcontext(c=%lx)\n", c));
#endif

	if (c > UCS_MAX)
		return (mdn__unicode_context_final);

	switch (LOOKUPTBL(casemap_ctx, CASEMAP_CTX, c)) {
	case CTX_CASED:
		return (mdn__unicode_context_nonfinal);
	case CTX_NSM:
		return (mdn__unicode_context_unknown);
	default:
		return (mdn__unicode_context_final);
	}
}

mdn_result_t
mdn__unicode_casefold(unsigned long c, unsigned long *v, size_t vlen,
		      int *foldlenp)
{
	unsigned long *vorg = v;
	int seqidx;
	unsigned long *seq;

	assert(v != NULL && vlen >= 0 && foldlenp != NULL);

#if 0
	TRACE(("mdn__unicode_casefold(compat=%d,vlen=%d,c=%lx)\n",
	      compat, vlen, c));
#endif

	if (c > UCS_MAX)
		goto nomap;

	/* Look up case folding table. */
	if ((seqidx = LOOKUPTBL(case_folding, CASE_FOLDING, c)) == 0)
		goto nomap;
	
	seq = &case_folding_seq[seqidx];
	do {
		if (vlen-- < 1)
			return (mdn_buffer_overflow);
		*v++ = *seq & ~END_BIT;
	} while ((*seq++ & END_BIT) == 0);
	
	*foldlenp = v - vorg;

	return (mdn_success);
 nomap:
	if (vlen < 1)
		return (mdn_buffer_overflow);
	*foldlenp = 1;
	*v = c;
	return (mdn_success);
}
