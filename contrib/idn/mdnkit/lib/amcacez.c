#ifndef lint
static char *rcsid = "$Id: amcacez.c,v 1.1.2.1 2002/02/08 12:13:45 marka Exp $";
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
#include <mdn/amcacez.h>
#include <mdn/ace.h>
#include <mdn/util.h>

/*
 * Although draft-ietf-idn-amc-ace-z-01.txt doesn't specify the ACE
 * signature, we have to choose one.  In order to prevent the converted
 * name from beginning with a hyphen, we should choose a prefix rather
 * than a suffix.
 */
#if !defined(MDN_AMCACEZ_PREFIX) && !defined(MDN_AMCACEZ_SUFFIX)
#define MDN_AMCACEZ_PREFIX	"zq--"
#endif

#define INVALID_UCS	0x80000000
#define MAX_UCS		0x10FFFF

/*
 * As the draft states, it is possible that `delta' may overflow during
 * the encoding.  The upper bound of 'delta' is:
 *   <# of chars. of input string> + <max. difference in code point> *
 *   <# of chars. of input string + 1>
 * For this value not to be greater than 0xffffffff (since the calculation
 * is done using unsigned long, which is at least 32bit long), the maxmum
 * input string size is about 3850 characters, which is long enough for
 * a domain label...
 */
#define AMCACEZ_MAXINPUT	3800

/*
 * Parameters.
 */
#define AMCACEZ_BASE		36
#define AMCACEZ_TMIN		1
#define AMCACEZ_TMAX		26
#define AMCACEZ_SKEW		38
#define AMCACEZ_DAMP		700
#define AMCACEZ_INITIAL_BIAS	72
#define AMCACEZ_INITIAL_N	0x80

static mdn_result_t	amcacez_decode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static mdn_result_t	amcacez_encode(const char *from, size_t fromlen,
				       char *to, size_t tolen);
static int		amcacez_getwc(const char *s, size_t len,
				      int bias, unsigned long *vp);
static int		amcacez_putwc(char *s, size_t len,
				      unsigned long delta, int bias);
static int		amcacez_update_bias(unsigned long delta,
					    size_t npoints, int first);

static mdn__ace_t amcacez_profile = {
#ifdef MDN_AMCACEZ_PREFIX
	mdn__ace_prefix,
	MDN_AMCACEZ_PREFIX,
#else
	mdn__ace_suffix,
	MDN_AMCACEZ_SUFFIX,
#endif
	amcacez_encode,
	amcacez_decode,
};



/* ARGSUSED */
mdn_result_t
mdn__amcacez_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		  void **privdata)
{
	return (mdn_success);
}

/* ARGSUSED */
mdn_result_t
mdn__amcacez_close(mdn_converter_t ctx, void *privdata,
		   mdn_converter_dir_t dir)
{
	return (mdn_success);
}

mdn_result_t
mdn__amcacez_convert(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir,
		     const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn__amcacez_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       mdn_debug_xstring(from, 20)));

	r = mdn__ace_convert(&amcacez_profile, dir, from, to, tolen);
	if (r != mdn_success)
		return (r);

	DUMP(("mdn__amcacez_convert: \"%s\"\n", mdn_debug_xstring(to, 70)));

	return (r);
}

static mdn_result_t
amcacez_decode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned long *ucs, ucs_tmp[64], c, idx;
	size_t uidx, fidx, ucslen;
	int first, bias;
	mdn_result_t r;

	/*
	 * Allocate enough memory for UCS-4 code point array 'ucs'.
	 */
	if (fromlen > 64) {
		ucs = malloc(fromlen * sizeof(unsigned long));
		if (ucs == NULL)
			return (mdn_nomemory);
	} else {
		ucs = ucs_tmp;
	}
	ucslen = 0;

	/*
	 * Find the last delimiter, and copy the characters
	 * before it verbatim.
	 */
	for (fidx = fromlen; fidx > 0; fidx--) {
		if (from[fidx - 1] == '-') {
			for (uidx = 0; uidx < fidx - 1; uidx++) {
				ucs[uidx] = from[uidx];
			}
			ucslen = uidx;
			break;
		}
	}

	first = 1;
	bias = AMCACEZ_INITIAL_BIAS;
	c = AMCACEZ_INITIAL_N;
	idx = 0;
	while (fidx < fromlen) {
		int len;
		unsigned long delta;
		int i;

		len = amcacez_getwc(from + fidx, fromlen - fidx, bias, &delta);
		if (len == 0)
			return (mdn_invalid_encoding);
		fidx += len;

		bias = amcacez_update_bias(delta, ucslen + 1, first);
		first = 0;
		idx += delta;
		c += idx / (ucslen + 1);
		uidx = idx % (ucslen + 1);

		/* Insert 'c' at uidx. */
		for (i = ucslen; i > uidx; i--)
			ucs[i] = ucs[i - 1];
		ucs[uidx] = c;

		ucslen++;
		idx = uidx + 1;
	}

	/*
	 * Convert from UCS-4 to UTF-8.
	 */
	for (uidx = 0; uidx < ucslen; uidx++) {
		int len = mdn_utf8_putwc(to, tolen, ucs[uidx]);
		if (len == 0)
			goto overflow;
		to += len;
		tolen -= len;
	}
	/* Terminate with NUL. */
	if (tolen <= 0)
		goto overflow;
	*to = '\0';

	r = mdn_success;
 ret:
	if (ucs != ucs_tmp)
		free(ucs);
	return (r);
	
 overflow:
	r = mdn_buffer_overflow;
	goto ret;
}

static mdn_result_t
amcacez_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	unsigned long *ucs, ucs_tmp[64];
	unsigned long cur_code, next_code, delta;
	size_t ucslen, ucsdone;
	size_t toidx;
	int uidx, bias, first;
	mdn_result_t r;

	/*
	 * Convert UTF-8 string 'from' to UCS-4 code point array 'ucs'.
	 */
	if (fromlen > 64) {
		ucs = malloc(fromlen * sizeof(unsigned long));
		if (ucs == NULL)
			return (mdn_nomemory);
	} else {
		ucs = ucs_tmp;
	}
	ucslen = 0;
	while (fromlen > 0) {
		unsigned long c;
		int len;

		len = mdn_utf8_getwc(from, fromlen, &c);
		if (len == 0 || c > MAX_UCS)
			goto invalid;
		ucs[ucslen++] = c;
		from += len;
		fromlen -= len;
	}

	/*
	 * If the input string is too long (actually too long to be sane),
	 * return failure in order to prevent possible overflow.
	 */
	if (ucslen > AMCACEZ_MAXINPUT)
		return (mdn_failure);

	ucsdone = 0;	/* number of characters processed */
	toidx = 0;

	/*
	 * First, pick up basic code points and copy them to 'to'.
	 */
	for (uidx = 0; uidx < ucslen; uidx++) {
		if (ucs[uidx] < 0x80) {
			if (toidx >= tolen)
				goto overflow;
			to[toidx++] = ucs[uidx];
			ucsdone++;
		}
	}

	/*
	 * If there are any basic code points, output a delimiter
	 * (hyphen-minus).
	 */
	if (toidx > 0) {
		if (toidx >= tolen)
			goto overflow;
		to[toidx++] = '-';
		to += toidx;
		tolen -= toidx;
	}

	/*
	 * Then encode non-basic characters.
	 */
	first = 1;
	cur_code = AMCACEZ_INITIAL_N;
	bias = AMCACEZ_INITIAL_BIAS;
	delta = 0;
	while (ucsdone < ucslen) {
		int limit = -1, rest;

		/*
		 * Find the smallest code point equal to or greater
		 * than 'cur_code'.  Also remember the index of the
		 * last occurence of the code point.
		 */
		for (next_code = MAX_UCS, uidx = ucslen - 1;
		     uidx >= 0; uidx--) {
			if (ucs[uidx] >= cur_code && ucs[uidx] < next_code) {
				next_code = ucs[uidx];
				limit = uidx;
			}
		}
		/* There must be such code point. */
		assert(limit >= 0);

		delta += (next_code - cur_code) * (ucsdone + 1);
		cur_code = next_code;

		/*
		 * Scan the input string again, and encode characters
		 * whose code point is 'cur_code'.  Use 'limit' to avoid
		 * unnecessary scan.
		 */
		for (uidx = 0, rest = ucsdone; uidx <= limit; uidx++) {
			if (ucs[uidx] < cur_code) {
				delta++;
				rest--;
			} else if (ucs[uidx] == cur_code) {
				int sz = amcacez_putwc(to, tolen, delta, bias);
				if (sz == 0)
					goto overflow;
				to += sz;
				tolen -= sz;
				ucsdone++;
				bias = amcacez_update_bias(delta, ucsdone,
							   first);
				delta = 0;
				first = 0;
			}
		}
		delta += rest + 1;
		cur_code++;
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		goto overflow;
	*to = '\0';

	r = mdn_success;
 ret:
	if (ucs != ucs_tmp)
		free(ucs);
	return (r);

 invalid:
	r = mdn_invalid_encoding;
	goto ret;
 overflow:
	r = mdn_buffer_overflow;
	goto ret;
}

static int
amcacez_getwc(const char *s, size_t len, int bias, unsigned long *vp) {
	size_t orglen = len;
	unsigned long v = 0, w = 1;
	int k;

	for (k = AMCACEZ_BASE - bias; len > 0; k += AMCACEZ_BASE) {
		int c = *s++;
		int t = (k < AMCACEZ_TMIN) ? AMCACEZ_TMIN :
			(k > AMCACEZ_TMAX) ? AMCACEZ_TMAX : k;

		len--;
		if ('a' <= c && c <= 'z')
			c = c - 'a';
		else if ('A' <= c && c <= 'Z')
			c = c - 'A';
		else if ('0' <= c && c <= '9')
			c = c - '0' + 26;
		else
			c = -1;

		if (c < 0)
			return (0);	/* invalid character */

		v += c * w;

		if (c < t) {
			*vp = v;
			return (orglen - len);
		}

		w *= (AMCACEZ_BASE - t);
	}

	return (0);	/* final character missing */
}

static int
amcacez_putwc(char *s, size_t len, unsigned long delta, int bias) {
	const char *amcacez_base36 = "abcdefghijklmnopqrstuvwxyz0123456789";
	int k;
	char *sorg = s;

	for (k = AMCACEZ_BASE - bias; 1; k += AMCACEZ_BASE) {
		int t = (k < AMCACEZ_TMIN) ? AMCACEZ_TMIN :
			(k > AMCACEZ_TMAX) ? AMCACEZ_TMAX : k;

		if (delta < t)
			break;
		if (len < 1)
			return (0);
		*s++ = amcacez_base36[t + ((delta - t) % (AMCACEZ_BASE - t))];
		len--;
		delta = (delta - t) / (AMCACEZ_BASE - t);
	}
	if (len < 1)
		return (0);
	*s++ = amcacez_base36[delta];
	return (s - sorg);
}

static int
amcacez_update_bias(unsigned long delta, size_t npoints, int first) {
	int k = 0;

	delta /= first ? AMCACEZ_DAMP : 2;
	delta += delta / npoints;

	while (delta > ((AMCACEZ_BASE - AMCACEZ_TMIN) * AMCACEZ_TMAX) / 2) {
		delta /= AMCACEZ_BASE - AMCACEZ_TMIN;
		k++;
	}
	return (AMCACEZ_BASE * k +
		(((AMCACEZ_BASE - AMCACEZ_TMIN + 1) * delta) /
		 (delta + AMCACEZ_SKEW)));
}
