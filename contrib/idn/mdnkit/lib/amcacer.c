#ifndef lint
static char *rcsid = "$Id: amcacer.c,v 1.1 2001/06/09 00:30:12 tale Exp $";
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
 * Although draft-ietf-idn-amc-ace-r-00.txt doesn't specify the ACE
 * signature, we have to choose one.  In order to prevent the converted
 * name from beginning with a hyphen, we should choose a prefix rather
 * than a suffix.
 */
#if !defined(MDN_AMCACER_PREFIX) && !defined(MDN_AMCACER_SUFFIX)
#define MDN_AMCACER_PREFIX	"amc3-"
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

static mdn_result_t	amcacer_decode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static mdn_result_t	amcacer_encode(const char *from, size_t fromlen,
				    char *to, size_t tolen);
static void		amcacer_update_refpoints(unsigned long *refpoint,
						 unsigned long *history,
						 int n);
static int		amcacer_getwc(const char *s, size_t len,
				      unsigned long *vp);
static int		amcacer_putwc(char *s, size_t len,
				      unsigned long v, int w);

static mdn_result_t	utf8_to_ucs4(const char *utf8, size_t fromlen,
				     ucsbuf_t *b);
static mdn_result_t	ucs4_to_utf8(ucsbuf_t *b, char *utf8, size_t ulen);
static void		ucsbuf_init(ucsbuf_t *b);
static mdn_result_t	ucsbuf_grow(ucsbuf_t *b);
static mdn_result_t	ucsbuf_append(ucsbuf_t *b, unsigned long v);
static void		ucsbuf_free(ucsbuf_t *b);
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
	0, 0x60, 0, 0, 0, 0x10000,
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
	size_t len;
	unsigned long refpoint[6], v;
	ucsbuf_t ucsb;
	int literal_mode = 0;
	mdn_result_t r;

	(void)memcpy(refpoint, amcacer_refpoint_initial, sizeof(refpoint));

	ucsbuf_init(&ucsb);

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
			len = amcacer_getwc(from, fromlen, &v);
			if (len == 0) {
				r = mdn_invalid_encoding;
				goto finish;
			}
			from += len;
			fromlen -= len;
			v = refpoint[len] + v;
		}
		if ((r = ucsbuf_append(&ucsb, v)) != mdn_success)
			goto finish;
		amcacer_update_refpoints(refpoint, ucsb.ucs, ucsb.len - 1);
	}

	r = ucs4_to_utf8(&ucsb, to, tolen);
 finish:
	ucsbuf_free(&ucsb);

	return (r);
}

static mdn_result_t
amcacer_encode(const char *from, size_t fromlen, char *to, size_t tolen) {
	ucsbuf_t ucsb;
	unsigned long *buf;
	size_t len;
	int literal_mode = 0;
	unsigned long refpoint[6];
	mdn_result_t r;
	int i;

	/* Initialize refpoints. */
	(void)memcpy(refpoint, amcacer_refpoint_initial, sizeof(refpoint));

	/*
	 * Convert input string to UCS-4.
	 */
	ucsbuf_init(&ucsb);
	if ((r = utf8_to_ucs4(from, fromlen, &ucsb)) != mdn_success)
		return (r);

	buf = ucsb.ucs;
	len = ucsb.len;

	/*
	 * Now 'buf' contains UCS-4 string consisting of 'len' characters.
	 */

	for (i = 0; i < len; i++) {
		if (buf[i] == '-') {
			/*
			 * Convert "-" to "--".
			 */
			if (tolen < 2)
				return (mdn_buffer_overflow);
			to[0] = to[1] = '-';
			to += 2;
			tolen -= 2;
		} else if (is_ldh(buf[i])) {
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
			*to++ = buf[i];
			tolen--;
		} else {
			/*
			 * Non-LDH characters.
			 */
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
				if (buf[i] >= refpoint[k] &&
				    buf[i] - refpoint[k] < (1 << (4 * k)))
					break;
			}
			k = amcacer_putwc(to, tolen, buf[i] - refpoint[k],
					    k);
			if (k == 0)
				goto overflow;
			to += k;
			tolen -= k;
			amcacer_update_refpoints(refpoint, buf, i);
		}
	}

	/*
	 * Terminate with NUL.
	 */
	if (tolen <= 0)
		return (mdn_buffer_overflow);

	*to = '\0';

	ucsbuf_free(&ucsb);
	return (mdn_success);

 overflow:
	ucsbuf_free(&ucsb);
	return (mdn_buffer_overflow);
}

static void
amcacer_update_refpoints(unsigned long *refpoint,
			 unsigned long *history, int n)
{
	int k;
	unsigned long lastchar = history[n];

#define MAX_K(k)	(1 << (4 * (k)))
#define ROUND_K(v, k)	(((v) >> (4 * (k))) << (4 * (k)))
	if (n == 0) {
		for (k = 1; k < 4; k++)
			refpoint[k] = ROUND_K(lastchar, k);
		return;
	}

	for (k = 1; k < 4; k++) {
		unsigned long max = MAX_K(k);
		int i;

		for (i = n - 1; i >= 0; i--) {
			if (is_ldh(history[i]))
				continue;
			if ((refpoint[k] ^ history[i]) < max)
				break;
			if ((lastchar ^ history[i]) < max) {
				refpoint[k] = ROUND_K(lastchar, k);
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

static mdn_result_t
ucs4_to_utf8(ucsbuf_t *b, char *utf8, size_t ulen) {
	unsigned long *s = b->ucs;
	size_t len = b->len;
	int i;

	for (i = 0; i < len; i++) {
		int w = mdn_utf8_putwc(utf8, ulen, s[i]);

		if (w == 0)
			return (mdn_buffer_overflow);
		utf8 += w;
		ulen -= w;
	}
	if (ulen < 1)
		return (mdn_buffer_overflow);
	*utf8 = '\0';
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
