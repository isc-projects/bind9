#ifndef lint
static char *rcsid = "$Id: util.c,v 1.1 2002/01/02 02:46:51 marka Exp $";
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

#include <mdn/assert.h>
#include <mdn/result.h>
#include <mdn/logmacro.h>
#include <mdn/utf8.h>
#include <mdn/util.h>

/*
 * ASCII ctype macros.
 * Note that these macros evaluate the argument multiple times.  Be careful.
 */
#define ASCII_ISDIGIT(c) \
	('0' <= (c) && (c) <= '9')
#define ASCII_ISUPPER(c) \
	('A' <= (c) && (c) <= 'Z')
#define ASCII_ISLOWER(c) \
	('a' <= (c) && (c) <= 'z')
#define ASCII_ISALPHA(c) \
	(ASCII_ISUPPER(c) || ASCII_ISLOWER(c))
#define ASCII_ISALNUM(c) \
	(ASCII_ISDIGIT(c) || ASCII_ISUPPER(c) || ASCII_ISLOWER(c))

#define ASCII_TOUPPER(c) \
	(('a' <= (c) && (c) <= 'z') ? ((c) - 'a' + 'A') : (c))
#define ASCII_TOLOWER(c) \
	(('A' <= (c) && (c) <= 'Z') ? ((c) - 'A' + 'a') : (c))

/*
 * Unicode surrogate pair.
 */
#define IS_SURROGATE_HIGH(v)	(0xd800 <= (v) && (v) <= 0xdbff)
#define IS_SURROGATE_LOW(v)	(0xdc00 <= (v) && (v) <= 0xdfff)
#define SURROGATE_HIGH(v)	(SURROGATE_H_OFF + (((v) - 0x10000) >> 10))
#define SURROGATE_LOW(v)	(SURROGATE_L_OFF + ((v) & 0x3ff))
#define SURROGATE_BASE		0x10000
#define SURROGATE_H_OFF		0xd800
#define SURROGATE_L_OFF		0xdc00
#define COMBINE_SURROGATE(h, l) \
	(SURROGATE_BASE + (((h)-SURROGATE_H_OFF)<<10) + ((l)-SURROGATE_L_OFF))

int
mdn_util_casematch(const char *s1, const char *s2, size_t n) {
	assert(s1 != NULL && s2 != NULL);

	while (n-- > 0) {
		if (*s1 != *s2 && ASCII_TOLOWER(*s1) != ASCII_TOLOWER(*s2))
			return (0);
		else if (*s1 == '\0')
			break;
		s1++;
		s2++;
	}
	return (1);
}

const char *
mdn_util_domainspan(const char *s, const char *end) {
	while (s < end && (ASCII_ISALNUM(*s) || *s == '-'))
		s++;
	return (s);
}

int
mdn_util_validstd13(const char *s, const char *end) {
	if (!ASCII_ISALNUM(*s))
		return (0);
	s++;
	if (end == NULL) {
		while (*s != '\0') {
			if (!ASCII_ISALNUM(*s) && *s != '-')
				return (0);
			s++;
		}
	} else {
		while (s < end) {
			if (!ASCII_ISALNUM(*s) && *s != '-')
				return (0);
			s++;
		}
	}
	s--;
	if (!ASCII_ISALNUM(*s))
		return (0);
	return (1);
}

mdn_result_t
mdn_util_utf8toutf16(const char *utf8, size_t fromlen,
		     unsigned short *utf16, size_t tolen, size_t *reslenp)
{
	int i = 0;

	while (fromlen > 0) {
		unsigned long v;
		int flen;

		flen = mdn_utf8_getwc(utf8, fromlen, &v);
		if (flen == 0) {
			WARNING(("mdn_util_utf8toutf16: "
				 "invalid character\n"));
			return (mdn_invalid_encoding);
		}
		utf8 += flen;
		fromlen -= flen;

		if (tolen < 1)
			return (mdn_buffer_overflow);

		if (IS_SURROGATE_LOW(v) || IS_SURROGATE_HIGH(v)) {
			WARNING(("mdn_util_utf8toutf16: UTF-8 string contains "
				 "surrogate pair\n"));
			return (mdn_invalid_encoding);
		} else if (v > 0xffff) {
			/* Convert to surrogate pair */
			if (v >= 0x110000)
				return (mdn_invalid_encoding);
			if (tolen < 2)
				return (mdn_buffer_overflow);
			utf16[i++] = SURROGATE_HIGH(v);
			utf16[i++] = SURROGATE_LOW(v);
			tolen -= 2;
		} else {
			utf16[i++] = v;
			tolen--;
		}
	}
	*reslenp = i;
	return (mdn_success);
}

mdn_result_t
mdn_util_utf16toutf8(const unsigned short *utf16, size_t fromlen,
		     char *utf8, size_t tolen, size_t *reslenp)
{
	int i;
	char *org = utf8;

	for (i = 0; i < fromlen; i++) {
		unsigned long v;
		int w;

		if (IS_SURROGATE_HIGH(utf16[i])) {
			if (i + 1 >= fromlen ||
			    !IS_SURROGATE_LOW(utf16[i + 1])) {
				WARNING(("mdn_util_utf16toutf8: "
					 "corrupted surrogate pair\n"));
				return (mdn_invalid_encoding);
			}
			v = COMBINE_SURROGATE(utf16[i], utf16[i + 1]);
			i++;
		} else {
			v = utf16[i];
		}
		w = mdn_utf8_putwc(utf8, tolen, v);
		if (w == 0)
			return (mdn_buffer_overflow);
		utf8 += w;
		tolen -= w;
	}
	*reslenp = utf8 - org;
	return (mdn_success);
}
