#ifndef lint
static char *rcsid = "$Id: utf5.c,v 1.1 2002/01/02 02:46:51 marka Exp $";
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
#include <mdn/logmacro.h>
#include <mdn/utf5.h>
#include <mdn/debug.h>

int
mdn_utf5_getwc(const char *s, size_t len, unsigned long *vp) {
	int top = 1;
	size_t orglen = len;
	unsigned long v = 0;

	assert(s != NULL && len >= 0 && vp != NULL);

#if 0
	TRACE(("mdn_utf5_getwc(s=<%s>,len=%d)\n",
	      mdn_debug_hexstring(s, 10), len));
#endif

	if (len == 0)
		return (0);

	/* Special case for domain name handling. */
	if (*s == '.') {
		*vp = '.';
		return (1);
	}

	while (len > 0) {
		int c = *s++;

		if (top) {
			if ('G' <= c && c <= 'V')
				v = c - 'G';
			else if ('g' <= c && c <= 'v')
				v = c - 'g';
			else
				return (0);
			top = 0;
		} else {
			if ('0' <= c && c <= '9')
				v = (v << 4) + (c - '0');
			else if ('A' <= c && c <= 'F')
				v = (v << 4) + (c - 'A' + 10);
			else if ('a' <= c && c <= 'f')
				v = (v << 4) + (c - 'a' + 10);
			else
				break;
		}
		len--;
	}
	*vp = v;
	return (orglen - len);
}

int
mdn_utf5_putwc(char *s, size_t len, unsigned long v) {
	int w;
	int off;

	assert(s != NULL);

#if 0
	TRACE(("mdn_utf5_putwc(v=%lx)\n", v));
#endif

	/* Special handling for domain delimiter '.' */
	if (v == '.') {
		if (len < 1)
			return (0);
		*s = v;
		return (1);
	}

	if (v < 0x10) {
		w = 1;
	} else if (v < 0x100) {
		w = 2;
	} else if (v < 0x1000) {
		w = 3;
	} else if (v < 0x10000) {
		w = 4;
	} else if (v < 0x100000) {
		w = 5;
	} else if (v < 0x1000000) {
		w = 6;
	} else if (v < 0x10000000) {
		w = 7;
	} else if (v < 0x80000000) {
		w = 8;
	} else {
		return (0);
	}

	if (len < w)
		return (0);

	off = (w - 1) * 4;
	*s++ = 'G' + ((v >> off) & 0xf);
	off -= 4;
	while (off >= 0) {
		int x = (v >> off) & 0xf;
		if (x < 10)
			*s++ = '0' + x;
		else
			*s++ = 'A' + x - 10;
		off -= 4;
	}
	return (w);
}
