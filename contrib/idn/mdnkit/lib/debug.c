#ifndef lint
static char *rcsid = "$Id: debug.c,v 1.1 2002/01/02 02:46:40 marka Exp $";
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include <mdn/debug.h>

static char *hex = "0123456789abcdef";

char *
mdn_debug_hexstring(const char *s, int maxbytes) {
	int i;
	char *p;
	static char buf[256 * 3 + 3 + 1];	/* +3 for "..." */

	if (maxbytes > 256)
		maxbytes = 256;

	for (i = 0, p = buf; i < maxbytes; i++) {
		int c = ((unsigned char *)s)[i];

		if (c == '\0')
			break;
		*p++ = hex[c >> 4];
		*p++ = hex[c & 15];
		*p++ = ' ';
	}

	if (i >= maxbytes)
		(void)strcpy(p, "...");
	else
		*p = '\0';

	return (buf);
}

char *
mdn_debug_xstring(const char *s, int maxbytes) {
	int i;
	char *p;
	static char buf[256 * 4 + 3 + 1];	/* +3 for "..." */

	if (maxbytes > 256)
		maxbytes = 256;

	for (i = 0, p = buf; i < maxbytes; i++) {
		int c = ((unsigned char *)s)[i];

		if (c == '\0') {
			break;
		} else if (c < 0x20 || c > 0x7e) {
			*p++ = '\\';
			*p++ = 'x';
			*p++ = hex[c >> 4];
			*p++ = hex[c & 15];
		} else {
			*p++ = c;
		}
	}

	if (i >= maxbytes)
		(void)strcpy(p, "...");
	else
		*p = '\0';

	return (buf);
}

char *
mdn_debug_hexdata(const char *s, int length, int maxlength) {
	int i;
	const unsigned char *p = (const unsigned char *)s;
	char *q;
	static char buf[256 * 3 + 3 + 1];	/* +3 for "..." */
	char *cont = NULL;

	if (maxlength > 256)
		maxlength = 256;

	if (length > maxlength) {
		length = maxlength;
		cont = "...";
	}

	for (i = 0, q = buf; i < length; i++) {
		int c = p[i];

		*q++ = hex[c >> 4];
		*q++ = hex[c & 15];
		*q++ = ' ';
	}

	if (cont != NULL)
		(void)strcpy(q, "...");
	else
		*q = '\0';

	return (buf);
}

void
mdn_debug_hexdump(const char *s, int length) {
	int i;
	const unsigned char *p = (const unsigned char *)s;

	i = 0;
	while (length-- > 0) {
		if (i % 16 == 0) {
			if (i > 0)
				fprintf(stderr, "\n");
			fprintf(stderr, "%4x:", i);
		}
		fprintf(stderr, " %02x", p[i]);
		i++;
	}
	fprintf(stderr, "\n");
}
