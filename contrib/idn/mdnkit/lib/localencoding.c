#ifndef lint
static char *rcsid = "$Id: localencoding.c,v 1.1 2002/01/02 02:46:42 marka Exp $";
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
#include <stdio.h>
#include <string.h>

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#include <mdn/logmacro.h>
#include <mdn/localencoding.h>
#include <mdn/debug.h>

#if defined(HAVE_NL_LANGINFO) && defined(CODESET)

/*
 * This is the correct method to get the codeset name
 * corresponding to the current locale.
 */
const char *
mdn_localencoding_name(void) {
	char *name;

	TRACE(("mdn_localencoding_name()\n"));
	if ((name = getenv(MDN_LOCALCS_ENV)) == NULL)
		name = nl_langinfo(CODESET);
	TRACE(("local encoding=\"%-.30s\"\n", name == NULL ? "<null>" : name));
	return (name);
}

#else

typedef struct locale2encoding {
	char *locale_pattern;		/* locale name pattern */
	char *encoding;			/* MIME-preferred charset name */
} locale2encoding_t;

static locale2encoding_t l2e[] = {
	{ "*.ISO_8859-1",	"ISO-8859-1" },
	{ "*.ISO_8859-2",	"ISO-8859-2" },
	{ "*.SJIS",		"Shift_JIS" },
	{ "*.Shift_JIS",	"Shift_JIS" },
	{ "ja_JP.EUC",		"EUC-JP" },
	{ "ko_KR.EUC",		"EUC-KR" },
	{ "*.big5"		"Big5" },
	{ "*.Big5"		"Big5" },
	{ "*.KOI8-R",		"KOI8-R" },
	{ "*.GB2312",		"GB2312" },
#ifdef hpux
	{ "japanese",		"Shift_JIS" },
#else
	{ "japanese",		"EUC-JP" },
#endif
	{ "ja",			"EUC-JP" },
	{ NULL,			NULL },
};

static const char	*locale_to_encoding(const char *name);
static int		match(const char *pattern, const char *str);

const char *
mdn_localencoding_name(void) {
	char *name;

	TRACE(("mdn_localencoding_name()\n"));

	if ((name = getenv(MDN_LOCALCS_ENV)) != NULL) {
		TRACE(("local encoding=\"%-.30s\"\n",
		      name == NULL ? "<null>" : name));
		return (name);
	}
	(void)(
#if HAVE_SETLOCALE
		(name = setlocale(LC_CTYPE, NULL)) ||
#endif
		(name = getenv("LC_ALL")) ||
		(name = getenv("LC_CTYPE")) ||
		(name = getenv("LANG")));
	name = (char *)locale_to_encoding(name);
	TRACE(("local encoding=\"%-.30s\"\n", name == NULL ? "<null>" : name));
	return (name);
}

/*
 * Locale name to encoding name.
 */
static const char *
locale_to_encoding(const char *name) {
	int i;

	if (name == NULL)
		return (NULL);

	for (i = 0; l2e[i].locale_pattern != NULL; i++) {
		if (match(l2e[i].locale_pattern, name))
			return (l2e[i].encoding);
	}
	return name;
}

/*
 * Wild card matching function that supports only '*'.
 */
static int
match(const char *pattern, const char *str) {
	for (;;) {
		int c;

		switch (c = *pattern++) {
		case '\0':
			return (*str == '\0');
		case '*':
			while (!match(pattern, str)) {
				if (*str == '\0')
					return (0);
				str++;
			}
			return (1);
			break;
		default:
			if (*str++ != c)
				return (0);
			break;
		}
	}
}

#endif
