#ifndef lint
static char *rcsid = "$Id: translator.c,v 1.17 2000/11/21 02:09:05 ishisone Exp $";
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
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/translator.h>
#include <mdn/debug.h>

static int		numdots(const char *s);
static int		contain_invalid_char(const char *s);
static mdn_result_t	append_zld(char *s, size_t len, const char *zld);

mdn_result_t
mdn_translator_translate(mdn_converter_t local_converter,
			 mdn_converter_t local_alternate_converter,
			 const char *local_zld,
			 mdn_normalizer_t normalizer,
			 mdn_converter_t target_converter,
			 mdn_converter_t target_alternate_converter,
			 const char *target_zld,
			 const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	size_t fromlen;
	int process;
	char domainbuf1[512], domainbuf2[512];	/* enough */

	assert(local_converter != NULL && target_converter != NULL &&
	       from != NULL && to != NULL && tolen >= 0);

	TRACE(("mdn_translator_translate(local_encoding=%s,local_zld=%s,"
	      "target_encoding=%s,target_zld=%s,from=\"%s\")\n",
	      mdn_converter_localencoding(local_converter),
	      local_zld == NULL ? "(none)" : local_zld,
	      mdn_converter_localencoding(target_converter),
	      target_zld == NULL ? "(none)" : target_zld,
	      mdn_debug_xstring(from, 30)));

	fromlen = strlen(from);
	if (fromlen + 1 > sizeof(domainbuf1)) {
		WARNING(("mdn_translator_translate: "
			"given domainname too long\n"));
		return (mdn_invalid_name);
	}

	(void)strcpy(domainbuf1, from);

	DUMP(("mdn_translator_translate: before translation \"%s\"\n",
	     mdn_debug_xstring(domainbuf1, 200)));

#define PROCESS_LOCAL		1
#define PROCESS_LOCALALT	2
#define PROCESS_DONE		4

	process = 0;

	if (local_zld != NULL) {
		/*
		 * Check if the domain name matches the local ZLD.
		 * If it does, strip ZLD and continue translation.
		 * Otherwise, no further processing is needed.
		 */
		if (mdn_translator_matchzld(domainbuf1, local_zld)) {
			/* Remove ZLD. */
			domainbuf1[fromlen - strlen(local_zld)] = '\0';
			process |= PROCESS_LOCAL;
			if (local_alternate_converter != NULL &&
			    !contain_invalid_char(domainbuf1))
				process |= PROCESS_LOCALALT;
		}
	} else if (contain_invalid_char(domainbuf1)) {
		/*
		 * The name contains invalid characters (as a legal
		 * traditional domain name).  So there's no point in
		 * trying local-alt codeset.
		 */
		process |= PROCESS_LOCAL;
	} else {
		/*
		 * The given name is a valid ASCII domain name.
		 */
		if (mdn_converter_isasciicompatible(local_converter))
			process |= PROCESS_LOCAL;
		if (local_alternate_converter != NULL)
			process |= PROCESS_LOCALALT;
	}

	if ((process & PROCESS_LOCALALT) != 0) {
		/*
		 * First, try converting from the alternate encoding to UTF-8.
		 */
		TRACE(("mdn_translator_translate: %s to UTF-8\n",
		       mdn_converter_localencoding(
			       local_alternate_converter)));
		r = mdn_converter_convert(local_alternate_converter,
					  mdn_converter_l2u,
					  domainbuf1, domainbuf2,
					  sizeof(domainbuf2));
		if (r == mdn_success)
			process |= PROCESS_DONE;
		else if (r != mdn_invalid_encoding)
			return (r);
	}
	if ((process & PROCESS_DONE) == 0 && (process & PROCESS_LOCAL) != 0) {
		/*
		 * Convert from local encoding to UTF-8.
		 */
		TRACE(("mdn_translator_translate: %s to UTF-8\n",
		       mdn_converter_localencoding(local_converter)));
		r = mdn_converter_convert(local_converter,
					  mdn_converter_l2u,
					  domainbuf1, domainbuf2,
					  sizeof(domainbuf2));
		if (r == mdn_success)
			process |= PROCESS_DONE;
		else if (r != mdn_invalid_encoding)
			return (r);
	}
	if ((process & PROCESS_DONE) == 0) {
		/*
		 * Not converted.  Copy verbatim.
		 */
		TRACE(("mdn_translator_translate: no translation required\n"));
		if (tolen < fromlen + 1)
			return (mdn_buffer_overflow);
		(void)memcpy(to, from, fromlen + 1);
		return (mdn_success);
	}
#undef PROCESS_LOCAL
#undef PROCESS_LOCALALT
#undef PROCESS_DONE

	DUMP(("mdn_translator_translate: UTF-8 string \"%s\"\n",
	     mdn_debug_xstring(domainbuf2, 200)));

	/*
	 * Normalize, if normalizer is specified.
	 */
	if (normalizer != NULL) {
		r = mdn_normalizer_normalize(normalizer,
					     domainbuf2, domainbuf1,
					     sizeof(domainbuf1));
		if (r != mdn_success)
			return (r);

		DUMP(("mdn_translator_translate: after normalization \"%s\"\n",
		     mdn_debug_xstring(domainbuf1, 200)));
		
		if (numdots(domainbuf2) != numdots(domainbuf1)) {
			INFO(("mdn_translator_translate: "
			     "number of labels has been changed by "
			     "normalization\n"));
		}
	}

	/*
	 * Convert from UTF-8 to target encoding.
	 */
	TRACE(("mdn_translator_translate: UTF-8 to %s\n",
	      mdn_converter_localencoding(target_converter)));
	r = mdn_converter_convert(target_converter,
				  mdn_converter_u2l,
				  normalizer == NULL ?
				      domainbuf2 : domainbuf1,
				  to, tolen);
	if (r == mdn_nomapping && target_alternate_converter != NULL) {
		TRACE(("mdn_translator_translate: use alternate encoding\n"));
		r = mdn_converter_convert(target_alternate_converter,
					  mdn_converter_u2l,
					  normalizer == NULL ?
					  domainbuf2 : domainbuf1,
					  to, tolen);
	}
	if (r != mdn_success)
		return (r);

	/*
	 * Append ZLD, if any.
	 */
	if (target_zld != NULL)
		r = append_zld(to, tolen, target_zld);

	DUMP(("mdn_translator_translate: after translation \"%s\"\n",
	     mdn_debug_xstring(to, 200)));

	return (r);
}

int
mdn_translator_matchzld(const char *domain, const char *zld) {
	int dlen;
	int zlen;
	const char *p;
	int i;

	/* An empty ZLD can match everything. */
	if (zld == NULL)
		return (1);

	dlen = strlen(domain);
	zlen = strlen(zld);

	/*
	 * Since ZLD is canonicalized, it must end with dot.
	 * DOMAIN may or may not end with dot.
	 */
	if (dlen > 0 && domain[dlen - 1] != '.')
		zlen--;

	/* If ZLD is longer than domain, no way. */
	if (zlen > dlen)
		return (0);

	p = domain + dlen - zlen;
	for (i = 0; p[i] != '\0'; i++) {
		/* ZLD is canonicalized (i.e. uppercase letters) */
		if (p[i] == zld[i] ||
		    ('a' <= p[i] && p[i] <= 'z' && p[i] - 'a' + 'A' == zld[i]))
			continue;
		else
			return (0);
	}

	if (p > domain && p[-1] != '.')
		return (0);

	return (1);
}

/*
 * Canonicalize ZLD.
 *  -- empty ZLD are nullified.
 *  -- leading dot is removed.
 *  -- append dot if it does not end with dot.
 *  -- lowercase characters are converted to uppercase.
 */
mdn_result_t
mdn_translator_canonicalzld(const char *zld, char **canonicalizedp) {
	size_t len;
	int append_dot = 0;
	char *canonicalized, *p;
	int c;

	/* Remove leading '.' */
	if (zld != NULL && zld[0] == '.')
		zld++;

	/* Is it empty? */
	if (zld == NULL || strcmp(zld, "") == 0) {
		*canonicalizedp = NULL;
		return (mdn_success);
	}

	len = strlen(zld);
	if (zld[len - 1] != '.')
		append_dot = 1;

	if ((canonicalized = malloc(len + 1 + append_dot)) == NULL)
		return (mdn_nomemory);
	*canonicalizedp = canonicalized;

	for (p = canonicalized; (c = *zld) != '\0'; zld++, p++) {
		if ('a' <= c && c <= 'z')
			c += 'A' - 'a';
		*p = c;
	}
	if (append_dot)
		*p++ = '.';
	*p = '\0';

	return (mdn_success);
}

static int
numdots(const char *s) {
	int n = 0;

	while ((s = strchr(s, '.')) != NULL) {
		n++;
		s++;
	}
	return (n);
}

static int
contain_invalid_char(const char *s) {
	int c;

	while ((c = *s++) != '\0') {
		if (('a' <= c && c <= 'z') ||
		    ('A' <= c && c <= 'Z') ||
		    ('0' <= c && c <= '9') ||
		    c == '.' || c == '-')
			continue;	/* valid character */
		return (1);
	}
	return (0);
}

static mdn_result_t
append_zld(char *s, size_t len, const char *zld) {
	size_t slen = strlen(s);

	if (slen + strlen(zld) + 1 > len)
		return (mdn_buffer_overflow);
	(void)strcpy(s + slen, zld);
	return (mdn_success);
}
