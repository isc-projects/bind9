#ifndef lint
static char *rcsid = "$Id: util.c,v 1.9 2000/12/07 02:35:12 m-kasahr Exp $";
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/localencoding.h>
#include <mdn/utf8.h>
#include <mdn/selectiveencode.h>
#include <mdn/util.h>

#include "util.h"

extern int		line_number;
extern mdn_converter_t	conv_in_ctx;
extern mdn_converter_t	conv_out_ctx;
extern mdn_normalizer_t	norm_ctx;

extern void		errormsg(const char *fmt, ...);

static int		ascii_tolower(int c);

mdn_result_t
selective_encode(char *from, char *to, int tolen,
		 const char *zld, int auto_zld)
{
	for (;;) {
		int len;
		char *region_start, *region_end;
		mdn_result_t r;
		char save;

		/*
		 * Find the region that needs conversion.
		 */
		r = mdn_selectiveencode_findregion(from, &region_start,
						   &region_end);
		if (r == mdn_notfound) {
			/*
			 * Not found.  Just copy the whole thing.
			 */
			if (tolen <= strlen(from))
				return (mdn_buffer_overflow);
			(void)strcpy(to, from);
			return (mdn_success);
		} else if (r != mdn_success) {
			/* This should not happen.. */
			errormsg("internal error at line %d: %s\n",
				 line_number, mdn_result_tostring(r));
			return (r);
		}

		/*
		 * We have found a region to convert.
		 * First, copy the prefix part verbatim.
		 */
		len = region_start - from;
		if (tolen < len) {
			errormsg("internal buffer overflow at line %d\n",
				 line_number);
			return (mdn_buffer_overflow);
		}
		(void)memcpy(to, from, len);
		to += len;
		tolen -= len;

		/*
		 * Terminate the region with NUL.
		 */
		save = *region_end;
		*region_end = '\0';

		/*
		 * Encode the region.
		 */
		r = encode_region(region_start, to, tolen, zld, auto_zld);

		/*
		 * Restore character.
		 */
		*region_end = save;

		if (r != mdn_success)
			return (r);

		len = strlen(to);
		to += len;
		tolen -= len;

		from = region_end;
	}
}

mdn_result_t
encode_region(const char *region, char *to, int tolen,
	      const char *zld, int auto_zld)
{
	int len;
	mdn_result_t r;
	int full_domain;
	int protect_zld;
	char line[1024];
		
	/*
	 * Perform normalization.
	 */
	r = mdn_normalizer_normalize(norm_ctx, region, line, 1024);
	if (r != mdn_success) {
		errormsg("normalization failed at line %d: %s\n",
			 line_number,
			 mdn_result_tostring(r));
		return (r);
	}
	/*
	 * This is not necessary if the noramlizer works correctly,
	 * but just in case..
	 */
	if (!mdn_utf8_isvalidstring(line)) {
		errormsg("normalizer corrupsed line %d\n",
			 line_number);
		return (mdn_invalid_encoding);
	}

	/*
	 * Now we have normalized string in line.
	 * See if it ends with '.'.
	 */
	len = strlen(line);
	full_domain = (line[len - 1] == '.');

	/*
	 * Protect ZLD part (if any) from conversion.
	 */
	if ((protect_zld = zld_match(line, zld)) != 0)
		line[len - strlen(zld)] = '\0';

	/*
	 * Convert the region to the output encoding.
	 */
	r = mdn_converter_utf8tolocal(conv_out_ctx, line, to, tolen);
	if (r != mdn_success) {
		errormsg("conversion to %s failed at line %d: %s\n",
			 mdn_converter_localencoding(conv_out_ctx),
			 line_number,
			 mdn_result_tostring(r));
		return (r);
	}

	len = strlen(to);
	to += len;
	tolen -= len;
		
	if ((full_domain && auto_zld) || protect_zld) {
		/*
		 * Append ZLD.
		 */
		if ((len = strlen(zld)) >= tolen)
			return (mdn_buffer_overflow);
		(void)strcpy(to, zld);
		to += len;
		tolen -= len;
	}

	return (mdn_success);
}

void
canonical_zld(char *s, const char *zld) {
	int i;
	int zlen = strlen(zld);

	if (zlen > 256) {
		errormsg("ZLD is too long\n");
		exit(1);
	}

	/* Remove leading dot. */
	if (zld[0] == '.') {
		zld++;
		zlen--;
	}

	for (i = 0; i < zlen; i++) {
		int c = *zld;
		if (('A' <= c && c <= 'Z') ||
		    ('a' <= c && c <= 'z') ||
		    ('0' <= c && c <= '9') ||
		    c == '.' || c == '-') {
			*s++ = *zld++;
		} else {
			errormsg("ZLD contains illegal character %c\n", c);
			exit(1);
		}
	}

	/* Supply trailing dot, if needed. */
	if (zlen > 0 && s[-1] != '.')
		(void)strcpy(s, ".");
}

int
zld_match(const char *s, const char *zld) {
	int slen = strlen(s);
	int zlen = strlen(zld);
	int i;

	if (slen < zlen)
		return (0);

	/* oops, strcasecmp is not a stnadard function. */
	/* return (strcasecmp(s + slen - zlen, zld) == 0); */
	s += slen - zlen;
	for (i = 0; i < zlen; i++) {
		if (s[i] != zld[i] &&
		    s[i] != tolower((unsigned char)zld[i]) &&
		    s[i] != toupper((unsigned char)zld[i]))
			return (0);
	}
	return (1);
}

mdn_result_t
selective_decode(char *from, char *to, int tolen) {
	char *domain_name;
	char *ignored_chunk;
	char save;
	int len;
	mdn_result_t r;

	/*
	 * While `*from' points to a character in a string which may be
	 * a domain name, `domain_name' refers to the beginning of the
	 * domain name.
	 */
	domain_name = NULL;

	/*
	 * We ignores a chunk maching to the regular expression:
	 *    [\-\.][0-9A-Za-z\-\.]*
	 *
	 * While `*from' points to a character in such a chunk,
	 * `ignored_chunk' refers to the beginning of the chunk.
	 */
	ignored_chunk = NULL;

	for (;;) {
		if (*from == '-') {
			/*
			 * We don't recognize `.-' as a part of domain name.
			 */
			if (domain_name != NULL) {
				if (*(from - 1) == '.') {
					ignored_chunk = domain_name;
					domain_name = NULL;
				}
			} else if (ignored_chunk == NULL) {
				ignored_chunk = from;
			}

		} else if (*from == '.') {
			/*
			 * We don't recognize `-.' nor `..' as a part of
			 * domain name.
			 */
			if (domain_name != NULL) {
				if (*(from - 1) == '-' || *(from - 1) == '.') {
					ignored_chunk = domain_name;
					domain_name = NULL;
				}
			} else if (ignored_chunk == NULL) {
				ignored_chunk = from;
			}

		} else if (('a' <= *from && *from <= 'z') ||
			   ('A' <= *from && *from <= 'Z') ||
			   ('0' <= *from && *from <= '9')) {
			if (ignored_chunk == NULL && domain_name == NULL)
				domain_name = from;

		} else {
			if (ignored_chunk != NULL) {
				/*
				 * `from' reaches the end of the ignored chunk.
				 * Copy the chunk to `to'.
				 */
				len = from - ignored_chunk;
				if (tolen < len)
					return (mdn_buffer_overflow);
				(void)memcpy(to, ignored_chunk, len);
				to += len;
				tolen -= len;

			} else if (domain_name != NULL) {
				/*
				 * `from' reaches the end of the domain name.
				 * Decode the domain name, and copy the result
				 * to `to'.
				 */
				save = *from;
				*from = '\0';
				r = mdn_converter_localtoutf8(conv_in_ctx,
							      domain_name, to,
							      tolen);
				*from = save;

				if (r == mdn_success) {
					len = strlen(to);
				} else if (r == mdn_invalid_encoding) {
					len = from - domain_name;
					if (tolen < len)
						return (mdn_buffer_overflow);
					(void)memcpy(to, domain_name, len);
				} else {
					return (r);
				}
				to += len;
				tolen -= len;

			}

			/*
			 * Copy a character `*from' to `to'.
			 */
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to = *from;
			to++;
			tolen--;

			domain_name = NULL;
			ignored_chunk = NULL;

			if (*from == '\0')
				break;
		}

		from++;
	}

	return (mdn_success);
}

int
initialize_converter(const char *in_code, const char *out_code,
		     const char *encoding_alias)
{
	mdn_result_t r;

	if (encoding_alias != NULL &&
	    (r = mdn_converter_aliasfile(encoding_alias)) != mdn_success) {
		errormsg("cannot read alias file %s: %s\n",
			 encoding_alias, mdn_result_tostring(r));
		return (0);
	}
	if ((r = mdn_converter_initialize()) != mdn_success) {
		errormsg("converter initialization failed: %s\n",
			 mdn_result_tostring(r));
		return (0);
	}
	if ((r = mdn_converter_create(in_code, &conv_in_ctx, 0))
	    != mdn_success) {
		errormsg("cannot create converter for codeset %s: %s\n",
			 in_code, mdn_result_tostring(r));
		return (0);
	}
	if ((r = mdn_converter_create(out_code, &conv_out_ctx, 0))
	    != mdn_success) {
		errormsg("cannot create converter for codeset %s: %s\n",
			 out_code, mdn_result_tostring(r));
		return (0);
	}
	return (1);
}

int
initialize_normalizer(char **normalizer, int nnormalizer) {
	mdn_result_t r;
	int i;

	if ((r = mdn_normalizer_initialize()) != mdn_success) {
		errormsg("normalizer initialization failed: %s\n",
			 mdn_result_tostring(r));
		return (0);
	}
	if ((r = mdn_normalizer_create(&norm_ctx)) != mdn_success) {
		errormsg("cannot create normalizer: %s\n",
			 mdn_result_tostring(r));
		return (0);
	}
	for (i = 0; i < nnormalizer; i++) {
		if ((r = mdn_normalizer_add(norm_ctx, normalizer[i]))
		     != mdn_success) {
			errormsg("cannot add normalizer %s: %s\n",
				 normalizer[i], mdn_result_tostring(r));
			return (0);
		}
	}
	return (1);
}

static int
ascii_tolower(int c) {
	if ('A' <= c && c <= 'Z')
		return (c - 'A' + 'a');
	else
		return (c);
}
