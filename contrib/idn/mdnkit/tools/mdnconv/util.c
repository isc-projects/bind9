#ifndef lint
static char *rcsid = "$Id: util.c,v 1.1 2002/01/02 02:47:02 marka Exp $";
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
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <mdn/resconf.h>
#include <mdn/res.h>
#include <mdn/utf8.h>
#include <mdn/selectiveencode.h>

#include "util.h"

extern int		line_number;

mdn_result_t
selective_encode(mdn_resconf_t conf, char *insn,
		 char *from, char *to, int tolen)
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
		r = mdn_res_nameconv(conf, insn, region_start, to, tolen);

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
selective_decode(mdn_resconf_t conf, char *insn,
		 char *from, char *to, int tolen)
{
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
	 * We ignore chunks matching to the regular expression:
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
				r = mdn_res_nameconv(conf, insn,
						     domain_name, to, tolen);
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

void
set_encoding_alias(const char *encoding_alias) {
	mdn_result_t r;

	if ((r = mdn_converter_aliasfile(encoding_alias)) != mdn_success) {
		errormsg("cannot read alias file %s: %s\n",
			 encoding_alias, mdn_result_tostring(r));
		exit(1);
	}
}

void
set_localcode(mdn_resconf_t conf, const char *code) {
	mdn_result_t r;

	r = mdn_resconf_setlocalconvertername(conf, code, 0);
	if (r != mdn_success) {
		errormsg("cannot create converter for codeset %s: %s\n",
			 code, mdn_result_tostring(r));
		exit(1);
	}
}

void
set_idncode(mdn_resconf_t conf, const char *code) {
	mdn_result_t r;

	r = mdn_resconf_setidnconvertername(conf, code, 0);
	if (r != mdn_success) {
		errormsg("cannot create converter for codeset %s: %s\n",
			 code, mdn_result_tostring(r));
		exit(1);
	}
}

void
set_delimitermapper(mdn_resconf_t conf, unsigned long *delimiters,
		    int ndelimiters) {
	mdn_result_t r;

	r = mdn_resconf_addalldelimitermapucs(conf, delimiters, ndelimiters);
	if (r != mdn_success) {
		errormsg("cannot add delimiter: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
set_localmapper(mdn_resconf_t conf, char **mappers, int nmappers) {
	mdn_result_t r;

	/* Add mapping. */
	r = mdn_resconf_addalllocalmapselectornames(conf, 
						    MDN_MAPSELECTOR_DEFAULT,
						    (const char **)mappers,
						    nmappers);
	if (r != mdn_success) {
		errormsg("cannot add local map: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
set_nameprep(mdn_resconf_t conf, char *version) {
	mdn_result_t r;

	r = mdn_resconf_setnameprepversion(conf, version);
	if (r != mdn_success) {
		errormsg("error setting nameprep %s: %s\n",
			 version, mdn_result_tostring(r));
		exit(1);
	}
}

void
set_mapper(mdn_resconf_t conf, char **mappers, int nmappers) {
	mdn_result_t r;

	/* Configure mapper. */
	r = mdn_resconf_addallmappernames(conf, (const char **)mappers,
					  nmappers);
	if (r != mdn_success) {
		errormsg("cannot add nameprep map: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
set_normalizer(mdn_resconf_t conf, char **normalizers, int nnormalizer) {
	mdn_result_t r;

	r = mdn_resconf_addallnormalizernames(conf,
					      (const char **)normalizers,
					      nnormalizer);
	if (r != mdn_success) {
		errormsg("cannot add normalizer: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
set_prohibit_checkers(mdn_resconf_t conf, char **prohibits, int nprohibits) {
	mdn_result_t r;

	r = mdn_resconf_addallprohibitcheckernames(conf,
						   (const char **)prohibits,
						   nprohibits);
	if (r != mdn_success) {
		errormsg("cannot add prohibit checker: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
set_unassigned_checkers(mdn_resconf_t conf, char **unassigns, int nunassigns) {
	mdn_result_t r;

	r = mdn_resconf_addallunassignedcheckernames(conf,
						     (const char **)unassigns,
						     nunassigns);
	if (r != mdn_success) {
		errormsg("cannot add unassigned checker: %s\n",
			 mdn_result_tostring(r));
		exit(1);
	}
}

void
check_defaultlocalcode(mdn_resconf_t conf, const char *opt) {
	mdn_converter_t conv = mdn_resconf_getlocalconverter(conf);

	if (conv == NULL) {
		errormsg("cannot get the default local encoding.\n"
			 "please specify an appropriate one "
			 "with `%s' option.\n", opt);
		exit(1);
	} else
		mdn_converter_destroy(conv);
}

void
check_defaultidncode(mdn_resconf_t conf, const char *opt) {
	mdn_converter_t conv = mdn_resconf_getidnconverter(conf);

	if (conv == NULL) {
		errormsg("cannot get the default IDN encoding.\n"
			 "please specify an appropriate one "
			 "with `%s' option.\n", opt);
		exit(1);
	} else
		mdn_converter_destroy(conv);
}

void
errormsg(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
