/* $Id: filechecker.h,v 1.1.2.1 2002/02/08 12:13:01 marka Exp $ */
/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
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

#ifndef MDN_FILECHECKER_H
#define MDN_FILECHECKER_H 1

/*
 * Character checker -- check if there are any characters specified
 * by a file in the given string.
 */

#include <mdn/result.h>

/*
 * Check object type.
 */
typedef struct mdn__filechecker *mdn__filechecker_t;

/*
 * Read the contents of the given file and create a context for
 * checking.
 *
 * 'file' is the pathname of the file, which specifies the set of
 * characters to be checked.  The file is a simple text file, and
 * each line must be of the form either
 *   <code_point>
 * or
 *   <code_point>-<code_point>
 * (or comment, see below) where <code_point> is a UCS code point
 * represented as hexadecimal string with optional prefix `U+'
 * (ex. `0041' or `U+FEDC').
 *
 * The former specifies just one character (a code point, to be precise),
 * while the latter specified a range of characters.  In the case of
 * a character range, the first code point (before hyphen) must not be
 * greater than the second code point (after hyphen).
 *
 * Lines starting with `#' are comments.
 *
 * If file is read with no errors, the created context is stored in
 * '*ctxp', and 'mdn_success' is returned.  Otherwise, the contents
 * of '*ctxp' is undefined.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nofile		-- cannot open the specified file.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_invalid_syntax	-- file format is not valid.
 */
extern mdn_result_t
mdn__filechecker_create(const char *file, mdn__filechecker_t *ctxp);

/*
 * Release memory for the specified context.
 */
extern void
mdn__filechecker_destroy(mdn__filechecker_t ctx);

/*
 * See if the given string contains any specified characters.
 *
 * Check if there is any characters pecified by the context 'ctx' in
 * the string 'str', which must be a valid UTF-8 string.  If there
 * are none, NULL is stored in '*found'.  Otherwise, the pointer to
 * the first occurence of such character is stored in '*found'.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_encoding	-- 'str' is not a valid UTF-8 string.
 */
extern mdn_result_t
mdn__filechecker_lookup(mdn__filechecker_t ctx, const char *str,
			const char **found);

/*
 * The following functions are for internal use.
 * They are used for this module to be add to the checker module.
 */
extern mdn_result_t
mdn__filechecker_createproc(const char *parameter, void **ctxp);

extern void
mdn__filechecker_destroyproc(void *ctxp);

extern mdn_result_t
mdn__filechecker_lookupproc(void *ctx, const char *str, const char **found);

#endif /* MDN_FILECHECKER_H */
