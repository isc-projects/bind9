/* $Id: unicode.h,v 1.10 2001/02/13 08:26:22 ishisone Exp $ */
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

#ifndef MDN_UNICODE_H
#define MDN_UNICODE_H 1

/*
 * Unicode attributes retriever.
 *
 * All the information this module provides is based on UnicodeData.txt,
 * CompositionExclusions-1.txt and SpecialCasing.txt, all of which can be
 * obtained from unicode.org.
 *
 * Unicode characters are represented as 'unsigned long'.
 */

#include <mdn/result.h>

/*
 * Context information for case conversion.
 */
typedef enum {
	mdn__unicode_context_unknown,
	mdn__unicode_context_final,
	mdn__unicode_context_nonfinal
} mdn__unicode_context_t;

/*
 * Get canonical class.
 *
 * For characters out of unicode range (i.e. above 0xffff), 0 will
 * be returned.
 */
extern int
mdn__unicode_canonicalclass(unsigned long c);

/*
 * Decompose a character.
 *
 * Decompose character given by 'c', and put the result into 'v',
 * which can hold 'vlen' characters.  The number of decomposed characters
 * will be stored in '*decomp_lenp'.
 *
 * If 'compat' is true, compatibility decomposition is performed.
 * Otherwise canonical decomposition is done.
 *
 * Since decomposition is done recursively, no further decomposition
 * will be needed.
 *
 * Returns:
 *	mdn_success		-- ok, decomposed.
 *	mdn_notfound		-- no decomposition possible.
 *	mdn_buffer_overflow	-- 'vlen' is too small.
 */
extern mdn_result_t
mdn__unicode_decompose(int compat, unsigned long *v, size_t vlen,
		       unsigned long c, int *decomp_lenp);

/*
 * Perform canonical composition.
 *
 * Do canonical composition to the character sequence 'c1' and 'c2', put the
 * result into '*compp'.
 *
 * Since Unicode Nomalization Froms requires only canonical composition,
 * compatibility composition is not supported.
 *
 * Returns:
 *	mdn_success		-- ok, composed.
 *	mdn_notfound		-- no composition possible.
 */
extern mdn_result_t
mdn__unicode_compose(unsigned long c1, unsigned long c2, unsigned long *compp);

/*
 * Returns if there may be a canonical composition sequence which starts
 * with the given character.
 *
 * Returns:
 *	1			-- there may be a composition sequence
 *				   (maybe not).
 *	0			-- no, there is definitely no such sequences.
 */
extern int
mdn__unicode_iscompositecandidate(unsigned long c);

/*
 * Translate lowercase character to uppercase, and vice versa, according
 * to Unicode Technical Report #21 "Case Mappings".
 *
 * Both functions perform conversion on the given unicode character 'c',
 * put the result into 'v', whose size is specified by 'vlen'.  The actual
 * number of characters stored in 'v' are returned as '*convlenp'.
 * In case 'c' has no mapping, 'v[0]' will contain 'c', and '*convlenp'
 * will be 1.
 *
 * Note that these functions perform locale-independent case conversion.
 *
 * There are some characters whose case mapping depends on the context.
 * 'ctx' specifies the context, which can be obtained by
 * 'mdn__unicode_getcontext'.  Most of the time you can just specify
 * 'mdn__unicode_context_unknown' as 'ctx', and if those functions
 * return 'mdn_context_required', you can get the context using
 * 'mdn__unicode_getcontext' and try again.
 *
 * Returns:
 *	mdn_success		-- successfully converted.
 *	mdn_context_required	-- context information is needed to
 *				   perform case conversion on 'c'.
 *	mdn_buffer_overflow	-- 'vlen' is too small.
 */
extern mdn_result_t
mdn__unicode_toupper(unsigned long c, mdn__unicode_context_t ctx,
		     unsigned long *v, size_t vlen, int *convlenp);
extern mdn_result_t
mdn__unicode_tolower(unsigned long c, mdn__unicode_context_t ctx,
		     unsigned long *v, size_t vlen, int *convlenp);

/*
 * Determine the context needed by the case conversion functions.
 *
 * Case conversion functions above needs context information for some
 * characters.  To get the context, you should call this function with
 * the next character as the parameter.  If you get final or nonfinal,
 * you're done.  If you get unknown, move on to the next character until
 * you get final or nonfinal.
 *
 * Returns:
 *	mdn__unicode_context_final	-- context is 'FINAL'.
 *	mdn__unicode_context_nonfinal	-- context is 'NON_FINAL'.
 *	mdn__unicode_context_unknown	-- context cannot be determined,
 *					   try the next character.
 */
extern mdn__unicode_context_t
mdn__unicode_getcontext(unsigned long c);

/*
 * Perform case-folding for caseless matching, defined by Unicode
 * Technical Report #21 "Case Mappings".
 *
 * Performs case-folding on the given unicode character 'c' and put
 * the result into 'v', whose size is specified by 'vlen'.  The actual
 * number of characters stored in 'v' are returned as '*foldlenp'.  In
 * case 'c' has no mapping, 'v[0]' will contain 'c', and '*foldlenp'
 * will be 1.
 *
 * Returns:
 *	mdn_success		-- successfully converted.
 *	mdn_buffer_overflow	-- 'vlen' is too small.
 */
extern mdn_result_t
mdn__unicode_casefold(unsigned long c, unsigned long *v, size_t vlen,
		      int *foldlenp);

#endif /* MDN_UNICODE_H */
