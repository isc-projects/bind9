/* $Id: zldrule.h,v 1.8 2000/08/02 02:06:41 ishisone Exp $ */
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

#ifndef MDN_ZLDRULE_H
#define MDN_ZLDRULE_H 1

/*
 * ZLD matcher.
 *
 * This module provides a function that takes a domain name as input,
 * and matches against set of ZLDs.
 *
 * Each ZLD has its corresponding codeset (character encoding), or codesets
 * in which a domain name with the ZLD is encoded.
 *
 * The function returns the matched ZLD and the corresponding codeset.
 *
 * If a name matches more than one ZLDs, the longer one takes precedence.
 *
 * If matched ZLD has more than one codesets, each codeset is applied to
 * the given domain name in order, and the first one for which the name
 * is valid is chosen.
 */

#include <mdn/result.h>
#include <mdn/converter.h>

/*
 * ZLD matching rule set type (opaque)
 */
typedef struct mdn_zldrule *mdn_zldrule_t;

/*
 * Create an empty rule set.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_zldrule_create(mdn_zldrule_t *ctxp);

/*
 * Destroy the rule set created by mdn_zldrule_create.
 */
extern void
mdn_zldrule_destroy(mdn_zldrule_t ctx);

/*
 * Add a ZLD and corresponding encoding(s) to the rule set.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_zldrule_add(mdn_zldrule_t ctx, const char *zld,
		const char **encodings, int nencodings);

/*
 * Select matching ZLD and encoding for the specified domain name.
 *
 * Returns:
 *	mdn_success		-- found.
 *	mdn_notfound		-- not found.
 *	mdn_invalid_encoding	-- ZLD matched, but encoding is wrong.
 */
extern mdn_result_t
mdn_zldrule_select(mdn_zldrule_t ctx, const char *domain,
		   char **zldp, mdn_converter_t *convctxp);

#endif /* MDN_ZLDRULE_H */
