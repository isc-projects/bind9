/* $Id: delimitermap.h,v 1.1.2.1 2002/02/08 12:12:58 marka Exp $ */
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

#ifndef MDN_DELIMITERMAP_H
#define MDN_DELIMITERMAP_H 1

/*
 * Mapper.
 *
 * Perfom mapping local delimiters to `.'.
 */

#include <mdn/result.h>

/*
 * Map object type.
 */
typedef struct mdn_delimitermap *mdn_delimitermap_t;

/*
 * Create a delimitermap context.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_delimitermap_create(mdn_delimitermap_t *ctxp);

/*
 * Decrement reference count of the delimitermap `ctx' created by
 * 'mdn_delimitermap_create', if it is still refered by another object.
 * Otherwise, release all the memory allocated to the delimitermap.
 */
extern void
mdn_delimitermap_destroy(mdn_delimitermap_t ctx);

/*
 * Increment reference count of the delimitermap `ctx' created by
 * 'mdn_delimitermap_create'.
 */
extern void
mdn_delimitermap_incrref(mdn_delimitermap_t ctx);

/*
 * Add a local delimiter.
 * The context must be in the building phase -- that is, before
 * 'mdn_delimitermap_fix' is called for the context.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 *      mdn_invalid_codepoint   -- delimiter is not valid UCS-4 character.
 *	mdn_failure		-- already fixed by 'mdn_delimitermap_fix'.
 */
extern mdn_result_t
mdn_delimitermap_add(mdn_delimitermap_t ctx, unsigned long delimiter);

extern mdn_result_t
mdn_delimitermap_addall(mdn_delimitermap_t ctx, unsigned long *delimiters,
			int ndelimiters);

/*
 * Perform internal arrangement of mapping.
 * Once the context is fixed by this function, it becomes immutable,
 * and it shifts into 'lookup' phase.
 */
extern void
mdn_delimitermap_fix(mdn_delimitermap_t ctx);

/*
 * Map local delimiters in an UTF-8 domain name to `.'.
 * The context must be in the lookup phase -- in other words,
 * 'mdn_delimitermap_fix' must be called for the context before calling
 * this function.
 *
 * Note that if no delimiter is added to the context, the function copies
 * the string and doesn't check that the input string has valid UTF-8
 * sequence.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_buffer_overflow     -- output buffer is too small.
 *      mdn_invalid_encoding    -- the input string has invalid/illegal
 *                                 UTF-8 sequence.
 *	mdn_failure		-- not fixed by 'mdn_delimitermap_fix' yet.
 */
extern mdn_result_t
mdn_delimitermap_map(mdn_delimitermap_t ctx, const char *from, char *to,
		     size_t tolen);

#endif /* MDN_DELIMITERMAP_H */
