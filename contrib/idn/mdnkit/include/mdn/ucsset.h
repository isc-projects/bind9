/* $Id: ucsset.h,v 1.1.2.1 2002/02/08 12:13:26 marka Exp $ */
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

#ifndef MDN_UCSSET_H
#define MDN_UCSSET_H 1

/*
 * A 'set' of UCS codepoints.
 */

#include <mdn/result.h>

/*
 * Type representing a set (opaque).
 */
typedef struct mdn_ucsset *mdn_ucsset_t;


/*
 * Create an empty set.  The reference count is set to 1.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_ucsset_create(mdn_ucsset_t *ctxp);

/*
 * Decrement the reference count of the given set, and if it reaches zero,
 * release all the memory allocated for it.
 */
extern void
mdn_ucsset_destroy(mdn_ucsset_t ctx);

/*
 * Increments the reference count by one.
 */
extern void
mdn_ucsset_incrref(mdn_ucsset_t ctx);

/*
 * Add a UCS code point to the set.
 * The set must be in the building phase -- that is, before 'mdn_ucsset_fix'
 * is called for the set.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_code	-- code point out of range.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_failure		-- already fixed by 'mdn_ucsset_fix'.
 */
extern mdn_result_t
mdn_ucsset_add(mdn_ucsset_t ctx, unsigned long v);

/*
 * Add a range of code points (from 'from' to 'to', inclusive) to the set.
 * 'from' must not be greater than 'to'.
 * This function is similar to 'mdn_ucsset_add' except that it accepts
 * range of code points.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_code	-- code point out of range, or the range
 *				   specification is invalid.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_failure		-- already fixed by 'mdn_ucsset_fix'.
 */
extern mdn_result_t
mdn_ucsset_addrange(mdn_ucsset_t ctx, unsigned long from, unsigned long to);

/*
 * Perform internal arrangement of the set for lookup.
 * Before calling this function, a set is in 'building' phase, and code
 * points can be added freely by 'mdn_ucsset_add' or 'mdn_ucsset_addrange'.
 * But once it is fixed by this function, the set becomes immutable, and
 * it shifts into 'lookup' phase.
 */
extern void
mdn_ucsset_fix(mdn_ucsset_t ctx);

/*
 * Find if the given code point is in the set.
 * The set must be in the lookup phase -- in other words, 'mdn_ucsset_fix'
 * must be called for the set before calling this function.
 * '*found' is set to 1 if the specified code point is in the set, 0 otherwise.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_code	-- specified code point is out of range.
 *	mdn_failure		-- not fixed by 'mdn_ucsset_fix' yet.
 */
mdn_result_t
mdn_ucsset_lookup(mdn_ucsset_t ctx, unsigned long v, int *found);

#endif /* MDN_UCSSET_H */
