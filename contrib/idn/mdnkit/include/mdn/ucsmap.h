/* $Id: ucsmap.h,v 1.1.2.1 2002/02/08 12:13:24 marka Exp $ */
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

#ifndef MDN_UCSMAP_H
#define MDN_UCSMAP_H 1

/*
 * Perform UCS character mapping.
 * This module support one-to-N mapping (N may be zero, one or more).
 */

#include <mdn/result.h>

/*
 * Mapper type (opaque).
 */
typedef struct mdn_ucsmap *mdn_ucsmap_t;

/*
 * Create an empty mapping.  The reference count is set to 1.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_ucsmap_create(mdn_ucsmap_t *ctxp);

/*
 * Decrement the reference count of the given set, and if it reaches zero,
 * release all the memory allocated for it.
 */
extern void
mdn_ucsmap_destroy(mdn_ucsmap_t ctx);

/*
 * Increment the reference count of the given set by one, so that
 * the map can be shared.
 */
extern void
mdn_ucsmap_incrref(mdn_ucsmap_t ctx);

/*
 * Add a mapping.
 * 'ucs' is the character to be mapped, 'map' points an array of mapped
 * characters of length 'maplen'.  'map' may be NULL if 'maplen' is zero,
 * meaning one-to-none mapping.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_failure		-- already fixed by 'mdn_ucsmap_fix',
 *				   or too large maplen.
 */
extern mdn_result_t
mdn_ucsmap_add(mdn_ucsmap_t ctx, unsigned long ucs, unsigned long *map,
	       size_t maplen);

/*
 * Perform internal arrangement of the map for lookup.
 * Once it is fixed, 'mdn_ucsmap_add' cannot be permitted to the map.
 */
extern void
mdn_ucsmap_fix(mdn_ucsmap_t ctx);

/*
 * Find the mapping for the given character.
 * 'mdn_ucsmap_fix' must be performed before calling this function.
 * Find the mapping for 'v' and store the result to 'to'.  The length
 * of the mapped sequence is stored in '*maplenp'.  'tolen' specifies
 * the length allocated for 'to'.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomapping		-- specified character has no mapping.
 *	mdn_failure		-- not fixed by 'mdn_ucsmap_fix' yet.
 */
mdn_result_t
mdn_ucsmap_map(mdn_ucsmap_t ctx, unsigned long v, unsigned long *to,
	       size_t tolen, size_t *maplenp);

#endif /* MDN_UCSMAP_H */
