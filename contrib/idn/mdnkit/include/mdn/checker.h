/* $Id: checker.h,v 1.1.2.1 2002/02/08 12:12:54 marka Exp $ */
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

#ifndef MDN_CHECKER_H
#define MDN_CHECKER_H 1

/*
 * Character Checker.
 *
 * Perfom checking characters in the specified domain name.
 */

#include <mdn/result.h>
#include <mdn/filechecker.h>
#include <mdn/nameprep.h>

/*
 * Schems name prefixes for the standard nameprep prohibit/unassigned
 * checks.
 *
 * If you'd like to add the unassigned check scheme of "nameprep-XX"
 * to a checker context, MDN_CHECKER_UNASSIGNED_PREFIX + "nameprep-XX"
 * (i.e. "unassigned#nameprep-XX") is the scheme name passed to
 * mdn_checker_add().
 */
#define MDN_CHECKER_PROHIBIT_PREFIX	"prohibit#"
#define MDN_CHECKER_UNASSIGNED_PREFIX	"unassigned#"

/*
 * Checker object type.
 */
typedef struct mdn_checker *mdn_checker_t;

/*
 * Initialize module.  Must be called before any other calls of
 * the functions of this module.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_checker_initialize(void);

/*
 * Create a checker context.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_checker_create(mdn_checker_t *ctxp);

/*
 * Decrement reference count of the checker `ctx' created by
 * 'mdn_checker_create', if it is still refered by another object.
 * Otherwise, release all the memory allocated to the checker.
 */
extern void
mdn_checker_destroy(mdn_checker_t ctx);

/*
 * Increment reference count of the checker `ctx' created by
 * 'mdn_checker_create'.
 */
extern void
mdn_checker_incrref(mdn_checker_t ctx);

/*
 * Add checking scheme `name' to the checker to `ctx'.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_invalid_name        -- the given name is not valid.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_checker_add(mdn_checker_t ctx, const char *name);

extern mdn_result_t
mdn_checker_addall(mdn_checker_t ctx, const char **names, int nnames);

/*
 * Check an UTF-8 name.  All checking schemes regsitered in `ctx'
 * are applied in the regisration order.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 *      mdn_buffer_overflow     -- output buffer is too small.
 *      mdn_invalid_encoding    -- the input string has invalid/illegal
 *                                 UTF-8 sequence.
 */
extern mdn_result_t
mdn_checker_lookup(mdn_checker_t ctx, const char *utf8, const char **found);

/*
 * Checking procedure type.
 */
typedef mdn_result_t (*mdn_checker_createproc_t)(const char *parameter,
						 void **ctxp);
typedef void         (*mdn_checker_destroyproc_t)(void *ctx);
typedef mdn_result_t (*mdn_checker_lookupproc_t)(void *ctx, const char *utf8,
                                                 const char **found);
                                              
/*
 * Register a new checking scheme.
 *
 * You can override the default normalization schemes, if you want.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_checker_register(const char *prefix,
		     mdn_checker_createproc_t create,
		     mdn_checker_destroyproc_t destroy,
		     mdn_checker_lookupproc_t lookup);

#endif /* MDN_CHECKER_H */
