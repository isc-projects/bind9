/* $Id: mapper.h,v 1.1.2.1 2002/02/08 12:13:10 marka Exp $ */
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

#ifndef MDN_MAPPER_H
#define MDN_MAPPER_H 1

/*
 * Mapper.
 *
 * Perfom mapping the specified domain name.
 */

#include <mdn/result.h>
#include <mdn/filemapper.h>
#include <mdn/nameprep.h>

/*
 * Map object type.
 */
typedef struct mdn_mapper *mdn_mapper_t;

/*
 * Initialize module.  Must be called before any other calls of
 * the functions of this module.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapper_initialize(void);

/*
 * Create a mapper context.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapper_create(mdn_mapper_t *ctxp);

/*
 * Decrement reference count of the mapper `ctx' created by
 * 'mdn_mapper_create', if it is still refered by another object.
 * Otherwise, release all the memory allocated to the mapper.
 */
extern void
mdn_mapper_destroy(mdn_mapper_t ctx);

/*
 * Increment reference count of the mapper `ctx' created by
 * 'mdn_mapper_create'.
 */
extern void
mdn_mapper_incrref(mdn_mapper_t ctx);

/*
 * Add mapping scheme `name' to the mapper to `ctx'.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_invalid_name        -- the given name is not valid.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapper_add(mdn_mapper_t ctx, const char *name);

extern mdn_result_t
mdn_mapper_addall(mdn_mapper_t ctx, const char **names, int nnames);

/*
 * Map an UTF-8 domain name.  All mapping schemes regsitered in `ctx'
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
mdn_mapper_map(mdn_mapper_t ctx, const char *from, char *to, size_t tolen);

/*
 * Mapping procedure type.
 */
typedef mdn_result_t (*mdn_mapper_createproc_t)(const char *parameter,
						void **ctxp);
typedef void         (*mdn_mapper_destroyproc_t)(void *ctxp);
typedef mdn_result_t (*mdn_mapper_mapproc_t)(void *ctx, const char *from,
                                             char *, size_t);
                                              
/*
 * Register a new mapping scheme.
 *
 * You can override the default normalization schemes, if you want.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapper_register(const char *prefix,
		    mdn_mapper_createproc_t create,
		    mdn_mapper_destroyproc_t destroy,
		    mdn_mapper_mapproc_t map);

#endif /* MDN_MAPPER_H */
