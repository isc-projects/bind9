/* $Id: mapselector.h,v 1.1.2.1 2002/02/08 12:13:11 marka Exp $ */
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

#ifndef MDN_MAPSELECTOR_H
#define MDN_MAPSELECTOR_H 1

/*
 * Map selector.
 *
 * Perfom mapping the specified domain name according with the TLD
 * of the donmain name.
 */

#include <mdn/result.h>
#include <mdn/mapper.h>

/*
 * Special TLDs for map selection.
 */
#define MDN_MAPSELECTOR_NO_TLD		"-"
#define MDN_MAPSELECTOR_DEFAULT		"."

/*
 * Mapselector object type.
 */
typedef struct mdn_mapselector *mdn_mapselector_t;

/*
 * Initialize module.  Must be called before any other calls of
 * the functions of this module.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapselector_initialize(void);

/*
 * Create a mapselector context.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapselector_create(mdn_mapselector_t *ctxp);

/*
 * Decrement reference count of the mapselector `ctx' created by
 * 'mdn_mapselector_create', if it is still refered by another object.
 * Otherwise, release all the memory allocated to the mapselector.
 */
extern void
mdn_mapselector_destroy(mdn_mapselector_t ctx);

/*
 * Increment reference count of the mapselector `ctx' created by
 * 'mdn_mapselector_create'.
 */
extern void
mdn_mapselector_incrref(mdn_mapselector_t ctx);

/*
 * Return the mapper for `tld' registered in `ctx', or return NULL if
 * mapper for `tld' is not registered.
 */
extern mdn_mapper_t
mdn_mapselector_mapper(mdn_mapselector_t ctx, const char *tld);

/*
 * Add mapping scheme `name' to the mapper for `tld' to the mapselector
 * context `ctx'.  If no mapper for `TLD' has not been registered, the
 * function creates a new mapper for `tld', and then adds the given mapping
 * scheme to the mapper.  Otherwise,  it adds the scheme to the mapper for
 * TLD registered in `ctx'.
 * 
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_invalid_name        -- the given tld or name is not valid.
 *      mdn_nomemory            -- malloc failed.
 */
extern mdn_result_t
mdn_mapselector_add(mdn_mapselector_t ctx, const char *tld, const char *name);

extern mdn_result_t
mdn_mapselector_addall(mdn_mapselector_t ctx, const char *tld,
		       const char **names, int nnames);

/*
 * Map an UTF-8 domain name with the mapper for TLD of the domain name.
 * If there is no mapper suitable for the domain name, the function
 * simply copies the doman name.
 *
 * Returns:
 *      mdn_success             -- ok.
 *      mdn_nomemory            -- malloc failed.
 *      mdn_buffer_overflow     -- output buffer is too small.
 *      mdn_invalid_encoding    -- the input string has invalid/illegal
 *                                 UTF-8 sequence.
 */
extern mdn_result_t
mdn_mapselector_map(mdn_mapselector_t ctx,
                    const char *from, char *to, size_t tolen);

#endif /* MDN_MAPSELECTOR_H */
