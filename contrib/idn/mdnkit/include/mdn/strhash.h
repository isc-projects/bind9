/* $Id: strhash.h,v 1.1 2002/01/02 02:46:35 marka Exp $ */
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

#ifndef MDN_STRHASH_H
#define MDN_STRHASH_H 1

/*
 * String-keyed hash table
 *
 * Just a hash table.  Nothing special.  Number of hash buckets
 * grows automatically.
 */

#include <mdn/result.h>

/*
 * Hash table type, which is opaque.
 */
typedef struct mdn_strhash *mdn_strhash_t;

/*
 * Hash value free proc.
 */
typedef void (*mdn_strhash_freeproc_t)(void *value);

/*
 * Create a hash table.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_strhash_create(mdn_strhash_t *hashp);

/*
 * Delete a hash table created by 'mdn_strhash_create'.
 * If 'proc' is not NULL, it is called for each value in the
 * hash to release memory for them.
 */
extern void
mdn_strhash_destroy(mdn_strhash_t hash, mdn_strhash_freeproc_t proc);

/*
 * Register an item to the hash table.  This function makes a
 * private copy of the key string.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_strhash_put(mdn_strhash_t hash, const char *key, void *value);

/*
 * Find an item with the specified key.
 *
 * Returns:
 *	mdn_success		-- ok. found.
 *	mdn_noentry		-- not found.
 */
extern mdn_result_t
mdn_strhash_get(mdn_strhash_t hash, const char *key, void **valuep);

/*
 * Check if an item with the specified key exists.
 *
 * Returns:
 *	1			-- yes.
 *	0			-- no.
 */
extern int
mdn_strhash_exists(mdn_strhash_t hash, const char *key);

#endif /* MDN_STRHASH_H */
