/* $Id: nameprep.h,v 1.1.2.1 2002/02/08 12:13:15 marka Exp $ */
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

#ifndef MDN_NAMEPREP_H
#define MDN_NAMEPREP_H 1

/*
 * Perform NAMEPREP (mapping, prohibited/unassigned checking).
 */

#include <mdn/result.h>

/*
 * A Handle for nameprep operations.
 */
typedef struct mdn_nameprep *mdn_nameprep_t;


/*
 * Create a handle for nameprep operations.
 * The handle is stored in '*handlep', which is used other functions
 * in this module.
 * The version of the NAMEPREP specification can be specified with
 * 'version' parameter.  If 'version' is NULL, the latest version
 * is used.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_notfound		-- specified version not found.
 */
extern mdn_result_t
mdn_nameprep_create(const char *version, mdn_nameprep_t *handlep);

/*
 * Close a handle, which was created by 'mdn_nameprep_create'.
 */
extern void
mdn_nameprep_destroy(mdn_nameprep_t handle);

/*
 * Perform character mapping on UTF-8 string specified by 'from', and
 * store the result into 'to', whose length is specified by 'tolen'.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_encoding	-- input is not a valid UTF-8 string.
 *	mdn_buffer_overflow	-- result buffer is too small.
 */
extern mdn_result_t
mdn_nameprep_map(mdn_nameprep_t handle, const char *from,
		 char *to, size_t tolen);

/*
 * Check if a UTF-8 string 's' contains any prohibited characters specified
 * by the draft.  If found, the pointer to the first such character is stored
 * into '*found'.  Otherwise '*found' will be NULL.
 *
 * Returns:
 *	mdn_success		-- no prohibited character found.
 *	mdn_invalid_encoding	-- input is not a valid UTF-8 string.
 */
extern mdn_result_t
mdn_nameprep_isprohibited(mdn_nameprep_t handle, const char *s,
			  const char **found);

/*
 * Check if a UTF-8 string 's' contains any unassigned characters specified
 * by the draft.  If found, the pointer to the first such character is stored
 * into '*found'.  Otherwise '*found' will be NULL.
 *
 * Returns:
 *	mdn_success		-- no unassigned character found.
 *	mdn_invalid_encoding	-- input is not a valid UTF-8 string.
 */
extern mdn_result_t
mdn_nameprep_isunassigned(mdn_nameprep_t handle, const char *s,
			  const char **found);

/*
 * The following functions are for internal use.
 * They are used for this module to be add to the checker and mapper modules.
 */
extern mdn_result_t
mdn__nameprep_createproc(const char *parameter, void **handlep);

extern void
mdn__nameprep_destroyproc(void *handle);

extern mdn_result_t
mdn__nameprep_mapproc(void *handle, const char *from, char *to, size_t tolen);

extern mdn_result_t
mdn__nameprep_prohibitproc(void *handle, const char *str, const char **found);

extern mdn_result_t
mdn__nameprep_unassignedproc(void *handle, const char *str,
			     const char **found);

#endif /* MDN_NAMEPREP_H */
