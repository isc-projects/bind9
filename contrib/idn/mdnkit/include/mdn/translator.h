/* $Id: translator.h,v 1.10 2000/11/21 02:09:04 ishisone Exp $ */
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

#ifndef MDN_TRANSLATOR_H
#define MDN_TRANSLATOR_H 1

/*
 * Domain name ZLD/codeset translator.
 */

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>

/*
 * Translate domain name encoded in the local codeset to the target
 * codeset.
 *
 * Requires:
 *	Both 'local_zld' and 'target_zld' must be canonicalized (or NULL)
 *	using mdn_translator_canonicalzld.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_buffer_overflow	-- output buffer too small.
 *	mdn_invalid_encoding	-- there are some invalid characters in
 *				   the specified domain name.
 */
extern mdn_result_t
mdn_translator_translate(mdn_converter_t local_converter,
			 mdn_converter_t local_alternate_converter,
			 const char *local_zld,
			 mdn_normalizer_t normalizer,
			 mdn_converter_t target_converter,
			 mdn_converter_t target_alternate_converter,
			 const char *target_zld,
			 const char *from, char *to, size_t tolen);

/*
 * Canonicalize ZLD.
 *
 * Note:
 *	The string returned in *canonicalizedp is malloc'ed by this
 *	function.  You should free it when no longer needed.
 *
 *	If specified ZLD is "" or ".", NULL will be returned in
 *	*canonicalizedp.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_translator_canonicalzld(const char *zld, char **canonicalizedp);

/*
 * Try matching ZLD against domain name.
 *
 * Requires:
 *	'zld' must be canonicalized (or NULL) using
 *	mdn_translator_canonicalzld.
 *
 * Returns:
 *	1		-- match.
 *	0		-- no match.
 */
extern int
mdn_translator_matchzld(const char *domain, const char *zld);

#endif /* MDN_TRANSLATOR_H */
