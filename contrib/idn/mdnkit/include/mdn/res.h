/* $Id: res.h,v 1.1 2002/01/02 02:46:34 marka Exp $ */
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

#ifndef MDN_RES_H
#define MDN_RES_H 1

/*
 * Resolver library support.
 *
 * All the functions provided by this module requires MDN resolver
 * configuration context of type 'mdn_resconf_t' as an argument.
 * This context holds information described in the configuration file
 * (mdnres.conf).  See mdn_resconf module for details.
 *
 * All functions also accept NULL as the context, but since
 * no conversion/normalization will be done in this case, it is
 * pretty useless.
 */

#include <mdn/result.h>
#include <mdn/resconf.h>

/*
 * Convert and check the string.
 *
 * This function converts the string `from' to `to', checks `from' or
 * combination of them, using `insn'.
 *
 * `insn' is a sequence of characters as follows:
 *
 *	l	convert the local codeset string to UTF-8.
 *	L	convert the UTF-8 string to the local codeset.
 *	d	perform local delimiter mapping.
 *	M	perfrom TLD based local mapping.
 *	m	perform the nameprep mapping.
 *	n	perform nameprep normalization.
 *	p	check whether the string contains nameprep prohibited
 *		character.
 *	N	equivalent to "mnp".
 *	u	check whether the string contains nameprep unassigned
 *		codepoint.
 *	I	convert the UTF-8 string to ACE.
 *	i	convert the ACE string to UTF-8.
 *	!m	inspect if nameprep mapping has been performed to the
 *		string.  If hasn't, convert the string to ACE.
 *	!n	inspect if nameprep normalizaion has been performed
 *		to the string.  If hasn't, convert the string to ACE.
 *	!p	search the string for nameprep prohibited character.
 *		If found, convert the string to ACE.
 *	!N	equivalent to "!m!n!p".
 *	!u	search the string for nameprep unassigned codepoint.
 *		If found, convert the string to ACE.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input string has invalid byte sequence.
 *	mdn_invalid_name	-- local encoding (codeset) name is invalid.
 *	mdn_invalid_action	-- `insn' contains invalid action.
 *	mdn_invalid_nomemory	-- out of memory.
 *	mdn_invalid_nomapping	-- no mapping to output codeset.
 *	mdn_prohibited		-- input string has a prohibited character.
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_res_nameconv(mdn_resconf_t ctx, const char *insn, const char *from,
		 char *to, size_t tolen);

/*
 * Convert the local codeset string to UTF-8.
 */
extern mdn_result_t
mdn_res_localtoucs(mdn_resconf_t ctx, const char *from, char *to,
		   size_t tolen);

#define mdn_res_localtoucs(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "l", from, to, tolen)

/*
 * Convert the UTF-8 string to the local codeset.
 */
extern mdn_result_t
mdn_res_ucstolocal(mdn_resconf_t ctx, const char *from, char *to,
		   size_t tolen);

#define mdn_res_ucstolocal(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "L", from, to, tolen)

/*
 * Perform the nameprep mapping.
 */
extern mdn_result_t
mdn_res_map(mdn_resconf_t ctx, const char *from, char *to, size_t tolen);

#define mdn_res_map(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "m", from, to, tolen)

/*
 * Perform nameprep normalization.
 */
extern mdn_result_t
mdn_res_normalize(mdn_resconf_t ctx, const char *from, char *to, size_t tolen);

#define mdn_res_normalize(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "n", from, to, tolen)

/*
 * Check whether the string contains nameprep prohibited character.
 */
extern mdn_result_t
mdn_res_prohibitcheck(mdn_resconf_t ctx, const char *from, char *to,
		      size_t tolen);

#define mdn_res_prohibitcheck(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "p", from, to, tolen)

/*
 * NAMEPREP.
 */
extern mdn_result_t
mdn_res_nameprep(mdn_resconf_t ctx, const char *from, char *to,
		 size_t tolen);

#define mdn_res_nameprep(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "N", from, to, tolen)

/*
 * NAMEPREP check.
 */
extern mdn_result_t
mdn_res_nameprepcheck(mdn_resconf_t ctx, const char *from, char *to,
		      size_t tolen);

#define mdn_res_nameprepcheck(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "!N", from, to, tolen)

/*
 * Check whether the string contains nameprep unassigned character.
 */
extern mdn_result_t
mdn_res_unassignedcheck(mdn_resconf_t ctx, const char *from, char *to,
			size_t tolen);

#define mdn_res_unassignedcheck(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "u", from, to, tolen)

/*
 * Perform local delimiter mapping.
 */
extern mdn_result_t
mdn_res_delimitermap(mdn_resconf_t ctx, const char *from, char *to,
		     size_t tolen);

#define mdn_res_delimitermap(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "d", from, to, tolen)

/*
 * Perfrom TLD based local mapping.
 */
extern mdn_result_t
mdn_res_localmap(mdn_resconf_t ctx, const char *from, char *to, size_t tolen);

#define mdn_res_localmap(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "M", from, to, tolen)

/*
 * Convert the UTF-8 string to ACE.
 */
extern mdn_result_t
mdn_res_ucstodns(mdn_resconf_t ctx, const char *from, char *to, size_t tolen);

#define mdn_res_ucstodns(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "I", from, to, tolen)

/*
 * Convert the ACE string to UTF-8.
 */
extern mdn_result_t
mdn_res_dnstoucs(mdn_resconf_t ctx, const char *from, char *to, size_t tolen);

#define mdn_res_dnstoucs(ctx, from, to, tolen) \
	mdn_res_nameconv(ctx, "i", from, to, tolen)

#endif /* MDN_RES_H */
