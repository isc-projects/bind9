/* $Id: api.h,v 1.1.2.1 2002/02/08 12:12:51 marka Exp $ */
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

#ifndef MDN_API_H
#define MDN_API_H 1

#include <mdn/result.h>

/*
 * Application Programming Interface for Multilingual Domain Name Handling.
 * This module provides high-level APIs for ordinary applications.
 * Low-level APIs are also available.  See "res.h" for details.
 */

/*
 * Actions
 */
#define MDN_LOCALCONV	0x0001 /* Local encoding <-> UTF-8 conversion */
#define MDN_IDNCONV	0x0002 /* UTF-8 <-> IDN encoding (ACE) conversion */
#define MDN_NAMEPREP	0x0004 /* NAMEPREP */
#define MDN_UNASCHECK	0x0008 /* Unassigned code point check */
#define MDN_DELIMMAP	0x0100 /* Delimiter mapping */
#define MDN_LOCALMAP	0x0200 /* Local mapping */

/*
 * Actions needed for ordinary applications.
 */
#define MDN_ENCODE_APP	\
	(MDN_LOCALCONV|MDN_DELIMMAP|MDN_LOCALMAP|MDN_NAMEPREP|MDN_IDNCONV)
#define MDN_DECODE_APP	(MDN_IDNCONV|MDN_NAMEPREP|MDN_LOCALCONV)

/*
 * Initialize the whole library, and load configuration from the default
 * configuration file (mdn.conf).
 *
 * Initialization of the library will be done only once when this function
 * is called first, while loading of the configuration file will be done
 * every time it is called.
 *
 * If 'mdn_encodename' or 'mdn_decodename' is called without calling this
 * function, implicit initialization will be done prior to encoding/decoding
 * process.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nofile		-- cannot open the configuration file.
 *	mdn_invalid_syntax	-- syntax error found in the file.
 *	mdn_invalid_name	-- there are invalid names (encoding,
 *				   normalization etc.).
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_nameinit(void);

/*
 * Encode multilingual domain name for name resolution.
 *
 * The encoding process consists of the following 5 steps.
 *
 *    1. local encoding (such as Shift-JIS or Big5) to UTF-8 conversion.
 *    2. delimiter mapping, which maps certain characters to period
 *       (U+002E, FULL STOP) character.
 *    3. non-standard local mapping, whose exact rule is determined by
 *       the TLD of the domain name to be encoded.  This allows
 *	 locale-specific mapping for each ccTLD.
 *    4. NAMEPREP, as described in the Internet Draft
 *       (draft-ietf-idn-nameprep-XX).  This step has an option of
 *       prohibiting use of unassigned code points in the domain name.
 *    5. UTF-8 to IDN encoding (ACE) conversion.
 *
 * Some steps can be skipped according to the application's needs.
 * For example, if the application holds the multilingual domain names in
 * UTF-8, step 1 above won't be necessary.
 *
 * 'actions' specifies what actions to take when encoding, and is
 * a bitwise-or of the following flags:
 *
 *   MDN_LOCALCONV	-- perform local encoding to UTF-8 conversion (step 1)
 *   MDN_DELIMMAP	-- perform delimiter mapping (step 2)
 *   MDN_LOCALMAP	-- perform local mapping (step 3)
 *   MDN_NAMEPREP       -- perform NAMEPREP (step 4)
 *   MDN_UNASCHECK	-- perform optional unassigned codepoint check
 *			   (also step 4)
 *   MDN_IDNCONV	-- perform UTF-8 to IDN encoding conversion (step 5)
 *
 * Note that if no flags are specified, 'mdn_encodename' does nothing
 * fancy, just copies the given name verbatim.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_action	-- invalid action flag specified.
 *	mdn_invalid_encoding	-- the given string has invalid/illegal
 *				   byte sequence.
 *	mdn_prohibited		-- prohibited/unassigned code point found.
 *	mdn_buffer_overflow	-- 'tolen' is too small.
 *	mdn_nomemory		-- malloc failed.
 *
 * Also, if this function is called without calling 'mdn_nameinit',
 * the following error codes might be returned.
 *	mdn_nofile		-- cannot open the configuration file.
 *	mdn_invalid_syntax	-- syntax error found in the file.
 *	mdn_invalid_name	-- there are invalid names (encoding,
 *				   normalization etc.).
 */
extern mdn_result_t
mdn_encodename(int actions, const char *from, char *to, size_t tolen);

/*
 * Decode multilingual domain name returned from resolver.
 *
 * The decoding process consists of the following 2 steps.  It is much
 * simpler than the encoding process because no name preparation is
 * necessary.
 *
 *    1. server encoding (ACE) to UTF-8 conversion.
 *    2. UTF-8 to local encoding conversion.
 *
 * 'actions' specifies what actions to take when decoding, and is
 * a bitwise-or of the following flags:
 *
 *   MDN_IDNCONV	-- perform IDN encoding to UTF-8 conversion (step 1)
 *   MDN_NAMEPREP	-- perform NAMEPREP for verification (step 2)
 *   MDN_UNASCHECK	-- perform optional unassigned codepoint check for
 *			   verification (also step 2)
 *   MDN_LOCALCONV	-- perform UTF-8 to local encoding conversion (step 3)
 *
 * Note that if no flags are specified, 'mdn_decodename' does nothing
 * but copying the given name verbatim.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_action	-- invalid action flag specified.
 *	mdn_invalid_encoding	-- the given string has invalid/illegal
 *				   byte sequence.
 *	mdn_buffer_overflow	-- 'tolen' is too small.
 *	mdn_nomemory		-- malloc failed.
 *
 * Also, if this function is called without calling 'mdn_nameinit',
 * the following error codes might be returned.
 *	mdn_nofile		-- cannot open the configuration file.
 *	mdn_invalid_syntax	-- syntax error found in the file.
 *	mdn_invalid_name	-- there are invalid names (encoding,
 *				   normalization etc.).
 */
extern mdn_result_t
mdn_decodename(int actions, const char *from, char *to, size_t tolen);

/*
 * For convenience.
 */
#define mdn_localtoutf8(from, to, tolen) \
	mdn_encodename(MDN_LOCALCONV, from, to, len)
#define mdn_delimitermap(from, to, tolen) \
	mdn_encodename(MDN_DELIMMAP, from, to, len)
#define mdn_localmap(from, to, tolen) \
	mdn_encodename(MDN_LOCALMAP, from, to, len)
#define mdn_nameprep(from, to, tolen) \
	mdn_encodename(MDN_NAMEPREP, from, to, len)
#define mdn_utf8toidn(from, to, tolen) \
	mdn_encodename(MDN_IDNCONV, from, to, len)
#define mdn_idntoutf8(from, to, tolen) \
	mdn_decodename(MDN_IDNCONV, from, to, tolen)
#define mdn_utf8tolocal(from, to, tolen) \
	mdn_decodename(MDN_LOCALCONV, from, to, tolen)
#define mdn_nameprepcheck(from, to, tolen) \
	mdn_decodename(MDN_NAMEPREP, from, to, tolen)

#define mdn_localtoidn(from, to, tolen) \
	mdn_encodename(MDN_ENCODE_APP, from, to, tolen)
#define mdn_idntolocal(from, to, tolen) \
	mdn_decodename(MDN_DECODE_APP, from, to, tolen)

#endif /* MDN_API_H */
