/* $Id: msgtrans.h,v 1.11 2000/11/21 02:09:04 ishisone Exp $ */
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

#ifndef MDN_MSGTRANS_H
#define MDN_MSGTRANS_H 1

/*
 * DNS message translator.
 *
 * Parse a DNS message, translate each domain name in it according
 * to a rule, and rebuild a message with the translated domain names.
 */

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/zldrule.h>

/*
 * Translation parameters.
 *
 * 'use_local_rule' determines how local codeset and ZLD should be
 * derived.
 *
 * If 'use_local_rule' is true, 'local_rule' will be used for
 * determining ZLD/codeset.  'mdn_msgtrans_translate' will use
 * the rule to determine the ZLD and codeset, and set 'local_zld'
 * and 'local_converter' properly upon return.
 *
 * Otherwise, 'mdn_msgtrans_translate' will assume that specified
 * domain name is either
 *   + the one having ZLD specified by 'local_zld' and codeset
 *     specified by 'local_converter', or
 *   + the one without ZLD and made of only legitimate characters
 *     (alphabets, digits and hyphens), that is, a non-internationalized
 *     domain name.
 *
 * If 'local_alt_converter' is not NULL, 'mdn_msgtrans_translate' tries
 * converting the specified domain name using it before attempting
 * 'local_conerter'.
 *
 * 'target_conveter' and 'target_zld' together define the ZLD/codeset
 * of the target.  If 'target_alt_converter' is not NULL, then it is
 * used instead of 'target_converter' if the conversion from UTF-8 to
 * the target encoding fails with error 'mdn_nomapping'.
 *
 * 'normalizer' defines the normalization schemes.
 */
typedef struct mdn_msgtrans_param {
	int use_local_rule;
	mdn_zldrule_t local_rule;
	mdn_converter_t local_converter;
	mdn_converter_t local_alt_converter;
	char *local_zld;
	mdn_converter_t target_converter;
	mdn_converter_t target_alt_converter;
	char *target_zld;
	mdn_normalizer_t normalizer;
} mdn_msgtrans_param_t;

/*
 * Translate DNS message according to the parameters given.
 *
 * Returns:
 *	mdn_success		-- ok, translated successfully.
 *	mdn_invalid_message	-- the specified message is not valid.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_msgtrans_translate(mdn_msgtrans_param_t *param,
		       const char *msg, size_t msglen,
		       char *outbuf, size_t outbufsize, size_t *outmsglenp);

#endif /* MDN_MSGTRANS_H */
