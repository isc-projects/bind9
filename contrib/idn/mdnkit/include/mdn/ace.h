/* $Id: ace.h,v 1.1.2.1 2002/02/08 12:12:41 marka Exp $ */
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

#ifndef MDN_ACE_H
#define MDN_ACE_H 1

/*
 * ACE converter utility module.
 */

#include <mdn/result.h>

/*
 * ACE identifier type -- prefix or suffix.
 */
enum {
	mdn__ace_prefix,
	mdn__ace_suffix
};

/*
 * ACE encoding/decode procedure.
 *
 * This prototype applies to both encode and decode procedure.  Both
 * of which converts a domain label (i.e. contains no dots) pointed by
 * 'from', whose length is 'fromlen', and stores the result to 'to',
 * whose size is 'tolen'.
 * the ACE string must not have ACE prefix/suffix, as it is automatically
 * handled by 'mdn__ace_convert'.
 */
typedef mdn_result_t (*mdn__ace_proc_t)(const char *from, size_t fromlen,
					char *to, size_t tolen);

/*
 * ACE converter property.
 *
 * 'id_type' shows the type of ACE identifier, which is either
 * 'mdn__ace_prefix' or 'mdn__ace_suffix'.  'id_str' is the ACE
 * identifier itself.  'encoder' and 'decode' are pointers to the
 * encode and decode procedures.
 * Encode procedure converts a domain name label in UTF-8 to
 * ACE-encoded one, and decode procedure converts ACE-encoded label to
 * UTF-8 encoded one.
 */
typedef struct {
	int id_type;			/* mdn__ace_prefix/mdn__ace_suffix */
	const char *id_str;		/* prefix/suffix string */
	mdn__ace_proc_t encoder;	/* encode procedure */
	mdn__ace_proc_t decoder;	/* decode procedure */
} mdn__ace_t;

/*
 * Utility for ACE converter.
 *
 * Convert a domain name given by 'from' and stores the result to
 * 'to', whose length is 'tolen'.  If 'dir' is 'mdn_convert_u2l',
 * 'from' points UTF-8 string which is converted to ACE encoding.  If
 * 'dir' is 'mdn_convert_l2u', 'from' points ACE string which is
 * converted to UTF-8.
 * This function first breaks down the given name into labels,
 * and encode/decode each label.  When encoding, conversion of
 * STD13 conforming labels (i.e. valid ASCII labels) is skipped.
 * When decoding, if the decoding failed but the label is a legitimate
 * ASCII label, those labels are copied verbatim.  To reject illegally
 * encoded labels, the decoding process performs two kinds of checks:
 *  1. check that the decoded string does NOT comform to STD13.
 *  2. try encoding the decoded string, and see if the result matches
 *     to the original string.
 */
extern mdn_result_t
mdn__ace_convert(mdn__ace_t *ctx, mdn_converter_dir_t dir,
		 const char *from, char *to, size_t tolen);

#endif /* MDN_ACE_H */
