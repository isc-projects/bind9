/* $Id: util.h,v 1.1 2002/01/02 02:46:37 marka Exp $ */
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

#ifndef MDN_UTIL_H
#define MDN_UTIL_H 1

/*
 * Utility functions.
 */

/*
 * Case-insensitive string match.
 *
 * This function compares two strings in case-insensitive way, like
 * strcasencmp() function which can be found in many systems.
 * However, this function only disregards the case difference of ASCII
 * letters ([A-Za-z]), so it is locale independent.
 * The result is 1 if 's1' and 's2' match, 0 otherwise.
 */
extern int
mdn_util_casematch(const char *s1, const char *s2, size_t n);

/*
 * Get a range of valid domain name characters.
 *
 * This function sees each character in string 's' until 'end',
 * and checks if it is valid as a character in ASCII domain names.
 * It returns a pointer to the first invalid character, or 'end'
 * if all characters are valid.
 */
extern const char *
mdn_util_domainspan(const char *s, const char *end);

/*
 * Test whether a string is valid domain name defined by STD 13.
 *
 * This function sees each character in string 's' until 'end', and
 * checks if the string is valid as an ASCII domain name that STD 13
 * defines.  If valid, it returns 1.  Otherwise, it returns 0.
 */
extern int
mdn_util_validstd13(const char *s, const char *end);

/*
 * UTF-8 to UTF-16 conversion and vice versa.
 */
extern mdn_result_t
mdn_util_utf8toutf16(const char *utf8, size_t fromlen,
		     unsigned short *utf16, size_t tolen, size_t *reslenp);

extern mdn_result_t
mdn_util_utf16toutf8(const unsigned short *utf16, size_t fromlen,
		     char *utf8, size_t tolen, size_t *reslenp);

#endif /* MDN_UTIL_H */
