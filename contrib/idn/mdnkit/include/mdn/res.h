/* $Id: res.h,v 1.3 2000/08/23 06:56:58 ishisone Exp $ */
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
 * Convert from the local codeset string to UCS (UTF-8).
 *
 * 'local_name' is a string containing a domain name encoded in the
 * local codeset or the encoding specified by 'alternate-encoding'
 * directive in the MDN configuration file (mdnres.conf).
 * This function converts it to UCS and stores in
 * the buffer 'ucs_name', which is 'ucs_name_len' bytes long.
 *
 * 'conf' is a MDN resolver configuration context created by
 * 'mdn_resconf_create()', or NULL.  If it is NULL, no conversion is
 * performed, and the contents of 'local_name' are copied to 'ucs_name'
 * verbatim.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input string has invalid byte sequence.
 *	mdn_invalid_name	-- local encoding (codeset) name is invalid.
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_res_localtoucs(mdn_resconf_t conf, const char *local_name,
		   char *ucs_name, size_t ucs_name_len);

/*
 * Convert from UCS (UTF-8) string to the local codeset.
 *
 * 'ucs_name' is a string containing a domain name encoded in UTF-8.
 * This function converts it to the local codeset and stores in
 * the buffer 'local_name', which is 'local_name_len' bytes long.
 * If there are any characters which cannot be converted to the local
 * codeset, the 'alternate-encoding' is used instead of the local codeset.
 *
 * 'conf' is a MDN resolver configuration context created by
 * 'mdn_resconf_create()', or NULL.  If it is NULL, no conversion is
 * performed, and the contents of 'local_name' are copied to 'ucs_name'
 * verbatim.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input string has invalid byte sequence.
 *	mdn_invalid_name	-- local encoding (codeset) name is invalid.
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_res_ucstolocal(mdn_resconf_t conf, const char *ucs_name,
		   char *local_name, size_t local_name_len);

/*
 * Normalize UCS string.
 *
 * Perform normalization/canonicalization specified by the configuration
 * context 'conf' on the UTF-8 encoded string 'name', and store the result
 * in 'normalized_name', whose size is 'normalized_name_len' bytes.
 *
 * 'conf' is a MDN resolver configuration context created by
 * 'mdn_resconf_create()', or NULL.  If it is NULL, no normalization is
 * performed, and the contents of 'name' are copied to 'normalized_name'
 * verbatim.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input is not a valid UTF-8 string.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_res_normalize(mdn_resconf_t conf, const char *name,
		  char *normalized_name, size_t normalized_name_len);

/*
 * Convert from UCS (UTF-8) string to the encoding used in DNS protocol.
 *
 * 'ucs_name' is a string containing a domain name encoded in UTF-8.
 * This function converts it to the encoding used in DNS protocol data
 * (such as RACE), and stores in the buffer 'dns_name', which is
 * 'dns_name_len' bytes long.  Also if ZLD is specified in the configuration
 * file, it is appended to the conversion result.
 *
 * Both the encoding used in DNS protocol and ZLD are specified by 'conf'
 * which is a MDN resolver configuration context.  If 'conf' is NULL,
 * then no conversion is done.
 *
 * Requires:
 *	'ucs_name' must be a FQDN.  Otherwise the conversion result might
 *	not be correct for some DNS protocol encoding (namely UTF-5).
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input string has invalid byte sequence.
 *	mdn_invalid_name	-- local encoding (codeset) name is invalid.
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_res_ucstodns(mdn_resconf_t conf, const char *ucs_name, char *dns_name,
		 size_t dns_name_len);

/*
 * Convert from the DNS protocol encoding to UCS (UTF-8).
 *
 * This function converts 'dns_name' whose encoding is the encoding
 * used in DNS protocol data into UTF-8, and stores the result in the
 * buffer 'ucs_name', which is 'ucs_name_len' bytes long.  Also, if
 * 'dns_name' has ZLD specified by 'conf', the ZLD part is removed
 * from 'dns_name' before the conversion.
 *
 * Both the encoding used in DNS protocol and ZLD are specified by 'conf'
 * which is a MDN resolver configuration context.  If 'conf' is NULL,
 * then no conversion is done.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- input string has invalid byte sequence.
 *	mdn_invalid_name	-- local encoding (codeset) name is invalid.
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_res_dnstoucs(mdn_resconf_t conf, const char *dns_name, char *ucs_name,
		 size_t ucs_name_len);

#endif
