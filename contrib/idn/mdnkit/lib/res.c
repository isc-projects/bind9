#ifndef lint
static char *rcsid = "$Id: res.c,v 1.5 2000/09/20 02:47:32 ishisone Exp $";
#endif

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

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/translator.h>
#include <mdn/resconf.h>
#include <mdn/res.h>
#include <mdn/debug.h>

static mdn_result_t	copy_verbatim(const char *from, char *to,
				      size_t tolen);
static int		contain_invalid_char(const char *name);

mdn_result_t
mdn_res_localtoucs(mdn_resconf_t conf, const char *local_name,
		   char *ucs_name, size_t ucs_name_len)
{
	mdn_converter_t conv;
	mdn_result_t r;

	assert(local_name != NULL && ucs_name != NULL);

	TRACE(("mdn_res_localtoucs(local_name=\"%-.20s\")\n", local_name));

	if (conf == NULL)
		return (copy_verbatim(local_name, ucs_name, ucs_name_len));

	if (!contain_invalid_char(local_name) &&
	    (conv = mdn_resconf_alternateconverter(conf)) != NULL) {
		TRACE(("mdn_res_localtoucs: trying alternate converter..\n"));
		r = mdn_converter_convert(conv, mdn_converter_l2u,
					  local_name, ucs_name, ucs_name_len);
		if (r == mdn_success)
			return (r);
	}
	
	if ((conv = mdn_resconf_localconverter(conf)) == NULL)
		return (copy_verbatim(local_name, ucs_name, ucs_name_len));

	TRACE(("mdn_res_localtoucs: using local converter..\n"));
	return (mdn_converter_convert(conv, mdn_converter_l2u,
				      local_name, ucs_name, ucs_name_len));
}

mdn_result_t
mdn_res_ucstolocal(mdn_resconf_t conf, const char *ucs_name,
		   char *local_name, size_t local_name_len)
{
	mdn_converter_t conv;
	mdn_result_t r;

	assert(ucs_name != NULL && local_name != NULL);

	TRACE(("mdn_res_ucstolocal(ucs_name=\"%s\")\n",
	      mdn_debug_xstring(ucs_name, 20)));

	if (conf == NULL ||
	    (conv = mdn_resconf_localconverter(conf)) == NULL)
		return (copy_verbatim(ucs_name, local_name, local_name_len));

	r = mdn_converter_convert(conv, mdn_converter_u2l,
				  ucs_name, local_name, local_name_len);

	if (r == mdn_nomapping &&
	    (conv = mdn_resconf_alternateconverter(conf)) != NULL) {
		TRACE(("mdn_res_ucstolocal: switched to alternate converter\n"));
		r = mdn_converter_convert(conv, mdn_converter_u2l,
					  ucs_name, local_name,
					  local_name_len);
	}
	return (r);
}

mdn_result_t
mdn_res_normalize(mdn_resconf_t conf, const char *name,
		  char *normalized_name, size_t normalized_name_len)
{
	mdn_normalizer_t norm;

	assert(name != NULL && normalized_name != NULL);

	TRACE(("mdn_res_normalize(name=\"%s\")\n",
	      mdn_debug_xstring(name, 20)));

	if (conf == NULL ||
	    (norm = mdn_resconf_normalizer(conf)) == NULL)
		return (copy_verbatim(name, normalized_name,
				      normalized_name_len));
	return (mdn_normalizer_normalize(norm, name, normalized_name,
					 normalized_name_len));
}

mdn_result_t
mdn_res_ucstodns(mdn_resconf_t conf, const char *ucs_name, char *dns_name,
		 size_t dns_name_len)
{
	mdn_converter_t conv;
	mdn_result_t r;
	const char *zld;

	assert(ucs_name != NULL && dns_name != NULL);

	TRACE(("mdn_res_ucstodns(ucs_name=\"%s\")\n",
	      mdn_debug_xstring(ucs_name, 20)));

	if (conf == NULL ||
	    (conv = mdn_resconf_serverconverter(conf)) == NULL ||
	    !contain_invalid_char(ucs_name))
		return (copy_verbatim(ucs_name, dns_name, dns_name_len));

	r = mdn_converter_convert(conv, mdn_converter_u2l,
				  ucs_name, dns_name, dns_name_len);
	if (r != mdn_success)
		return (r);

	if ((zld = mdn_resconf_zld(conf)) != NULL) {
		size_t len;

		TRACE(("mdn_res_ucstodns: adding ZLD\n"));
		len = strlen(dns_name);
		if (len > 0 && dns_name[len - 1] != '.') {
			if (len + 1 >= dns_name_len)
				return (mdn_buffer_overflow);
			strcpy(dns_name + len, ".");
			len++;
		}
		if (len + strlen(zld) >= dns_name_len)
			return (mdn_buffer_overflow);
		(void)strcat(dns_name, zld);
	}
	return (mdn_success);
}

mdn_result_t
mdn_res_dnstoucs(mdn_resconf_t conf, const char *dns_name, char *ucs_name,
		 size_t ucs_name_len)
{
	const char *zld;
	mdn_converter_t conv;
	char domainbuf[512];
	int convert;

	assert(dns_name != NULL && ucs_name != NULL);

	TRACE(("mdn_res_dnstoucs(dns_name=\"%s\")\n",
	      mdn_debug_xstring(dns_name, 20)));

	if (conf == NULL ||
	    (conv = mdn_resconf_serverconverter(conf)) == NULL)
		return (copy_verbatim(dns_name, ucs_name, ucs_name_len));

	if ((zld = mdn_resconf_zld(conf)) != NULL) {
		if (mdn_translator_matchzld(dns_name, zld)) {
			/*
			 * Strip 'zld' from 'dns_name'.
			 */
			size_t namelen = strlen(dns_name);

			TRACE(("mdn_res_dnstoucs: ZLD matched\n"));
			/* 'zld' must end with dot, but 'dns_name' may not. */
			if (namelen > 0 && dns_name[namelen - 1] != '.')
				namelen++;
			namelen -= strlen(zld);
			if (namelen >= sizeof(domainbuf))
				return (mdn_invalid_name);
			(void)strncpy(domainbuf, dns_name, namelen);
			domainbuf[namelen] = '\0';
			dns_name = domainbuf;
			convert = 1;
		} else if (contain_invalid_char(dns_name)) {
			TRACE(("mdn_res_dnstoucs: contain invalid char\n"));
			return (mdn_invalid_name);
		} else {
			convert = 0;
		}
	} else if (!mdn_converter_isasciicompatible(conv) &&
		   !contain_invalid_char(dns_name)) {
		convert = 0;
	} else {
		convert = 1;
	}

	if (convert) {
		TRACE(("mdn_res_dnstoucs: convert to ucs\n"));
		return (mdn_converter_convert(conv, mdn_converter_l2u,
					      dns_name, ucs_name,
					      ucs_name_len));
	} else {
		return (copy_verbatim(dns_name, ucs_name, ucs_name_len));
	}
}

static mdn_result_t
copy_verbatim(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from) + 1;

	if (tolen < fromlen)
		return (mdn_buffer_overflow);
	(void)memcpy(to, from, fromlen);
	return (mdn_success);
}

static int
contain_invalid_char(const char *name) {
	int c;

	while ((c = *name++) != '\0') {
		if (('a' <= c && c <= 'z') ||
		    ('A' <= c && c <= 'Z') ||
		    ('0' <= c && c <= '9') ||
		    c == '.' || c == '-')
			continue;	/* valid character */
		return (1);
	}
	return (0);
}
