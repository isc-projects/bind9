/*
 * convert.c - convert domain name
 */

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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jpnicmdn.h"

/*
 * prepare/dispose conversion context
 */
 
void
mdnConvDone(CONVPTR converter)
{
    if (converter == NULL) {
        return;
    }
    mdn_resconf_destroy(converter->conf);
    free(converter);
}

CONVPTR
mdnConvInit(void)
{
    CONVPTR conv;
    UCHAR confpath[256];
    UCHAR encoding[100];
    mdn_result_t r;
    
    mdnLogPrintf(mdn_log_level_info, "libmdn version: %s\n",
		 mdn_version_getstring());

    if ((conv = malloc(sizeof(CONVREC))) == NULL) {
        mdnPrintf("mdnConvInit: allocation failed\n");
        return NULL;
    }
    conv->conf = NULL;

    /*
     * Initialize.
     */
    if ((r = mdn_resconf_initialize()) != mdn_success) {
        mdnPrintf("mdnConvInit: cannot initialize mdn library: %s\n",
		  mdn_result_tostring(r));
        mdnConvDone(conv);
	return NULL;
    }
    if ((r = mdn_resconf_create(&conv->conf)) != mdn_success) {
        mdnPrintf("mdnConvInit: cannot create configuration context: %s\n",
		  mdn_result_tostring(r));
        mdnConvDone(conv);
	return NULL;
    }

    /*
     * load configuration file.
     */
    if (mdnGetConfFile(confpath) != TRUE) {
        mdnPrintf("mdnConvInit: cannot find configuration file path\n");
        mdnConvDone(conv);
	return NULL;
    }
    if ((r = mdn_resconf_loadfile(conv->conf, confpath)) != mdn_success) {
	mdnPrintf("mdnConvInit: cannot read configuration file %s: %s\n",
		  confpath, mdn_result_tostring(r));
	mdnConvDone(conv);
	return NULL;
    }

    /*
     * Set local codeset.
     */
    if (mdnGetPrgEncoding(encoding) == TRUE) {
	mdnPrintf("Encoding PRG <%s>\n", encoding);
	r = mdn_resconf_setlocalconvertername(conv->conf, encoding,
					      MDN_CONVERTER_RTCHECK);
	if (r != mdn_success) {
	    mdnPrintf("mdnConvInit: cannot open converter for %s: %s\n",
		      encoding, mdn_result_tostring(r));
	    mdnConvDone(conv);
	    return NULL;
	}
    }

    return conv;
}

/*
 * mdnConvReq - convert domain name in a DNS request
 *
 *      convert local encoding to DNS encoding
 */
 
BOOL
mdnConvReq(CONVPTR converter, const char FAR *from, char FAR *to, size_t tolen)
{
    if (converter == NULL) {
        if (strlen(from) >= tolen)
	    return FALSE;
        strcpy(to, from);
	return TRUE;
    }
        
    if (mdn_res_nameconv(converter->conf, "ldMNI",
			 from, to, tolen) == mdn_success)
        return TRUE;
    else
        return FALSE;
}

/*
 * mdnConvRsp - convert domain name in a DNS response
 *
 *      convert DNS encoding to local encoding
 */

BOOL
mdnConvRsp(CONVPTR converter, const char FAR *from, char FAR *to, size_t tolen)
{
    if (converter == NULL) {
        if (strlen(from) >= tolen)
	    return FALSE;
        strcpy(to, from);
	return TRUE;
    }
        
    if (mdn_res_nameconv(converter->conf, "iL",
			 from, to, tolen) == mdn_success)
        return TRUE;
    else
        return FALSE;
}

