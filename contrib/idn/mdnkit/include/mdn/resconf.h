/* $Id: resconf.h,v 1.4 2000/08/23 05:53:23 ishisone Exp $ */
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

#ifndef MDN_RESCONF_H
#define MDN_RESCONF_H 1

/*
 * MDN resolver configuration.
 */

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>

/*
 * Configuration type (opaque).
 */
typedef struct mdn_resconf *mdn_resconf_t;

/*
 * Initialize.
 *
 * Initialize this module and underlying ones.  Must be called before
 * any other functions of this module.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_resconf_initialize(void);

/*
 * Create a configuration context.
 *
 * Create an empty context and store it in '*ctxp'.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_resconf_create(mdn_resconf_t *ctxp);

/*
 * Destroy the configuration context.
 *
 * Destroy the configuration context created by 'mdn_resconf_create',
 * and release memory for it.
 */
extern void
mdn_resconf_destroy(mdn_resconf_t ctx);

/*
 * Load configuration file.
 *
 * Parse an MDN configuration file whose name is specified by 'file',
 * store the result in 'ctx'.  If 'file' is NULL, the default file is
 * loaded.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nofile		-- couldn't open specified file.
 *	mdn_invalid_syntax	-- syntax error found.
 *	mdn_invalid_name	-- invalid encoding/nomalization name is
 *				   specified.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_resconf_loadfile(mdn_resconf_t ctx, const char *file);

/*
 * Get the pathname of the default configuration file.
 *
 * Returns:
 *	the pathname of the default MDN configuration file.
 */
extern char *
mdn_resconf_defaultfile(void);

/*
 * Get codeset converters.
 *
 *  + for local encoding,
 *  + for DNS protocol encoding,
 *  + for alternate encoding (which is used when the string to be converterd
 *    to the local encoding has some characters having no mapping to the
 *    local encoding)
 * In case of error, NULL will be returned.
 */

extern mdn_converter_t
mdn_resconf_localconverter(mdn_resconf_t ctx);

extern mdn_converter_t
mdn_resconf_serverconverter(mdn_resconf_t ctx);

extern mdn_converter_t
mdn_resconf_alternateconverter(mdn_resconf_t ctx);

/*
 * Get Zero-Level-Domain name.
 *
 * If there's no ZLD, NULL will be returned.
 */
extern const char *
mdn_resconf_zld(mdn_resconf_t ctx);

/*
 * Get domain name normalizer.
 *
 * In case of error, NULL will be returned.
 */
extern mdn_normalizer_t
mdn_resconf_normalizer(mdn_resconf_t ctx);

#endif
