/* $Id: resconf.h,v 1.1 2002/01/02 02:46:34 marka Exp $ */
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

#ifndef MDN_RESCONF_H
#define MDN_RESCONF_H 1

/*
 * MDN resolver configuration.
 */

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/checker.h>
#include <mdn/mapper.h>
#include <mdn/mapselector.h>
#include <mdn/delimitermap.h>

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
 * Increment reference count of the context created by 'mdn_resconf_create'.
 */
extern void
mdn_resconf_incrref(mdn_resconf_t ctx);

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
 * Get an object of lower module that `ctx' holds.
 */
extern mdn_delimitermap_t
mdn_resconf_getdelimitermap(mdn_resconf_t ctx);

extern mdn_converter_t
mdn_resconf_getidnconverter(mdn_resconf_t ctx);

extern mdn_converter_t
mdn_resconf_getlocalconverter(mdn_resconf_t ctx);

extern mdn_mapselector_t
mdn_resconf_getlocalmapselector(mdn_resconf_t ctx);

extern mdn_mapper_t
mdn_resconf_getmapper(mdn_resconf_t ctx);

extern mdn_normalizer_t
mdn_resconf_getnormalizer(mdn_resconf_t ctx);

extern mdn_checker_t
mdn_resconf_getprohibitchecker(mdn_resconf_t ctx);

extern mdn_checker_t
mdn_resconf_getunassignedchecker(mdn_resconf_t ctx);

/*
 * Set an object of lower module to `ctx'.
 */
extern void
mdn_resconf_setdelimitermap(mdn_resconf_t ctx,
			    mdn_delimitermap_t delimiter_mapper);

extern void
mdn_resconf_setidnconverter(mdn_resconf_t ctx,
                            mdn_converter_t idn_coverter);

extern void
mdn_resconf_setlocalconverter(mdn_resconf_t ctx,
			      mdn_converter_t local_converter);

extern void
mdn_resconf_setlocalmapselector(mdn_resconf_t ctx,
				mdn_mapselector_t map_selector);

extern void
mdn_resconf_setmapper(mdn_resconf_t ctx, mdn_mapper_t mapper);

extern void
mdn_resconf_setnormalizer(mdn_resconf_t ctx, mdn_normalizer_t normalizer);

extern void
mdn_resconf_setprohibitchecker(mdn_resconf_t ctx,
			       mdn_checker_t prohibit_checker);

extern void
mdn_resconf_setunassignedchecker(mdn_resconf_t ctx,
				 mdn_checker_t unassigned_checker);

/*
 * Set name or add names to an object of lower module that `ctx' holds.
 */
extern mdn_result_t
mdn_resconf_setidnconvertername(mdn_resconf_t ctx, const char *name,
				int flags);

extern mdn_result_t
mdn_resconf_addalldelimitermapucs(mdn_resconf_t ctx, unsigned long *v, int nv);

extern mdn_result_t
mdn_resconf_setlocalconvertername(mdn_resconf_t ctx, const char *name,
				  int flags);

extern mdn_result_t
mdn_resconf_addalllocalmapselectornames(mdn_resconf_t ctx, const char *tld,
					const char **names, int nnames);

extern mdn_result_t
mdn_resconf_addallmappernames(mdn_resconf_t ctx, const char **names,
			      int nnames);

extern mdn_result_t
mdn_resconf_addallnormalizernames(mdn_resconf_t ctx, const char **names,
				  int nnames);

extern mdn_result_t
mdn_resconf_addallprohibitcheckernames(mdn_resconf_t ctx, const char **names,
				       int nnames);

extern mdn_result_t
mdn_resconf_addallunassignedcheckernames(mdn_resconf_t ctx, const char **names,
					 int nnames);

extern mdn_result_t
mdn_resconf_setnameprepversion(mdn_resconf_t ctx, const char *version);

/*
 * These macros are provided for backward compatibility to mDNkit 2.1
 * and older.
 */
extern void
mdn_resconf_setalternateconverter(mdn_resconf_t ctx,
                                  mdn_converter_t alternate_converter);

extern mdn_result_t
mdn_resconf_setalternateconvertername(mdn_resconf_t ctx, const char *name,
				      int flags);

extern mdn_converter_t
mdn_resconf_getalternateconverter(mdn_resconf_t ctx);


/*
 * These macros are provided for backward compatibility to mDNkit 1.x.
 */
#define mdn_resconf_localconverter(ctx) \
	mdn_resconf_getlocalconverter(ctx)

#define mdn_resconf_idnconverter(ctx) \
	mdn_resconf_getidnconverter(ctx)

#define mdn_resconf_alternateconverter(ctx) \
	mdn_resconf_getalternateconverter(ctx)

#define mdn_resconf_normalizer(ctx) \
	mdn_resconf_getnormalizer(ctx)

#define mdn_resconf_mapper(ctx) \
	mdn_resconf_getmapper(ctx)

#define mdn_resconf_delimitermap(ctx) \
	mdn_resconf_getdelimitermap(ctx)

#define mdn_resconf_localmapselector(ctx) \
	mdn_resconf_getlocalmapselector(ctx)

#define mdn_resconf_prohibitchecker(ctx) \
	mdn_resconf_getprohibitchecker(ctx)

#define mdn_resconf_unassignedchecker(ctx) \
	mdn_resconf_getunassignedchecker(ctx)

#endif /* MDN_RESCONF_H */
