/* $Id: converter.h,v 1.1 2002/01/02 02:46:30 marka Exp $ */
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

#ifndef MDN_CONVERTER_H
#define MDN_CONVERTER_H 1

/*
 * Codeset converter.
 *
 * This module provides conversions from some local codeset to UTF-8
 * and vice versa.
 */

#include <mdn/result.h>

/*
 * Converter context type (opaque).
 */
typedef struct mdn_converter *mdn_converter_t;

/*
 * Conversion direction (local codeset -> UTF-8 or the opposite)
 */
typedef enum {
	mdn_converter_l2u,		/* local-to-utf8 */
	mdn_converter_u2l		/* utf8-to-local */
} mdn_converter_dir_t;

/*
 * Conversion flags.
 */
#define MDN_CONVERTER_DELAYEDOPEN	1
#define MDN_CONVERTER_RTCHECK		2

/*
 * Encoding types.
 */
#define MDN_NONACE			0
#define MDN_ACE_STRICTCASE		1
#define MDN_ACE_LOOSECASE		2

/*
 * Initialize module.  Must be called before any other calls of
 * the functions of this module.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_converter_initialize(void);

/*
 * Create a conversion context.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_invalid_name	-- specified codeset is not supported.
 *	mdn_nomemory		-- malloc failed.
 *	mdn_failure		-- other failure (unknown cause).
 */
extern mdn_result_t
mdn_converter_create(const char *name, mdn_converter_t *ctxp,
		     int flags);

/*
 * Decrement reference count of the converter `ctx' created by
 * 'mdn_converter_create', if it is still refered by another object.
 * Otherwise, release all the memory allocated to the converter.
 */
extern void
mdn_converter_destroy(mdn_converter_t ctx);

/*
 * Increment reference count of the converter `ctx' created by
 * 'mdn_converter_create'.
 */
extern void
mdn_converter_incrref(mdn_converter_t ctx);

/*
 * Convert between local codeset and UTF-8.  Note that each conversion
 * is started with initial state.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_buffer_overflow	-- output buffer is too small.
 *	mdn_invalid_encoding	-- the input string has invalid/illegal
 *				   byte sequence.
 *	mdn_invalid_name	-- codeset is not supported (this error
 *				   should happen only if 'delayedopen'
 *				   flag was set when mdn_converter_create
 *				   was called)
 *	mdn_failure		-- other failure.
 */
extern mdn_result_t
mdn_converter_convert(mdn_converter_t ctx, mdn_converter_dir_t dir,
		      const char *from, char *to, size_t tolen);

/*
 * Macros for convenience.
 */
#define mdn_converter_localtoutf8(ctx, from, to, tolen) \
	mdn_converter_convert((ctx), mdn_converter_l2u, (from), (to), (tolen))

#define mdn_converter_utf8tolocal(ctx, from, to, tolen) \
	mdn_converter_convert((ctx), mdn_converter_u2l, (from), (to), (tolen))

/*
 * Get the name of local codeset.  The returned name may be different from
 * the one specified to mdn_converter_create, if the specified one was an
 * alias.
 *
 * Returns:
 *	the local codeset name.
 */
extern char *
mdn_converter_localencoding(mdn_converter_t ctx);

/*
 * Return the encoding type of this local encoding.
 *
 * Returns:
 *	MDN_NOACE		-- encoding is not ACE.
 *	MDN_ACE_STRICTCASE	-- encoding is ACE.
 *				   decoder of this ACE preserve letter case.
 *	MDN_ACE_LOOSECASE	-- encoding type is ACE.
 *				   decoder cannot preserve letter case.
 */
extern int
mdn_converter_encodingtype(mdn_converter_t ctx);

/*
 * Return if this local encoding is ACE (Ascii Compatible Encoding).
 *
 * Returns:
 *	1	-- yes, it is ACE.
 *	0	-- no.
 */
extern int
mdn_converter_isasciicompatible(mdn_converter_t ctx);

/*
 * Register an alias for a codeset name.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_converter_addalias(const char *alias_name, const char *real_name);

/*
 * Register aliases defined by the specified file.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nofile		-- no such file.
 *	mdn_invalid_syntax	-- file is malformed.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_converter_aliasfile(const char *path);

/*
 * Unregister all the aliases.
 */
extern mdn_result_t
mdn_converter_resetalias(void);


/*
 * New converter registration.
 */

/*
 * Conversion operation functions.
 */
typedef mdn_result_t (*mdn_converter_openproc_t)(mdn_converter_t ctx,
						 mdn_converter_dir_t dir,
						 void **privdata);
typedef mdn_result_t (*mdn_converter_closeproc_t)(mdn_converter_t ctx,
						  void *privdata,
						  mdn_converter_dir_t dir);
typedef mdn_result_t (*mdn_converter_convertproc_t)(mdn_converter_t ctx,
						    void *privdata,
						    mdn_converter_dir_t dir,
						    const char *from,
						    char *to, size_t tolen);

/*
 * Register a new converter.
 * 'encoding_type' is a value which mdn_converter_encodingtype() returns.
 *
 * Returns:
 *	mdn_success		-- ok.
 *	mdn_nomemory		-- malloc failed.
 */
extern mdn_result_t
mdn_converter_register(const char *name,
		       mdn_converter_openproc_t open,
		       mdn_converter_closeproc_t close,
		       mdn_converter_convertproc_t convert,
		       int encoding_type);

#endif /* MDN_CONVERTER_H */
