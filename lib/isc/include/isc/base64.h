/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* $Id: base64.h,v 1.4 2000/03/21 00:37:35 gson Exp $ */

#ifndef ISC_BASE64_H
#define ISC_BASE64_H 1

#include <isc/buffer.h>
#include <isc/lang.h>
#include <isc/lex.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/***
 *** Functions
 ***/

/* Convert data into base64 encoded text.
 *
 * Notes:
 *	The base64 encoded text in "target" will be divided into 
 *	words of at most "wordlength" characters, separated by
 * 	the "wordbreak" string.  No parentheses will surround
 *	the text.
 *
 * Requires:
 *	"source" is a region containing binary data
 *	"target" is a text buffer containing available space
 *	"wordbreak" points to a null-terminated string of
 *		zero or more whitespace characters
 *
 * Ensures:
 *	target will contain the base64 encoded version of the data
 *	in source.  The "used" pointer in target will be advanced as
 *	necessary.
 */
isc_result_t
isc_base64_totext(isc_region_t *source, int wordlength,
		  char *wordbreak, isc_buffer_t *target);

/* Convert base64 encoded text into data.
 *
 * Requires:
 *	"lex" is a valid lexer context
 *	"target" is a binary buffer containing binary data
 *	"length" is an integer
 *
 * Ensures:
 *	target will contain the data represented by the base64 encoded 
 *	string parsed by the lexer.  No more than length bytes will be read,
 *	if length is positive.  The "used" pointer in target will be
 *	advanced as necessary.
 */
isc_result_t
isc_base64_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length);

ISC_LANG_ENDDECLS

#endif /* ISC_BASE64_H */
