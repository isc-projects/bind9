/*
 * Copyright (C) 2004-2007  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ISC_COMMANDLINE_H
#define ISC_COMMANDLINE_H 1

/*! \file isc/commandline.h */

#include <isc/boolean.h>
#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/result.h>

/*% Index into parent argv vector. */
LIBISC_EXTERNAL_DATA extern int isc_commandline_index;
/*% Character checked for validity. */
LIBISC_EXTERNAL_DATA extern int isc_commandline_option;
/*% Argument associated with option. */
LIBISC_EXTERNAL_DATA extern char *isc_commandline_argument;
/*% For printing error messages. */
LIBISC_EXTERNAL_DATA extern char *isc_commandline_progname;
/*% Print error message. */
LIBISC_EXTERNAL_DATA extern isc_boolean_t isc_commandline_errprint;
/*% Reset getopt. */
LIBISC_EXTERNAL_DATA extern isc_boolean_t isc_commandline_reset;

ISC_LANG_BEGINDECLS

int
isc_commandline_parse(int argc, char * const *argv, const char *options);
/*%<
 * Parse a command line (similar to getopt())
 */

isc_result_t
isc_commandline_strtoargv(isc_mem_t *mctx, char *s, unsigned int *argcp,
			  char ***argvp, unsigned int n);
/*%<
 * Tokenize the string "s" into whitespace-separated words,
 * returning the number of words in '*argcp' and an array
 * of pointers to the words in '*argvp'.  The caller
 * must free the array using isc_mem_free().  The string
 * is modified in-place.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_COMMANDLINE_H */
