/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

/*****
 ***** Module Info
 *****/

/*
 * Parser
 *
 * The parser module handles the parsing of config files. Two entry points
 * are provided:
 *
 * 	parser_init()
 *
 * 	parse_configuration(const char *filename,
 * 			    isc_mem_t *mem, isc_cfgctx_t **configctx);
 *
 *
 * MP:
 * 	Only a single thread is let through the module at once.
 *
 * 	The program *MUST* first call parser_init() one time. Calling
 * 	parser_init() more than once may result in abort() dump (best case)
 * 	or undefined behaviour (worst case).
 *
 * Reliability:
 * 	No anticipated impact.
 *
 * Resources:
 * 	<TBS>
 *
 * Security:
 * 	<TBS>
 *
 * Standards:
 * 	None.
 */


/***
 *** Imports
 ***/

#include <config.h>

#include "configctx.h"

/***
 *** Functions
 ***/

isc_result_t parser_init(void);
/*
 * Does parser intitialization. Must be called before
 * isc_parse_configuration() is called
 *
 * Requires:
 *	The caller do necessary locking to prevent multiple threads from
 *	calling it at once.
 *
 * Ensures:
 *	Nothing.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *	ISC_R_FAILURE			something broke
 */


isc_result_t parse_configuration(const char *filename, isc_mem_t *mem,
				 isc_cfgctx_t **configctx);

/*
 * Parse the confile file. Fills up the config context with the new config
 * data. All memory allocations for the contents of configctx are done
 * using the MEM argument.
 *
 * Requires:
 *	*filename is a valid filename.
 *	*mem is a valid memory manager.
 *	*configctx is a valid isc_config_ctx_t pointer
 *
 * Ensures:
 *	On success, *configctx is attached to the newly created config context.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *	ISC_R_NOMEMORY
 *	ISC_R_INVALIDFILE		file doesn't exist or is unreadable
 *	ISC_R_FAILURE			file contains errors.
 */

