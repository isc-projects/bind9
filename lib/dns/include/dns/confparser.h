/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: confparser.h,v 1.12.4.1 2001/01/09 22:45:23 bwelling Exp $ */

#ifndef DNS_CONFPARSER_H
#define DNS_CONFPARSER_H 1

/*****
 ***** Module Info
 *****/

/*
 * Main entry point in the config file parser module.
 *
 * The parser module handles the parsing of config files. The entry point
 * is:
 *
 * isc_result_t dns_c_parse_namedconf(const char *filename, isc_mem_t *mem,
 *				   dns_c_ctx_t **configctx,
 *				   dns_c_cbks_t *callbacks);
 *
 * MP:
 * 	Only a single thread is let through the module at once.
 *
 * Reliability:
 * 	No anticipated impact.
 *
 * Resources:
 * 	Long-term memory allocation done with memory allocator supplied by
 * 	caller.
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

#include <isc/lang.h>
#include <isc/types.h>

#include <dns/confctx.h>

/*
 * Typedefs for the callbacks done while parsing. If the callback functions
 * return anything other than ISC_R_SUCCESS, then the parse routine
 * terminates with an error.
 */

typedef isc_result_t (*dns_c_zonecbk_t)(dns_c_ctx_t *ctx,
					dns_c_zone_t *zone,
					dns_c_view_t *view,
					void *uap);
typedef isc_result_t (*dns_c_optscbk_t)(dns_c_ctx_t *ctx, void *uap);

typedef struct dns_c_cbks {
	dns_c_zonecbk_t	zonecbk;
	void	       *zonecbkuap;

	dns_c_optscbk_t optscbk;
	void	       *optscbkuap;
} dns_c_cbks_t;

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_parse_namedconf(const char *filename, isc_mem_t *mem,
		      dns_c_ctx_t **configctx, dns_c_cbks_t *callbacks);

/*
 * Parse a named confile file. Fills up a new config context with the config
 * data. All memory allocations for the contents of configctx are done
 * using the MEM argument. Caller must destroy the config context with
 * dns_c_ctx_delete() when done.
 *
 * Requires:
 *	*filename is a valid filename.
 *	*mem is a valid memory manager.
 *	*configctx is a valid isc_config_ctx_t pointer
 *	callbacks is NULL or it points to a valid dns_c_cbks_t structure.
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

ISC_LANG_ENDDECLS

#endif /* DNS_CONFPARSER_H */
