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

#ifndef DNS_MASTER_H
#define DNS_MASTER_H 1

/***
 ***	Imports
 ***/

#include <stdio.h>

#include <isc/lang.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

/***
 ***	Function
 ***/

isc_result_t
dns_master_loadfile(const char *master_file,
		    dns_name_t *top,
		    dns_name_t *origin,
		    dns_rdataclass_t zclass,
		    isc_boolean_t age_ttl,
		    dns_rdatacallbacks_t *callbacks,
		    isc_mem_t *mctx);

isc_result_t
dns_master_loadstream(FILE *stream,
		      dns_name_t *top,
		      dns_name_t *origin,
		      dns_rdataclass_t zclass,
		      isc_boolean_t age_ttl,
		      dns_rdatacallbacks_t *callbacks,
		      isc_mem_t *mctx);

isc_result_t
dns_master_loadbuffer(isc_buffer_t *buffer,
		      dns_name_t *top,
		      dns_name_t *origin,
		      dns_rdataclass_t zclass,
		      isc_boolean_t age_ttl,
		      dns_rdatacallbacks_t *callbacks,
		      isc_mem_t *mctx);

/*
 * Loads a RFC 1305 master file from a file, stream, or buffer into rdatasets
 * and then calls 'callbacks->commit' to commit the rdatasets.  Rdata memory
 * belongs to dns_master_load and will be reused / released when the callback
 * completes.  dns_load_master will abort if callbacks->commit returns
 * any value other than ISC_R_SUCCESS.
 *
 * If 'age_ttl' is ISC_TRUE and the master file contains one or more
 * $DATE directives, the TTLs of the data will be aged accordingly.
 * 
 * 'callbacks->commit' is assumed to call 'callbacks->error' or
 * 'callbacks->warn' to generate any error messages required.
 *
 * Requires:
 *	'master_file' to point to a valid string.
 *	'top' to point to a valid name.
 *	'origin' to point to a valid name.
 *	'callbacks->commit' to point ta a valid function.
 *	'callbacks->error' to point ta a valid function.
 *	'callbacks->warn' to point ta a valid function.
 *	'mctx' to point to a memory context.
 *
 * Returns:
 *	ISC_R_SUCCESS upon successfully loading the master file.
 *	ISC_R_NOMEMORY out of memory.
 *	ISC_R_UNEXPECTEDEND expected to be able to read a input token and
 *		there was not one.
 *	ISC_R_UNEXPECTED
 *	DNS_R_NOOWNER failed to specify a ownername.
 *	DNS_R_NOTTL failed to specify a ttl.
 *	DNS_R_BADCLASS record class did not match zone class.
 *	Any dns_rdata_fromtext() error code.
 *	Any error code from callbacks->commit().
 */

ISC_LANG_ENDDECLS

#endif /* DNS_MASTER_H */
