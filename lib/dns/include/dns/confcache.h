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

#ifndef DNS_CONFCACHE_H
#define DNS_CONFCACHE_H 1

/*****
 ***** Module Info
 *****/

/*
 * A container for the cache configuration data pulled from a
 * named.conf-style config file.
 */

/*
 *
 * MP:
 *	Client must do necessary locking.
 *      
 * Reliability:
 *
 *	No problems.
 *
 * Resources:
 *
 *	Use memory managers supplied by client.
 *
 * Security:
 *
 *	N/A
 *      
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/types.h>


/***
 *** Types
 ***/

typedef struct dns_c_cache		dns_c_cache_t;

struct dns_c_cache
{
	isc_mem_t	       *mem;

	/* XXX need this fleshed out */
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_cache_new(isc_mem_t *mem, dns_c_cache_t **cfgres);
/*
 * Creates a new cache-config object.
 *
 * Requires:
 *	mem be a pointer to a valid memory manager.
 *	newres be a valid non-NULL pointer.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- out of memory
 * 
 */

isc_result_t
dns_c_cache_delete(dns_c_cache_t **cfgres);
/*
 * Deletes the config-cache object and its contents.
 *
 * Requires:
 *	cfgres be a valid non-NULL pointer. The pointer it points to
 *	can be NULL or must be a valid dns_c_cache_t object.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 * 
 */

ISC_LANG_ENDDECLS

#endif /* DNS_CONFCACHE_H */
