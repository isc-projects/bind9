/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef DNS_RDATASLAB_H
#define DNS_RDATASLAB_H 1

/*
 * DNS Rdata Slab
 *
 * Implements storage of rdatasets into slabs of memory.
 *
 * MP:
 *	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *	This module deals with low-level byte streams.  Errors in any of
 *	the functions are likely to crash the server or corrupt memory.
 *
 * Resources:
 *	None.
 *
 * Security:
 *
 *	Very little range checking is done in these functions for rdata
 *	copied in or out.  It is assumed that the caller knows what is
 *	going on.
 *
 * Standards:
 *	None.
 */

/***
 *** Imports
 ***/

#include <isc/region.h>

#include <dns/types.h>
#include <dns/rdataset.h>

/***
 *** Functions
 ***/

dns_result_t
dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   isc_region_t *region, unsigned int reservelen);
/*
 * Slabify a rdataset.  The slab area will be allocated and returned
 * in 'region'.
 *
 * Requires:
 *	'rdataset' is valid.
 *
 * Ensures:
 *	'region' will have base pointing to the start of allocated memory,
 *	with the slabified region beginning at region->base + reservelen.
 *	region->length contains the total length allocated.
 *
 * Returns:
 *	DNS_R_SUCCESS		- successful completion
 *	DNS_R_NOMEM		- no memory.
 *	<XXX others>
 */


dns_result_t
dns_rdataslab_tordataset(dns_rdataset_t *rdataset, isc_region_t *region,
			 unsigned int reservelen);
/*
 * Unslabify a rdataset.  The slab is not deallocated.
 *
 * Requires:
 *	'rdataset' is valid.
 *
 *	'region' points to a region of memory that contains the slabified
 *	data at offset 'reservelen'.
 *
 * Ensures:
 *	'rdataset' contains the structure version of data in 'region'.
 *
 * Returns:
 *	DNS_R_SUCCESS		- successful completion
 *	DNS_R_NOMEM		- no memory.
 *	<XXX others>
 */

#endif /* DNS_RDATADLAB_H */
