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

/* $Id: rdataslab.c,v 1.2 1999/02/06 00:07:08 halley Exp $ */

#include <config.h>

#include <isc/region.h>
#include <isc/buffer.h>
#include <isc/assertions.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>

dns_result_t
dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   isc_region_t *region, unsigned int reservelen)
{
	dns_rdata_t	rdata;
	unsigned char  *rawbuf;
	unsigned int	buflen;
	dns_result_t	result;
	unsigned int	nitems;

	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);

	buflen = reservelen + 2;
	nitems = 0;

	/*
	 * Run through the rdataset list once, counting up the size
	 * of all the rdata members within it.  We do not store the
	 * class, type, etc, just the rdata, so our overhead is 2 bytes
	 * for the number of records, and 2 for each rdata length, and
	 * then the rdata itself.
	 */
	do {
		dns_rdataset_current(rdataset, &rdata);
		buflen += (2 + rdata.length);

		nitems++;

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	/*
	 * Allocate the memory, set up a buffer, start copying in
	 * data.
	 */
	rawbuf = isc_mem_get(mctx, buflen);
	if (rawbuf == NULL)
		return (DNS_R_NOMEMORY);

	region->base = rawbuf;
	region->length = buflen;

	rawbuf += reservelen;

	*rawbuf++ = (nitems & 0xff00) >> 8;
	*rawbuf++ = (nitems & 0x00ff);
	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);
	do {
		dns_rdataset_current(rdataset, &rdata);
		*rawbuf++ = (rdata.length & 0xff00) >> 8;
		*rawbuf++ = (rdata.length & 0x00ff);
		memcpy(rawbuf, rdata.data, rdata.length);
		rawbuf += rdata.length;

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE) {
		isc_mem_put(mctx, region->base, region->length);
		region->base = NULL;
		region->length = 0;

		return (result);
	}

	return (DNS_R_SUCCESS);
}

unsigned int
dns_rdataslab_size(unsigned char *slab, unsigned int reservelen) {
	unsigned int count, length;
	unsigned char *current;

	REQUIRE(slab != NULL);

	current = slab + reservelen;
	count = *current++ * 256;
	count += *current++;
	while (count > 0) {
		count--;
		length = *current++ * 256;
		length += *current++;
		current += length;
	}
	
	return ((unsigned int)(current - slab));
}
