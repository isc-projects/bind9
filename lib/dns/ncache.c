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

#include <config.h>

#include <isc/assertions.h>
#include <isc/region.h>
#include <isc/buffer.h>

#include <dns/types.h>
#include <dns/ncache.h>
#include <dns/name.h>
#include <dns/compress.h>
#include <dns/message.h>
#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>

/*
 * The format of an ncache rdata is a sequence of one or more records of
 * the following format:
 *
 *	owner name
 *	type
 *	rdata count
 *		rdata length			These two occur 'rdata count'
 *		rdata				times.
 *
 */

static inline isc_result_t
copy_rdataset(dns_rdataset_t *rdataset, isc_buffer_t *buffer) {
	isc_result_t result;
	unsigned int count;
	isc_region_t ar, r;
	dns_rdata_t rdata;

	/*
	 * Copy the rdataset count to the buffer.
	 */
	isc_buffer_available(buffer, &ar);
	if (ar.length < 2)
		return (ISC_R_NOSPACE);
	count = dns_rdataset_count(rdataset);
	INSIST(count <= 65535);
	isc_buffer_putuint16(buffer, (isc_uint16_t)count);

	result = dns_rdataset_first(rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(rdataset, &rdata);
		dns_rdata_toregion(&rdata, &r);
		INSIST(r.length <= 65535);
		isc_buffer_available(buffer, &ar);
		if (ar.length < 2)
			return (ISC_R_NOSPACE);
		/*
		 * Copy the rdata length to the buffer.
		 */
		isc_buffer_putuint16(buffer, (isc_uint16_t)r.length);
		/*
		 * Copy the rdata to the buffer.
		 */
		result = isc_buffer_copyregion(buffer, &r);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = dns_rdataset_next(rdataset);
	}
	if (result != ISC_R_NOMORE)
		return (result);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_ncache_add(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
	       dns_rdatatype_t covers, isc_stdtime_t now,
	       dns_rdataset_t *addedrdataset)
{
	isc_result_t result;
	isc_buffer_t buffer;
	isc_region_t r;
	dns_rdataset_t *rdataset;
	dns_rdata_t rdata;
	dns_rdataset_t ncrdataset;
	dns_rdatalist_t ncrdatalist;
	dns_rdatatype_t type;
	dns_name_t *name;
	dns_ttl_t ttl;
	char *data[4096];

	/*
	 * We assume that all data in the authority section has been
	 * validated by the caller.
	 */

	/*
	 * First, build an ncache rdata in buffer.
	 */
	ttl = 0xffffffff;
	isc_buffer_init(&buffer, data, sizeof data, ISC_BUFFERTYPE_BINARY);
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY,
					&name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			/*
			 * XXXRTH  check for ignore bit here?
			 */
			type = rdataset->type;
			if (type == dns_rdatatype_sig)
				type = rdataset->covers;
			if (type == dns_rdatatype_soa ||
			    type == dns_rdatatype_nxt) {
				if (ttl > rdataset->ttl)
					ttl = rdataset->ttl;
				/*
				 * Copy the owner name to the buffer.
				 */
				dns_name_toregion(name, &r);
				result = isc_buffer_copyregion(&buffer,
							       &r);
				if (result != ISC_R_SUCCESS)
					return (result);
				/*
				 * Copy the type to the buffer.
				 */
				isc_buffer_available(&buffer, &r);
				if (r.length < 2)
					return (ISC_R_NOSPACE);
				isc_buffer_putuint16(&buffer, type);
				/*
				 * Copy the rdataset into the buffer.
				 */
				result = copy_rdataset(rdataset, &buffer);
				if (result != ISC_R_SUCCESS)
					return (result);
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
	}
	if (result != ISC_R_NOMORE)
		return (result);

	/*
	 * Now, turn 'buffer' into an ncache rdataset and add it to
	 * the cache.
	 */

	dns_rdata_init(&rdata);
	isc_buffer_available(&buffer, &r);
	rdata.data = r.base;
	rdata.length = r.length;
	rdata.rdclass = dns_db_class(cache);
	rdata.type = 0;

	ncrdatalist.rdclass = rdata.rdclass;
	ncrdatalist.type = 0;
	ncrdatalist.covers = covers;
	ncrdatalist.ttl = ttl;
	ISC_LIST_INIT(ncrdatalist.rdata);
	ISC_LINK_INIT(&ncrdatalist, link);

	ISC_LIST_APPEND(ncrdatalist.rdata, &rdata, link);

	dns_rdataset_init(&ncrdataset);
	dns_rdatalist_tordataset(&ncrdatalist, &ncrdataset);

	result = dns_db_addrdataset(cache, node, NULL, now, &ncrdataset,
				    ISC_FALSE, addedrdataset);

	return (result);
}

isc_result_t
dns_ncache_towire(dns_rdataset_t *rdataset, dns_compress_t *cctx,
		  isc_buffer_t *target, unsigned int *countp)
{
	REQUIRE(rdataset->type == 0);

	

	return (ISC_R_NOTIMPLEMENTED);
}
