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

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>

#include <dns/rdata.h>
#include <dns/rdataset.h>

void
dns_rdataset_init(dns_rdataset_t *rdataset) {

	/*
	 * Make 'rdataset' a valid, disassociated rdataset.
	 */

	REQUIRE(rdataset != NULL);

	rdataset->magic = DNS_RDATASET_MAGIC;
	rdataset->methods = NULL;
	ISC_LINK_INIT(rdataset, link);
	rdataset->class = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
}

void
dns_rdataset_invalidate(dns_rdataset_t *rdataset) {

	/*
	 * Invalidate 'rdataset'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);
	
	rdataset->magic = 0;
	ISC_LINK_INIT(rdataset, link);
	rdataset->class = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
}

void
dns_rdataset_disassociate(dns_rdataset_t *rdataset) {

	/*
	 * Disassocate 'rdataset' from its rdata, allowing it to be reused.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	(rdataset->methods->disassociate)(rdataset);
	rdataset->methods = NULL;
	ISC_LINK_INIT(rdataset, link);
	rdataset->class = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
}

dns_result_t
dns_rdataset_first(dns_rdataset_t *rdataset) {

	/*
	 * Move the rdata cursor to the first rdata in the rdataset (if any).
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	return ((rdataset->methods->first)(rdataset));
}

dns_result_t
dns_rdataset_next(dns_rdataset_t *rdataset) {

	/*
	 * Move the rdata cursor to the next rdata in the rdataset (if any).
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	return ((rdataset->methods->next)(rdataset));
}

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {

	/*
	 * Make 'rdata' refer to the current rdata.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	(rdataset->methods->current)(rdataset, rdata);
}

dns_result_t
dns_rdataset_totext(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    isc_boolean_t omit_final_dot,
		    isc_buffer_t *target)
{
	dns_result_t result;
	unsigned int common_start, common_length, length;
	char *common, *tabs;
	dns_rdata_t rdata;
	isc_boolean_t first = ISC_TRUE;
	isc_region_t r;
	char classtypettl[100];

	/*
	 * Convert 'rdataset' to text format, storing the result in 'target'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);

	/*
	 * Make compiler happy.
	 */
	common_start = 0;
	common_length = 0;
	common = NULL;
	tabs = NULL;
	length = 0;

	/*
	 * XXX Explicit buffer structure references here.  Improve buffer
	 * API.
	 */
	do {
		if (first) {
			common_start = target->used;
			result = dns_name_totext(owner_name, omit_final_dot,
						 target);
			if (result != DNS_R_SUCCESS)
				return (result);
			common_length = target->used - common_start;
			common = (char *)target->base + common_start;
			if (common_length >= 16) {
				tabs = "\t";
				length = 1;
			} else if (common_length >= 8) {
				tabs = "\t\t";
				length = 2;
			} else {
				tabs = "\t\t\t";
				length = 3;
			}
			isc_buffer_available(target, &r);
			if (r.length < length)
				return (DNS_R_NOSPACE);
			memcpy(r.base, tabs, length);
			isc_buffer_add(target, length);
			common_length += length;
			/*
			 * XXX We print the class and type as numbers
			 * for now, but we'll convert to the mnemonics when
			 * the rdata implementation is available.
			 *
			 * XXX The following sprintf() is safe, but it
			 * would still be good to use snprintf if we had it.
			 */
			length = sprintf(classtypettl, "%u %u %u  ",
					 rdataset->class, rdataset->type,
					 rdataset->ttl);
			INSIST(length <= sizeof classtypettl);
			isc_buffer_available(target, &r);
			if (r.length < length)
				return (DNS_R_NOSPACE);
			memcpy(r.base, classtypettl, length);
			isc_buffer_add(target, length);
			common_length += length;
			first = ISC_FALSE;
		} else {
			isc_buffer_available(target, &r);
			if (r.length < common_length)
				return (DNS_R_NOSPACE);
			memcpy(r.base, common, common_length);
			isc_buffer_add(target, common_length);
		}

		dns_rdataset_current(rdataset, &rdata);
		/*
		 * XXX Call dns_rdata_towire() here.
		 */

		isc_buffer_available(target, &r);
		if (r.length < 1)
			return (DNS_R_NOSPACE);
		memcpy(r.base, "\n", 1);
		isc_buffer_add(target, 1);

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_rdataset_towire(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    dns_compress_t *cctx,
		    isc_buffer_t *target)
{

	/*
	 * Convert 'rdataset' to wire format, compressing names as specified
	 * in cctx, and storing the result in 'target'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	/* XXX stop warnings. */
	owner_name = NULL;
	cctx = NULL;
	target = NULL;

	return (DNS_R_NOTIMPLEMENTED);
}
