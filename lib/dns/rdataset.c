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

#include <isc/assertions.h>

#include <dns/rdataset.h>

#define RDATASET_MAGIC			0x444E5352U	/* DNSR */
#define VALID_RDATASET(rdataset)	((rdataset) != NULL && \
					 (rdataset)->magic == RDATASET_MAGIC)

void
dns_rdataset_init(dns_rdataset_t *rdataset) {

	/*
	 * Make 'rdataset' a valid, disassociated rdataset.
	 */

	REQUIRE(rdataset != NULL);

	rdataset->magic = RDATASET_MAGIC;
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

	REQUIRE(VALID_RDATASET(rdataset));
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

	REQUIRE(VALID_RDATASET(rdataset));

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

	REQUIRE(VALID_RDATASET(rdataset));

	return ((rdataset->methods->first)(rdataset));
}

dns_result_t
dns_rdataset_next(dns_rdataset_t *rdataset) {

	/*
	 * Move the rdata cursor to the next rdata in the rdataset (if any).
	 */

	REQUIRE(VALID_RDATASET(rdataset));

	return ((rdataset->methods->next)(rdataset));
}

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {

	/*
	 * Make 'rdata' refer to the current rdata.
	 */

	REQUIRE(VALID_RDATASET(rdataset));

	(rdataset->methods->current)(rdataset, rdata);
}

dns_result_t
dns_rdataset_totext(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    isc_boolean_t omit_final_dot,
		    isc_buffer_t *target)
{

	/*
	 * Convert 'rdataset' to text format, storing the result in 'target'.
	 */

	REQUIRE(VALID_RDATASET(rdataset));

	/* XXX stop warnings. */
	owner_name = NULL;
	omit_final_dot = ISC_FALSE;
	target = NULL;

	return (DNS_R_NOTIMPLEMENTED);
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

	/* XXX stop warnings. */
	owner_name = NULL;
	cctx = NULL;
	target = NULL;

	REQUIRE(VALID_RDATASET(rdataset));

	return (DNS_R_NOTIMPLEMENTED);
}
