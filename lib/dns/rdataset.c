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

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>

#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdataset.h>
#include <dns/compress.h>

void
dns_rdataset_init(dns_rdataset_t *rdataset) {

	/*
	 * Make 'rdataset' a valid, disassociated rdataset.
	 */

	REQUIRE(rdataset != NULL);

	rdataset->magic = DNS_RDATASET_MAGIC;
	rdataset->methods = NULL;
	ISC_LINK_INIT(rdataset, link);
	rdataset->rdclass = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->trust = 0;
	rdataset->covers = 0;
	rdataset->attributes = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
	rdataset->private4 = NULL;
	rdataset->private5 = NULL;
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
	rdataset->rdclass = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->trust = 0;
	rdataset->covers = 0;
	rdataset->attributes = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
	rdataset->private4 = NULL;
	rdataset->private5 = NULL;
}

void
dns_rdataset_disassociate(dns_rdataset_t *rdataset) {

	/*
	 * Disassociate 'rdataset' from its rdata, allowing it to be reused.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	(rdataset->methods->disassociate)(rdataset);
	rdataset->methods = NULL;
	ISC_LINK_INIT(rdataset, link);
	rdataset->rdclass = 0;
	rdataset->type = 0;
	rdataset->ttl = 0;
	rdataset->trust = 0;
	rdataset->covers = 0;
	rdataset->attributes = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
	rdataset->private4 = NULL;
	rdataset->private5 = NULL;
}

isc_boolean_t
dns_rdataset_isassociated(dns_rdataset_t *rdataset) {
	/*
	 * Is 'rdataset' associated?
	 */
	
	REQUIRE(DNS_RDATASET_VALID(rdataset));

	if (rdataset->methods != NULL)
		return (ISC_TRUE);

	return (ISC_FALSE);
}

static void
question_disassociate(dns_rdataset_t *rdataset) {
	(void)rdataset;
}

static dns_result_t
question_cursor(dns_rdataset_t *rdataset) {
	(void)rdataset;
	return (DNS_R_NOMORE);
}

static void
question_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	/*
	 * This routine should never be called.
	 */
	(void)rdataset;
	(void)rdata;
	REQUIRE(0);
}

static void
question_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	*target = *source;
}

static dns_rdatasetmethods_t question_methods = {
	question_disassociate,
	question_cursor,
	question_cursor,
	question_current,
	question_clone,
};

void
dns_rdataset_makequestion(dns_rdataset_t *rdataset, dns_rdataclass_t rdclass,
			  dns_rdatatype_t type)
{

	/*
	 * Make 'rdataset' a valid, associated, question rdataset, with a
	 * question class of 'rdclass' and type 'type'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);

	rdataset->methods = &question_methods;
	rdataset->rdclass = rdclass;
	rdataset->type = type;
	rdataset->attributes |= DNS_RDATASETATTR_QUESTION;
}

void
dns_rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {

	/*
	 * Make 'target' refer to the same rdataset as 'source'.
	 */

	REQUIRE(DNS_RDATASET_VALID(source));
	REQUIRE(source->methods != NULL);
	REQUIRE(DNS_RDATASET_VALID(target));
	REQUIRE(target->methods == NULL);
	
	(source->methods->clone)(source, target);
}

dns_result_t
dns_rdataset_first(dns_rdataset_t *rdataset) {

	/*
	 * Move the rdata cursor to the first rdata in the rdataset (if any).
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	return ((rdataset->methods->first)(rdataset));
}

dns_result_t
dns_rdataset_next(dns_rdataset_t *rdataset) {

	/*
	 * Move the rdata cursor to the next rdata in the rdataset (if any).
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	return ((rdataset->methods->next)(rdataset));
}

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {

	/*
	 * Make 'rdata' refer to the current rdata.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	(rdataset->methods->current)(rdataset, rdata);
}

dns_result_t
dns_rdataset_towire(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    dns_compress_t *cctx,
		    isc_buffer_t *target,
		    unsigned int *countp)
{
	dns_rdata_t rdata;
	isc_region_t r;
	dns_result_t result;
	unsigned int count;
	isc_buffer_t st;
	isc_buffer_t rdlen;
	unsigned int headlen;
	isc_boolean_t question = ISC_FALSE;

	/*
	 * Convert 'rdataset' to wire format, compressing names as specified
	 * in cctx, and storing the result in 'target'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(countp != NULL);

	if ((rdataset->attributes & DNS_RDATASETATTR_QUESTION) != 0) {
		question = ISC_TRUE;
		result = dns_rdataset_first(rdataset);
		INSIST(result == DNS_R_NOMORE);
	} else {
		result = dns_rdataset_first(rdataset);
		if (result == DNS_R_NOMORE)
			return (DNS_R_SUCCESS);
		if (result != DNS_R_SUCCESS)
			return (result);
	}

	count = 0;
	do {
		/*
		 * copy out the name, type, class, ttl.
		 */
		if (dns_compress_getedns(cctx) >= 1)
			dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL);
		else
			dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);
		st = *target;
		result = dns_name_towire(owner_name, cctx, target);
		if (result != DNS_R_SUCCESS) {
			dns_compress_rollback(cctx, st.used);
			*countp += count;
			*target = st;
			return (result);
		}
		headlen = sizeof(dns_rdataclass_t) + sizeof(dns_rdatatype_t);
		if (!question)
			headlen += sizeof(dns_ttl_t)
				+ 2;  /* XXX 2 for rdata len */
		isc_buffer_available(target, &r);
		if (r.length < headlen) {
			dns_compress_rollback(cctx, st.used);
			*countp += count;
			*target = st;
			return (DNS_R_NOSPACE);
		}
		isc_buffer_putuint16(target, rdataset->type);
		isc_buffer_putuint16(target, rdataset->rdclass);
		if (!question) {
			isc_buffer_putuint32(target, rdataset->ttl);

			/*
			 * Save space for rdlen.
			 */
			rdlen = *target;
			isc_buffer_add(target, 2);

			/*
			 * copy out the rdata
			 */
			dns_rdataset_current(rdataset, &rdata);
			result = dns_compress_localinit(cctx, owner_name,
							target);
			if (result != DNS_R_SUCCESS) {
				dns_compress_rollback(cctx, st.used);
				*countp += count;
				*target = st;
				return (result);
			}
			result = dns_rdata_towire(&rdata, cctx, target);
			dns_compress_localinvalidate(cctx);
			if (result != DNS_R_SUCCESS) {
				dns_compress_rollback(cctx, st.used);
				*countp += count;
				*target = st;
				return (result);
			}
			isc_buffer_putuint16(&rdlen,
					     target->used - rdlen.used - 2);
		}

		count++;

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	*countp += count;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_rdataset_additionaldata(dns_rdataset_t *rdataset,
			    dns_additionaldatafunc_t add, void *arg)
{
	dns_rdata_t rdata;
	dns_result_t result;

	/*
	 * For each rdata in rdataset, call 'add' for each name and type in the
	 * rdata which is subject to additional section processing.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE((rdataset->attributes & DNS_RDATASETATTR_QUESTION) == 0);

	result = dns_rdataset_first(rdataset);
	if (result != DNS_R_SUCCESS)
		return (result);

	do {
		dns_rdataset_current(rdataset, &rdata);
		result = dns_rdata_additionaldata(&rdata, add, arg);
		if (result == DNS_R_SUCCESS)
			result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	return (DNS_R_SUCCESS);
}
