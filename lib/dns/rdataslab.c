/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/ascii.h>
#include <isc/atomic.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>
#include <dns/stats.h>

#include "rdataslab_p.h"

/*
 * The memory structure of an rdataslab is as follows:
 *
 *	header		(dns_slabheader_t)
 *	record count	(2 bytes)
 *	data records
 *		data length	(2 bytes)
 *		order		(2 bytes)
 *		meta data	(1 byte for RRSIG, 0 for all other types)
 *		data		(data length bytes)
 *
 * A "bare" rdataslab is everything after "header".
 *
 * When a slab is created, data records are sorted into DNSSEC order.
 */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
static isc_result_t
rdataset_first(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_next(dns_rdataset_t *rdataset);
static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
rdataset_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG);
static unsigned int
rdataset_count(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig DNS__DB_FLARG);
static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig DNS__DB_FLARG);
static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG);
static void
rdataset_clearprefetch(dns_rdataset_t *rdataset);
static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);
static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset);

dns_rdatasetmethods_t dns_rdataslab_rdatasetmethods = {
	.disassociate = rdataset_disassociate,
	.first = rdataset_first,
	.next = rdataset_next,
	.current = rdataset_current,
	.clone = rdataset_clone,
	.count = rdataset_count,
	.getnoqname = rdataset_getnoqname,
	.getclosest = rdataset_getclosest,
	.settrust = rdataset_settrust,
	.expire = rdataset_expire,
	.clearprefetch = rdataset_clearprefetch,
	.getownercase = rdataset_getownercase,
};

static void
slabheader_proof_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
static isc_result_t
slabheader_proof_first(dns_rdataset_t *rdataset);
static isc_result_t
slabheader_proof_next(dns_rdataset_t *rdataset);
static void
slabheader_proof_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
slabheader_proof_clone(const dns_rdataset_t *source,
		       dns_rdataset_t *target DNS__DB_FLARG);
static unsigned int
slabheader_proof_count(dns_rdataset_t *rdataset);
static dns_slabheader_t *
slabheader_proof_getheader(const dns_rdataset_t *rdataset);

dns_rdatasetmethods_t dns_rdataslab_proof_rdatasetmethods = {
	.disassociate = slabheader_proof_disassociate,
	.first = slabheader_proof_first,
	.next = slabheader_proof_next,
	.current = slabheader_proof_current,
	.clone = slabheader_proof_clone,
	.count = slabheader_proof_count,
	.getnoqname = NULL,
	.getclosest = NULL,
	.settrust = NULL,
	.expire = NULL,
	.clearprefetch = NULL,
	.getownercase = NULL,
};

/*% Note: the "const void *" are just to make qsort happy.  */
static int
compare_rdata(const void *p1, const void *p2) {
	return dns_rdata_compare(p1, p2);
}

static unsigned char *
newslab(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	uint16_t nitems, size_t size, const char *func, const char *file,
	const unsigned int line) {
	dns_slabheader_t *header = isc_mem_get(mctx, size);

	*header = (dns_slabheader_t){
		.headers_link = CDS_LIST_HEAD_INIT(header->headers_link),
		.trust = rdataset->trust,
		.nitems = nitems,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
		.lrulink = ISC_LINK_INITIALIZER,
	};

#if DNS_SLABHEADER_TRACE
	fprintf(stderr,
		"%s:%s:%s:%u:t%" PRItid ":%p->references = %" PRIuFAST32 "\n",
		__func__, func, file, line, isc_tid(), header,
		header->references);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif

	region->base = (unsigned char *)header;
	region->length = size;

	return (unsigned char *)header + sizeof(*header);
}

static isc_result_t
makeslab(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	 uint32_t maxrrperset, const char *func, const char *file,
	 const unsigned int line) {
	/*
	 * Use &removed as a sentinel pointer for duplicate
	 * rdata as rdata.data == NULL is valid.
	 */
	static unsigned char removed;
	dns_rdata_t *rdata = NULL;
	unsigned char *rawbuf = NULL;
	unsigned int headerlen = sizeof(dns_slabheader_t);
	uint32_t buflen = headerlen;
	isc_result_t result;
	unsigned int nitems;
	unsigned int nalloc;
	unsigned int length;
	size_t i;
	size_t rdatasize;

	/*
	 * If the source rdataset is also a slab, we don't need
	 * to do anything special, just copy the whole slab to a
	 * new buffer.
	 */
	if (rdataset->methods == &dns_rdataslab_rdatasetmethods) {
		dns_slabheader_t *header = rdataset_getheader(rdataset);
		buflen = dns_rdataslab_size(header);

		rawbuf = newslab(rdataset, mctx, region, header->nitems, buflen,
				 func, file, line);

		INSIST(headerlen <= buflen);
		memmove(rawbuf, (unsigned char *)header + headerlen,
			buflen - headerlen);
		return ISC_R_SUCCESS;
	}

	/*
	 * If there are no rdata then we just need to allocate a header
	 * with a zero record count.
	 */
	nitems = dns_rdataset_count(rdataset);
	if (nitems == 0) {
		if (rdataset->type != 0) {
			return ISC_R_FAILURE;
		}
		(void)newslab(rdataset, mctx, region, 0, buflen, func, file,
			      line);
		return ISC_R_SUCCESS;
	}

	if (maxrrperset > 0 && nitems > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	if (nitems > 0xffff) {
		return ISC_R_NOSPACE;
	}

	/*
	 * Remember the original number of items.
	 */
	nalloc = nitems;

	RUNTIME_CHECK(!ckd_mul(&rdatasize, nalloc, sizeof(rdata[0])));
	rdata = isc_mem_get(mctx, rdatasize);

	/*
	 * Save all of the rdata members into an array.
	 */
	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOMORE) {
		goto free_rdatas;
	}
	for (i = 0; i < nalloc && result == ISC_R_SUCCESS; i++) {
		INSIST(result == ISC_R_SUCCESS);
		dns_rdata_init(&rdata[i]);
		dns_rdataset_current(rdataset, &rdata[i]);
		INSIST(rdata[i].data != &removed);
		result = dns_rdataset_next(rdataset);
	}
	if (i != nalloc || result != ISC_R_NOMORE) {
		/*
		 * Somehow we iterated over fewer rdatas than
		 * dns_rdataset_count() said there were or there
		 * were more items than dns_rdataset_count said
		 * there were.
		 */
		result = ISC_R_FAILURE;
		goto free_rdatas;
	}

	/*
	 * Put into DNSSEC order.
	 */
	if (nalloc > 1U) {
		qsort(rdata, nalloc, sizeof(rdata[0]), compare_rdata);
	}

	/*
	 * Remove duplicates and compute the total storage required.
	 *
	 * If an rdata is not a duplicate, accumulate the storage size
	 * required for the rdata.  We do not store the class, type, etc,
	 * just the rdata, so our overhead is 2 bytes for the number of
	 * records, and 2 bytes for the length of each rdata, plus the
	 * rdata itself.
	 */
	for (i = 1; i < nalloc; i++) {
		if (compare_rdata(&rdata[i - 1], &rdata[i]) == 0) {
			rdata[i - 1].data = &removed;
			nitems--;
		} else {
			buflen += 2 + rdata[i - 1].length;
			/*
			 * Provide space to store the per RR meta data.
			 */
			if (rdataset->type == dns_rdatatype_rrsig) {
				buflen++;
			}
			if (buflen - headerlen > DNS_RDATA_MAXLENGTH) {
				result = ISC_R_NOSPACE;
				goto free_rdatas;
			}
		}
	}

	/*
	 * Don't forget the last item!
	 */
	buflen += 2 + rdata[i - 1].length;

	/*
	 * Provide space to store the per RR meta data.
	 */
	if (rdataset->type == dns_rdatatype_rrsig) {
		buflen++;
	}
	if (buflen - headerlen > DNS_RDATA_MAXLENGTH) {
		result = ISC_R_NOSPACE;
		goto free_rdatas;
	}

	/*
	 * Ensure that singleton types are actually singletons.
	 */
	if (nitems > 1 && dns_rdatatype_issingleton(rdataset->type)) {
		/*
		 * We have a singleton type, but there's more than one
		 * RR in the rdataset.
		 */
		result = DNS_R_SINGLETON;
		goto free_rdatas;
	}

	/*
	 * Allocate the memory, set up a buffer, start copying in
	 * data.
	 */
	rawbuf = newslab(rdataset, mctx, region, nitems, buflen, func, file,
			 line);

	for (i = 0; i < nalloc; i++) {
		if (rdata[i].data == &removed) {
			continue;
		}
		length = rdata[i].length;
		if (rdataset->type == dns_rdatatype_rrsig) {
			length++;
		}
		INSIST(length <= 0xffff);

		put_uint16(rawbuf, length);

		/*
		 * Store the per RR meta data.
		 */
		if (rdataset->type == dns_rdatatype_rrsig) {
			*rawbuf++ = (rdata[i].flags & DNS_RDATA_OFFLINE)
					    ? DNS_RDATASLAB_OFFLINE
					    : 0;
		}
		if (rdata[i].length != 0) {
			memmove(rawbuf, rdata[i].data, rdata[i].length);
		}
		rawbuf += rdata[i].length;
	}

	result = ISC_R_SUCCESS;

free_rdatas:
	isc_mem_put(mctx, rdata, rdatasize);
	return result;
}

isc_result_t
dns_rdataslab__fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			    isc_region_t *region, uint32_t maxrrperset,
			    const char *func, const char *file,
			    const unsigned int line) {
	if (rdataset->type == dns_rdatatype_none &&
	    rdataset->covers == dns_rdatatype_none)
	{
		return DNS_R_DISALLOWED;
	}

	isc_result_t result = makeslab(rdataset, mctx, region, maxrrperset,
				       func, file, line);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_slabheader_t *header = (dns_slabheader_t *)region->base;
	if (rdataset->attributes.negative) {
		INSIST(rdataset->type == dns_rdatatype_none);
		INSIST(rdataset->covers != dns_rdatatype_none);
		header->typepair = DNS_TYPEPAIR_VALUE(rdataset->covers,
						      dns_rdatatype_none);
	} else {
		INSIST(rdataset->type != dns_rdatatype_none);
		INSIST(dns_rdatatype_issig(rdataset->type) ||
		       rdataset->covers == dns_rdatatype_none);
		header->typepair = DNS_TYPEPAIR_VALUE(rdataset->type,
						      rdataset->covers);
	}

	return ISC_R_SUCCESS;
}

unsigned int
dns_rdataslab_size(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *slab = (unsigned char *)header +
			      sizeof(dns_slabheader_t);
	INSIST(slab != NULL);

	unsigned char *current = slab;
	uint16_t count = header->nitems;

	while (count-- > 0) {
		uint16_t length = get_uint16(current);
		current += length;
	}

	return (unsigned int)(current - slab) + sizeof(dns_slabheader_t);
}

unsigned int
dns_rdataslab_count(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	return header->nitems;
}

/*
 * Make the dns_rdata_t 'rdata' refer to the slab item
 * beginning at '*current' (which is part of a slab of type
 * 'type' and class 'rdclass') and advance '*current' to
 * point to the next item in the slab.
 */
static void
rdata_from_slabitem(unsigned char **current, dns_rdataclass_t rdclass,
		    dns_rdatatype_t type, dns_rdata_t *rdata) {
	unsigned char *tcurrent = *current;
	isc_region_t region;
	bool offline = false;
	uint16_t length = get_uint16(tcurrent);

	if (type == dns_rdatatype_rrsig) {
		if ((*tcurrent & DNS_RDATASLAB_OFFLINE) != 0) {
			offline = true;
		}
		length--;
		tcurrent++;
	}
	region.length = length;
	region.base = tcurrent;
	tcurrent += region.length;
	dns_rdata_fromregion(rdata, rdclass, type, &region);
	if (offline) {
		rdata->flags |= DNS_RDATA_OFFLINE;
	}
	*current = tcurrent;
}

bool
dns_rdataslab_equal(dns_slabheader_t *slab1, dns_slabheader_t *slab2) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = slab1->nitems;

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = slab2->nitems;

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		unsigned int length1 = get_uint16(current1);
		unsigned int length2 = get_uint16(current2);

		if (length1 != length2 ||
		    memcmp(current1, current2, length1) != 0)
		{
			return false;
		}

		current1 += length1;
		current2 += length1;
	}
	return true;
}

bool
dns_rdataslab_equalx(dns_slabheader_t *slab1, dns_slabheader_t *slab2,
		     dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = slab1->nitems;

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = slab2->nitems;

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		dns_rdata_t rdata1 = DNS_RDATA_INIT;
		dns_rdata_t rdata2 = DNS_RDATA_INIT;

		rdata_from_slabitem(&current1, rdclass, type, &rdata1);
		rdata_from_slabitem(&current2, rdclass, type, &rdata2);
		if (dns_rdata_compare(&rdata1, &rdata2) != 0) {
			return false;
		}
	}
	return true;
}

void
dns_slabheader__reset(dns_slabheader_t *h, dns_dbnode_t *node, const char *func,
		      const char *file, const unsigned int line) {
	h->node = node;

	atomic_init(&h->attributes, 0);
	atomic_init(&h->last_refresh_fail_ts, 0);
	isc_refcount_init(&h->references, 1);

	STATIC_ASSERT(sizeof(h->attributes) == 2,
		      "The .attributes field of dns_slabheader_t needs to be "
		      "16-bit int type exactly.");

#if DNS_SLABHEADER_TRACE
	fprintf(stderr,
		"%s:%s:%s:%u:t%" PRItid ":%p->references = %" PRIuFAST32 "\n",
		__func__, func, file, line, isc_tid(), h, h->references);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif
}

dns_slabheader_t *
dns_slabheader__new(isc_mem_t *mctx, dns_dbnode_t *node, const char *func,
		    const char *file, const unsigned int line) {
	dns_slabheader_t *h = NULL;

	h = isc_mem_get(mctx, sizeof(*h));
	*h = (dns_slabheader_t){
		.headers_link = CDS_LIST_HEAD_INIT(h->headers_link),
		.node = node,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
		.lrulink = ISC_LINK_INITIALIZER,
	};

#if DNS_SLABHEADER_TRACE
	fprintf(stderr,
		"%s:%s:%s:%u:t%" PRItid ":%p->references = %" PRIuFAST32 "\n",
		__func__, func, file, line, isc_tid(), h, h->references);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif

	return h;
}

static void
slabheader_destroy(dns_slabheader_t *header) {
	unsigned int size;

	if (EXISTS(header)) {
		size = dns_rdataslab_size(header);
	} else {
		size = sizeof(*header);
	}

	if (header->noqname != NULL) {
		dns_slabheader_freeproof(header->mctx, &header->noqname);
	}
	if (header->closest != NULL) {
		dns_slabheader_freeproof(header->mctx, &header->closest);
	}

	isc_mem_putanddetach(&header->mctx, header, size);
}

void
dns_slabheader_freeproof(isc_mem_t *mctx, dns_slabheader_proof_t **proofp) {
	dns_slabheader_proof_t *proof = *proofp;
	*proofp = NULL;

	if (dns_name_dynamic(&proof->name)) {
		dns_name_free(&proof->name, mctx);
	}
	if (proof->neg != NULL) {
		dns_slabheader_t *header =
			(dns_slabheader_t *)((uint8_t *)proof->neg -
					     sizeof(dns_slabheader_t));
		dns_slabheader_detach(&header);
	}
	if (proof->negsig != NULL) {
		dns_slabheader_t *header =
			(dns_slabheader_t *)((uint8_t *)proof->negsig -
					     sizeof(dns_slabheader_t));
		dns_slabheader_detach(&header);
	}
	isc_mem_put(mctx, proof, sizeof(*proof));
}

#if DNS_SLABHEADER_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_slabheader, slabheader_destroy);
#else
ISC_REFCOUNT_IMPL(dns_slabheader, slabheader_destroy);
#endif

/* Fixed RRSet helper macros */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	dns_slabheader_detach(&header);

	dns__db_detachnode(&rdataset->slab.node DNS__DB_FLARG_PASS);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	unsigned char *raw = rdataset->slab.raw;
	uint16_t count = header->nitems;

	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		rdataset->slab.iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	rdataset->slab.iter_pos = raw;
	rdataset->slab.iter_count = count - 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	uint16_t count = rdataset->slab.iter_count;
	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->slab.iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	unsigned char *raw = rdataset->slab.iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	rdataset->slab.iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = rdataset->slab.iter_pos;
	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
	length = get_uint16(raw);

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
rdataset_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(source);

	INSIST(target->slab.node == NULL);
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);
	target->slab.node = NULL;
	dns__db_attachnode(source->slab.node,
			   &target->slab.node DNS__DB_FLARG_PASS);

	target->slab.iter_pos = NULL;
	target->slab.iter_count = 0;

	dns_slabheader_ref(header);
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	return header->nitems;
}

static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec,
		    dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->slab.node;
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	const dns_slabheader_proof_t *noqname = rdataset->slab.noqname;

	/*
	 * Normally, rdataset->slab.raw points to the data immediately
	 * following a dns_slabheader in memory. Here, though, it will
	 * point to a bare rdataslab, a pointer to which is stored in
	 * the dns_slabheader's `noqname` field.
	 *
	 * The 'keepcase' attribute is set to prevent setownercase and
	 * getownercase methods from affecting the case of NSEC/NSEC3
	 * owner names.
	 */
	*nsec = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = noqname->neg,
		.link = nsec->link,
		.attributes = nsec->attributes,
		.magic = nsec->magic,
	};
	nsec->attributes.keepcase = true;
	dns__db_attachnode(node, &nsec->proof.node DNS__DB_FLARG_PASS);

	*nsecsig = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = dns_rdatatype_rrsig,
		.covers = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = noqname->negsig,
		.link = nsecsig->link,
		.attributes = nsecsig->attributes,
		.magic = nsecsig->magic,
	};
	nsecsig->attributes.keepcase = true;
	dns__db_attachnode(node, &nsecsig->proof.node DNS__DB_FLARG_PASS);

	dns_name_clone(&noqname->name, name);

	return ISC_R_SUCCESS;
}

static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec,
		    dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->slab.node;
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	const dns_slabheader_proof_t *closest = rdataset->slab.closest;

	/*
	 * Normally, rdataset->slab.raw points to the data immediately
	 * following a dns_slabheader in memory. Here, though, it will
	 * point to a bare rdataslab, a pointer to which is stored in
	 * the dns_slabheader's `closest` field.
	 *
	 * The 'keepcase' attribute is set to prevent setownercase and
	 * getownercase methods from affecting the case of NSEC/NSEC3
	 * owner names.
	 */
	*nsec = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = closest->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = closest->neg,
		.link = nsec->link,
		.attributes = nsec->attributes,
		.magic = nsec->magic,
	};
	nsec->attributes.keepcase = true;
	dns__db_attachnode(node, &nsec->proof.node DNS__DB_FLARG_PASS);

	*nsecsig = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = dns_rdatatype_rrsig,
		.covers = closest->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = closest->negsig,
		.link = nsecsig->link,
		.attributes = nsecsig->attributes,
		.magic = nsecsig->magic,
	};
	nsecsig->attributes.keepcase = true;
	dns__db_attachnode(node, &nsecsig->proof.node DNS__DB_FLARG_PASS);

	dns_name_clone(&closest->name, name);

	return ISC_R_SUCCESS;
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	rdataset->trust = trust;
	atomic_store_release(&header->trust, trust);
}

static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	dns_db_expiredata(rdataset->slab.node, header);
}

static void
rdataset_clearprefetch(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_PREFETCH);
}

static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	uint8_t mask = (1 << 7);
	uint8_t bits = 0;

	if (!CASESET(header)) {
		return;
	}

	if (CASEFULLYLOWER(header)) {
		isc_ascii_lowercopy(name->ndata, name->ndata, name->length);
		return;
	}

	uint8_t *nd = name->ndata;
	for (size_t i = 0; i < name->length; i++) {
		if (mask == (1 << 7)) {
			bits = header->upper[i / 8];
			mask = 1;
		} else {
			mask <<= 1;
		}
		nd[i] = (bits & mask) ? isc_ascii_toupper(nd[i])
				      : isc_ascii_tolower(nd[i]);
	}
}

static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset) {
	uint8_t *rawbuf = rdataset->slab.raw;
	return (dns_slabheader_t *)(rawbuf - offsetof(dns_slabheader_t, raw));
}

/* Fixed Proof helper macros */

static void
slabheader_proof_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_detach(&rdataset->proof.header);
	dns__db_detachnode(&rdataset->proof.node DNS__DB_FLARG_PASS);
}

static isc_result_t
slabheader_proof_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->proof.raw;
	uint16_t count = slabheader_proof_count(rdataset);

	if (count == 0) {
		rdataset->proof.iter_pos = NULL;
		rdataset->proof.iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	rdataset->proof.iter_pos = raw;
	rdataset->proof.iter_count = count - 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
slabheader_proof_next(dns_rdataset_t *rdataset) {
	uint16_t count = rdataset->proof.iter_count;
	if (count == 0) {
		rdataset->proof.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->proof.iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	unsigned char *raw = rdataset->proof.iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	rdataset->proof.iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

static void
slabheader_proof_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = rdataset->proof.iter_pos;
	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
	length = get_uint16(raw);

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
slabheader_proof_clone(const dns_rdataset_t *source,
		       dns_rdataset_t *target DNS__DB_FLARG) {
	INSIST(!ISC_LINK_LINKED(target, link));
	INSIST(target->proof.node == NULL);
	INSIST(target->proof.header == NULL);

	*target = *source;

	ISC_LINK_INIT(target, link);
	target->proof.node = NULL;
	dns__db_attachnode(source->proof.node,
			   &target->proof.node DNS__DB_FLARG_PASS);
	dns_slabheader_ref(target->proof.header);

	target->proof.iter_pos = NULL;
	target->proof.iter_count = 0;
}

static unsigned int
slabheader_proof_count(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = slabheader_proof_getheader(rdataset);

	return header->nitems;
}

static dns_slabheader_t *
slabheader_proof_getheader(const dns_rdataset_t *rdataset) {
	uint8_t *rawbuf = rdataset->proof.raw;
	return (dns_slabheader_t *)(rawbuf - offsetof(dns_slabheader_t, raw));
}
