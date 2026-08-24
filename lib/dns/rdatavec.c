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

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <isc/ascii.h>
#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatavec.h>
#include <dns/stats.h>

#include "rdatavec_p.h"

/*
 * The memory structure of an rdatavec is as follows:
 *
 *	header		(dns_vecheader_t, including record count)
 *	data records
 *		data length	(2 bytes, big endian)
 *		meta data	(1 byte for RRSIG, 0 bytes for all other types)
 *		data		(data length bytes)
 *
 * A "bare" rdatavec is everything after the header. The data records are
 * stored sequentially in memory. Each record consists of a length field,
 * optional metadata, and the actual rdata bytes.
 *
 * The rdata format depends on the RR type and is defined by the type-specific
 * *_fromwire and *_towire functions (e.g., lib/dns/rdata/in_1/a_1.c for A
 * records). The data is typically stored in wire format.
 *
 * When a vec is created, data records are sorted into DNSSEC canonical order.
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
static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);

dns_rdatasetmethods_t dns_rdatavec_rdatasetmethods = {
	.disassociate = rdataset_disassociate,
	.first = rdataset_first,
	.next = rdataset_next,
	.current = rdataset_current,
	.clone = rdataset_clone,
	.count = rdataset_count,
	.settrust = rdataset_settrust,
	.expire = NULL,
	.clearprefetch = NULL,
	.getownercase = rdataset_getownercase,
};

/*% Note: the "const void *" are just to make qsort happy.  */
static int
compare_rdata(const void *p1, const void *p2) {
	return dns_rdata_compare(p1, p2);
}

static unsigned char *
newvec(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
       size_t size, uint16_t count) {
	dns_vecheader_t *header = isc_mem_get(mctx, size);

	*header = (dns_vecheader_t){
		.count = count,
		.next_header = ISC_SLINK_INITIALIZER,
		.typepair = DNS_TYPEPAIR_VALUE(rdataset->type,
					       rdataset->covers),
		.trust = rdataset->trust,
		.ttl = rdataset->ttl,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
	};

	region->base = (unsigned char *)header;
	region->length = size;

	return header->raw;
}

static isc_result_t
makevec(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	uint32_t maxrrperset) {
	dns_rdata_t *rdata = NULL;
	unsigned char *rawbuf = NULL;
	unsigned int headerlen = sizeof(dns_vecheader_t);
	uint32_t buflen = headerlen;
	isc_result_t result;
	unsigned int nitems;
	unsigned int nalloc;
	unsigned int length;
	size_t i;
	size_t rdatasize;

	/*
	 * If the source rdataset is also a vec, we don't need
	 * to do anything special, just copy the whole vec to a
	 * new buffer.
	 */
	if (rdataset->methods == &dns_rdatavec_rdatasetmethods) {
		dns_vecheader_t *header = dns_vecheader_getheader(rdataset);
		buflen = dns_rdatavec_size(header);

		rawbuf = newvec(rdataset, mctx, region, buflen, header->count);

		INSIST(headerlen <= buflen);
		memmove(rawbuf, header->raw, buflen - headerlen);
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
		(void)newvec(rdataset, mctx, region, buflen, 0);
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
	nitems = 0;

	/*
	 * Remove duplicates and compute the total storage required.
	 *
	 * If an rdata is not a duplicate, accumulate the storage size
	 * required for the rdata.  We do not store the class, type, etc,
	 * just the rdata, so our overhead is 2 bytes for the length of each
	 * rdata, plus the rdata itself.
	 */
	for (i = 0; i < nalloc; i++) {
		bool duplicate = i + 1 < nalloc &&
				 compare_rdata(&rdata[i], &rdata[i + 1]) == 0;

		if (duplicate) {
			continue;
		}

		buflen += sizeof(uint16_t) + rdata[i].length +
			  (rdataset->type == dns_rdatatype_rrsig);
		if (buflen - headerlen > DNS_RDATA_MAXLENGTH) {
			result = ISC_R_NOSPACE;
			goto free_rdatas;
		}

		rdata[nitems++] = rdata[i];
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
	rawbuf = newvec(rdataset, mctx, region, buflen, nitems);

	for (i = 0; i < nitems; i++) {
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
					    ? DNS_RDATAVEC_OFFLINE
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
dns_rdatavec_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			  isc_region_t *region, uint32_t maxrrperset) {
	if (rdataset->type == dns_rdatatype_none &&
	    rdataset->covers == dns_rdatatype_none)
	{
		return DNS_R_DISALLOWED;
	}

	INSIST(!rdataset->attributes.negative);
	INSIST(rdataset->type != dns_rdatatype_none);
	INSIST(dns_rdatatype_issig(rdataset->type) ||
	       rdataset->covers == dns_rdatatype_none);

	return makevec(rdataset, mctx, region, maxrrperset);
}

unsigned int
dns_rdatavec_size(dns_vecheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *current = header->raw;
	uint16_t count = header->count;

	while (count-- > 0) {
		uint16_t length = get_uint16(current);
		current += length;
	}

	return (unsigned int)(current - (unsigned char *)header);
}

unsigned int
dns_rdatavec_count(dns_vecheader_t *header) {
	REQUIRE(header != NULL);

	return header->count;
}

static void
rdata_to_vecitem(unsigned char **current, dns_rdatatype_t type,
		 dns_rdata_t *rdata) {
	unsigned int length = rdata->length;
	unsigned char *data = rdata->data;
	unsigned char *p = *current;

	if (type == dns_rdatatype_rrsig) {
		length++;
		data--;
	}

	put_uint16(p, length);
	memmove(p, data, length);
	p += length;

	*current = p;
}

typedef struct vecmerge_iter {
	rdatavec_iter_t left;
	rdatavec_iter_t right;
} vecmerge_iter_t;

static void
vecmerge_first(vecmerge_iter_t *iter, dns_vecheader_t *left,
	       dns_vecheader_t *right, dns_rdataclass_t rdclass) {
	(void)vecheader_first(&iter->left, left, rdclass);
	(void)vecheader_first(&iter->right, right, rdclass);
}

static bool
vecmerge_next(vecmerge_iter_t *iter, dns_rdata_t *rdata) {
	bool have_left = iter->left.iter_count > 0;
	bool have_right = iter->right.iter_count > 0;

	if (!have_left && !have_right) {
		return false;
	}

	dns_rdata_reset(rdata);

	if (!have_right) {
		vecheader_current(&iter->left, rdata);
		(void)vecheader_next(&iter->left);
	} else if (!have_left) {
		vecheader_current(&iter->right, rdata);
		(void)vecheader_next(&iter->right);
	} else {
		dns_rdata_t left = DNS_RDATA_INIT, right = DNS_RDATA_INIT;
		int cmp;

		vecheader_current(&iter->left, &left);
		vecheader_current(&iter->right, &right);

		cmp = dns_rdata_compare(&left, &right);
		*rdata = cmp <= 0 ? left : right;

		(void)vecheader_next(cmp <= 0 ? &iter->left : &iter->right);
		if (cmp == 0) {
			(void)vecheader_next(&iter->right);
		}
	}

	return true;
}

static bool
vecsubtract_next(vecmerge_iter_t *iter, dns_rdata_t *rdata) {
	while (iter->left.iter_count > 0) {
		dns_rdata_t left = DNS_RDATA_INIT, right = DNS_RDATA_INIT;
		bool have_right = iter->right.iter_count > 0;
		int cmp;

		vecheader_current(&iter->left, &left);
		if (have_right) {
			vecheader_current(&iter->right, &right);
		}

		cmp = have_right ? dns_rdata_compare(&left, &right) : -1;
		(void)vecheader_next(cmp <= 0 ? &iter->left : &iter->right);
		if (cmp == 0) {
			(void)vecheader_next(&iter->right);
		}

		if (cmp < 0) {
			dns_rdata_reset(rdata);
			*rdata = left;
			return true;
		}
	}

	return false;
}

isc_result_t
dns_rdatavec_merge(dns_vecheader_t *oheader, dns_vecheader_t *nheader,
		   isc_mem_t *mctx, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, unsigned int flags,
		   uint32_t maxrrperset, dns_vecheader_t **theaderp) {
	unsigned int ocount, ncount, tcount = 0;
	unsigned int ndup;
	size_t rlength = 0, tlength;
	vecmerge_iter_t iter;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && nheader != NULL);

	ocount = oheader->count;
	ncount = nheader->count;

	if (maxrrperset > 0 && ocount + ncount > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	vecmerge_first(&iter, oheader, nheader, rdclass);

	while (vecmerge_next(&iter, &rdata)) {
		rlength += sizeof(uint16_t) + rdata.length +
			   (type == dns_rdatatype_rrsig);
		tcount++;
	}
	ndup = ocount + ncount - tcount;

	if (rlength > DNS_RDATA_MAXLENGTH) {
		return ISC_R_NOSPACE;
	}

	/*
	 * If the EXACT flag is set, there can't be any rdata in
	 * the new vec that was also in the old.
	 */
	if (((flags & DNS_RDATAVEC_EXACT) != 0) && (ndup != 0)) {
		return DNS_R_NOTEXACT;
	}

	/*
	 * If nothing's being copied in from the new vec, and the
	 * FORCE flag isn't set, we're done.
	 */
	if (ndup == ncount && (flags & DNS_RDATAVEC_FORCE) == 0) {
		return DNS_R_UNCHANGED;
	}

	/* Single types can't have more than one RR. */
	if (tcount > 1 && dns_rdatatype_issingleton(type)) {
		return DNS_R_SINGLETON;
	}

	if (tcount > 0xffff) {
		return ISC_R_NOSPACE;
	}

	tlength = sizeof(*oheader) + rlength;

	/*
	 * Allocate the target buffer and initialize the header.
	 * Preserve the case of the old header, but the rest from the
	 * new header.
	 */
	dns_vecheader_t *theader = isc_mem_get(mctx, tlength);
	uint16_t attrs = DNS_VECHEADER_GETATTR(
		oheader,
		DNS_VECHEADERATTR_CASESET | DNS_VECHEADERATTR_CASEFULLYLOWER);
	if (RESIGN(nheader)) {
		attrs |= DNS_VECHEADERATTR_RESIGN;
	}
	*theader = (dns_vecheader_t){
		.count = tcount,
		.typepair = nheader->typepair,
		.mctx = isc_mem_ref(mctx),
		.serial = nheader->serial,
		.ttl = nheader->ttl,
		.resign = nheader->resign,
		.next_header = ISC_SLINK_INITIALIZER,
	};
	isc_refcount_init(&theader->references, 1);
	atomic_init(&theader->attributes, attrs);
	atomic_init(&theader->trust, atomic_load_acquire(&nheader->trust));
	memmove(theader->upper, oheader->upper, sizeof(oheader->upper));

	unsigned char *tcurrent = theader->raw;

	/*
	 * Now walk the sets together, adding each item in DNSSEC order,
	 * and skipping over any more dups in the new vec.
	 */
	vecmerge_first(&iter, oheader, nheader, rdclass);

	while (vecmerge_next(&iter, &rdata)) {
		rdata_to_vecitem(&tcurrent, type, &rdata);
	}

	INSIST(tcurrent == (unsigned char *)theader + tlength);

	*theaderp = theader;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_rdatavec_subtract(dns_vecheader_t *oheader, dns_vecheader_t *sheader,
		      isc_mem_t *mctx, dns_rdataclass_t rdclass,
		      dns_rdatatype_t type, unsigned int flags,
		      dns_vecheader_t **theaderp) {
	unsigned int ocount, scount;
	unsigned int tcount = 0, rcount;
	size_t rlength = 0, tlength;
	vecmerge_iter_t iter;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && sheader != NULL);

	ocount = oheader->count;
	scount = sheader->count;

	vecmerge_first(&iter, oheader, sheader, rdclass);

	while (vecsubtract_next(&iter, &rdata)) {
		rlength += sizeof(uint16_t) + rdata.length +
			   (type == dns_rdatatype_rrsig);
		tcount++;
	}
	rcount = ocount - tcount;

	if (rlength > DNS_RDATA_MAXLENGTH) {
		return ISC_R_NOSPACE;
	}

	/*
	 * If the EXACT flag was set, check that all the records that
	 * were to be subtracted actually did exist in the original vec.
	 * (The numeric check works here because rdatavecs do not contain
	 * duplicates.)
	 */
	if ((flags & DNS_RDATAVEC_EXACT) != 0 && rcount != scount) {
		return DNS_R_NOTEXACT;
	}

	/*
	 * If the resulting rdatavec would be empty, don't bother to
	 * create a new buffer, just return.
	 */
	if (tcount == 0) {
		return DNS_R_NXRRSET;
	}

	/*
	 * If nothing is going to change, stop.
	 */
	if (rcount == 0) {
		return DNS_R_UNCHANGED;
	}

	tlength = sizeof(*oheader) + rlength;

	/*
	 * Allocate the target buffer and copy the old vec's header.
	 */
	dns_vecheader_t *theader = isc_mem_get(mctx, tlength);
	uint16_t attrs = RESIGN(oheader) ? DNS_VECHEADERATTR_RESIGN : 0;
	*theader = (dns_vecheader_t){
		.count = tcount,
		.typepair = oheader->typepair,
		.mctx = isc_mem_ref(mctx),
		.serial = oheader->serial,
		.ttl = oheader->ttl,
		.resign = oheader->resign,
		.next_header = ISC_SLINK_INITIALIZER,
	};
	isc_refcount_init(&theader->references, 1);
	atomic_init(&theader->attributes, attrs);
	atomic_init(&theader->trust, atomic_load_acquire(&oheader->trust));
	memmove(theader->upper, oheader->upper, sizeof(oheader->upper));

	unsigned char *tcurrent = theader->raw;

	/*
	 * Copy the parts of the old vec that didn't have duplicates.
	 */
	vecmerge_first(&iter, oheader, sheader, rdclass);

	while (vecsubtract_next(&iter, &rdata)) {
		rdata_to_vecitem(&tcurrent, type, &rdata);
	}

	INSIST(tcurrent == (unsigned char *)theader + tlength);

	*theaderp = theader;

	return ISC_R_SUCCESS;
}

void
dns_vecheader_setownercase(dns_vecheader_t *header, const dns_name_t *name) {
	REQUIRE(!CASESET(header));

	bool casefullylower = true;

	/*
	 * We do not need to worry about label lengths as they are all
	 * less than or equal to 63.
	 */
	memset(header->upper, 0, sizeof(header->upper));
	for (size_t i = 0; i < name->length; i++) {
		if (isupper(name->ndata[i])) {
			header->upper[i / 8] |= 1 << (i % 8);
			casefullylower = false;
		}
	}
	if (casefullylower) {
		DNS_VECHEADER_SETATTR(header, DNS_VECHEADERATTR_CASEFULLYLOWER);
	}
	DNS_VECHEADER_SETATTR(header, DNS_VECHEADERATTR_CASESET);
}

dns_vecheader_t *
dns_vecheader_new(isc_mem_t *mctx) {
	dns_vecheader_t *h = isc_mem_get(mctx, sizeof(*h));
	*h = (dns_vecheader_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
	};
	return h;
}

/* Iterators for already bound rdatavec */

isc_result_t
vecheader_first(rdatavec_iter_t *iter, dns_vecheader_t *header,
		dns_rdataclass_t rdclass) {
	uint16_t count = header->count;

	*iter = (rdatavec_iter_t){
		.iter_pos = count == 0 ? NULL : header->raw,
		.iter_count = count,
		.iter_rdclass = rdclass,
		.iter_type = DNS_TYPEPAIR_TYPE(header->typepair),
	};

	return count == 0 ? ISC_R_NOMORE : ISC_R_SUCCESS;
}

isc_result_t
vecheader_next(rdatavec_iter_t *iter) {
	unsigned int count = iter->iter_count;
	if (count <= 1) {
		iter->iter_pos = NULL;
		iter->iter_count = 0;
		return ISC_R_NOMORE;
	}
	iter->iter_count = count - 1;

	unsigned char *raw = iter->iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	iter->iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

void
vecheader_current(rdatavec_iter_t *iter, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = iter->iter_pos;
	REQUIRE(raw != NULL);

	length = get_uint16(raw);

	if (iter->iter_type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATAVEC_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, iter->iter_rdclass, iter->iter_type, &r);
	rdata->flags |= flags;
}

/* Fixed RRSet helper macros */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_vecheader_unref(rdataset->vec.header);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	return vecheader_first(&rdataset->vec.iter, rdataset->vec.header,
			       rdataset->rdclass);
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	return vecheader_next(&rdataset->vec.iter);
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	vecheader_current(&rdataset->vec.iter, rdata);
}

static void
rdataset_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG) {
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);

	target->vec.iter.iter_pos = NULL;
	target->vec.iter.iter_count = 0;

	dns_vecheader_ref(target->vec.header);
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	return rdataset->vec.header->count;
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_vecheader_t *header = dns_vecheader_getheader(rdataset);

	rdataset->trust = trust;
	atomic_store_release(&header->trust, trust);
}

static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name) {
	dns_vecheader_t *header = dns_vecheader_getheader(rdataset);
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

dns_vecheader_t *
dns_vecheader_getheader(const dns_rdataset_t *rdataset) {
	return rdataset->vec.header;
}

dns_vecheader_t *
dns_vecheader_moveheader(dns_rdataset_t *rdataset) {
	dns_vecheader_t *header = MOVE_OWNERSHIP(rdataset->vec.header);
	/*
	 * We stole the header, it is safe to reset the rdataset.
	 */
	dns_rdataset_init(rdataset);
	return header;
}

dns_vectop_t *
dns_vectop_new(isc_mem_t *mctx, dns_typepair_t typepair) {
	dns_vectop_t *top = isc_mem_get(mctx, sizeof(*top));
	*top = (dns_vectop_t){
		.next_type = ISC_SLINK_INITIALIZER,
		.headers = ISC_SLIST_INITIALIZER,
		.typepair = typepair,
	};

	return top;
}

void
dns_vectop_destroy(isc_mem_t *mctx, dns_vectop_t **topp) {
	REQUIRE(topp != NULL && *topp != NULL);
	dns_vectop_t *top = *topp;
	*topp = NULL;
	isc_mem_put(mctx, top, sizeof(*top));
}

static void
vecheader_destroy(dns_vecheader_t *header) {
	isc_mem_putanddetach(&header->mctx, header, dns_rdatavec_size(header));
}

/*
 * Reference counting implementation for dns_vecheader_t
 */
ISC_REFCOUNT_IMPL(dns_vecheader, vecheader_destroy);
