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
 *	header		(dns_vecheader_t)
 *	record count	(2 bytes, big endian)
 *	data records
 *		data length	(2 bytes, big endian)
 *		meta data	(1 byte for RRSIG, 0 bytes for all other types)
 *		data		(data length bytes)
 *
 * A "bare" rdatavec is everything after the header. The first two bytes
 * contain the count of rdata records in the rdatavec. For records with
 * the DNS_VECHEADERATTR_NONEXISTENT attribute, the record count is omitted
 * entirely.
 *
 * After the count, the rdata records are stored sequentially in memory.
 * Each record consists of a length field, optional metadata, and the actual
 * rdata bytes.
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

static size_t
header_size(const dns_vecheader_t *header) {
	UNUSED(header);
	return sizeof(dns_vecheader_t);
}

static unsigned char *
rdatavec_raw(dns_vecheader_t *header) {
	unsigned char *as_char_star = (unsigned char *)header;
	unsigned char *raw = as_char_star + header_size(header);

	return raw;
}

static unsigned char *
rdatavec_data(dns_vecheader_t *header) {
	return rdatavec_raw(header) + 2;
}

static unsigned int
rdatavec_count(dns_vecheader_t *header) {
	unsigned char *raw = rdatavec_raw(header);
	unsigned int count = get_uint16(raw);

	return count;
}

static unsigned char *
newvec(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
       size_t size) {
	dns_vecheader_t *header = isc_mem_get(mctx, size);

	*header = (dns_vecheader_t){
		.next_header = ISC_SLINK_INITIALIZER,
		.trust = rdataset->trust,
		.ttl = rdataset->ttl,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
	};

	region->base = (unsigned char *)header;
	region->length = size;

	return (unsigned char *)header + sizeof(*header);
}

static isc_result_t
makevec(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	uint32_t maxrrperset) {
	/*
	 * Use &removed as a sentinel pointer for duplicate
	 * rdata as rdata.data == NULL is valid.
	 */
	static unsigned char removed;
	dns_rdata_t *rdata = NULL;
	unsigned char *rawbuf = NULL;
	unsigned int headerlen = sizeof(dns_vecheader_t);
	uint32_t buflen = headerlen + 2;
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

		rawbuf = newvec(rdataset, mctx, region, buflen);

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
		rawbuf = newvec(rdataset, mctx, region, buflen);
		put_uint16(rawbuf, 0);
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
			if (buflen - headerlen - 2 > DNS_RDATA_MAXLENGTH) {
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
	if (buflen - headerlen - 2 > DNS_RDATA_MAXLENGTH) {
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
	rawbuf = newvec(rdataset, mctx, region, buflen);
	put_uint16(rawbuf, nitems);

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
	isc_result_t result;

	if (rdataset->type == dns_rdatatype_none &&
	    rdataset->covers == dns_rdatatype_none)
	{
		return DNS_R_DISALLOWED;
	}

	result = makevec(rdataset, mctx, region, maxrrperset);
	if (result == ISC_R_SUCCESS) {
		dns_vecheader_t *new = (dns_vecheader_t *)region->base;
		dns_typepair_t typepair;

		if (rdataset->attributes.negative) {
			INSIST(rdataset->type == dns_rdatatype_none);
			INSIST(rdataset->covers != dns_rdatatype_none);
			typepair = DNS_TYPEPAIR_VALUE(rdataset->covers,
						      dns_rdatatype_none);
		} else {
			INSIST(rdataset->type != dns_rdatatype_none);
			INSIST(dns_rdatatype_issig(rdataset->type) ||
			       rdataset->covers == dns_rdatatype_none);
			typepair = DNS_TYPEPAIR_VALUE(rdataset->type,
						      rdataset->covers);
		}

		/*
		 * Reset the vecheader content, but keep the refcount and mctx.
		 */
		*new = (dns_vecheader_t){
			.next_header = ISC_SLINK_INITIALIZER,
			.typepair = typepair,
			.trust = rdataset->trust,
			.ttl = rdataset->ttl,
			.references = atomic_load_acquire(&new->references),
			.mctx = new->mctx,
		};
	}

	return result;
}

unsigned int
dns_rdatavec_size(dns_vecheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *vec = rdatavec_raw(header);
	INSIST(vec != NULL);

	unsigned char *current = rdatavec_data(header);
	uint16_t count = rdatavec_count(header);

	while (count-- > 0) {
		uint16_t length = get_uint16(current);
		current += length;
	}

	return (unsigned int)(current - vec) + header_size(header);
}

unsigned int
dns_rdatavec_count(dns_vecheader_t *header) {
	REQUIRE(header != NULL);

	return rdatavec_count(header);
}

/*
 * Make the dns_rdata_t 'rdata' refer to the vec item
 * beginning at '*current' (which is part of a vec of type
 * 'type' and class 'rdclass') and advance '*current' to
 * point to the next item in the vec.
 */
static void
rdata_from_vecitem(unsigned char **current, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, dns_rdata_t *rdata) {
	unsigned char *tcurrent = *current;
	isc_region_t region;
	bool offline = false;
	uint16_t length = get_uint16(tcurrent);

	if (type == dns_rdatatype_rrsig) {
		if ((*tcurrent & DNS_RDATAVEC_OFFLINE) != 0) {
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

typedef struct vecinfo {
	unsigned char *pos;
	dns_rdata_t rdata;
	bool dup;
} vecinfo_t;

isc_result_t
dns_rdatavec_merge(dns_vecheader_t *oheader, dns_vecheader_t *nheader,
		   isc_mem_t *mctx, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, unsigned int flags,
		   uint32_t maxrrperset, dns_vecheader_t **theaderp) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char *ocurrent = NULL, *ncurrent = NULL, *tcurrent = NULL;
	unsigned int ocount, ncount, tcount = 0;
	uint32_t tlength;
	vecinfo_t *oinfo = NULL, *ninfo = NULL;
	size_t o = 0, n = 0;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && nheader != NULL);

	ocurrent = rdatavec_data(oheader);
	ocount = rdatavec_count(oheader);

	ncurrent = rdatavec_data(nheader);
	ncount = rdatavec_count(nheader);

	INSIST(ocount > 0 && ncount > 0);

	if (maxrrperset > 0 && ocount + ncount > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	/*
	 * Figure out the target length. Start with the header,
	 * plus 2 octets for the count.
	 */
	tlength = header_size(oheader) + 2;

	/*
	 * Allocate both info arrays up front so the cleanup path is
	 * always safe to call regardless of where we exit.
	 */
	oinfo = isc_mem_cget(mctx, ocount, sizeof(struct vecinfo));
	ninfo = isc_mem_cget(mctx, ncount, sizeof(struct vecinfo));

	/*
	 * Gather the rdatas in the old vec and add their lengths to
	 * the larget length.
	 */
	for (size_t i = 0; i < ocount; i++) {
		oinfo[i].pos = ocurrent;
		dns_rdata_init(&oinfo[i].rdata);
		rdata_from_vecitem(&ocurrent, rdclass, type, &oinfo[i].rdata);
		tlength += (uint32_t)(ocurrent - oinfo[i].pos);
		if (tlength - header_size(oheader) - 2 > DNS_RDATA_MAXLENGTH) {
			CLEANUP(ISC_R_NOSPACE);
		}
	}

	/*
	 * Then add the length of rdatas in the new vec that aren't
	 * duplicated in the old vec.
	 */
	for (size_t i = 0; i < ncount; i++) {
		ninfo[i].pos = ncurrent;
		dns_rdata_init(&ninfo[i].rdata);
		rdata_from_vecitem(&ncurrent, rdclass, type, &ninfo[i].rdata);

		for (size_t j = 0; j < ocount; j++) {
			if (oinfo[j].dup) {
				/*
				 * This was already found to be
				 * duplicated; no need to compare
				 * it again.
				 */
				continue;
			}

			if (dns_rdata_compare(&oinfo[j].rdata,
					      &ninfo[i].rdata) == 0)
			{
				/*
				 * Found a dup. Mark the old copy as a
				 * duplicate so we don't check it again;
				 * mark the new copy as a duplicate so we
				 * don't copy it to the target.
				 */
				oinfo[j].dup = ninfo[i].dup = true;
				break;
			}
		}

		if (ninfo[i].dup) {
			continue;
		}

		/*
		 * We will be copying this item to the target, so
		 * add its length to tlength and increment tcount.
		 */
		tlength += (uint32_t)(ncurrent - ninfo[i].pos);
		if (tlength - header_size(oheader) - 2 > DNS_RDATA_MAXLENGTH) {
			CLEANUP(ISC_R_NOSPACE);
		}
		tcount++;
	}

	/*
	 * If the EXACT flag is set, there can't be any rdata in
	 * the new vec that was also in the old. If tcount is less
	 * than ncount, then we found such a duplicate.
	 */
	if (((flags & DNS_RDATAVEC_EXACT) != 0) && (tcount < ncount)) {
		CLEANUP(DNS_R_NOTEXACT);
	}

	/*
	 * If nothing's being copied in from the new vec, and the
	 * FORCE flag isn't set, we're done.
	 */
	if (tcount == 0 && (flags & DNS_RDATAVEC_FORCE) == 0) {
		CLEANUP(DNS_R_UNCHANGED);
	}

	/* Add to tcount the total number of items from the old vec. */
	tcount += ocount;

	/* Resposition ncurrent at the first item. */
	ncurrent = rdatavec_data(nheader);

	/* Single types can't have more than one RR. */
	if (tcount > 1 && dns_rdatatype_issingleton(type)) {
		CLEANUP(DNS_R_SINGLETON);
	}

	if (tcount > 0xffff) {
		CLEANUP(ISC_R_NOSPACE);
	}

	/*
	 * Allocate the target buffer and initialize the header.
	 * Preserve the case of the old header, but the rest from the
	 * new header.
	 */
	unsigned char *tstart = isc_mem_get(mctx, tlength);
	dns_vecheader_t *as_header = (dns_vecheader_t *)tstart;
	uint16_t attrs = DNS_VECHEADER_GETATTR(
		oheader,
		DNS_VECHEADERATTR_CASESET | DNS_VECHEADERATTR_CASEFULLYLOWER);
	if (RESIGN(nheader)) {
		attrs |= DNS_VECHEADERATTR_RESIGN;
	}
	*as_header = (dns_vecheader_t){
		.typepair = nheader->typepair,
		.mctx = isc_mem_ref(mctx),
		.serial = nheader->serial,
		.ttl = nheader->ttl,
		.resign = nheader->resign,
		.next_header = ISC_SLINK_INITIALIZER,
	};
	isc_refcount_init(&as_header->references, 1);
	atomic_init(&as_header->attributes, attrs);
	atomic_init(&as_header->trust, atomic_load_acquire(&nheader->trust));
	memmove(as_header->upper, oheader->upper, sizeof(oheader->upper));

	tcurrent = tstart + header_size(nheader);

	/* Write the new count, then start merging the vecs. */
	put_uint16(tcurrent, tcount);

	/*
	 * Now walk the sets together, adding each item in DNSSEC order,
	 * and skipping over any more dups in the new vec.
	 */
	while (o < ocount || n < ncount) {
		bool fromold;

		/* Skip to the next non-duplicate in the new vec. */
		for (; n < ncount && ninfo[n].dup; n++)
			;

		if (o == ocount) {
			fromold = false;
		} else if (n == ncount) {
			fromold = true;
		} else {
			fromold = dns_rdata_compare(&oinfo[o].rdata,
						    &ninfo[n].rdata) < 0;
		}

		if (fromold) {
			rdata_to_vecitem(&tcurrent, type, &oinfo[o].rdata);
			if (++o < ocount) {
				/* Skip to the next rdata in the old vec */
				continue;
			}
		} else {
			rdata_to_vecitem(&tcurrent, type, &ninfo[n++].rdata);
		}
	}

	INSIST(tcurrent == tstart + tlength);

	*theaderp = (dns_vecheader_t *)tstart;

cleanup:
	isc_mem_cput(mctx, oinfo, ocount, sizeof(struct vecinfo));
	isc_mem_cput(mctx, ninfo, ncount, sizeof(struct vecinfo));

	return result;
}

isc_result_t
dns_rdatavec_subtract(dns_vecheader_t *oheader, dns_vecheader_t *sheader,
		      isc_mem_t *mctx, dns_rdataclass_t rdclass,
		      dns_rdatatype_t type, unsigned int flags,
		      dns_vecheader_t **theaderp) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char *ocurrent = NULL, *scurrent = NULL;
	unsigned char *tstart = NULL, *tcurrent = NULL;
	unsigned int ocount, scount;
	uint32_t tlength;
	unsigned int tcount = 0, rcount = 0;
	vecinfo_t *oinfo = NULL, *sinfo = NULL;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && sheader != NULL);

	ocurrent = rdatavec_data(oheader);
	ocount = rdatavec_count(oheader);

	scurrent = rdatavec_data(sheader);
	scount = rdatavec_count(sheader);

	INSIST(ocount > 0 && scount > 0);

	/* Get info about the rdatas being subtracted */
	sinfo = isc_mem_cget(mctx, scount, sizeof(struct vecinfo));
	for (size_t i = 0; i < scount; i++) {
		sinfo[i].pos = scurrent;
		dns_rdata_init(&sinfo[i].rdata);
		rdata_from_vecitem(&scurrent, rdclass, type, &sinfo[i].rdata);
	}

	/*
	 * Figure out the target length. Start with the header,
	 * plus 2 octets for the count.
	 */
	tlength = header_size(oheader) + 2;

	/*
	 * Add the length of the rdatas in the old vec that
	 * aren't being subtracted.
	 */
	oinfo = isc_mem_cget(mctx, ocount, sizeof(struct vecinfo));
	for (size_t i = 0; i < ocount; i++) {
		bool matched = false;

		oinfo[i].pos = ocurrent;
		dns_rdata_init(&oinfo[i].rdata);
		rdata_from_vecitem(&ocurrent, rdclass, type, &oinfo[i].rdata);

		for (size_t j = 0; j < scount; j++) {
			if (sinfo[j].dup) {
				continue;
			} else if (dns_rdata_compare(&oinfo[i].rdata,
						     &sinfo[j].rdata) == 0)
			{
				matched = true;
				oinfo[i].dup = sinfo[j].dup = true;
				break;
			}
		}

		if (matched) {
			/* This item will be subtracted. */
			rcount++;
		} else {
			/*
			 * This rdata wasn't in the vec to be subtracted,
			 * so copy it to the target.  Add its length to
			 * tlength and increment tcount.
			 */
			tlength += (uint32_t)(ocurrent - oinfo[i].pos);
			if (tlength - header_size(oheader) - 2 >
			    DNS_RDATA_MAXLENGTH)
			{
				CLEANUP(ISC_R_NOSPACE);
			}
			tcount++;
		}
	}

	/*
	 * If the EXACT flag wasn't set, check that all the records that
	 * were to be subtracted actually did exist in the original vec.
	 * (The numeric check works here because rdatavecs do not contain
	 * duplicates.)
	 */
	if ((flags & DNS_RDATAVEC_EXACT) != 0 && rcount != scount) {
		CLEANUP(DNS_R_NOTEXACT);
	}

	/*
	 * If the resulting rdatavec would be empty, don't bother to
	 * create a new buffer, just return.
	 */
	if (tcount == 0) {
		CLEANUP(DNS_R_NXRRSET);
	}

	/*
	 * If nothing is going to change, stop.
	 */
	if (rcount == 0) {
		CLEANUP(DNS_R_UNCHANGED);
	}

	/*
	 * Allocate the target buffer and copy the old vec's header.
	 */
	tstart = isc_mem_get(mctx, tlength);
	dns_vecheader_t *as_header = (dns_vecheader_t *)tstart;
	uint16_t attrs = RESIGN(oheader) ? DNS_VECHEADERATTR_RESIGN : 0;
	*as_header = (dns_vecheader_t){
		.typepair = oheader->typepair,
		.mctx = isc_mem_ref(mctx),
		.serial = oheader->serial,
		.ttl = oheader->ttl,
		.resign = oheader->resign,
		.next_header = ISC_SLINK_INITIALIZER,
	};
	isc_refcount_init(&as_header->references, 1);
	atomic_init(&as_header->attributes, attrs);
	atomic_init(&as_header->trust, atomic_load_acquire(&oheader->trust));
	memmove(as_header->upper, oheader->upper, sizeof(oheader->upper));

	tcurrent = tstart + header_size(oheader);

	/*
	 * Write the new count.
	 */
	put_uint16(tcurrent, tcount);

	/*
	 * Copy the parts of the old vec that didn't have duplicates.
	 */
	for (size_t i = 0; i < ocount; i++) {
		if (!oinfo[i].dup) {
			rdata_to_vecitem(&tcurrent, type, &oinfo[i].rdata);
		}
	}

	INSIST(tcurrent == tstart + tlength);

	*theaderp = (dns_vecheader_t *)tstart;

cleanup:
	isc_mem_cput(mctx, oinfo, ocount, sizeof(struct vecinfo));
	isc_mem_cput(mctx, sinfo, scount, sizeof(struct vecinfo));

	return result;
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
	dns_vecheader_t *h = NULL;

	h = isc_mem_get(mctx, sizeof(*h));
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
	unsigned char *raw = rdatavec_data(header);
	uint16_t count = rdatavec_count(header);
	if (count == 0) {
		iter->iter_pos = NULL;
		iter->iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter.iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	iter->iter_pos = raw;
	iter->iter_count = count - 1;
	iter->iter_rdclass = rdclass;
	iter->iter_type = DNS_TYPEPAIR_TYPE(header->typepair);

	return ISC_R_SUCCESS;
}

isc_result_t
vecheader_next(rdatavec_iter_t *iter) {
	uint16_t count = iter->iter_count;
	if (count == 0) {
		iter->iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	iter->iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
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

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
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
	return rdatavec_count(rdataset->vec.header);
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_vecheader_t *header = dns_vecheader_getheader(rdataset);

	rdataset->trust = trust;
	atomic_store(&header->trust, trust);
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
	unsigned int size = EXISTS(header) ? dns_rdatavec_size(header)
					   : sizeof(*header);

	isc_mem_putanddetach(&header->mctx, header, size);
}

/*
 * Reference counting implementation for dns_vecheader_t
 */
ISC_REFCOUNT_IMPL(dns_vecheader, vecheader_destroy);
