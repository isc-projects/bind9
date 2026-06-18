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

#pragma once

/*! \file dns/rdataslab.h
 * \brief
 * Implements storage of rdatasets into slabs of memory.
 *
 * MP:
 *\li	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *\li	This module deals with low-level byte streams.  Errors in any of
 *	the functions are likely to crash the server or corrupt memory.
 *
 *\li	If the caller passes invalid memory references, these functions are
 *	likely to crash the server or corrupt memory.
 *
 * Resources:
 *\li	None.
 *
 * Security:
 *\li	None.
 *
 * Standards:
 *\li	None.
 */

/***
 *** Imports
 ***/

/* Add -DDNS_SLABHEADER_TRACE=1 to CFLAGS for detailed reference tracing */

#include <stdalign.h>
#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/stdtime.h>
#include <isc/urcu.h>

#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/types.h>

#define DNS_RDATASLAB_FORCE 0x1
#define DNS_RDATASLAB_EXACT 0x2

#define DNS_RDATASLAB_OFFLINE 0x01 /* RRSIG is for offline DNSKEY */

struct dns_slabheader_proof {
	dns_name_t	name;
	void	       *neg;
	void	       *negsig;
	dns_rdatatype_t type;
};

#define DNS_SLABTOP_FOREACH(pos, head)                 \
	dns_slabtop_t *pos = NULL, *pos##_next = NULL; \
	cds_list_for_each_entry_safe(pos, pos##_next, head, types_link)

#define DNS_SLABTOP_FOREACH_FROM(pos, head, first)      \
	dns_slabtop_t *pos = first, *pos##_next = NULL; \
	cds_list_for_each_entry_safe_from(pos, pos##_next, head, types_link)

typedef struct dns_slabtop dns_slabtop_t;
struct dns_slabtop {
	struct cds_list_head types_link;
	struct cds_list_head headers;

	dns_slabtop_t *related;

	dns_typepair_t typepair;

	/*% Used for SIEVE-LRU (cache) */
	bool visited;
	ISC_LINK(struct dns_slabtop) link;
};

struct dns_slabheader {
	_Atomic(uint16_t)    attributes;
	_Atomic(dns_trust_t) trust;

	isc_refcount_t references;

	isc_mem_t *mctx;

	/*%
	 * Locked by the owning node's lock.
	 */
	isc_stdtime_t  expire;
	dns_typepair_t typepair;

	dns_slabheader_proof_t *noqname;
	dns_slabheader_proof_t *closest;

	/*%
	 * Points to the top slabtop structure for the type.
	 */
	dns_slabtop_t *top;

	/*%
	 * Link to the other versions of this rdataset.
	 */
	struct cds_list_head headers_link;

	/*%
	 * The database node objects containing this rdataset, if any.
	 */
	dns_dbnode_t *node;

	/*%
	 * Case vector.  If the bit is set then the corresponding
	 * character in the owner name needs to be AND'd with 0x20,
	 * rendering that character upper case.
	 */
	unsigned char upper[32];

	/* Used for stale refresh */
	_Atomic(isc_stdtime_t) last_refresh_fail_ts;

	uint16_t nitems;

	/*%
	 * Flexible member indicates the address of the raw data
	 * following this header.  This needs to be aligned to the
	 * size of the pointer because we cast raw[] to slabheader
	 * in rdataset_getheader().
	 */
	alignas(sizeof(void *)) unsigned char raw[];
};

#if DNS_SLABHEADER_TRACE
#define dns_slabheader_ref(ptr) \
	dns_slabheader__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_slabheader_unref(ptr) \
	dns_slabheader__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_slabheader_attach(ptr, ptrp) \
	dns_slabheader__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_slabheader_detach(ptrp) \
	dns_slabheader__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_slabheader);
#else
ISC_REFCOUNT_DECL(dns_slabheader);
#endif

enum {
	DNS_SLABHEADERATTR_NONEXISTENT = 1 << 0,
	DNS_SLABHEADERATTR_STALE = 1 << 1,
	DNS_SLABHEADERATTR_IGNORE = 1 << 2,
	DNS_SLABHEADERATTR_NXDOMAIN = 1 << 3,
	DNS_SLABHEADERATTR_RESIGN = 1 << 4,
	DNS_SLABHEADERATTR_STATCOUNT = 1 << 5,
	DNS_SLABHEADERATTR_OPTOUT = 1 << 6,
	DNS_SLABHEADERATTR_NEGATIVE = 1 << 7,
	DNS_SLABHEADERATTR_PREFETCH = 1 << 8,
	DNS_SLABHEADERATTR_CASESET = 1 << 9,
	DNS_SLABHEADERATTR_ZEROTTL = 1 << 10,
	DNS_SLABHEADERATTR_CASEFULLYLOWER = 1 << 11,
	DNS_SLABHEADERATTR_ANCIENT = 1 << 12,
	DNS_SLABHEADERATTR_STALE_WINDOW = 1 << 13,
};

/* clang-format off : RemoveParentheses */
#define DNS_SLABHEADER_GETATTR(header, attribute) \
	(atomic_load_acquire(&(header)->attributes) & (attribute))
/* clang-format on */
#define DNS_SLABHEADER_SETATTR(header, attribute) \
	atomic_fetch_or_release(&(header)->attributes, attribute)
#define DNS_SLABHEADER_CLRATTR(header, attribute) \
	atomic_fetch_and_release(&(header)->attributes, ~(attribute))

extern dns_rdatasetmethods_t dns_rdataslab_rdatasetmethods;

/***
 *** Functions
 ***/

#define dns_rdataslab_fromrdataset(rdataset, mctx, region, limit)            \
	dns_rdataslab__fromrdataset(rdataset, mctx, region, limit, __func__, \
				    __FILE__, __LINE__)
isc_result_t
dns_rdataslab__fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			    isc_region_t *region, uint32_t limit,
			    const char *func, const char *file,
			    const unsigned int line);
/*%<
 * Allocate space for a slab to hold the data in rdataset, and copy the
 * data into it.  The resulting slab will be returned in 'region'.
 *
 * dns_rdataslab_fromrdataset() allocates space for a dns_slabheader object
 * and the memory needed for a raw slab, and partially initializes
 * it, setting the type, and trust fields to match rdataset->type,
 * rdataset->covers, and rdataset->trust.
 *
 * Requires:
 *\li	'rdataset' is valid.
 *
 * Ensures:
 *\li	'region' will have base pointing to the start of allocated memory,
 *	with the slabified region beginning at region->base + reservelen.
 *	region->length contains the total length allocated.
 *
 * Returns:
 *\li	ISC_R_SUCCESS		- successful completion
 *\li	ISC_R_NOSPACE		- more than 64k RRs
 *\li	DNS_R_TOOMANYRECORDS	- more than max-records-per-rrset RRs
 *\li	DNS_R_SINGLETON		- singleton type has more than one RR
 */

unsigned int
dns_rdataslab_size(dns_slabheader_t *header);
/*%<
 * Return the total size of the rdataslab following 'header'.
 *
 * Requires:
 *\li	'header' points to a slabheader with an rdataslab following it.
 *
 * Returns:
 *\li	The number of bytes in the slab, plus the header.
 */

unsigned int
dns_rdataslab_count(dns_slabheader_t *header);
/*%<
 * Return the number of records in the rdataslab following 'header'.
 *
 * Requires:
 *\li	'header' points to a slabheader with an rdataslab following it.
 *
 * Returns:
 *\li	The number of records in the slab.
 */

bool
dns_rdataslab_equal(dns_slabheader_t *header1, dns_slabheader_t *header2);
/*%<
 * Compare two rdataslabs for equality.  This does _not_ do a full
 * DNSSEC comparison.
 *
 * Requires:
 *\li	'header1' and 'header1' point to slab headers followed by slabs.
 *
 * Returns:
 *\li	true if the slabs are equal, false otherwise.
 */
bool
dns_rdataslab_equalx(dns_slabheader_t *header1, dns_slabheader_t *header2,
		     dns_rdataclass_t rdclass, dns_rdatatype_t type);
/*%<
 * Compare two rdataslabs for DNSSEC equality.
 *
 * Requires:
 *\li	'header1' and 'header2' point to slab headers followed by slabs.
 *
 * Returns:
 *\li	true if the slabs are equal, #false otherwise.
 */

#define dns_slabheader_reset(header, node) \
	dns_slabheader__reset(header, node, __func__, __FILE__, __LINE__)
void
dns_slabheader__reset(dns_slabheader_t *h, dns_dbnode_t *node, const char *func,
		      const char *file, const unsigned int line);
/*%<
 * Reset an rdataslab header 'h' so it can be used to store data in
 * database node 'node'.
 */

#define dns_slabheader_new(mctx, node) \
	dns_slabheader__new(mctx, node, __func__, __FILE__, __LINE__)
dns_slabheader_t *
dns_slabheader__new(isc_mem_t *mctx, dns_dbnode_t *node, const char *func,
		    const char *file, const unsigned int line);
/*%<
 * Allocate memory for an rdataslab header and initialize it for use
 * in database node 'node'.
 */

void
dns_slabheader_freeproof(isc_mem_t *mctx, dns_slabheader_proof_t **proof);
/*%<
 * Free all memory associated with a nonexistence proof.
 */

dns_slabtop_t *
dns_slabtop_new(isc_mem_t *mctx, dns_typepair_t typepair);
/*%<
 * Allocate memory for an rdataslab top and initialize it for use
 * with 'typepair' type and covers pair.
 */

void
dns_slabtop_destroy(isc_mem_t *mctx, dns_slabtop_t **topp);
/*%<
 * Free all memory associated with '*slabtopp'.
 */
