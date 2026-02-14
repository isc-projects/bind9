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

/*! \file dns/rdatavec.h
 * \brief
 * Implements storage of rdatasets into vectors of memory.
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

#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/heap.h>
#include <isc/slist.h>
#include <isc/stdtime.h>
#include <isc/urcu.h>

#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/types.h>

#define DNS_RDATAVEC_FORCE 0x1
#define DNS_RDATAVEC_EXACT 0x2

#define DNS_RDATAVEC_OFFLINE 0x01 /* RRSIG is for offline DNSKEY */

typedef struct dns_vectop    dns_vectop_t;
typedef struct dns_vecheader dns_vecheader_t;

struct rdatavec_iter {
	unsigned char	*iter_pos;
	unsigned int	 iter_count;
	dns_rdataclass_t iter_rdclass;
	dns_rdatatype_t	 iter_type;
};

typedef struct rdatavec_iter rdatavec_iter_t;

struct dns_vectop {
	ISC_SLINK(dns_vectop_t) next_type;
	ISC_SLIST(dns_vecheader_t) headers;

	dns_typepair_t typepair;
};

struct dns_vecheader {
	_Atomic(uint16_t)    attributes;
	_Atomic(dns_trust_t) trust;

	dns_typepair_t typepair;

	isc_refcount_t references;

	/*%
	 * Memory context for this header.
	 */
	isc_mem_t *mctx;

	/*%
	 * Locked by the owning node's lock.
	 */
	uint32_t  serial;
	dns_ttl_t ttl;

	/*
	 * resigning (zone).
	 */
	int64_t resign;

	/*%
	 * Link to the other versions of this rdataset.
	 */
	ISC_SLINK(dns_vecheader_t) next_header;

	/*%
	 * Cached glue records for an rdataset of type NS (zone only).
	 */
	dns_gluelist_t *gluelist;

	/*%
	 * Case vector.  If the bit is set then the corresponding
	 * character in the owner name needs to be AND'd with 0x20,
	 * rendering that character upper case.
	 */
	unsigned char upper[32];

	/*%
	 * Flexible member indicates the address of the raw data
	 * following this header.
	 */
	unsigned char raw[];
};

enum {
	DNS_VECHEADERATTR_NONEXISTENT = 1 << 0,
	DNS_VECHEADERATTR_IGNORE = 1 << 1,
	DNS_VECHEADERATTR_RESIGN = 1 << 2,
	DNS_VECHEADERATTR_OPTOUT = 1 << 3,
	DNS_VECHEADERATTR_CASESET = 1 << 4,
	DNS_VECHEADERATTR_ZEROTTL = 1 << 5,
	DNS_VECHEADERATTR_CASEFULLYLOWER = 1 << 6,
};

/* clang-format off : RemoveParentheses */
#define DNS_VECHEADER_GETATTR(header, attribute) \
	(atomic_load_acquire(&(header)->attributes) & (attribute))
/* clang-format on */
#define DNS_VECHEADER_SETATTR(header, attribute) \
	atomic_fetch_or_release(&(header)->attributes, attribute)
#define DNS_VECHEADER_CLRATTR(header, attribute) \
	atomic_fetch_and_release(&(header)->attributes, ~(attribute))

extern dns_rdatasetmethods_t dns_rdatavec_rdatasetmethods;

/***
 *** Functions
 ***/

isc_result_t
dns_rdatavec_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			  isc_region_t *region, uint32_t limit);
/*%<
 * Allocate space for a vec to hold the data in rdataset, and copy the
 * data into it.  The resulting vec will be returned in 'region'.
 *
 * dns_rdatavec_fromrdataset() allocates space for a dns_vecheader object
 * and the memory needed for a raw vec, and partially initializes
 * it, setting the type, trust, and TTL fields to match rdataset->type,
 * rdataset->covers, rdataset->trust, and rdataset->ttl.  (Note that the
 * last field needs to be overridden when used in the cache database,
 * since cache headers use an expire time instead of a TTL.)
 *
 * Requires:
 *\li	'rdataset' is valid.
 *
 * Ensures:
 *\li	'region' will have base pointing to the start of allocated memory,
 *	with the vecified region beginning at region->base + reservelen.
 *	region->length contains the total length allocated.
 *
 * Returns:
 *\li	ISC_R_SUCCESS		- successful completion
 *\li	ISC_R_NOSPACE		- more than 64k RRs
 *\li	DNS_R_TOOMANYRECORDS	- more than max-records-per-rrset RRs
 *\li	DNS_R_SINGLETON		- singleton type has more than one RR
 */

unsigned int
dns_rdatavec_size(dns_vecheader_t *header);
/*%<
 * Return the total size of the rdatavec following 'header'.
 *
 * Requires:
 *\li	'header' points to a vecheader with an rdatavec following it.
 *
 * Returns:
 *\li	The number of bytes in the vec, plus the header.
 */

unsigned int
dns_rdatavec_count(dns_vecheader_t *header);
/*%<
 * Return the number of records in the rdatavec following 'header'.
 *
 * Requires:
 *\li	'header' points to a vecheader with an rdatavec following it.
 *
 * Returns:
 *\li	The number of records in the vec.
 */

isc_result_t
dns_rdatavec_merge(dns_vecheader_t *oheader, dns_vecheader_t *nheader,
		   isc_mem_t *mctx, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, unsigned int flags,
		   uint32_t maxrrperset, dns_vecheader_t **theaderp);
/*%<
 * Merge the vecs following 'oheader' and 'nheader'.
 */

isc_result_t
dns_rdatavec_subtract(dns_vecheader_t *mheader, dns_vecheader_t *sheader,
		      isc_mem_t *mctx, dns_rdataclass_t rdclass,
		      dns_rdatatype_t type, unsigned int flags,
		      dns_vecheader_t **theaderp);
/*%<
 * Subtract the vec following 'sheader' from the one following 'mheader'.
 * If 'exact' is true then all elements from the 'sheader' vec must exist
 * in the 'mheader' vec.
 *
 * XXX
 * valid flags are DNS_RDATAVEC_EXACT
 */

void
dns_vecheader_setownercase(dns_vecheader_t *header, const dns_name_t *name);
/*%<
 * Store the casing of 'name', into a bitfield in 'header'.
 *
 * Requires:
 * \li	'header' is a valid vecheader.
 * \li	'name' is a valid name.
 */

dns_vecheader_t *
dns_vecheader_new(isc_mem_t *mctx);
/*%<
 * Allocate memory for an rdatavec header and initialize it.
 */

dns_vectop_t *
dns_vectop_new(isc_mem_t *mctx, dns_typepair_t typepair);
/*%<
 * Allocate memory for an rdatavec top and initialize it for use
 * with 'typepair' type and covers pair.
 */

void
dns_vectop_destroy(isc_mem_t *mctx, dns_vectop_t **topp);
/*%<
 * Free all memory associated with '*vectopp'.
 */

dns_vecheader_t *
dns_vecheader_moveheader(dns_rdataset_t *rdataset);
/*%<
 * Transfer ownership of the vecheader from 'rdataset' to the caller.
 * The rdataset is left disassociated so that dns_rdataset_cleanup()
 * becomes a no-op.
 *
 * Requires:
 *\li	'rdataset' is associated with an rdatavec.
 *
 * Returns:
 *\li	The vecheader pointer previously held by the rdataset.
 */

/*
 * Reference counting for dns_vecheader_t
 */
ISC_REFCOUNT_DECL(dns_vecheader);
