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

/*! \file dns/rdatatype.h */

#include <dns/types.h>

#if DNS_TYPEPAIR_CHECK
#define DNS__TYPEPAIR_CHECK(base, covers)                                     \
	INSIST((dns_rdatatype_issig(base) && covers != dns_rdatatype_none) || \
	       (base != dns_rdatatype_none && covers == dns_rdatatype_none))
#else
#define DNS__TYPEPAIR_CHECK(base, covers) (void)(base), (void)(covers)
#endif

#define DNS_TYPEPAIR_TYPE(type)                                              \
	({                                                                   \
		dns_rdatatype_t __base = (dns_rdatatype_t)((type) & 0xFFFF); \
		dns_rdatatype_t __covers = (dns_rdatatype_t)((type) >> 16);  \
		DNS__TYPEPAIR_CHECK(__base, __covers);                       \
		__base;                                                      \
	})
#define DNS_TYPEPAIR_COVERS(type)                                            \
	({                                                                   \
		dns_rdatatype_t __base = (dns_rdatatype_t)((type) & 0xFFFF); \
		dns_rdatatype_t __covers = (dns_rdatatype_t)((type) >> 16);  \
		DNS__TYPEPAIR_CHECK(__base, __covers);                       \
		__covers;                                                    \
	})
#define DNS__TYPEPAIR_VALUE(base, covers)             \
	((dns_typepair_t)(((uint32_t)covers) << 16) | \
	 (((uint32_t)base) & 0xffff))
#define DNS_TYPEPAIR_VALUE(base, covers)           \
	({                                         \
		DNS__TYPEPAIR_CHECK(base, covers); \
		DNS__TYPEPAIR_VALUE(base, covers); \
	})

#define DNS_TYPEPAIR(type)    DNS__TYPEPAIR_VALUE(type, dns_rdatatype_none)
#define DNS_SIGTYPEPAIR(type) DNS__TYPEPAIR_VALUE(dns_rdatatype_rrsig, type)

constexpr dns_typepair_t dns_typepair_none = DNS_TYPEPAIR(dns_rdatatype_none);
constexpr dns_typepair_t dns_typepair_any = DNS_TYPEPAIR(dns_rdatatype_any);

isc_result_t
dns_rdatatype_fromtext(dns_rdatatype_t *typep, isc_textregion_t *source);
/*%<
 * Convert the text 'source' refers to into a DNS rdata type.
 *
 * Requires:
 *\li	'typep' is a valid pointer.
 *
 *\li	'source' is a valid text region.
 *
 * Returns:
 *\li	ISC_R_SUCCESS			on success
 *\li	DNS_R_UNKNOWN			type is unknown
 */

isc_result_t
dns_rdatatype_totext(dns_rdatatype_t type, isc_buffer_t *target);
/*%<
 * Put a textual representation of type 'type' into 'target'.
 *
 * Requires:
 *\li	'type' is a valid type.
 *
 *\li	'target' is a valid text buffer.
 *
 * Ensures,
 *	if the result is success:
 *\li		The used space in 'target' is updated.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS			on success
 *\li	#ISC_R_NOSPACE			target buffer is too small
 */

isc_result_t
dns_rdatatype_tounknowntext(dns_rdatatype_t type, isc_buffer_t *target);
/*%<
 * Put textual RFC3597 TYPEXXXX representation of type 'type' into
 * 'target'.
 *
 * Requires:
 *\li	'type' is a valid type.
 *
 *\li	'target' is a valid text buffer.
 *
 * Ensures,
 *	if the result is success:
 *\li		The used space in 'target' is updated.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS			on success
 *\li	#ISC_R_NOSPACE			target buffer is too small
 */

void
dns_rdatatype_format(dns_rdatatype_t rdtype, char *array, unsigned int size);
/*%<
 * Format a human-readable representation of the type 'rdtype'
 * into the character array 'array', which is of size 'size'.
 * The resulting string is guaranteed to be null-terminated.
 */

#define DNS_RDATATYPE_FORMATSIZE sizeof("NSEC3PARAM")

/*%<
 * Minimum size of array to pass to dns_rdatatype_format().
 * May need to be adjusted if a new RR type with a very long
 * name is defined.
 */
