/*
 * Copyright (C) 2004-2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: stats.h,v 1.13.128.2 2008/01/24 23:46:26 tbox Exp $ */

#ifndef DNS_STATS_H
#define DNS_STATS_H 1

/*! \file dns/stats.h */

#include <dns/types.h>

/*%
 * Query statistics counter types.
 */
typedef enum {
	dns_statscounter_success = 0,    /*%< Successful lookup */
	dns_statscounter_referral = 1,   /*%< Referral result */
	dns_statscounter_nxrrset = 2,    /*%< NXRRSET result */
	dns_statscounter_nxdomain = 3,   /*%< NXDOMAIN result */
	dns_statscounter_recursion = 4,  /*%< Recursion was used */
	dns_statscounter_failure = 5,    /*%< Some other failure */
	dns_statscounter_duplicate = 6,  /*%< Duplicate query */
	dns_statscounter_dropped = 7     /*%< Duplicate query */
} dns_statscounter_t;

#define DNS_STATS_NCOUNTERS 8

LIBDNS_EXTERNAL_DATA extern const char *dns_statscounter_names[];

isc_result_t
dns_stats_create(isc_mem_t *mctx, dns_stats_t **statsp);
/*%<
 * Create a statistics counter structure.
 *
 * Requires:
 *
 *\li	'mctx' must be a valid memory context.
 *
 *\li	'statsp' != NULL && '*statsp' == NULL.
 */

void
dns_stats_destroy(isc_mem_t *mctx, dns_stats_t **statsp);
/*%<
 * Destroy a statistics counter structure.
 *
 * Requires:
 *
 *\li	'mctx' must be a valid memory context.
 *
 *\li	'statsp' != NULL and '*statsp' be valid dns_stats_t.
 *
 * Ensures:
 *
 *\li	'*statsp' == NULL
 */

void
dns_stats_incrementcounter(dns_stats_t *stat, dns_statscounter_t counter);
/*%<
 * Increment a counter field of 'stat' specified by 'counter'.
 *
 * Requires:
 *
 *\li	'stat' be a valid dns_stats_t.
 *
 *\li	counter < DNS_STATS_NCOUNTERS
 */

void
dns_stats_copy(dns_stats_t *src, isc_uint64_t *dst);
/*%<
 * Copy statistics counter fields of 'src' to the 'dst' array.
 *
 * Requires:
 *
 *\li	'src' be a valid dns_stats_t.
 *
 *\li	'dst' be sufficiently large to store DNS_STATS_NCOUNTERS 64-bit
 *	integers.
 */

isc_result_t
dns_stats_alloccounters(isc_mem_t *mctx, isc_uint64_t **ctrp);
/*%<
 * Allocate an array of query statistics counters from the memory
 * context 'mctx'.
 *
 * This function is obsoleted.  Use dns_stats_create() instead.
 */

void
dns_stats_freecounters(isc_mem_t *mctx, isc_uint64_t **ctrp);
/*%<
 * Free an array of query statistics counters allocated from the memory
 * context 'mctx'.
 *
 * This function is obsoleted.  Use dns_stats_destroy() instead.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_STATS_H */
