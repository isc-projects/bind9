/*
 * Copyright (C) 2004, 2005, 2007, 2008  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id: stats.c,v 1.12.128.2 2008/01/24 23:46:25 tbox Exp $ */

/*! \file */

#include <config.h>

#include <string.h>

#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include <dns/stats.h>

LIBDNS_EXTERNAL_DATA const char *dns_statscounter_names[DNS_STATS_NCOUNTERS] =
	{
	"success",
	"referral",
	"nxrrset",
	"nxdomain",
	"recursion",
	"failure",
	"duplicate",
	"dropped"
	};

#ifndef DNS_STATS_USEMULTIFIELDS
#if defined(ISC_RWLOCK_USEATOMIC) && defined(ISC_PLATFORM_HAVEXADD) && !defined(ISC_PLATFORM_HAVEXADDQ)
#define DNS_STATS_USEMULTIFIELDS 1
#else
#define DNS_STATS_USEMULTIFIELDS 0
#endif
#endif	/* DNS_STATS_USEMULTIFIELDS */

#if DNS_STATS_USEMULTIFIELDS
typedef struct {
	isc_uint32_t hi;
	isc_uint32_t lo;
} dns_stat_t;
#else
typedef isc_uint64_t dns_stat_t;
#endif

struct dns_stats {
	/* XXXJT: do we need a magic? */
#ifdef ISC_RWLOCK_USEATOMIC
	isc_rwlock_t	lock;
#endif
	dns_stat_t	counters[DNS_STATS_NCOUNTERS];
};

isc_result_t
dns_stats_create(isc_mem_t *mctx, dns_stats_t **statsp) {
	dns_stats_t *stats;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(statsp != NULL && *statsp == NULL);

	stats = isc_mem_get(mctx, sizeof(*stats));
	if (stats == NULL)
		return (ISC_R_NOMEMORY);

#ifdef ISC_RWLOCK_USEATOMIC
	result = isc_rwlock_init(&stats->lock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, stats, sizeof(*stats));
		return (result);
	}
#endif

	memset(stats->counters, 0, sizeof(dns_stat_t) * DNS_STATS_NCOUNTERS);

	*statsp = stats;

	return (result);
}

void
dns_stats_destroy(isc_mem_t *mctx, dns_stats_t **statsp) {
	dns_stats_t *stats;

	REQUIRE(statsp != NULL && *statsp != NULL);

	stats = *statsp;

#ifdef ISC_RWLOCK_USEATOMIC
	isc_rwlock_destroy(&stats->lock);
#endif
	isc_mem_put(mctx, stats, sizeof(*stats));

	*statsp = NULL;
}

void
dns_stats_incrementcounter(dns_stats_t *stats, dns_statscounter_t counter) {
	isc_int32_t prev;

	REQUIRE(counter < DNS_STATS_NCOUNTERS);

#ifdef ISC_RWLOCK_USEATOMIC
	/*
	 * We use a "read" lock to prevent other threads from reading the
	 * counter while we "writing" a counter field.  The write access itself
	 * is protected by the atomic operation.
	 */
	isc_rwlock_lock(&stats->lock, isc_rwlocktype_read);
#endif

#if DNS_STATS_USEMULTIFIELDS
	prev = isc_atomic_xadd((isc_int32_t *)&stats->counters[counter].lo, 1);
	/*
	 * If the lower 32-bit field overflows, increment the higher field.
	 * Note that it's *theoretically* possible that the lower field
	 * overlaps again before the higher field is incremented.  It doesn't
	 * matter, however, because we don't read the value until
	 * dns_stats_copy() is called where the whole process is protected
	 * by the write (exclusive) lock.
	 */
	if (prev == (isc_int32_t)0xffffffff)
		isc_atomic_xadd((isc_int32_t *)&stats->counters[counter].hi, 1);
#elif defined(ISC_PLATFORM_HAVEXADDQ)
	UNUSED(prev);
	isc_atomic_xaddq((isc_int64_t *)&stats->counters[counter], 1);
#else
	UNUSED(prev);
	stats->counters[counter]++;
#endif

#ifdef ISC_RWLOCK_USEATOMIC
	isc_rwlock_unlock(&stats->lock, isc_rwlocktype_read);
#endif
}

void
dns_stats_copy(dns_stats_t *src, isc_uint64_t *dst) {
	int i;

#ifdef ISC_RWLOCK_USEATOMIC
	/*
	 * We use a "write" lock before "reading" the statistics counters as
	 * an exclusive lock.
	 */
	isc_rwlock_lock(&src->lock, isc_rwlocktype_write);
#endif

#if DNS_STATS_USEMULTIFIELDS
	for (i = 0; i < DNS_STATS_NCOUNTERS; i++) {
		dst[i] = ((isc_uint64_t)src->counters[i].hi) << 32 |
			src->counters[i].lo;
	}
#else
	UNUSED(i);
	memcpy(dst, src->counters, DNS_STATS_NCOUNTERS * sizeof(dst[0]));
#endif

#ifdef ISC_RWLOCK_USEATOMIC
	isc_rwlock_unlock(&src->lock, isc_rwlocktype_write);
#endif
}

/***
 *** Obsolete functions follow
 ***/
isc_result_t
dns_stats_alloccounters(isc_mem_t *mctx, isc_uint64_t **ctrp) {
	int i;
	isc_uint64_t *p =
		isc_mem_get(mctx, DNS_STATS_NCOUNTERS * sizeof(isc_uint64_t));
	if (p == NULL)
		return (ISC_R_NOMEMORY);
	for (i = 0; i < DNS_STATS_NCOUNTERS; i++)
		p[i] = 0;
	*ctrp = p;
	return (ISC_R_SUCCESS);
}

void
dns_stats_freecounters(isc_mem_t *mctx, isc_uint64_t **ctrp) {
	isc_mem_put(mctx, *ctrp, DNS_STATS_NCOUNTERS * sizeof(isc_uint64_t));
	*ctrp = NULL;
}
