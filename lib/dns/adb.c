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

/*! \file
 *
 * \note
 * In finds, if task == NULL, no events will be generated, and no events
 * have been sent.  If task != NULL but taskaction == NULL, an event has been
 * posted but not yet freed.  If neither are NULL, no event was posted.
 *
 */

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/ht.h>
#include <isc/mutexblock.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/adb.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/log.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/resolver.h>
#include <dns/stats.h>

/* Detailed logging of attach/detach */
#ifndef ADB_TRACE
#undef ADB_TRACE
#endif

#define DNS_ADB_MAGIC		 ISC_MAGIC('D', 'a', 'd', 'b')
#define DNS_ADB_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADB_MAGIC)
#define DNS_ADBNAME_MAGIC	 ISC_MAGIC('a', 'd', 'b', 'N')
#define DNS_ADBNAME_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADBNAME_MAGIC)
#define DNS_ADBNAMEHOOK_MAGIC	 ISC_MAGIC('a', 'd', 'N', 'H')
#define DNS_ADBNAMEHOOK_VALID(x) ISC_MAGIC_VALID(x, DNS_ADBNAMEHOOK_MAGIC)
#define DNS_ADBLAMEINFO_MAGIC	 ISC_MAGIC('a', 'd', 'b', 'Z')
#define DNS_ADBLAMEINFO_VALID(x) ISC_MAGIC_VALID(x, DNS_ADBLAMEINFO_MAGIC)
#define DNS_ADBENTRY_MAGIC	 ISC_MAGIC('a', 'd', 'b', 'E')
#define DNS_ADBENTRY_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADBENTRY_MAGIC)
#define DNS_ADBFETCH_MAGIC	 ISC_MAGIC('a', 'd', 'F', '4')
#define DNS_ADBFETCH_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADBFETCH_MAGIC)
#define DNS_ADBFETCH6_MAGIC	 ISC_MAGIC('a', 'd', 'F', '6')
#define DNS_ADBFETCH6_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADBFETCH6_MAGIC)

/*!
 * For type 3 negative cache entries, we will remember that the address is
 * broken for this long.  XXXMLG This is also used for actual addresses, too.
 * The intent is to keep us from constantly asking about A/AAAA records
 * if the zone has extremely low TTLs.
 */
#define ADB_CACHE_MINIMUM 10	/*%< seconds */
#define ADB_CACHE_MAXIMUM 86400 /*%< seconds (86400 = 24 hours) */
#define ADB_ENTRY_WINDOW  1800	/*%< seconds */

/*%
 * The period in seconds after which an ADB name entry is regarded as stale
 * and forced to be cleaned up.
 * TODO: This should probably be configurable at run-time.
 */
#ifndef ADB_STALE_MARGIN
#define ADB_STALE_MARGIN 1800
#endif /* ifndef ADB_STALE_MARGIN */

#define DNS_ADB_MINADBSIZE (1024U * 1024U) /*%< 1 Megabyte */

typedef ISC_LIST(dns_adbname_t) dns_adbnamelist_t;
typedef struct dns_adbnamehook dns_adbnamehook_t;
typedef ISC_LIST(dns_adbnamehook_t) dns_adbnamehooklist_t;
typedef struct dns_adblameinfo dns_adblameinfo_t;
typedef ISC_LIST(dns_adbentry_t) dns_adbentrylist_t;
typedef struct dns_adbfetch dns_adbfetch_t;
typedef struct dns_adbfetch6 dns_adbfetch6_t;

/*% dns adb structure */
struct dns_adb {
	unsigned int magic;

	isc_mutex_t lock;
	isc_mem_t *mctx;
	dns_view_t *view;
	dns_resolver_t *res;

	isc_taskmgr_t *taskmgr;
	isc_task_t *task;

	isc_refcount_t references;

	isc_ht_t *namebuckets;
	isc_rwlock_t names_lock;

	isc_ht_t *entrybuckets;
	isc_rwlock_t entries_lock;

	isc_stats_t *stats;

	atomic_bool exiting;

	uint32_t quota;
	uint32_t atr_freq;
	double atr_low;
	double atr_high;
	double atr_discount;
};

/*%
 * dns_adbname structure:
 *
 * This is the structure representing a nameserver name; it can be looked
 * up via the adb->namebuckets hash table. It holds references to fetches
 * for A and AAAA records while they are ongoing (fetch_a, fetch_aaaa), and
 * lists of records pointing to address information when the fetches are
 * complete (v4, v6).
 */
struct dns_adbname {
	unsigned int magic;
	dns_name_t name;
	dns_adb_t *adb;
	unsigned int partial_result;
	unsigned int flags;
	dns_adbnamebucket_t *bucket;
	dns_name_t target;
	isc_stdtime_t expire_target;
	isc_stdtime_t expire_v4;
	isc_stdtime_t expire_v6;
	dns_adbnamehooklist_t v4;
	dns_adbnamehooklist_t v6;
	dns_adbfetch_t *fetch_a;
	dns_adbfetch_t *fetch_aaaa;
	unsigned int fetch_err;
	unsigned int fetch6_err;
	dns_adbfindlist_t finds;
	/* for LRU-based management */
	isc_stdtime_t last_used;

	ISC_LINK(dns_adbname_t) plink;
};

/*%
 * dns_adbnamebucket structure:
 *
 * Hash bucket for dns_adbname objects.
 */
struct dns_adbnamebucket {
	dns_adbnamelist_t names;
	dns_adbnamelist_t deadnames;
	isc_mutex_t lock;
	isc_refcount_t references;
};

/*%
 * dns_adbfetch structure:
 * Stores the state for an ongoing A or AAAA fetch.
 */
struct dns_adbfetch {
	unsigned int magic;
	dns_fetch_t *fetch;
	dns_rdataset_t rdataset;
	unsigned int depth;
};

/*%
 * dns_adbnamehook structure:
 *
 * This is a small widget that dangles off a dns_adbname_t.  It contains a
 * pointer to the address information about this host, and a link to the next
 * namehook that will contain the next address this host has.
 */
struct dns_adbnamehook {
	unsigned int magic;
	dns_adbentry_t *entry;
	ISC_LINK(dns_adbnamehook_t) plink;
};

/*%
 * dns_adblameinfo structure:
 *
 * This is a small widget that holds qname-specific information about an
 * address.  Currently limited to lameness, but could just as easily be
 * extended to other types of information about zones.
 */
struct dns_adblameinfo {
	unsigned int magic;

	dns_name_t qname;
	dns_rdatatype_t qtype;
	isc_stdtime_t lame_timer;

	ISC_LINK(dns_adblameinfo_t) plink;
};

/*%
 * dns_adbentry structure:
 *
 * This is the structure representing a nameserver address; it can be looked
 * up via the adb->entrybuckets hash table. Also, each dns_adbnamehook and
 * and dns_adbaddrinfo object will contain a pointer to one of these.
 *
 * The structure holds quite a bit of information about addresses,
 * including edns state (in "flags"), RTT, and of course the address of
 * the host.
 */
struct dns_adbentry {
	unsigned int magic;

	isc_refcount_t references;

	dns_adb_t *adb;
	dns_adbentrybucket_t *bucket;

	unsigned int nh;
	unsigned int flags;
	unsigned int srtt;
	unsigned int completed;
	unsigned int timeouts;
	unsigned char plain;
	unsigned char plainto;
	unsigned char edns;
	unsigned char ednsto;
	uint16_t udpsize;

	uint8_t mode;
	atomic_uint_fast32_t quota;
	atomic_uint_fast32_t active;
	double atr;

	isc_sockaddr_t sockaddr;
	unsigned char *cookie;
	uint16_t cookielen;

	isc_stdtime_t expires;
	isc_stdtime_t lastage;
	/*%<
	 * A nonzero 'expires' field indicates that the entry should
	 * persist until that time.  This allows entries found
	 * using dns_adb_findaddrinfo() to persist for a limited time
	 * even though they are not necessarily associated with a
	 * entry.
	 */

	ISC_LIST(dns_adblameinfo_t) lameinfo;
	ISC_LINK(dns_adbentry_t) plink;
};

/*% dns_adbentrybucket_t structure:
 *
 * Hash bucket for dns_adbentry objects.
 */
struct dns_adbentrybucket {
	dns_adbentrylist_t entries;
	dns_adbentrylist_t deadentries;
	isc_mutex_t lock;
	isc_refcount_t references;
};

/*
 * Internal functions (and prototypes).
 */
static dns_adbname_t *
new_adbname(dns_adb_t *, const dns_name_t *);
static dns_adbnamebucket_t *
new_adbnamebucket(dns_adb_t *);
static void
free_adbname(dns_adbname_t **);
static dns_adbnamehook_t *
new_adbnamehook(dns_adb_t *, dns_adbentry_t *);
static void
free_adbnamehook(dns_adb_t *, dns_adbnamehook_t **);
static dns_adblameinfo_t *
new_adblameinfo(dns_adb_t *, const dns_name_t *, dns_rdatatype_t);
static void
free_adblameinfo(dns_adb_t *, dns_adblameinfo_t **);
static dns_adbentry_t *
new_adbentry(dns_adb_t *);
static void
free_adbentry(dns_adbentry_t **);
static dns_adbentrybucket_t *
new_adbentrybucket(dns_adb_t *adb);
static dns_adbfind_t *
new_adbfind(dns_adb_t *, in_port_t);
static void
free_adbfind(dns_adbfind_t **);
static dns_adbaddrinfo_t *
new_adbaddrinfo(dns_adb_t *, dns_adbentry_t *, in_port_t);
static dns_adbfetch_t *
new_adbfetch(dns_adb_t *);
static void
free_adbfetch(dns_adb_t *, dns_adbfetch_t **);
static void
get_namebucket(dns_adb_t *, const dns_name_t *, dns_adbnamebucket_t **);
static dns_adbname_t *
get_name(dns_adbnamebucket_t *, const dns_name_t *, unsigned int);
static void
get_entrybucket(dns_adb_t *, const isc_sockaddr_t *, dns_adbentrybucket_t **);
static dns_adbentry_t *
get_entry(dns_adbentrybucket_t *, const isc_sockaddr_t *, isc_stdtime_t);
static void
dump_adb(dns_adb_t *, FILE *, bool debug, isc_stdtime_t);
static void
print_namehook_list(FILE *, const char *legend, dns_adb_t *adb,
		    dns_adbnamehooklist_t *list, bool debug, isc_stdtime_t now);
static void
print_find_list(FILE *, dns_adbname_t *);
static void
print_fetch_list(FILE *, dns_adbname_t *);
static void
clean_namehooks(dns_adb_t *, dns_adbnamehooklist_t *);
static void
clean_target(dns_adb_t *, dns_name_t *);
static void
clean_finds_at_name(dns_adbname_t *, isc_eventtype_t, unsigned int);
static void
maybe_expire_namehooks(dns_adbname_t *, isc_stdtime_t);
static void
maybe_expire_entry(dns_adbentry_t **, isc_stdtime_t);
static isc_result_t
dbfind_name(dns_adbname_t *, isc_stdtime_t, dns_rdatatype_t);
static isc_result_t
fetch_name(dns_adbname_t *, bool, unsigned int, isc_counter_t *qc,
	   dns_rdatatype_t);
static void
destroy(dns_adb_t *);
static void
shutdown_names(dns_adb_t *);
static void
shutdown_entries(dns_adb_t *);
static void
link_name(dns_adbnamebucket_t *, dns_adbname_t *);
static void
unlink_name(dns_adbname_t *);
static void
link_entry(dns_adbentrybucket_t *, dns_adbentry_t *);
static void
unlink_entry(dns_adbentry_t *);
static void
expire_name(dns_adbname_t **, isc_eventtype_t);
static void
water(void *, int);
static void
dump_entry(FILE *, dns_adb_t *, dns_adbentry_t *, bool, isc_stdtime_t);
static void
adjustsrtt(dns_adbaddrinfo_t *addr, unsigned int rtt, unsigned int factor,
	   isc_stdtime_t now);
static void
log_quota(dns_adbentry_t *entry, const char *fmt, ...) ISC_FORMAT_PRINTF(2, 3);

/*
 * MUST NOT overlap DNS_ADBFIND_* flags!
 */
#define FIND_EVENT_SENT	   0x40000000
#define FIND_EVENT_FREED   0x80000000
#define FIND_EVENTSENT(h)  (((h)->flags & FIND_EVENT_SENT) != 0)
#define FIND_EVENTFREED(h) (((h)->flags & FIND_EVENT_FREED) != 0)

#define NAME_IS_DEAD	 0x40000000
#define NAME_HINT_OK	 DNS_ADBFIND_HINTOK
#define NAME_GLUE_OK	 DNS_ADBFIND_GLUEOK
#define NAME_STARTATZONE DNS_ADBFIND_STARTATZONE
#define NAME_DEAD(n)	 (((n)->flags & NAME_IS_DEAD) != 0)
#define NAME_GLUEOK(n)	 (((n)->flags & NAME_GLUE_OK) != 0)
#define NAME_HINTOK(n)	 (((n)->flags & NAME_HINT_OK) != 0)

/*
 * Private flag(s) for entries.
 * MUST NOT overlap FCTX_ADDRINFO_xxx and DNS_FETCHOPT_NOEDNS0.
 */
#define ENTRY_IS_DEAD 0x00400000

/*
 * To the name, address classes are all that really exist.  If it has a
 * V6 address it doesn't care if it came from a AAAA query.
 */
#define NAME_HAS_V4(n) (!ISC_LIST_EMPTY((n)->v4))
#define NAME_HAS_V6(n) (!ISC_LIST_EMPTY((n)->v6))

/*
 * Fetches are broken out into A and AAAA types.  In some cases,
 * however, it makes more sense to test for a particular class of fetches,
 * like V4 or V6 above.
 */
#define NAME_FETCH_A(n)	   ((n)->fetch_a != NULL)
#define NAME_FETCH_AAAA(n) ((n)->fetch_aaaa != NULL)
#define NAME_FETCH(n)	   (NAME_FETCH_A(n) || NAME_FETCH_AAAA(n))

/*
 * Find options and tests to see if there are addresses on the list.
 */
#define FIND_WANTEVENT(fn)	(((fn)->options & DNS_ADBFIND_WANTEVENT) != 0)
#define FIND_WANTEMPTYEVENT(fn) (((fn)->options & DNS_ADBFIND_EMPTYEVENT) != 0)
#define FIND_AVOIDFETCHES(fn)	(((fn)->options & DNS_ADBFIND_AVOIDFETCHES) != 0)
#define FIND_STARTATZONE(fn)	(((fn)->options & DNS_ADBFIND_STARTATZONE) != 0)
#define FIND_HINTOK(fn)		(((fn)->options & DNS_ADBFIND_HINTOK) != 0)
#define FIND_GLUEOK(fn)		(((fn)->options & DNS_ADBFIND_GLUEOK) != 0)
#define FIND_HAS_ADDRS(fn)	(!ISC_LIST_EMPTY((fn)->list))
#define FIND_RETURNLAME(fn)	(((fn)->options & DNS_ADBFIND_RETURNLAME) != 0)
#define FIND_NOFETCH(fn)	(((fn)->options & DNS_ADBFIND_NOFETCH) != 0)

/*
 * These are currently used on simple unsigned ints, so they are
 * not really associated with any particular type.
 */
#define WANT_INET(x)  (((x)&DNS_ADBFIND_INET) != 0)
#define WANT_INET6(x) (((x)&DNS_ADBFIND_INET6) != 0)

#define EXPIRE_OK(exp, now) ((exp == INT_MAX) || (exp < now))

/*
 * Find out if the flags on a name (nf) indicate if it is a hint or
 * glue, and compare this to the appropriate bits set in o, to see if
 * this is ok.
 */
#define GLUE_OK(nf, o)	   (!NAME_GLUEOK(nf) || (((o)&DNS_ADBFIND_GLUEOK) != 0))
#define HINT_OK(nf, o)	   (!NAME_HINTOK(nf) || (((o)&DNS_ADBFIND_HINTOK) != 0))
#define GLUEHINT_OK(nf, o) (GLUE_OK(nf, o) || HINT_OK(nf, o))
#define STARTATZONE_MATCHES(nf, o) \
	(((nf)->flags & NAME_STARTATZONE) == ((o)&DNS_ADBFIND_STARTATZONE))

#define ENTER_LEVEL  ISC_LOG_DEBUG(50)
#define CLEAN_LEVEL  ISC_LOG_DEBUG(100)
#define DEF_LEVEL    ISC_LOG_DEBUG(5)
#define NCACHE_LEVEL ISC_LOG_DEBUG(20)

#define NCACHE_RESULT(r) \
	((r) == DNS_R_NCACHENXDOMAIN || (r) == DNS_R_NCACHENXRRSET)
#define AUTH_NX(r) ((r) == DNS_R_NXDOMAIN || (r) == DNS_R_NXRRSET)

/*
 * Error states.
 */
enum {
	FIND_ERR_SUCCESS = 0,
	FIND_ERR_CANCELED,
	FIND_ERR_FAILURE,
	FIND_ERR_NXDOMAIN,
	FIND_ERR_NXRRSET,
	FIND_ERR_UNEXPECTED,
	FIND_ERR_NOTFOUND,
};

static const char *errnames[] = { "success",  "canceled", "failure",
				  "nxdomain", "nxrrset",  "unexpected",
				  "not_found" };

static isc_result_t find_err_map[] = {
	ISC_R_SUCCESS, ISC_R_CANCELED,	 ISC_R_FAILURE, DNS_R_NXDOMAIN,
	DNS_R_NXRRSET, ISC_R_UNEXPECTED, ISC_R_NOTFOUND /* not YET found */
};

static void
DP(int level, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);

static void
DP(int level, const char *format, ...) {
	va_list args;

	va_start(args, format);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_ADB,
		       level, format, args);
	va_end(args);
}

/*%
 * Increment resolver-related statistics counters.
 */
static void
inc_resstats(dns_adb_t *adb, isc_statscounter_t counter) {
	if (adb->res != NULL) {
		dns_resolver_incstats(adb->res, counter);
	}
}

/*%
 * Set adb-related statistics counters.
 */
static void
set_adbstat(dns_adb_t *adb, uint64_t val, isc_statscounter_t counter) {
	if (adb->stats != NULL) {
		isc_stats_set(adb->stats, val, counter);
	}
}

static void
dec_adbstats(dns_adb_t *adb, isc_statscounter_t counter) {
	if (adb->stats != NULL) {
		isc_stats_decrement(adb->stats, counter);
	}
}

static void
inc_adbstats(dns_adb_t *adb, isc_statscounter_t counter) {
	if (adb->stats != NULL) {
		isc_stats_increment(adb->stats, counter);
	}
}

static dns_ttl_t
ttlclamp(dns_ttl_t ttl) {
	if (ttl < ADB_CACHE_MINIMUM) {
		ttl = ADB_CACHE_MINIMUM;
	}
	if (ttl > ADB_CACHE_MAXIMUM) {
		ttl = ADB_CACHE_MAXIMUM;
	}

	return (ttl);
}

#define entry_attach(s, t) _entry_attach(s, t, __func__, __FILE__, __LINE__)

static void
_entry_attach(dns_adbentry_t *source, dns_adbentry_t **targetp,
	      const char *func, const char *file, unsigned int line) {
	uint_fast32_t refs;

	REQUIRE(DNS_ADBENTRY_VALID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	refs = isc_refcount_increment(&source->references);
#ifdef ADB_TRACE
	fprintf(stderr, "%s:%s:%u:%s(%p, %p) = %" PRIuFAST32 "\n", func, file,
		line, __func__, source, targetp, refs + 1);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
	UNUSED(refs);
#endif /* ADB_TRACE */

	*targetp = source;
}

#define entry_detach(ep) _entry_detach(ep, __func__, __FILE__, __LINE__)

static void
_entry_detach(dns_adbentry_t **entryp, const char *func, const char *file,
	      unsigned int line) {
	dns_adbentry_t *entry = NULL;
	uint_fast32_t refs;

	REQUIRE(entryp != NULL);

	entry = *entryp;
	*entryp = NULL;

	REQUIRE(DNS_ADBENTRY_VALID(entry));

	refs = isc_refcount_decrement(&entry->references);

#ifdef ADB_TRACE
	fprintf(stderr, "%s:%s:%u:%s(%p, %p), %" PRIuFAST32 "\n", func, file,
		line, __func__, entry, entryp, refs - 1);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif /* ADB_TRACE */

	if (refs == 1) {
		/*
		 * If the entry is linked to a bucket, we need to
		 * unlink it before destroying it.
		 */
		if (ISC_LINK_LINKED(entry, plink)) {
			unlink_entry(entry);
		}
		free_adbentry(&entry);
	}
}

/*
 * Requires the name's bucket to be locked and that no entry buckets be locked.
 *
 * This code handles A and AAAA rdatasets only.
 */
static isc_result_t
import_rdataset(dns_adbname_t *adbname, dns_rdataset_t *rdataset,
		isc_stdtime_t now) {
	isc_result_t result;
	dns_adb_t *adb = NULL;
	bool new_addresses_added = false;
	dns_rdatatype_t rdtype;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	rdtype = rdataset->type;

	REQUIRE(rdtype == dns_rdatatype_a || rdtype == dns_rdatatype_aaaa);

	for (result = dns_rdataset_first(rdataset); result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(rdataset))
	{
		dns_adbentrybucket_t *ebucket = NULL;
		dns_adbnamehooklist_t *hookhead = NULL;
		dns_adbentry_t *entry = NULL;
		dns_adbnamehook_t *nh = NULL;
		dns_rdata_t rdata = DNS_RDATA_INIT;
		isc_sockaddr_t sockaddr;
		struct in_addr ina;
		struct in6_addr in6a;

		dns_rdataset_current(rdataset, &rdata);
		if (rdtype == dns_rdatatype_a) {
			INSIST(rdata.length == 4);
			memmove(&ina.s_addr, rdata.data, 4);
			isc_sockaddr_fromin(&sockaddr, &ina, 0);
			hookhead = &adbname->v4;
		} else {
			INSIST(rdata.length == 16);
			memmove(in6a.s6_addr, rdata.data, 16);
			isc_sockaddr_fromin6(&sockaddr, &in6a, 0);
			hookhead = &adbname->v6;
		}

		nh = new_adbnamehook(adb, NULL);

		get_entrybucket(adb, &sockaddr, &ebucket);
		INSIST(ebucket != NULL);
		LOCK(&ebucket->lock);

		entry = get_entry(ebucket, &sockaddr, now);
		if (entry == NULL) {
			entry = new_adbentry(adb);
			entry->sockaddr = sockaddr;
			entry_attach(entry, &nh->entry);
			link_entry(ebucket, entry);
			entry->nh = 1;
		} else {
			dns_adbnamehook_t *anh = NULL;
			for (anh = ISC_LIST_HEAD(*hookhead); anh != NULL;
			     anh = ISC_LIST_NEXT(anh, plink))
			{
				if (anh->entry == entry) {
					break;
				}
			}
			if (anh == NULL) {
				/* Move entry to the head of the LRU list */
				ISC_LIST_UNLINK(ebucket->entries, entry, plink);
				ISC_LIST_PREPEND(ebucket->entries, entry,
						 plink);
				entry_attach(entry, &nh->entry);
				entry->nh++;
			} else {
				free_adbnamehook(adb, &nh);
			}
		}
		UNLOCK(&ebucket->lock);

		new_addresses_added = true;
		if (nh != NULL) {
			ISC_LIST_APPEND(*hookhead, nh, plink);
		}
	}
	if (result == ISC_R_NOMORE) {
		result = ISC_R_SUCCESS;
	}

	if (rdataset->trust == dns_trust_glue ||
	    rdataset->trust == dns_trust_additional)
	{
		rdataset->ttl = ADB_CACHE_MINIMUM;
	} else if (rdataset->trust == dns_trust_ultimate) {
		rdataset->ttl = 0;
	} else {
		rdataset->ttl = ttlclamp(rdataset->ttl);
	}

	if (rdtype == dns_rdatatype_a) {
		DP(NCACHE_LEVEL, "expire_v4 set to MIN(%u,%u) import_rdataset",
		   adbname->expire_v4, now + rdataset->ttl);
		adbname->expire_v4 = ISC_MIN(
			adbname->expire_v4,
			ISC_MIN(now + ADB_ENTRY_WINDOW, now + rdataset->ttl));
	} else {
		DP(NCACHE_LEVEL, "expire_v6 set to MIN(%u,%u) import_rdataset",
		   adbname->expire_v6, now + rdataset->ttl);
		adbname->expire_v6 = ISC_MIN(
			adbname->expire_v6,
			ISC_MIN(now + ADB_ENTRY_WINDOW, now + rdataset->ttl));
	}

	if (new_addresses_added) {
		/*
		 * Lie a little here.  This is more or less so code that cares
		 * can find out if any new information was added or not.
		 */
		return (ISC_R_SUCCESS);
	}

	return (result);
}

/*
 * Requires the name's bucket to be locked.
 */
static void
expire_name(dns_adbname_t **n, isc_eventtype_t evtype) {
	dns_adb_t *adb = NULL;
	dns_adbname_t *adbname = NULL;

	REQUIRE(n != NULL);

	adbname = *n;
	*n = NULL;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	DP(DEF_LEVEL, "killing name %p", adbname);

	/*
	 * If we're dead already and have no active fetch, unlink
	 * and free the name.
	 */
	if (NAME_DEAD(adbname) && !NAME_FETCH(adbname)) {
		unlink_name(adbname);
		free_adbname(&adbname);
		return;
	}

	/*
	 * Clean up the name's various contents.  These functions
	 * are destructive in that they will always empty the lists
	 * of finds and namehooks.
	 */
	clean_finds_at_name(adbname, evtype, DNS_ADBFIND_ADDRESSMASK);
	clean_namehooks(adb, &adbname->v4);
	clean_namehooks(adb, &adbname->v6);
	clean_target(adb, &adbname->target);

	/*
	 * If no fetches are running, unlink and free the name now;
	 * otherwise cancel them.
	 */
	if (!NAME_FETCH(adbname)) {
		unlink_name(adbname);
		free_adbname(&adbname);
		return;
	}

	if (NAME_FETCH_A(adbname)) {
		dns_resolver_cancelfetch(adbname->fetch_a->fetch);
	}

	if (NAME_FETCH_AAAA(adbname)) {
		dns_resolver_cancelfetch(adbname->fetch_aaaa->fetch);
	}

	/*
	 * Mark the name as dead and move it from 'names' to 'deadnames';
	 * we'll clean it up later.
	 */
	if (!NAME_DEAD(adbname)) {
		dns_adbnamebucket_t *nbucket = adbname->bucket;
		ISC_LIST_UNLINK(nbucket->names, adbname, plink);
		ISC_LIST_APPEND(nbucket->deadnames, adbname, plink);
		adbname->flags |= NAME_IS_DEAD;
	}
}

/*
 * Requires the name's bucket to be locked and no entry buckets be locked.
 */
static void
maybe_expire_namehooks(dns_adbname_t *name, isc_stdtime_t now) {
	dns_adb_t *adb = NULL;

	REQUIRE(DNS_ADBNAME_VALID(name));

	adb = name->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	/*
	 * Check to see if we need to remove the v4 addresses
	 */
	if (!NAME_FETCH_A(name) && EXPIRE_OK(name->expire_v4, now)) {
		if (NAME_HAS_V4(name)) {
			DP(DEF_LEVEL, "expiring v4 for name %p", name);
			clean_namehooks(adb, &name->v4);
			name->partial_result &= ~DNS_ADBFIND_INET;
		}
		name->expire_v4 = INT_MAX;
		name->fetch_err = FIND_ERR_UNEXPECTED;
	}

	/*
	 * Check to see if we need to remove the v6 addresses
	 */
	if (!NAME_FETCH_AAAA(name) && EXPIRE_OK(name->expire_v6, now)) {
		if (NAME_HAS_V6(name)) {
			DP(DEF_LEVEL, "expiring v6 for name %p", name);
			clean_namehooks(adb, &name->v6);
			name->partial_result &= ~DNS_ADBFIND_INET6;
		}
		name->expire_v6 = INT_MAX;
		name->fetch6_err = FIND_ERR_UNEXPECTED;
	}

	/*
	 * Check to see if we need to remove the alias target.
	 */
	if (EXPIRE_OK(name->expire_target, now)) {
		clean_target(adb, &name->target);
		name->expire_target = INT_MAX;
	}
}

/*
 * Requires the name's bucket to be locked.
 */
static void
link_name(dns_adbnamebucket_t *nbucket, dns_adbname_t *name) {
	REQUIRE(name->bucket == NULL);
	REQUIRE(!ISC_LINK_LINKED(name, plink));

	name->bucket = nbucket;

	ISC_LIST_PREPEND(nbucket->names, name, plink);
	isc_refcount_increment0(&nbucket->references);
}

/*
 * Requires the name's bucket to be locked.
 */
static void
unlink_name(dns_adbname_t *name) {
	dns_adbnamebucket_t *nbucket = NULL;

	REQUIRE(DNS_ADBNAME_VALID(name));
	REQUIRE(ISC_LINK_LINKED(name, plink));

	nbucket = name->bucket;
	name->bucket = NULL;

	REQUIRE(nbucket != NULL);

	if (NAME_DEAD(name)) {
		ISC_LIST_UNLINK(nbucket->deadnames, name, plink);
	} else {
		ISC_LIST_UNLINK(nbucket->names, name, plink);
	}

	isc_refcount_decrement(&nbucket->references);
}

/*
 * Requires the entry's bucket to be locked.
 */
static void
link_entry(dns_adbentrybucket_t *ebucket, dns_adbentry_t *entry) {
	REQUIRE(entry != NULL && entry->bucket == NULL);
	REQUIRE(!ISC_LINK_LINKED(entry, plink));

	DP(DEF_LEVEL, "link ADB entry %p to bucket %p", entry, ebucket);

	/*
	 * If we're in the overmem condition, take this opportunity to
	 * clean up the least-recently used entries in the bucket.
	 */
	if (isc_mem_isovermem(entry->adb->mctx)) {
		int i;

		DP(ISC_LOG_DEBUG(1), "adb: overmem, cleaning bucket %p",
		   ebucket);

		for (i = 0; i < 2; i++) {
			dns_adbentry_t *e = ISC_LIST_TAIL(ebucket->entries);
			if (e == NULL) {
				break;
			}

			/*
			 * If the only reference to an entry is from
			 * the bucket itself, we can kill it. Otherwise
			 * we move it to deadentries and kill it later.
			 */
			if (isc_refcount_current(&e->references) == 1) {
				unlink_entry(e);
				entry_detach(&e);
				continue;
			}

			INSIST((e->flags & ENTRY_IS_DEAD) == 0);
			e->flags |= ENTRY_IS_DEAD;
			ISC_LIST_UNLINK(ebucket->entries, e, plink);
			ISC_LIST_PREPEND(ebucket->deadentries, e, plink);
		}
	}

	entry->bucket = ebucket;
	ISC_LIST_PREPEND(ebucket->entries, entry, plink);
	isc_refcount_increment0(&ebucket->references);
}

/*
 * Requires the entry's bucket to be locked.
 */
static void
unlink_entry(dns_adbentry_t *entry) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADBENTRY_VALID(entry));
	REQUIRE(ISC_LINK_LINKED(entry, plink));

	ebucket = entry->bucket;
	entry->bucket = NULL;

	REQUIRE(ebucket != NULL);

	DP(DEF_LEVEL, "unlink ADB entry %p from bucket %p", entry, ebucket);

	if ((entry->flags & ENTRY_IS_DEAD) != 0) {
		ISC_LIST_UNLINK(ebucket->deadentries, entry, plink);
	} else {
		ISC_LIST_UNLINK(ebucket->entries, entry, plink);
	}

	isc_refcount_decrement(&ebucket->references);
}

static void
shutdown_names(dns_adb_t *adb) {
	isc_result_t result;
	isc_ht_iter_t *it = NULL;

	RWLOCK(&adb->names_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->namebuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(it))
	{
		dns_adbnamebucket_t *nbucket = NULL;
		dns_adbname_t *name = NULL;
		dns_adbname_t *next_name = NULL;

		isc_ht_iter_current(it, (void **)&nbucket);
		INSIST(nbucket != NULL);

		LOCK(&nbucket->lock);
		/*
		 * Run through the list.  For each name, clean up finds
		 * found there, and cancel any fetches running.  When
		 * all the fetches are canceled, the name will destroy
		 * itself.
		 */
		name = ISC_LIST_HEAD(nbucket->names);
		while (name != NULL) {
			next_name = ISC_LIST_NEXT(name, plink);
			expire_name(&name, DNS_EVENT_ADBSHUTDOWN);
			name = next_name;
		}

		UNLOCK(&nbucket->lock);
	}

	isc_ht_iter_destroy(&it);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);
}

static void
shutdown_entries(dns_adb_t *adb) {
	isc_result_t result;
	isc_ht_iter_t *iter = NULL;

	RWLOCK(&adb->entries_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->entrybuckets, &iter);
	for (result = isc_ht_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(iter))
	{
		dns_adbentrybucket_t *ebucket = NULL;
		dns_adbentry_t *entry = NULL;
		dns_adbentry_t *next_entry = NULL;

		isc_ht_iter_current(iter, (void **)&ebucket);
		INSIST(ebucket != NULL);

		LOCK(&ebucket->lock);
		entry = ISC_LIST_HEAD(ebucket->entries);
		while (entry != NULL) {
			/*
			 * Run through the list and clean up any
			 * entries not in use.
			 */
			next_entry = ISC_LIST_NEXT(entry, plink);
			if (isc_refcount_current(&entry->references) == 1 &&
			    entry->expires == 0) {
				unlink_entry(entry);
			}
			entry_detach(&entry);
			entry = next_entry;
		}

		UNLOCK(&ebucket->lock);
	}
	RWUNLOCK(&adb->entries_lock, isc_rwlocktype_read);

	isc_ht_iter_destroy(&iter);
}

/*
 * The bucket for the name containing the 'namehooks' list must be locked.
 */
static void
clean_namehooks(dns_adb_t *adb, dns_adbnamehooklist_t *namehooks) {
	dns_adbentrybucket_t *ebucket = NULL;
	dns_adbnamehook_t *namehook = NULL;

	namehook = ISC_LIST_HEAD(*namehooks);
	while (namehook != NULL) {
		INSIST(DNS_ADBNAMEHOOK_VALID(namehook));

		/*
		 * Clean up the entry if needed.
		 */
		if (namehook->entry != NULL) {
			INSIST(DNS_ADBENTRY_VALID(namehook->entry));

			/*
			 * If entry bucket for the next address is
			 * different from the previous one, then
			 * unlock the old one, lock the new one, and
			 * carry on. (This way we don't necessarily
			 * have to lock and unlock for every list
			 * member.)
			 */
			if (ebucket != namehook->entry->bucket) {
				if (ebucket != NULL) {
					UNLOCK(&ebucket->lock);
				}
				ebucket = namehook->entry->bucket;
				INSIST(ebucket != NULL);
				LOCK(&ebucket->lock);
			}

			namehook->entry->nh--;
			entry_detach(&namehook->entry);
		}

		/*
		 * Free the namehook
		 */
		ISC_LIST_UNLINK(*namehooks, namehook, plink);
		free_adbnamehook(adb, &namehook);

		namehook = ISC_LIST_HEAD(*namehooks);
	}

	if (ebucket != NULL) {
		UNLOCK(&ebucket->lock);
	}
}

static void
clean_target(dns_adb_t *adb, dns_name_t *target) {
	if (dns_name_countlabels(target) > 0) {
		dns_name_free(target, adb->mctx);
		dns_name_init(target, NULL);
	}
}

static isc_result_t
set_target(dns_adb_t *adb, const dns_name_t *name, const dns_name_t *fname,
	   dns_rdataset_t *rdataset, dns_name_t *target) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	REQUIRE(dns_name_countlabels(target) == 0);

	if (rdataset->type == dns_rdatatype_cname) {
		dns_rdata_cname_t cname;

		/*
		 * Copy the CNAME's target into the target name.
		 */
		result = dns_rdataset_first(rdataset);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		dns_rdataset_current(rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &cname, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		dns_name_dup(&cname.cname, adb->mctx, target);
		dns_rdata_freestruct(&cname);
	} else {
		dns_fixedname_t fixed1, fixed2;
		dns_name_t *prefix = NULL, *new_target = NULL;
		dns_rdata_dname_t dname;
		dns_namereln_t namereln;
		unsigned int nlabels;
		int order;

		INSIST(rdataset->type == dns_rdatatype_dname);
		namereln = dns_name_fullcompare(name, fname, &order, &nlabels);
		INSIST(namereln == dns_namereln_subdomain);

		/*
		 * Get the target name of the DNAME.
		 */
		result = dns_rdataset_first(rdataset);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		dns_rdataset_current(rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &dname, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}

		/*
		 * Construct the new target name.
		 */
		prefix = dns_fixedname_initname(&fixed1);
		new_target = dns_fixedname_initname(&fixed2);
		dns_name_split(name, nlabels, prefix, NULL);
		result = dns_name_concatenate(prefix, &dname.dname, new_target,
					      NULL);
		dns_rdata_freestruct(&dname);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		dns_name_dup(new_target, adb->mctx, target);
	}

	return (ISC_R_SUCCESS);
}

static void
event_freefind(isc_event_t *event) {
	dns_adbfind_t *find = NULL;

	REQUIRE(event != NULL);

	find = event->ev_destroy_arg;

	REQUIRE(DNS_ADBFIND_VALID(find));

	LOCK(&find->lock);
	find->flags |= FIND_EVENT_FREED;
	event->ev_destroy_arg = NULL;
	UNLOCK(&find->lock);
}

/*
 * Assumes the name's bucket is locked.
 */
static void
clean_finds_at_name(dns_adbname_t *name, isc_eventtype_t evtype,
		    unsigned int addrs) {
	dns_adbfind_t *find = NULL, *next = NULL;

	DP(ENTER_LEVEL,
	   "ENTER clean_finds_at_name, name %p, evtype %08x, addrs %08x", name,
	   evtype, addrs);

	for (find = ISC_LIST_HEAD(name->finds); find != NULL; find = next) {
		bool process = false;
		unsigned int wanted, notify;

		LOCK(&find->lock);
		next = ISC_LIST_NEXT(find, plink);

		wanted = find->flags & DNS_ADBFIND_ADDRESSMASK;
		notify = wanted & addrs;

		switch (evtype) {
		case DNS_EVENT_ADBMOREADDRESSES:
			DP(ISC_LOG_DEBUG(3), "DNS_EVENT_ADBMOREADDRESSES");
			if ((notify) != 0) {
				find->flags &= ~addrs;
				process = true;
			}
			break;
		case DNS_EVENT_ADBNOMOREADDRESSES:
			DP(ISC_LOG_DEBUG(3), "DNS_EVENT_ADBNOMOREADDRESSES");
			find->flags &= ~addrs;
			wanted = find->flags & DNS_ADBFIND_ADDRESSMASK;
			if (wanted == 0) {
				process = true;
			}
			break;
		default:
			find->flags &= ~addrs;
			process = true;
		}

		if (process) {
			isc_task_t *task = NULL;
			isc_event_t *ev = NULL;

			DP(DEF_LEVEL, "cfan: processing find %p", find);

			/*
			 * Unlink the find from the name, letting the caller
			 * call dns_adb_destroyfind() on it to clean it up
			 * later.
			 */
			ISC_LIST_UNLINK(name->finds, find, plink);
			find->adbname = NULL;

			INSIST(!FIND_EVENTSENT(find));

			ev = &find->event;
			task = ev->ev_sender;
			ev->ev_sender = find;
			find->result_v4 = find_err_map[name->fetch_err];
			find->result_v6 = find_err_map[name->fetch6_err];
			ev->ev_type = evtype;
			ev->ev_destroy = event_freefind;
			ev->ev_destroy_arg = find;

			DP(DEF_LEVEL,
			   "cfan: sending event %p "
			   "to task %p for find %p",
			   ev, task, find);

			isc_task_sendanddetach(&task, (isc_event_t **)&ev);
			find->flags |= FIND_EVENT_SENT;
		} else {
			DP(DEF_LEVEL, "cfan: skipping find %p", find);
		}

		UNLOCK(&find->lock);
	}
	DP(ENTER_LEVEL, "EXIT clean_finds_at_name, name %p", name);
}

static dns_adbname_t *
new_adbname(dns_adb_t *adb, const dns_name_t *dnsname) {
	dns_adbname_t *name = NULL;

	name = isc_mem_get(adb->mctx, sizeof(*name));
	*name = (dns_adbname_t){
		.expire_v4 = INT_MAX,
		.expire_v6 = INT_MAX,
		.expire_target = INT_MAX,
		.fetch_err = FIND_ERR_UNEXPECTED,
		.fetch6_err = FIND_ERR_UNEXPECTED,
	};

	dns_adb_attach(adb, &name->adb);

	dns_name_init(&name->name, NULL);
	dns_name_dup(dnsname, adb->mctx, &name->name);
	dns_name_init(&name->target, NULL);

	ISC_LIST_INIT(name->v4);
	ISC_LIST_INIT(name->v6);

	ISC_LIST_INIT(name->finds);
	ISC_LINK_INIT(name, plink);

	name->magic = DNS_ADBNAME_MAGIC;

	inc_adbstats(adb, dns_adbstats_namescnt);

	return (name);
}

static void
free_adbname(dns_adbname_t **namep) {
	dns_adb_t *adb = NULL;
	dns_adbname_t *name = NULL;

	REQUIRE(namep != NULL && DNS_ADBNAME_VALID(*namep));

	name = *namep;
	*namep = NULL;

	REQUIRE(!NAME_HAS_V4(name));
	REQUIRE(!NAME_HAS_V6(name));
	REQUIRE(!NAME_FETCH(name));
	REQUIRE(ISC_LIST_EMPTY(name->finds));
	REQUIRE(!ISC_LINK_LINKED(name, plink));
	REQUIRE(name->bucket == NULL);

	name->magic = 0;

	adb = name->adb;
	dns_name_free(&name->name, adb->mctx);
	dec_adbstats(adb, dns_adbstats_namescnt);
	isc_mem_put(adb->mctx, name, sizeof(*name));
	dns_adb_detach(&adb);
}

static dns_adbnamebucket_t *
new_adbnamebucket(dns_adb_t *adb) {
	dns_adbnamebucket_t *nbucket = NULL;

	nbucket = isc_mem_get(adb->mctx, sizeof(*nbucket));
	*nbucket = (dns_adbnamebucket_t){
		.references = 0, /* workaround for old gcc */
	};

	ISC_LIST_INIT(nbucket->names);
	ISC_LIST_INIT(nbucket->deadnames);

	isc_mutex_init(&nbucket->lock);
	isc_refcount_init(&nbucket->references, 0);

	return (nbucket);
}

static dns_adbnamehook_t *
new_adbnamehook(dns_adb_t *adb, dns_adbentry_t *entry) {
	dns_adbnamehook_t *nh = NULL;

	nh = isc_mem_get(adb->mctx, sizeof(*nh));
	*nh = (dns_adbnamehook_t){ .entry = entry };

	ISC_LINK_INIT(nh, plink);

	nh->magic = DNS_ADBNAMEHOOK_MAGIC;
	return (nh);
}

static void
free_adbnamehook(dns_adb_t *adb, dns_adbnamehook_t **namehook) {
	dns_adbnamehook_t *nh = NULL;

	REQUIRE(namehook != NULL && DNS_ADBNAMEHOOK_VALID(*namehook));

	nh = *namehook;
	*namehook = NULL;

	REQUIRE(nh->entry == NULL);
	REQUIRE(!ISC_LINK_LINKED(nh, plink));

	nh->magic = 0;

	isc_mem_put(adb->mctx, nh, sizeof(*nh));
}

static dns_adblameinfo_t *
new_adblameinfo(dns_adb_t *adb, const dns_name_t *qname,
		dns_rdatatype_t qtype) {
	dns_adblameinfo_t *li = isc_mem_get(adb->mctx, sizeof(*li));

	dns_name_init(&li->qname, NULL);
	dns_name_dup(qname, adb->mctx, &li->qname);
	li->magic = DNS_ADBLAMEINFO_MAGIC;
	li->lame_timer = 0;
	li->qtype = qtype;
	ISC_LINK_INIT(li, plink);

	return (li);
}

static void
free_adblameinfo(dns_adb_t *adb, dns_adblameinfo_t **lameinfo) {
	dns_adblameinfo_t *li = NULL;

	REQUIRE(lameinfo != NULL && DNS_ADBLAMEINFO_VALID(*lameinfo));

	li = *lameinfo;
	*lameinfo = NULL;

	REQUIRE(!ISC_LINK_LINKED(li, plink));

	dns_name_free(&li->qname, adb->mctx);

	li->magic = 0;

	isc_mem_put(adb->mctx, li, sizeof(*li));
}

static dns_adbentry_t *
new_adbentry(dns_adb_t *adb) {
	dns_adbentry_t *entry = NULL;

	entry = isc_mem_get(adb->mctx, sizeof(*entry));
	*entry = (dns_adbentry_t){
		.srtt = isc_random_uniform(0x1f) + 1,
	};

	dns_adb_attach(adb, &entry->adb);

	isc_refcount_init(&entry->references, 1);
	atomic_init(&entry->active, 0);
	atomic_init(&entry->quota, adb->quota);

	ISC_LIST_INIT(entry->lameinfo);
	ISC_LINK_INIT(entry, plink);

	entry->magic = DNS_ADBENTRY_MAGIC;

	inc_adbstats(adb, dns_adbstats_entriescnt);

	return (entry);
}

static void
free_adbentry(dns_adbentry_t **entryp) {
	dns_adb_t *adb = NULL;
	dns_adbentry_t *entry = NULL;
	dns_adblameinfo_t *li = NULL;

	REQUIRE(entryp != NULL && DNS_ADBENTRY_VALID(*entryp));

	entry = *entryp;
	*entryp = NULL;

	REQUIRE(entry->bucket == NULL);
	REQUIRE(!ISC_LINK_LINKED(entry, plink));

	adb = entry->adb;

	entry->magic = 0;

	if (entry->cookie != NULL) {
		isc_mem_put(adb->mctx, entry->cookie, entry->cookielen);
	}

	li = ISC_LIST_HEAD(entry->lameinfo);
	while (li != NULL) {
		ISC_LIST_UNLINK(entry->lameinfo, li, plink);
		free_adblameinfo(adb, &li);
		li = ISC_LIST_HEAD(entry->lameinfo);
	}

	isc_refcount_destroy(&entry->references);
	dec_adbstats(adb, dns_adbstats_entriescnt);
	isc_mem_put(adb->mctx, entry, sizeof(*entry));
	dns_adb_detach(&adb);
}

static dns_adbentrybucket_t *
new_adbentrybucket(dns_adb_t *adb) {
	dns_adbentrybucket_t *ebucket = NULL;

	ebucket = isc_mem_get(adb->mctx, sizeof(*ebucket));
	*ebucket = (dns_adbentrybucket_t){
		.references = 0, /* workaround for old gcc */
	};

	ISC_LIST_INIT(ebucket->entries);
	ISC_LIST_INIT(ebucket->deadentries);

	isc_mutex_init(&ebucket->lock);
	isc_refcount_init(&ebucket->references, 0);

	return (ebucket);
}

static dns_adbfind_t *
new_adbfind(dns_adb_t *adb, in_port_t port) {
	dns_adbfind_t *find = NULL;

	find = isc_mem_get(adb->mctx, sizeof(*find));
	*find = (dns_adbfind_t){
		.port = port,
		.result_v4 = ISC_R_UNEXPECTED,
		.result_v6 = ISC_R_UNEXPECTED,
	};
	dns_adb_attach(adb, &find->adb);
	ISC_LINK_INIT(find, publink);
	ISC_LINK_INIT(find, plink);
	ISC_LIST_INIT(find->list);
	isc_mutex_init(&find->lock);
	ISC_EVENT_INIT(&find->event, sizeof(isc_event_t), 0, 0, 0, NULL, NULL,
		       NULL, NULL, find);

	find->magic = DNS_ADBFIND_MAGIC;

	return (find);
}

static void
free_adbfind(dns_adbfind_t **findp) {
	dns_adb_t *adb = NULL;
	dns_adbfind_t *find = NULL;

	REQUIRE(findp != NULL && DNS_ADBFIND_VALID(*findp));

	find = *findp;
	*findp = NULL;

	adb = find->adb;

	REQUIRE(!FIND_HAS_ADDRS(find));
	REQUIRE(!ISC_LINK_LINKED(find, publink));
	REQUIRE(!ISC_LINK_LINKED(find, plink));
	REQUIRE(find->adbname == NULL);

	find->magic = 0;

	isc_mutex_destroy(&find->lock);

	isc_mem_put(adb->mctx, find, sizeof(*find));
	dns_adb_detach(&adb);
}

static dns_adbfetch_t *
new_adbfetch(dns_adb_t *adb) {
	dns_adbfetch_t *fetch = NULL;

	fetch = isc_mem_get(adb->mctx, sizeof(*fetch));
	*fetch = (dns_adbfetch_t){ 0 };
	dns_rdataset_init(&fetch->rdataset);

	fetch->magic = DNS_ADBFETCH_MAGIC;

	return (fetch);
}

static void
free_adbfetch(dns_adb_t *adb, dns_adbfetch_t **fetchp) {
	dns_adbfetch_t *fetch = NULL;

	REQUIRE(fetchp != NULL && DNS_ADBFETCH_VALID(*fetchp));

	fetch = *fetchp;
	*fetchp = NULL;

	fetch->magic = 0;

	if (dns_rdataset_isassociated(&fetch->rdataset)) {
		dns_rdataset_disassociate(&fetch->rdataset);
	}

	isc_mem_put(adb->mctx, fetch, sizeof(*fetch));
}

/*
 * Copy bits from an adbentry into a newly allocated adb_addrinfo structure.
 * The entry must be locked, and its reference count must be incremented.
 */
static dns_adbaddrinfo_t *
new_adbaddrinfo(dns_adb_t *adb, dns_adbentry_t *entry, in_port_t port) {
	dns_adbaddrinfo_t *ai = NULL;

	ai = isc_mem_get(adb->mctx, sizeof(*ai));
	*ai = (dns_adbaddrinfo_t){ .srtt = entry->srtt,
				   .flags = entry->flags,
				   .dscp = -1 };

	ISC_LINK_INIT(ai, publink);
	entry_attach(entry, &ai->entry);
	ai->sockaddr = entry->sockaddr;
	isc_sockaddr_setport(&ai->sockaddr, port);

	ai->magic = DNS_ADBADDRINFO_MAGIC;

	return (ai);
}

static void
free_adbaddrinfo(dns_adb_t *adb, dns_adbaddrinfo_t **ainfo) {
	dns_adbaddrinfo_t *ai = NULL;

	REQUIRE(ainfo != NULL && DNS_ADBADDRINFO_VALID(*ainfo));

	ai = *ainfo;
	*ainfo = NULL;

	REQUIRE(!ISC_LINK_LINKED(ai, publink));

	ai->magic = 0;

	entry_detach(&ai->entry);

	isc_mem_put(adb->mctx, ai, sizeof(*ai));
}

/*
 * Search for the name bucket in the hash table.
 */
static void
get_namebucket(dns_adb_t *adb, const dns_name_t *name,
	       dns_adbnamebucket_t **nbucketp) {
	isc_result_t result;
	dns_adbnamebucket_t *nbucket = NULL;

	REQUIRE(nbucketp != NULL && *nbucketp == NULL);

	RWLOCK(&adb->names_lock, isc_rwlocktype_write);
	result = isc_ht_find(adb->namebuckets, name->ndata, name->length,
			     (void **)&nbucket);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * Allocate a new bucket and add it to the hash table.
		 */
		nbucket = new_adbnamebucket(adb);
		result = isc_ht_add(adb->namebuckets, name->ndata, name->length,
				    nbucket);
	}
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_write);
	INSIST(result == ISC_R_SUCCESS);

	*nbucketp = nbucket;
}

/*
 * Get the name from its bucket. The bucket must be locked.
 */
static dns_adbname_t *
get_name(dns_adbnamebucket_t *nbucket, const dns_name_t *name,
	 unsigned int options) {
	dns_adbname_t *adbname = ISC_LIST_HEAD(nbucket->names);
	while (adbname != NULL) {
		if (!NAME_DEAD(adbname)) {
			if (dns_name_equal(name, &adbname->name) &&
			    GLUEHINT_OK(adbname, options) &&
			    STARTATZONE_MATCHES(adbname, options))
			{
				return (adbname);
			}
		}
		adbname = ISC_LIST_NEXT(adbname, plink);
	}

	return (NULL);
}

/*
 * Search for the entry bucket for this address in the hash table.
 */
static void
get_entrybucket(dns_adb_t *adb, const isc_sockaddr_t *addr,
		dns_adbentrybucket_t **ebucketp) {
	isc_result_t result;
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(ebucketp != NULL && *ebucketp == NULL);

	RWLOCK(&adb->entries_lock, isc_rwlocktype_write);
	result = isc_ht_find(adb->entrybuckets, (const unsigned char *)addr,
			     sizeof(*addr), (void **)&ebucket);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * Allocate a new bucket and add it to the hash table.
		 */
		ebucket = new_adbentrybucket(adb);
		result = isc_ht_add(adb->entrybuckets,
				    (const unsigned char *)addr, sizeof(*addr),
				    ebucket);
	}
	RWUNLOCK(&adb->entries_lock, isc_rwlocktype_write);
	INSIST(result == ISC_R_SUCCESS);

	*ebucketp = ebucket;
}

/*
 * Find the entry from its bucket. The bucket must be locked.
 */
static dns_adbentry_t *
get_entry(dns_adbentrybucket_t *ebucket, const isc_sockaddr_t *addr,
	  isc_stdtime_t now) {
	dns_adbentry_t *entry = NULL, *entry_next = NULL;

	/* Search the list, while cleaning up expired entries. */
	for (entry = ISC_LIST_HEAD(ebucket->entries); entry != NULL;
	     entry = entry_next) {
		entry_next = ISC_LIST_NEXT(entry, plink);

		/* Address entries expire after 30 minutes. */
		maybe_expire_entry(&entry, now);
		if (entry != NULL && isc_sockaddr_equal(addr, &entry->sockaddr))
		{
			ISC_LIST_UNLINK(ebucket->entries, entry, plink);
			ISC_LIST_PREPEND(ebucket->entries, entry, plink);
			return (entry);
		}
	}

	return (NULL);
}

/*
 * The entry's bucket must be locked.
 */
static bool
entry_is_lame(dns_adb_t *adb, dns_adbentry_t *entry, const dns_name_t *qname,
	      dns_rdatatype_t qtype, isc_stdtime_t now) {
	dns_adblameinfo_t *li = NULL, *next_li = NULL;
	bool is_bad = false;

	li = ISC_LIST_HEAD(entry->lameinfo);
	if (li == NULL) {
		return (false);
	}
	while (li != NULL) {
		next_li = ISC_LIST_NEXT(li, plink);

		/*
		 * Has the entry expired?
		 */
		if (li->lame_timer < now) {
			ISC_LIST_UNLINK(entry->lameinfo, li, plink);
			free_adblameinfo(adb, &li);
		}

		/*
		 * Order tests from least to most expensive.
		 *
		 * We do not break out of the main loop here as
		 * we use the loop for house keeping.
		 */
		if (li != NULL && !is_bad && li->qtype == qtype &&
		    dns_name_equal(qname, &li->qname))
		{
			is_bad = true;
		}

		li = next_li;
	}

	return (is_bad);
}

static void
log_quota(dns_adbentry_t *entry, const char *fmt, ...) {
	va_list ap;
	char msgbuf[2048];
	char addrbuf[ISC_NETADDR_FORMATSIZE];
	isc_netaddr_t netaddr;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_netaddr_fromsockaddr(&netaddr, &entry->sockaddr);
	isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_ADB,
		      ISC_LOG_INFO,
		      "adb: quota %s (%" PRIuFAST32 "/%" PRIuFAST32 "): %s",
		      addrbuf, atomic_load_relaxed(&entry->active),
		      atomic_load_relaxed(&entry->quota), msgbuf);
}

static void
copy_namehook_lists(dns_adb_t *adb, dns_adbfind_t *find,
		    const dns_name_t *qname, dns_rdatatype_t qtype,
		    dns_adbname_t *name, isc_stdtime_t now) {
	dns_adbnamehook_t *namehook = NULL;
	dns_adbaddrinfo_t *addrinfo = NULL;
	dns_adbentry_t *entry = NULL;
	dns_adbentrybucket_t *ebucket = NULL;

	if ((find->options & DNS_ADBFIND_INET) != 0) {
		namehook = ISC_LIST_HEAD(name->v4);
		while (namehook != NULL) {
			entry = namehook->entry;
			ebucket = entry->bucket;
			INSIST(ebucket != NULL);
			LOCK(&ebucket->lock);

			if (dns_adbentry_overquota(entry)) {
				find->options |= (DNS_ADBFIND_LAMEPRUNED |
						  DNS_ADBFIND_OVERQUOTA);
				goto nextv4;
			}

			if (!FIND_RETURNLAME(find) &&
			    entry_is_lame(adb, entry, qname, qtype, now)) {
				find->options |= DNS_ADBFIND_LAMEPRUNED;
				goto nextv4;
			}

			addrinfo = new_adbaddrinfo(adb, entry, find->port);

			/*
			 * Found a valid entry.  Add it to the find's list.
			 */
			entry_attach(entry, &(dns_adbentry_t *){ NULL });
			ISC_LIST_APPEND(find->list, addrinfo, publink);
			addrinfo = NULL;
		nextv4:
			UNLOCK(&ebucket->lock);
			ebucket = NULL;
			namehook = ISC_LIST_NEXT(namehook, plink);
		}
	}

	if ((find->options & DNS_ADBFIND_INET6) != 0) {
		namehook = ISC_LIST_HEAD(name->v6);
		while (namehook != NULL) {
			entry = namehook->entry;
			ebucket = entry->bucket;
			INSIST(ebucket != NULL);
			LOCK(&ebucket->lock);

			if (dns_adbentry_overquota(entry)) {
				find->options |= (DNS_ADBFIND_LAMEPRUNED |
						  DNS_ADBFIND_OVERQUOTA);
				goto nextv6;
			}

			if (!FIND_RETURNLAME(find) &&
			    entry_is_lame(adb, entry, qname, qtype, now)) {
				find->options |= DNS_ADBFIND_LAMEPRUNED;
				goto nextv6;
			}
			addrinfo = new_adbaddrinfo(adb, entry, find->port);

			/*
			 * Found a valid entry.  Add it to the find's list.
			 */
			entry_attach(entry, &(dns_adbentry_t *){ NULL });
			ISC_LIST_APPEND(find->list, addrinfo, publink);
			addrinfo = NULL;
		nextv6:
			UNLOCK(&ebucket->lock);
			ebucket = NULL;
			namehook = ISC_LIST_NEXT(namehook, plink);
		}
	}

	if (ebucket != NULL) {
		UNLOCK(&ebucket->lock);
	}
}

/*
 * The name's bucket must be locked.
 */
static void
maybe_expire_name(dns_adbname_t **namep, isc_stdtime_t now) {
	dns_adbname_t *name = NULL;

	REQUIRE(namep != NULL && DNS_ADBNAME_VALID(*namep));

	name = *namep;

	/* Leave this name alone if it still has active namehooks... */
	if (NAME_HAS_V4(name) || NAME_HAS_V6(name)) {
		return;
	}

	/* ...an active fetch in progres... */
	if (NAME_FETCH(name)) {
		return;
	}

	/* ... or is not yet expired. */
	if (!EXPIRE_OK(name->expire_v4, now) ||
	    !EXPIRE_OK(name->expire_v6, now) ||
	    !EXPIRE_OK(name->expire_target, now))
	{
		return;
	}

	*namep = NULL;
	expire_name(&name, DNS_EVENT_ADBEXPIRED);
}

/*%
 * Examine the tail entry of the LRU list to see if it expires or is stale
 * (unused for some period); if so, the name entry will be freed.  If the ADB
 * is in the overmem condition, the tail and the next to tail entries
 * will be unconditionally removed (unless they have an outstanding fetch).
 * We don't care about a race on 'overmem' at the risk of causing some
 * collateral damage or a small delay in starting cleanup, so we don't bother
 * to lock ADB (if it's not locked).
 *
 * Name bucket must be locked; adb may be locked; no other locks held.
 */
static void
purge_stale_names(dns_adb_t *adb, dns_adbnamebucket_t *nbucket,
		  isc_stdtime_t now) {
	dns_adbname_t *adbname = NULL, *next_adbname = NULL;
	bool overmem = isc_mem_isovermem(adb->mctx);
	int max_removed = overmem ? 2 : 1;
	int scans = 0, removed = 0;

	REQUIRE(nbucket != NULL);

	/*
	 * We limit the number of scanned entries to 10 (arbitrary choice)
	 * in order to avoid examining too many entries when there are many
	 * tail entries that have fetches (this should be rare, but could
	 * happen).
	 */
	for (adbname = ISC_LIST_TAIL(nbucket->names);
	     adbname != NULL && removed < max_removed && scans < 10;
	     adbname = next_adbname)
	{
		INSIST(!NAME_DEAD(adbname));

		next_adbname = ISC_LIST_PREV(adbname, plink);
		scans++;

		/*
		 * Remove the name if it's expired or unused, has no
		 * address data, and there are no active fetches.
		 */
		maybe_expire_name(&adbname, now);
		if (adbname == NULL) {
			removed++;
			if (overmem) {
				continue;
			}
			break;
		}

		if (!NAME_FETCH(adbname) &&
		    (overmem || adbname->last_used + ADB_STALE_MARGIN <= now))
		{
			expire_name(&adbname, DNS_EVENT_ADBCANCELED);
			removed++;
		}
	}
}

/*
 * The entry's bucket must be locked.
 */
static void
maybe_expire_entry(dns_adbentry_t **entryp, isc_stdtime_t now) {
	dns_adbentry_t *entry = NULL;

	REQUIRE(entryp != NULL && DNS_ADBENTRY_VALID(*entryp));

	entry = *entryp;

	if (isc_refcount_current(&entry->references) > 1) {
		return;
	}

	if (entry->expires == 0 || entry->expires > now) {
		return;
	}

	/*
	 * The entry is not in use.  Delete it.
	 */
	*entryp = NULL;
	DP(DEF_LEVEL, "killing entry %p", entry);
	INSIST(ISC_LINK_LINKED(entry, plink));
	unlink_entry(entry);
	entry_detach(&entry);
}

/*
 * A read lock must be held on adb->names_lock.
 */
static void
cleanup_names(dns_adbnamebucket_t *nbucket, isc_stdtime_t now) {
	dns_adbname_t *name = NULL;

	DP(CLEAN_LEVEL, "cleaning name bucket %p", nbucket);

	LOCK(&nbucket->lock);
	name = ISC_LIST_HEAD(nbucket->names);
	while (name != NULL) {
		dns_adbname_t *next_name = ISC_LIST_NEXT(name, plink);
		/*
		 * Name hooks expire after the address record's TTL
		 * or 30 minutes, whichever is shorter. If after cleaning
		 * those up there are no name hooks left, and no active
		 * fetches, we can remove this name from the bucket.
		 */
		maybe_expire_namehooks(name, now);
		maybe_expire_name(&name, now);
		name = next_name;
	}
	UNLOCK(&nbucket->lock);
}

/*
 * A read lock must be held on adb->entries_lock.
 */
static void
cleanup_entries(dns_adbentrybucket_t *ebucket, isc_stdtime_t now) {
	dns_adbentry_t *entry = NULL;

	DP(CLEAN_LEVEL, "cleaning entry bucket %p", ebucket);

	LOCK(&ebucket->lock);
	entry = ISC_LIST_HEAD(ebucket->entries);
	while (entry != NULL) {
		dns_adbentry_t *next = ISC_LIST_NEXT(entry, plink);

		/* Address entries expire after 30 minutes. */
		maybe_expire_entry(&entry, now);
		entry = next;
	}
	UNLOCK(&ebucket->lock);
}

static void
clean_hashes(dns_adb_t *adb, isc_stdtime_t now) {
	isc_result_t result;
	isc_ht_iter_t *it = NULL;

	RWLOCK(&adb->names_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->namebuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(it))
	{
		dns_adbnamebucket_t *nbucket = NULL;
		isc_ht_iter_current(it, (void **)&nbucket);
		cleanup_names(nbucket, now);
	}
	isc_ht_iter_destroy(&it);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);

	RWLOCK(&adb->entries_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->entrybuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(it))
	{
		dns_adbentrybucket_t *ebucket = NULL;
		isc_ht_iter_current(it, (void **)&ebucket);
		cleanup_entries(ebucket, now);
	}
	isc_ht_iter_destroy(&it);
	RWUNLOCK(&adb->entries_lock, isc_rwlocktype_read);
}

static void
destroy(dns_adb_t *adb) {
	isc_result_t result;
	isc_ht_iter_t *it = NULL;

	DP(DEF_LEVEL, "destroying ADB %p", adb);

	adb->magic = 0;

	RWLOCK(&adb->names_lock, isc_rwlocktype_write);
	isc_ht_iter_create(adb->namebuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_delcurrent_next(it))
	{
		dns_adbnamebucket_t *nbucket = NULL;
		isc_ht_iter_current(it, (void **)&nbucket);
		cleanup_names(nbucket, INT_MAX);
		isc_mutex_destroy(&nbucket->lock);
		isc_refcount_destroy(&nbucket->references);
		isc_mem_put(adb->mctx, nbucket, sizeof(*nbucket));
	}
	isc_ht_iter_destroy(&it);
	isc_ht_destroy(&adb->namebuckets);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_write);
	isc_rwlock_destroy(&adb->names_lock);

	RWLOCK(&adb->entries_lock, isc_rwlocktype_write);
	isc_ht_iter_create(adb->entrybuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_delcurrent_next(it))
	{
		dns_adbentrybucket_t *ebucket = NULL;
		isc_ht_iter_current(it, (void **)&ebucket);
		cleanup_entries(ebucket, INT_MAX);
		isc_mutex_destroy(&ebucket->lock);
		isc_refcount_destroy(&ebucket->references);
		isc_mem_put(adb->mctx, ebucket, sizeof(*ebucket));
	}
	isc_ht_iter_destroy(&it);
	isc_ht_destroy(&adb->entrybuckets);
	RWUNLOCK(&adb->entries_lock, isc_rwlocktype_write);
	isc_rwlock_destroy(&adb->entries_lock);

	isc_mutex_destroy(&adb->lock);
	isc_refcount_destroy(&adb->references);

	isc_task_detach(&adb->task);
	isc_stats_detach(&adb->stats);
	dns_resolver_detach(&adb->res);
	dns_view_weakdetach(&adb->view);
	isc_mem_putanddetach(&adb->mctx, adb, sizeof(dns_adb_t));
}

/*
 * Public functions.
 */

isc_result_t
dns_adb_create(isc_mem_t *mem, dns_view_t *view, isc_taskmgr_t *taskmgr,
	       dns_adb_t **newadb) {
	dns_adb_t *adb = NULL;
	isc_result_t result;

	REQUIRE(mem != NULL);
	REQUIRE(view != NULL);
	REQUIRE(taskmgr != NULL);
	REQUIRE(newadb != NULL && *newadb == NULL);

	adb = isc_mem_get(mem, sizeof(dns_adb_t));
	*adb = (dns_adb_t){
		.taskmgr = taskmgr,
	};

	/*
	 * Initialize things here that cannot fail, and especially things
	 * that must be NULL for the error return to work properly.
	 */
	isc_refcount_init(&adb->references, 1);
	dns_view_weakattach(view, &adb->view);
	dns_resolver_attach(view->resolver, &adb->res);
	isc_mem_attach(mem, &adb->mctx);

	isc_ht_init(&adb->namebuckets, adb->mctx, 1, ISC_HT_CASE_INSENSITIVE);
	isc_rwlock_init(&adb->names_lock, 0, 0);

	isc_ht_init(&adb->entrybuckets, adb->mctx, 1, ISC_HT_CASE_SENSITIVE);
	isc_rwlock_init(&adb->entries_lock, 0, 0);

	isc_mutex_init(&adb->lock);

	/*
	 * Allocate an internal task.
	 */
	result = isc_task_create(adb->taskmgr, 0, &adb->task, 0);
	if (result != ISC_R_SUCCESS) {
		goto free_lock;
	}

	isc_task_setname(adb->task, "ADB", adb);

	result = isc_stats_create(adb->mctx, &adb->stats, dns_adbstats_max);
	if (result != ISC_R_SUCCESS) {
		goto free_task;
	}

	set_adbstat(adb, isc_ht_count(adb->namebuckets), dns_adbstats_nnames);
	set_adbstat(adb, isc_ht_count(adb->entrybuckets),
		    dns_adbstats_nentries);

	/*
	 * Normal return.
	 */
	adb->magic = DNS_ADB_MAGIC;
	*newadb = adb;
	return (ISC_R_SUCCESS);

free_task:
	isc_task_detach(&adb->task);

free_lock:
	isc_mutex_destroy(&adb->lock);

	isc_rwlock_destroy(&adb->entries_lock);
	isc_ht_destroy(&adb->entrybuckets);

	isc_rwlock_destroy(&adb->names_lock);
	isc_ht_destroy(&adb->namebuckets);

	dns_resolver_detach(&adb->res);
	dns_view_weakdetach(&adb->view);
	isc_mem_putanddetach(&adb->mctx, adb, sizeof(dns_adb_t));

	return (result);
}

void
dns__adb_attach(dns_adb_t *adb, dns_adb_t **adbp, const char *func,
		const char *file, unsigned int line) {
	uint_fast32_t refs;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(adbp != NULL && *adbp == NULL);

	refs = isc_refcount_increment(&adb->references);
#ifdef ADB_TRACE
	fprintf(stderr, "%s:%s:%u:%s(%p, %p) = %" PRIuFAST32 "\n", func, file,
		line, __func__, adb, adbp, refs + 1);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
	UNUSED(refs);
#endif /* ADB_TRACE */

	*adbp = adb;
}

void
dns__adb_detach(dns_adb_t **adbp, const char *func, const char *file,
		unsigned int line) {
	dns_adb_t *adb = NULL;
	uint_fast32_t refs;

	REQUIRE(adbp != NULL && DNS_ADB_VALID(*adbp));

	adb = *adbp;
	*adbp = NULL;

	refs = isc_refcount_decrement(&adb->references);
#ifdef ADB_TRACE
	fprintf(stderr, "%s:%s:%u:%s(%p, %p), %" PRIuFAST32 "\n", func, file,
		line, __func__, adb, adbp, refs - 1);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif /* ADB_TRACE */

	if (refs == 1) {
		destroy(adb);
	}
}

void
dns_adb_shutdown(dns_adb_t *adb) {
	if (!atomic_compare_exchange_strong(&adb->exiting, &(bool){ false },
					    true)) {
		return;
	}

	DP(DEF_LEVEL, "shutting down ADB %p", adb);

	isc_mem_clearwater(adb->mctx);

	shutdown_names(adb);
	shutdown_entries(adb);
}

/*
 * Look up the name in our internal database.
 *
 * There are three possibilities. Note that these are not always exclusive.
 *
 * - No name found.  In this case, allocate a new name header and
 *   an initial namehook or two.
 *
 * - Name found, valid addresses present.  Allocate one addrinfo
 *   structure for each found and append it to the linked list
 *   of addresses for this header.
 *
 * - Name found, queries pending.  In this case, if a task was
 *   passed in, allocate a job id, attach it to the name's job
 *   list and remember to tell the caller that there will be
 *   more info coming later.
 */
isc_result_t
dns_adb_createfind(dns_adb_t *adb, isc_task_t *task, isc_taskaction_t action,
		   void *arg, const dns_name_t *name, const dns_name_t *qname,
		   dns_rdatatype_t qtype, unsigned int options,
		   isc_stdtime_t now, dns_name_t *target, in_port_t port,
		   unsigned int depth, isc_counter_t *qc,
		   dns_adbfind_t **findp) {
	isc_result_t result = ISC_R_UNEXPECTED;
	dns_adbfind_t *find = NULL;
	dns_adbname_t *adbname = NULL;
	dns_adbnamebucket_t *nbucket = NULL;
	bool want_event = true;
	bool start_at_zone = false;
	bool alias = false;
	bool have_address = false;
	unsigned int wanted_addresses = (options & DNS_ADBFIND_ADDRESSMASK);
	unsigned int wanted_fetches = 0;
	unsigned int query_pending = 0;
	char namebuf[DNS_NAME_FORMATSIZE] = { 0 };

	REQUIRE(DNS_ADB_VALID(adb));
	if (task != NULL) {
		REQUIRE(action != NULL);
	}
	REQUIRE(name != NULL);
	REQUIRE(qname != NULL);
	REQUIRE(findp != NULL && *findp == NULL);
	REQUIRE(target == NULL || dns_name_hasbuffer(target));

	REQUIRE((options & DNS_ADBFIND_ADDRESSMASK) != 0);

	if (atomic_load(&adb->exiting)) {
		DP(DEF_LEVEL, "dns_adb_createfind: returning "
			      "ISC_R_SHUTTINGDOWN");

		return (ISC_R_SHUTTINGDOWN);
	}

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	/*
	 * Remember what types of addresses we are interested in.
	 */
	find = new_adbfind(adb, port);
	find->options = options;
	find->flags |= wanted_addresses;
	if (FIND_WANTEVENT(find)) {
		REQUIRE(task != NULL);
	}

	if (isc_log_wouldlog(dns_lctx, DEF_LEVEL)) {
		dns_name_format(name, namebuf, sizeof(namebuf));
	}

	/*
	 * Try to see if we know anything about this name at all.
	 */
	get_namebucket(adb, name, &nbucket);
	INSIST(nbucket != NULL);
	LOCK(&nbucket->lock);
	adbname = get_name(nbucket, name, find->options);
	if (adbname == NULL) {
		/*
		 * Nothing found.  Allocate a new adbname structure for
		 * this name. First, see if there are stale names at the
		 * end of the list, and purge them if so.
		 */
		purge_stale_names(adb, nbucket, now);

		adbname = new_adbname(adb, name);
		link_name(nbucket, adbname);
		if (FIND_HINTOK(find)) {
			adbname->flags |= NAME_HINT_OK;
		}
		if (FIND_GLUEOK(find)) {
			adbname->flags |= NAME_GLUE_OK;
		}
		if (FIND_STARTATZONE(find)) {
			adbname->flags |= NAME_STARTATZONE;
		}
	} else {
		/* Move this name forward in the LRU list */
		ISC_LIST_UNLINK(nbucket->names, adbname, plink);
		ISC_LIST_PREPEND(nbucket->names, adbname, plink);
	}

	adbname->last_used = now;

	/*
	 * Name hooks expire after the address record's TTL or 30 minutes,
	 * whichever is shorter. If there are expired name hooks, remove
	 * them so we'll send a new fetch.
	 */
	maybe_expire_namehooks(adbname, now);

	/*
	 * Do we know that the name is an alias?
	 */
	if (!EXPIRE_OK(adbname->expire_target, now)) {
		/*
		 * Yes, it is.
		 */
		DP(DEF_LEVEL,
		   "dns_adb_createfind: name %s (%p) is an alias (cached)",
		   namebuf, adbname);
		alias = true;
		goto post_copy;
	}

	/*
	 * Try to populate the name from the database and/or
	 * start fetches.  First try looking for an A record
	 * in the database.
	 */
	if (!NAME_HAS_V4(adbname) && EXPIRE_OK(adbname->expire_v4, now) &&
	    WANT_INET(wanted_addresses))
	{
		result = dbfind_name(adbname, now, dns_rdatatype_a);
		switch (result) {
		case ISC_R_SUCCESS:
			/* Found an A; now we proceed to check for AAAA */
			DP(DEF_LEVEL,
			   "dns_adb_createfind: found A for name %s (%p) in db",
			   namebuf, adbname);
			break;

		case DNS_R_ALIAS:
			/* Got a CNAME or DNAME. */
			DP(DEF_LEVEL,
			   "dns_adb_createfind: name %s (%p) is an alias",
			   namebuf, adbname);
			alias = true;
			goto post_copy;

		case DNS_R_NXDOMAIN:
		case DNS_R_NCACHENXDOMAIN:
			/*
			 * If the name doesn't exist at all, don't bother with
			 * v6 queries; they won't work.
			 */
			goto fetch;

		case DNS_R_NXRRSET:
		case DNS_R_NCACHENXRRSET:
		case DNS_R_HINTNXRRSET:
			/*
			 * The name does exist but we didn't get our data, go
			 * ahead and try AAAA.
			 */
			break;

		default:
			/*
			 * Any other result, start a fetch for A, then fall
			 * through to AAAA.
			 */
			if (!NAME_FETCH_A(adbname)) {
				wanted_fetches |= DNS_ADBFIND_INET;
			}
			break;
		}
	}

	/*
	 * Now look up or start fetches for AAAA.
	 */
	if (!NAME_HAS_V6(adbname) && EXPIRE_OK(adbname->expire_v6, now) &&
	    WANT_INET6(wanted_addresses))
	{
		result = dbfind_name(adbname, now, dns_rdatatype_aaaa);
		switch (result) {
		case ISC_R_SUCCESS:
			DP(DEF_LEVEL,
			   "dns_adb_createfind: found AAAA for name %s (%p)",
			   namebuf, adbname);
			break;

		case DNS_R_ALIAS:
			/* Got a CNAME or DNAME. */
			DP(DEF_LEVEL,
			   "dns_adb_createfind: name %s (%p) is an alias",
			   namebuf, adbname);
			alias = true;
			goto post_copy;

		case DNS_R_NXDOMAIN:
		case DNS_R_NCACHENXDOMAIN:
		case DNS_R_NXRRSET:
		case DNS_R_NCACHENXRRSET:
			/*
			 * Name doens't exist or was found in the negative
			 * cache to have no AAAA, don't bother fetching.
			 */
			break;

		default:
			/*
			 * Any other result, start a fetch for AAAA.
			 */
			if (!NAME_FETCH_AAAA(adbname)) {
				wanted_fetches |= DNS_ADBFIND_INET6;
			}
			break;
		}
	}

fetch:
	if ((WANT_INET(wanted_addresses) && NAME_HAS_V4(adbname)) ||
	    (WANT_INET6(wanted_addresses) && NAME_HAS_V6(adbname)))
	{
		have_address = true;
	} else {
		have_address = false;
	}
	if (wanted_fetches != 0 && !(FIND_AVOIDFETCHES(find) && have_address) &&
	    !FIND_NOFETCH(find))
	{
		/*
		 * We're missing at least one address family.  Either the
		 * caller hasn't instructed us to avoid fetches, or we don't
		 * know anything about any of the address families that would
		 * be acceptable so we have to launch fetches.
		 */

		if (FIND_STARTATZONE(find)) {
			start_at_zone = true;
		}

		/*
		 * Start V4.
		 */
		if (WANT_INET(wanted_fetches) &&
		    fetch_name(adbname, start_at_zone, depth, qc,
			       dns_rdatatype_a) == ISC_R_SUCCESS)
		{
			DP(DEF_LEVEL,
			   "dns_adb_createfind: "
			   "started A fetch for name %s (%p)",
			   namebuf, adbname);
		}

		/*
		 * Start V6.
		 */
		if (WANT_INET6(wanted_fetches) &&
		    fetch_name(adbname, start_at_zone, depth, qc,
			       dns_rdatatype_aaaa) == ISC_R_SUCCESS)
		{
			DP(DEF_LEVEL,
			   "dns_adb_createfind: "
			   "started AAAA fetch for name %s (%p)",
			   namebuf, adbname);
		}
	}

	/*
	 * Run through the name and copy out the bits we are
	 * interested in.
	 */
	copy_namehook_lists(adb, find, qname, qtype, adbname, now);

post_copy:
	if (NAME_FETCH_A(adbname)) {
		query_pending |= DNS_ADBFIND_INET;
	}
	if (NAME_FETCH_AAAA(adbname)) {
		query_pending |= DNS_ADBFIND_INET6;
	}

	/*
	 * Attach to the name's query list if there are queries
	 * already running, and we have been asked to.
	 */
	if (!FIND_WANTEVENT(find)) {
		want_event = false;
	}
	if (FIND_WANTEMPTYEVENT(find) && FIND_HAS_ADDRS(find)) {
		want_event = false;
	}
	if ((wanted_addresses & query_pending) == 0) {
		want_event = false;
	}
	if (alias) {
		want_event = false;
	}
	if (want_event) {
		bool empty;

		find->adbname = adbname;
		empty = ISC_LIST_EMPTY(adbname->finds);
		ISC_LIST_APPEND(adbname->finds, find, plink);
		find->query_pending = (query_pending & wanted_addresses);
		find->flags &= ~DNS_ADBFIND_ADDRESSMASK;
		find->flags |= (find->query_pending & DNS_ADBFIND_ADDRESSMASK);
		DP(DEF_LEVEL, "createfind: attaching find %p to adbname %p %d",
		   find, adbname, empty);
	} else {
		/*
		 * Remove the flag so the caller knows there will never
		 * be an event, and set internal flags to fake that
		 * the event was sent and freed, so dns_adb_destroyfind() will
		 * do the right thing.
		 */
		find->query_pending = (query_pending & wanted_addresses);
		find->options &= ~DNS_ADBFIND_WANTEVENT;
		find->flags |= (FIND_EVENT_SENT | FIND_EVENT_FREED);
		find->flags &= ~DNS_ADBFIND_ADDRESSMASK;
	}

	find->partial_result |= (adbname->partial_result & wanted_addresses);
	if (alias) {
		if (target != NULL) {
			dns_name_copy(&adbname->target, target);
		}
		result = DNS_R_ALIAS;
	} else {
		result = ISC_R_SUCCESS;
	}

	/*
	 * Copy out error flags from the name structure into the find.
	 */
	find->result_v4 = find_err_map[adbname->fetch_err];
	find->result_v6 = find_err_map[adbname->fetch6_err];

	if (want_event) {
		INSIST((find->flags & DNS_ADBFIND_ADDRESSMASK) != 0);
		isc_task_attach(task, &(isc_task_t *){ NULL });
		find->event.ev_sender = task;
		find->event.ev_action = action;
		find->event.ev_arg = arg;
	}

	*findp = find;

	UNLOCK(&nbucket->lock);
	return (result);
}

void
dns_adb_destroyfind(dns_adbfind_t **findp) {
	dns_adbfind_t *find = NULL;
	dns_adbaddrinfo_t *ai = NULL;
	dns_adb_t *adb = NULL;

	REQUIRE(findp != NULL && DNS_ADBFIND_VALID(*findp));

	find = *findp;
	*findp = NULL;

	DP(DEF_LEVEL, "dns_adb_destroyfind on find %p", find);

	adb = find->adb;

	LOCK(&find->lock);

	REQUIRE(FIND_EVENTFREED(find));
	REQUIRE(find->adbname == NULL);

	/*
	 * Free the addrinfo objects on the find's list. Note that
	 * we also need to decrement the reference counter in the
	 * associated adbentry every time we remove one from the list.
	 */
	ai = ISC_LIST_HEAD(find->list);
	while (ai != NULL) {
		entry_detach(&(dns_adbentry_t *){ ai->entry });
		ISC_LIST_UNLINK(find->list, ai, publink);
		free_adbaddrinfo(adb, &ai);
		ai = ISC_LIST_HEAD(find->list);
	}
	UNLOCK(&find->lock);

	free_adbfind(&find);
}

/*
 * Caller must hold find lock.
 */
static void
find_sendevent(dns_adbfind_t *find) {
	if (!FIND_EVENTSENT(find)) {
		isc_event_t *ev = &find->event;
		isc_task_t *task = ev->ev_sender;

		ev->ev_sender = find;
		ev->ev_type = DNS_EVENT_ADBCANCELED;
		ev->ev_destroy = event_freefind;
		ev->ev_destroy_arg = find;
		find->result_v4 = ISC_R_CANCELED;
		find->result_v6 = ISC_R_CANCELED;

		DP(DEF_LEVEL, "sending event %p to task %p for find %p", ev,
		   task, find);

		isc_task_sendanddetach(&task, (isc_event_t **)&ev);
	}
}

void
dns_adb_cancelfind(dns_adbfind_t *find) {
	dns_adbname_t *adbname = NULL;

	DP(DEF_LEVEL, "dns_adb_cancelfind on find %p", find);

	REQUIRE(DNS_ADBFIND_VALID(find));
	REQUIRE(DNS_ADB_VALID(find->adb));

	LOCK(&find->lock);
	REQUIRE(!FIND_EVENTFREED(find));
	REQUIRE(FIND_WANTEVENT(find));

	adbname = find->adbname;

	if (adbname == NULL) {
		find_sendevent(find);
		UNLOCK(&find->lock);
	} else {
		/*
		 * Release the find lock, then acquire the bucket and find
		 * locks in that order, to match locking hierarchy
		 * elsewhere.
		 */
		UNLOCK(&find->lock);
		LOCK(&adbname->bucket->lock);
		LOCK(&find->lock);

		if (find->adbname != NULL) {
			ISC_LIST_UNLINK(adbname->finds, find, plink);
			find->adbname = NULL;
		}
		find_sendevent(find);

		UNLOCK(&find->lock);
		UNLOCK(&adbname->bucket->lock);
	}
}

void
dns_adb_dump(dns_adb_t *adb, FILE *f) {
	isc_stdtime_t now;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(f != NULL);

	if (atomic_load(&adb->exiting)) {
		return;
	}

	isc_stdtime_get(&now);
	clean_hashes(adb, now);
	dump_adb(adb, f, false, now);
}

static void
dump_ttl(FILE *f, const char *legend, isc_stdtime_t value, isc_stdtime_t now) {
	if (value == INT_MAX) {
		return;
	}
	fprintf(f, " [%s TTL %d]", legend, (int)(value - now));
}

/*
 * Both rwlocks for the hash tables need to be held by the caller.
 */
static void
dump_adb(dns_adb_t *adb, FILE *f, bool debug, isc_stdtime_t now) {
	isc_result_t result;
	isc_ht_iter_t *it = NULL;

	fprintf(f, ";\n; Address database dump\n;\n");
	fprintf(f, "; [edns success/timeout]\n");
	fprintf(f, "; [plain success/timeout]\n;\n");
	if (debug) {
		fprintf(f, "; addr %p, references %" PRIuFAST32 "\n", adb,
			isc_refcount_current(&adb->references));
	}

	/*
	 * Ensure this operation is applied to both hash tables at once.
	 */
	RWLOCK(&adb->names_lock, isc_rwlocktype_read);

	isc_ht_iter_create(adb->namebuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(it))
	{
		dns_adbnamebucket_t *nbucket = NULL;
		dns_adbname_t *name = NULL;

		isc_ht_iter_current(it, (void **)&nbucket);
		LOCK(&nbucket->lock);
		if (debug) {
			static int n = 0;
			fprintf(f, "; bucket %d\n", n);
			n++;
		}

		/*
		 * Dump the names
		 */
		for (name = ISC_LIST_HEAD(nbucket->names); name != NULL;
		     name = ISC_LIST_NEXT(name, plink))
		{
			if (debug) {
				fprintf(f, "; name %p (flags %08x)\n", name,
					name->flags);
			}
			fprintf(f, "; ");
			dns_name_print(&name->name, f);
			if (dns_name_countlabels(&name->target) > 0) {
				fprintf(f, " alias ");
				dns_name_print(&name->target, f);
			}

			dump_ttl(f, "v4", name->expire_v4, now);
			dump_ttl(f, "v6", name->expire_v6, now);
			dump_ttl(f, "target", name->expire_target, now);

			fprintf(f, " [v4 %s] [v6 %s]",
				errnames[name->fetch_err],
				errnames[name->fetch6_err]);

			fprintf(f, "\n");

			print_namehook_list(f, "v4", adb, &name->v4, debug,
					    now);
			print_namehook_list(f, "v6", adb, &name->v6, debug,
					    now);

			if (debug) {
				print_fetch_list(f, name);
				print_find_list(f, name);
			}
		}
		UNLOCK(&nbucket->lock);
	}
	isc_ht_iter_destroy(&it);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);

	fprintf(f, ";\n; Unassociated entries\n;\n");

	RWLOCK(&adb->entries_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->entrybuckets, &it);
	for (result = isc_ht_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(it))
	{
		dns_adbentrybucket_t *ebucket = NULL;
		dns_adbentry_t *entry = NULL;

		isc_ht_iter_current(it, (void **)&ebucket);
		LOCK(&ebucket->lock);

		for (entry = ISC_LIST_HEAD(ebucket->entries); entry != NULL;
		     entry = ISC_LIST_NEXT(entry, plink))
		{
			if (entry->nh == 0) {
				dump_entry(f, adb, entry, debug, now);
			}
		}
		UNLOCK(&ebucket->lock);
	}
	isc_ht_iter_destroy(&it);

	RWUNLOCK(&adb->entries_lock, isc_rwlocktype_read);
}

static void
dump_entry(FILE *f, dns_adb_t *adb, dns_adbentry_t *entry, bool debug,
	   isc_stdtime_t now) {
	char addrbuf[ISC_NETADDR_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];
	isc_netaddr_t netaddr;
	dns_adblameinfo_t *li = NULL;

	isc_netaddr_fromsockaddr(&netaddr, &entry->sockaddr);
	isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));

	if (debug) {
		fprintf(f, ";\t%p: refcnt %" PRIuFAST32 "\n", entry,
			isc_refcount_current(&entry->references));
	}

	fprintf(f,
		";\t%s [srtt %u] [flags %08x] [edns %u/%u] "
		"[plain %u/%u]",
		addrbuf, entry->srtt, entry->flags, entry->edns, entry->ednsto,
		entry->plain, entry->plainto);
	if (entry->udpsize != 0U) {
		fprintf(f, " [udpsize %u]", entry->udpsize);
	}
	if (entry->cookie != NULL) {
		unsigned int i;
		fprintf(f, " [cookie=");
		for (i = 0; i < entry->cookielen; i++) {
			fprintf(f, "%02x", entry->cookie[i]);
		}
		fprintf(f, "]");
	}
	if (entry->expires != 0) {
		fprintf(f, " [ttl %d]", (int)(entry->expires - now));
	}

	if (adb != NULL && adb->quota != 0 && adb->atr_freq != 0) {
		uint_fast32_t quota = atomic_load_relaxed(&entry->quota);
		fprintf(f, " [atr %0.2f] [quota %" PRIuFAST32 "]", entry->atr,
			quota);
	}

	fprintf(f, "\n");
	for (li = ISC_LIST_HEAD(entry->lameinfo); li != NULL;
	     li = ISC_LIST_NEXT(li, plink))
	{
		fprintf(f, ";\t\t");
		dns_name_print(&li->qname, f);
		dns_rdatatype_format(li->qtype, typebuf, sizeof(typebuf));
		fprintf(f, " %s [lame TTL %d]\n", typebuf,
			(int)(li->lame_timer - now));
	}
}

static void
dumpfind(dns_adbfind_t *find, FILE *f) {
	char tmp[512];
	const char *tmpp = NULL;
	dns_adbaddrinfo_t *ai = NULL;
	isc_sockaddr_t *sa = NULL;

	/*
	 * Not used currently, in the API Just In Case we
	 * want to dump out the name and/or entries too.
	 */

	LOCK(&find->lock);

	fprintf(f, ";Find %p\n", find);
	fprintf(f, ";\tqpending %08x partial %08x options %08x flags %08x\n",
		find->query_pending, find->partial_result, find->options,
		find->flags);
	fprintf(f, ";\tname bucket %p, name %p, event sender %p\n",
		find->adbname->bucket, find->adbname, find->event.ev_sender);

	ai = ISC_LIST_HEAD(find->list);
	if (ai != NULL) {
		fprintf(f, "\tAddresses:\n");
	}
	while (ai != NULL) {
		sa = &ai->sockaddr;
		switch (sa->type.sa.sa_family) {
		case AF_INET:
			tmpp = inet_ntop(AF_INET, &sa->type.sin.sin_addr, tmp,
					 sizeof(tmp));
			break;
		case AF_INET6:
			tmpp = inet_ntop(AF_INET6, &sa->type.sin6.sin6_addr,
					 tmp, sizeof(tmp));
			break;
		default:
			tmpp = "UnkFamily";
		}

		if (tmpp == NULL) {
			tmpp = "BadAddress";
		}

		fprintf(f,
			"\t\tentry %p, flags %08x"
			" srtt %u addr %s\n",
			ai->entry, ai->flags, ai->srtt, tmpp);

		ai = ISC_LIST_NEXT(ai, publink);
	}

	UNLOCK(&find->lock);
}

static void
print_namehook_list(FILE *f, const char *legend, dns_adb_t *adb,
		    dns_adbnamehooklist_t *list, bool debug,
		    isc_stdtime_t now) {
	dns_adbnamehook_t *nh = NULL;

	for (nh = ISC_LIST_HEAD(*list); nh != NULL;
	     nh = ISC_LIST_NEXT(nh, plink)) {
		if (debug) {
			fprintf(f, ";\tHook(%s) %p\n", legend, nh);
		}
		dump_entry(f, adb, nh->entry, debug, now);
	}
}

static void
print_fetch(FILE *f, dns_adbfetch_t *ft, const char *type) {
	fprintf(f, "\t\tFetch(%s): %p -> { fetch %p }\n", type, ft, ft->fetch);
}

static void
print_fetch_list(FILE *f, dns_adbname_t *n) {
	if (NAME_FETCH_A(n)) {
		print_fetch(f, n->fetch_a, "A");
	}
	if (NAME_FETCH_AAAA(n)) {
		print_fetch(f, n->fetch_aaaa, "AAAA");
	}
}

static void
print_find_list(FILE *f, dns_adbname_t *name) {
	dns_adbfind_t *find = NULL;

	find = ISC_LIST_HEAD(name->finds);
	while (find != NULL) {
		dumpfind(find, f);
		find = ISC_LIST_NEXT(find, plink);
	}
}

static isc_result_t
dbfind_name(dns_adbname_t *adbname, isc_stdtime_t now, dns_rdatatype_t rdtype) {
	isc_result_t result;
	dns_rdataset_t rdataset;
	dns_adb_t *adb = NULL;
	dns_fixedname_t foundname;
	dns_name_t *fname = NULL;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(rdtype == dns_rdatatype_a || rdtype == dns_rdatatype_aaaa);

	fname = dns_fixedname_initname(&foundname);
	dns_rdataset_init(&rdataset);

	if (rdtype == dns_rdatatype_a) {
		adbname->fetch_err = FIND_ERR_UNEXPECTED;
	} else {
		adbname->fetch6_err = FIND_ERR_UNEXPECTED;
	}

	/*
	 * We need to specify whether to search static-stub zones (if
	 * configured) depending on whether this is a "start at zone" lookup,
	 * i.e., whether it's a "bailiwick" glue.  If it's bailiwick (in which
	 * case NAME_STARTATZONE is set) we need to stop the search at any
	 * matching static-stub zone without looking into the cache to honor
	 * the configuration on which server we should send queries to.
	 */
	result = dns_view_find(adb->view, &adbname->name, rdtype, now,
			       NAME_GLUEOK(adbname) ? DNS_DBFIND_GLUEOK : 0,
			       NAME_HINTOK(adbname),
			       ((adbname->flags & NAME_STARTATZONE) != 0), NULL,
			       NULL, fname, &rdataset, NULL);

	/* XXXVIX this switch statement is too sparse to gen a jump table. */
	switch (result) {
	case DNS_R_GLUE:
	case DNS_R_HINT:
	case ISC_R_SUCCESS:
		/*
		 * Found in the database.  Even if we can't copy out
		 * any information, return success, or else a fetch
		 * will be made, which will only make things worse.
		 */
		if (rdtype == dns_rdatatype_a) {
			adbname->fetch_err = FIND_ERR_SUCCESS;
		} else {
			adbname->fetch6_err = FIND_ERR_SUCCESS;
		}
		result = import_rdataset(adbname, &rdataset, now);
		break;
	case DNS_R_NXDOMAIN:
	case DNS_R_NXRRSET:
		/*
		 * We're authoritative and the data doesn't exist.
		 * Make up a negative cache entry so we don't ask again
		 * for a while.
		 *
		 * XXXRTH  What time should we use?  I'm putting in 30 seconds
		 * for now.
		 */
		if (rdtype == dns_rdatatype_a) {
			adbname->expire_v4 = now + 30;
			DP(NCACHE_LEVEL,
			   "adb name %p: Caching auth negative entry for A",
			   adbname);
			if (result == DNS_R_NXDOMAIN) {
				adbname->fetch_err = FIND_ERR_NXDOMAIN;
			} else {
				adbname->fetch_err = FIND_ERR_NXRRSET;
			}
		} else {
			DP(NCACHE_LEVEL,
			   "adb name %p: Caching auth negative entry for AAAA",
			   adbname);
			adbname->expire_v6 = now + 30;
			if (result == DNS_R_NXDOMAIN) {
				adbname->fetch6_err = FIND_ERR_NXDOMAIN;
			} else {
				adbname->fetch6_err = FIND_ERR_NXRRSET;
			}
		}
		break;
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		/*
		 * We found a negative cache entry.  Pull the TTL from it
		 * so we won't ask again for a while.
		 */
		rdataset.ttl = ttlclamp(rdataset.ttl);
		if (rdtype == dns_rdatatype_a) {
			adbname->expire_v4 = rdataset.ttl + now;
			if (result == DNS_R_NCACHENXDOMAIN) {
				adbname->fetch_err = FIND_ERR_NXDOMAIN;
			} else {
				adbname->fetch_err = FIND_ERR_NXRRSET;
			}
			DP(NCACHE_LEVEL,
			   "adb name %p: Caching negative entry for A (ttl %u)",
			   adbname, rdataset.ttl);
		} else {
			DP(NCACHE_LEVEL,
			   "adb name %p: Caching negative entry for AAAA (ttl "
			   "%u)",
			   adbname, rdataset.ttl);
			adbname->expire_v6 = rdataset.ttl + now;
			if (result == DNS_R_NCACHENXDOMAIN) {
				adbname->fetch6_err = FIND_ERR_NXDOMAIN;
			} else {
				adbname->fetch6_err = FIND_ERR_NXRRSET;
			}
		}
		break;
	case DNS_R_CNAME:
	case DNS_R_DNAME:
		/*
		 * Clear the hint and glue flags, so this will match
		 * more often.
		 */
		adbname->flags &= ~(DNS_ADBFIND_GLUEOK | DNS_ADBFIND_HINTOK);

		rdataset.ttl = ttlclamp(rdataset.ttl);
		clean_target(adb, &adbname->target);
		adbname->expire_target = INT_MAX;
		result = set_target(adb, &adbname->name, fname, &rdataset,
				    &adbname->target);
		if (result == ISC_R_SUCCESS) {
			result = DNS_R_ALIAS;
			DP(NCACHE_LEVEL, "adb name %p: caching alias target",
			   adbname);
			adbname->expire_target = rdataset.ttl + now;
		}
		if (rdtype == dns_rdatatype_a) {
			adbname->fetch_err = FIND_ERR_SUCCESS;
		} else {
			adbname->fetch6_err = FIND_ERR_SUCCESS;
		}
		break;
	default:
		break;
	}

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	return (result);
}

static void
fetch_callback(isc_task_t *task, isc_event_t *ev) {
	dns_fetchevent_t *dev = (dns_fetchevent_t *)ev;
	dns_adbname_t *name = NULL;
	dns_adb_t *adb = NULL;
	dns_adbfetch_t *fetch = NULL;
	dns_adbnamebucket_t *nbucket = NULL;
	isc_eventtype_t ev_status;
	isc_stdtime_t now;
	isc_result_t result;
	unsigned int address_type;

	UNUSED(task);

	REQUIRE(ev->ev_type == DNS_EVENT_FETCHDONE);
	name = ev->ev_arg;

	REQUIRE(DNS_ADBNAME_VALID(name));
	dns_adb_attach(name->adb, &adb);

	REQUIRE(DNS_ADB_VALID(adb));

	nbucket = name->bucket;
	LOCK(&nbucket->lock);

	INSIST(NAME_FETCH_A(name) || NAME_FETCH_AAAA(name));
	address_type = 0;
	if (NAME_FETCH_A(name) && (name->fetch_a->fetch == dev->fetch)) {
		address_type = DNS_ADBFIND_INET;
		fetch = name->fetch_a;
		name->fetch_a = NULL;
	} else if (NAME_FETCH_AAAA(name) &&
		   (name->fetch_aaaa->fetch == dev->fetch)) {
		address_type = DNS_ADBFIND_INET6;
		fetch = name->fetch_aaaa;
		name->fetch_aaaa = NULL;
	} else {
		fetch = NULL;
	}

	INSIST(address_type != 0 && fetch != NULL);

	ev_status = DNS_EVENT_ADBNOMOREADDRESSES;

	/*
	 * Cleanup things we don't care about.
	 */
	if (dev->node != NULL) {
		dns_db_detachnode(dev->db, &dev->node);
	}
	if (dev->db != NULL) {
		dns_db_detach(&dev->db);
	}

	/*
	 * If this name is marked as dead, clean up, throwing away
	 * potentially good data.
	 */
	if (NAME_DEAD(name)) {
		ev_status = DNS_EVENT_ADBCANCELED;
		goto out;
	}

	isc_stdtime_get(&now);

	/*
	 * If we got a negative cache response, remember it.
	 */
	if (NCACHE_RESULT(dev->result)) {
		dev->rdataset->ttl = ttlclamp(dev->rdataset->ttl);
		if (address_type == DNS_ADBFIND_INET) {
			DP(NCACHE_LEVEL,
			   "adb fetch name %p: "
			   "caching negative entry for A (ttl %u)",
			   name, dev->rdataset->ttl);
			name->expire_v4 = ISC_MIN(name->expire_v4,
						  dev->rdataset->ttl + now);
			if (dev->result == DNS_R_NCACHENXDOMAIN) {
				name->fetch_err = FIND_ERR_NXDOMAIN;
			} else {
				name->fetch_err = FIND_ERR_NXRRSET;
			}
			inc_resstats(adb, dns_resstatscounter_gluefetchv4fail);
		} else {
			DP(NCACHE_LEVEL,
			   "adb fetch name %p: "
			   "caching negative entry for AAAA (ttl %u)",
			   name, dev->rdataset->ttl);
			name->expire_v6 = ISC_MIN(name->expire_v6,
						  dev->rdataset->ttl + now);
			if (dev->result == DNS_R_NCACHENXDOMAIN) {
				name->fetch6_err = FIND_ERR_NXDOMAIN;
			} else {
				name->fetch6_err = FIND_ERR_NXRRSET;
			}
			inc_resstats(adb, dns_resstatscounter_gluefetchv6fail);
		}
		goto out;
	}

	/*
	 * Handle CNAME/DNAME.
	 */
	if (dev->result == DNS_R_CNAME || dev->result == DNS_R_DNAME) {
		dev->rdataset->ttl = ttlclamp(dev->rdataset->ttl);
		clean_target(adb, &name->target);
		name->expire_target = INT_MAX;
		result = set_target(adb, &name->name, dev->foundname,
				    dev->rdataset, &name->target);
		if (result == ISC_R_SUCCESS) {
			DP(NCACHE_LEVEL,
			   "adb fetch name %p: caching alias target", name);
			name->expire_target = dev->rdataset->ttl + now;
		}
		goto check_result;
	}

	/*
	 * Did we get back junk?  If so, and there are no more fetches
	 * sitting out there, tell all the finds about it.
	 */
	if (dev->result != ISC_R_SUCCESS) {
		char buf[DNS_NAME_FORMATSIZE];

		dns_name_format(&name->name, buf, sizeof(buf));
		DP(DEF_LEVEL, "adb: fetch of '%s' %s failed: %s", buf,
		   address_type == DNS_ADBFIND_INET ? "A" : "AAAA",
		   isc_result_totext(dev->result));
		/*
		 * Don't record a failure unless this is the initial
		 * fetch of a chain.
		 */
		if (fetch->depth > 1) {
			goto out;
		}
		/* XXXMLG Don't pound on bad servers. */
		if (address_type == DNS_ADBFIND_INET) {
			name->expire_v4 = ISC_MIN(name->expire_v4, now + 10);
			name->fetch_err = FIND_ERR_FAILURE;
			inc_resstats(adb, dns_resstatscounter_gluefetchv4fail);
		} else {
			name->expire_v6 = ISC_MIN(name->expire_v6, now + 10);
			name->fetch6_err = FIND_ERR_FAILURE;
			inc_resstats(adb, dns_resstatscounter_gluefetchv6fail);
		}
		goto out;
	}

	/*
	 * We got something potentially useful.
	 */
	result = import_rdataset(name, &fetch->rdataset, now);

check_result:
	if (result == ISC_R_SUCCESS) {
		ev_status = DNS_EVENT_ADBMOREADDRESSES;
		if (address_type == DNS_ADBFIND_INET) {
			name->fetch_err = FIND_ERR_SUCCESS;
		} else {
			name->fetch6_err = FIND_ERR_SUCCESS;
		}
	}

out:
	dns_resolver_destroyfetch(&fetch->fetch);
	free_adbfetch(adb, &fetch);
	isc_event_free(&ev);
	if (ev_status == DNS_EVENT_ADBCANCELED) {
		expire_name(&name, ev_status);
	} else {
		clean_finds_at_name(name, ev_status, address_type);
	}
	UNLOCK(&nbucket->lock);
	dns_adb_detach(&adb);
}

static isc_result_t
fetch_name(dns_adbname_t *adbname, bool start_at_zone, unsigned int depth,
	   isc_counter_t *qc, dns_rdatatype_t type) {
	isc_result_t result;
	dns_adbfetch_t *fetch = NULL;
	dns_adb_t *adb = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	dns_rdataset_t rdataset;
	dns_rdataset_t *nameservers = NULL;
	unsigned int options;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	REQUIRE((type == dns_rdatatype_a && !NAME_FETCH_A(adbname)) ||
		(type == dns_rdatatype_aaaa && !NAME_FETCH_AAAA(adbname)));

	adbname->fetch_err = FIND_ERR_NOTFOUND;

	dns_rdataset_init(&rdataset);

	options = DNS_FETCHOPT_NOVALIDATE;
	if (start_at_zone) {
		DP(ENTER_LEVEL, "fetch_name: starting at zone for name %p",
		   adbname);
		name = dns_fixedname_initname(&fixed);
		result = dns_view_findzonecut(adb->view, &adbname->name, name,
					      NULL, 0, 0, true, false,
					      &rdataset, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_HINT) {
			goto cleanup;
		}
		nameservers = &rdataset;
		options |= DNS_FETCHOPT_UNSHARED;
	}

	fetch = new_adbfetch(adb);
	fetch->depth = depth;

	/*
	 * We're not minimizing this query, as nothing user-related should
	 * be leaked here.
	 * However, if we'd ever want to change it we'd have to modify
	 * createfetch to find deepest cached name when we're providing
	 * domain and nameservers.
	 */
	result = dns_resolver_createfetch(
		adb->res, &adbname->name, type, name, nameservers, NULL, NULL,
		0, options, depth, qc, adb->task, fetch_callback, adbname,
		&fetch->rdataset, NULL, &fetch->fetch);
	if (result != ISC_R_SUCCESS) {
		DP(ENTER_LEVEL, "fetch_name: createfetch failed with %s",
		   isc_result_totext(result));
		goto cleanup;
	}

	if (type == dns_rdatatype_a) {
		adbname->fetch_a = fetch;
		inc_resstats(adb, dns_resstatscounter_gluefetchv4);
	} else {
		adbname->fetch_aaaa = fetch;
		inc_resstats(adb, dns_resstatscounter_gluefetchv6);
	}
	fetch = NULL; /* Keep us from cleaning this up below. */

cleanup:
	if (fetch != NULL) {
		free_adbfetch(adb, &fetch);
	}
	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	return (result);
}

isc_result_t
dns_adb_marklame(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		 const dns_name_t *qname, dns_rdatatype_t qtype,
		 isc_stdtime_t expire_time) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_adblameinfo_t *li = NULL;
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));
	REQUIRE(qname != NULL);

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);
	li = ISC_LIST_HEAD(addr->entry->lameinfo);
	while (li != NULL &&
	       (li->qtype != qtype || !dns_name_equal(qname, &li->qname))) {
		li = ISC_LIST_NEXT(li, plink);
	}
	if (li != NULL) {
		if (expire_time > li->lame_timer) {
			li->lame_timer = expire_time;
		}
		goto unlock;
	}
	li = new_adblameinfo(adb, qname, qtype);
	li->lame_timer = expire_time;

	ISC_LIST_PREPEND(addr->entry->lameinfo, li, plink);

unlock:
	UNLOCK(&ebucket->lock);
	return (result);
}

void
dns_adb_adjustsrtt(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int rtt,
		   unsigned int factor) {
	dns_adbentrybucket_t *ebucket = NULL;
	isc_stdtime_t now = 0;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));
	REQUIRE(factor <= 10);

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	if (addr->entry->expires == 0 || factor == DNS_ADB_RTTADJAGE) {
		isc_stdtime_get(&now);
	}
	adjustsrtt(addr, rtt, factor, now);

	UNLOCK(&ebucket->lock);
}

void
dns_adb_agesrtt(dns_adb_t *adb, dns_adbaddrinfo_t *addr, isc_stdtime_t now) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	adjustsrtt(addr, 0, DNS_ADB_RTTADJAGE, now);

	UNLOCK(&ebucket->lock);
}

static void
adjustsrtt(dns_adbaddrinfo_t *addr, unsigned int rtt, unsigned int factor,
	   isc_stdtime_t now) {
	uint64_t new_srtt;

	if (factor == DNS_ADB_RTTADJAGE) {
		if (addr->entry->lastage != now) {
			new_srtt = addr->entry->srtt;
			new_srtt <<= 9;
			new_srtt -= addr->entry->srtt;
			new_srtt >>= 9;
			addr->entry->lastage = now;
		} else {
			new_srtt = addr->entry->srtt;
		}
	} else {
		new_srtt = ((uint64_t)addr->entry->srtt / 10 * factor) +
			   ((uint64_t)rtt / 10 * (10 - factor));
	}

	addr->entry->srtt = (unsigned int)new_srtt;
	addr->srtt = (unsigned int)new_srtt;

	if (addr->entry->expires == 0) {
		addr->entry->expires = now + ADB_ENTRY_WINDOW;
	}
}

void
dns_adb_changeflags(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int bits,
		    unsigned int mask) {
	dns_adbentrybucket_t *ebucket = NULL;
	isc_stdtime_t now;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	REQUIRE((bits & ENTRY_IS_DEAD) == 0);
	REQUIRE((mask & ENTRY_IS_DEAD) == 0);

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	addr->entry->flags = (addr->entry->flags & ~mask) | (bits & mask);
	if (addr->entry->expires == 0) {
		isc_stdtime_get(&now);
		addr->entry->expires = now + ADB_ENTRY_WINDOW;
	}

	/*
	 * Note that we do not update the other bits in addr->flags with
	 * the most recent values from addr->entry->flags.
	 */
	addr->flags = (addr->flags & ~mask) | (bits & mask);

	UNLOCK(&ebucket->lock);
}

/*
 * The polynomial backoff curve (10000 / ((10 + n) / 10)^(3/2)) <0..99> drops
 * fairly aggressively at first, then slows down and tails off at around 2-3%.
 *
 * These will be used to make quota adjustments.
 */
static int quota_adj[] = {
	10000, 8668, 7607, 6747, 6037, 5443, 4941, 4512, 4141, 3818, 3536,
	3286,  3065, 2867, 2690, 2530, 2385, 2254, 2134, 2025, 1925, 1832,
	1747,  1668, 1595, 1527, 1464, 1405, 1350, 1298, 1250, 1205, 1162,
	1121,  1083, 1048, 1014, 981,  922,  894,  868,	 843,  820,  797,
	775,   755,  735,  716,	 698,  680,  664,  648,	 632,  618,  603,
	590,   577,  564,  552,	 540,  529,  518,  507,	 497,  487,  477,
	468,   459,  450,  442,	 434,  426,  418,  411,	 404,  397,  390,
	383,   377,  370,  364,	 358,  353,  347,  342,	 336,  331,  326,
	321,   316,  312,  307,	 303,  298,  294,  290,	 286,  282,  278
};

#define QUOTA_ADJ_SIZE (sizeof(quota_adj) / sizeof(quota_adj[0]))

/*
 * The adb entry associated with 'addr' must be locked.
 */
static void
maybe_adjust_quota(dns_adb_t *adb, dns_adbaddrinfo_t *addr, bool timeout) {
	double tr;

	UNUSED(adb);

	if (adb->quota == 0 || adb->atr_freq == 0) {
		return;
	}

	if (timeout) {
		addr->entry->timeouts++;
	}

	if (addr->entry->completed++ <= adb->atr_freq) {
		return;
	}

	/*
	 * Calculate an exponential rolling average of the timeout ratio
	 *
	 * XXX: Integer arithmetic might be better than floating point
	 */
	tr = (double)addr->entry->timeouts / addr->entry->completed;
	addr->entry->timeouts = addr->entry->completed = 0;
	INSIST(addr->entry->atr >= 0.0);
	INSIST(addr->entry->atr <= 1.0);
	INSIST(adb->atr_discount >= 0.0);
	INSIST(adb->atr_discount <= 1.0);
	addr->entry->atr *= 1.0 - adb->atr_discount;
	addr->entry->atr += tr * adb->atr_discount;
	addr->entry->atr = ISC_CLAMP(addr->entry->atr, 0.0, 1.0);

	if (addr->entry->atr < adb->atr_low && addr->entry->mode > 0) {
		uint_fast32_t new_quota =
			adb->quota * quota_adj[--addr->entry->mode] / 10000;
		atomic_store_release(&addr->entry->quota,
				     ISC_MAX(1, new_quota));
		log_quota(addr->entry,
			  "atr %0.2f, quota increased to %" PRIuFAST32,
			  addr->entry->atr, new_quota);
	} else if (addr->entry->atr > adb->atr_high &&
		   addr->entry->mode < (QUOTA_ADJ_SIZE - 1))
	{
		uint_fast32_t new_quota =
			adb->quota * quota_adj[++addr->entry->mode] / 10000;
		atomic_store_release(&addr->entry->quota,
				     ISC_MAX(1, new_quota));
		log_quota(addr->entry,
			  "atr %0.2f, quota decreased to %" PRIuFAST32,
			  addr->entry->atr, new_quota);
	}
}

#define EDNSTOS 3U

void
dns_adb_plainresponse(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	maybe_adjust_quota(adb, addr, false);

	addr->entry->plain++;
	if (addr->entry->plain == 0xff) {
		addr->entry->edns >>= 1;
		addr->entry->ednsto >>= 1;
		addr->entry->plain >>= 1;
		addr->entry->plainto >>= 1;
	}
	UNLOCK(&ebucket->lock);
}

void
dns_adb_timeout(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	maybe_adjust_quota(adb, addr, true);

	addr->entry->plainto++;
	if (addr->entry->plainto == 0xff) {
		addr->entry->edns >>= 1;
		addr->entry->ednsto >>= 1;
		addr->entry->plain >>= 1;
		addr->entry->plainto >>= 1;
	}
	UNLOCK(&ebucket->lock);
}

void
dns_adb_ednsto(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	maybe_adjust_quota(adb, addr, true);

	addr->entry->ednsto++;
	if (addr->entry->ednsto == 0xff) {
		addr->entry->edns >>= 1;
		addr->entry->ednsto >>= 1;
		addr->entry->plain >>= 1;
		addr->entry->plainto >>= 1;
	}
	UNLOCK(&ebucket->lock);
}

void
dns_adb_setudpsize(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int size) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);
	if (size < 512U) {
		size = 512U;
	}
	if (size > addr->entry->udpsize) {
		addr->entry->udpsize = size;
	}

	maybe_adjust_quota(adb, addr, false);

	addr->entry->edns++;
	if (addr->entry->edns == 0xff) {
		addr->entry->edns >>= 1;
		addr->entry->ednsto >>= 1;
		addr->entry->plain >>= 1;
		addr->entry->plainto >>= 1;
	}
	UNLOCK(&ebucket->lock);
}

unsigned int
dns_adb_getudpsize(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	dns_adbentrybucket_t *ebucket = NULL;
	unsigned int size;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);
	size = addr->entry->udpsize;
	UNLOCK(&ebucket->lock);

	return (size);
}

void
dns_adb_setcookie(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		  const unsigned char *cookie, size_t len) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);

	if (addr->entry->cookie != NULL &&
	    (cookie == NULL || len != addr->entry->cookielen))
	{
		isc_mem_put(adb->mctx, addr->entry->cookie,
			    addr->entry->cookielen);
		addr->entry->cookie = NULL;
		addr->entry->cookielen = 0;
	}

	if (addr->entry->cookie == NULL && cookie != NULL && len != 0U) {
		addr->entry->cookie = isc_mem_get(adb->mctx, len);
		addr->entry->cookielen = (uint16_t)len;
	}

	if (addr->entry->cookie != NULL) {
		memmove(addr->entry->cookie, cookie, len);
	}
	UNLOCK(&ebucket->lock);
}

size_t
dns_adb_getcookie(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		  unsigned char *cookie, size_t len) {
	dns_adbentrybucket_t *ebucket = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	ebucket = addr->entry->bucket;
	LOCK(&ebucket->lock);
	if (cookie != NULL && addr->entry->cookie != NULL &&
	    len >= addr->entry->cookielen)
	{
		memmove(cookie, addr->entry->cookie, addr->entry->cookielen);
		len = addr->entry->cookielen;
	} else {
		len = 0;
	}
	UNLOCK(&ebucket->lock);

	return (len);
}

isc_result_t
dns_adb_findaddrinfo(dns_adb_t *adb, const isc_sockaddr_t *sa,
		     dns_adbaddrinfo_t **addrp, isc_stdtime_t now) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_adbentrybucket_t *ebucket = NULL;
	dns_adbentry_t *entry = NULL;
	dns_adbaddrinfo_t *addr = NULL;
	in_port_t port;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(addrp != NULL && *addrp == NULL);

	if (atomic_load(&adb->exiting)) {
		return (ISC_R_SHUTTINGDOWN);
	}

	get_entrybucket(adb, sa, &ebucket);
	INSIST(ebucket != NULL);
	LOCK(&ebucket->lock);

	entry = get_entry(ebucket, sa, now);
	if (entry == NULL) {
		/*
		 * We don't know anything about this address.
		 */
		entry = new_adbentry(adb);
		entry->sockaddr = *sa;
		link_entry(ebucket, entry);
		DP(ENTER_LEVEL, "findaddrinfo: new entry %p", entry);
	} else {
		/* Move entry to the head of the LRU list */
		ISC_LIST_UNLINK(ebucket->entries, entry, plink);
		ISC_LIST_PREPEND(ebucket->entries, entry, plink);
		DP(ENTER_LEVEL, "findaddrinfo: found entry %p", entry);
	}

	port = isc_sockaddr_getport(sa);
	addr = new_adbaddrinfo(adb, entry, port);
	*addrp = addr;

	UNLOCK(&ebucket->lock);
	return (result);
}

void
dns_adb_freeaddrinfo(dns_adb_t *adb, dns_adbaddrinfo_t **addrp) {
	dns_adbaddrinfo_t *addr = NULL;
	dns_adbentry_t *entry = NULL;
	isc_stdtime_t now;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(addrp != NULL);

	addr = *addrp;
	*addrp = NULL;

	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	entry = addr->entry;

	REQUIRE(DNS_ADBENTRY_VALID(entry));

	if (entry->expires == 0) {
		isc_stdtime_get(&now);
		entry->expires = now + ADB_ENTRY_WINDOW;
	}

	free_adbaddrinfo(adb, &addr);
}

void
dns_adb_flush(dns_adb_t *adb) {
	REQUIRE(DNS_ADB_VALID(adb));

	if (atomic_load(&adb->exiting)) {
		return;
	}

	clean_hashes(adb, INT_MAX);
#ifdef DUMP_ADB_AFTER_CLEANING
	dump_adb(adb, stdout, true, INT_MAX);
#endif /* ifdef DUMP_ADB_AFTER_CLEANING */
}

void
dns_adb_flushname(dns_adb_t *adb, const dns_name_t *name) {
	dns_adbname_t *adbname = NULL;
	dns_adbname_t *nextname = NULL;
	dns_adbnamebucket_t *nbucket = NULL;
	isc_result_t result;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(name != NULL);

	if (atomic_load(&adb->exiting)) {
		return;
	}

	RWLOCK(&adb->names_lock, isc_rwlocktype_read);
	result = isc_ht_find(adb->namebuckets, name->ndata, name->length,
			     (void **)&nbucket);
	if (result != ISC_R_SUCCESS) {
		RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);
		return;
	}

	LOCK(&nbucket->lock);
	adbname = ISC_LIST_HEAD(nbucket->names);
	while (adbname != NULL) {
		nextname = ISC_LIST_NEXT(adbname, plink);
		if (!NAME_DEAD(adbname) && dns_name_equal(name, &adbname->name))
		{
			expire_name(&adbname, DNS_EVENT_ADBCANCELED);
		}
		adbname = nextname;
	}
	UNLOCK(&nbucket->lock);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);
}

void
dns_adb_flushnames(dns_adb_t *adb, const dns_name_t *name) {
	isc_result_t result;
	isc_ht_iter_t *iter = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(name != NULL);

	if (atomic_load(&adb->exiting)) {
		return;
	}

	RWLOCK(&adb->names_lock, isc_rwlocktype_read);
	isc_ht_iter_create(adb->namebuckets, &iter);
	for (result = isc_ht_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_ht_iter_next(iter))
	{
		dns_adbnamebucket_t *nbucket = NULL;
		dns_adbname_t *adbname = NULL, *nextname = NULL;

		isc_ht_iter_current(iter, (void **)&nbucket);
		LOCK(&nbucket->lock);
		adbname = ISC_LIST_HEAD(nbucket->names);
		while (adbname != NULL) {
			nextname = ISC_LIST_NEXT(adbname, plink);
			if (!NAME_DEAD(adbname) &&
			    dns_name_issubdomain(&adbname->name, name)) {
				expire_name(&adbname, DNS_EVENT_ADBCANCELED);
			}
			adbname = nextname;
		}
		UNLOCK(&nbucket->lock);
	}
	isc_ht_iter_destroy(&iter);
	RWUNLOCK(&adb->names_lock, isc_rwlocktype_read);
}

static void
water(void *arg, int mark) {
	dns_adb_t *adb = arg;
	bool overmem = (mark == ISC_MEM_HIWATER);

	/*
	 * We're going to change the way to handle overmem condition: use
	 * isc_mem_isovermem() instead of storing the state via this callback,
	 * since the latter way tends to cause race conditions.
	 * To minimize the change, and in case we re-enable the callback
	 * approach, however, keep this function at the moment.
	 */

	REQUIRE(DNS_ADB_VALID(adb));

	DP(ISC_LOG_DEBUG(1), "adb reached %s water mark",
	   overmem ? "high" : "low");
}

void
dns_adb_setadbsize(dns_adb_t *adb, size_t size) {
	size_t hiwater, lowater;

	REQUIRE(DNS_ADB_VALID(adb));

	if (size != 0U && size < DNS_ADB_MINADBSIZE) {
		size = DNS_ADB_MINADBSIZE;
	}

	hiwater = size - (size >> 3); /* Approximately 7/8ths. */
	lowater = size - (size >> 2); /* Approximately 3/4ths. */

	if (size == 0U || hiwater == 0U || lowater == 0U) {
		isc_mem_clearwater(adb->mctx);
	} else {
		isc_mem_setwater(adb->mctx, water, adb, hiwater, lowater);
	}
}

void
dns_adb_setquota(dns_adb_t *adb, uint32_t quota, uint32_t freq, double low,
		 double high, double discount) {
	REQUIRE(DNS_ADB_VALID(adb));

	adb->quota = quota;
	adb->atr_freq = freq;
	adb->atr_low = low;
	adb->atr_high = high;
	adb->atr_discount = discount;
}

bool
dns_adbentry_overquota(dns_adbentry_t *entry) {
	uint_fast32_t quota, active;

	REQUIRE(DNS_ADBENTRY_VALID(entry));

	quota = atomic_load_relaxed(&entry->quota);
	active = atomic_load_acquire(&entry->active);

	return (quota != 0 && active >= quota);
}

void
dns_adb_beginudpfetch(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	uint_fast32_t active;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	active = atomic_fetch_add_relaxed(&addr->entry->active, 1);
	INSIST(active != UINT32_MAX);
}

void
dns_adb_endudpfetch(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	uint_fast32_t active;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	active = atomic_fetch_sub_release(&addr->entry->active, 1);
	INSIST(active != 0);
}

isc_stats_t *
dns_adb_getstats(dns_adb_t *adb) {
	REQUIRE(DNS_ADB_VALID(adb));

	return (adb->stats);
}
