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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/attributes.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mutex.h>
#include <isc/netaddr.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/sieve.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/tid.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/adb.h>
#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/stats.h>
#include <dns/transport.h>
#include <dns/types.h>

#define DNS_ADB_MAGIC		 ISC_MAGIC('D', 'a', 'd', 'b')
#define DNS_ADB_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADB_MAGIC)
#define DNS_ADBNAME_MAGIC	 ISC_MAGIC('a', 'd', 'b', 'N')
#define DNS_ADBNAME_VALID(x)	 ISC_MAGIC_VALID(x, DNS_ADBNAME_MAGIC)
#define DNS_ADBNAMEHOOK_MAGIC	 ISC_MAGIC('a', 'd', 'N', 'H')
#define DNS_ADBNAMEHOOK_VALID(x) ISC_MAGIC_VALID(x, DNS_ADBNAMEHOOK_MAGIC)
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
#define ADB_ENTRY_WINDOW  60	/*%< seconds */

#define ADB_HASH_SIZE (1 << 12)

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
typedef ISC_LIST(dns_adbentry_t) dns_adbentrylist_t;
typedef struct dns_adbfetch dns_adbfetch_t;
typedef struct dns_adbfetch6 dns_adbfetch6_t;

typedef struct dns_adblru {
	ISC_SIEVE(dns_adbname_t) names;
	ISC_SIEVE(dns_adbentry_t) entries;

	uint8_t __padding[ISC_OS_CACHELINE_SIZE -
			  (sizeof(ISC_SIEVE(dns_adbname_t)) +
			   sizeof(ISC_SIEVE(dns_adbentry_t))) %
				  ISC_OS_CACHELINE_SIZE];
} dns_adblru_t;

/*% dns adb structure */
struct dns_adb {
	unsigned int magic;
	uint32_t nloops;

	isc_mutex_t lock;
	isc_mem_t *mctx;
	isc_mem_t *hmctx;
	dns_view_t *view;
	dns_resolver_t *res;

	isc_refcount_t references;

	dns_adblru_t *lru;

	struct cds_lfht *names_ht;
	struct cds_lfht *entries_ht;

	isc_stats_t *stats;

	atomic_bool shuttingdown;

	uint32_t quota;
	uint32_t atr_freq;
	double atr_low;
	double atr_high;
	double atr_discount;

	struct rcu_head rcu_head;
};

/*%
 * dns_adbname structure:
 *
 * This is the structure representing a nameserver name; it can be looked
 * up via the adb->names hash table. It holds references to fetches
 * for A and AAAA records while they are ongoing (fetch_a, fetch_aaaa), and
 * lists of records pointing to address information when the fetches are
 * complete (v4, v6).
 */
struct dns_adbname {
	unsigned int magic;
	isc_refcount_t references;
	dns_adb_t *adb;
	dns_fixedname_t fname;
	dns_name_t *name;
	unsigned int partial_result;
	unsigned int flags;
	unsigned int type;
	isc_stdtime_t expire_v4;
	isc_stdtime_t expire_v6;
	dns_adbnamehooklist_t v4;
	dns_adbnamehooklist_t v6;
	dns_adbfetch_t *fetch_a;
	dns_adbfetch_t *fetch_aaaa;
	unsigned int fetch_err;
	unsigned int fetch6_err;
	dns_adbfindlist_t finds;
	isc_mutex_t lock;

	/* for LFHT */
	struct cds_lfht_node ht_node;

	/* for LRU-based management */
	ISC_LINK(dns_adbname_t) link;
	bool visited;

	isc_loop_t *loop;
	struct rcu_head rcu_head;
	struct cds_list_head lru_head;
};

#if DNS_ADB_TRACE
#define dns_adbname_ref(ptr) dns_adbname__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_adbname_unref(ptr) \
	dns_adbname__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_adbname_attach(ptr, ptrp) \
	dns_adbname__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_adbname_detach(ptrp) \
	dns_adbname__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_adbname);
#else
ISC_REFCOUNT_DECL(dns_adbname);
#endif

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
	ISC_LINK(dns_adbnamehook_t) name_link;
	ISC_LINK(dns_adbnamehook_t) entry_link;
};

/*%
 * dns_adbentry structure:
 *
 * This is the structure representing a nameserver address; it can be looked
 * up via the adb->entries hash table. Also, each dns_adbnamehook and
 * and dns_adbaddrinfo object will contain a pointer to one of these.
 *
 * The structure holds quite a bit of information about addresses,
 * including edns state (in "flags"), RTT, and of course the address of
 * the host.
 */
struct dns_adbentry {
	unsigned int magic;

	dns_adb_t *adb;

	isc_mutex_t lock;

	isc_refcount_t references;
	dns_adbnamehooklist_t nhs;

	atomic_uint flags;
	atomic_uint srtt;
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
	_Atomic(isc_stdtime_t) lastage;
	/*%<
	 * A nonzero 'expires' field indicates that the entry should
	 * persist until that time.  This allows entries found
	 * using dns_adb_findaddrinfo() to persist for a limited time
	 * even though they are not necessarily associated with a
	 * entry.
	 */

	struct cds_lfht_node ht_node;

	ISC_LINK(dns_adbentry_t) link;
	bool visited;

	isc_loop_t *loop;
	struct rcu_head rcu_head;
	struct cds_list_head lru_head;
};

#if DNS_ADB_TRACE
#define dns_adbentry_ref(ptr) \
	dns_adbentry__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_adbentry_unref(ptr) \
	dns_adbentry__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_adbentry_attach(ptr, ptrp) \
	dns_adbentry__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_adbentry_detach(ptrp) \
	dns_adbentry__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_adbentry);
#else
ISC_REFCOUNT_DECL(dns_adbentry);
#endif

/*
 * Internal functions (and prototypes).
 */
static dns_adbname_t *
new_adbname(dns_adb_t *adb, const dns_name_t *, unsigned int type);
static void
destroy_adbname(dns_adbname_t *);
static int
match_adbname(struct cds_lfht_node *ht_node, const void *key);
static uint32_t
hash_adbname(const dns_adbname_t *adbname);
static dns_adbnamehook_t *
new_adbnamehook(dns_adb_t *adb);
static void
free_adbnamehook(dns_adb_t *adb, dns_adbnamehook_t **namehookp);
static dns_adbentry_t *
new_adbentry(dns_adb_t *adb, const isc_sockaddr_t *addr, isc_stdtime_t now);
static void
destroy_adbentry(dns_adbentry_t *entry);
static int
match_adbentry(struct cds_lfht_node *ht_node, const void *key);
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
purge_names_overmem(dns_adb_t *adb, size_t requested);
static dns_adbname_t *
get_attached_and_locked_name(dns_adb_t *, const dns_name_t *, unsigned int type,
			     isc_stdtime_t now);
static void
purge_entries_overmem(dns_adb_t *adb, size_t requested);
static dns_adbentry_t *
get_attached_and_locked_entry(dns_adb_t *adb, isc_stdtime_t now,
			      const isc_sockaddr_t *addr);
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
clean_finds_at_name(dns_adbname_t *, dns_adbstatus_t, unsigned int);
static void
maybe_expire_namehooks(dns_adbname_t *, isc_stdtime_t);
static bool
name_expired(dns_adbname_t *adbname, isc_stdtime_t now);
static bool
maybe_expire_name(dns_adbname_t *adbname, isc_stdtime_t now);
static void
expire_name(dns_adbname_t *adbname, dns_adbstatus_t astat);
static bool
entry_expired(dns_adbentry_t *adbentry, isc_stdtime_t now);
static bool
maybe_expire_entry(dns_adbentry_t *adbentry, isc_stdtime_t now);
static void
expire_entry(dns_adbentry_t *adbentry);
static isc_result_t
dbfind_name(dns_adbname_t *, isc_stdtime_t, dns_rdatatype_t);
static isc_result_t
fetch_name(dns_adbname_t *, bool, bool, unsigned int, isc_counter_t *qc,
	   isc_counter_t *gqc, dns_rdatatype_t);
static void
shutdown_names(dns_adb_t *);
static void
shutdown_entries(dns_adb_t *);
static void
dump_entry(FILE *, dns_adb_t *, dns_adbentry_t *, bool, isc_stdtime_t);
static void
adjustsrtt(dns_adbaddrinfo_t *addr, unsigned int rtt, unsigned int factor,
	   isc_stdtime_t now);
static void
log_quota(dns_adbentry_t *entry, const char *fmt, ...) ISC_FORMAT_PRINTF(2, 3);

static bool
adbentry_overquota(dns_adbentry_t *entry);

/*
 * Private flag(s) for adbfind objects. These are used internally and
 * are not meant to be seen or used by the caller; however, we use the
 * same flags field as for DNS_ADBFIND_xxx flags, so we must be careful
 * that there is no overlap between these values and those. To make it
 * easier, we will number these starting from the most significant bit
 * instead of the least significant.
 */
enum {
	FIND_EVENT_SENT = 1 << 31,
};
#define FIND_EVENTSENT(h) (((h)->flags & FIND_EVENT_SENT) != 0)

/*
 * Private flag(s) for adbname objects.
 */
enum {
	NAME_IS_ALIAS = 1 << 31,
};
#define NAME_ALIAS(n) (((n)->flags & NAME_IS_ALIAS) != 0)

/*
 * Currently there are no private flags for adbentry objects.
 * If we ever use them again, they'll share bit space with the
 * addrinfo flags, FCTX_ADDRINFO_xxx, defined in resolver.c, so
 * when defining them, they should count back from the most
 * significant bit instead of counting up from zero.
 */

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
#define FIND_STATICSTUB(fn)	(((fn)->options & DNS_ADBFIND_STATICSTUB) != 0)
#define FIND_NOVALIDATE(fn)	(((fn)->options & DNS_ADBFIND_NOVALIDATE) != 0)
#define FIND_HAS_ADDRS(fn)	(!ISC_LIST_EMPTY((fn)->list))
#define FIND_NOFETCH(fn)	(((fn)->options & DNS_ADBFIND_NOFETCH) != 0)

#define ADBNAME_TYPE_MASK                                   \
	(DNS_ADBFIND_STARTATZONE | DNS_ADBFIND_STATICSTUB | \
	 DNS_ADBFIND_NOVALIDATE)

#define ADBNAME_TYPE(options) ((options) & ADBNAME_TYPE_MASK)

/*
 * These are currently used on simple unsigned ints, so they are
 * not really associated with any particular type.
 */
#define WANT_INET(x)  (((x) & DNS_ADBFIND_INET) != 0)
#define WANT_INET6(x) (((x) & DNS_ADBFIND_INET6) != 0)

#define EXPIRE_OK(exp, now) ((exp == INT_MAX) || (exp < now))

#define ENTER_LEVEL  ISC_LOG_DEBUG(50)
#define CLEAN_LEVEL  ISC_LOG_DEBUG(100)
#define DEF_LEVEL    ISC_LOG_DEBUG(5)
#define NCACHE_LEVEL ISC_LOG_DEBUG(20)

#define NCACHE_RESULT(r) \
	((r) == DNS_R_NCACHENXDOMAIN || (r) == DNS_R_NCACHENXRRSET)
#define AUTH_NX(r) ((r) == DNS_R_NXDOMAIN || (r) == DNS_R_NXRRSET)

/*
 * Due to the ttlclamp(), the TTL is never 0 unless the trust is ultimate,
 * in which case we need to set the expiration to have immediate effect.
 */
#define ADJUSTED_EXPIRE(expire, now, ttl)                                      \
	((ttl != 0)                                                            \
		 ? ISC_MIN(expire, ISC_MAX(now + ADB_ENTRY_WINDOW, now + ttl)) \
		 : INT_MAX)

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
	isc_log_vwrite(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_ADB, level,
		       format, args);
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

	return ttl;
}

/*
 * Requires the name to be locked and that no entries to be locked.
 *
 * This code handles A and AAAA rdatasets only.
 */
static void
import_rdataset(dns_adbname_t *adbname, dns_rdataset_t *rdataset,
		isc_stdtime_t now) {
	dns_adb_t *adb = NULL;
	dns_rdatatype_t rdtype;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	rdtype = rdataset->type;

	switch (rdataset->trust) {
	case dns_trust_glue:
	case dns_trust_additional:
	case dns_trust_pending_answer:
	case dns_trust_pending_additional:
		rdataset->ttl = ADB_CACHE_MINIMUM;
		break;
	case dns_trust_ultimate:
		rdataset->ttl = 0;
		break;
	default:
		rdataset->ttl = ttlclamp(rdataset->ttl);
	}

	REQUIRE(dns_rdatatype_isaddr(rdtype));

	DNS_RDATASET_FOREACH (rdataset) {
		/* FIXME: Move to a separate function */
		dns_adbnamehooklist_t *hookhead = NULL;
		dns_adbentry_t *entry = NULL;
		dns_rdata_t rdata = DNS_RDATA_INIT;
		isc_sockaddr_t sockaddr;
		struct in_addr ina;
		struct in6_addr in6a;

		dns_rdataset_current(rdataset, &rdata);
		switch (rdtype) {
		case dns_rdatatype_a:
			INSIST(rdata.length == 4);
			memmove(&ina.s_addr, rdata.data, 4);
			isc_sockaddr_fromin(&sockaddr, &ina, 0);
			hookhead = &adbname->v4;
			break;
		case dns_rdatatype_aaaa:
			INSIST(rdata.length == 16);
			memmove(in6a.s6_addr, rdata.data, 16);
			isc_sockaddr_fromin6(&sockaddr, &in6a, 0);
			hookhead = &adbname->v6;
			break;
		default:
			UNREACHABLE();
		}

		entry = get_attached_and_locked_entry(adb, now, &sockaddr);

		bool found = false;
		ISC_LIST_FOREACH (*hookhead, anh, name_link) {
			if (anh->entry == entry) {
				found = true;
			}
		}
		if (!found) {
			dns_adbnamehook_t *nh = new_adbnamehook(adb);
			dns_adbentry_attach(entry, &nh->entry);
			ISC_LIST_APPEND(*hookhead, nh, name_link);
			ISC_LIST_APPEND(entry->nhs, nh, entry_link);
		}
		UNLOCK(&entry->lock);
		dns_adbentry_detach(&entry);
	}

	switch (rdtype) {
	case dns_rdatatype_a:
		adbname->expire_v4 = ADJUSTED_EXPIRE(adbname->expire_v4, now,
						     rdataset->ttl);
		DP(NCACHE_LEVEL, "expire_v4 set to %u import_rdataset",
		   adbname->expire_v4);
		break;
	case dns_rdatatype_aaaa:
		adbname->expire_v6 = ADJUSTED_EXPIRE(adbname->expire_v6, now,
						     rdataset->ttl);
		DP(NCACHE_LEVEL, "expire_v6 set to %u import_rdataset",
		   adbname->expire_v6);
		break;
	default:
		UNREACHABLE();
	}
}

static void
expire_name_async(void *arg) {
	dns_adbname_t *adbname = arg;
	dns_adb_t *adb = adbname->adb;

	RUNTIME_CHECK(adbname->loop == isc_loop());

	/* ... and LRU list */
	ISC_SIEVE_UNLINK(adb->lru[isc_tid()].names, adbname, link);

	dns_adbname_detach(&adbname);
}

/*
 * Requires the name to be locked and write lock on adb->names_lock.
 */
static void
expire_name(dns_adbname_t *adbname, dns_adbstatus_t astat) {
	REQUIRE(DNS_ADBNAME_VALID(adbname));

	dns_adb_t *adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	DP(DEF_LEVEL, "killing name %p", adbname);

	/*
	 * Clean up the name's various contents.  These functions
	 * are destructive in that they will always empty the lists
	 * of finds and namehooks.
	 */
	clean_finds_at_name(adbname, astat, DNS_ADBFIND_ADDRESSMASK);
	clean_namehooks(adb, &adbname->v4);
	clean_namehooks(adb, &adbname->v6);

	if (NAME_FETCH_A(adbname)) {
		dns_resolver_cancelfetch(adbname->fetch_a->fetch);
	}

	if (NAME_FETCH_AAAA(adbname)) {
		dns_resolver_cancelfetch(adbname->fetch_aaaa->fetch);
	}

	/* Remove the adbname from the hashtable... */
	if (cds_lfht_del(adb->names_ht, &adbname->ht_node) == 0) {
		isc_async_run(adbname->loop, expire_name_async, adbname);
	}
}

/*
 * Requires the name to be locked and no entries to be locked.
 */
static void
maybe_expire_namehooks(dns_adbname_t *adbname, isc_stdtime_t now) {
	REQUIRE(DNS_ADBNAME_VALID(adbname));
	REQUIRE(DNS_ADB_VALID(adbname->adb));

	dns_adb_t *adb = adbname->adb;

	/*
	 * Check to see if we need to remove the v4 addresses
	 */
	if (!NAME_FETCH_A(adbname) && EXPIRE_OK(adbname->expire_v4, now)) {
		if (NAME_HAS_V4(adbname)) {
			DP(DEF_LEVEL, "expiring v4 for name %p", adbname);
			clean_namehooks(adb, &adbname->v4);
			adbname->partial_result &= ~DNS_ADBFIND_INET;
		}
		adbname->expire_v4 = INT_MAX;
		adbname->fetch_err = FIND_ERR_UNEXPECTED;
	}

	/*
	 * Check to see if we need to remove the v6 addresses
	 */
	if (!NAME_FETCH_AAAA(adbname) && EXPIRE_OK(adbname->expire_v6, now)) {
		if (NAME_HAS_V6(adbname)) {
			DP(DEF_LEVEL, "expiring v6 for name %p", adbname);
			clean_namehooks(adb, &adbname->v6);
			adbname->partial_result &= ~DNS_ADBFIND_INET6;
		}
		adbname->expire_v6 = INT_MAX;
		adbname->fetch6_err = FIND_ERR_UNEXPECTED;
	}
}

static void
shutdown_names(dns_adb_t *adb) {
	dns_adbname_t *adbname = NULL;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(adb->names_ht, &iter, adbname, ht_node) {
		dns_adbname_ref(adbname);
		LOCK(&adbname->lock);
		/*
		 * Run through the list.  For each name, clean up finds
		 * found there, and cancel any fetches running.  When
		 * all the fetches are canceled, the name will destroy
		 * itself.
		 */
		expire_name(adbname, DNS_ADB_SHUTTINGDOWN);
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	}
}

static void
shutdown_entries(dns_adb_t *adb) {
	dns_adbentry_t *adbentry = NULL;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(adb->entries_ht, &iter, adbentry, ht_node) {
		dns_adbentry_ref(adbentry);
		LOCK(&adbentry->lock);
		expire_entry(adbentry);
		UNLOCK(&adbentry->lock);
		dns_adbentry_detach(&adbentry);
	}
}

/*
 * The name containing the 'namehooks' list must be locked.
 */
static void
clean_namehooks(dns_adb_t *adb, dns_adbnamehooklist_t *namehooks) {
	ISC_LIST_FOREACH (*namehooks, namehook, name_link) {
		INSIST(DNS_ADBNAMEHOOK_VALID(namehook));
		INSIST(DNS_ADBENTRY_VALID(namehook->entry));

		dns_adbentry_t *adbentry = namehook->entry;
		namehook->entry = NULL;

		/*
		 * Free the namehook
		 */
		ISC_LIST_UNLINK(*namehooks, namehook, name_link);

		LOCK(&adbentry->lock);
		ISC_LIST_UNLINK(adbentry->nhs, namehook, entry_link);
		UNLOCK(&adbentry->lock);
		dns_adbentry_detach(&adbentry);

		free_adbnamehook(adb, &namehook);
	}
}

/*
 * The name must be locked.
 */
static void
clean_finds_at_name(dns_adbname_t *name, dns_adbstatus_t astat,
		    unsigned int addrs) {
	dns_adbfind_t *find = NULL, *next = NULL;

	DP(ENTER_LEVEL,
	   "ENTER clean_finds_at_name, name %p, astat %08x, addrs %08x", name,
	   astat, addrs);

	for (find = ISC_LIST_HEAD(name->finds); find != NULL; find = next) {
		bool process = false;
		unsigned int wanted, notify;

		LOCK(&find->lock);
		next = ISC_LIST_NEXT(find, plink);

		wanted = find->flags & DNS_ADBFIND_ADDRESSMASK;
		notify = wanted & addrs;

		switch (astat) {
		case DNS_ADB_MOREADDRESSES:
			DP(ISC_LOG_DEBUG(3), "more addresses");
			if ((notify) != 0) {
				find->flags &= ~addrs;
				process = true;
			}
			break;
		case DNS_ADB_NOMOREADDRESSES:
			DP(ISC_LOG_DEBUG(3), "no more addresses");
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
			DP(DEF_LEVEL, "cfan: processing find %p", find);

			/*
			 * Unlink the find from the name, letting the caller
			 * call dns_adb_destroyfind() on it to clean it up
			 * later.
			 */
			ISC_LIST_UNLINK(name->finds, find, plink);
			find->adbname = NULL;

			INSIST(!FIND_EVENTSENT(find));

			atomic_store(&find->status, astat);

			DP(DEF_LEVEL, "cfan: sending find %p to caller", find);

			isc_async_run(find->loop, find->cb, find);
			find->flags |= FIND_EVENT_SENT;
		} else {
			DP(DEF_LEVEL, "cfan: skipping find %p", find);
		}

		UNLOCK(&find->lock);
	}
	DP(ENTER_LEVEL, "EXIT clean_finds_at_name, name %p", name);
}

static dns_adbname_t *
new_adbname(dns_adb_t *adb, const dns_name_t *dnsname, unsigned int type) {
	dns_adbname_t *name = NULL;

	name = isc_mem_get(adb->mctx, sizeof(*name));
	*name = (dns_adbname_t){
		.adb = dns_adb_ref(adb),
		.expire_v4 = INT_MAX,
		.expire_v6 = INT_MAX,
		.fetch_err = FIND_ERR_UNEXPECTED,
		.fetch6_err = FIND_ERR_UNEXPECTED,
		.v4 = ISC_LIST_INITIALIZER,
		.v6 = ISC_LIST_INITIALIZER,
		.finds = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
		.type = type,
		.loop = isc_loop_ref(isc_loop()),
		.magic = DNS_ADBNAME_MAGIC,
	};

#if DNS_ADB_TRACE
	fprintf(stderr, "dns_adbname__init:%s:%s:%d:%p->references = 1\n",
		__func__, __FILE__, __LINE__ + 1, name);
#endif
	isc_refcount_init(&name->references, 1);

	isc_mutex_init(&name->lock);

	name->name = dns_fixedname_initname(&name->fname);
	dns_name_copy(dnsname, name->name);

	inc_adbstats(adb, dns_adbstats_namescnt);
	return name;
}

#if DNS_ADB_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_adbname, destroy_adbname);
#else
ISC_REFCOUNT_IMPL(dns_adbname, destroy_adbname);
#endif

static void
destroy_adbname_rcu(struct rcu_head *rcu_head) {
	dns_adbname_t *adbname = caa_container_of(rcu_head, dns_adbname_t,
						  rcu_head);
	REQUIRE(DNS_ADBNAME_VALID(adbname));

	dns_adb_t *adb = adbname->adb;

	REQUIRE(!NAME_HAS_V4(adbname));
	REQUIRE(!NAME_HAS_V6(adbname));
	REQUIRE(!NAME_FETCH(adbname));
	REQUIRE(ISC_LIST_EMPTY(adbname->finds));
	REQUIRE(!ISC_LINK_LINKED(adbname, link));

	adbname->magic = 0;

	isc_mutex_destroy(&adbname->lock);
	isc_loop_detach(&adbname->loop);

	isc_mem_put(adb->mctx, adbname, sizeof(*adbname));

	dec_adbstats(adb, dns_adbstats_namescnt);

	dns_adb_detach(&adb);
}

static void
destroy_adbname(dns_adbname_t *adbname) {
	call_rcu(&adbname->rcu_head, destroy_adbname_rcu);
}

static dns_adbnamehook_t *
new_adbnamehook(dns_adb_t *adb) {
	dns_adbnamehook_t *nh = isc_mem_get(adb->mctx, sizeof(*nh));
	*nh = (dns_adbnamehook_t){
		.name_link = ISC_LINK_INITIALIZER,
		.entry_link = ISC_LINK_INITIALIZER,
		.magic = DNS_ADBNAMEHOOK_MAGIC,
	};

	return nh;
}

static void
free_adbnamehook(dns_adb_t *adb, dns_adbnamehook_t **namehook) {
	dns_adbnamehook_t *nh = NULL;

	REQUIRE(namehook != NULL && DNS_ADBNAMEHOOK_VALID(*namehook));

	nh = *namehook;
	*namehook = NULL;

	REQUIRE(nh->entry == NULL);
	REQUIRE(!ISC_LINK_LINKED(nh, name_link));
	REQUIRE(!ISC_LINK_LINKED(nh, entry_link));

	nh->magic = 0;

	isc_mem_put(adb->mctx, nh, sizeof(*nh));
}

static dns_adbentry_t *
new_adbentry(dns_adb_t *adb, const isc_sockaddr_t *addr, isc_stdtime_t now) {
	dns_adbentry_t *entry = NULL;

	entry = isc_mem_get(adb->mctx, sizeof(*entry));
	*entry = (dns_adbentry_t){
		.srtt = isc_random_uniform(0x1f) + 1,
		.sockaddr = *addr,
		.link = ISC_LINK_INITIALIZER,
		.quota = adb->quota,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.adb = dns_adb_ref(adb),
		.expires = now + ADB_ENTRY_WINDOW,
		.loop = isc_loop_ref(isc_loop()),
		.magic = DNS_ADBENTRY_MAGIC,
	};

#if DNS_ADB_TRACE
	fprintf(stderr, "dns_adbentry__init:%s:%s:%d:%p->references = 1\n",
		__func__, __FILE__, __LINE__ + 1, entry);
#endif
	isc_mutex_init(&entry->lock);

	inc_adbstats(adb, dns_adbstats_entriescnt);

	return entry;
}

static void
destroy_adbentry_rcu(struct rcu_head *rcu_head) {
	dns_adbentry_t *adbentry = caa_container_of(rcu_head, dns_adbentry_t,
						    rcu_head);

	REQUIRE(DNS_ADBENTRY_VALID(adbentry));

	dns_adb_t *adb = adbentry->adb;
	uint_fast32_t active;

	adbentry->magic = 0;

	INSIST(!ISC_LINK_LINKED(adbentry, link));

	INSIST(ISC_LIST_EMPTY(adbentry->nhs));

	active = atomic_load_acquire(&adbentry->active);
	INSIST(active == 0);

	if (adbentry->cookie != NULL) {
		isc_mem_put(adb->mctx, adbentry->cookie, adbentry->cookielen);
	}

	isc_mutex_destroy(&adbentry->lock);
	isc_loop_detach(&adbentry->loop);

	isc_mem_put(adb->mctx, adbentry, sizeof(*adbentry));

	dec_adbstats(adb, dns_adbstats_entriescnt);

	dns_adb_detach(&adb);
}

static void
destroy_adbentry(dns_adbentry_t *adbentry) {
	call_rcu(&adbentry->rcu_head, destroy_adbentry_rcu);
}

#if DNS_ADB_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_adbentry, destroy_adbentry);
#else
ISC_REFCOUNT_IMPL(dns_adbentry, destroy_adbentry);
#endif

static dns_adbfind_t *
new_adbfind(dns_adb_t *adb, in_port_t port) {
	dns_adbfind_t *find = NULL;

	find = isc_mem_get(adb->hmctx, sizeof(*find));
	*find = (dns_adbfind_t){
		.port = port,
		.result_v4 = ISC_R_UNEXPECTED,
		.result_v6 = ISC_R_UNEXPECTED,
		.publink = ISC_LINK_INITIALIZER,
		.plink = ISC_LINK_INITIALIZER,
		.list = ISC_LIST_INITIALIZER,
	};

	dns_adb_attach(adb, &find->adb);
	isc_mutex_init(&find->lock);

	find->magic = DNS_ADBFIND_MAGIC;

	return find;
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

	isc_mem_put(adb->hmctx, find, sizeof(*find));
	dns_adb_detach(&adb);
}

static dns_adbfetch_t *
new_adbfetch(dns_adb_t *adb) {
	dns_adbfetch_t *fetch = NULL;

	fetch = isc_mem_get(adb->hmctx, sizeof(*fetch));
	*fetch = (dns_adbfetch_t){
		.magic = DNS_ADBFETCH_MAGIC,
	};
	dns_rdataset_init(&fetch->rdataset);

	return fetch;
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

	isc_mem_put(adb->hmctx, fetch, sizeof(*fetch));
}

/*
 * Copy bits from an adbentry into a newly allocated adb_addrinfo structure.
 * The entry must be locked, and its reference count must be incremented.
 */
static dns_adbaddrinfo_t *
new_adbaddrinfo(dns_adb_t *adb, dns_adbentry_t *entry, in_port_t port) {
	dns_adbaddrinfo_t *ai = NULL;

	ai = isc_mem_get(adb->hmctx, sizeof(*ai));
	*ai = (dns_adbaddrinfo_t){
		.srtt = atomic_load(&entry->srtt),
		.flags = atomic_load(&entry->flags),
		.publink = ISC_LINK_INITIALIZER,
		.sockaddr = entry->sockaddr,
		.entry = dns_adbentry_ref(entry),
		.magic = DNS_ADBADDRINFO_MAGIC,
	};

	isc_sockaddr_setport(&ai->sockaddr, port);

	return ai;
}

static void
free_adbaddrinfo(dns_adb_t *adb, dns_adbaddrinfo_t **ainfo) {
	dns_adbaddrinfo_t *ai = NULL;

	REQUIRE(ainfo != NULL && DNS_ADBADDRINFO_VALID(*ainfo));

	ai = *ainfo;
	*ainfo = NULL;

	REQUIRE(!ISC_LINK_LINKED(ai, publink));

	ai->magic = 0;

	if (ai->transport != NULL) {
		dns_transport_detach(&ai->transport);
	}
	dns_adbentry_detach(&ai->entry);

	isc_mem_put(adb->hmctx, ai, sizeof(*ai));
}

static int
match_adbname(struct cds_lfht_node *ht_node, const void *key) {
	const dns_adbname_t *adbname0 = caa_container_of(ht_node, dns_adbname_t,
							 ht_node);
	const dns_adbname_t *adbname1 = key;

	if (adbname0->type != adbname1->type) {
		return 0;
	}

	return dns_name_equal(adbname0->name, adbname1->name);
}

static uint32_t
hash_adbname(const dns_adbname_t *adbname) {
	isc_hash32_t hash;

	isc_hash32_init(&hash);
	isc_hash32_hash(&hash, adbname->name->ndata, adbname->name->length,
			false);
	isc_hash32_hash(&hash, &adbname->type, sizeof(adbname->type), true);
	return isc_hash32_finalize(&hash);
}

/*
 * Search for the name in the hash table.
 */
static dns_adbname_t *
get_attached_and_locked_name(dns_adb_t *adb, const dns_name_t *name,
			     unsigned int type, isc_stdtime_t now) {
	dns_adbname_t *adbname = NULL;
	dns_adbname_t key = {
		.name = UNCONST(name),
		.type = type,
	};
	uint32_t hashval = hash_adbname(&key);
	if (isc_mem_isovermem(adb->mctx)) {
		purge_names_overmem(adb, 2 * sizeof(*adbname));
	}

	struct cds_lfht_iter iter;
	cds_lfht_lookup(adb->names_ht, hashval, match_adbname, &key, &iter);

	adbname = cds_lfht_entry(cds_lfht_iter_get_node(&iter), dns_adbname_t,
				 ht_node);

	if (adbname == NULL) {
	create:
		adbname = new_adbname(adb, name, key.type);

		/*
		 * We need to lock the adbname before inserting it into the
		 * hashtable because any other thread could immediately look the
		 * newly created adbname after it has been inserted but not yet
		 * properly initialized by the caller.
		 */
		LOCK(&adbname->lock);

		struct cds_lfht_node *ht_node = cds_lfht_add_unique(
			adb->names_ht, hashval, match_adbname, &key,
			&adbname->ht_node);

		if (ht_node == &adbname->ht_node) {
			/* Success. */

			dns_adbname_ref(adbname);

			ISC_SIEVE_INSERT(adb->lru[isc_tid()].names, adbname,
					 link);

			return adbname;
		}

		/* Somebody was faster */
		UNLOCK(&adbname->lock);

		destroy_adbname_rcu(&adbname->rcu_head);
		adbname = caa_container_of(ht_node, dns_adbname_t, ht_node);
	}

	LOCK(&adbname->lock);

	if (cds_lfht_is_node_deleted(&adbname->ht_node)) {
		UNLOCK(&adbname->lock);
		goto create;
	}

	dns_adbname_ref(adbname);

	/* Is the name we found already expired */
	if (maybe_expire_name(adbname, now)) {
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
		goto create;
	}

	ISC_SIEVE_MARK(adbname, visited);

	return adbname;
}

static int
match_adbentry(struct cds_lfht_node *ht_node, const void *key) {
	const dns_adbentry_t *adbentry =
		caa_container_of(ht_node, dns_adbentry_t, ht_node);

	return isc_sockaddr_equal(&adbentry->sockaddr, key);
}

/*
 * Find the entry in the adb->entries hashtable.
 */
static dns_adbentry_t *
get_attached_and_locked_entry(dns_adb_t *adb, isc_stdtime_t now,
			      const isc_sockaddr_t *addr) {
	dns_adbentry_t *adbentry = NULL;
	uint32_t hashval = isc_sockaddr_hash(addr, true);

	if (isc_mem_isovermem(adb->mctx)) {
		purge_entries_overmem(adb, 2 * sizeof(*adbentry));
	}

	struct cds_lfht_iter iter;
	cds_lfht_lookup(adb->entries_ht, hashval, match_adbentry,
			(const unsigned char *)addr, &iter);

	adbentry = cds_lfht_entry(cds_lfht_iter_get_node(&iter), dns_adbentry_t,
				  ht_node);

	if (adbentry == NULL) {
	create:
		adbentry = new_adbentry(adb, addr, now);

		/*
		 * We need to lock the adbentry before inserting it into the
		 * hashtable because any other thread could immediately look the
		 * newly created adbentry after it has been inserted but not yet
		 * properly initialized by the caller.
		 */
		LOCK(&adbentry->lock);

		struct cds_lfht_node *ht_node = cds_lfht_add_unique(
			adb->entries_ht, hashval, match_adbentry,
			(const unsigned char *)addr, &adbentry->ht_node);

		if (ht_node == &adbentry->ht_node) {
			/* Success */

			dns_adbentry_ref(adbentry);

			ISC_SIEVE_INSERT(adb->lru[isc_tid()].entries, adbentry,
					 link);

			return adbentry;
		}

		/* Somebody was faster */
		UNLOCK(&adbentry->lock);

		destroy_adbentry_rcu(&adbentry->rcu_head);
		adbentry = caa_container_of(ht_node, dns_adbentry_t, ht_node);
	}

	LOCK(&adbentry->lock);

	if (cds_lfht_is_node_deleted(&adbentry->ht_node)) {
		UNLOCK(&adbentry->lock);
		goto create;
	}

	dns_adbentry_ref(adbentry);

	/* Is the entry we found already expired */
	if (maybe_expire_entry(adbentry, now)) {
		UNLOCK(&adbentry->lock);
		dns_adbentry_detach(&adbentry);
		goto create;
	}

	ISC_SIEVE_MARK(adbentry, visited);

	return adbentry;
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

	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_ADB, ISC_LOG_INFO,
		      "adb: quota %s (%" PRIuFAST32 "/%" PRIuFAST32 "): %s",
		      addrbuf, atomic_load_relaxed(&entry->active),
		      atomic_load_relaxed(&entry->quota), msgbuf);
}

static void
copy_namehook_lists(dns_adb_t *adb, dns_adbfind_t *find, dns_adbname_t *name) {
	dns_adbentry_t *entry = NULL;

	if ((find->options & DNS_ADBFIND_INET) != 0) {
		ISC_LIST_FOREACH (name->v4, namehook, name_link) {
			dns_adbaddrinfo_t *addrinfo = NULL;
			entry = namehook->entry;

			if ((find->options & DNS_ADBFIND_QUOTAEXEMPT) == 0 &&
			    adbentry_overquota(entry))
			{
				find->options |= DNS_ADBFIND_OVERQUOTA;
				continue;
			}

			addrinfo = new_adbaddrinfo(adb, entry, find->port);

			/*
			 * Found a valid entry.  Add it to the find's list.
			 */
			ISC_LIST_APPEND(find->list, addrinfo, publink);
		}
	}

	if ((find->options & DNS_ADBFIND_INET6) != 0) {
		ISC_LIST_FOREACH (name->v6, namehook, name_link) {
			dns_adbaddrinfo_t *addrinfo = NULL;
			entry = namehook->entry;

			if ((find->options & DNS_ADBFIND_QUOTAEXEMPT) == 0 &&
			    adbentry_overquota(entry))
			{
				find->options |= DNS_ADBFIND_OVERQUOTA;
				continue;
			}

			addrinfo = new_adbaddrinfo(adb, entry, find->port);

			/*
			 * Found a valid entry.  Add it to the find's list.
			 */
			ISC_LIST_APPEND(find->list, addrinfo, publink);
		}
	}
}

static bool
name_expired(dns_adbname_t *adbname, isc_stdtime_t now) {
	REQUIRE(DNS_ADBNAME_VALID(adbname));

	/* Leave this name alone if it still has active namehooks... */
	if (NAME_HAS_V4(adbname) || NAME_HAS_V6(adbname)) {
		return false;
	}

	/* ...an active fetch in progres... */
	if (NAME_FETCH(adbname)) {
		return false;
	}

	/* ... or is not yet expired. */
	if (!EXPIRE_OK(adbname->expire_v4, now) ||
	    !EXPIRE_OK(adbname->expire_v6, now))
	{
		return false;
	}

	return true;
}

/*
 * The name must be locked and write lock on adb->names_lock must be held.
 */
static bool
maybe_expire_name(dns_adbname_t *adbname, isc_stdtime_t now) {
	if (name_expired(adbname, now)) {
		expire_name(adbname, DNS_ADB_EXPIRED);
		return true;
	}

	return false;
}

static void
expire_entry_async(void *arg) {
	dns_adbentry_t *adbentry = arg;
	dns_adb_t *adb = adbentry->adb;

	REQUIRE(adbentry->loop == isc_loop());

	ISC_SIEVE_UNLINK(adb->lru[isc_tid()].entries, adbentry, link);

	dns_adbentry_detach(&adbentry);
}

static void
expire_entry(dns_adbentry_t *adbentry) {
	dns_adb_t *adb = adbentry->adb;

	if (cds_lfht_del(adb->entries_ht, &adbentry->ht_node) == 0) {
		isc_async_run(adbentry->loop, expire_entry_async, adbentry);
	}
}

static bool
entry_expired(dns_adbentry_t *adbentry, isc_stdtime_t now) {
	if (!ISC_LIST_EMPTY(adbentry->nhs)) {
		return false;
	}

	if (!EXPIRE_OK(adbentry->expires, now)) {
		return false;
	}

	return true;
}

static bool
maybe_expire_entry(dns_adbentry_t *adbentry, isc_stdtime_t now) {
	REQUIRE(DNS_ADBENTRY_VALID(adbentry));

	if (entry_expired(adbentry, now)) {
		expire_entry(adbentry);
		return true;
	}

	return false;
}

static void
purge_names_overmem(dns_adb_t *adb, size_t requested) {
	size_t expired = 0;

	do {
		dns_adbname_t *adbname = ISC_SIEVE_NEXT(
			adb->lru[isc_tid()].names, visited, link);
		if (adbname == NULL) {
			break;
		}

		dns_adbname_ref(adbname);
		LOCK(&adbname->lock);

		/*
		 * Remove the name if it's expired or unused,
		 * has no address data.
		 */
		maybe_expire_namehooks(adbname, INT_MAX);
		expire_name(adbname, DNS_ADB_CANCELED);
		expired += sizeof(*adbname);

		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	} while (expired < requested);
}

static void
cleanup_names(dns_adb_t *adb, isc_stdtime_t now) {
	dns_adbname_t *adbname = NULL;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(adb->names_ht, &iter, adbname, ht_node) {
		dns_adbname_ref(adbname);
		LOCK(&adbname->lock);
		/*
		 * Name hooks expire after the address record's TTL
		 * or 30 minutes, whichever is shorter. If after cleaning
		 * those up there are no name hooks left, and no active
		 * fetches, we can remove this name from the bucket.
		 */
		maybe_expire_namehooks(adbname, now);
		(void)maybe_expire_name(adbname, now);
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	}
}

static void
purge_entries_overmem(dns_adb_t *adb, size_t requested) {
	size_t expired = 0;

	do {
		dns_adbentry_t *adbentry = ISC_SIEVE_NEXT(
			adb->lru[isc_tid()].entries, visited, link);
		if (adbentry == NULL) {
			break;
		}

		dns_adbentry_ref(adbentry);
		LOCK(&adbentry->lock);

		expire_entry(adbentry);
		expired += sizeof(*adbentry);

		UNLOCK(&adbentry->lock);
		dns_adbentry_detach(&adbentry);
	} while (expired < requested);
}

static void
cleanup_entries(dns_adb_t *adb, isc_stdtime_t now) {
	dns_adbentry_t *adbentry = NULL;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(adb->entries_ht, &iter, adbentry, ht_node) {
		dns_adbentry_ref(adbentry);
		LOCK(&adbentry->lock);
		maybe_expire_entry(adbentry, now);
		UNLOCK(&adbentry->lock);
		dns_adbentry_detach(&adbentry);
	}
}

static void
dns_adb_destroy(dns_adb_t *adb) {
	DP(DEF_LEVEL, "destroying ADB %p", adb);

	adb->magic = 0;

	RUNTIME_CHECK(!cds_lfht_destroy(adb->names_ht, NULL));
	adb->names_ht = NULL;

	RUNTIME_CHECK(!cds_lfht_destroy(adb->entries_ht, NULL));
	adb->entries_ht = NULL;

	isc_mem_cput(adb->hmctx, adb->lru, adb->nloops, sizeof(adb->lru[0]));

	isc_mem_detach(&adb->hmctx);

	isc_mutex_destroy(&adb->lock);

	isc_stats_detach(&adb->stats);
	dns_resolver_detach(&adb->res);
	dns_view_weakdetach(&adb->view);
	isc_mem_putanddetach(&adb->mctx, adb, sizeof(dns_adb_t));
}

#if DNS_ADB_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_adb, dns_adb_destroy);
#else
ISC_REFCOUNT_IMPL(dns_adb, dns_adb_destroy);
#endif

/*
 * Public functions.
 */

void
dns_adb_create(isc_mem_t *mem, dns_view_t *view, dns_adb_t **adbp) {
	REQUIRE(mem != NULL);
	REQUIRE(view != NULL);
	REQUIRE(adbp != NULL && *adbp == NULL);

	uint32_t nloops = isc_loopmgr_nloops();
	dns_adb_t *adb = isc_mem_get(mem, sizeof(dns_adb_t));
	*adb = (dns_adb_t){
		.references = 1,
		.nloops = nloops,
		.magic = DNS_ADB_MAGIC,
	};

	/*
	 * Initialize things here that cannot fail, and especially things
	 * that must be NULL for the error return to work properly.
	 */
#if DNS_ADB_TRACE
	fprintf(stderr, "dns_adb__init:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, adb);
#endif
	dns_view_weakattach(view, &adb->view);
	dns_resolver_attach(view->resolver, &adb->res);
	isc_mem_attach(mem, &adb->mctx);

	isc_mem_create("ADB_dynamic", &adb->hmctx);

	adb->names_ht = cds_lfht_new(ADB_HASH_SIZE, ADB_HASH_SIZE, 0,
				     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				     NULL);
	INSIST(adb->names_ht != NULL);

	adb->entries_ht =
		cds_lfht_new(ADB_HASH_SIZE, ADB_HASH_SIZE, 0,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(adb->entries_ht != NULL);

	adb->lru = isc_mem_cget(adb->hmctx, adb->nloops, sizeof(adb->lru[0]));

	for (size_t i = 0; i < adb->nloops; i++) {
		ISC_SIEVE_INIT(adb->lru[i].names);
		ISC_SIEVE_INIT(adb->lru[i].entries);
	}

	isc_mutex_init(&adb->lock);

	isc_stats_create(adb->mctx, &adb->stats, dns_adbstats_max);

	set_adbstat(adb, 0, dns_adbstats_nnames);
	set_adbstat(adb, 0, dns_adbstats_nentries);

	*adbp = adb;
}

static void
dns_adb_shutdown_async(void *arg) {
	dns_adb_t *adb = arg;

	synchronize_rcu();

	rcu_read_lock();
	shutdown_names(adb);
	shutdown_entries(adb);
	rcu_read_unlock();

	dns_adb_detach(&adb);
}

void
dns_adb_shutdown(dns_adb_t *adb) {
	if (!atomic_compare_exchange_strong(&adb->shuttingdown,
					    &(bool){ false }, true))
	{
		return;
	}

	DP(DEF_LEVEL, "shutting down ADB %p", adb);

	isc_mem_clearwater(adb->mctx);

	/*
	 * dns_adb_shutdown() can get called from call_rcu thread, so we need to
	 * pass the control over synchronize_rcu() back to main loop thread when
	 * shutting down ADB.
	 */
	dns_adb_ref(adb);
	isc_async_run(isc_loop_main(), dns_adb_shutdown_async, adb);
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
 * - Name found, queries pending.  In this case, if a loop was
 *   passed in, allocate a job id, attach it to the name's job
 *   list and remember to tell the caller that there will be
 *   more info coming later.
 */
isc_result_t
dns_adb_createfind(dns_adb_t *adb, isc_loop_t *loop, isc_job_cb cb, void *cbarg,
		   const dns_name_t *name, const dns_name_t *qname,
		   dns_rdatatype_t qtype ISC_ATTR_UNUSED, unsigned int options,
		   isc_stdtime_t now, in_port_t port, unsigned int depth,
		   isc_counter_t *qc, isc_counter_t *gqc,
		   dns_adbfind_t **findp) {
	isc_result_t result = ISC_R_UNEXPECTED;
	dns_adbfind_t *find = NULL;
	dns_adbname_t *adbname = NULL;
	bool want_event = true;
	bool start_at_zone = false;
	bool alias = false;
	bool have_address = false;
	unsigned int wanted_addresses = (options & DNS_ADBFIND_ADDRESSMASK);
	unsigned int wanted_fetches = 0;
	unsigned int query_pending = 0;
	char namebuf[DNS_NAME_FORMATSIZE] = { 0 };

	REQUIRE(DNS_ADB_VALID(adb));
	if (loop != NULL) {
		REQUIRE(cb != NULL);
	}
	REQUIRE(name != NULL);
	REQUIRE(qname != NULL);
	REQUIRE(findp != NULL && *findp == NULL);

	REQUIRE((options & DNS_ADBFIND_ADDRESSMASK) != 0);

	rcu_read_lock();

	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return ISC_R_SHUTTINGDOWN;
	}

	if (now == 0) {
		now = isc_stdtime_now();
	}

	/*
	 * If STATICSTUB is set we always want to have STARTATZONE set.
	 */
	if (options & DNS_ADBFIND_STATICSTUB) {
		options |= DNS_ADBFIND_STARTATZONE;
	}

	/*
	 * Remember what types of addresses we are interested in.
	 */
	find = new_adbfind(adb, port);
	find->options = options;
	find->flags |= wanted_addresses;
	if (FIND_WANTEVENT(find)) {
		REQUIRE(loop != NULL);
	}

	if (isc_log_wouldlog(DEF_LEVEL)) {
		dns_name_format(name, namebuf, sizeof(namebuf));
	}

	/* Try to see if we know anything about this name at all. */
	adbname = get_attached_and_locked_name(
		adb, name, ADBNAME_TYPE(find->options), now);

	/*
	 * Name hooks expire after the address record's TTL or 30 minutes,
	 * whichever is shorter. If there are expired name hooks, remove
	 * them so we'll send a new fetch.
	 */
	maybe_expire_namehooks(adbname, now);

	/*
	 * Do we know that the name is an alias?
	 */
	if (NAME_ALIAS(adbname) && !EXPIRE_OK(adbname->expire_v4, now)) {
		/* Yes, it is. */
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
			if (!NAME_FETCH_A(adbname) && !FIND_STATICSTUB(find)) {
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
			if (!NAME_FETCH_AAAA(adbname) && !FIND_STATICSTUB(find))
			{
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
		bool no_validate = FIND_NOVALIDATE(find);

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
		    fetch_name(adbname, start_at_zone, no_validate, depth, qc,
			       gqc, dns_rdatatype_a) == ISC_R_SUCCESS)
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
		    fetch_name(adbname, start_at_zone, no_validate, depth, qc,
			       gqc, dns_rdatatype_aaaa) == ISC_R_SUCCESS)
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
	copy_namehook_lists(adb, find, adbname);

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
		find->flags |= FIND_EVENT_SENT;
		find->flags &= ~DNS_ADBFIND_ADDRESSMASK;
	}

	find->partial_result |= (adbname->partial_result & wanted_addresses);
	if (alias) {
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
		find->loop = loop;
		atomic_store(&find->status, DNS_ADB_UNSET);
		find->cb = cb;
		find->cbarg = cbarg;
	}

	*findp = find;

	UNLOCK(&adbname->lock);
	dns_adbname_detach(&adbname);

	rcu_read_unlock();

	return result;
}

void
dns_adb_destroyfind(dns_adbfind_t **findp) {
	dns_adbfind_t *find = NULL;
	dns_adb_t *adb = NULL;

	REQUIRE(findp != NULL && DNS_ADBFIND_VALID(*findp));

	find = *findp;
	*findp = NULL;

	DP(DEF_LEVEL, "dns_adb_destroyfind on find %p", find);

	adb = find->adb;

	LOCK(&find->lock);

	REQUIRE(find->adbname == NULL);

	/*
	 * Free the addrinfo objects on the find's list. Note that
	 * we also need to decrement the reference counter in the
	 * associated adbentry every time we remove one from the list.
	 */
	ISC_LIST_FOREACH (find->list, ai, publink) {
		ISC_LIST_UNLINK(find->list, ai, publink);
		free_adbaddrinfo(adb, &ai);
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
		atomic_store(&find->status, DNS_ADB_CANCELED);

		DP(DEF_LEVEL, "sending find %p to caller", find);

		isc_async_run(find->loop, find->cb, find);
	}
}

void
dns_adb_cancelfind(dns_adbfind_t *find) {
	dns_adbname_t *adbname = NULL;

	DP(DEF_LEVEL, "dns_adb_cancelfind on find %p", find);

	REQUIRE(DNS_ADBFIND_VALID(find));
	REQUIRE(DNS_ADB_VALID(find->adb));

	LOCK(&find->lock);
	REQUIRE(FIND_WANTEVENT(find));

	adbname = find->adbname;

	if (adbname == NULL) {
		find_sendevent(find);
		UNLOCK(&find->lock);
	} else {
		/*
		 * Release the find lock, then acquire the name and find
		 * locks in that order, to match locking hierarchy
		 * elsewhere.
		 */
		dns_adbname_ref(adbname);
		UNLOCK(&find->lock);

		/*
		 * Other thread could cancel the find between the unlock and
		 * lock, so we need to recheck whether the adbname is still
		 * valid and reference the adbname, so it does not vanish before
		 * we have a chance to lock it again.
		 */

		LOCK(&adbname->lock);
		LOCK(&find->lock);

		if (find->adbname != NULL) {
			ISC_LIST_UNLINK(find->adbname->finds, find, plink);
			find->adbname = NULL;
		}

		find_sendevent(find);

		UNLOCK(&find->lock);
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	}
}

unsigned int
dns_adb_findstatus(dns_adbfind_t *find) {
	REQUIRE(DNS_ADBFIND_VALID(find));

	return atomic_load(&find->status);
}

void
dns_adb_dump(dns_adb_t *adb, FILE *f) {
	isc_stdtime_t now = isc_stdtime_now();

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(f != NULL);

	rcu_read_lock();

	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return;
	}

	cleanup_names(adb, now);
	cleanup_entries(adb, now);
	dump_adb(adb, f, false, now);

	rcu_read_unlock();
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
	struct cds_lfht_iter iter;

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
	dns_adbname_t *adbname = NULL;
	cds_lfht_for_each_entry(adb->names_ht, &iter, adbname, ht_node) {
		LOCK(&adbname->lock);
		/*
		 * Dump the names
		 */
		if (debug) {
			fprintf(f, "; name %p (flags %08x)\n", adbname,
				adbname->flags);
		}
		fprintf(f, "; ");
		dns_name_print(adbname->name, f);

		dump_ttl(f, "v4", adbname->expire_v4, now);
		dump_ttl(f, "v6", adbname->expire_v6, now);

		fprintf(f, " [v4 %s] [v6 %s]", errnames[adbname->fetch_err],
			errnames[adbname->fetch6_err]);

		fprintf(f, "\n");

		print_namehook_list(f, "v4", adb, &adbname->v4, debug, now);
		print_namehook_list(f, "v6", adb, &adbname->v6, debug, now);

		if (debug) {
			print_fetch_list(f, adbname);
			print_find_list(f, adbname);
		}
		UNLOCK(&adbname->lock);
	}

	dns_adbentry_t *adbentry = NULL;

	fprintf(f, ";\n; Unassociated entries\n;\n");
	cds_lfht_for_each_entry(adb->entries_ht, &iter, adbentry, ht_node) {
		LOCK(&adbentry->lock);
		if (ISC_LIST_EMPTY(adbentry->nhs)) {
			dump_entry(f, adb, adbentry, debug, now);
		}
		UNLOCK(&adbentry->lock);
	}
}

static void
dump_entry(FILE *f, dns_adb_t *adb, dns_adbentry_t *entry, bool debug,
	   isc_stdtime_t now) {
	char addrbuf[ISC_NETADDR_FORMATSIZE];
	isc_netaddr_t netaddr;

	isc_netaddr_fromsockaddr(&netaddr, &entry->sockaddr);
	isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));

	if (debug) {
		fprintf(f, ";\t%p: refcnt %" PRIuFAST32 "\n", entry,
			isc_refcount_current(&entry->references));
	}

	fprintf(f,
		";\t%s [srtt %u] [flags %08x] [edns %u/%u] "
		"[plain %u/%u]",
		addrbuf, atomic_load(&entry->srtt), atomic_load(&entry->flags),
		entry->edns, entry->ednsto, entry->plain, entry->plainto);
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
	fprintf(f, " [ttl %d]", entry->expires - now);

	if (adb != NULL && adb->quota != 0 && adb->atr_freq != 0) {
		uint_fast32_t quota = atomic_load_relaxed(&entry->quota);
		fprintf(f, " [atr %0.2f] [quota %" PRIuFAST32 "]", entry->atr,
			quota);
	}

	fprintf(f, "\n");
}

static void
dumpfind(dns_adbfind_t *find, FILE *f) {
	char tmp[512];
	const char *tmpp = NULL;
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
	fprintf(f, ";\tname %p\n", find->adbname);

	if (!ISC_LIST_EMPTY(find->list)) {
		fprintf(f, "\tAddresses:\n");
	}
	ISC_LIST_FOREACH (find->list, ai, publink) {
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
	}

	UNLOCK(&find->lock);
}

static void
print_namehook_list(FILE *f, const char *legend, dns_adb_t *adb,
		    dns_adbnamehooklist_t *list, bool debug,
		    isc_stdtime_t now) {
	ISC_LIST_FOREACH (*list, nh, name_link) {
		if (debug) {
			fprintf(f, ";\tHook(%s) %p\n", legend, nh);
		}
		LOCK(&nh->entry->lock);
		dump_entry(f, adb, nh->entry, debug, now);
		UNLOCK(&nh->entry->lock);
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
	ISC_LIST_FOREACH (name->finds, find, plink) {
		dumpfind(find, f);
	}
}

static isc_result_t
putstr(isc_buffer_t **b, const char *str) {
	isc_result_t result;

	result = isc_buffer_reserve(*b, strlen(str));
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	isc_buffer_putstr(*b, str);
	return ISC_R_SUCCESS;
}

isc_result_t
dns_adb_dumpquota(dns_adb_t *adb, isc_buffer_t **buf) {
	REQUIRE(DNS_ADB_VALID(adb));

	dns_adbentry_t *adbentry = NULL;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return ISC_R_SHUTTINGDOWN;
	}

	cds_lfht_for_each_entry(adb->entries_ht, &iter, adbentry, ht_node) {
		LOCK(&adbentry->lock);
		char addrbuf[ISC_NETADDR_FORMATSIZE];
		char text[ISC_NETADDR_FORMATSIZE + BUFSIZ];
		isc_netaddr_t netaddr;

		if (adbentry->atr == 0.0 && adbentry->quota == adb->quota) {
			goto unlock;
		}

		isc_netaddr_fromsockaddr(&netaddr, &adbentry->sockaddr);
		isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));

		snprintf(text, sizeof(text),
			 "\n- quota %s (%" PRIuFAST32 "/%d) atr %0.2f", addrbuf,
			 atomic_load_relaxed(&adbentry->quota), adb->quota,
			 adbentry->atr);
		putstr(buf, text);
	unlock:
		UNLOCK(&adbentry->lock);
	}
	rcu_read_unlock();

	return ISC_R_SUCCESS;
}

static isc_result_t
dbfind_name(dns_adbname_t *adbname, isc_stdtime_t now, dns_rdatatype_t rdtype) {
	isc_result_t result;
	dns_rdataset_t rdataset;
	dns_adb_t *adb = NULL;
	dns_fixedname_t foundname;
	dns_name_t *fname = NULL;
	unsigned int options = DNS_DBFIND_GLUEOK | DNS_DBFIND_ADDITIONALOK;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(dns_rdatatype_isaddr(rdtype));

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
	 * case DNS_ADBFIND_STARTATZONE is set) we need to stop the search at
	 * any matching static-stub zone without looking into the cache to honor
	 * the configuration on which server we should send queries to.
	 */
	if ((adbname->type & DNS_ADBFIND_STARTATZONE) != 0) {
		options |= DNS_DBFIND_PENDINGOK;
	}
	result = dns_view_find(adb->view, adbname->name, rdtype, now, options,
			       true,
			       (adbname->type & DNS_ADBFIND_STARTATZONE) != 0,
			       NULL, NULL, fname, &rdataset, NULL);

	switch (result) {
	case DNS_R_GLUE:
	case DNS_R_HINT:
		result = ISC_R_SUCCESS;
		FALLTHROUGH;
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
		import_rdataset(adbname, &rdataset, now);
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
		 * We found a CNAME or DNAME. Mark this as an
		 * alias (not to be used) and mark the expiry
		 * for both address families so we won't ask again
		 * for a while.
		 */
		rdataset.ttl = ttlclamp(rdataset.ttl);
		result = DNS_R_ALIAS;
		adbname->flags |= NAME_IS_ALIAS;
		adbname->expire_v4 = adbname->expire_v6 =
			ADJUSTED_EXPIRE(INT_MAX, now, rdataset.ttl);
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

	return result;
}

static void
fetch_callback(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	dns_adbname_t *name = resp->arg;
	dns_adb_t *adb = NULL;
	dns_adbfetch_t *fetch = NULL;
	dns_adbstatus_t astat = DNS_ADB_NOMOREADDRESSES;
	isc_stdtime_t now = isc_stdtime_now();
	unsigned int address_type;

	REQUIRE(DNS_ADBNAME_VALID(name));
	dns_adb_attach(name->adb, &adb);

	REQUIRE(DNS_ADB_VALID(adb));

	rcu_read_lock();

	LOCK(&name->lock);

	INSIST(NAME_FETCH_A(name) || NAME_FETCH_AAAA(name));
	address_type = 0;
	if (NAME_FETCH_A(name) && (name->fetch_a->fetch == resp->fetch)) {
		address_type = DNS_ADBFIND_INET;
		fetch = name->fetch_a;
		name->fetch_a = NULL;
	} else if (NAME_FETCH_AAAA(name) &&
		   (name->fetch_aaaa->fetch == resp->fetch))
	{
		address_type = DNS_ADBFIND_INET6;
		fetch = name->fetch_aaaa;
		name->fetch_aaaa = NULL;
	} else {
		fetch = NULL;
	}

	INSIST(address_type != 0 && fetch != NULL);

	/*
	 * Cleanup things we don't care about.
	 */
	if (resp->node != NULL) {
		dns_db_detachnode(resp->db, &resp->node);
	}
	if (resp->db != NULL) {
		dns_db_detach(&resp->db);
	}

	if (atomic_load(&adb->shuttingdown)) {
		astat = DNS_ADB_SHUTTINGDOWN;
		goto out;
	}

	/*
	 * If this name is marked as dead, clean up, throwing away
	 * potentially good data.
	 */
	if (cds_lfht_is_node_deleted(&name->ht_node)) {
		astat = DNS_ADB_CANCELED;
		goto out;
	}

	/*
	 * If we got a negative cache response, remember it.
	 */
	if (NCACHE_RESULT(resp->result)) {
		resp->rdataset->ttl = ttlclamp(resp->rdataset->ttl);
		if (address_type == DNS_ADBFIND_INET) {
			name->expire_v4 = ADJUSTED_EXPIRE(name->expire_v4, now,
							  resp->rdataset->ttl);
			DP(NCACHE_LEVEL,
			   "adb fetch name %p: "
			   "caching negative entry for A (ttl %u)",
			   name, name->expire_v4);
			if (resp->result == DNS_R_NCACHENXDOMAIN) {
				name->fetch_err = FIND_ERR_NXDOMAIN;
			} else {
				name->fetch_err = FIND_ERR_NXRRSET;
			}
			inc_resstats(adb, dns_resstatscounter_gluefetchv4fail);
		} else {
			name->expire_v6 = ADJUSTED_EXPIRE(name->expire_v6, now,
							  resp->rdataset->ttl);
			DP(NCACHE_LEVEL,
			   "adb fetch name %p: "
			   "caching negative entry for AAAA (ttl %u)",
			   name, name->expire_v6);
			if (resp->result == DNS_R_NCACHENXDOMAIN) {
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
	if (resp->result == DNS_R_CNAME || resp->result == DNS_R_DNAME) {
		resp->rdataset->ttl = ttlclamp(resp->rdataset->ttl);
		name->flags |= NAME_IS_ALIAS;
		name->expire_v4 = name->expire_v6 =
			ADJUSTED_EXPIRE(INT_MAX, now, resp->rdataset->ttl);
		goto moreaddrs;
	}

	/*
	 * Did we get back junk?  If so, and there are no more fetches
	 * sitting out there, tell all the finds about it.
	 */
	if (resp->result != ISC_R_SUCCESS) {
		char buf[DNS_NAME_FORMATSIZE];

		dns_name_format(name->name, buf, sizeof(buf));
		DP(DEF_LEVEL, "adb: fetch of '%s' %s failed: %s", buf,
		   address_type == DNS_ADBFIND_INET ? "A" : "AAAA",
		   isc_result_totext(resp->result));
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
	import_rdataset(name, &fetch->rdataset, now);

moreaddrs:
	astat = DNS_ADB_MOREADDRESSES;
	if (address_type == DNS_ADBFIND_INET) {
		name->fetch_err = FIND_ERR_SUCCESS;
	} else {
		name->fetch6_err = FIND_ERR_SUCCESS;
	}

out:
	dns_resolver_destroyfetch(&fetch->fetch);
	free_adbfetch(adb, &fetch);
	dns_resolver_freefresp(&resp);
	if (astat != DNS_ADB_CANCELED) {
		clean_finds_at_name(name, astat, address_type);
	}
	UNLOCK(&name->lock);
	dns_adbname_detach(&name);
	dns_adb_detach(&adb);

	rcu_read_unlock();
}

static isc_result_t
fetch_name(dns_adbname_t *adbname, bool start_at_zone, bool no_validation,
	   unsigned int depth, isc_counter_t *qc, isc_counter_t *gqc,
	   dns_rdatatype_t type) {
	isc_result_t result;
	dns_adbfetch_t *fetch = NULL;
	dns_adb_t *adb = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	dns_rdataset_t rdataset;
	dns_rdataset_t *nameservers = NULL;
	unsigned int options = no_validation ? DNS_FETCHOPT_NOVALIDATE : 0;

	REQUIRE(DNS_ADBNAME_VALID(adbname));

	adb = adbname->adb;

	REQUIRE(DNS_ADB_VALID(adb));

	REQUIRE((type == dns_rdatatype_a && !NAME_FETCH_A(adbname)) ||
		(type == dns_rdatatype_aaaa && !NAME_FETCH_AAAA(adbname)));

	adbname->fetch_err = FIND_ERR_NOTFOUND;

	dns_rdataset_init(&rdataset);

	if (start_at_zone) {
		DP(ENTER_LEVEL, "fetch_name: starting at zone for name %p",
		   adbname);
		name = dns_fixedname_initname(&fixed);
		result = dns_view_findzonecut(adb->view, adbname->name, name,
					      NULL, 0, 0, true, false,
					      &rdataset, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_HINT) {
			goto cleanup;
		}
		nameservers = &rdataset;
		options |= DNS_FETCHOPT_UNSHARED;
	} else if (adb->view->qminimization) {
		options |= DNS_FETCHOPT_QMINIMIZE | DNS_FETCHOPT_QMIN_SKIP_IP6A;
		if (adb->view->qmin_strict) {
			options |= DNS_FETCHOPT_QMIN_STRICT;
		}
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
	dns_adbname_ref(adbname);
	result = dns_resolver_createfetch(
		adb->res, adbname->name, type, name, nameservers, NULL, NULL, 0,
		options, depth, qc, gqc, isc_loop(), fetch_callback, adbname,
		NULL, &fetch->rdataset, NULL, &fetch->fetch);
	if (result != ISC_R_SUCCESS) {
		DP(ENTER_LEVEL, "fetch_name: createfetch failed with %s",
		   isc_result_totext(result));
		dns_adbname_unref(adbname);
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

	return result;
}

void
dns_adb_adjustsrtt(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int rtt,
		   unsigned int factor) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));
	REQUIRE(factor <= 10);

	isc_stdtime_t now = 0;
	if (factor == DNS_ADB_RTTADJAGE) {
		now = isc_stdtime_now();
	}

	adjustsrtt(addr, rtt, factor, now);
}

void
dns_adb_agesrtt(dns_adb_t *adb, dns_adbaddrinfo_t *addr, isc_stdtime_t now) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	adjustsrtt(addr, 0, DNS_ADB_RTTADJAGE, now);
}

static void
adjustsrtt(dns_adbaddrinfo_t *addr, unsigned int rtt, unsigned int factor,
	   isc_stdtime_t now) {
	unsigned int new_srtt;

	if (factor == DNS_ADB_RTTADJAGE) {
		if (atomic_load(&addr->entry->lastage) != now) {
			new_srtt = (uint64_t)atomic_load(&addr->entry->srtt) *
				   98 / 100;
			atomic_store(&addr->entry->lastage, now);
			atomic_store(&addr->entry->srtt, new_srtt);
			addr->srtt = new_srtt;
		}
	} else {
		new_srtt = ((uint64_t)atomic_load(&addr->entry->srtt) / 10 *
			    factor) +
			   ((uint64_t)rtt / 10 * (10 - factor));
		atomic_store(&addr->entry->srtt, new_srtt);
		addr->srtt = new_srtt;
	}
}

void
dns_adb_changeflags(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int bits,
		    unsigned int mask) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;

	unsigned int flags = atomic_load(&entry->flags);
	while (!atomic_compare_exchange_strong(&entry->flags, &flags,
					       (flags & ~mask) | (bits & mask)))
	{
		/* repeat */
	}

	/*
	 * Note that we do not update the other bits in addr->flags with
	 * the most recent values from addr->entry->flags.
	 */
	addr->flags = (addr->flags & ~mask) | (bits & mask);
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
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;
	LOCK(&entry->lock);

	maybe_adjust_quota(adb, addr, false);

	entry->plain++;
	if (entry->plain == 0xff) {
		entry->edns >>= 1;
		entry->ednsto >>= 1;
		entry->plain >>= 1;
		entry->plainto >>= 1;
	}
	UNLOCK(&entry->lock);
}

void
dns_adb_timeout(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;
	LOCK(&entry->lock);

	maybe_adjust_quota(adb, addr, true);

	addr->entry->plainto++;
	if (addr->entry->plainto == 0xff) {
		addr->entry->edns >>= 1;
		addr->entry->ednsto >>= 1;
		addr->entry->plain >>= 1;
		addr->entry->plainto >>= 1;
	}
	UNLOCK(&entry->lock);
}

void
dns_adb_ednsto(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;
	LOCK(&entry->lock);

	maybe_adjust_quota(adb, addr, true);

	entry->ednsto++;
	if (addr->entry->ednsto == 0xff) {
		entry->edns >>= 1;
		entry->ednsto >>= 1;
		entry->plain >>= 1;
		entry->plainto >>= 1;
	}
	UNLOCK(&entry->lock);
}

void
dns_adb_setudpsize(dns_adb_t *adb, dns_adbaddrinfo_t *addr, unsigned int size) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;

	LOCK(&entry->lock);
	if (size < 512U) {
		size = 512U;
	}
	if (size > addr->entry->udpsize) {
		addr->entry->udpsize = size;
	}

	maybe_adjust_quota(adb, addr, false);

	entry->edns++;
	if (entry->edns == 0xff) {
		entry->edns >>= 1;
		entry->ednsto >>= 1;
		entry->plain >>= 1;
		entry->plainto >>= 1;
	}
	UNLOCK(&entry->lock);
}

unsigned int
dns_adb_getudpsize(dns_adb_t *adb, dns_adbaddrinfo_t *addr) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	unsigned int size;
	dns_adbentry_t *entry = addr->entry;

	LOCK(&entry->lock);
	size = entry->udpsize;
	UNLOCK(&entry->lock);

	return size;
}

void
dns_adb_setcookie(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		  const unsigned char *cookie, size_t len) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;

	LOCK(&entry->lock);

	if (entry->cookie != NULL &&
	    (cookie == NULL || len != entry->cookielen))
	{
		isc_mem_put(adb->mctx, entry->cookie, entry->cookielen);
		entry->cookielen = 0;
	}

	if (entry->cookie == NULL && cookie != NULL && len != 0U) {
		entry->cookie = isc_mem_get(adb->mctx, len);
		entry->cookielen = (uint16_t)len;
	}

	if (entry->cookie != NULL) {
		memmove(entry->cookie, cookie, len);
	}
	UNLOCK(&entry->lock);
}

size_t
dns_adb_getcookie(dns_adbaddrinfo_t *addr, unsigned char *cookie, size_t len) {
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	dns_adbentry_t *entry = addr->entry;

	LOCK(&entry->lock);
	if (entry->cookie == NULL) {
		len = 0;
		goto unlock;
	}
	if (cookie != NULL) {
		if (len < entry->cookielen) {
			len = 0;
			goto unlock;
		}
		memmove(cookie, entry->cookie, entry->cookielen);
	}
	len = entry->cookielen;

unlock:
	UNLOCK(&entry->lock);

	return len;
}

isc_result_t
dns_adb_findaddrinfo(dns_adb_t *adb, const isc_sockaddr_t *addr,
		     dns_adbaddrinfo_t **adbaddrp, isc_stdtime_t now) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(adbaddrp != NULL && *adbaddrp == NULL);

	rcu_read_lock();
	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return ISC_R_SHUTTINGDOWN;
	}

	dns_adbentry_t *adbentry = get_attached_and_locked_entry(adb, now,
								 addr);

	in_port_t port = isc_sockaddr_getport(addr);
	*adbaddrp = new_adbaddrinfo(adb, adbentry, port);

	UNLOCK(&adbentry->lock);
	dns_adbentry_detach(&adbentry);

	rcu_read_unlock();

	return ISC_R_SUCCESS;
}

void
dns_adb_freeaddrinfo(dns_adb_t *adb, dns_adbaddrinfo_t **addrp) {
	dns_adbaddrinfo_t *addr = NULL;
	dns_adbentry_t *entry = NULL;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(addrp != NULL);

	addr = *addrp;
	*addrp = NULL;

	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	entry = addr->entry;

	REQUIRE(DNS_ADBENTRY_VALID(entry));

	free_adbaddrinfo(adb, &addr);
}

void
dns_adb_flush(dns_adb_t *adb) {
	REQUIRE(DNS_ADB_VALID(adb));

	rcu_read_lock();

	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return;
	}

	cleanup_names(adb, INT_MAX);
	cleanup_entries(adb, INT_MAX);
#ifdef DUMP_ADB_AFTER_CLEANING
	dump_adb(adb, stdout, true, INT_MAX);
#endif /* ifdef DUMP_ADB_AFTER_CLEANING */

	rcu_read_unlock();
}

void
dns_adb_flushname(dns_adb_t *adb, const dns_name_t *name) {
	dns_adbname_t *adbname = NULL;
	bool start_at_zone = false;
	bool static_stub = false;
	bool novalidate = false;
	dns_adbname_t key = { .name = UNCONST(name) };

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(name != NULL);

	rcu_read_lock();

	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return;
	}
again:
	/*
	 * Delete all entries - with and without DNS_ADBFIND_STARTATZONE set
	 * with and without DNS_ADBFIND_STATICSTUB set and with and without
	 * DNS_ADBFIND_NOVALIDATE set.
	 */
	key.type = ((static_stub) ? DNS_ADBFIND_STATICSTUB : 0) |
		   ((start_at_zone) ? DNS_ADBFIND_STARTATZONE : 0) |
		   ((novalidate) ? DNS_ADBFIND_NOVALIDATE : 0);

	uint32_t hashval = hash_adbname(&key);
	struct cds_lfht_iter iter;
	cds_lfht_lookup(adb->names_ht, hashval, match_adbname, &key, &iter);

	adbname = cds_lfht_entry(cds_lfht_iter_get_node(&iter), dns_adbname_t,
				 ht_node);

	if (adbname != NULL) {
		dns_adbname_ref(adbname);
		LOCK(&adbname->lock);
		if (dns_name_equal(name, adbname->name)) {
			expire_name(adbname, DNS_ADB_CANCELED);
		}
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	}
	if (!start_at_zone) {
		start_at_zone = true;
		goto again;
	}
	if (!static_stub) {
		static_stub = true;
		goto again;
	}
	if (!novalidate) {
		start_at_zone = false;
		static_stub = false;
		novalidate = true;
		goto again;
	}
	rcu_read_unlock();
}

void
dns_adb_flushnames(dns_adb_t *adb, const dns_name_t *name) {
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(name != NULL);

	rcu_read_lock();

	if (atomic_load(&adb->shuttingdown)) {
		rcu_read_unlock();
		return;
	}

	dns_adbname_t *adbname = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(adb->names_ht, &iter, adbname, ht_node) {
		dns_adbname_ref(adbname);
		LOCK(&adbname->lock);
		if (dns_name_issubdomain(adbname->name, name)) {
			expire_name(adbname, DNS_ADB_CANCELED);
		}
		UNLOCK(&adbname->lock);
		dns_adbname_detach(&adbname);
	}
	rcu_read_unlock();
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
		isc_mem_setwater(adb->mctx, hiwater, lowater);
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

void
dns_adb_getquota(dns_adb_t *adb, uint32_t *quotap, uint32_t *freqp,
		 double *lowp, double *highp, double *discountp) {
	REQUIRE(DNS_ADB_VALID(adb));

	SET_IF_NOT_NULL(quotap, adb->quota);

	SET_IF_NOT_NULL(freqp, adb->atr_freq);

	SET_IF_NOT_NULL(lowp, adb->atr_low);

	SET_IF_NOT_NULL(highp, adb->atr_high);

	SET_IF_NOT_NULL(discountp, adb->atr_discount);
}

static bool
adbentry_overquota(dns_adbentry_t *entry) {
	REQUIRE(DNS_ADBENTRY_VALID(entry));

	uint_fast32_t quota = atomic_load_relaxed(&entry->quota);
	uint_fast32_t active = atomic_load_acquire(&entry->active);

	return quota != 0 && active >= quota;
}

bool
dns_adb_overquota(dns_adb_t *adb ISC_ATTR_UNUSED, dns_adbaddrinfo_t *addrinfo) {
	REQUIRE(DNS_ADBADDRINFO_VALID(addrinfo));

	return adbentry_overquota(addrinfo->entry);
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

	return adb->stats;
}
