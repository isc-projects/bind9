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

/*! \file */

#include <stdbool.h>

#include <dns/adb.h>
#include <dns/db.h>
#include <dns/notify.h>
#include <dns/remote.h>
#include <dns/update.h>
#include <dns/zonefetch.h>

/*%
 *	Types and functions below meant to be used for internal zone
 *	modules only, and associated unit tests.
 */

#define ZONE_MAGIC	     ISC_MAGIC('Z', 'O', 'N', 'E')
#define DNS_ZONE_VALID(zone) ISC_MAGIC_VALID(zone, ZONE_MAGIC)

#define CHECKDS_MAGIC		   ISC_MAGIC('C', 'h', 'D', 'S')
#define DNS_CHECKDS_VALID(checkds) ISC_MAGIC_VALID(checkds, CHECKDS_MAGIC)

#define STUB_MAGIC	     ISC_MAGIC('S', 't', 'u', 'b')
#define DNS_STUB_VALID(stub) ISC_MAGIC_VALID(stub, STUB_MAGIC)

#define ZONEMGR_MAGIC		ISC_MAGIC('Z', 'm', 'g', 'r')
#define DNS_ZONEMGR_VALID(stub) ISC_MAGIC_VALID(stub, ZONEMGR_MAGIC)

#define FORWARD_MAGIC		ISC_MAGIC('F', 'o', 'r', 'w')
#define DNS_FORWARD_VALID(load) ISC_MAGIC_VALID(load, FORWARD_MAGIC)

#define IO_MAGIC	   ISC_MAGIC('Z', 'm', 'I', 'O')
#define DNS_IO_VALID(load) ISC_MAGIC_VALID(load, IO_MAGIC)

/*
 * Default values.
 */
#define DNS_DEFAULT_IDLEIN  3600       /*%< 1 hour */
#define DNS_DEFAULT_IDLEOUT 3600       /*%< 1 hour */
#define MAX_XFER_TIME	    (2 * 3600) /*%< Documented default is 2 hours */
#define RESIGN_DELAY	    3600       /*%< 1 hour */

#ifndef DNS_MAX_EXPIRE
#define DNS_MAX_EXPIRE 14515200 /*%< 24 weeks */
#endif				/* ifndef DNS_MAX_EXPIRE */

#ifndef DNS_DUMP_DELAY
#define DNS_DUMP_DELAY 900 /*%< 15 minutes */
#endif			   /* ifndef DNS_DUMP_DELAY */

/*%
 * Transport timeouts.
 */
#define UDP_REQUEST_TIMEOUT 5 /*%< 5 seconds */
#define UDP_REQUEST_RETRIES 2
#define TCP_REQUEST_TIMEOUT \
	(UDP_REQUEST_TIMEOUT * (UDP_REQUEST_RETRIES + 1) + 1)

/*%
 * Zone locks.
 */
#define DNS_ZONE_CHECKLOCK
#ifdef DNS_ZONE_CHECKLOCK
#define LOCK_ZONE(z)                  \
	do {                          \
		LOCK(&(z)->lock);     \
		INSIST(!(z)->locked); \
		(z)->locked = true;   \
	} while (0)
#define UNLOCK_ZONE(z)               \
	do {                         \
		INSIST((z)->locked); \
		(z)->locked = false; \
		UNLOCK(&(z)->lock);  \
	} while (0)
#define LOCKED_ZONE(z) ((z)->locked)
#define TRYLOCK_ZONE(result, z)                         \
	do {                                            \
		result = isc_mutex_trylock(&(z)->lock); \
		if (result == ISC_R_SUCCESS) {          \
			INSIST(!(z)->locked);           \
			(z)->locked = true;             \
		}                                       \
	} while (0)
#else /* ifdef DNS_ZONE_CHECKLOCK */
#define LOCK_ZONE(z)   LOCK(&(z)->lock)
#define UNLOCK_ZONE(z) UNLOCK(&(z)->lock)
#define LOCKED_ZONE(z) true
#define TRYLOCK_ZONE(result, z)                         \
	do {                                            \
		result = isc_mutex_trylock(&(z)->lock); \
	} while (0)
#endif /* ifdef DNS_ZONE_CHECKLOCK */

#define ZONEDB_INITLOCK(l)    isc_rwlock_init(l)
#define ZONEDB_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define ZONEDB_LOCK(l, t)     RWLOCK((l), (t))
#define ZONEDB_UNLOCK(l, t)   RWUNLOCK((l), (t))

/*%
 * Zone flags.
 */
#define DNS_ZONE_FLAG(z, f)    ((atomic_load_relaxed(&(z)->flags) & (f)) != 0)
#define DNS_ZONE_SETFLAG(z, f) atomic_fetch_or(&(z)->flags, (f))
#define DNS_ZONE_CLRFLAG(z, f) atomic_fetch_and(&(z)->flags, ~(f))
typedef enum {
	DNS_ZONEFLG_REFRESH = 1U << 0,	    /*%< refresh check in progress */
	DNS_ZONEFLG_NEEDDUMP = 1U << 1,	    /*%< zone need consolidation */
	DNS_ZONEFLG_USEVC = 1U << 2,	    /*%< use tcp for refresh query */
	DNS_ZONEFLG_DUMPING = 1U << 3,	    /*%< a dump is in progress */
	DNS_ZONEFLG_HASINCLUDE = 1U << 4,   /*%< $INCLUDE in zone file */
	DNS_ZONEFLG_LOADED = 1U << 5,	    /*%< database has loaded */
	DNS_ZONEFLG_EXITING = 1U << 6,	    /*%< zone is being destroyed */
	DNS_ZONEFLG_EXPIRED = 1U << 7,	    /*%< zone has expired */
	DNS_ZONEFLG_NEEDREFRESH = 1U << 8,  /*%< refresh check needed */
	DNS_ZONEFLG_UPTODATE = 1U << 9,	    /*%< zone contents are
					     * up-to-date */
	DNS_ZONEFLG_NEEDNOTIFY = 1U << 10,  /*%< need to send out notify
					     * messages */
	DNS_ZONEFLG_FIXJOURNAL = 1U << 11,  /*%< journal file had
					     * recoverable error,
					     * needs rewriting */
	DNS_ZONEFLG_NOPRIMARIES = 1U << 12, /*%< an attempt to refresh a
					     * zone with no primaries
					     * occurred */
	DNS_ZONEFLG_LOADING = 1U << 13,	    /*%< load from disk in progress*/
	DNS_ZONEFLG_HAVETIMERS = 1U << 14,  /*%< timer values have been set
					     * from SOA (if not set, we
					     * are still using
					     * default timer values) */
	DNS_ZONEFLG_FORCEXFER = 1U << 15,   /*%< Force a zone xfer */
	DNS_ZONEFLG_SHUTDOWN = 1U << 16,
	DNS_ZONEFLG_NOIXFR = 1U << 17, /*%< IXFR failed, force AXFR */
	DNS_ZONEFLG_FLUSH = 1U << 18,
	DNS_ZONEFLG_NOEDNS = 1U << 19,
	DNS_ZONEFLG_USEALTXFRSRC = 1U << 20, /*%< Obsoleted. */
	DNS_ZONEFLG_SOABEFOREAXFR = 1U << 21,
	DNS_ZONEFLG_NEEDCOMPACT = 1U << 22,
	DNS_ZONEFLG_REFRESHING = 1U << 23, /*%< Refreshing keydata */
	DNS_ZONEFLG_THAW = 1U << 24,
	DNS_ZONEFLG_LOADPENDING = 1U << 25, /*%< Loading scheduled */
	DNS_ZONEFLG_NODELAY = 1U << 26,
	DNS_ZONEFLG_NEEDSTARTUPNOTIFY = 1U << 28, /*%< need to send out
						   * notify due to the zone
						   * just being loaded for
						   * the first time. */
	DNS_ZONEFLG_NOTIFYNODEFER = 1U << 29,	  /*%< ignore the
						   * notify-defer option. */
	DNS_ZONEFLG_NOTIFYDEFERRED = 1U << 30,	  /*%< notify was deferred
						   * according to the
						   * notify-defer option. */
	DNS_ZONEFLG_FIRSTREFRESH = 1U << 31,	  /*%< First refresh pending */
	DNS_ZONEFLG___MAX = UINT64_MAX, /* trick to make the ENUM 64-bit wide */
} dns_zoneflg_t;

/*%
 * Zone options.
 */
#define DNS_ZONE_OPTION(z, o) ((atomic_load_relaxed(&(z)->options) & (o)) != 0)
#define DNS_ZONE_SETOPTION(z, o) atomic_fetch_or(&(z)->options, (o))
#define DNS_ZONE_CLROPTION(z, o) atomic_fetch_and(&(z)->options, ~(o))

/*%
 * Zone specific structures.
 */
typedef struct dns_checkds dns_checkds_t;
typedef struct dns_forward dns_forward_t;
typedef ISC_LIST(dns_forward_t) dns_forwardlist_t;
typedef struct dns_signing dns_signing_t;
typedef ISC_LIST(dns_signing_t) dns_signinglist_t;
typedef struct dns_nsec3chain dns_nsec3chain_t;
typedef ISC_LIST(dns_nsec3chain_t) dns_nsec3chainlist_t;
typedef struct dns_include dns_include_t;

/*
 * Pending inline-signing sync request for the secure zone.  Active
 * incremental signing continuation state is owned separately by rss_* fields.
 */
typedef enum inline_sync_state {
	inline_sync_idle = 0,	  /*%< No inline sync request is queued. */
	inline_sync_pull_pending, /*%< Incremental pull wake is queued. */
	inline_sync_full_pending, /*%< Full rebuild wake is queued. */
} inline_sync_state_t;

/*%
 * Hold checkds state.
 */
struct dns_checkds {
	unsigned int magic;
	dns_notify_flags_t flags;
	isc_mem_t *mctx;
	dns_zone_t *zone;
	dns_adbfind_t *find;
	dns_request_t *request;
	dns_name_t ns;
	isc_sockaddr_t src;
	isc_sockaddr_t dst;
	dns_tsigkey_t *key;
	dns_transport_t *transport;
	ISC_LINK(dns_checkds_t) link;
	isc_rlevent_t *rlevent;
};

/*%
 *	Hold forward state.
 */
struct dns_forward {
	unsigned int magic;
	isc_mem_t *mctx;
	dns_zone_t *zone;
	isc_buffer_t *msgbuf;
	dns_request_t *request;
	uint32_t which;
	isc_sockaddr_t addr;
	dns_transport_t *transport;
	dns_updatecallback_t callback;
	void *callback_arg;
	unsigned int options;
	ISC_LINK(dns_forward_t) link;
};

/*%
 *	Hold state for when we are signing a zone with a new
 *	DNSKEY as result of an update.
 */
struct dns_signing {
	unsigned int magic;
	dns_db_t *db;
	dns_dbiterator_t *dbiterator;
	dst_algorithm_t algorithm;
	uint16_t keyid;
	bool deleteit;
	bool fullsign;
	bool done;
	ISC_LINK(dns_signing_t) link;
};

struct dns_nsec3chain {
	unsigned int magic;
	dns_db_t *db;
	dns_dbiterator_t *dbiterator;
	dns_rdata_nsec3param_t nsec3param;
	unsigned char salt[255];
	bool done;
	bool seen_nsec;
	bool delete_nsec;
	bool save_delete_nsec;
	ISC_LINK(dns_nsec3chain_t) link;
};

/*%<
 * 'dbiterator' contains a iterator for the database.  If we are creating
 * a NSEC3 chain only the non-NSEC3 nodes will be iterated.  If we are
 * removing a NSEC3 chain then both NSEC3 and non-NSEC3 nodes will be
 * iterated.
 *
 * 'nsec3param' contains the parameters of the NSEC3 chain being created
 * or removed.
 *
 * 'salt' is buffer space and is referenced via 'nsec3param.salt'.
 *
 * 'seen_nsec' will be set to true if, while iterating the zone to create a
 * NSEC3 chain, a NSEC record is seen.
 *
 * 'delete_nsec' will be set to true if, at the completion of the creation
 * of a NSEC3 chain, 'seen_nsec' is true.  If 'delete_nsec' is true then we
 * are in the process of deleting the NSEC chain.
 *
 * 'save_delete_nsec' is used to store the initial state of 'delete_nsec'
 * so it can be recovered in the event of a error.
 */

/*%
 * Reference to an include file encountered during loading
 */
struct dns_include {
	char *name;
	isc_time_t filetime;
	ISC_LINK(dns_include_t) link;
};

typedef struct dns_rad {
	isc_mem_t *mctx;
	struct rcu_head rcu_head;
	dns_fixedname_t fname;
} dns_rad_t;

typedef struct zone_settimer {
	dns_zone_t *zone;
	isc_time_t now;
} zone_settimer_t;

/*%
 * Zone manager structure.
 */
struct dns_zonemgr {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t refs;
	uint32_t workers;
	isc_mem_t **mctxpool;
	isc_ratelimiter_t *checkdsrl;
	isc_ratelimiter_t *notifyrl;
	isc_ratelimiter_t *refreshrl;
	isc_ratelimiter_t *startupnotifyrl;
	isc_ratelimiter_t *startuprefreshrl;
	isc_rwlock_t rwlock;

	/* Locked by rwlock. */
	dns_zonelist_t zones;
	dns_zonelist_t waiting_for_xfrin;
	dns_zonelist_t xfrin_in_progress;

	/* Configuration data. */
	uint32_t transfersin;
	uint32_t transfersperns;
	unsigned int checkdsrate;
	unsigned int notifyrate;
	unsigned int startupnotifyrate;
	unsigned int serialqueryrate;
	unsigned int startupserialqueryrate;
	dns_keystorelist_t *keystores;

	isc_tlsctx_cache_t *tlsctx_cache;
	isc_rwlock_t tlsctx_cache_rwlock;
};

/*%
 * Zone structure.
 */
struct dns_zone {
	/* Unlocked */
	unsigned int magic;
	isc_mutex_t lock;
#ifdef DNS_ZONE_CHECKLOCK
	bool locked;
#endif /* ifdef DNS_ZONE_CHECKLOCK */
	isc_mem_t *mctx;
	isc_refcount_t references;

	isc_rwlock_t dblock;
	dns_db_t *db; /* Locked by dblock */

	isc_tid_t tid;
	/* Locked */
	dns_zonemgr_t *zmgr;
	ISC_LINK(dns_zone_t) link; /* Used by zmgr. */
	isc_loop_t *loop;
	isc_timer_t *timer;
	isc_refcount_t irefs;
	dns_name_t origin;
	dns_rad_t *rad;
	char *masterfile;
	char *initfile;
	const FILE *stream;		     /* loading from a stream? */
	ISC_LIST(dns_include_t) includes;    /* Include files */
	ISC_LIST(dns_include_t) newincludes; /* Loading */
	unsigned int nincludes;
	dns_masterformat_t masterformat;
	const dns_master_style_t *masterstyle;
	char *journal;
	int32_t journalsize;
	dns_rdataclass_t rdclass;
	dns_zonetype_t type;
	atomic_uint_fast64_t flags;
	atomic_uint_fast64_t options;
	unsigned int db_argc;
	char **db_argv;
	isc_time_t expiretime;
	isc_time_t refreshtime;
	isc_time_t dumptime;
	isc_time_t loadtime;
	isc_time_t notifytime;
	isc_time_t resigntime;
	isc_time_t keywarntime;
	isc_time_t signingtime;
	isc_time_t nsec3chaintime;
	isc_time_t refreshkeytime;
	isc_time_t xfrintime;
	uint32_t refreshkeyinterval;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
	isc_stdtime_t key_expiry;
	isc_stdtime_t log_key_expired_timer;
	char *keydirectory;
	dns_xfrin_t *xfr;

	uint32_t maxrefresh;
	uint32_t minrefresh;
	uint32_t maxretry;
	uint32_t minretry;

	uint32_t maxrecords;
	uint32_t maxrrperset;
	uint32_t maxtypepername;

	dns_remote_t primaries;

	dns_remote_t parentals;
	dns_dnsseckeylist_t checkds_ok;
	dns_checkdstype_t checkdstype;
	uint32_t parent_nscount;

	uint32_t fetchcount[ZONEFETCHTYPE_COUNT];

	dns_remote_t alsonotify;
	dns_notifyctx_t notifysoa;

	dns_remote_t cds_endpoints;
	dns_notifyctx_t notifycds;

	isc_sockaddr_t parentalsrc4;
	isc_sockaddr_t parentalsrc6;
	isc_sockaddr_t xfrsource4;
	isc_sockaddr_t xfrsource6;
	isc_sockaddr_t sourceaddr;
	dns_tsigkey_t *tsigkey;	    /* key used for xfr */
	dns_transport_t *transport; /* transport used for xfr */
	/* Access Control Lists */
	dns_acl_t *update_acl;
	dns_acl_t *forward_acl;
	dns_acl_t *query_acl;
	dns_acl_t *queryon_acl;
	dns_acl_t *xfr_acl;
	bool update_disabled;
	bool zero_no_soa_ttl;
	dns_severity_t check_names;

	ISC_LIST(dns_checkds_t) checkds_requests;
	dns_request_t *request;
	dns_loadctx_t *loadctx;
	dns_dumpctx_t *dumpctx;
	uint32_t minxfrratebytesin;
	uint32_t minxfrratesecondsin;
	uint32_t maxxfrin;
	uint32_t maxxfrout;
	uint32_t idlein;
	uint32_t idleout;
	dns_ssutable_t *ssutable;
	uint32_t sigvalidityinterval;
	uint32_t keyvalidityinterval;
	uint32_t sigresigninginterval;
	dns_view_t *view;
	dns_view_t *prev_view;
	dns_kasp_t *kasp;
	dns_kasp_t *defaultkasp;
	dns_dnsseckeylist_t keyring;
	dns_checkmxfunc_t checkmx;
	dns_checksrvfunc_t checksrv;
	dns_checknsfunc_t checkns;
	dns_checkisservedbyfunc_t checkisservedby;
	/*%
	 * Zones in certain states such as "waiting for zone transfer"
	 * or "zone transfer in progress" are kept on per-state linked lists
	 * in the zone manager using the 'statelink' field.  The 'statelist'
	 * field points at the list the zone is currently on.  It the zone
	 * is not on any such list, statelist is NULL.
	 */
	ISC_LINK(dns_zone_t) statelink;
	dns_zonelist_t *statelist;
	/*%
	 * Statistics counters about zone management.
	 */
	isc_stats_t *stats;

	/*
	 * Optional per-zone statistics counters.  Counted outside of this
	 * module.
	 */
	dns_zonestat_level_t statlevel;
	bool requeststats_on;
	isc_stats_t *requeststats;
	isc_statsmulti_t *rcvquerystats;
	dns_stats_t *dnssecsignstats;
	dns_isselffunc_t isself;
	void *isselfarg;

	char *strnamerd;
	char *strname;
	char *strrdclass;
	char *strviewname;

	/*%
	 * Serial number for deferred journal compaction.
	 */
	uint32_t compact_serial;
	/*%
	 * Keys that are signing the zone for the first time.
	 */
	dns_signinglist_t signing;
	dns_nsec3chainlist_t nsec3chain;
	/*%
	 * List of outstanding NSEC3PARAM change requests.
	 */
	ISC_LIST(struct np3) setnsec3param_queue;
	/*%
	 * Signing / re-signing quantum stopping parameters.
	 */
	uint32_t signatures;
	uint32_t nodes;
	dns_rdatatype_t privatetype;

	/*%
	 * True if added by "rndc addzone"
	 */
	bool added;

	/*%
	 * True if modded by "rndc modzone"
	 */
	bool modded;

	/*%
	 * True if added by automatically by named.
	 */
	bool automatic;

	/*%
	 * response policy data to be relayed to the database
	 */
	dns_rpz_zones_t *rpzs;
	dns_rpz_num_t rpz_num;

	/*%
	 * catalog zone data
	 */
	dns_catz_zones_t *catzs;

	/*%
	 * parent catalog zone
	 */
	dns_catz_zone_t *parentcatz;

	/*%
	 * Serial number update method.
	 */
	dns_updatemethod_t updatemethod;

	/*%
	 * whether ixfr is requested
	 */
	bool requestixfr;
	uint32_t requestixfr_maxdiffs;
	uint32_t ixfr_ratio;

	/*%
	 * whether EDNS EXPIRE is requested
	 */
	bool requestexpire;

	/*%
	 * Outstanding forwarded UPDATE requests.
	 */
	dns_forwardlist_t forwards;

	dns_zone_t *raw;
	dns_zone_t *secure;

	bool sourceserialset;
	uint32_t sourceserial;

	/*%
	 * soa and maximum zone ttl
	 */
	dns_ttl_t soattl;
	dns_ttl_t maxttl;

	/*
	 * Inline zone signing state.
	 */
	inline_sync_state_t inline_sync_state;
	dns_diff_t rss_diff;
	dns_dbversion_t *rss_newver;
	dns_dbversion_t *rss_oldver;
	dns_db_t *rss_db;
	dns_zone_t *rss_raw;
	uint32_t rss_end;
	dns_zone_t *rss_zone;
	dns_update_state_t *rss_state;

	isc_stats_t *gluecachestats;

	/*%
	 * Offline KSK signed key responses.
	 */
	dns_skr_t *skr;
	dns_skrbundle_t *skrbundle;

	/*
	 * Plugin-related data structures
	 */
	void *plugins;
	void (*plugins_free)(isc_mem_t *, void **);
	void *hooktable;
	void (*hooktable_free)(isc_mem_t *, void **);

	/* Configuration text */
	char *cfg;
};

typedef struct {
	dns_diff_t *diff;
	bool offline;
} dns__zonediff_t;

isc_result_t
dns__zone_updatesigs(dns_diff_t *diff, dns_db_t *db, dns_dbversion_t *version,
		     dst_key_t *zone_keys[], unsigned int nkeys,
		     dns_zone_t *zone, isc_stdtime_t inception,
		     isc_stdtime_t expire, isc_stdtime_t keyxpire,
		     isc_stdtime_t now, dns__zonediff_t *zonediff);

isc_result_t
dns__zone_lookup_nsec3param(dns_zone_t *zone, dns_rdata_nsec3param_t *lookup,
			    dns_rdata_nsec3param_t *param,
			    unsigned char saltbuf[255], bool resalt);

void
dns__zone_lock(dns_zone_t *zone);
/*%<
 *      Locks the zone.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 */

void
dns__zone_unlock(dns_zone_t *zone);
/*%<
 *      Unlocks the zone.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 */

bool
dns__zone_locked(dns_zone_t *zone);
/*%<
 *      Checks if the zone is locked.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is locked, false otherwise.
 */

bool
dns__zone_loaded(dns_zone_t *zone);
/*%<
 *      Checks if the zone is loaded.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is loaded, false otherwise.
 */

bool
dns__zone_exiting(dns_zone_t *zone);
/*%<
 *      Checks if the zone is exiting.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is exiting, false otherwise.
 */

void
dns__zone_stats_increment(dns_zone_t *zone, isc_statscounter_t counter);
/*%
 *      Increment resolver-related statistics counters
 *
 * Requires:
 *\li   'zone' to be a valid zone, and locked.
 */

dns_notifyctx_t *
dns__zone_getnotifyctx(dns_zone_t *zone, dns_rdatatype_t type);
/*%<
 *	Returns the notify context.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns__zonemgr_getnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl);
/*%<
 *	Get the NOTIFY requests rate limiter
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns__zonemgr_getstartupnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl);
/*%<
 *	Get the startup NOTIFY requests rate limiter
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns__zonemgr_tlsctx_attach(dns_zonemgr_t *zmgr,
			   isc_tlsctx_cache_t **ptlsctx_cache);
/*%<
 *	Attach to TLS client context cache used for zone transfers via
 * 	encrypted transports (e.g. XoT).
 *
 *	The obtained reference needs to be detached by a call to
 *	'isc_tlsctx_cache_detach()' when not needed anymore.
 *
 * Requires:
 *\li	'zmgr' is a valid zone manager.
 *\li	'ptlsctx_cache' is not 'NULL' and points to 'NULL'.
 */

void
dns__zone_getisself(dns_zone_t *zone, dns_isselffunc_t *isself, void **arg);
/*%<
 *	Returns the isself callback function and argument.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'isself' is not NULL.
 *\li	'arg' is not NULL and '*arg' is NULL.
 */

void
dns__zone_iattach_locked(dns_zone_t *source, dns_zone_t **target);
/*%<
 *      Attach '*target' to 'source' incrementing its internal
 *      reference count.  This is intended for use by operations
 *      such as zone transfers that need to prevent the zone
 *      object from being freed but not from shutting down.
 *
 * Require:
 *\li   The caller is running in the context of the zone's loop.
 *\li   'zone' to be a valid zone, already locked.
 *\li   'target' to be non NULL and '*target' to be NULL.
 */

void
dns__zone_idetach_locked(dns_zone_t **zonep);
/*%<
 *      Detach from a zone decrementing its internal reference count.
 *      If there are no more internal or external references to the
 *      zone, it will be freed.
 *
 * Require:
 *\li   The caller is running in the context of the zone's loop.
 *\li   'zonep' to point to a valid zone, already locked.
 */

isc_refcount_t *
dns__zone_irefs(dns_zone_t *zone);
/*%<
 *	Get the reference count of a zone.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone.
 */

void
dns__zone_free(dns_zone_t *zone);
/*
 *	Free a zone.  Because we require that there be no more
 *	outstanding events or references, no locking is necessary.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone, unlocked.
 */

bool
dns__zone_free_check(dns_zone_t *zone);

void
dns__zone_keymgmt_initialize(void);

void
dns__zone_keymgmt_shutdown(void);
/*
 *	Check if a zone is ready to be freed.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone, locked.
 */

void
dns__zone_setview_helper(dns_zone_t *zone, dns_view_t *view);
/*
 *	Helper function to associate a zone with a view.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone, locked.
 */

bool
dns__zone_inline_secure(dns_zone_t *zone);
/*
 *	Returns true iff this the signed side of an inline-signing zone.
 *	Caller should hold zone lock.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone, locked.
 */

bool
dns__zone_inline_raw(dns_zone_t *zone);
/*
 *	Returns true iff this the signed side of an inline-signing zone.
 *	Caller should hold zone lock.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone, locked.
 */

void
dns__zone_freedbargs(dns_zone_t *zone);
/*%<
 *	Free zone dbargs.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone.
 */

void
dns__zone_settimer(dns_zone_t *zone, isc_time_t now);
/*%<
 *	Sets zone timer to 'now' time.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone.
 */

void
dns__zone_set_resigntime(dns_zone_t *zone);
/*%<
 *	Calculates the next resign time and sets zone timer
 *	accordingly.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone, locked.
 */

void
dns__zone_forward_cancel(dns_zone_t *zone);
/*%<
 *	Cancel forwarding.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone, locked.
 */

void
dns__zone_xfrdone(dns_zone_t *zone, uint32_t *expireopt, isc_result_t result);
/*%<
 *	Process a finished zone transfer.
 *
 * Requires:
 *
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns__zonemgr_start_xfrin_ifquota(dns_zonemgr_t *zmgr, dns_zone_t *zone);
/*%<
 *	Try to start an incoming zone transfer for 'zone', quota permitting.
 *
 * Requires:
 *
 *\li	'zmgr' to be a valid zone manager.
 *
 * Returns:
 *
 *\li #ISC_R_SUCCESS	There was enough quota and we attempted to
 *			start a transfer.  zone_xfrdone() has been or will
 *			be called.
 *\li #ISC_R_QUOTA	Not enough quota.
 *\li Other failure.
 */

void
dns__zonemgr_resume_xfrs(dns_zonemgr_t *zmgr, bool multi);
/*%<
 *	Try to start a new incoming zone transfer to fill a quota
 *	slot that was just vacated.
 *
 * Requires:
 *
 *\li	'zmgr' to be a valid zone manager.
 */
