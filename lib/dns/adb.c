/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Implementation notes
 * --------------------
 *
 * In handles, if task == NULL, no events will be generated, and no events
 * have been sent.  If task != NULL but taskaction == NULL, an event has been
 * posted but not yet freed.  If neigher are NULL, no event was posted.
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/condition.h>
#include <isc/event.h>
#include <isc/magic.h>
#include <isc/mutex.h>
#include <isc/mutexblock.h>
#include <isc/random.h>
#include <isc/timer.h>

#include <dns/adb.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/types.h>
#include <dns/view.h>

#include "../isc/util.h"

#if 1
#define DP(x)		printf x
#else
#define DP(x)
#endif

#define DNS_ADB_MAGIC		  0x44616462	/* Dadb. */
#define DNS_ADB_VALID(x)	  ISC_MAGIC_VALID(x, DNS_ADB_MAGIC)
#define DNS_ADBNAME_MAGIC	  0x6164624e	/* adbN. */
#define DNS_ADBNAME_VALID(x)	  ISC_MAGIC_VALID(x, DNS_ADBNAME_MAGIC)
#define DNS_ADBNAMEHOOK_MAGIC	  0x61644e48	/* adNH. */
#define DNS_ADBNAMEHOOK_VALID(x)  ISC_MAGIC_VALID(x, DNS_ADBNAMEHOOK_MAGIC)
#define DNS_ADBZONEINFO_MAGIC	  0x6164625a	/* adbZ. */
#define DNS_ADBZONEINFO_VALID(x)  ISC_MAGIC_VALID(x, DNS_ADBZONEINFO_MAGIC)
#define DNS_ADBENTRY_MAGIC	  0x61646245	/* adbE. */
#define DNS_ADBENTRY_VALID(x)	  ISC_MAGIC_VALID(x, DNS_ADBENTRY_MAGIC)
#define DNS_ADBFETCH_MAGIC	  0x61646246	/* adbF. */
#define DNS_ADBFETCH_VALID(x)	  ISC_MAGIC_VALID(x, DNS_ADBFETCH_MAGIC)

/*
 * Lengths of lists needs to be powers of two.
 */
#define DNS_ADBNAMELIST_LENGTH	32	/* how many buckets for names */
#define DNS_ADBENTRYLIST_LENGTH	32	/* how many buckets for addresses */

#define CLEAN_SECONDS		20	/* clean this many seconds initially */

#define FREE_ITEMS		16	/* free count for memory pools */
#define FILL_COUNT		 8	/* fill count for memory pools */

#define DNS_ADB_INVALIDBUCKET (-1)	/* invalid bucket address */

typedef ISC_LIST(dns_adbname_t) dns_adbnamelist_t;
typedef struct dns_adbnamehook dns_adbnamehook_t;
typedef struct dns_adbzoneinfo dns_adbzoneinfo_t;
typedef ISC_LIST(dns_adbentry_t) dns_adbentrylist_t;
typedef struct dns_adbfetch dns_adbfetch_t;

struct dns_adb {
	unsigned int			magic;

	isc_mutex_t			lock;
	isc_mem_t		       *mctx;
	dns_view_t		       *view;
	isc_timermgr_t		       *timermgr;
	isc_timer_t		       *timer;
	isc_taskmgr_t		       *taskmgr;
	isc_task_t		       *task;
	isc_interval_t			tick_interval;

	unsigned int			irefcnt;
	unsigned int			erefcnt;

	isc_mutex_t			mplock;
	isc_mempool_t		       *nmp;	/* dns_adbname_t */
	isc_mempool_t		       *nhmp;	/* dns_adbnamehook_t */
	isc_mempool_t		       *zimp;	/* dns_adbzoneinfo_t */
	isc_mempool_t		       *emp;	/* dns_adbentry_t */
	isc_mempool_t		       *ahmp;	/* dns_adbhandle_t */
	isc_mempool_t		       *aimp;	/* dns_adbaddrinfo_t */
	isc_mempool_t		       *afmp;	/* dns_adbfetch_t */

	isc_random_t			rand;

	/*
	 * Bucketized locks and lists for names.
	 */
	dns_adbnamelist_t		names[DNS_ADBNAMELIST_LENGTH];
	isc_mutex_t			namelocks[DNS_ADBNAMELIST_LENGTH];
	isc_boolean_t			name_sd[DNS_ADBNAMELIST_LENGTH];
	unsigned int			name_refcnt[DNS_ADBNAMELIST_LENGTH];

	/*
	 * Bucketized locks for entries.
	 */
	dns_adbentrylist_t		entries[DNS_ADBENTRYLIST_LENGTH];
	isc_mutex_t			entrylocks[DNS_ADBENTRYLIST_LENGTH];
};

/*
 * XXX:  This has a pointer to the adb it came from.  It shouldn't need
 * this, but I can't think of how to get rid of it.  In particular, since
 * events have but one "arg" value, and that is currently used for the name
 * pointer in fetches, we need a way to get to the fetch contexts as well
 * as the adb itself.
 */
struct dns_adbname {
	unsigned int			magic;
	dns_name_t			name;
	dns_adb_t		       *adb;
	isc_boolean_t			partial_result;
	isc_boolean_t			dead;
	isc_stdtime_t			expire_time;
	int				lock_bucket;
	ISC_LIST(dns_adbnamehook_t)	namehooks;
	ISC_LIST(dns_adbfetch_t)	fetches;
	ISC_LIST(dns_adbhandle_t)	handles;
	ISC_LINK(dns_adbname_t)		link;
};

struct dns_adbfetch {
	unsigned int			magic;
	dns_adbnamehook_t	       *namehook;
	dns_adbentry_t		       *entry;
	dns_fetch_t		       *fetch;
	dns_rdataset_t			rdataset;
	ISC_LINK(dns_adbfetch_t)	link;
};

/*
 * dns_adbnamehook_t
 *
 * This is a small widget that dangles off a dns_adbname_t.  It contains a
 * pointer to the address information about this host, and a link to the next
 * namehook that will contain the next address this host has.
 */
struct dns_adbnamehook {
	unsigned int			magic;
	dns_adbentry_t		       *entry;
	ISC_LINK(dns_adbnamehook_t)	link;
};

/*
 * dns_adbzoneinfo_t
 *
 * This is a small widget that holds zone-specific information about an
 * address.  Currently limited to lameness, but could just as easily be
 * extended to other types of information about zones.
 */
struct dns_adbzoneinfo {
	unsigned int			magic;

	dns_name_t			zone;
	isc_stdtime_t			lame_timer;

	ISC_LINK(dns_adbzoneinfo_t)	link;
};

/*
 * An address entry.  It holds quite a bit of information about addresses,
 * including edns state, rtt, and of course the address of the host.
 */
struct dns_adbentry {
	unsigned int			magic;

	int				lock_bucket;
	unsigned int			refcnt;

	unsigned int			flags;
	int				edns_level;	/* must be int! */
	int				goodness;	/* bad < 0 <= good */
	unsigned int			srtt;
	isc_sockaddr_t			sockaddr;

	ISC_LIST(dns_adbzoneinfo_t)	zoneinfo;
	ISC_LINK(dns_adbentry_t)	link;
};

/*
 * Internal functions (and prototypes).
 */
static inline dns_adbname_t *new_adbname(dns_adb_t *, dns_name_t *);
static inline void free_adbname(dns_adb_t *, dns_adbname_t **);
static inline dns_adbnamehook_t *new_adbnamehook(dns_adb_t *,
						 dns_adbentry_t *);
static inline void free_adbnamehook(dns_adb_t *, dns_adbnamehook_t **);
static inline dns_adbzoneinfo_t *new_adbzoneinfo(dns_adb_t *, dns_name_t *);
static inline void free_adbzoneinfo(dns_adb_t *, dns_adbzoneinfo_t **);
static inline dns_adbentry_t *new_adbentry(dns_adb_t *);
static inline void free_adbentry(dns_adb_t *, dns_adbentry_t **);
static inline dns_adbhandle_t *new_adbhandle(dns_adb_t *);
static inline void free_adbhandle(dns_adb_t *, dns_adbhandle_t **);
static inline dns_adbaddrinfo_t *new_adbaddrinfo(dns_adb_t *,
						 dns_adbentry_t *);

static inline dns_adbname_t *find_name_and_lock(dns_adb_t *, dns_name_t *,
						int *);
static inline dns_adbentry_t *find_entry_and_lock(dns_adb_t *,
						  isc_sockaddr_t *, int *);
static void dump_adb(dns_adb_t *, FILE *);
static void print_dns_name(FILE *, dns_name_t *);
static void print_namehook_list(FILE *, dns_adbname_t *);
static void print_handle_list(FILE *, dns_adbname_t *);
static void print_fetch_list(FILE *, dns_adbname_t *);
static inline void inc_adb_irefcnt(dns_adb_t *, isc_boolean_t);
static inline void dec_adb_irefcnt(dns_adb_t *, isc_boolean_t);
static inline void inc_adb_erefcnt(dns_adb_t *, isc_boolean_t);
static inline void dec_adb_erefcnt(dns_adb_t *, isc_boolean_t);
static inline void inc_entry_refcnt(dns_adb_t *, dns_adbentry_t *,
				    isc_boolean_t);
static inline void dec_entry_refcnt(dns_adb_t *, dns_adbentry_t *,
				    isc_boolean_t);
static inline void violate_locking_hierarchy(isc_mutex_t *, isc_mutex_t *);
static void clean_namehooks_at_name(dns_adb_t *, dns_adbname_t *);
static void clean_handles_at_name(dns_adbname_t *, isc_eventtype_t);
static void cancel_fetches_at_name(dns_adb_t *, dns_adbname_t *);
static isc_result_t construct_name(dns_adb_t *, dns_adbhandle_t *,
				   dns_name_t *, dns_adbname_t *, int,
				   isc_stdtime_t);
static isc_result_t fetch_name(dns_adb_t *, dns_name_t *, dns_adbname_t *,
			       isc_stdtime_t now);
static inline void check_exit(dns_adb_t *);
static void timer_cleanup(isc_task_t *, isc_event_t *);
static void destroy(dns_adb_t *);
static void shutdown_names(dns_adb_t *);
static inline void link_name(dns_adb_t *, int, dns_adbname_t *);
static inline void unlink_name(dns_adb_t *, dns_adbname_t *);
static void kill_name(dns_adb_t *, dns_adbname_t **, isc_eventtype_t ev);

/*
 * Requires the name's bucket be locked.
 */
static void
kill_name(dns_adb_t *adb, dns_adbname_t **n, isc_eventtype_t ev)
{
	dns_adbname_t *name;

	INSIST(n != NULL);
	name = *n;
	*n = NULL;
	INSIST(DNS_ADBNAME_VALID(name));

	DP(("killing name %p\n", name));

	/*
	 * If we're dead already, just check to see if we should go
	 * away now or not.
	 */
	if (name->dead && ISC_LIST_EMPTY(name->fetches)) {
		unlink_name(adb, name);
		free_adbname(adb, &name);
		return;
	}

	/*
	 * Clean up the name's various lists.  These two are destructive
	 * in that they will always empty the list.
	 */
	clean_handles_at_name(name, ev);
	clean_namehooks_at_name(adb, name);

	/*
	 * If fetches are running, cancel them.  If none are running, we can
	 * just kill the name here.
	 */
	if (ISC_LIST_EMPTY(name->fetches)) {
		unlink_name(adb, name);
		free_adbname(adb, &name);
	} else {
		name->dead = ISC_TRUE;
		cancel_fetches_at_name(adb, name);
	}
}

/*
 * Requires the name's bucket be locked.
 */
static inline void
link_name(dns_adb_t *adb, int bucket, dns_adbname_t *name)
{
	INSIST(name->lock_bucket == DNS_ADB_INVALIDBUCKET);

	ISC_LIST_PREPEND(adb->names[bucket], name, link);
	name->lock_bucket = bucket;
	adb->name_refcnt[bucket]++;
}

/*
 * Requires the name's bucket be locked.
 */
static inline void
unlink_name(dns_adb_t *adb, dns_adbname_t *name)
{
	int bucket;

	bucket = name->lock_bucket;
	INSIST(bucket != DNS_ADB_INVALIDBUCKET);

	ISC_LIST_UNLINK(adb->names[bucket], name, link);
	name->lock_bucket = DNS_ADB_INVALIDBUCKET;
	INSIST(adb->name_refcnt[bucket] > 0);
	adb->name_refcnt[bucket]--;
}

static inline void
violate_locking_hierarchy(isc_mutex_t *have, isc_mutex_t *want)
{
	if (isc_mutex_trylock(want) != ISC_R_SUCCESS) {
		UNLOCK(have);
		LOCK(want);
		LOCK(have);
	}
}

/*
 * The ADB _MUST_ be locked before calling.  Also, exit conditions must be
 * checked after calling this function.
 */
static void
shutdown_names(dns_adb_t *adb)
{
	int bucket;
	dns_adbname_t *name;
	dns_adbname_t *next_name;

	for (bucket = 0 ; bucket < DNS_ADBNAMELIST_LENGTH ; bucket++) {
		LOCK(&adb->namelocks[bucket]);
		adb->name_sd[bucket] = ISC_TRUE;

		/*
		 * Run through the list.  For each name, clean up handles
		 * found there, and cancel any fetches running.  When
		 * all the fetches are canceled, the name will destroy
		 * itself.
		 */
		name = ISC_LIST_HEAD(adb->names[bucket]);
		while (name != NULL) {
			next_name = ISC_LIST_NEXT(name, link);

			kill_name(adb, &name, DNS_EVENT_ADBSHUTDOWN);

			name = next_name;
		}

		/* kill_name() will decrement the refcnt. */
		if (adb->name_refcnt[bucket] == 0)
			dec_adb_irefcnt(adb, ISC_FALSE);

		UNLOCK(&adb->namelocks[bucket]);
	}

	dump_adb(adb, stderr);
}

/*
 * Name bucket must be locked
 */
static void
cancel_fetches_at_name(dns_adb_t *adb, dns_adbname_t *name)
{
	dns_adbfetch_t *fetch;

	fetch = ISC_LIST_HEAD(name->fetches);
	while (fetch != NULL) {
		DP(("Canceling fetch %p for name %p\n", fetch, name));
		dns_resolver_cancelfetch(adb->view->resolver, fetch->fetch);
		fetch = ISC_LIST_NEXT(fetch, link);
	}
}

/*
 * Assumes the name bucket is locked.
 */
static void
clean_namehooks_at_name(dns_adb_t *adb, dns_adbname_t *name)
{
	dns_adbentry_t *entry;
	dns_adbnamehook_t *namehook;
	int addr_bucket;

	addr_bucket = DNS_ADB_INVALIDBUCKET;
	namehook = ISC_LIST_HEAD(name->namehooks);
	while (namehook != NULL) {
		INSIST(DNS_ADBNAMEHOOK_VALID(namehook));

		/*
		 * Clean up the entry if needed.
		 */
		entry = namehook->entry;
		if (entry != NULL) {
			INSIST(DNS_ADBENTRY_VALID(entry));

			if (addr_bucket != entry->lock_bucket) {
				if (addr_bucket != DNS_ADB_INVALIDBUCKET)
					UNLOCK(&adb->entrylocks[addr_bucket]);
				addr_bucket = entry->lock_bucket;
				LOCK(&adb->entrylocks[addr_bucket]);
			}

			dec_entry_refcnt(adb, entry, ISC_FALSE);
		}

		/*
		 * Free the namehook
		 */
		namehook->entry = NULL;
		ISC_LIST_UNLINK(name->namehooks, namehook, link);
		free_adbnamehook(adb, &namehook);

		namehook = ISC_LIST_HEAD(name->namehooks);
	}

	if (addr_bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->entrylocks[addr_bucket]);
}

/*
 * Assumes the name bucket is locked.
 */
static void
clean_handles_at_name(dns_adbname_t *name, isc_eventtype_t evtype)
{
	isc_event_t *ev;
	isc_task_t *task;
	dns_adbhandle_t *handle;

	handle = ISC_LIST_HEAD(name->handles);
	while (handle != NULL) {
		LOCK(&handle->lock);

		/*
		 * Unlink the handle from the name, letting the caller
		 * call dns_adb_done() on it to clean it up later.
		 */
		ISC_LIST_UNLINK(name->handles, handle, link);
		handle->adbname = NULL;
		handle->name_bucket = DNS_ADB_INVALIDBUCKET;

		ev = &handle->event;
		task = ev->sender;
		ev->sender = handle;
		ev->type = evtype;
		isc_task_sendanddetach(&task, &ev);

		UNLOCK(&handle->lock);

		handle = ISC_LIST_HEAD(name->handles);
	}
}

static inline void
check_exit(dns_adb_t *adb)
{
	if ((adb->irefcnt == 0) && (adb->erefcnt == 0)
	    && (isc_mempool_getallocated(adb->ahmp) == 0))
		isc_task_shutdown(adb->task);
}

static inline void
inc_adb_irefcnt(dns_adb_t *adb, isc_boolean_t lock)
{
	if (lock)
		LOCK(&adb->lock);

	adb->irefcnt++;

	if (lock)
		UNLOCK(&adb->lock);
}

static inline void
dec_adb_irefcnt(dns_adb_t *adb, isc_boolean_t lock)
{
	if (lock)
		LOCK(&adb->lock);

	INSIST(adb->irefcnt > 0);
	adb->irefcnt--;

	check_exit(adb);

	if (lock)
		UNLOCK(&adb->lock);
}

static inline void
inc_adb_erefcnt(dns_adb_t *adb, isc_boolean_t lock)
{
	if (lock)
		LOCK(&adb->lock);

	adb->erefcnt++;

	if (lock)
		UNLOCK(&adb->lock);
}

static inline void
dec_adb_erefcnt(dns_adb_t *adb, isc_boolean_t lock)
{
	if (lock)
		LOCK(&adb->lock);

	INSIST(adb->erefcnt > 0);
	adb->erefcnt--;

	check_exit(adb);

	if (lock)
		UNLOCK(&adb->lock);
}

static inline void
inc_entry_refcnt(dns_adb_t *adb, dns_adbentry_t *entry, isc_boolean_t lock)
{
	int bucket;

	bucket = entry->lock_bucket;

	if (lock)
		LOCK(&adb->entrylocks[bucket]);

	entry->refcnt++;

	if (lock)
		UNLOCK(&adb->entrylocks[bucket]);
}

static inline void
dec_entry_refcnt(dns_adb_t *adb, dns_adbentry_t *entry, isc_boolean_t lock)
{
	int bucket;
	isc_boolean_t destroy_entry;

	bucket = entry->lock_bucket;

	if (lock)
		LOCK(&adb->entrylocks[bucket]);

	INSIST(entry->refcnt > 0);
	entry->refcnt--;

	destroy_entry = ISC_FALSE;
	if (entry->refcnt == 0) {
		destroy_entry = ISC_TRUE;
		ISC_LIST_UNLINK(adb->entries[bucket], entry, link);
	}

	if (lock)
		UNLOCK(&adb->entrylocks[bucket]);

	if (!destroy_entry)
		return;

	entry->lock_bucket = DNS_ADB_INVALIDBUCKET;

	free_adbentry(adb, &entry);
}

static inline dns_adbname_t *
new_adbname(dns_adb_t *adb, dns_name_t *dnsname)
{
	dns_adbname_t *name;

	name = isc_mempool_get(adb->nmp);
	if (name == NULL)
		return (NULL);

	dns_name_init(&name->name, NULL);
	if (dns_name_dup(dnsname, adb->mctx, &name->name) != ISC_R_SUCCESS) {
		isc_mempool_put(adb->nmp, name);
		return (NULL);
	}

	name->magic = DNS_ADBNAME_MAGIC;
	name->adb = adb;
	name->partial_result = ISC_FALSE;
	name->dead = ISC_FALSE;
	name->expire_time = 0;
	name->lock_bucket = DNS_ADB_INVALIDBUCKET;
	ISC_LIST_INIT(name->namehooks);
	ISC_LIST_INIT(name->fetches);
	ISC_LIST_INIT(name->handles);
	ISC_LINK_INIT(name, link);

	return (name);
}

static inline void
free_adbname(dns_adb_t *adb, dns_adbname_t **name)
{
	dns_adbname_t *n;

	INSIST(name != NULL && DNS_ADBNAME_VALID(*name));
	n = *name;
	*name = NULL;

	INSIST(ISC_LIST_EMPTY(n->namehooks));
	INSIST(ISC_LIST_EMPTY(n->fetches));
	INSIST(ISC_LIST_EMPTY(n->handles));
	INSIST(!ISC_LINK_LINKED(n, link));
	INSIST(n->lock_bucket == DNS_ADB_INVALIDBUCKET);
	INSIST(n->adb == adb);

	n->magic = 0;
	dns_name_free(&n->name, adb->mctx);

	isc_mempool_put(adb->nmp, n);
}

static inline dns_adbnamehook_t *
new_adbnamehook(dns_adb_t *adb, dns_adbentry_t *entry)
{
	dns_adbnamehook_t *nh;

	nh = isc_mempool_get(adb->nhmp);
	if (nh == NULL)
		return (NULL);

	nh->magic = DNS_ADBNAMEHOOK_MAGIC;
	nh->entry = entry;
	ISC_LINK_INIT(nh, link);

	return (nh);
}

static inline void
free_adbnamehook(dns_adb_t *adb, dns_adbnamehook_t **namehook)
{
	dns_adbnamehook_t *nh;

	INSIST(namehook != NULL && DNS_ADBNAMEHOOK_VALID(*namehook));
	nh = *namehook;
	*namehook = NULL;

	INSIST(nh->entry == NULL);
	INSIST(!ISC_LINK_LINKED(nh, link));

	nh->magic = 0;
	isc_mempool_put(adb->nhmp, nh);
}

static inline dns_adbzoneinfo_t *
new_adbzoneinfo(dns_adb_t *adb, dns_name_t *zone)
{
	dns_adbzoneinfo_t *zi;

	zi = isc_mempool_get(adb->zimp);
	if (zi == NULL)
		return (NULL);

	dns_name_init(&zi->zone, NULL);
	if (dns_name_dup(zone, adb->mctx, &zi->zone) != ISC_R_SUCCESS) {
		isc_mempool_put(adb->zimp, zi);
		return (NULL);
	}

	zi->magic = DNS_ADBZONEINFO_MAGIC;
	zi->lame_timer = 0;
	ISC_LINK_INIT(zi, link);

	return (zi);
}

static inline void
free_adbzoneinfo(dns_adb_t *adb, dns_adbzoneinfo_t **zoneinfo)
{
	dns_adbzoneinfo_t *zi;

	INSIST(zoneinfo != NULL && DNS_ADBZONEINFO_VALID(*zoneinfo));
	zi = *zoneinfo;
	*zoneinfo = NULL;

	INSIST(!ISC_LINK_LINKED(zi, link));

	dns_name_free(&zi->zone, adb->mctx);

	zi->magic = 0;

	isc_mempool_put(adb->zimp, zi);
}

static inline dns_adbentry_t *
new_adbentry(dns_adb_t *adb)
{
	dns_adbentry_t *e;
	isc_uint32_t r;

	e = isc_mempool_get(adb->emp);
	if (e == NULL)
		return (NULL);

	e->magic = DNS_ADBENTRY_MAGIC;
	e->lock_bucket = DNS_ADB_INVALIDBUCKET;
	e->refcnt = 0;
	e->flags = 0;
	e->goodness = 0;
	isc_random_get(&adb->rand, &r);
	e->srtt = (r & 0x1f) + 1;
	ISC_LIST_INIT(e->zoneinfo);
	ISC_LINK_INIT(e, link);

	return (e);
}

static inline void
free_adbentry(dns_adb_t *adb, dns_adbentry_t **entry)
{
	dns_adbentry_t *e;
	dns_adbzoneinfo_t *zi;

	INSIST(entry != NULL && DNS_ADBENTRY_VALID(*entry));
	e = *entry;
	*entry = NULL;

	INSIST(e->lock_bucket == DNS_ADB_INVALIDBUCKET);
	INSIST(e->refcnt == 0);
	INSIST(!ISC_LINK_LINKED(e, link));

	e->magic = 0;

	zi = ISC_LIST_HEAD(e->zoneinfo);
	while (zi != NULL) {
		ISC_LIST_UNLINK(e->zoneinfo, zi, link);
		free_adbzoneinfo(adb, &zi);
		zi = ISC_LIST_HEAD(e->zoneinfo);
	}

	isc_mempool_put(adb->emp, e);
}

static inline dns_adbhandle_t *
new_adbhandle(dns_adb_t *adb)
{
	dns_adbhandle_t *h;
	isc_result_t result;

	h = isc_mempool_get(adb->ahmp);
	if (h == NULL)
		return (NULL);

	/*
	 * public members
	 */
	h->magic = 0;
	h->adb = adb;
	h->query_pending = ISC_FALSE;
	h->partial_result = ISC_FALSE;
	h->result = ISC_R_UNEXPECTED;
	ISC_LIST_INIT(h->list);
	ISC_LINK_INIT(h, next);
	h->name_bucket = DNS_ADB_INVALIDBUCKET;
	h->adbname = NULL;

	/*
	 * private members
	 */
	result = isc_mutex_init(&h->lock);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init failed in new_adbhandle()");
		isc_mempool_put(adb->ahmp, h);
		return (NULL);
	}
	ISC_LINK_INIT(h, link);

	ISC_EVENT_INIT(&h->event, sizeof (isc_event_t), 0, 0, 0, NULL, NULL,
		       NULL, NULL, h);

	h->magic = DNS_ADBHANDLE_MAGIC;
	return (h);
}

static inline dns_adbfetch_t *
new_adbfetch(dns_adb_t *adb)
{
	dns_adbfetch_t *f;

	f = isc_mempool_get(adb->afmp);
	if (f == NULL)
		return (NULL);

	f->magic = 0;
	f->namehook = NULL;
	f->entry = NULL;
	f->fetch = NULL;

	f->namehook = new_adbnamehook(adb, NULL);
	if (f->namehook == NULL)
		goto err;

	f->entry = new_adbentry(adb);
	if (f->entry == NULL)
		goto err;

	dns_rdataset_init(&f->rdataset);
	ISC_LINK_INIT(f, link);

	f->magic = DNS_ADBFETCH_MAGIC;

	return (f);

 err:
	if (f->namehook != NULL)
		free_adbnamehook(adb, &f->namehook);
	if (f->entry != NULL)
		free_adbentry(adb, &f->entry);
	isc_mempool_put(adb->afmp, f);
	return (NULL);
}

static inline void
free_adbfetch(dns_adb_t *adb, dns_adbfetch_t **fetch)
{
	dns_adbfetch_t *f;

	INSIST(fetch != NULL && DNS_ADBFETCH_VALID(*fetch));
	f = *fetch;
	*fetch = NULL;

	INSIST(!ISC_LINK_LINKED(f, link));

	f->magic = 0;

	if (f->namehook != NULL)
		free_adbnamehook(adb, &f->namehook);
	if (f->entry != NULL)
		free_adbentry(adb, &f->entry);

	if (f->rdataset.methods != NULL)
		if (dns_rdataset_isassociated(&f->rdataset))
			dns_rdataset_disassociate(&f->rdataset);

	isc_mempool_put(adb->afmp, f);
}

static inline void
free_adbhandle(dns_adb_t *adb, dns_adbhandle_t **handlep)
{
	dns_adbhandle_t *handle;

	INSIST(handlep != NULL && DNS_ADBHANDLE_VALID(*handlep));
	handle = *handlep;
	*handlep = NULL;

	INSIST(ISC_LIST_EMPTY(handle->list));
	INSIST(!ISC_LINK_LINKED(handle, next));
	INSIST(!ISC_LINK_LINKED(handle, link));
	INSIST(handle->name_bucket == DNS_ADB_INVALIDBUCKET);
	INSIST(handle->adbname == NULL);

	handle->magic = 0;

	isc_mutex_destroy(&handle->lock);
	isc_mempool_put(adb->ahmp, handle);
}

/*
 * Copy bits from the entry into the newly allocated addrinfo.  The entry
 * must be locked, and the reference count must be bumped up by one
 * if this function returns a valid pointer.
 */
static inline dns_adbaddrinfo_t *
new_adbaddrinfo(dns_adb_t *adb, dns_adbentry_t *entry)
{
	dns_adbaddrinfo_t *ai;

	ai = isc_mempool_get(adb->aimp);
	if (ai == NULL)
		return (NULL);

	ai->magic = DNS_ADBADDRINFO_MAGIC;
	ai->sockaddr = &entry->sockaddr;
	ai->goodness = entry->goodness;
	ai->srtt = entry->srtt;
	ai->flags = entry->flags;
	ai->entry = entry;
	ISC_LINK_INIT(ai, link);

	return (ai);
}

static inline void
free_adbaddrinfo(dns_adb_t *adb, dns_adbaddrinfo_t **ainfo)
{
	dns_adbaddrinfo_t *ai;

	INSIST(ainfo != NULL && DNS_ADBADDRINFO_VALID(*ainfo));
	ai = *ainfo;
	*ainfo = NULL;

	INSIST(ai->sockaddr == NULL);
	INSIST(ai->entry == NULL);
	INSIST(!ISC_LINK_LINKED(ai, link));

	ai->magic = 0;

	isc_mempool_put(adb->aimp, ai);
}

/*
 * Search for the name.  NOTE:  The bucket is kept locked on both
 * success and failure, so it must always be unlocked by the caller!
 *
 * On the first call to this function, *bucketp must be set to
 * DNS_ADB_INVALIDBUCKET.
 */
static inline dns_adbname_t *
find_name_and_lock(dns_adb_t *adb, dns_name_t *name, int *bucketp)
{
	dns_adbname_t *adbname;
	int bucket;

	bucket = dns_name_hash(name, ISC_FALSE);
	bucket &= (DNS_ADBNAMELIST_LENGTH - 1);

	if (*bucketp == DNS_ADB_INVALIDBUCKET) {
		LOCK(&adb->namelocks[bucket]);
		*bucketp = bucket;
	} else if (*bucketp != bucket) {
		UNLOCK(&adb->namelocks[*bucketp]);
		LOCK(&adb->namelocks[bucket]);
		*bucketp = bucket;
	}

	adbname = ISC_LIST_HEAD(adb->names[bucket]);
	while (adbname != NULL) {
		if (adbname->dead != ISC_TRUE) {
			/* XXX should check for expired names here? */
			if (dns_name_equal(name, &adbname->name))
				return (adbname);
		}
		adbname = ISC_LIST_NEXT(adbname, link);
	}

	return (NULL);
}

/*
 * Search for the address.  NOTE:  The bucket is kept locked on both
 * success and failure, so it must always be unlocked by the caller.
 *
 * On the first call to this function, *bucketp must be set to
 * DNS_ADB_INVALIDBUCKET.  This will cause a lock to occur.  On
 * later calls (within the same "lock path") it can be left alone, so
 * if this function is called multiple times locking is only done if
 * the bucket changes.
 */
static inline dns_adbentry_t *
find_entry_and_lock(dns_adb_t *adb, isc_sockaddr_t *addr, int *bucketp)
{
	dns_adbentry_t *entry;
	int bucket;

	bucket = isc_sockaddr_hash(addr, ISC_TRUE);
	bucket &= (DNS_ADBENTRYLIST_LENGTH - 1);

	if (*bucketp == DNS_ADB_INVALIDBUCKET) {
		LOCK(&adb->entrylocks[bucket]);
		*bucketp = bucket;
	} else if (*bucketp != bucket) {
		UNLOCK(&adb->entrylocks[*bucketp]);
		LOCK(&adb->entrylocks[bucket]);
		*bucketp = bucket;
	}

	entry = ISC_LIST_HEAD(adb->entries[bucket]);
	while (entry != NULL) {
		if (isc_sockaddr_equal(addr, &entry->sockaddr))
			return (entry);
		entry = ISC_LIST_NEXT(entry, link);
	}

	return (NULL);
}

/*
 * Entry bucket MUST be locked!
 */
static isc_boolean_t
entry_is_bad_for_zone(dns_adb_t *adb, dns_adbentry_t *entry, dns_name_t *zone,
		      isc_stdtime_t now)
{
	dns_adbzoneinfo_t *zi, *next_zi;
	isc_boolean_t is_bad;

	is_bad = ISC_FALSE;

	zi = ISC_LIST_HEAD(entry->zoneinfo);
	if (zi == NULL)
		return (ISC_FALSE);
	while (zi != NULL) {
		next_zi = ISC_LIST_NEXT(zi, link);

		/*
		 * Has the entry expired?
		 */
		if (zi->lame_timer < now) {
			ISC_LIST_UNLINK(entry->zoneinfo, zi, link);
			free_adbzoneinfo(adb, &zi);
		}

		/*
		 * Order tests from least to most expensive.
		 */
		if (zi != NULL && !is_bad) {
			if (dns_name_equal(zone, &zi->zone))
				is_bad = ISC_TRUE;
		}

		zi = next_zi;
	}
	
	return (is_bad);
}

static void
copy_namehook_list(dns_adb_t *adb, dns_adbhandle_t *handle,
		   dns_adbname_t *name, dns_name_t *zone, isc_stdtime_t now)
{
	dns_adbnamehook_t *namehook;
	dns_adbaddrinfo_t *addrinfo;
	int bucket;

	handle->query_pending = ISC_FALSE;
	bucket = DNS_ADB_INVALIDBUCKET;

	namehook = ISC_LIST_HEAD(name->namehooks);
	while (namehook != NULL) {
		bucket = namehook->entry->lock_bucket;
		LOCK(&adb->entrylocks[bucket]);
		if (entry_is_bad_for_zone(adb, namehook->entry, zone, now))
			goto next;
		addrinfo = new_adbaddrinfo(adb, namehook->entry);
		if (addrinfo == NULL) {
			handle->partial_result = ISC_TRUE;
			handle->result = ISC_R_NOMEMORY;
			goto out;
		}
		/*
		 * Found a valid entry.  Add it to the handle's list.
		 */
		inc_entry_refcnt(adb, namehook->entry, ISC_FALSE);
		ISC_LIST_APPEND(handle->list, addrinfo, link);
		addrinfo = NULL;
	next:
		UNLOCK(&adb->entrylocks[bucket]);
		bucket = DNS_ADB_INVALIDBUCKET;
		namehook = ISC_LIST_NEXT(namehook, link);
	}

	handle->result = ISC_R_SUCCESS; /* all were copied */
 out:
	if (bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->entrylocks[bucket]);
}

static void
shutdown_task(isc_task_t *task, isc_event_t *ev)
{
	dns_adb_t *adb;

	(void)task;  /* not used */

	adb = ev->arg;
	INSIST(DNS_ADB_VALID(adb));

	/*
	 * Kill the timer, and then the ADB itself.  Note that this implies
	 * that this task was the one scheduled to get timer events.  If
	 * this is not true (and it is unfortunate there is no way to INSIST()
	 * this) baddness will occur.
	 */
	LOCK(&adb->lock);
	isc_timer_detach(&adb->timer);
	UNLOCK(&adb->lock);
	destroy(adb);

	isc_event_free(&ev);
}

/*
 * ADB must be locked
 */
static void
cleanup(dns_adb_t *adb)
{
}

static void
timer_cleanup(isc_task_t *task, isc_event_t *ev)
{
	dns_adb_t *adb;
	isc_result_t result;

	(void)task;  /* not used */

	adb = ev->arg;
	INSIST(DNS_ADB_VALID(adb));

	LOCK(&adb->lock);

	/*
	 * Call our cleanup routine.
	 */
	cleanup(adb);

	/*
	 * Reset the timer.
	 */
	result = isc_timer_reset(adb->timer, isc_timertype_once, NULL,
				 &adb->tick_interval, ISC_FALSE);

	UNLOCK(&adb->lock);

	isc_event_free(&ev);
}

static void
destroy(dns_adb_t *adb)
{
	adb->magic = 0;

	/*
	 * The timer is already dead, from the task's shutdown callback.
	 */
	isc_task_detach(&adb->task);

	isc_mempool_destroy(&adb->nmp);
	isc_mempool_destroy(&adb->nhmp);
	isc_mempool_destroy(&adb->zimp);
	isc_mempool_destroy(&adb->emp);
	isc_mempool_destroy(&adb->ahmp);
	isc_mempool_destroy(&adb->aimp);
	isc_mempool_destroy(&adb->afmp);

	isc_mutexblock_destroy(adb->entrylocks, DNS_ADBENTRYLIST_LENGTH);
	isc_mutexblock_destroy(adb->namelocks, DNS_ADBNAMELIST_LENGTH);

	isc_mutex_destroy(&adb->lock);
	isc_mutex_destroy(&adb->mplock);

	isc_random_invalidate(&adb->rand);

	isc_mem_put(adb->mctx, adb, sizeof (dns_adb_t));
}


/*
 * Public functions.
 */

isc_result_t
dns_adb_create(isc_mem_t *mem, dns_view_t *view, isc_timermgr_t *timermgr,
	       isc_taskmgr_t *taskmgr, dns_adb_t **newadb)
{
	dns_adb_t *adb;
	isc_result_t result;
	int i;

	REQUIRE(mem != NULL);
	REQUIRE(view != NULL);
	REQUIRE(timermgr != NULL);
	REQUIRE(taskmgr != NULL);
	REQUIRE(newadb != NULL && *newadb == NULL);

	adb = isc_mem_get(mem, sizeof (dns_adb_t));
	if (adb == NULL)
		return (ISC_R_NOMEMORY);

	/*
	 * Initialize things here that cannot fail, and especially things
	 * that must be NULL for the error return to work properly.
	 */
	adb->magic = 0;
	adb->erefcnt = 1;
	adb->irefcnt = 0;
	adb->nmp = NULL;
	adb->nhmp = NULL;
	adb->zimp = NULL;
	adb->emp = NULL;
	adb->ahmp = NULL;
	adb->aimp = NULL;
	adb->afmp = NULL;
	adb->task = NULL;
	adb->timer = NULL;
	adb->mctx = mem;
	adb->view = view;
	adb->timermgr = timermgr;
	adb->taskmgr = taskmgr;

	result = isc_random_init(&adb->rand);
	if (result != ISC_R_SUCCESS)
		goto fail0a;

	result = isc_mutex_init(&adb->lock);
	if (result != ISC_R_SUCCESS)
		goto fail0b;

	result = isc_mutex_init(&adb->mplock);
	if (result != ISC_R_SUCCESS)
		goto fail0c;

	/*
	 * Initialize the bucket locks for names and elements.
	 * May as well initialize the list heads, too.
	 */
	result = isc_mutexblock_init(adb->namelocks, DNS_ADBNAMELIST_LENGTH);
	if (result != ISC_R_SUCCESS)
		goto fail1;
	for (i = 0 ; i < DNS_ADBNAMELIST_LENGTH ; i++) {
		ISC_LIST_INIT(adb->names[i]);
		adb->name_sd[i] = ISC_FALSE;
		adb->name_refcnt[i] = 0;
		adb->irefcnt++;
	}
	for (i = 0 ; i < DNS_ADBENTRYLIST_LENGTH ; i++)
		ISC_LIST_INIT(adb->entries[i]);
	result = isc_mutexblock_init(adb->entrylocks, DNS_ADBENTRYLIST_LENGTH);
	if (result != ISC_R_SUCCESS)
		goto fail2;

	/*
	 * Memory pools
	 */
#define MPINIT(t, p, l, n) do { \
	result = isc_mempool_create(mem, sizeof (t), &(p)); \
	if (result != ISC_R_SUCCESS) \
		goto fail3; \
	isc_mempool_setfreemax((p), FREE_ITEMS); \
	isc_mempool_setfillcount((p), FILL_COUNT); \
	isc_mempool_setname((p), n); \
	if (l) \
		isc_mempool_associatelock((p), &adb->mplock); \
} while (0)

	MPINIT(dns_adbname_t, adb->nmp, ISC_TRUE, "adbname");
	MPINIT(dns_adbnamehook_t, adb->nhmp, ISC_TRUE, "adbnamehook");
	MPINIT(dns_adbzoneinfo_t, adb->zimp, ISC_TRUE, "adbzoneinfo");
	MPINIT(dns_adbentry_t, adb->emp, ISC_TRUE, "adbentry");
	MPINIT(dns_adbhandle_t, adb->ahmp, ISC_TRUE, "adbhandle");
	MPINIT(dns_adbaddrinfo_t, adb->aimp, ISC_TRUE, "adbaddrinfo");
	MPINIT(dns_adbfetch_t, adb->afmp, ISC_TRUE, "adbfetch");

#undef MPINIT

	/*
	 * Allocate a timer and a task for our periodic cleanup.
	 */
	result = isc_task_create(adb->taskmgr, adb->mctx, 0, &adb->task);
	if (result != ISC_R_SUCCESS)
		goto fail3;
	result = isc_task_onshutdown(adb->task, shutdown_task, adb);
	isc_interval_set(&adb->tick_interval, CLEAN_SECONDS, 0);
	result = isc_timer_create(adb->timermgr, isc_timertype_once,
				  NULL, &adb->tick_interval, adb->task,
				  timer_cleanup, adb, &adb->timer);
	if (result != ISC_R_SUCCESS)
		goto fail3;

	/*
	 * Normal return.
	 */
	adb->magic = DNS_ADB_MAGIC;
	*newadb = adb;
	return (ISC_R_SUCCESS);

 fail3:
	if (adb->task != NULL)
		isc_task_detach(&adb->task);
	if (adb->timer != NULL)
		isc_timer_detach(&adb->timer);

	/* clean up entrylocks */
	isc_mutexblock_destroy(adb->entrylocks, DNS_ADBENTRYLIST_LENGTH);

 fail2: /* clean up namelocks */
	isc_mutexblock_destroy(adb->namelocks, DNS_ADBNAMELIST_LENGTH);

 fail1: /* clean up only allocated memory */
	if (adb->nmp != NULL)
		isc_mempool_destroy(&adb->nmp);
	if (adb->nhmp != NULL)
		isc_mempool_destroy(&adb->nhmp);
	if (adb->zimp != NULL)
		isc_mempool_destroy(&adb->zimp);
	if (adb->emp != NULL)
		isc_mempool_destroy(&adb->emp);
	if (adb->ahmp != NULL)
		isc_mempool_destroy(&adb->ahmp);
	if (adb->aimp != NULL)
		isc_mempool_destroy(&adb->aimp);
	if (adb->aimp != NULL)
		isc_mempool_destroy(&adb->afmp);

	isc_mutex_destroy(&adb->mplock);
 fail0c:
	isc_mutex_destroy(&adb->lock);
 fail0b:
	isc_random_invalidate(&adb->rand);
 fail0a:
	isc_mem_put(mem, adb, sizeof (dns_adb_t));

	return (result);
}

void
dns_adb_detach(dns_adb_t **adbx)
{
	dns_adb_t *adb;

	REQUIRE(adbx != NULL && DNS_ADB_VALID(*adbx));

	adb = *adbx;
	*adbx = NULL;

	LOCK(&adb->lock);
	dec_adb_erefcnt(adb, ISC_FALSE);
	if (adb->erefcnt == 0)
		shutdown_names(adb);
	check_exit(adb);
	UNLOCK(&adb->lock);
}

isc_result_t
dns_adb_lookup(dns_adb_t *adb, isc_task_t *task, isc_taskaction_t action,
	       void *arg, dns_name_t *name, dns_name_t *zone,
	       isc_stdtime_t now, dns_adbhandle_t **handlep)
{
	dns_adbhandle_t *handle;
	dns_adbname_t *adbname;
	int bucket;
	isc_result_t result;
	isc_boolean_t attach_to_task;

	REQUIRE(DNS_ADB_VALID(adb));
	if (task != NULL) {
		REQUIRE(action != NULL);
	}
	REQUIRE(name != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(handlep != NULL && *handlep == NULL);

	attach_to_task = ISC_FALSE;
	result = ISC_R_UNEXPECTED;

	if (now == 0) {
		result = isc_stdtime_get(&now);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	/*
	 * Look up the name in our internal database.
	 *
	 * Possibilities:  Note that these are not always exclusive.
	 *
	 *	No name found.  In this case, allocate a new name header and
	 *	an initial namehook or two.  If any of these allocations
	 *	fail, clean up and return ISC_R_NOMEMORY.
	 *
	 *	Name found, valid addresses present.  Allocate one addrinfo
	 *	structure for each found and append it to the linked list
	 *	of addresses for this header.
	 *
	 *	Name found, queries pending.  In this case, if a task was
	 *	passed in, allocate a job id, attach it to the name's job
	 *	list and remember to tell the caller that there will be
	 *	more info coming later.
	 */
	handle = new_adbhandle(adb);
	if (handle == NULL) {
		result = ISC_R_NOMEMORY;
		goto success;
	}

	/*
	 * Look things up in our database first.
	 */
	bucket = DNS_ADB_INVALIDBUCKET;
	adbname = find_name_and_lock(adb, name, &bucket);
	if (adb->name_sd[bucket]) {
		DP(("lookup:  returning ISC_R_SHUTTINGDOWN\n"));
		result = ISC_R_SHUTTINGDOWN;
		goto fail;
	}

	/*
	 * Give us a chance to expire this name.
	 */
	if (adbname != NULL && adbname->expire_time < now) {
		DP(("lookup:  Lazy expiration of name %p\n", adbname));
		kill_name(adb, &adbname, DNS_EVENT_ADBEXPIRED);
	}

	/*
	 * Still there?
	 */
	if (adbname != NULL) {
		DP(("lookup:  Found name %p in adb\n", adbname));
		goto found;  /* goodness, I hate goto's. */
	}

	/*
	 * Nothing found.  Allocate a new adbname structure for this name
	 * and look in the database for details.  If the database has
	 * nothing useful, start a fetch if we can.
	 */
	adbname = new_adbname(adb, name);
	if (adbname == NULL) {
		result = ISC_R_NOMEMORY;
		goto fail;
	}

	/*
	 * Try to populate the name from the database and/or
	 * start fetches.  If this function returns
	 * ISC_R_SUCCESS at least ONE new bit of data was
	 * added, and/or fetches were started.  If nothing new
	 * can ever be found it will return DNS_R_NOMEMORY more
	 * than likely.
	 */
	result = construct_name(adb, handle, zone, adbname, bucket, now);
	if (result == ISC_R_SUCCESS) {
		DP(("lookup:  Found name %p in db\n", adbname));
		link_name(adb, bucket, adbname);
		goto found;
	}

	/*
	 * Try to start fetches.
	 */
	result = fetch_name(adb, zone, adbname, now);
	if (result == ISC_R_SUCCESS) {
		DP(("lookup:  Started fetch for name %p\n", adbname));
		link_name(adb, bucket, adbname);
		goto found;
	}

	goto fail;

	/*
	 * Found!  Run through the name and copy out the bits we are
	 * interested in.  If we cannot copy at least one address, return
	 * ISC_R_NOMEMORY, otherwise copy out what we can and set the
	 * missing_data bit in the header.
	 */
 found:
	INSIST(adbname != NULL);  /* should NEVER be null at this point! */
	copy_namehook_list(adb, handle, adbname, zone, now);
	if (handle->result == ISC_R_NOMEMORY
	    && ISC_LIST_EMPTY(handle->list)) {
		result = ISC_R_NOMEMORY;
		goto fail;
	}

	/*
	 * Attach to the name's query list if there are queries
	 * already running.
	 */
	if (!ISC_LIST_EMPTY(adbname->fetches) && (task != NULL)) {
		handle->adbname = adbname;
		handle->name_bucket = bucket;
		ISC_LIST_APPEND(adbname->handles, handle, link);
		attach_to_task = ISC_TRUE;
	}

	if (adbname->partial_result)
		handle->partial_result = ISC_TRUE;

	result = ISC_R_SUCCESS;
	goto success;

	/*
	 * If anything other than success is returned, free the name
	 * (since it will have nothing useful in it) and return via the
	 * failure return.
	 */
 fail:
	free_adbhandle(adb, &handle);

	/*
	 * If the name isn't on a list it means we allocated it here, and it
	 * should be killed.
	 */
	if (adbname != NULL) {
		INSIST(!ISC_LINK_LINKED(adbname, link));
		free_adbname(adb, &adbname);
	}

	/*
	 * "goto success" if the handle will be returned to the caller.  This
	 * is a non-fatal return, since it will give the caller a handle
	 * at the very least.
	 */
 success:
	if (handle != NULL) {
		*handlep = handle;

		if (attach_to_task) {
			isc_task_t *taskp;

			taskp = NULL;
			isc_task_attach(task, &taskp);
			handle->event.sender = taskp;
			handle->event.action = action;
			handle->event.arg = arg;
		}
	}

	if (bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->namelocks[bucket]);

	return (result);
}

isc_result_t
dns_adb_deletename(dns_adb_t *adb, dns_name_t *host)
{
	int name_bucket;
	dns_adbname_t *name;
	isc_boolean_t decr_adbrefcnt;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(host != NULL);

	name = NULL;

	/*
	 * Find the name.
	 */
	name_bucket = DNS_ADB_INVALIDBUCKET;
	name = find_name_and_lock(adb, host, &name_bucket);
	if (name == NULL) {
		UNLOCK(&adb->namelocks[name_bucket]);
		return (ISC_R_NOTFOUND);
	}

	kill_name(adb, &name, DNS_EVENT_ADBNAMEDELETED);

	decr_adbrefcnt = ISC_FALSE;
	if (adb->name_sd[name_bucket] && (adb->name_refcnt[name_bucket] == 0))
		decr_adbrefcnt = ISC_TRUE;

	if (name_bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->namelocks[name_bucket]);

	if (decr_adbrefcnt)
		dec_adb_irefcnt(adb, ISC_TRUE);

	return (DNS_R_SUCCESS);
}

isc_result_t
dns_adb_insert(dns_adb_t *adb, dns_name_t *host, isc_sockaddr_t *addr,
	       dns_ttl_t ttl, isc_stdtime_t now)
{
	dns_adbname_t *name;
	isc_boolean_t free_name;
	dns_adbentry_t *entry;
	isc_boolean_t free_entry;
	dns_adbnamehook_t *namehook;
	isc_boolean_t free_namehook;
	int name_bucket, addr_bucket; /* unlock if != DNS_ADB_INVALIDBUCKET */
	isc_result_t result;
	isc_stdtime_t expire_time;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(host != NULL);
	REQUIRE(addr != NULL);

	if (now == 0) {
		result = isc_stdtime_get(&now);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	expire_time = now + ttl;

	name = NULL;
	free_name = ISC_FALSE;
	entry = NULL;
	free_entry = ISC_FALSE;
	namehook = NULL;
	free_namehook = ISC_FALSE;
	result = ISC_R_UNEXPECTED;

	/*
	 * First, see if the host is already in the database.  If it is,
	 * don't make a new host entry.  If not, copy the name and name's
	 * contents into our structure and allocate what we'll need
	 * to attach things together.
	 */
	name_bucket = DNS_ADB_INVALIDBUCKET;
	name = find_name_and_lock(adb, host, &name_bucket);
	if (name == NULL) {
		name = new_adbname(adb, host);
		if (name == NULL) {
			result = ISC_R_NOMEMORY;
			goto out;
		}
		free_name = ISC_TRUE;
		name->expire_time = expire_time;
	}

	/*
	 * Now, while keeping the name locked, search for the address.
	 * Three possibilities:  One, the address doesn't exist.
	 * Two, the address exists, but we aren't linked to it.
	 * Three, the address exists and we are linked to it.
	 * (1) causes a new entry and namehook to be created.
	 * (2) causes only a new namehook.
	 * (3) is an error.
	 */
	addr_bucket = DNS_ADB_INVALIDBUCKET;
	entry = find_entry_and_lock(adb, addr, &addr_bucket);
	/*
	 * Case (1):  new entry and namehook.
	 */
	if (entry == NULL) {
		entry = new_adbentry(adb);
		if (entry == NULL) {
			result = ISC_R_NOMEMORY;
			goto out;
		}
		free_entry = ISC_TRUE;
	}

	/*
	 * Case (3):  entry exists, we're linked.
	 */
	namehook = ISC_LIST_HEAD(name->namehooks);
	while (namehook != NULL) {
		if (namehook->entry == entry) {
			result = ISC_R_EXISTS;
			goto out;
		}
		namehook = ISC_LIST_NEXT(namehook, link);
	}

	/*
	 * Case (2):  New namehook, link to entry from above.
	 */
	namehook = new_adbnamehook(adb, entry);
	if (namehook == NULL) {
		result = ISC_R_NOMEMORY;
		goto out;
	}
	free_namehook = ISC_TRUE;
	ISC_LIST_APPEND(name->namehooks, namehook, link);

	entry->lock_bucket = addr_bucket;
	inc_entry_refcnt(adb, entry, ISC_FALSE);
	entry->sockaddr = *addr;

	/*
	 * If needed, string up the name and entry.
	 */
	if (!ISC_LINK_LINKED(name, link))
		link_name(adb, name_bucket, name);
	if (!ISC_LINK_LINKED(entry, link))
		ISC_LIST_PREPEND(adb->entries[addr_bucket], entry, link);

	if (name->expire_time > expire_time)
		name->expire_time = expire_time;

	UNLOCK(&adb->namelocks[name_bucket]);
	name_bucket = DNS_ADB_INVALIDBUCKET;
	UNLOCK(&adb->entrylocks[addr_bucket]);
	addr_bucket = DNS_ADB_INVALIDBUCKET;

	return (ISC_R_SUCCESS);

 out:
	if (free_name)
		free_adbname(adb, &name);
	if (free_entry)
		isc_mempool_put(adb->emp, entry);
	if (free_namehook)
		isc_mempool_put(adb->nhmp, namehook);
	if (name_bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->namelocks[name_bucket]);
	if (addr_bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->entrylocks[addr_bucket]);

	return (result);
}

void
dns_adb_done(dns_adbhandle_t **handlep)
{
	dns_adbhandle_t *handle;
	dns_adbentry_t *entry;
	dns_adbaddrinfo_t *ai;
	int bucket;
	dns_adb_t *adb;

	REQUIRE(handlep != NULL && DNS_ADBHANDLE_VALID(*handlep));
	handle = *handlep;
	*handlep = NULL;

	LOCK(&handle->lock);

	DP(("dns_adb_done on handle %p\n", handle));

	adb = handle->adb;
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(!ISC_LINK_LINKED(handle, next));

	bucket = handle->name_bucket;
	if (bucket == DNS_ADB_INVALIDBUCKET)
		goto cleanup;

	/*
	 * We need to get the adbname's lock to unlink the handle.
	 */
	violate_locking_hierarchy(&handle->lock, &adb->namelocks[bucket]);
	bucket = handle->name_bucket;
	if (bucket != DNS_ADB_INVALIDBUCKET) {
		ISC_LIST_UNLINK(handle->adbname->handles, handle, link);
		handle->adbname = NULL;
		handle->name_bucket = DNS_ADB_INVALIDBUCKET;
	}
	UNLOCK(&adb->namelocks[bucket]);
	bucket = DNS_ADB_INVALIDBUCKET;

 cleanup:
	UNLOCK(&handle->lock);

	/*
	 * The handle doesn't exist on any list, and nothing is locked.
	 * Return the handle to the memory pool, and decrement the adb's
	 * reference count.
	 */
	ai = ISC_LIST_HEAD(handle->list);
	while (ai != NULL) {
		ISC_LIST_UNLINK(handle->list, ai, link);
		entry = ai->entry;
		ai->entry = NULL;
		ai->sockaddr = NULL;
		INSIST(DNS_ADBENTRY_VALID(entry));
		dec_entry_refcnt(adb, entry, ISC_TRUE);
		free_adbaddrinfo(adb, &ai);
		ai = ISC_LIST_HEAD(handle->list);
	}

	LOCK(&adb->lock);
	free_adbhandle(adb, &handle);
	check_exit(adb);
	UNLOCK(&adb->lock);
}

void
dns_adb_dump(dns_adb_t *adb, FILE *f)
{
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(f != NULL);

	/*
	 * Lock the adb itself, lock all the name buckets, then lock all
	 * the entry buckets.  This should put the adb into a state where
	 * nothing can change, so we can iterate through everything and
	 * print at our leasure.
	 */

	LOCK(&adb->lock);
	dump_adb(adb, f);
	UNLOCK(&adb->lock);
}

static void
dump_adb(dns_adb_t *adb, FILE *f)
{
	int i;
	isc_sockaddr_t *sa;
	dns_adbname_t *name;
	dns_adbentry_t *entry;
	char tmp[512];
	const char *tmpp;

	fprintf(f, "ADB %p DUMP:\n", adb);
	fprintf(f, "erefcnt %u, irefcnt %u\n", adb->erefcnt, adb->irefcnt);

	for (i = 0 ; i < DNS_ADBNAMELIST_LENGTH ; i++)
		LOCK(&adb->namelocks[i]);
	for (i = 0 ; i < DNS_ADBENTRYLIST_LENGTH ; i++)
		LOCK(&adb->entrylocks[i]);

	/*
	 * Dump the names
	 */
	fprintf(f, "Names:\n");
	for (i = 0 ; i < DNS_ADBNAMELIST_LENGTH ; i++) {
		name = ISC_LIST_HEAD(adb->names[i]);
		if (name == NULL)
			continue;
		fprintf(f, "Name bucket %d:\n", i);
		while (name != NULL) {
			fprintf(f, "name %p\n", name);
			if (!DNS_ADBNAME_VALID(name))
				fprintf(f, "\tMAGIC %08x\n", name->magic);
			fprintf(f, "\texpiry %u ", name->expire_time);
			print_dns_name(f, &name->name);
			fprintf(f, "\n");
			print_namehook_list(f, name);
			print_fetch_list(f, name);
			print_handle_list(f, name);
			fprintf(f, "\n");

			name = ISC_LIST_NEXT(name, link);
		}
	}

	/*
	 * Dump the entries
	 */
	fprintf(f, "Entries:\n");
	for (i = 0 ; i < DNS_ADBENTRYLIST_LENGTH ; i++) {
		entry = ISC_LIST_HEAD(adb->entries[i]);
		if (entry == NULL)
			continue;
		fprintf(f, "Entry bucket %d:\n", i);
		while (entry != NULL) {
			if (!DNS_ADBENTRY_VALID(entry))
				fprintf(f, "\tMAGIC %08x\n", entry->magic);
			if (entry->lock_bucket != i)
				fprintf(f, "\tWRONG BUCKET!  lock_bucket %d\n",
					entry->lock_bucket);

			sa = &entry->sockaddr;
			switch (sa->type.sa.sa_family) {
			case AF_INET:
				tmpp = inet_ntop(AF_INET,
						 &sa->type.sin.sin_addr,
						 tmp, sizeof tmp);
				break;
			case AF_INET6:
				tmpp = inet_ntop(AF_INET6,
						 &sa->type.sin6.sin6_addr,
						 tmp, sizeof tmp);
				break;
			default:
				tmpp = "UnkFamily";
			}

			if (tmpp == NULL)
				tmpp = "CANNOT TRANSLATE ADDRESS!";

			fprintf(f, "\t%p: refcnt %u flags %08x goodness %d"
				" srtt %u addr %s\n",
				entry, entry->refcnt, entry->flags,
				entry->goodness, entry->srtt, tmpp);

			entry = ISC_LIST_NEXT(entry, link);
		}
	}

	/*
	 * Unlock everything
	 */
	for (i = 0 ; i < DNS_ADBENTRYLIST_LENGTH ; i++)
		UNLOCK(&adb->entrylocks[i]);
	for (i = 0 ; i < DNS_ADBNAMELIST_LENGTH ; i++)
		UNLOCK(&adb->namelocks[i]);
}

void
dns_adb_dumphandle(dns_adb_t *adb, dns_adbhandle_t *handle, FILE *f)
{
	char tmp[512];
	const char *tmpp;
	dns_adbaddrinfo_t *ai;
	isc_sockaddr_t *sa;

	/*
	 * Not used currently, in the API Just In Case we
	 * want to dump out the name and/or entries too.
	 */
	(void)adb;

	LOCK(&handle->lock);

	fprintf(f, "Handle %p\n", handle);
	fprintf(f, "\tquery_pending %d, result %d (%s)\n",
		handle->query_pending, handle->result,
		isc_result_totext(handle->result));
	fprintf(f, "\tname_bucket %d, name %p, event sender %p\n",
		handle->name_bucket, handle->adbname, handle->event.sender);

	ai = ISC_LIST_HEAD(handle->list);
	if (ai != NULL)
		fprintf(f, "\tAddresses:\n");
	while (ai != NULL) {
		sa = ai->sockaddr;
		switch (sa->type.sa.sa_family) {
		case AF_INET:
			tmpp = inet_ntop(AF_INET, &sa->type.sin.sin_addr,
					 tmp, sizeof tmp);
			break;
		case AF_INET6:
			tmpp = inet_ntop(AF_INET6, &sa->type.sin6.sin6_addr,
					 tmp, sizeof tmp);
			break;
		default:
			tmpp = "UnkFamily";
		}

		if (tmpp == NULL)
			tmpp = "CANNOT TRANSLATE ADDRESS!";

		fprintf(f, "\t\tentry %p, flags %08x goodness %d"
			" srtt %u addr %s\n",
			ai->entry, ai->flags, ai->goodness, ai->srtt, tmpp);

		ai = ISC_LIST_NEXT(ai, link);
	}

	UNLOCK(&handle->lock);
}

static void
print_dns_name(FILE *f, dns_name_t *name)
{
	char buf[257];
	isc_buffer_t b;

	INSIST(f != NULL);

	memset(buf, 0, sizeof (buf));
	isc_buffer_init(&b, buf, sizeof (buf) - 1, ISC_BUFFERTYPE_TEXT);

	dns_name_totext(name, ISC_FALSE, &b);
	fprintf(f, buf); /* safe, since names < 256 chars, and we memset */
}

static void
print_namehook_list(FILE *f, dns_adbname_t *n)
{
	dns_adbnamehook_t *nh;

	nh = ISC_LIST_HEAD(n->namehooks);
	while (nh != NULL) {
		fprintf(f, "\t\tHook %p -> entry %p\n", nh, nh->entry);
		nh = ISC_LIST_NEXT(nh, link);
	}
}

static void
print_fetch_list(FILE *f, dns_adbname_t *n)
{
	dns_adbfetch_t *fetch;

	fetch = ISC_LIST_HEAD(n->fetches);
	while (fetch != NULL) {
		fprintf(f, "\t\tFetch %p\n", fetch);
		fetch = ISC_LIST_NEXT(fetch, link);
	}
}

static void
print_handle_list(FILE *f, dns_adbname_t *name)
{
	dns_adbhandle_t *handle;

	handle = ISC_LIST_HEAD(name->handles);
	while (handle != NULL) {
		fprintf(f, "\t\tHandle %p\n", handle);
		handle = ISC_LIST_NEXT(handle, link);
	}
}

/*
 * On entry, "bucket" refers to a locked name bucket, "handle" is not NULL,
 * and "name" is the name we are looking for.  We will allocate an adbname
 * and return a pointer to it in *adbnamep.
 *
 * If we return ISC_R_SUCCESS, the new name will have been allocated, and
 * perhaps some namehooks will have been filled in with valid entries, and
 * perhaps some fetches have been started.
 */
static isc_result_t
construct_name(dns_adb_t *adb, dns_adbhandle_t *handle, dns_name_t *zone,
	       dns_adbname_t *adbname, int bucket, isc_stdtime_t now)
{
	dns_adbnamehook_t *nh;
	isc_result_t result;
	int addr_bucket;
	isc_boolean_t return_success;
	isc_boolean_t use_hints;
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;
	struct in_addr ina;
	isc_sockaddr_t sockaddr;
	dns_adbentry_t *foundentry;  /* NO CLEAN UP! */
	isc_stdtime_t expire_time;

	INSIST(DNS_ADB_VALID(adb));
	INSIST(DNS_ADBHANDLE_VALID(handle));
	INSIST(DNS_ADBNAME_VALID(adbname));
	INSIST(bucket != DNS_ADB_INVALIDBUCKET);

	if (adb->view == NULL)
		return (ISC_R_NOTIMPLEMENTED);

	result = ISC_R_UNEXPECTED;
	addr_bucket = DNS_ADB_INVALIDBUCKET;
	return_success = ISC_FALSE;
	expire_time = INT_MAX;
	nh = NULL;

	use_hints = dns_name_equal(zone, dns_rootname);
	dns_rdataset_init(&rdataset);
	adbname->partial_result = ISC_FALSE;

	result = dns_view_find(adb->view, &adbname->name, dns_rdatatype_a,
			       now, DNS_DBFIND_GLUEOK, use_hints,
			       &rdataset, NULL);
	switch (result) {
	case DNS_R_GLUE:
	case DNS_R_HINT:
	case DNS_R_SUCCESS:
		result = dns_rdataset_first(&rdataset);
		while (result == ISC_R_SUCCESS) {
			nh = new_adbnamehook(adb, NULL);
			if (nh == NULL) {
				adbname->partial_result = ISC_TRUE;
				result = ISC_R_NOMEMORY;
				goto fail;
			}

			if (now + rdataset.ttl < expire_time)
				expire_time = now + rdataset.ttl;

			dns_rdataset_current(&rdataset, &rdata);
			INSIST(rdata.length == 4);
			memcpy(&ina.s_addr, rdata.data, 4);
			isc_sockaddr_fromin(&sockaddr, &ina, 53);

			foundentry = find_entry_and_lock(adb, &sockaddr,
							 &addr_bucket);
			if (foundentry == NULL) {
				dns_adbentry_t *entry;

				entry = new_adbentry(adb);
				if (entry == NULL) {
					adbname->partial_result = ISC_TRUE;
					result = ISC_R_NOMEMORY;
					goto fail;
				}

				entry->sockaddr = sockaddr;
				entry->refcnt = 1;
				entry->lock_bucket = addr_bucket;

				nh->entry = entry;

				ISC_LIST_APPEND(adb->entries[addr_bucket],
						entry, link);
			} else {
				foundentry->refcnt++;
				nh->entry = foundentry;
			}

			ISC_LIST_APPEND(adbname->namehooks, nh, link);
			nh = NULL;

			return_success = ISC_TRUE;

			result = dns_rdataset_next(&rdataset);
		}
	}

 fail:
	if (rdataset.methods != NULL)
		if (dns_rdataset_isassociated(&rdataset))
			dns_rdataset_disassociate(&rdataset);

	if (nh != NULL)
		free_adbnamehook(adb, &nh);

	if (addr_bucket != DNS_ADB_INVALIDBUCKET)
		UNLOCK(&adb->entrylocks[addr_bucket]);

	adbname->expire_time = expire_time;

	if (return_success)
		return (ISC_R_SUCCESS);
	return (result);
}

static void
fetch_callback(isc_task_t *task, isc_event_t *ev)
{
	dns_fetchevent_t *dev;
	dns_adbname_t *name;
	dns_adb_t *adb;
	dns_adbfetch_t *fetch;
	int bucket;
	isc_eventtype_t ev_status;

	(void)task;

	fprintf(stderr, "Event!\n");

	INSIST(ev->type == DNS_EVENT_FETCHDONE);
	dev = (dns_fetchevent_t *)ev;
	name = ev->arg;
	INSIST(DNS_ADBNAME_VALID(name));
	adb = name->adb;
	INSIST(DNS_ADB_VALID(adb));

	fprintf(stderr, "Fetch %p\n", dev->fetch);

	bucket = name->lock_bucket;
	LOCK(&adb->namelocks[bucket]);

	/*
	 * Find the fetch.
	 */
	fetch = ISC_LIST_HEAD(name->fetches);
	while (fetch != NULL && fetch->fetch != dev->fetch)
		fetch = ISC_LIST_NEXT(fetch, link);

	INSIST(fetch != NULL);
	ISC_LIST_UNLINK(name->fetches, fetch, link);
	dns_resolver_destroyfetch(adb->view->resolver, &fetch->fetch);
	dev->fetch = NULL;

	/*
	 * If this name is marked as dead, clean up, throwing away
	 * potentially good data.
	 */
	if (name->dead) {
		isc_boolean_t decr_adbrefcnt;

		free_adbfetch(adb, &fetch);
		isc_event_free(&ev);

		kill_name(adb, &name, DNS_EVENT_ADBCANCELED);

		decr_adbrefcnt = ISC_FALSE;
		if (adb->name_sd[bucket] && (adb->name_refcnt[bucket] == 0))
			decr_adbrefcnt = ISC_TRUE;

		UNLOCK(&adb->namelocks[bucket]);

		if (decr_adbrefcnt)
			dec_adb_irefcnt(adb, ISC_TRUE);

		return;
	}

	/*
	 * Did we get back junk?  If so, and there are no more fetches
	 * sitting out there, tell all the handles about it.
	 */
	if (dev->result != ISC_R_SUCCESS) {
		ev_status = DNS_EVENT_ADBNOMOREADDRESSES;
		goto out;
	}

	/*
	 * We got something potentially useful.  For now, just assume failure
	 * anyway. XXXMLG
	 */
	ev_status = DNS_EVENT_ADBNOMOREADDRESSES;

 out:
	free_adbfetch(adb, &fetch);
	isc_event_free(&ev);

	if (EMPTY(name->fetches))
		clean_handles_at_name(name, DNS_EVENT_ADBNOMOREADDRESSES);

	UNLOCK(&adb->namelocks[bucket]);

	return;

}

static isc_result_t
fetch_name(dns_adb_t *adb, dns_name_t *zone, dns_adbname_t *adbname,
	   isc_stdtime_t now)
{
	isc_result_t result;
	dns_adbfetch_t *fetch;
	dns_rdataset_t nameservers;
	dns_name_t fname;
	isc_buffer_t buffer;
	unsigned char ndata[256];

	isc_buffer_init(&buffer, ndata, sizeof(ndata), ISC_BUFFERTYPE_BINARY);

	fetch = NULL;
	dns_name_init(&fname, NULL);
	dns_name_setbuffer(&fname, &buffer);
	dns_rdataset_init(&nameservers);

	result = dns_view_findzonecut(adb->view, &adbname->name, &fname, now,
				      0, ISC_TRUE, &nameservers, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	fetch = new_adbfetch(adb);
	if (fetch == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	result = dns_resolver_createfetch(adb->view->resolver, &adbname->name,
					  dns_rdatatype_a, dns_rootname,
					  &nameservers, NULL, 0,
					  adb->task, fetch_callback, adbname,
					  &fetch->rdataset, NULL,
					  &fetch->fetch);
	INSIST(result == ISC_R_SUCCESS);  /* XXX temporary */
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	ISC_LIST_APPEND(adbname->fetches, fetch, link);
	fetch = NULL;  /* keep us from cleaning this up below */

 cleanup:
	if (fetch != NULL)
		free_adbfetch(adb, &fetch);

	if (nameservers.methods != NULL)
		if (dns_rdataset_isassociated(&nameservers))
			dns_rdataset_disassociate(&nameservers);

	return (result);
}

isc_result_t
dns_adb_marklame(dns_adb_t *adb, dns_adbaddrinfo_t *addr, dns_name_t *zone,
		 isc_stdtime_t expire_time)
{
	dns_adbzoneinfo_t *zi;
	int bucket;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));
	REQUIRE(zone != NULL);

	zi = new_adbzoneinfo(adb, zone);
	if (zi == NULL)
		return (ISC_R_NOMEMORY);

	zi->lame_timer = expire_time;

	bucket = addr->entry->lock_bucket;
	LOCK(&adb->entrylocks[bucket]);
	ISC_LIST_PREPEND(addr->entry->zoneinfo, zi, link);
	UNLOCK(&adb->entrylocks[bucket]);

	return (ISC_R_SUCCESS);
}

void
dns_adb_adjustgoodness(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		       int goodness_adjustment)
{
	int bucket;
	int old_goodness, new_goodness;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	if (goodness_adjustment == 0)
		return;

	bucket = addr->entry->lock_bucket;
	LOCK(&adb->entrylocks[bucket]);

	old_goodness = addr->entry->goodness;

	if (goodness_adjustment > 0) {
		if (old_goodness > INT_MAX - goodness_adjustment)
			new_goodness = INT_MAX;
		else
			new_goodness = old_goodness + goodness_adjustment;
	} else {
		if (old_goodness < INT_MIN - goodness_adjustment)
			new_goodness = INT_MAX;
		else
			new_goodness = old_goodness + goodness_adjustment;
	}

	addr->entry->goodness = new_goodness;
	addr->goodness = new_goodness;

	UNLOCK(&adb->entrylocks[bucket]);
}

void
dns_adb_adjustsrtt(dns_adb_t *adb, dns_adbaddrinfo_t *addr,
		   unsigned int rtt, unsigned int factor)
{
	int bucket;
	unsigned int new_srtt;

	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(DNS_ADBADDRINFO_VALID(addr));

	if (factor == 0)
		factor = 4;

	bucket = addr->entry->lock_bucket;
	LOCK(&adb->entrylocks[bucket]);

	new_srtt = (addr->entry->srtt * (factor - 1) + rtt) / factor;
	addr->entry->srtt = new_srtt;
	addr->srtt = new_srtt;

	UNLOCK(&adb->entrylocks[bucket]);
}
