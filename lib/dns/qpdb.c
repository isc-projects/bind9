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
#include <stdbool.h>
#include <sys/mman.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/crc64.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/heap.h>
#include <isc/hex.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/serial.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/qp.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/view.h>
#include <dns/zonekey.h>

#include "db_p.h"
#include "qpdb_p.h"

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) == 0)
#define NONEXISTENT(header)                            \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) != 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_IGNORE) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NXDOMAIN) != 0)
#define STALE(header)                                  \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE) != 0)
#define STALE_WINDOW(header)                           \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE_WINDOW) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_OPTOUT) != 0)
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NEGATIVE) != 0)
#define PREFETCH(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_PREFETCH) != 0)
#define CASESET(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_CASESET) != 0)
#define ZEROTTL(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ZEROTTL) != 0)
#define ANCIENT(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ANCIENT) != 0)
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STATCOUNT) != 0)

#define STALE_TTL(header, qpdb) \
	(NXDOMAIN(header) ? 0 : qpdb->common.serve_stale_ttl)

#define ACTIVE(header, now) \
	(((header)->ttl > (now)) || ((header)->ttl == (now) && ZEROTTL(header)))

#define DEFAULT_NODE_LOCK_COUNT 7 /*%< Should be prime. */

#define EXPIREDOK(rbtiterator) \
	(((rbtiterator)->common.options & DNS_DB_EXPIREDOK) != 0)

#define STALEOK(rbtiterator) \
	(((rbtiterator)->common.options & DNS_DB_STALEOK) != 0)

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

#define QPDBITER_NSEC3_ORIGIN_NODE(qpdb, iterator)        \
	((iterator)->current == &(iterator)->nsec3iter && \
	 (iterator)->node == (qpdb)->nsec3_origin_node)

/*%
 * Number of buckets for cache DB entries (locks, LRU lists, TTL heaps).
 * There is a tradeoff issue about configuring this value: if this is too
 * small, it may cause heavier contention between threads; if this is too large,
 * LRU purge algorithm won't work well (entries tend to be purged prematurely).
 * The default value should work well for most environments, but this can
 * also be configurable at compilation time via the
 * DNS_QPDB_CACHE_NODE_LOCK_COUNT variable.  This value must be larger than
 * 1 due to the assumption of dns__qpcache_overmem().
 */
#ifdef DNS_QPDB_CACHE_NODE_LOCK_COUNT
#if DNS_QPDB_CACHE_NODE_LOCK_COUNT <= 1
#error "DNS_QPDB_CACHE_NODE_LOCK_COUNT must be larger than 1"
#else /* if DNS_QPDB_CACHE_NODE_LOCK_COUNT <= 1 */
#define DEFAULT_CACHE_NODE_LOCK_COUNT DNS_QPDB_CACHE_NODE_LOCK_COUNT
#endif /* if DNS_QPDB_CACHE_NODE_LOCK_COUNT <= 1 */
#else  /* ifdef DNS_QPDB_CACHE_NODE_LOCK_COUNT */
#define DEFAULT_CACHE_NODE_LOCK_COUNT 17
#endif /* DNS_QPDB_CACHE_NODE_LOCK_COUNT */

/*
 * This defines the number of headers that we try to expire each time the
 * expire_ttl_headers() is run.  The number should be small enough, so the
 * TTL-based header expiration doesn't take too long, but it should be large
 * enough, so we expire enough headers if their TTL is clustered.
 */
#define DNS_QPDB_EXPIRE_TTL_COUNT 10

/* QP methods */
static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_qpdata_t *data = pval;
	dns_qpdata_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_qpdata_t *data = pval;
	dns_qpdata_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	dns_qpdata_t *data = pval;
	return (dns_qpkey_fromname(key, data->name));
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	UNUSED(uctx);
	snprintf(buf, size, "qpdb-lite");
}

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

typedef struct qpdb_rdatasetiter {
	dns_rdatasetiter_t common;
	dns_slabheader_t *current;
} qpdb_rdatasetiter_t;

/*
 * Note that these iterators, unless created with either DNS_DB_NSEC3ONLY or
 * DNS_DB_NONSEC3, will transparently move between the last node of the
 * "regular" QP ("iter" field) and the root node of the NSEC3 QP
 * ("nsec3iter" field) of the database in question, as if the latter was a
 * successor to the former in lexical order.  The "current" field always holds
 * the address of either "iter" or "nsec3iter", depending on which QP is
 * being traversed at given time.
 */
static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG);
static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy, dbiterator_first, dbiterator_last,
	dbiterator_seek,    dbiterator_prev,  dbiterator_next,
	dbiterator_current, dbiterator_pause, dbiterator_origin
};

/*
 * If 'paused' is true, then the tree lock is not being held.
 */
typedef struct qpdb_dbiterator {
	dns_dbiterator_t common;
	bool paused;
	bool new_origin;
	isc_rwlocktype_t tree_locked;
	isc_result_t result;
	dns_fixedname_t origin;
	dns_fixedname_t fixed;
	dns_name_t *name;
	dns_qpiter_t iter;
	dns_qpiter_t nsec3iter;
	dns_qpiter_t *current;
	dns_qpdata_t *node;
	enum { full, nonsec3, nsec3only } nsec3mode;
} qpdb_dbiterator_t;

static void
free_qpdb(dns_qpdb_t *qpdb, bool log);

/*%
 * 'init_count' is used to initialize 'newheader->count' which inturn
 * is used to determine where in the cycle rrset-order cyclic starts.
 * We don't lock this as we don't care about simultaneous updates.
 */
static atomic_uint_fast16_t init_count = 0;

/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Tree Lock
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

/*
 * DB Routines
 */

static void
update_rrsetstats(dns_stats_t *stats, const dns_typepair_t htype,
		  const uint_least16_t hattributes, const bool increment) {
	dns_rdatastatstype_t statattributes = 0;
	dns_rdatastatstype_t base = 0;
	dns_rdatastatstype_t type;
	dns_slabheader_t *header = &(dns_slabheader_t){
		.type = htype,
		.attributes = hattributes,
	};

	if (!EXISTS(header) || !STATCOUNT(header)) {
		return;
	}

	if (NEGATIVE(header)) {
		if (NXDOMAIN(header)) {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXDOMAIN;
		} else {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXRRSET;
			base = DNS_TYPEPAIR_COVERS(header->type);
		}
	} else {
		base = DNS_TYPEPAIR_TYPE(header->type);
	}

	if (STALE(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_STALE;
	}
	if (ANCIENT(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_ANCIENT;
	}

	type = DNS_RDATASTATSTYPE_VALUE(base, statattributes);
	if (increment) {
		dns_rdatasetstats_increment(stats, type);
	} else {
		dns_rdatasetstats_decrement(stats, type);
	}
}

void
dns__qpdb_setttl(dns_slabheader_t *header, dns_ttl_t newttl) {
	dns_ttl_t oldttl = header->ttl;

	header->ttl = newttl;

	if (header->db == NULL || !dns_db_iscache(header->db)) {
		return;
	}

	/*
	 * This is a cache. Adjust the heaps if necessary.
	 */
	if (header->heap == NULL || header->heap_index == 0 || newttl == oldttl)
	{
		return;
	}

	if (newttl < oldttl) {
		isc_heap_increased(header->heap, header->heap_index);
	} else {
		isc_heap_decreased(header->heap, header->heap_index);
	}

	if (newttl == 0) {
		isc_heap_delete(header->heap, header->heap_index);
	}
}

static bool
prio_type(dns_typepair_t type) {
	switch (type) {
	case dns_rdatatype_soa:
	case DNS_SIGTYPE(dns_rdatatype_soa):
	case dns_rdatatype_a:
	case DNS_SIGTYPE(dns_rdatatype_a):
	case dns_rdatatype_aaaa:
	case DNS_SIGTYPE(dns_rdatatype_aaaa):
	case dns_rdatatype_nsec:
	case DNS_SIGTYPE(dns_rdatatype_nsec):
	case dns_rdatatype_nsec3:
	case DNS_SIGTYPE(dns_rdatatype_nsec3):
	case dns_rdatatype_ns:
	case DNS_SIGTYPE(dns_rdatatype_ns):
	case dns_rdatatype_ds:
	case DNS_SIGTYPE(dns_rdatatype_ds):
	case dns_rdatatype_cname:
	case DNS_SIGTYPE(dns_rdatatype_cname):
		return (true);
	}
	return (false);
}

/*%
 * These functions allow the heap code to rank the priority of each
 * element.  It returns true if v1 happens "sooner" than v2.
 */
static bool
ttl_sooner(void *v1, void *v2) {
	dns_slabheader_t *h1 = v1;
	dns_slabheader_t *h2 = v2;

	return (h1->ttl < h2->ttl);
}

/*%
 * This function sets the heap index into the header.
 */
static void
set_index(void *what, unsigned int idx) {
	dns_slabheader_t *h = what;

	h->heap_index = idx;
}

static void
free_qpdb(dns_qpdb_t *qpdb, bool log) {
	unsigned int i;
	char buf[DNS_NAME_FORMATSIZE];
	dns_qp_t **treep = NULL;

	/*
	 * We assume the number of remaining dead nodes is reasonably small;
	 * the overhead of unlinking all nodes here should be negligible.
	 */
	for (i = 0; i < qpdb->node_lock_count; i++) {
		dns_qpdata_t *node = NULL;

		node = ISC_LIST_HEAD(qpdb->deadnodes[i]);
		while (node != NULL) {
			ISC_LIST_UNLINK(qpdb->deadnodes[i], node, deadlink);
			node = ISC_LIST_HEAD(qpdb->deadnodes[i]);
		}
	}

	qpdb->quantum = (qpdb->loop != NULL) ? 100 : 0;

	for (;;) {
		/*
		 * pick the next tree to (start to) destroy
		 */
		treep = &qpdb->tree;
		if (*treep == NULL) {
			treep = &qpdb->nsec;
			if (*treep == NULL) {
				treep = &qpdb->nsec3;
				/*
				 * we're finished after clear cutting
				 */
				if (*treep == NULL) {
					break;
				}
			}
		}

		dns_qp_destroy(treep);
		INSIST(*treep == NULL);
	}

	if (log) {
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "done free_qpdb(%s)", buf);
	}
	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}
	for (i = 0; i < qpdb->node_lock_count; i++) {
		isc_refcount_destroy(&qpdb->node_locks[i].references);
		NODE_DESTROYLOCK(&qpdb->node_locks[i].lock);
	}

	/*
	 * Clean up LRU / re-signing order lists.
	 */
	if (qpdb->lru != NULL) {
		for (i = 0; i < qpdb->node_lock_count; i++) {
			INSIST(ISC_LIST_EMPTY(qpdb->lru[i]));
		}
		isc_mem_cput(qpdb->common.mctx, qpdb->lru,
			     qpdb->node_lock_count,
			     sizeof(dns_slabheaderlist_t));
	}
	/*
	 * Clean up dead node buckets.
	 */
	if (qpdb->deadnodes != NULL) {
		for (i = 0; i < qpdb->node_lock_count; i++) {
			INSIST(ISC_LIST_EMPTY(qpdb->deadnodes[i]));
		}
		isc_mem_cput(qpdb->common.mctx, qpdb->deadnodes,
			     qpdb->node_lock_count, sizeof(dns_qpdatalist_t));
	}
	/*
	 * Clean up heap objects.
	 */
	if (qpdb->heaps != NULL) {
		for (i = 0; i < qpdb->node_lock_count; i++) {
			isc_heap_destroy(&qpdb->heaps[i]);
		}
		isc_mem_cput(qpdb->hmctx, qpdb->heaps, qpdb->node_lock_count,
			     sizeof(isc_heap_t *));
	}

	if (qpdb->rrsetstats != NULL) {
		dns_stats_detach(&qpdb->rrsetstats);
	}
	if (qpdb->cachestats != NULL) {
		isc_stats_detach(&qpdb->cachestats);
	}
	if (qpdb->gluecachestats != NULL) {
		isc_stats_detach(&qpdb->gluecachestats);
	}

	isc_mem_cput(qpdb->common.mctx, qpdb->node_locks, qpdb->node_lock_count,
		     sizeof(db_nodelock_t));
	TREE_DESTROYLOCK(&qpdb->tree_lock);
	isc_refcount_destroy(&qpdb->common.references);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
	}

	isc_rwlock_destroy(&qpdb->lock);
	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;
	isc_mem_detach(&qpdb->hmctx);

	if (qpdb->common.update_listeners != NULL) {
		INSIST(!cds_lfht_destroy(qpdb->common.update_listeners, NULL));
	}

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb, sizeof(*qpdb));
}

void
dns__qpdb_destroy(dns_db_t *arg) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)arg;
	bool want_free = false;
	unsigned int i;
	unsigned int inactive = 0;

	if (qpdb->origin_node != NULL) {
		dns_qpdata_detach(&qpdb->origin_node);
	}
	if (qpdb->nsec3_origin_node != NULL) {
		dns_qpdata_detach(&qpdb->nsec3_origin_node);
	}

	/* XXX check for open versions here */

	if (qpdb->soanode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->soanode);
	}
	if (qpdb->nsnode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->nsnode);
	}

	/*
	 * Even though there are no external direct references, there still
	 * may be nodes in use.
	 */
	for (i = 0; i < qpdb->node_lock_count; i++) {
		isc_rwlocktype_t nodelock = isc_rwlocktype_none;
		NODE_WRLOCK(&qpdb->node_locks[i].lock, &nodelock);
		qpdb->node_locks[i].exiting = true;
		if (isc_refcount_current(&qpdb->node_locks[i].references) == 0)
		{
			inactive++;
		}
		NODE_UNLOCK(&qpdb->node_locks[i].lock, &nodelock);
	}

	if (inactive != 0) {
		RWLOCK(&qpdb->lock, isc_rwlocktype_write);
		qpdb->active -= inactive;
		if (qpdb->active == 0) {
			want_free = true;
		}
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
		if (want_free) {
			char buf[DNS_NAME_FORMATSIZE];
			if (dns_name_dynamic(&qpdb->common.origin)) {
				dns_name_format(&qpdb->common.origin, buf,
						sizeof(buf));
			} else {
				strlcpy(buf, "<UNKNOWN>", sizeof(buf));
			}
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
				      "calling free_qpdb(%s)", buf);
			free_qpdb(qpdb, true);
		}
	}
}

void
dns__qpdb_mark(dns_slabheader_t *header, uint_least16_t flag) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;
	dns_stats_t *stats = NULL;

	/*
	 * If we are already ancient there is nothing to do.
	 */
	do {
		if ((attributes & flag) != 0) {
			return;
		}
		newattributes = attributes | flag;
	} while (!atomic_compare_exchange_weak_acq_rel(
		&header->attributes, &attributes, newattributes));

	/*
	 * Decrement and increment the stats counter for the appropriate
	 * RRtype.
	 */
	stats = dns_db_getrrsetstats(header->db);
	if (stats != NULL) {
		update_rrsetstats(stats, header->type, attributes, false);
		update_rrsetstats(stats, header->type, newattributes, true);
	}
}

static void
mark_ancient(dns_slabheader_t *header) {
	dns__qpdb_setttl(header, 0);
	dns__qpdb_mark(header, DNS_SLABHEADERATTR_ANCIENT);
	QPDB_HEADERNODE(header)->dirty = 1;
}

static void
clean_stale_headers(dns_slabheader_t *top) {
	dns_slabheader_t *d = NULL, *down_next = NULL;

	for (d = top->down; d != NULL; d = down_next) {
		down_next = d->down;
		dns_slabheader_destroy(&d);
	}
	top->down = NULL;
}

static void
clean_cache_node(dns_qpdb_t *qpdb, dns_qpdata_t *node) {
	dns_slabheader_t *current = NULL, *top_prev = NULL, *top_next = NULL;

	/*
	 * Caller must be holding the node lock.
	 */

	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;
		clean_stale_headers(current);
		/*
		 * If current is nonexistent, ancient, or stale and
		 * we are not keeping stale, we can clean it up.
		 */
		if (NONEXISTENT(current) || ANCIENT(current) ||
		    (STALE(current) && !KEEPSTALE(qpdb)))
		{
			if (top_prev != NULL) {
				top_prev->next = current->next;
			} else {
				node->data = current->next;
			}
			dns_slabheader_destroy(&current);
		} else {
			top_prev = current;
		}
	}
	node->dirty = 0;
}

/*
 * tree_lock(write) must be held.
 */
static void
delete_node(dns_qpdb_t *qpdb, dns_qpdata_t *node) {
	isc_result_t result = ISC_R_UNEXPECTED;

	INSIST(!ISC_LINK_LINKED(node, deadlink));

	if (isc_log_wouldlog(dns_lctx, ISC_LOG_DEBUG(1))) {
		char printname[DNS_NAME_FORMATSIZE];
		dns_name_format(node->name, printname, sizeof(printname));
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "delete_node(): %p %s (bucket %d)", node,
			      printname, node->locknum);
	}

	switch (node->nsec) {
	case DNS_DB_NSEC_HAS_NSEC:
		/*
		 * Delete the corresponding node from the auxiliary NSEC
		 * tree before deleting from the main tree.
		 */
		result = dns_qp_deletename(qpdb->nsec, node->name, NULL, NULL);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
				      "delete_node(): "
				      "dns_qp_deletename: %s",
				      isc_result_totext(result));
		}
		/* FALLTHROUGH */
	case DNS_DB_NSEC_NORMAL:
		result = dns_qp_deletename(qpdb->tree, node->name, NULL, NULL);
		break;
	case DNS_DB_NSEC_NSEC:
		result = dns_qp_deletename(qpdb->nsec, node->name, NULL, NULL);
		break;
	case DNS_DB_NSEC_NSEC3:
		result = dns_qp_deletename(qpdb->nsec3, node->name, NULL, NULL);
		break;
	}
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
			      "delete_node(): "
			      "dns_qp_deletename: %s",
			      isc_result_totext(result));
	}
}

/*
 * Caller must be holding the node lock.
 */
void
dns__qpdb_newref(dns_qpdb_t *qpdb, dns_qpdata_t *node,
		 isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	uint_fast32_t refs;

	if (nlocktype == isc_rwlocktype_write &&
	    ISC_LINK_LINKED(node, deadlink))
	{
		ISC_LIST_UNLINK(qpdb->deadnodes[node->locknum], node, deadlink);
	}

	dns_qpdata_ref(node);
	refs = isc_refcount_increment0(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	if (refs == 0) {
		/* this is the first external reference to the node */
		refs = isc_refcount_increment0(
			&qpdb->node_locks[node->locknum].references);
#if DNS_DB_NODETRACE
		fprintf(stderr,
			"incr:nodelock:%s:%s:%u:%p:%p->references = "
			"%" PRIuFAST32 "\n",
			func, file, line, node,
			&qpdb->node_locks[node->locknum], refs + 1);
#else
		UNUSED(refs);
#endif
	}
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not or chose not to delete
 * them when we deleted all the data at that node because we did not want
 * to wait for the tree write lock.
 *
 * The caller must hold a tree write lock and bucketnum'th node (write) lock.
 */
static void
cleanup_dead_nodes(dns_qpdb_t *qpdb, int bucketnum DNS__DB_FLARG) {
	dns_qpdata_t *node = NULL;
	int count = 10; /* XXXJT: should be adjustable */

	node = ISC_LIST_HEAD(qpdb->deadnodes[bucketnum]);
	while (node != NULL && count > 0) {
		ISC_LIST_UNLINK(qpdb->deadnodes[bucketnum], node, deadlink);

		/*
		 * We might have reactivated this node without a tree write
		 * lock, so we couldn't remove this node from deadnodes then
		 * and we have to do it now.
		 */
		if (isc_refcount_current(&node->references) != 0 ||
		    node->data != NULL)
		{
			node = ISC_LIST_HEAD(qpdb->deadnodes[bucketnum]);
			count--;
			continue;
		}

		delete_node(qpdb, node);

		node = ISC_LIST_HEAD(qpdb->deadnodes[bucketnum]);
		count--;
	}
}

/*
 * This function is assumed to be called when a node is newly referenced
 * and can be in the deadnode list.  In that case the node must be retrieved
 * from the list because it is going to be used.  In addition, if the caller
 * happens to hold a write lock on the tree, it's a good chance to purge dead
 * nodes.
 * Note: while a new reference is gained in multiple places, there are only very
 * few cases where the node can be in the deadnode list (only empty nodes can
 * have been added to the list).
 */
static void
reactivate_node(dns_qpdb_t *qpdb, dns_qpdata_t *node,
		isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nodelock = &qpdb->node_locks[node->locknum].lock;
	bool maybe_cleanup = false;

	POST(nlocktype);

	NODE_RDLOCK(nodelock, &nlocktype);

	/*
	 * Check if we can possibly cleanup the dead node.  If so, upgrade
	 * the node lock below to perform the cleanup.
	 */
	if (!ISC_LIST_EMPTY(qpdb->deadnodes[node->locknum]) &&
	    tlocktype == isc_rwlocktype_write)
	{
		maybe_cleanup = true;
	}

	if (ISC_LINK_LINKED(node, deadlink) || maybe_cleanup) {
		/*
		 * Upgrade the lock and test if we still need to unlink.
		 */
		NODE_FORCEUPGRADE(nodelock, &nlocktype);
		POST(nlocktype);
		if (ISC_LINK_LINKED(node, deadlink)) {
			ISC_LIST_UNLINK(qpdb->deadnodes[node->locknum], node,
					deadlink);
		}
		if (maybe_cleanup) {
			cleanup_dead_nodes(qpdb,
					   node->locknum DNS__DB_FILELINE);
		}
	}

	dns__qpdb_newref(qpdb, node, nlocktype DNS__DB_FLARG_PASS);

	NODE_UNLOCK(nodelock, &nlocktype);
}

/*
 * Caller must be holding the node lock; either the read or write lock.
 * Note that the lock must be held even when node references are
 * atomically modified; in that case the decrement operation itself does not
 * have to be protected, but we must avoid a race condition where multiple
 * threads are decreasing the reference to zero simultaneously and at least
 * one of them is going to free the node.
 *
 * This decrements both the internal and external node reference counters.
 * If the external reference count drops to zero, then the node lock
 * reference count is also decremented.
 *
 * This function returns true if and only if the node reference decreases
 * to zero.  (NOTE: Decrementing the reference count of a node to zero does
 * not mean it will be immediately freed.)
 */
bool
dns__qpdb_decref(dns_qpdb_t *qpdb, dns_qpdata_t *node, uint32_t least_serial,
		 isc_rwlocktype_t *nlocktypep, isc_rwlocktype_t *tlocktypep,
		 bool tryupgrade, bool pruning DNS__DB_FLARG) {
	isc_result_t result;
	bool locked = *tlocktypep != isc_rwlocktype_none;
	bool write_locked = false;
	db_nodelock_t *nodelock = NULL;
	int bucket = node->locknum;
	bool no_reference = true;
	uint_fast32_t refs;

	REQUIRE(*nlocktypep != isc_rwlocktype_none);

	UNUSED(pruning);
	UNUSED(least_serial);

	nodelock = &qpdb->node_locks[bucket];

#define KEEP_NODE(n, r)                                  \
	((n)->data != NULL || (n) == (r)->origin_node || \
	 (n) == (r)->nsec3_origin_node)

	/* Handle easy and typical case first. */
	if (!node->dirty && KEEP_NODE(node, qpdb)) {
		refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
		fprintf(stderr,
			"decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
			func, file, line, node, refs - 1);
#else
		UNUSED(refs);
#endif
		if (refs == 1) {
			refs = isc_refcount_decrement(&nodelock->references);
#if DNS_DB_NODETRACE
			fprintf(stderr,
				"decr:nodelock:%s:%s:%u:%p:%p->references = "
				"%" PRIuFAST32 "\n",
				func, file, line, node, nodelock, refs - 1);
#else
			UNUSED(refs);
#endif
			no_reference = true;
		} else {
			no_reference = false;
		}

		dns_qpdata_unref(node);
		return (no_reference);
	}

	/* Upgrade the lock? */
	if (*nlocktypep == isc_rwlocktype_read) {
		NODE_FORCEUPGRADE(&nodelock->lock, nlocktypep);
	}

	refs = isc_refcount_decrement(&node->erefs);
#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif

	if (refs > 1) {
		dns_qpdata_unref(node);
		return (false);
	}

	INSIST(refs == 1);

	if (node->dirty) {
		clean_cache_node(qpdb, node);
	}

	/*
	 * Attempt to switch to a write lock on the tree.  If this fails,
	 * we will add this node to a linked list of nodes in this locking
	 * bucket which we will free later.
	 *
	 * Locking hierarchy notwithstanding, we don't need to free
	 * the node lock before acquiring the tree write lock because
	 * we only do a trylock.
	 */
	/* We are allowed to upgrade the tree lock */

	switch (*tlocktypep) {
	case isc_rwlocktype_write:
		result = ISC_R_SUCCESS;
		break;
	case isc_rwlocktype_read:
		if (tryupgrade) {
			result = TREE_TRYUPGRADE(&qpdb->tree_lock, tlocktypep);
		} else {
			result = ISC_R_LOCKBUSY;
		}
		break;
	case isc_rwlocktype_none:
		result = TREE_TRYWRLOCK(&qpdb->tree_lock, tlocktypep);
		break;
	default:
		UNREACHABLE();
	}
	RUNTIME_CHECK(result == ISC_R_SUCCESS || result == ISC_R_LOCKBUSY);
	if (result == ISC_R_SUCCESS) {
		write_locked = true;
	}

	refs = isc_refcount_decrement(&nodelock->references);
#if DNS_DB_NODETRACE
	fprintf(stderr,
		"decr:nodelock:%s:%s:%u:%p:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, nodelock, refs - 1);
#else
	UNUSED(refs);
#endif

	if (KEEP_NODE(node, qpdb)) {
		goto restore_locks;
	}

#undef KEEP_NODE

	if (write_locked) {
		/*
		 * We can now delete the node.
		 */
		delete_node(qpdb, node);
	} else {
		INSIST(node->data == NULL);
		if (!ISC_LINK_LINKED(node, deadlink)) {
			ISC_LIST_APPEND(qpdb->deadnodes[bucket], node,
					deadlink);
		}
	}

restore_locks:
	/*
	 * Relock a read lock, or unlock the write lock if no lock was held.
	 */
	if (!locked && write_locked) {
		TREE_UNLOCK(&qpdb->tree_lock, tlocktypep);
	}

	dns_qpdata_unref(node);
	return (no_reference);
}

isc_result_t
dns__qpdb_findnodeintree(dns_qpdb_t *qpdb, dns_qp_t *tree,
			 const dns_name_t *name, bool create,
			 dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_qpdata_t *node = NULL;
	isc_result_t result;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(tree == qpdb->tree || tree == qpdb->nsec3);

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	result = dns_qp_lookup(tree, name, NULL, NULL, NULL, (void **)&node,
			       NULL);
	if (result != ISC_R_SUCCESS) {
		if (!create) {
			if (result == DNS_R_PARTIALMATCH) {
				result = ISC_R_NOTFOUND;
			}
			goto unlock;
		}
		/*
		 * Try to upgrade the lock and if that fails unlock then relock.
		 */
		TREE_FORCEUPGRADE(&qpdb->tree_lock, &tlocktype);
		result = dns_qp_lookup(tree, name, NULL, NULL, NULL,
				       (void **)&node, NULL);
		if (result != ISC_R_SUCCESS) {
			node = dns_qpdata_create(qpdb, name);
			result = dns_qp_insert(tree, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			dns_qpdata_unref(node);
		}

		if (tree == qpdb->nsec3) {
			node->nsec = DNS_DB_NSEC_NSEC3;
		}
	}

	if (tree == qpdb->nsec3) {
		INSIST(node->nsec == DNS_DB_NSEC_NSEC3);
	}

	reactivate_node(qpdb, node, tlocktype DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)node;
unlock:
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return (result);
}

isc_result_t
dns__qpdb_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		   dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	return (dns__qpdb_findnodeintree(qpdb, qpdb->tree, name, create,
					 nodep DNS__DB_FLARG_PASS));
}

void
dns__qpdb_bindrdataset(dns_qpdb_t *qpdb, dns_qpdata_t *node,
		       dns_slabheader_t *header, isc_stdtime_t now,
		       isc_rwlocktype_t locktype,
		       dns_rdataset_t *rdataset DNS__DB_FLARG) {
	bool stale = STALE(header);
	bool ancient = ANCIENT(header);

	/*
	 * Caller must be holding the node reader lock.
	 * XXXJT: technically, we need a writer lock, since we'll increment
	 * the header count below.  However, since the actual counter value
	 * doesn't matter, we prioritize performance here.  (We may want to
	 * use atomic increment when available).
	 */

	if (rdataset == NULL) {
		return;
	}

	dns__qpdb_newref(qpdb, node, locktype DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale or ancient if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (KEEPSTALE(qpdb) && stale_ttl > now) {
			stale = true;
		} else {
			/*
			 * We are not keeping stale, or it is outside the
			 * stale window. Mark ancient, i.e. ready for cleanup.
			 */
			ancient = true;
		}
	}

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->type);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->type);
	rdataset->ttl = header->ttl - now;
	rdataset->trust = header->trust;
	rdataset->resign = 0;

	if (NEGATIVE(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NEGATIVE;
	}
	if (NXDOMAIN(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NXDOMAIN;
	}
	if (OPTOUT(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_OPTOUT;
	}
	if (PREFETCH(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_PREFETCH;
	}

	if (stale && !ancient) {
		dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);
		if (stale_ttl > now) {
			rdataset->ttl = stale_ttl - now;
		} else {
			rdataset->ttl = 0;
		}
		if (STALE_WINDOW(header)) {
			rdataset->attributes |= DNS_RDATASETATTR_STALE_WINDOW;
		}
		rdataset->attributes |= DNS_RDATASETATTR_STALE;
	} else if (!ACTIVE(header, now)) {
		rdataset->attributes |= DNS_RDATASETATTR_ANCIENT;
		rdataset->ttl = header->ttl;
	}

	rdataset->count = atomic_fetch_add_relaxed(&header->count, 1);

	rdataset->slab.db = (dns_db_t *)qpdb;
	rdataset->slab.node = (dns_dbnode_t *)node;
	rdataset->slab.raw = dns_slabheader_raw(header);
	rdataset->slab.iter_pos = NULL;
	rdataset->slab.iter_count = 0;

	/*
	 * Add noqname proof.
	 */
	rdataset->slab.noqname = header->noqname;
	if (header->noqname != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_NOQNAME;
	}
	rdataset->slab.closest = header->closest;
	if (header->closest != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_CLOSEST;
	}
}

void
dns__qpdb_attachnode(dns_db_t *db, dns_dbnode_t *source,
		     dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));
	REQUIRE(targetp != NULL && *targetp == NULL);

	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *node = (dns_qpdata_t *)source;

	dns__qpdb_newref(qpdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*targetp = source;
}

void
dns__qpdb_detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *node = NULL;
	bool want_free = false;
	bool inactive = false;
	db_nodelock_t *nodelock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (dns_qpdata_t *)(*targetp);
	nodelock = &qpdb->node_locks[node->locknum];

	NODE_RDLOCK(&nodelock->lock, &nlocktype);

	if (dns__qpdb_decref(qpdb, node, 0, &nlocktype, &tlocktype, true,
			     false DNS__DB_FLARG_PASS))
	{
		if (isc_refcount_current(&nodelock->references) == 0 &&
		    nodelock->exiting)
		{
			inactive = true;
		}
	}

	NODE_UNLOCK(&nodelock->lock, &nlocktype);
	INSIST(tlocktype == isc_rwlocktype_none);

	*targetp = NULL;

	if (inactive) {
		RWLOCK(&qpdb->lock, isc_rwlocktype_write);
		qpdb->active--;
		if (qpdb->active == 0) {
			want_free = true;
		}
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
		if (want_free) {
			char buf[DNS_NAME_FORMATSIZE];
			if (dns_name_dynamic(&qpdb->common.origin)) {
				dns_name_format(&qpdb->common.origin, buf,
						sizeof(buf));
			} else {
				strlcpy(buf, "<UNKNOWN>", sizeof(buf));
			}
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
				      "calling free_qpdb(%s)", buf);
			free_qpdb(qpdb, true);
		}
	}
}

isc_result_t
dns__qpdb_createiterator(dns_db_t *db, unsigned int options,
			 dns_dbiterator_t **iteratorp) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdb_dbiterator_t *qpdbiter = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE((options & (DNS_DB_NSEC3ONLY | DNS_DB_NONSEC3)) !=
		(DNS_DB_NSEC3ONLY | DNS_DB_NONSEC3));

	qpdbiter = isc_mem_get(qpdb->common.mctx, sizeof(*qpdbiter));

	qpdbiter->common.methods = &dbiterator_methods;
	qpdbiter->common.db = NULL;
	dns_db_attach(db, &qpdbiter->common.db);
	qpdbiter->common.relative_names = 0; /* no special logic for relative
						 names */
	qpdbiter->common.magic = DNS_DBITERATOR_MAGIC;
	qpdbiter->paused = true;
	qpdbiter->tree_locked = isc_rwlocktype_none;
	qpdbiter->result = ISC_R_SUCCESS;
	dns_fixedname_init(&qpdbiter->origin);
	dns_fixedname_init(&qpdbiter->fixed);
	qpdbiter->name = dns_fixedname_initname(&qpdbiter->fixed);
	qpdbiter->node = NULL;

	if ((options & DNS_DB_NSEC3ONLY) != 0) {
		qpdbiter->nsec3mode = nsec3only;
	} else if ((options & DNS_DB_NONSEC3) != 0) {
		qpdbiter->nsec3mode = nonsec3;
	} else {
		qpdbiter->nsec3mode = full;
	}
	dns_qpiter_init(qpdb->tree, &qpdbiter->iter);
	dns_qpiter_init(qpdb->nsec3, &qpdbiter->nsec3iter);
	if (qpdbiter->nsec3mode == nsec3only) {
		qpdbiter->current = &qpdbiter->nsec3iter;
	} else {
		qpdbiter->current = &qpdbiter->iter;
	}

	*iteratorp = (dns_dbiterator_t *)qpdbiter;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns__qpdb_allrdatasets(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, unsigned int options,
		       isc_stdtime_t now,
		       dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;
	qpdb_rdatasetiter_t *iterator = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	UNUSED(version);

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = NULL;
	iterator->common.options = options;
	iterator->common.now = now;
	iterator->current = NULL;

	dns__qpdb_newref(qpdb, qpnode, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns__qpdb_add(dns_qpdb_t *qpdb, dns_qpdata_t *qpnode,
	      const dns_name_t *nodename ISC_ATTR_UNUSED,
	      dns_slabheader_t *newheader, unsigned int options, bool loading,
	      dns_rdataset_t *addedrdataset, isc_stdtime_t now DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	dns_slabheader_t *topheader = NULL, *topheader_prev = NULL;
	dns_slabheader_t *header = NULL, *sigheader = NULL;
	dns_slabheader_t *prioheader = NULL;
	bool header_nx;
	bool newheader_nx;
	dns_rdatatype_t rdtype, covers;
	dns_typepair_t negtype = 0, sigtype;
	dns_trust_t trust;
	int idx;

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	newheader_nx = NONEXISTENT(newheader) ? true : false;
	if (!newheader_nx) {
		rdtype = DNS_TYPEPAIR_TYPE(newheader->type);
		covers = DNS_TYPEPAIR_COVERS(newheader->type);
		sigtype = DNS_SIGTYPE(covers);
		if (NEGATIVE(newheader)) {
			/*
			 * We're adding a negative cache entry.
			 */
			if (covers == dns_rdatatype_any) {
				/*
				 * If we're adding an negative cache entry
				 * which covers all types (NXDOMAIN,
				 * NODATA(QTYPE=ANY)),
				 *
				 * We make all other data ancient so that the
				 * only rdataset that can be found at this
				 * node is the negative cache entry.
				 */
				for (topheader = qpnode->data;
				     topheader != NULL;
				     topheader = topheader->next)
				{
					mark_ancient(topheader);
				}
				goto find_header;
			}
			/*
			 * Otherwise look for any RRSIGs of the given
			 * type so they can be marked ancient later.
			 */
			for (topheader = qpnode->data; topheader != NULL;
			     topheader = topheader->next)
			{
				if (topheader->type == sigtype) {
					sigheader = topheader;
				}
			}
			negtype = DNS_TYPEPAIR_VALUE(covers, 0);
		} else {
			/*
			 * We're adding something that isn't a
			 * negative cache entry.  Look for an extant
			 * non-ancient NXDOMAIN/NODATA(QTYPE=ANY) negative
			 * cache entry.  If we're adding an RRSIG, also
			 * check for an extant non-ancient NODATA ncache
			 * entry which covers the same type as the RRSIG.
			 */
			for (topheader = qpnode->data; topheader != NULL;
			     topheader = topheader->next)
			{
				if ((topheader->type == RDATATYPE_NCACHEANY) ||
				    (newheader->type == sigtype &&
				     topheader->type ==
					     DNS_TYPEPAIR_VALUE(0, covers)))
				{
					break;
				}
			}
			if (topheader != NULL && EXISTS(topheader) &&
			    ACTIVE(topheader, now))
			{
				/*
				 * Found one.
				 */
				if (trust < topheader->trust) {
					/*
					 * The NXDOMAIN/NODATA(QTYPE=ANY)
					 * is more trusted.
					 */
					dns_slabheader_destroy(&newheader);
					if (addedrdataset != NULL) {
						dns__qpdb_bindrdataset(
							qpdb, qpnode, topheader,
							now,
							isc_rwlocktype_write,
							addedrdataset
								DNS__DB_FLARG_PASS);
					}
					return (DNS_R_UNCHANGED);
				}
				/*
				 * The new rdataset is better.  Expire the
				 * ncache entry.
				 */
				mark_ancient(topheader);
				topheader = NULL;
				goto find_header;
			}
			negtype = DNS_TYPEPAIR_VALUE(0, rdtype);
		}
	}

	for (topheader = qpnode->data; topheader != NULL;
	     topheader = topheader->next)
	{
		if (prio_type(topheader->type)) {
			prioheader = topheader;
		}
		if (topheader->type == newheader->type ||
		    topheader->type == negtype)
		{
			break;
		}
		topheader_prev = topheader;
	}

find_header:
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
	if (header != NULL) {
		header_nx = NONEXISTENT(header) ? true : false;

		/*
		 * Deleting an already non-existent rdataset has no effect.
		 */
		if (header_nx && newheader_nx) {
			dns_slabheader_destroy(&newheader);
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		if (trust < header->trust && (ACTIVE(header, now) || header_nx))
		{
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				dns__qpdb_bindrdataset(
					qpdb, qpnode, header, now,
					isc_rwlocktype_write,
					addedrdataset DNS__DB_FLARG_PASS);
			}
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Don't replace existing NS, A and AAAA RRsets in the
		 * cache if they are already exist. This prevents named
		 * being locked to old servers. Don't lower trust of
		 * existing record if the update is forced. Nothing
		 * special to be done w.r.t stale data; it gets replaced
		 * normally further down.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equalx((unsigned char *)header,
					 (unsigned char *)newheader,
					 (unsigned int)(sizeof(*newheader)),
					 qpdb->common.rdclass,
					 (dns_rdatatype_t)header->type))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->ttl > newheader->ttl) {
				dns__qpdb_setttl(header, newheader->ttl);
			}
			if (header->last_used != now) {
				ISC_LIST_UNLINK(
					qpdb->lru[QPDB_HEADERNODE(header)
							  ->locknum],
					header, link);
				header->last_used = now;
				ISC_LIST_PREPEND(
					qpdb->lru[QPDB_HEADERNODE(header)
							  ->locknum],
					header, link);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL)
			{
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				dns__qpdb_bindrdataset(
					qpdb, qpnode, header, now,
					isc_rwlocktype_write,
					addedrdataset DNS__DB_FLARG_PASS);
			}
			return (ISC_R_SUCCESS);
		}

		/*
		 * If we have will be replacing a NS RRset force its TTL
		 * to be no more than the current NS RRset's TTL.  This
		 * ensures the delegations that are withdrawn are honoured.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust <= newheader->trust)
		{
			if (newheader->ttl > header->ttl) {
				newheader->ttl = header->ttl;
			}
		}
		if (ACTIVE(header, now) &&
		    (options & DNS_DBADD_PREFETCH) == 0 &&
		    (header->type == dns_rdatatype_a ||
		     header->type == dns_rdatatype_aaaa ||
		     header->type == dns_rdatatype_ds ||
		     header->type == DNS_SIGTYPE(dns_rdatatype_ds)) &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equal((unsigned char *)header,
					(unsigned char *)newheader,
					(unsigned int)(sizeof(*newheader))))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->ttl > newheader->ttl) {
				dns__qpdb_setttl(header, newheader->ttl);
			}
			if (header->last_used != now) {
				ISC_LIST_UNLINK(
					qpdb->lru[QPDB_HEADERNODE(header)
							  ->locknum],
					header, link);
				header->last_used = now;
				ISC_LIST_PREPEND(
					qpdb->lru[QPDB_HEADERNODE(header)
							  ->locknum],
					header, link);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL)
			{
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				dns__qpdb_bindrdataset(
					qpdb, qpnode, header, now,
					isc_rwlocktype_write,
					addedrdataset DNS__DB_FLARG_PASS);
			}
			return (ISC_R_SUCCESS);
		}

		if (loading) {
			newheader->down = NULL;
			idx = QPDB_HEADERNODE(newheader)->locknum;
			if (ZEROTTL(newheader)) {
				newheader->last_used = qpdb->last_used + 1;
				ISC_LIST_APPEND(qpdb->lru[idx], newheader,
						link);
			} else {
				ISC_LIST_PREPEND(qpdb->lru[idx], newheader,
						 link);
			}
			INSIST(qpdb->heaps != NULL);
			isc_heap_insert(qpdb->heaps[idx], newheader);
			newheader->heap = qpdb->heaps[idx];

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			dns_slabheader_destroy(&header);
		} else {
			idx = QPDB_HEADERNODE(newheader)->locknum;
			INSIST(qpdb->heaps != NULL);
			isc_heap_insert(qpdb->heaps[idx], newheader);
			newheader->heap = qpdb->heaps[idx];
			if (ZEROTTL(newheader)) {
				newheader->last_used = qpdb->last_used + 1;
				ISC_LIST_APPEND(qpdb->lru[idx], newheader,
						link);
			} else {
				ISC_LIST_PREPEND(qpdb->lru[idx], newheader,
						 link);
			}
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			qpnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
			mark_ancient(header);
			if (sigheader != NULL) {
				mark_ancient(sigheader);
			}
		}
	} else {
		/*
		 * No non-IGNORED rdatasets of the given type exist at
		 * this node.
		 */

		/*
		 * If we're trying to delete the type, don't bother.
		 */
		if (newheader_nx) {
			dns_slabheader_destroy(&newheader);
			return (DNS_R_UNCHANGED);
		}

		idx = QPDB_HEADERNODE(newheader)->locknum;
		isc_heap_insert(qpdb->heaps[idx], newheader);
		newheader->heap = qpdb->heaps[idx];
		if (ZEROTTL(newheader)) {
			ISC_LIST_APPEND(qpdb->lru[idx], newheader, link);
		} else {
			ISC_LIST_PREPEND(qpdb->lru[idx], newheader, link);
		}

		if (topheader != NULL) {
			/*
			 * We have an list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			qpnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */
			INSIST(newheader->down == NULL);

			if (prio_type(newheader->type)) {
				/* This is a priority type, prepend it */
				newheader->next = qpnode->data;
				qpnode->data = newheader;
			} else if (prioheader != NULL) {
				/* Append after the priority headers */
				newheader->next = prioheader->next;
				prioheader->next = newheader;
			} else {
				/* There were no priority headers */
				newheader->next = qpnode->data;
				qpnode->data = newheader;
			}
		}
	}

	if (addedrdataset != NULL) {
		dns__qpdb_bindrdataset(qpdb, qpnode, newheader, now,
				       isc_rwlocktype_write,
				       addedrdataset DNS__DB_FLARG_PASS);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
addnoqname(isc_mem_t *mctx, dns_slabheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *noqname = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1, r2;

	result = dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_rdataslab_fromrdataset(&neg, mctx, &r1, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r2, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	noqname = isc_mem_get(mctx, sizeof(*noqname));
	*noqname = (dns_slabheader_proof_t){
		.neg = r1.base,
		.negsig = r2.base,
		.type = neg.type,
		.name = DNS_NAME_INITEMPTY,
	};
	dns_name_dup(&name, mctx, &noqname->name);
	newheader->noqname = noqname;

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);

	return (result);
}

static isc_result_t
addclosest(isc_mem_t *mctx, dns_slabheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *closest = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1, r2;

	result = dns_rdataset_getclosest(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_rdataslab_fromrdataset(&neg, mctx, &r1, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r2, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	closest = isc_mem_get(mctx, sizeof(*closest));
	*closest = (dns_slabheader_proof_t){
		.neg = r1.base,
		.negsig = r2.base,
		.name = DNS_NAME_INITEMPTY,
		.type = neg.type,
	};
	dns_name_dup(&name, mctx, &closest->name);
	newheader->closest = closest;

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	return (result);
}

static void
expire_ttl_headers(dns_qpdb_t *qpdb, unsigned int locknum,
		   isc_rwlocktype_t *tlocktypep, isc_stdtime_t now,
		   bool cache_is_overmem DNS__DB_FLARG);

isc_result_t
dns__qpdb_addrdataset(dns_db_t *db, dns_dbnode_t *node,
		      dns_dbversion_t *version, isc_stdtime_t now,
		      dns_rdataset_t *rdataset, unsigned int options,
		      dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	bool delegating = false;
	bool newnsec;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	bool cache_is_overmem = false;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	if (now == 0) {
		now = isc_stdtime_now();
	}

	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, sizeof(dns_slabheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(qpnode->name, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (dns_slabheader_t *)region.base;
	*newheader = (dns_slabheader_t){
		.type = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers),
		.trust = rdataset->trust,
		.last_used = now,
		.node = qpnode,
	};

	dns_slabheader_reset(newheader, db, node);
	dns__qpdb_setttl(newheader, rdataset->ttl + now);
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->serial = 1;
	if ((rdataset->attributes & DNS_RDATASETATTR_PREFETCH) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_PREFETCH);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NEGATIVE);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NXDOMAIN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NXDOMAIN);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_OPTOUT) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_OPTOUT);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NOQNAME) != 0) {
		result = addnoqname(qpdb->common.mctx, newheader, rdataset);
		if (result != ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			return (result);
		}
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_CLOSEST) != 0) {
		result = addclosest(qpdb->common.mctx, newheader, rdataset);
		if (result != ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			return (result);
		}
	}

	/*
	 * If we're adding a delegation type (which would be an NS or DNAME
	 * for a zone, but only DNAME counts for a cache), we need to set
	 * the callback bit on the node.
	 */
	if (rdataset->type == dns_rdatatype_dname) {
		delegating = true;
	}

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	if (qpnode->nsec != DNS_DB_NSEC_HAS_NSEC &&
	    rdataset->type == dns_rdatatype_nsec)
	{
		newnsec = true;
	} else {
		newnsec = false;
	}
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	/*
	 * If we're adding a delegation type, adding to the auxiliary NSEC
	 * tree, or the DB is a cache in an overmem state, hold an
	 * exclusive lock on the tree.  In the latter case the lock does
	 * not necessarily have to be acquired but it will help purge
	 * ancient entries more effectively.
	 */
	if (isc_mem_isovermem(qpdb->common.mctx)) {
		cache_is_overmem = true;
	}
	if (delegating || newnsec || cache_is_overmem) {
		TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
	}

	if (cache_is_overmem) {
		dns__qpcache_overmem(qpdb, newheader,
				     &tlocktype DNS__DB_FLARG_PASS);
	}

	NODE_WRLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	if (qpdb->rrsetstats != NULL) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->type,
				  atomic_load_acquire(&newheader->attributes),
				  true);
	}

	if (tlocktype == isc_rwlocktype_write) {
		cleanup_dead_nodes(qpdb, qpnode->locknum DNS__DB_FLARG_PASS);
	}

	expire_ttl_headers(qpdb, qpnode->locknum, &tlocktype, now,
			   cache_is_overmem DNS__DB_FLARG_PASS);

	/*
	 * If we've been holding a write lock on the tree just for
	 * cleaning, we can release it now.  However, we still need the
	 * node lock.
	 */
	if (tlocktype == isc_rwlocktype_write && !delegating && !newnsec) {
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}

	result = ISC_R_SUCCESS;
	if (newnsec) {
		dns_qpdata_t *nsecnode = NULL;

		result = dns_qp_getname(qpdb->nsec, name, (void **)&nsecnode,
					NULL);
		if (result == ISC_R_SUCCESS) {
			result = ISC_R_SUCCESS;
		} else {
			INSIST(nsecnode == NULL);
			nsecnode = dns_qpdata_create(qpdb, name);
			nsecnode->nsec = DNS_DB_NSEC_NSEC;
			result = dns_qp_insert(qpdb->nsec, nsecnode, 0);
			INSIST(result == ISC_R_SUCCESS);
			dns_qpdata_detach(&nsecnode);
		}
		qpnode->nsec = DNS_DB_NSEC_HAS_NSEC;
	}

	if (result == ISC_R_SUCCESS) {
		result = dns__qpdb_add(qpdb, qpnode, name, newheader, options,
				       false, addedrdataset,
				       now DNS__DB_FLARG_PASS);
	}
	if (result == ISC_R_SUCCESS && delegating) {
		qpnode->find_callback = 1;
	}

	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	if (tlocktype != isc_rwlocktype_none) {
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}
	INSIST(tlocktype == isc_rwlocktype_none);

	return (result);
}

isc_result_t
dns__qpdb_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
			 dns_dbversion_t *version, dns_rdatatype_t type,
			 dns_rdatatype_t covers DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;
	isc_result_t result;
	dns_slabheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	if (type == dns_rdatatype_any) {
		return (ISC_R_NOTIMPLEMENTED);
	}
	if (type == dns_rdatatype_rrsig && covers == 0) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	newheader = dns_slabheader_new(db, node);
	newheader->type = DNS_TYPEPAIR_VALUE(type, covers);
	dns__qpdb_setttl(newheader, 0);
	atomic_init(&newheader->attributes, DNS_SLABHEADERATTR_NONEXISTENT);

	NODE_WRLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);
	result = dns__qpdb_add(qpdb, qpnode, NULL, newheader, DNS_DBADD_FORCE,
			       false, NULL, 0 DNS__DB_FLARG_PASS);
	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	return (result);
}

unsigned int
dns__qpdb_nodecount(dns_db_t *db, dns_dbtree_t tree) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qp_memusage_t mu;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	switch (tree) {
	case dns_dbtree_main:
		mu = dns_qp_memusage(qpdb->tree);
		break;
	case dns_dbtree_nsec:
		mu = dns_qp_memusage(qpdb->nsec);
		break;
	case dns_dbtree_nsec3:
		mu = dns_qp_memusage(qpdb->nsec3);
		break;
	default:
		UNREACHABLE();
	}
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return (mu.leaves);
}

void
dns__qpdb_setloop(dns_db_t *db, isc_loop_t *loop) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
	}
	if (loop != NULL) {
		isc_loop_attach(loop, &qpdb->loop);
	}
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
}

isc_result_t
dns__qpdb_getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *onode = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to origin_node doesn't require a DB lock */
	onode = (dns_qpdata_t *)qpdb->origin_node;
	if (onode != NULL) {
		dns__qpdb_newref(qpdb, onode,
				 isc_rwlocktype_none DNS__DB_FLARG_PASS);
		*nodep = qpdb->origin_node;
	} else {
		result = ISC_R_NOTFOUND;
	}

	return (result);
}

void
dns__qpdb_locknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;

	RWLOCK(&qpdb->node_locks[qpnode->locknum].lock, type);
}

void
dns__qpdb_unlocknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;

	RWUNLOCK(&qpdb->node_locks[qpnode->locknum].lock, type);
}

isc_result_t
dns__qpdb_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	dns_qpdb_t *qpdb = NULL;
	isc_result_t result;
	isc_mem_t *hmctx = mctx;
	int i;

	/* This database implementation only supports cache semantics */
	REQUIRE(type == dns_dbtype_cache);

	qpdb = isc_mem_get(mctx, sizeof(*qpdb));
	*qpdb = (dns_qpdb_t){
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.current_serial = 1,
		.least_serial = 1,
		.next_serial = 2,
	};

	isc_refcount_init(&qpdb->common.references, 1);

	/*
	 * If argv[0] exists, it points to a memory context to use for heap
	 */
	if (argc != 0) {
		hmctx = (isc_mem_t *)argv[0];
	}

	qpdb->common.methods = &dns__qpdb_cachemethods;
	qpdb->common.attributes |= DNS_DBATTR_CACHE;

	isc_rwlock_init(&qpdb->lock);
	TREE_INITLOCK(&qpdb->tree_lock);

	/*
	 * Initialize node_lock_count in a generic way to support future
	 * extension which allows the user to specify this value on creation.
	 * Note that when specified for a cache DB it must be larger than 1
	 * as commented with the definition of DEFAULT_CACHE_NODE_LOCK_COUNT.
	 */
	if (qpdb->node_lock_count == 0) {
		qpdb->node_lock_count = DEFAULT_CACHE_NODE_LOCK_COUNT;
	}
	INSIST(qpdb->node_lock_count < (1 << DNS_RBT_LOCKLENGTH));
	qpdb->node_locks = isc_mem_cget(mctx, qpdb->node_lock_count,
					sizeof(db_nodelock_t));

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	dns_rdatasetstats_create(mctx, &qpdb->rrsetstats);
	qpdb->lru = isc_mem_cget(mctx, qpdb->node_lock_count,
				 sizeof(dns_slabheaderlist_t));
	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		ISC_LIST_INIT(qpdb->lru[i]);
	}

	/*
	 * Create the heaps.
	 */
	qpdb->heaps = isc_mem_cget(hmctx, qpdb->node_lock_count,
				   sizeof(isc_heap_t *));
	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		qpdb->heaps[i] = NULL;
	}

	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		isc_heap_create(hmctx, ttl_sooner, set_index, 0,
				&qpdb->heaps[i]);
	}

	/*
	 * Create deadnode lists.
	 */
	qpdb->deadnodes = isc_mem_cget(mctx, qpdb->node_lock_count,
				       sizeof(dns_qpdatalist_t));
	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		ISC_LIST_INIT(qpdb->deadnodes[i]);
	}

	qpdb->active = qpdb->node_lock_count;

	for (i = 0; i < (int)(qpdb->node_lock_count); i++) {
		NODE_INITLOCK(&qpdb->node_locks[i].lock);
		isc_refcount_init(&qpdb->node_locks[i].references, 0);
		qpdb->node_locks[i].exiting = false;
	}

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &qpdb->common.mctx);
	isc_mem_attach(hmctx, &qpdb->hmctx);

	/*
	 * Make a copy of the origin name.
	 */
	result = dns_name_dupwithoffsets(origin, mctx, &qpdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		free_qpdb(qpdb, false);
		return (result);
	}

	/*
	 * Make the qp tries.
	 */
	dns_qp_create(mctx, &qpmethods, qpdb, &qpdb->tree);
	dns_qp_create(mctx, &qpmethods, qpdb, &qpdb->nsec);
	dns_qp_create(mctx, &qpmethods, qpdb, &qpdb->nsec3);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPDB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return (ISC_R_SUCCESS);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = NULL;

	rbtiterator = (qpdb_rdatasetiter_t *)(*iteratorp);

	dns__db_detachnode(rbtiterator->common.db,
			   &rbtiterator->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(rbtiterator->common.db->mctx, rbtiterator,
		    sizeof(*rbtiterator));

	*iteratorp = NULL;
}

static bool
iterator_active(dns_qpdb_t *qpdb, qpdb_rdatasetiter_t *rbtiterator,
		dns_slabheader_t *header) {
	dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);

	/*
	 * Is this a "this rdataset doesn't exist" record?
	 */
	if (NONEXISTENT(header)) {
		return (false);
	}

	/*
	 * If this header is still active then return it.
	 */
	if (ACTIVE(header, rbtiterator->common.now)) {
		return (true);
	}

	/*
	 * If we are not returning stale records or the rdataset is
	 * too old don't return it.
	 */
	if (!STALEOK(rbtiterator) || (rbtiterator->common.now > stale_ttl)) {
		return (false);
	}
	return (true);
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	dns_qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL, *top_next = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	NODE_RDLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	for (header = qpnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (EXPIREDOK(rbtiterator)) {
				if (!NONEXISTENT(header)) {
					break;
				}
				header = header->down;
			} else if (header->serial <= 1 && !IGNORE(header)) {
				if (!iterator_active(qpdb, rbtiterator, header))
				{
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			break;
		}
	}

	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	dns_qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL, *top_next = NULL;
	dns_typepair_t type, negtype;
	dns_rdatatype_t rdtype, covers;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	bool expiredok = EXPIREDOK(rbtiterator);

	header = rbtiterator->current;
	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	NODE_RDLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	type = header->type;
	rdtype = DNS_TYPEPAIR_TYPE(header->type);
	if (NEGATIVE(header)) {
		covers = DNS_TYPEPAIR_COVERS(header->type);
		negtype = DNS_TYPEPAIR_VALUE(covers, 0);
	} else {
		negtype = DNS_TYPEPAIR_VALUE(0, rdtype);
	}

	/*
	 * Find the start of the header chain for the next type
	 * by walking back up the list.
	 */
	top_next = header->next;
	while (top_next != NULL &&
	       (top_next->type == type || top_next->type == negtype))
	{
		top_next = top_next->next;
	}
	if (expiredok) {
		/*
		 * Keep walking down the list if possible or
		 * start the next type.
		 */
		header = header->down != NULL ? header->down : top_next;
	} else {
		header = top_next;
	}
	for (; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (expiredok) {
				if (!NONEXISTENT(header)) {
					break;
				}
				header = header->down;
			} else if (header->serial <= 1 && !IGNORE(header)) {
				if (!iterator_active(qpdb, rbtiterator, header))
				{
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			break;
		}
		/*
		 * Find the start of the header chain for the next type
		 * by walking back up the list.
		 */
		while (top_next != NULL &&
		       (top_next->type == type || top_next->type == negtype))
		{
			top_next = top_next->next;
		}
	}

	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	dns_qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	header = rbtiterator->current;
	REQUIRE(header != NULL);

	NODE_RDLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);

	dns__qpdb_bindrdataset(qpdb, qpnode, header, rbtiterator->common.now,
			       isc_rwlocktype_read,
			       rdataset DNS__DB_FLARG_PASS);

	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);
}

/*
 * Database Iterator Methods
 */

static void
reference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	dns_qpdata_t *node = qpdbiter->node;

	if (node == NULL) {
		return;
	}

	INSIST(qpdbiter->tree_locked != isc_rwlocktype_none);
	reactivate_node(qpdb, node, qpdbiter->tree_locked DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	dns_qpdata_t *node = qpdbiter->node;
	isc_rwlock_t *lock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = qpdbiter->tree_locked;

	if (node == NULL) {
		return;
	}

	REQUIRE(tlocktype != isc_rwlocktype_write);

	lock = &qpdb->node_locks[node->locknum].lock;
	NODE_RDLOCK(lock, &nlocktype);
	dns__qpdb_decref(qpdb, node, 0, &nlocktype, &qpdbiter->tree_locked,
			 false, false DNS__DB_FLARG_PASS);
	NODE_UNLOCK(lock, &nlocktype);

	INSIST(qpdbiter->tree_locked == tlocktype);

	qpdbiter->node = NULL;
}

static void
resume_iteration(qpdb_dbiterator_t *qpdbiter, bool continuing) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;

	REQUIRE(qpdbiter->paused);
	REQUIRE(qpdbiter->tree_locked == isc_rwlocktype_none);

	TREE_RDLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);

	/*
	 * If we're being called from dbiterator_next or _prev,
	 * then we may need to reinitialize the iterator to the current
	 * name. The tree could have changed while it was unlocked,
	 * would make the iterator traversal inconsistent.
	 *
	 * As long as the iterator is holding a reference to
	 * qpdbiter->node, the node won't be removed from the tree,
	 * so the lookup should always succeed.
	 */
	if (continuing && qpdbiter->node != NULL) {
		isc_result_t result;
		dns_qp_t *tree = qpdb->tree;

		if (qpdbiter->current == &qpdbiter->nsec3iter) {
			tree = qpdb->nsec3;
		}
		result = dns_qp_lookup(tree, qpdbiter->name, NULL,
				       qpdbiter->current, NULL, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
	}

	qpdbiter->paused = false;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)(*iteratorp);
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	dns_db_t *db = NULL;

	if (qpdbiter->tree_locked == isc_rwlocktype_read) {
		TREE_UNLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);
	}
	INSIST(qpdbiter->tree_locked == isc_rwlocktype_none);

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_db_attach(qpdbiter->common.db, &db);
	dns_db_detach(&qpdbiter->common.db);

	isc_mem_put(db->mctx, qpdbiter, sizeof(*qpdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdb->nsec3, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
			/* If we're in the NSEC3 tree, skip the origin */
			if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
				result = dns_qpiter_next(
					qpdbiter->current, qpdbiter->name,
					(void **)&qpdbiter->node, NULL);
			}
		}
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->iter;
		dns_qpiter_init(qpdb->tree, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		break;
	case full:
		qpdbiter->current = &qpdbiter->iter;
		dns_qpiter_init(qpdb->tree, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		if (result == ISC_R_NOMORE) {
			qpdbiter->current = &qpdbiter->nsec3iter;
			dns_qpiter_init(qpdb->nsec3, qpdbiter->current);
			result = dns_qpiter_next(
				qpdbiter->current, qpdbiter->name,
				(void **)&qpdbiter->node, NULL);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		qpdbiter->new_origin = true;
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE); /* The tree is empty. */
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	if (result != ISC_R_SUCCESS) {
		ENSURE(!qpdbiter->paused);
	}

	return (result);
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdb->nsec3, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		if ((result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			/*
			 * NSEC3 tree only has an origin node.
			 */
			qpdbiter->node = NULL;
			result = ISC_R_NOMORE;
		}
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->iter;
		dns_qpiter_init(qpdb->tree, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		break;
	case full:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdb->nsec3, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
		if ((result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			/*
			 * NSEC3 tree only has an origin node.
			 */
			qpdbiter->node = NULL;
			result = ISC_R_NOMORE;
		}
		if (result == ISC_R_NOMORE) {
			qpdbiter->current = &qpdbiter->iter;
			dns_qpiter_init(qpdb->tree, qpdbiter->current);
			result = dns_qpiter_prev(
				qpdbiter->current, qpdbiter->name,
				(void **)&qpdbiter->node, NULL);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		qpdbiter->new_origin = true;
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE); /* The tree is empty. */
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result, tresult;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3iter;
		result = dns_qp_lookup(qpdb->nsec3, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->iter;
		result = dns_qp_lookup(qpdb->tree, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case full:
		/*
		 * Stay on main chain if not found on
		 * either iterator.
		 */
		qpdbiter->current = &qpdbiter->iter;
		result = dns_qp_lookup(qpdb->tree, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		if (result == DNS_R_PARTIALMATCH) {
			dns_qpdata_t *node = NULL;
			tresult = dns_qp_lookup(qpdb->nsec3, name, NULL,
						&qpdbiter->nsec3iter, NULL,
						(void **)&node, NULL);
			if (tresult == ISC_R_SUCCESS) {
				qpdbiter->node = node;
				qpdbiter->current = &qpdbiter->nsec3iter;
				result = tresult;
			}
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		qpdbiter->new_origin = true;
		dns_name_copy(qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							  : result;

	return (result);
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, true);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_prev(qpdbiter->current, qpdbiter->name,
				 (void **)&qpdbiter->node, NULL);

	if (qpdbiter->current == &qpdbiter->nsec3iter) {
		if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
			/*
			 * If we're in the NSEC3 tree, it's empty or
			 * we've reached the origin, then we're done
			 * with it.
			 */
			if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			}
		}
		if (result == ISC_R_NOMORE && qpdbiter->nsec3mode == full) {
			qpdbiter->current = &qpdbiter->iter;
			dns_qpiter_init(qpdb->tree, qpdbiter->current);
			result = dns_qpiter_prev(
				qpdbiter->current, qpdbiter->name,
				(void **)&qpdbiter->node, NULL);
		}
	}

	qpdbiter->new_origin = (result == DNS_R_NEWORIGIN);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, true);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_next(qpdbiter->current, qpdbiter->name,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_NOMORE && qpdbiter->nsec3mode == full &&
	    qpdbiter->current == &qpdbiter->iter)
	{
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdb->nsec3, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, qpdbiter->name,
					 (void **)&qpdbiter->node, NULL);
	}

	if (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		/*
		 * If we've just started the NSEC3 tree,
		 * skip over the origin.
		 */
		if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
			switch (qpdbiter->nsec3mode) {
			case nsec3only:
			case full:
				result = dns_qpiter_next(
					qpdbiter->current, qpdbiter->name,
					(void **)&qpdbiter->node, NULL);
				break;
			case nonsec3:
				result = ISC_R_NOMORE;
				qpdbiter->node = NULL;
				break;
			default:
				UNREACHABLE();
			}
		}
	}

	qpdbiter->new_origin = (result == DNS_R_NEWORIGIN);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdata_t *node = qpdbiter->node;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	if (name != NULL) {
		dns_name_copy(qpdbiter->node->name, name);

		if (qpdbiter->common.relative_names && qpdbiter->new_origin) {
			result = DNS_R_NEWORIGIN;
		}
	} else {
		result = ISC_R_SUCCESS;
	}

	dns__qpdb_newref(qpdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*nodep = qpdbiter->node;

	return (result);
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		return (ISC_R_SUCCESS);
	}

	qpdbiter->paused = true;

	if (qpdbiter->tree_locked == isc_rwlocktype_read) {
		TREE_UNLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);
	}
	INSIST(qpdbiter->tree_locked == isc_rwlocktype_none);

	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_name_t *origin = dns_fixedname_name(&qpdbiter->origin);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	dns_name_copy(origin, name);
	return (ISC_R_SUCCESS);
}

void
dns__qpdb_deletedata(dns_db_t *db ISC_ATTR_UNUSED,
		     dns_dbnode_t *node ISC_ATTR_UNUSED, void *data) {
	dns_slabheader_t *header = data;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

	if (header->heap != NULL && header->heap_index != 0) {
		isc_heap_delete(header->heap, header->heap_index);
	}

	update_rrsetstats(qpdb->rrsetstats, header->type,
			  atomic_load_acquire(&header->attributes), false);

	if (ISC_LINK_LINKED(header, link)) {
		int idx = QPDB_HEADERNODE(header)->locknum;
		ISC_LIST_UNLINK(qpdb->lru[idx], header, link);
	}

	if (header->noqname != NULL) {
		dns_slabheader_freeproof(db->mctx, &header->noqname);
	}
	if (header->closest != NULL) {
		dns_slabheader_freeproof(db->mctx, &header->closest);
	}
}

/*
 * Caller must be holding the node write lock.
 */
static void
expire_ttl_headers(dns_qpdb_t *qpdb, unsigned int locknum,
		   isc_rwlocktype_t *tlocktypep, isc_stdtime_t now,
		   bool cache_is_overmem DNS__DB_FLARG) {
	isc_heap_t *heap = qpdb->heaps[locknum];

	for (size_t i = 0; i < DNS_QPDB_EXPIRE_TTL_COUNT; i++) {
		dns_slabheader_t *header = isc_heap_element(heap, 1);

		if (header == NULL) {
			/* No headers left on this TTL heap; exit cleaning */
			return;
		}

		dns_ttl_t ttl = header->ttl;

		if (!cache_is_overmem) {
			/* Only account for stale TTL if cache is not overmem */
			ttl += STALE_TTL(header, qpdb);
		}

		if (ttl >= now - QPDB_VIRTUAL) {
			/*
			 * The header at the top of this TTL heap is not yet
			 * eligible for expiry, so none of the other headers on
			 * the same heap can be eligible for expiry, either;
			 * exit cleaning.
			 */
			return;
		}

		dns__qpcache_expireheader(header, tlocktypep,
					  dns_expire_ttl DNS__DB_FLARG_PASS);
	}
}

dns_qpdata_t *
dns_qpdata_create(dns_qpdb_t *qpdb, const dns_name_t *name) {
	dns_qpdata_t *newdata = isc_mem_get(qpdb->common.mctx,
					    sizeof(*newdata));
	*newdata = (dns_qpdata_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};
	newdata->hashval = dns_name_hash(name);
	newdata->locknum = newdata->hashval % qpdb->node_lock_count;
	newdata->name = dns_fixedname_initname(&newdata->fn);
	dns_name_copy(name, newdata->name);
	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);

	ISC_LINK_INIT(newdata, deadlink);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "dns_qpdata_create:%s:%s:%d:%p->references = 1\n",
		__func__, __FILE__, __LINE__ + 1, name);
#endif
	return (newdata);
}

void
dns_qpdata_destroy(dns_qpdata_t *data) {
	dns_slabheader_t *current = NULL, *next = NULL;

	for (current = data->data; current != NULL; current = next) {
		dns_slabheader_t *down = current->down, *down_next = NULL;

		next = current->next;

		for (down = current->down; down != NULL; down = down_next) {
			down_next = down->down;
			dns_slabheader_destroy(&down);
		}

		dns_slabheader_destroy(&current);
	}

	isc_mem_putanddetach(&data->mctx, data, sizeof(dns_qpdata_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_TRACE_IMPL(dns_qpdata, dns_qpdata_destroy);
#else
ISC_REFCOUNT_IMPL(dns_qpdata, dns_qpdata_destroy);
#endif
