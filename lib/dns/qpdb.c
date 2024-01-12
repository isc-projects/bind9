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
#include <dns/zone.h>
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
#define RESIGN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_RESIGN) != 0)
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

#define QPDBITER_NSEC3_ORIGIN_NODE(qpdb, iterator)         \
	((iterator)->current == &(iterator)->nsec3chain && \
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
prune_tree(void *arg);
static void
free_gluetable(dns_qpdb_version_t *version);

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
 * "regular" RBT ("chain" field) and the root node of the NSEC3 RBT
 * ("nsec3chain" field) of the database in question, as if the latter was a
 * successor to the former in lexical order.  The "current" field always holds
 * the address of either "chain" or "nsec3chain", depending on which RBT is
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
	dns_fixedname_t name;
	dns_fixedname_t origin;
	dns_rbtnodechain_t chain;
	dns_rbtnodechain_t nsec3chain;
	dns_rbtnodechain_t *current;
	dns_rbtnode_t *node;
	enum { full, nonsec3, nsec3only } nsec3mode;
} qpdb_dbiterator_t;

static void
free_qpdb(dns_qpdb_t *qpdb, bool log);
static void
setnsec3parameters(dns_db_t *db, dns_qpdb_version_t *version);

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
 * Deleting Nodes
 *
 * For zone databases the node for the origin of the zone MUST NOT be deleted.
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
 * Return which RRset should be resigned sooner.  If the RRsets have the
 * same signing time, prefer the other RRset over the SOA RRset.
 */
static bool
resign_sooner(void *v1, void *v2) {
	dns_slabheader_t *h1 = v1;
	dns_slabheader_t *h2 = v2;

	return (h1->resign < h2->resign ||
		(h1->resign == h2->resign && h1->resign_lsb < h2->resign_lsb) ||
		(h1->resign == h2->resign && h1->resign_lsb == h2->resign_lsb &&
		 h2->type == DNS_SIGTYPE(dns_rdatatype_soa)));
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

	REQUIRE(qpdb->current_version != NULL || EMPTY(qpdb->open_versions));
	REQUIRE(qpdb->future_version == NULL);

	if (qpdb->current_version != NULL) {
		isc_refcount_decrementz(&qpdb->current_version->references);

		isc_refcount_destroy(&qpdb->current_version->references);
		UNLINK(qpdb->open_versions, qpdb->current_version, link);
		cds_wfs_destroy(&qpdb->current_version->glue_stack);
		isc_rwlock_destroy(&qpdb->current_version->rwlock);
		isc_mem_put(qpdb->common.mctx, qpdb->current_version,
			    sizeof(*qpdb->current_version));
	}

	/*
	 * We assume the number of remaining dead nodes is reasonably small;
	 * the overhead of unlinking all nodes here should be negligible.
	 */
	for (i = 0; i < qpdb->node_lock_count; i++) {
		dns_rbtnode_t *node = NULL;

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
			     qpdb->node_lock_count, sizeof(dns_rbtnodelist_t));
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

	/* XXX check for open versions here */

	if (qpdb->soanode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->soanode);
	}
	if (qpdb->nsnode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->nsnode);
	}

	/*
	 * The current version's glue table needs to be freed early
	 * so the nodes are dereferenced before we check the active
	 * node count below.
	 */
	if (qpdb->current_version != NULL) {
		free_gluetable(qpdb->current_version);
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
dns__qpdb_currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdb_version_t *version = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	version = qpdb->current_version;
	isc_refcount_increment(&version->references);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	*versionp = (dns_dbversion_t *)version;
}

static dns_qpdb_version_t *
allocate_version(isc_mem_t *mctx, uint32_t serial, unsigned int references,
		 bool writer) {
	dns_qpdb_version_t *version = isc_mem_get(mctx, sizeof(*version));
	*version = (dns_qpdb_version_t){
		.serial = serial,
		.writer = writer,
		.changed_list = ISC_LIST_INITIALIZER,
		.resigned_list = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
	};

	cds_wfs_init(&version->glue_stack);

	isc_refcount_init(&version->references, references);

	return (version);
}

isc_result_t
dns__qpdb_newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdb_version_t *version = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(versionp != NULL && *versionp == NULL);
	REQUIRE(qpdb->future_version == NULL);

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	RUNTIME_CHECK(qpdb->next_serial != 0); /* XXX Error? */
	version = allocate_version(qpdb->common.mctx, qpdb->next_serial, 1,
				   true);
	version->qpdb = qpdb;
	version->commit_ok = true;
	version->secure = qpdb->current_version->secure;
	version->havensec3 = qpdb->current_version->havensec3;
	if (version->havensec3) {
		version->flags = qpdb->current_version->flags;
		version->iterations = qpdb->current_version->iterations;
		version->hash = qpdb->current_version->hash;
		version->salt_length = qpdb->current_version->salt_length;
		memmove(version->salt, qpdb->current_version->salt,
			version->salt_length);
	} else {
		version->flags = 0;
		version->iterations = 0;
		version->hash = 0;
		version->salt_length = 0;
		memset(version->salt, 0, sizeof(version->salt));
	}
	isc_rwlock_init(&version->rwlock);
	RWLOCK(&qpdb->current_version->rwlock, isc_rwlocktype_read);
	version->records = qpdb->current_version->records;
	version->xfrsize = qpdb->current_version->xfrsize;
	RWUNLOCK(&qpdb->current_version->rwlock, isc_rwlocktype_read);
	qpdb->next_serial++;
	qpdb->future_version = version;
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	*versionp = version;

	return (ISC_R_SUCCESS);
}

void
dns__qpdb_attachversion(dns_db_t *db, dns_dbversion_t *source,
			dns_dbversion_t **targetp) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdb_version_t *rbtversion = source;

	REQUIRE(VALID_QPDB(qpdb));
	INSIST(rbtversion != NULL && rbtversion->qpdb == qpdb);

	isc_refcount_increment(&rbtversion->references);

	*targetp = rbtversion;
}

static qpdb_changed_t *
add_changed(dns_slabheader_t *header,
	    dns_qpdb_version_t *version DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

	/*
	 * Caller must be holding the node lock if its reference must be
	 * protected by the lock.
	 */

	changed = isc_mem_get(qpdb->common.mctx, sizeof(*changed));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);

	REQUIRE(version->writer);

	if (changed != NULL) {
		dns_rbtnode_t *node = (dns_rbtnode_t *)header->node;
		uint_fast32_t refs = isc_refcount_increment(&node->references);
#if DNS_DB_NODETRACE
		fprintf(stderr,
			"incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
			func, file, line, node, refs + 1);
#else
		UNUSED(refs);
#endif
		changed->node = node;
		changed->dirty = false;
		ISC_LIST_INITANDAPPEND(version->changed_list, changed, link);
	} else {
		version->commit_ok = false;
	}

	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	return (changed);
}

static void
rollback_node(dns_rbtnode_t *node, uint32_t serial) {
	dns_slabheader_t *header = NULL, *dcurrent = NULL;
	bool make_dirty = false;

	/*
	 * Caller must hold the node lock.
	 */

	/*
	 * We set the IGNORE attribute on rdatasets with serial number
	 * 'serial'.  When the reference count goes to zero, these rdatasets
	 * will be cleaned up; until that time, they will be ignored.
	 */
	for (header = node->data; header != NULL; header = header->next) {
		if (header->serial == serial) {
			DNS_SLABHEADER_SETATTR(header,
					       DNS_SLABHEADERATTR_IGNORE);
			make_dirty = true;
		}
		for (dcurrent = header->down; dcurrent != NULL;
		     dcurrent = dcurrent->down)
		{
			if (dcurrent->serial == serial) {
				DNS_SLABHEADER_SETATTR(
					dcurrent, DNS_SLABHEADERATTR_IGNORE);
				make_dirty = true;
			}
		}
	}
	if (make_dirty) {
		node->dirty = 1;
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
clean_cache_node(dns_qpdb_t *qpdb, dns_rbtnode_t *node) {
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

static void
clean_zone_node(dns_rbtnode_t *node, uint32_t least_serial) {
	dns_slabheader_t *current = NULL, *dcurrent = NULL;
	dns_slabheader_t *down_next = NULL, *dparent = NULL;
	dns_slabheader_t *top_prev = NULL, *top_next = NULL;
	bool still_dirty = false;

	/*
	 * Caller must be holding the node lock.
	 */
	REQUIRE(least_serial != 0);

	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;

		/*
		 * First, we clean up any instances of multiple rdatasets
		 * with the same serial number, or that have the IGNORE
		 * attribute.
		 */
		dparent = current;
		for (dcurrent = current->down; dcurrent != NULL;
		     dcurrent = down_next)
		{
			down_next = dcurrent->down;
			INSIST(dcurrent->serial <= dparent->serial);
			if (dcurrent->serial == dparent->serial ||
			    IGNORE(dcurrent))
			{
				if (down_next != NULL) {
					down_next->next = dparent;
				}
				dparent->down = down_next;
				dns_slabheader_destroy(&dcurrent);
			} else {
				dparent = dcurrent;
			}
		}

		/*
		 * We've now eliminated all IGNORE datasets with the possible
		 * exception of current, which we now check.
		 */
		if (IGNORE(current)) {
			down_next = current->down;
			if (down_next == NULL) {
				if (top_prev != NULL) {
					top_prev->next = current->next;
				} else {
					node->data = current->next;
				}
				dns_slabheader_destroy(&current);
				/*
				 * current no longer exists, so we can
				 * just continue with the loop.
				 */
				continue;
			} else {
				/*
				 * Pull up current->down, making it the new
				 * current.
				 */
				if (top_prev != NULL) {
					top_prev->next = down_next;
				} else {
					node->data = down_next;
				}
				down_next->next = top_next;
				dns_slabheader_destroy(&current);
				current = down_next;
			}
		}

		/*
		 * We now try to find the first down node less than the
		 * least serial.
		 */
		dparent = current;
		for (dcurrent = current->down; dcurrent != NULL;
		     dcurrent = down_next)
		{
			down_next = dcurrent->down;
			if (dcurrent->serial < least_serial) {
				break;
			}
			dparent = dcurrent;
		}

		/*
		 * If there is a such an rdataset, delete it and any older
		 * versions.
		 */
		if (dcurrent != NULL) {
			do {
				down_next = dcurrent->down;
				INSIST(dcurrent->serial <= least_serial);
				dns_slabheader_destroy(&dcurrent);
				dcurrent = down_next;
			} while (dcurrent != NULL);
			dparent->down = NULL;
		}

		/*
		 * Note.  The serial number of 'current' might be less than
		 * least_serial too, but we cannot delete it because it is
		 * the most recent version, unless it is a NONEXISTENT
		 * rdataset.
		 */
		if (current->down != NULL) {
			still_dirty = true;
			top_prev = current;
		} else {
			/*
			 * If this is a NONEXISTENT rdataset, we can delete it.
			 */
			if (NONEXISTENT(current)) {
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
	}
	if (!still_dirty) {
		node->dirty = 0;
	}
}

/*
 * tree_lock(write) must be held.
 */
static void
delete_node(dns_qpdb_t *qpdb, dns_rbtnode_t *node) {
	dns_name_t *name = NULL;
	isc_result_t result = ISC_R_UNEXPECTED;

	INSIST(!ISC_LINK_LINKED(node, deadlink));

	if (isc_log_wouldlog(dns_lctx, ISC_LOG_DEBUG(1))) {
		char printname[DNS_NAME_FORMATSIZE];
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "delete_node(): %p %s (bucket %d)", node,
			      dns_rbt_formatnodename(node, printname,
						     sizeof(printname)),
			      node->locknum);
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
dns__qpdb_newref(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
		 isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	uint_fast32_t refs;

	if (nlocktype == isc_rwlocktype_write &&
	    ISC_LINK_LINKED(node, deadlink))
	{
		ISC_LIST_UNLINK(qpdb->deadnodes[node->locknum], node, deadlink);
	}

	refs = isc_refcount_increment0(&node->references);
#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	if (refs == 0) {
		/* this is the first reference to the node */
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
 * The tree lock must be held for the result to be valid.
 */
static bool
is_leaf(dns_rbtnode_t *node) {
	return (node->parent != NULL && node->parent->down == node &&
		node->left == NULL && node->right == NULL);
}

static void
send_to_prune_tree(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
		   isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	qpdb_prune_t *prune = isc_mem_get(qpdb->common.mctx, sizeof(*prune));
	*prune = (qpdb_prune_t){ .node = node };

	dns_db_attach((dns_db_t *)qpdb, &prune->db);
	dns__qpdb_newref(qpdb, node, nlocktype DNS__DB_FLARG_PASS);

	isc_async_run(qpdb->loop, prune_tree, prune);
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
	dns_rbtnode_t *node = NULL;
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

		if (is_leaf(node) && qpdb->loop != NULL) {
			send_to_prune_tree(
				qpdb, node,
				isc_rwlocktype_write DNS__DB_FLARG_PASS);
		} else if (node->down == NULL && node->data == NULL) {
			/*
			 * Not a interior node and not needing to be
			 * reactivated.
			 */
			delete_node(qpdb, node);
		} else if (node->data == NULL) {
			/*
			 * A interior node without data. Leave linked to
			 * to be cleaned up when node->down becomes NULL.
			 */
			ISC_LIST_APPEND(qpdb->deadnodes[bucketnum], node,
					deadlink);
		}
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
reactivate_node(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
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
 * This function returns true if and only if the node reference decreases
 * to zero.
 *
 * NOTE: Decrementing the reference count of a node to zero does not mean it
 * will be immediately freed.
 */
bool
dns__qpdb_decref(dns_qpdb_t *qpdb, dns_rbtnode_t *node, uint32_t least_serial,
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

	nodelock = &qpdb->node_locks[bucket];

#define KEEP_NODE(n, r, l)                                  \
	((n)->data != NULL || ((l) && (n)->down != NULL) || \
	 (n) == (r)->origin_node || (n) == (r)->nsec3_origin_node)

	/* Handle easy and typical case first. */
	if (!node->dirty && KEEP_NODE(node, qpdb, locked)) {
		refs = isc_refcount_decrement(&node->references);
#if DNS_DB_NODETRACE
		fprintf(stderr,
			"decr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
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
			return (true);
		} else {
			return (false);
		}
	}

	/* Upgrade the lock? */
	if (*nlocktypep == isc_rwlocktype_read) {
		NODE_FORCEUPGRADE(&nodelock->lock, nlocktypep);
	}

	refs = isc_refcount_decrement(&node->references);
#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#else
	UNUSED(refs);
#endif
	if (refs > 1) {
		return (false);
	}

	if (node->dirty) {
		if (IS_CACHE(qpdb)) {
			clean_cache_node(qpdb, node);
		} else {
			if (least_serial == 0) {
				/*
				 * Caller doesn't know the least serial.
				 * Get it.
				 */
				RWLOCK(&qpdb->lock, isc_rwlocktype_read);
				least_serial = qpdb->least_serial;
				RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);
			}
			clean_zone_node(node, least_serial);
		}
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

	if (KEEP_NODE(node, qpdb, (locked || write_locked))) {
		goto restore_locks;
	}

#undef KEEP_NODE

	if (write_locked) {
		/*
		 * If this node is the only one in the level it's in, deleting
		 * this node may recursively make its parent the only node in
		 * the parent level; if so, and if no one is currently using
		 * the parent node, this is almost the only opportunity to
		 * clean it up.  But the recursive cleanup is not that trivial
		 * since the child and parent may be in different lock buckets,
		 * which would cause a lock order reversal problem.  To avoid
		 * the trouble, we'll dispatch a separate event for batch
		 * cleaning.  We need to check whether we're deleting the node
		 * as a result of pruning to avoid infinite dispatching.
		 * Note: pruning happens only when a loop has been set for the
		 * qpdb.  If the user of the qpdb chooses not to set a loop,
		 * it's their responsibility to purge stale leaves (e.g. by
		 * periodic walk-through).
		 */

		if (!pruning && is_leaf(node) && qpdb->loop != NULL) {
			send_to_prune_tree(qpdb, node,
					   *nlocktypep DNS__DB_FLARG_PASS);
			no_reference = false;
		} else {
			/*  We can now delete the node. */

			delete_node(qpdb, node);
		}
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

	return (no_reference);
}

/*
 * Prune the tree by cleaning up single leaves.  A single execution of this
 * function cleans up a single node; if the parent of the latter becomes a
 * single leaf on its own level as a result, the parent is then also sent to
 * this function.
 */
static void
prune_tree(void *arg) {
	qpdb_prune_t *prune = (qpdb_prune_t *)arg;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)prune->db;
	dns_rbtnode_t *node = prune->node;
	dns_rbtnode_t *parent = NULL;
	unsigned int locknum = node->locknum;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	isc_mem_put(qpdb->common.mctx, prune, sizeof(*prune));

	TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);

	parent = node->parent;

	NODE_WRLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);
	dns__qpdb_decref(qpdb, node, 0, &nlocktype, &tlocktype, true,
			 true DNS__DB_FILELINE);
	NODE_UNLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);

	if (parent != NULL && is_leaf(parent)) {
		NODE_WRLOCK(&qpdb->node_locks[parent->locknum].lock,
			    &nlocktype);
		send_to_prune_tree(qpdb, parent, nlocktype);
		NODE_UNLOCK(&qpdb->node_locks[parent->locknum].lock,
			    &nlocktype);
	}

	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	dns_db_detach((dns_db_t **)&qpdb);
}

static void
make_least_version(dns_qpdb_t *qpdb, dns_qpdb_version_t *version,
		   qpdb_changedlist_t *cleanup_list) {
	/*
	 * Caller must be holding the database lock.
	 */

	qpdb->least_serial = version->serial;
	*cleanup_list = version->changed_list;
	ISC_LIST_INIT(version->changed_list);
}

static void
cleanup_nondirty(dns_qpdb_version_t *version,
		 qpdb_changedlist_t *cleanup_list) {
	qpdb_changed_t *changed = NULL, *next_changed = NULL;

	/*
	 * If the changed record is dirty, then
	 * an update created multiple versions of
	 * a given rdataset.  We keep this list
	 * until we're the least open version, at
	 * which point it's safe to get rid of any
	 * older versions.
	 *
	 * If the changed record isn't dirty, then
	 * we don't need it anymore since we're
	 * committing and not rolling back.
	 *
	 * The caller must be holding the database lock.
	 */
	for (changed = HEAD(version->changed_list); changed != NULL;
	     changed = next_changed)
	{
		next_changed = NEXT(changed, link);
		if (!changed->dirty) {
			UNLINK(version->changed_list, changed, link);
			APPEND(*cleanup_list, changed, link);
		}
	}
}

void
dns__qpdb_setsecure(dns_db_t *db, dns_qpdb_version_t *version,
		    dns_dbnode_t *origin) {
	dns_rdataset_t keyset;
	dns_rdataset_t nsecset, signsecset;
	bool haszonekey = false;
	bool hasnsec = false;
	isc_result_t result;

	dns_rdataset_init(&keyset);
	result = dns_db_findrdataset(db, origin, version, dns_rdatatype_dnskey,
				     0, 0, &keyset, NULL);
	if (result == ISC_R_SUCCESS) {
		result = dns_rdataset_first(&keyset);
		while (result == ISC_R_SUCCESS) {
			dns_rdata_t keyrdata = DNS_RDATA_INIT;
			dns_rdataset_current(&keyset, &keyrdata);
			if (dns_zonekey_iszonekey(&keyrdata)) {
				haszonekey = true;
				break;
			}
			result = dns_rdataset_next(&keyset);
		}
		dns_rdataset_disassociate(&keyset);
	}
	if (!haszonekey) {
		version->secure = false;
		version->havensec3 = false;
		return;
	}

	dns_rdataset_init(&nsecset);
	dns_rdataset_init(&signsecset);
	result = dns_db_findrdataset(db, origin, version, dns_rdatatype_nsec, 0,
				     0, &nsecset, &signsecset);
	if (result == ISC_R_SUCCESS) {
		if (dns_rdataset_isassociated(&signsecset)) {
			hasnsec = true;
			dns_rdataset_disassociate(&signsecset);
		}
		dns_rdataset_disassociate(&nsecset);
	}

	setnsec3parameters(db, version);

	/*
	 * Do we have a valid NSEC/NSEC3 chain?
	 */
	if (version->havensec3 || hasnsec) {
		version->secure = true;
	} else {
		version->secure = false;
	}
}

/*%<
 * Walk the origin node looking for NSEC3PARAM records.
 * Cache the nsec3 parameters.
 */
static void
setnsec3parameters(dns_db_t *db, dns_qpdb_version_t *version) {
	dns_rbtnode_t *node = NULL;
	dns_rdata_nsec3param_t nsec3param;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_region_t region;
	isc_result_t result;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	unsigned char *raw; /* RDATASLAB */
	unsigned int count, length;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	version->havensec3 = false;
	node = qpdb->origin_node;
	NODE_RDLOCK(&(qpdb->node_locks[node->locknum].lock), &nlocktype);
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		do {
			if (header->serial <= version->serial &&
			    !IGNORE(header))
			{
				if (NONEXISTENT(header)) {
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);

		if (header != NULL &&
		    (header->type == dns_rdatatype_nsec3param))
		{
			/*
			 * Find A NSEC3PARAM with a supported algorithm.
			 */
			raw = dns_slabheader_raw(header);
			count = raw[0] * 256 + raw[1]; /* count */
			raw += DNS_RDATASET_COUNT + DNS_RDATASET_LENGTH;
			while (count-- > 0U) {
				length = raw[0] * 256 + raw[1];
				raw += DNS_RDATASET_ORDER + DNS_RDATASET_LENGTH;
				region.base = raw;
				region.length = length;
				raw += length;
				dns_rdata_fromregion(
					&rdata, qpdb->common.rdclass,
					dns_rdatatype_nsec3param, &region);
				result = dns_rdata_tostruct(&rdata, &nsec3param,
							    NULL);
				INSIST(result == ISC_R_SUCCESS);
				dns_rdata_reset(&rdata);

				if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG &&
				    !dns_nsec3_supportedhash(nsec3param.hash))
				{
					continue;
				}

				if (nsec3param.flags != 0) {
					continue;
				}

				memmove(version->salt, nsec3param.salt,
					nsec3param.salt_length);
				version->hash = nsec3param.hash;
				version->salt_length = nsec3param.salt_length;
				version->iterations = nsec3param.iterations;
				version->flags = nsec3param.flags;
				version->havensec3 = true;
				/*
				 * Look for a better algorithm than the
				 * unknown test algorithm.
				 */
				if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG) {
					goto unlock;
				}
			}
		}
	}
unlock:
	NODE_UNLOCK(&(qpdb->node_locks[node->locknum].lock), &nlocktype);
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
}

static void
cleanup_dead_nodes_callback(void *arg) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)arg;
	bool again = false;
	unsigned int locknum;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
	for (locknum = 0; locknum < qpdb->node_lock_count; locknum++) {
		NODE_WRLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);
		cleanup_dead_nodes(qpdb, locknum DNS__DB_FILELINE);
		if (ISC_LIST_HEAD(qpdb->deadnodes[locknum]) != NULL) {
			again = true;
		}
		NODE_UNLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);
	}
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	if (again) {
		isc_async_run(qpdb->loop, cleanup_dead_nodes_callback, qpdb);
	} else {
		dns_db_detach((dns_db_t **)&qpdb);
	}
}

void
dns__qpdb_closeversion(dns_db_t *db, dns_dbversion_t **versionp,
		       bool commit DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdb_version_t *version = NULL, *cleanup_version = NULL;
	dns_qpdb_version_t *least_greater = NULL;
	bool rollback = false;
	qpdb_changedlist_t cleanup_list;
	dns_slabheaderlist_t resigned_list;
	qpdb_changed_t *changed = NULL, *next_changed = NULL;
	uint32_t serial, least_serial;
	dns_rbtnode_t *rbtnode = NULL;
	dns_slabheader_t *header = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	version = (dns_qpdb_version_t *)*versionp;
	INSIST(version->qpdb == qpdb);

	ISC_LIST_INIT(cleanup_list);
	ISC_LIST_INIT(resigned_list);

	if (isc_refcount_decrement(&version->references) > 1) {
		/* typical and easy case first */
		if (commit) {
			RWLOCK(&qpdb->lock, isc_rwlocktype_read);
			INSIST(!version->writer);
			RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);
		}
		goto end;
	}

	/*
	 * Update the zone's secure status in version before making
	 * it the current version.
	 */
	if (version->writer && commit && !IS_CACHE(qpdb)) {
		dns__qpdb_setsecure(db, version, qpdb->origin_node);
	}

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	serial = version->serial;
	if (version->writer) {
		if (commit) {
			unsigned int cur_ref;
			dns_qpdb_version_t *cur_version = NULL;

			INSIST(version->commit_ok);
			INSIST(version == qpdb->future_version);
			/*
			 * The current version is going to be replaced.
			 * Release the (likely last) reference to it from the
			 * DB itself and unlink it from the open list.
			 */
			cur_version = qpdb->current_version;
			cur_ref = isc_refcount_decrement(
				&cur_version->references);
			if (cur_ref == 1) {
				(void)isc_refcount_current(
					&cur_version->references);
				if (cur_version->serial == qpdb->least_serial) {
					INSIST(EMPTY(
						cur_version->changed_list));
				}
				UNLINK(qpdb->open_versions, cur_version, link);
			}
			if (EMPTY(qpdb->open_versions)) {
				/*
				 * We're going to become the least open
				 * version.
				 */
				make_least_version(qpdb, version,
						   &cleanup_list);
			} else {
				/*
				 * Some other open version is the
				 * least version.  We can't cleanup
				 * records that were changed in this
				 * version because the older versions
				 * may still be in use by an open
				 * version.
				 *
				 * We can, however, discard the
				 * changed records for things that
				 * we've added that didn't exist in
				 * prior versions.
				 */
				cleanup_nondirty(version, &cleanup_list);
			}
			/*
			 * If the (soon to be former) current version
			 * isn't being used by anyone, we can clean
			 * it up.
			 */
			if (cur_ref == 1) {
				cleanup_version = cur_version;
				APPENDLIST(version->changed_list,
					   cleanup_version->changed_list, link);
			}
			/*
			 * Become the current version.
			 */
			version->writer = false;
			qpdb->current_version = version;
			qpdb->current_serial = version->serial;
			qpdb->future_version = NULL;

			/*
			 * Keep the current version in the open list, and
			 * gain a reference for the DB itself (see the DB
			 * creation function below).  This must be the only
			 * case where we need to increment the counter from
			 * zero and need to use isc_refcount_increment0().
			 */
			INSIST(isc_refcount_increment0(&version->references) ==
			       0);
			PREPEND(qpdb->open_versions, qpdb->current_version,
				link);
			resigned_list = version->resigned_list;
			ISC_LIST_INIT(version->resigned_list);
		} else {
			/*
			 * We're rolling back this transaction.
			 */
			cleanup_list = version->changed_list;
			ISC_LIST_INIT(version->changed_list);
			resigned_list = version->resigned_list;
			ISC_LIST_INIT(version->resigned_list);
			rollback = true;
			cleanup_version = version;
			qpdb->future_version = NULL;
		}
	} else {
		if (version != qpdb->current_version) {
			/*
			 * There are no external or internal references
			 * to this version and it can be cleaned up.
			 */
			cleanup_version = version;

			/*
			 * Find the version with the least serial
			 * number greater than ours.
			 */
			least_greater = PREV(version, link);
			if (least_greater == NULL) {
				least_greater = qpdb->current_version;
			}

			INSIST(version->serial < least_greater->serial);
			/*
			 * Is this the least open version?
			 */
			if (version->serial == qpdb->least_serial) {
				/*
				 * Yes.  Install the new least open
				 * version.
				 */
				make_least_version(qpdb, least_greater,
						   &cleanup_list);
			} else {
				/*
				 * Add any unexecuted cleanups to
				 * those of the least greater version.
				 */
				APPENDLIST(least_greater->changed_list,
					   version->changed_list, link);
			}
		} else if (version->serial == qpdb->least_serial) {
			INSIST(EMPTY(version->changed_list));
		}
		UNLINK(qpdb->open_versions, version, link);
	}
	least_serial = qpdb->least_serial;
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	if (cleanup_version != NULL) {
		isc_refcount_destroy(&cleanup_version->references);
		INSIST(EMPTY(cleanup_version->changed_list));
		free_gluetable(cleanup_version);
		cds_wfs_destroy(&cleanup_version->glue_stack);
		isc_rwlock_destroy(&cleanup_version->rwlock);
		isc_mem_put(qpdb->common.mctx, cleanup_version,
			    sizeof(*cleanup_version));
	}

	/*
	 * Commit/rollback re-signed headers.
	 */
	for (header = HEAD(resigned_list); header != NULL;
	     header = HEAD(resigned_list))
	{
		isc_rwlock_t *lock = NULL;
		isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

		ISC_LIST_UNLINK(resigned_list, header, link);

		lock = &qpdb->node_locks[QPDB_HEADERNODE(header)->locknum].lock;
		NODE_WRLOCK(lock, &nlocktype);
		if (rollback && !IGNORE(header)) {
			dns__qpzone_resigninsert(
				qpdb, QPDB_HEADERNODE(header)->locknum, header);
		}
		dns__qpdb_decref(qpdb, QPDB_HEADERNODE(header), least_serial,
				 &nlocktype, &tlocktype, true,
				 false DNS__DB_FLARG_PASS);
		NODE_UNLOCK(lock, &nlocktype);
		INSIST(tlocktype == isc_rwlocktype_none);
	}

	if (!EMPTY(cleanup_list)) {
		isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

		if (qpdb->loop == NULL) {
			/*
			 * We acquire a tree write lock here in order to make
			 * sure that stale nodes will be removed in
			 * dns__qpdb_decref().  If we didn't have the lock,
			 * those nodes could miss the chance to be removed
			 * until the server stops.  The write lock is
			 * expensive, but this should be rare enough
			 * to justify the cost.
			 */
			TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
		}

		for (changed = HEAD(cleanup_list); changed != NULL;
		     changed = next_changed)
		{
			isc_rwlock_t *lock = NULL;
			isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

			next_changed = NEXT(changed, link);
			rbtnode = changed->node;
			lock = &qpdb->node_locks[rbtnode->locknum].lock;

			NODE_WRLOCK(lock, &nlocktype);
			/*
			 * This is a good opportunity to purge any dead nodes,
			 * so use it.
			 */
			if (qpdb->loop == NULL) {
				cleanup_dead_nodes(
					qpdb,
					rbtnode->locknum DNS__DB_FLARG_PASS);
			}

			if (rollback) {
				rollback_node(rbtnode, serial);
			}
			dns__qpdb_decref(qpdb, rbtnode, least_serial,
					 &nlocktype, &tlocktype, true,
					 false DNS__DB_FILELINE);

			NODE_UNLOCK(lock, &nlocktype);

			isc_mem_put(qpdb->common.mctx, changed,
				    sizeof(*changed));
		}
		if (qpdb->loop != NULL) {
			isc_refcount_increment(&qpdb->common.references);
			isc_async_run(qpdb->loop, cleanup_dead_nodes_callback,
				      qpdb);
		} else {
			TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
		}

		INSIST(tlocktype == isc_rwlocktype_none);
	}

end:
	*versionp = NULL;
}

isc_result_t
dns__qpdb_findnodeintree(dns_qpdb_t *qpdb, dns_qp_t *tree,
			 const dns_name_t *name, bool create,
			 dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_rbtnode_t *node = NULL;
	dns_name_t nodename;
	isc_result_t result;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	INSIST(tree == qpdb->tree || tree == qpdb->nsec3);

	dns_name_init(&nodename, NULL);
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
		node = dns_qpdata_create(qpdb, name);
		result = dns_qp_insert(tree, node, 0);
		INSIST(result == ISC_R_SUCCESS);

		if (tree == qpdb->tree) {
			dns__qpzone_addwildcards(qpdb, name, true);

			if (dns_name_iswildcard(name)) {
				result = dns__qpzone_wildcardmagic(qpdb, name,
								   true);
				if (result != ISC_R_SUCCESS) {
					goto unlock;
				}
			}
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
dns__qpdb_bindrdataset(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
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
	} else if (IS_CACHE(qpdb) && !ACTIVE(header, now)) {
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

	/*
	 * Copy out re-signing information.
	 */
	if (RESIGN(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_RESIGN;
		rdataset->resign = (header->resign << 1) | header->resign_lsb;
	} else {
		rdataset->resign = 0;
	}
}

void
dns__qpdb_attachnode(dns_db_t *db, dns_dbnode_t *source,
		     dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));
	REQUIRE(targetp != NULL && *targetp == NULL);

	dns_rbtnode_t *node = (dns_rbtnode_t *)source;
	uint_fast32_t refs = isc_refcount_increment(&node->references);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	*targetp = source;
}

void
dns__qpdb_detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *node = NULL;
	bool want_free = false;
	bool inactive = false;
	db_nodelock_t *nodelock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (dns_rbtnode_t *)(*targetp);
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
	qpdbiter->common.relative_names = ((options & DNS_DB_RELATIVENAMES) !=
					   0);
	qpdbiter->common.magic = DNS_DBITERATOR_MAGIC;
	qpdbiter->paused = true;
	qpdbiter->tree_locked = isc_rwlocktype_none;
	qpdbiter->result = ISC_R_SUCCESS;
	dns_fixedname_init(&qpdbiter->name);
	dns_fixedname_init(&qpdbiter->origin);
	qpdbiter->node = NULL;
	if ((options & DNS_DB_NSEC3ONLY) != 0) {
		qpdbiter->nsec3mode = nsec3only;
	} else if ((options & DNS_DB_NONSEC3) != 0) {
		qpdbiter->nsec3mode = nonsec3;
	} else {
		qpdbiter->nsec3mode = full;
	}
	dns_rbtnodechain_init(&qpdbiter->chain);
	dns_rbtnodechain_init(&qpdbiter->nsec3chain);
	if (qpdbiter->nsec3mode == nsec3only) {
		qpdbiter->current = &qpdbiter->nsec3chain;
	} else {
		qpdbiter->current = &qpdbiter->chain;
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
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	dns_qpdb_version_t *rbtversion = version;
	qpdb_rdatasetiter_t *iterator = NULL;
	uint_fast32_t refs;

	REQUIRE(VALID_QPDB(qpdb));

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));

	if ((db->attributes & DNS_DBATTR_CACHE) == 0) {
		now = 0;
		if (rbtversion == NULL) {
			dns__qpdb_currentversion(
				db, (dns_dbversion_t **)(void *)(&rbtversion));
		} else {
			INSIST(rbtversion->qpdb == qpdb);

			(void)isc_refcount_increment(&rbtversion->references);
		}
	} else {
		if (now == 0) {
			now = isc_stdtime_now();
		}
		rbtversion = NULL;
	}

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = (dns_dbversion_t *)rbtversion;
	iterator->common.options = options;
	iterator->common.now = now;

	refs = isc_refcount_increment(&rbtnode->references);
#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	iterator->current = NULL;

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static bool
cname_and_other_data(dns_rbtnode_t *node, uint32_t serial) {
	dns_slabheader_t *header = NULL, *header_next = NULL;
	bool cname = false, other_data = false;
	dns_rdatatype_t rdtype;

	/*
	 * The caller must hold the node lock.
	 */

	/*
	 * Look for CNAME and "other data" rdatasets active in our version.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (!prio_type(header->type)) {
			/*
			 * CNAME is in the priority list, so if we are done
			 * with the priority list, we know there will not be
			 * CNAME, so we are safe to skip the rest of the types.
			 */
			return (false);
		}
		if (header->type == dns_rdatatype_cname) {
			/*
			 * Look for an active extant CNAME.
			 */
			do {
				if (header->serial <= serial && !IGNORE(header))
				{
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 */
					if (NONEXISTENT(header)) {
						header = NULL;
					}
					break;
				} else {
					header = header->down;
				}
			} while (header != NULL);
			if (header != NULL) {
				cname = true;
			}
		} else {
			/*
			 * Look for active extant "other data".
			 *
			 * "Other data" is any rdataset whose type is not
			 * KEY, NSEC, SIG or RRSIG.
			 */
			rdtype = DNS_TYPEPAIR_TYPE(header->type);
			if (rdtype != dns_rdatatype_key &&
			    rdtype != dns_rdatatype_sig &&
			    rdtype != dns_rdatatype_nsec &&
			    rdtype != dns_rdatatype_rrsig)
			{
				/*
				 * Is it active and extant?
				 */
				do {
					if (header->serial <= serial &&
					    !IGNORE(header))
					{
						/*
						 * Is this a "this rdataset
						 * doesn't exist" record?
						 */
						if (NONEXISTENT(header)) {
							header = NULL;
						}
						break;
					} else {
						header = header->down;
					}
				} while (header != NULL);
				if (header != NULL) {
					other_data = true;
				}
			}
		}
		if (cname && other_data) {
			return (true);
		}
	}

	return (false);
}

static uint64_t
recordsize(dns_slabheader_t *header, unsigned int namelen) {
	return (dns_rdataslab_rdatasize((unsigned char *)header,
					sizeof(*header)) +
		sizeof(dns_ttl_t) + sizeof(dns_rdatatype_t) +
		sizeof(dns_rdataclass_t) + namelen);
}

static void
update_recordsandxfrsize(bool add, dns_qpdb_version_t *rbtversion,
			 dns_slabheader_t *header, unsigned int namelen) {
	unsigned char *hdr = (unsigned char *)header;
	size_t hdrsize = sizeof(*header);

	RWLOCK(&rbtversion->rwlock, isc_rwlocktype_write);
	if (add) {
		rbtversion->records += dns_rdataslab_count(hdr, hdrsize);
		rbtversion->xfrsize += recordsize(header, namelen);
	} else {
		rbtversion->records -= dns_rdataslab_count(hdr, hdrsize);
		rbtversion->xfrsize -= recordsize(header, namelen);
	}
	RWUNLOCK(&rbtversion->rwlock, isc_rwlocktype_write);
}

isc_result_t
dns__qpdb_add(dns_qpdb_t *qpdb, dns_rbtnode_t *rbtnode,
	      const dns_name_t *nodename, dns_qpdb_version_t *rbtversion,
	      dns_slabheader_t *newheader, unsigned int options, bool loading,
	      dns_rdataset_t *addedrdataset, isc_stdtime_t now DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	dns_slabheader_t *topheader = NULL, *topheader_prev = NULL;
	dns_slabheader_t *header = NULL, *sigheader = NULL;
	dns_slabheader_t *prioheader = NULL;
	unsigned char *merged = NULL;
	isc_result_t result;
	bool header_nx;
	bool newheader_nx;
	bool merge;
	dns_rdatatype_t rdtype, covers;
	dns_typepair_t negtype = 0, sigtype;
	dns_trust_t trust;
	int idx;

	if ((options & DNS_DBADD_MERGE) != 0) {
		REQUIRE(rbtversion != NULL);
		merge = true;
	} else {
		merge = false;
	}

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	if (rbtversion != NULL && !loading) {
		/*
		 * We always add a changed record, even if no changes end up
		 * being made to this node, because it's harmless and
		 * simplifies the code.
		 */
		changed = add_changed(newheader, rbtversion DNS__DB_FLARG_PASS);
		if (changed == NULL) {
			dns_slabheader_destroy(&newheader);
			return (ISC_R_NOMEMORY);
		}
	}

	newheader_nx = NONEXISTENT(newheader) ? true : false;
	if (rbtversion == NULL && !newheader_nx) {
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
				for (topheader = rbtnode->data;
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
			for (topheader = rbtnode->data; topheader != NULL;
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
			for (topheader = rbtnode->data; topheader != NULL;
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
							qpdb, rbtnode,
							topheader, now,
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

	for (topheader = rbtnode->data; topheader != NULL;
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
		if (rbtversion == NULL && trust < header->trust &&
		    (ACTIVE(header, now) || header_nx))
		{
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				dns__qpdb_bindrdataset(
					qpdb, rbtnode, header, now,
					isc_rwlocktype_write,
					addedrdataset DNS__DB_FLARG_PASS);
			}
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Don't merge if a nonexistent rdataset is involved.
		 */
		if (merge && (header_nx || newheader_nx)) {
			merge = false;
		}

		/*
		 * If 'merge' is true, we'll try to create a new rdataset
		 * that is the union of 'newheader' and 'header'.
		 */
		if (merge) {
			unsigned int flags = 0;
			INSIST(rbtversion->serial >= header->serial);
			merged = NULL;
			result = ISC_R_SUCCESS;

			if ((options & DNS_DBADD_EXACT) != 0) {
				flags |= DNS_RDATASLAB_EXACT;
			}
			/*
			 * TTL use here is irrelevant to the cache;
			 * merge is only done with zonedbs.
			 */
			if ((options & DNS_DBADD_EXACTTTL) != 0 &&
			    newheader->ttl != header->ttl)
			{
				result = DNS_R_NOTEXACT;
			} else if (newheader->ttl != header->ttl) {
				flags |= DNS_RDATASLAB_FORCE;
			}
			if (result == ISC_R_SUCCESS) {
				result = dns_rdataslab_merge(
					(unsigned char *)header,
					(unsigned char *)newheader,
					(unsigned int)(sizeof(*newheader)),
					qpdb->common.mctx, qpdb->common.rdclass,
					(dns_rdatatype_t)header->type, flags,
					&merged);
			}
			if (result == ISC_R_SUCCESS) {
				/*
				 * If 'header' has the same serial number as
				 * we do, we could clean it up now if we knew
				 * that our caller had no references to it.
				 * We don't know this, however, so we leave it
				 * alone.  It will get cleaned up when
				 * clean_zone_node() runs.
				 */
				dns_slabheader_destroy(&newheader);
				newheader = (dns_slabheader_t *)merged;
				dns_slabheader_reset(newheader,
						     (dns_db_t *)qpdb,
						     (dns_dbnode_t *)rbtnode);
				dns_slabheader_copycase(newheader, header);
				if (loading && RESIGN(newheader) &&
				    RESIGN(header) &&
				    resign_sooner(header, newheader))
				{
					newheader->resign = header->resign;
					newheader->resign_lsb =
						header->resign_lsb;
				}
			} else {
				dns_slabheader_destroy(&newheader);
				return (result);
			}
		}
		/*
		 * Don't replace existing NS, A and AAAA RRsets in the
		 * cache if they are already exist. This prevents named
		 * being locked to old servers. Don't lower trust of
		 * existing record if the update is forced. Nothing
		 * special to be done w.r.t stale data; it gets replaced
		 * normally further down.
		 */
		if (IS_CACHE(qpdb) && ACTIVE(header, now) &&
		    header->type == dns_rdatatype_ns && !header_nx &&
		    !newheader_nx && header->trust >= newheader->trust &&
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
					qpdb, rbtnode, header, now,
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
		if (IS_CACHE(qpdb) && ACTIVE(header, now) &&
		    header->type == dns_rdatatype_ns && !header_nx &&
		    !newheader_nx && header->trust <= newheader->trust)
		{
			if (newheader->ttl > header->ttl) {
				newheader->ttl = header->ttl;
			}
		}
		if (IS_CACHE(qpdb) && ACTIVE(header, now) &&
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
					qpdb, rbtnode, header, now,
					isc_rwlocktype_write,
					addedrdataset DNS__DB_FLARG_PASS);
			}
			return (ISC_R_SUCCESS);
		}
		INSIST(rbtversion == NULL ||
		       rbtversion->serial >= topheader->serial);
		if (loading) {
			newheader->down = NULL;
			idx = QPDB_HEADERNODE(newheader)->locknum;
			if (IS_CACHE(qpdb)) {
				if (ZEROTTL(newheader)) {
					newheader->last_used = qpdb->last_used +
							       1;
					ISC_LIST_APPEND(qpdb->lru[idx],
							newheader, link);
				} else {
					ISC_LIST_PREPEND(qpdb->lru[idx],
							 newheader, link);
				}
				INSIST(qpdb->heaps != NULL);
				isc_heap_insert(qpdb->heaps[idx], newheader);
				newheader->heap = qpdb->heaps[idx];
			} else if (RESIGN(newheader)) {
				dns__qpzone_resigninsert(qpdb, idx, newheader);
				/*
				 * Don't call resigndelete, we don't need
				 * to reverse the delete.  The free_slabheader
				 * call below will clean up the heap entry.
				 */
			}

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			if (rbtversion != NULL && !header_nx) {
				update_recordsandxfrsize(false, rbtversion,
							 header,
							 nodename->length);
			}
			dns_slabheader_destroy(&header);
		} else {
			idx = QPDB_HEADERNODE(newheader)->locknum;
			if (IS_CACHE(qpdb)) {
				INSIST(qpdb->heaps != NULL);
				isc_heap_insert(qpdb->heaps[idx], newheader);
				newheader->heap = qpdb->heaps[idx];
				if (ZEROTTL(newheader)) {
					newheader->last_used = qpdb->last_used +
							       1;
					ISC_LIST_APPEND(qpdb->lru[idx],
							newheader, link);
				} else {
					ISC_LIST_PREPEND(qpdb->lru[idx],
							 newheader, link);
				}
			} else if (RESIGN(newheader)) {
				dns__qpzone_resigninsert(qpdb, idx, newheader);
				dns__qpzone_resigndelete(
					qpdb, rbtversion,
					header DNS__DB_FLARG_PASS);
			}
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			rbtnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
			if (rbtversion == NULL) {
				mark_ancient(header);
				if (sigheader != NULL) {
					mark_ancient(sigheader);
				}
			}
			if (rbtversion != NULL && !header_nx) {
				update_recordsandxfrsize(false, rbtversion,
							 header,
							 nodename->length);
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
		if (IS_CACHE(qpdb)) {
			isc_heap_insert(qpdb->heaps[idx], newheader);
			newheader->heap = qpdb->heaps[idx];
			if (ZEROTTL(newheader)) {
				ISC_LIST_APPEND(qpdb->lru[idx], newheader,
						link);
			} else {
				ISC_LIST_PREPEND(qpdb->lru[idx], newheader,
						 link);
			}
		} else if (RESIGN(newheader)) {
			dns__qpzone_resigninsert(qpdb, idx, newheader);
			dns__qpzone_resigndelete(qpdb, rbtversion,
						 header DNS__DB_FLARG_PASS);
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
			INSIST(rbtversion == NULL ||
			       rbtversion->serial >= topheader->serial);
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			rbtnode->dirty = 1;
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
				newheader->next = rbtnode->data;
				rbtnode->data = newheader;
			} else if (prioheader != NULL) {
				/* Append after the priority headers */
				newheader->next = prioheader->next;
				prioheader->next = newheader;
			} else {
				/* There were no priority headers */
				newheader->next = rbtnode->data;
				rbtnode->data = newheader;
			}
		}
	}

	if (rbtversion != NULL && !newheader_nx) {
		update_recordsandxfrsize(true, rbtversion, newheader,
					 nodename->length);
	}

	/*
	 * Check if the node now contains CNAME and other data.
	 */
	if (rbtversion != NULL &&
	    cname_and_other_data(rbtnode, rbtversion->serial))
	{
		return (DNS_R_CNAMEANDOTHER);
	}

	if (addedrdataset != NULL) {
		dns__qpdb_bindrdataset(qpdb, rbtnode, newheader, now,
				       isc_rwlocktype_write,
				       addedrdataset DNS__DB_FLARG_PASS);
	}

	return (ISC_R_SUCCESS);
}

static bool
delegating_type(dns_qpdb_t *qpdb, dns_rbtnode_t *node, dns_typepair_t type) {
	if (IS_CACHE(qpdb)) {
		if (type == dns_rdatatype_dname) {
			return (true);
		} else {
			return (false);
		}
	} else if (type == dns_rdatatype_dname ||
		   (type == dns_rdatatype_ns &&
		    (node != qpdb->origin_node || IS_STUB(qpdb))))
	{
		return (true);
	}
	return (false);
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
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	dns_qpdb_version_t *rbtversion = version;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	bool delegating;
	bool newnsec;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	bool cache_is_overmem = false;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	INSIST(rbtversion == NULL || rbtversion->qpdb == qpdb);

	if (!IS_CACHE(qpdb)) {
		/*
		 * SOA records are only allowed at top of zone.
		 */
		if (rdataset->type == dns_rdatatype_soa &&
		    node != qpdb->origin_node)
		{
			return (DNS_R_NOTZONETOP);
		}
		TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
		REQUIRE(((rbtnode->nsec == DNS_DB_NSEC_NSEC3 &&
			  (rdataset->type == dns_rdatatype_nsec3 ||
			   rdataset->covers == dns_rdatatype_nsec3)) ||
			 (rbtnode->nsec != DNS_DB_NSEC_NSEC3 &&
			  rdataset->type != dns_rdatatype_nsec3 &&
			  rdataset->covers != dns_rdatatype_nsec3)));
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}

	if (rbtversion == NULL) {
		if (now == 0) {
			now = isc_stdtime_now();
		}
	} else {
		now = 0;
	}

	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, sizeof(dns_slabheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	name = dns_fixedname_initname(&fixed);
	dns__qpdb_nodefullname(db, node, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (dns_slabheader_t *)region.base;
	*newheader = (dns_slabheader_t){
		.type = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers),
		.trust = rdataset->trust,
		.last_used = now,
		.node = rbtnode,
	};

	dns_slabheader_reset(newheader, db, node);
	dns__qpdb_setttl(newheader, rdataset->ttl + now);
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	if (rbtversion != NULL) {
		newheader->serial = rbtversion->serial;
		now = 0;

		if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
			DNS_SLABHEADER_SETATTR(newheader,
					       DNS_SLABHEADERATTR_RESIGN);
			newheader->resign =
				(isc_stdtime_t)(dns_time64_from32(
							rdataset->resign) >>
						1);
			newheader->resign_lsb = rdataset->resign & 0x1;
		}
	} else {
		newheader->serial = 1;
		if ((rdataset->attributes & DNS_RDATASETATTR_PREFETCH) != 0) {
			DNS_SLABHEADER_SETATTR(newheader,
					       DNS_SLABHEADERATTR_PREFETCH);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0) {
			DNS_SLABHEADER_SETATTR(newheader,
					       DNS_SLABHEADERATTR_NEGATIVE);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NXDOMAIN) != 0) {
			DNS_SLABHEADER_SETATTR(newheader,
					       DNS_SLABHEADERATTR_NXDOMAIN);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_OPTOUT) != 0) {
			DNS_SLABHEADER_SETATTR(newheader,
					       DNS_SLABHEADERATTR_OPTOUT);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NOQNAME) != 0) {
			result = addnoqname(qpdb->common.mctx, newheader,
					    rdataset);
			if (result != ISC_R_SUCCESS) {
				dns_slabheader_destroy(&newheader);
				return (result);
			}
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_CLOSEST) != 0) {
			result = addclosest(qpdb->common.mctx, newheader,
					    rdataset);
			if (result != ISC_R_SUCCESS) {
				dns_slabheader_destroy(&newheader);
				return (result);
			}
		}
	}

	/*
	 * If we're adding a delegation type (e.g. NS or DNAME for a zone,
	 * just DNAME for the cache), then we need to set the callback bit
	 * on the node.
	 */
	if (delegating_type(qpdb, rbtnode, rdataset->type)) {
		delegating = true;
	} else {
		delegating = false;
	}

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	if (rbtnode->nsec != DNS_DB_NSEC_HAS_NSEC &&
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
	if (IS_CACHE(qpdb) && isc_mem_isovermem(qpdb->common.mctx)) {
		cache_is_overmem = true;
	}
	if (delegating || newnsec || cache_is_overmem) {
		TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
	}

	if (cache_is_overmem) {
		dns__qpcache_overmem(qpdb, newheader,
				     &tlocktype DNS__DB_FLARG_PASS);
	}

	NODE_WRLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	if (qpdb->rrsetstats != NULL) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->type,
				  atomic_load_acquire(&newheader->attributes),
				  true);
	}

	if (IS_CACHE(qpdb)) {
		if (tlocktype == isc_rwlocktype_write) {
			cleanup_dead_nodes(qpdb,
					   rbtnode->locknum DNS__DB_FLARG_PASS);
		}

		expire_ttl_headers(qpdb, rbtnode->locknum, &tlocktype, now,
				   cache_is_overmem DNS__DB_FLARG_PASS);

		/*
		 * If we've been holding a write lock on the tree just for
		 * cleaning, we can release it now.  However, we still need the
		 * node lock.
		 */
		if (tlocktype == isc_rwlocktype_write && !delegating &&
		    !newnsec)
		{
			TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
		}
	}

	result = ISC_R_SUCCESS;
	if (newnsec) {
		dns_rbtnode_t *nsecnode = NULL;

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
		}
		rbtnode->nsec = DNS_DB_NSEC_HAS_NSEC;
	}

	if (result == ISC_R_SUCCESS) {
		result = dns__qpdb_add(qpdb, rbtnode, name, rbtversion,
				       newheader, options, false, addedrdataset,
				       now DNS__DB_FLARG_PASS);
	}
	if (result == ISC_R_SUCCESS && delegating) {
		rbtnode->find_callback = 1;
	}

	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	if (tlocktype != isc_rwlocktype_none) {
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}
	INSIST(tlocktype == isc_rwlocktype_none);

	/*
	 * Update the zone's secure status.  If version is non-NULL
	 * this is deferred until dns__qpdb_closeversion() is called.
	 */
	if (result == ISC_R_SUCCESS && version == NULL && !IS_CACHE(qpdb)) {
		dns__qpdb_setsecure(db, version, qpdb->origin_node);
	}

	return (result);
}

isc_result_t
dns__qpdb_subtractrdataset(dns_db_t *db, dns_dbnode_t *node,
			   dns_dbversion_t *version, dns_rdataset_t *rdataset,
			   unsigned int options,
			   dns_rdataset_t *newrdataset DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	dns_qpdb_version_t *rbtversion = version;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	dns_slabheader_t *topheader = NULL, *topheader_prev = NULL;
	dns_slabheader_t *header = NULL, *newheader = NULL;
	unsigned char *subresult = NULL;
	isc_region_t region;
	isc_result_t result;
	qpdb_changed_t *changed = NULL;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(rbtversion != NULL && rbtversion->qpdb == qpdb);

	if (!IS_CACHE(qpdb)) {
		TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
		REQUIRE(((rbtnode->nsec == DNS_DB_NSEC_NSEC3 &&
			  (rdataset->type == dns_rdatatype_nsec3 ||
			   rdataset->covers == dns_rdatatype_nsec3)) ||
			 (rbtnode->nsec != DNS_DB_NSEC_NSEC3 &&
			  rdataset->type != dns_rdatatype_nsec3 &&
			  rdataset->covers != dns_rdatatype_nsec3)));
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}

	dns__qpdb_nodefullname(db, node, nodename);

	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, sizeof(dns_slabheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, db, node);
	dns__qpdb_setttl(newheader, rdataset->ttl);
	newheader->type = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers);
	atomic_init(&newheader->attributes, 0);
	newheader->serial = rbtversion->serial;
	newheader->trust = 0;
	newheader->noqname = NULL;
	newheader->closest = NULL;
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->last_used = 0;
	newheader->node = rbtnode;
	newheader->db = (dns_db_t *)qpdb;
	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	} else {
		newheader->resign = 0;
		newheader->resign_lsb = 0;
	}

	NODE_WRLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	changed = add_changed(newheader, rbtversion DNS__DB_FLARG_PASS);
	if (changed == NULL) {
		dns_slabheader_destroy(&newheader);
		NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock,
			    &nlocktype);
		return (ISC_R_NOMEMORY);
	}

	for (topheader = rbtnode->data; topheader != NULL;
	     topheader = topheader->next)
	{
		if (topheader->type == newheader->type) {
			break;
		}
		topheader_prev = topheader;
	}
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
	if (header != NULL && EXISTS(header)) {
		unsigned int flags = 0;
		subresult = NULL;
		result = ISC_R_SUCCESS;
		if ((options & DNS_DBSUB_EXACT) != 0) {
			flags |= DNS_RDATASLAB_EXACT;
			if (newheader->ttl != header->ttl) {
				result = DNS_R_NOTEXACT;
			}
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_rdataslab_subtract(
				(unsigned char *)header,
				(unsigned char *)newheader,
				(unsigned int)(sizeof(*newheader)),
				qpdb->common.mctx, qpdb->common.rdclass,
				(dns_rdatatype_t)header->type, flags,
				&subresult);
		}
		if (result == ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			newheader = (dns_slabheader_t *)subresult;
			dns_slabheader_reset(newheader, db, node);
			dns_slabheader_copycase(newheader, header);
			if (RESIGN(header)) {
				DNS_SLABHEADER_SETATTR(
					newheader, DNS_SLABHEADERATTR_RESIGN);
				newheader->resign = header->resign;
				newheader->resign_lsb = header->resign_lsb;
				dns__qpzone_resigninsert(qpdb, rbtnode->locknum,
							 newheader);
			}
			/*
			 * We have to set the serial since the rdataslab
			 * subtraction routine copies the reserved portion of
			 * header, not newheader.
			 */
			newheader->serial = rbtversion->serial;
			/*
			 * XXXJT: dns_rdataslab_subtract() copied the pointers
			 * to additional info.  We need to clear these fields
			 * to avoid having duplicated references.
			 */
			update_recordsandxfrsize(true, rbtversion, newheader,
						 nodename->length);
		} else if (result == DNS_R_NXRRSET) {
			/*
			 * This subtraction would remove all of the rdata;
			 * add a nonexistent header instead.
			 */
			dns_slabheader_destroy(&newheader);
			newheader = dns_slabheader_new((dns_db_t *)qpdb,
						       (dns_dbnode_t *)rbtnode);
			dns__qpdb_setttl(newheader, 0);
			newheader->type = topheader->type;
			atomic_init(&newheader->attributes,
				    DNS_SLABHEADERATTR_NONEXISTENT);
			newheader->serial = rbtversion->serial;
		} else {
			dns_slabheader_destroy(&newheader);
			goto unlock;
		}

		/*
		 * If we're here, we want to link newheader in front of
		 * topheader.
		 */
		INSIST(rbtversion->serial >= topheader->serial);
		update_recordsandxfrsize(false, rbtversion, header,
					 nodename->length);
		if (topheader_prev != NULL) {
			topheader_prev->next = newheader;
		} else {
			rbtnode->data = newheader;
		}
		newheader->next = topheader->next;
		newheader->down = topheader;
		topheader->next = newheader;
		rbtnode->dirty = 1;
		changed->dirty = true;
		dns__qpzone_resigndelete(qpdb, rbtversion,
					 header DNS__DB_FLARG_PASS);
	} else {
		/*
		 * The rdataset doesn't exist, so we don't need to do anything
		 * to satisfy the deletion request.
		 */
		dns_slabheader_destroy(&newheader);
		if ((options & DNS_DBSUB_EXACT) != 0) {
			result = DNS_R_NOTEXACT;
		} else {
			result = DNS_R_UNCHANGED;
		}
	}

	if (result == ISC_R_SUCCESS && newrdataset != NULL) {
		dns__qpdb_bindrdataset(qpdb, rbtnode, newheader, 0,
				       isc_rwlocktype_write,
				       newrdataset DNS__DB_FLARG_PASS);
	}

	if (result == DNS_R_NXRRSET && newrdataset != NULL &&
	    (options & DNS_DBSUB_WANTOLD) != 0)
	{
		dns__qpdb_bindrdataset(qpdb, rbtnode, header, 0,
				       isc_rwlocktype_write,
				       newrdataset DNS__DB_FLARG_PASS);
	}

unlock:
	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	/*
	 * Update the zone's secure status.  If version is non-NULL
	 * this is deferred until dns__qpdb_closeversion() is called.
	 */
	if (result == ISC_R_SUCCESS && version == NULL && !IS_CACHE(qpdb)) {
		RWLOCK(&qpdb->lock, isc_rwlocktype_read);
		version = qpdb->current_version;
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);
		dns__qpdb_setsecure(db, version, qpdb->origin_node);
	}

	return (result);
}

isc_result_t
dns__qpdb_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
			 dns_dbversion_t *version, dns_rdatatype_t type,
			 dns_rdatatype_t covers DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	dns_qpdb_version_t *rbtversion = version;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	isc_result_t result;
	dns_slabheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	INSIST(rbtversion == NULL || rbtversion->qpdb == qpdb);

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
	if (rbtversion != NULL) {
		newheader->serial = rbtversion->serial;
	}

	dns__qpdb_nodefullname(db, node, nodename);

	NODE_WRLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);
	result = dns__qpdb_add(qpdb, rbtnode, nodename, rbtversion, newheader,
			       DNS_DBADD_FORCE, false, NULL,
			       0 DNS__DB_FLARG_PASS);
	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	/*
	 * Update the zone's secure status.  If version is non-NULL
	 * this is deferred until dns__qpdb_closeversion() is called.
	 */
	if (result == ISC_R_SUCCESS && version == NULL && !IS_CACHE(qpdb)) {
		RWLOCK(&qpdb->lock, isc_rwlocktype_read);
		version = qpdb->current_version;
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);
		dns__qpdb_setsecure(db, version, qpdb->origin_node);
	}

	return (result);
}

unsigned int
dns__qpdb_nodecount(dns_db_t *db, dns_dbtree_t tree) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	unsigned int count;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	switch (tree) {
	case dns_dbtree_main:
		count = dns_rbt_nodecount(qpdb->tree);
		break;
	case dns_dbtree_nsec:
		count = dns_rbt_nodecount(qpdb->nsec);
		break;
	case dns_dbtree_nsec3:
		count = dns_rbt_nodecount(qpdb->nsec3);
		break;
	default:
		UNREACHABLE();
	}
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return (count);
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
	dns_rbtnode_t *onode = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to origin_node doesn't require a DB lock */
	onode = (dns_rbtnode_t *)qpdb->origin_node;
	if (onode != NULL) {
		dns__qpdb_newref(qpdb, onode,
				 isc_rwlocktype_none DNS__DB_FLARG_PASS);
		*nodep = qpdb->origin_node;
	} else {
		INSIST(IS_CACHE(qpdb));
		result = ISC_R_NOTFOUND;
	}

	return (result);
}

void
dns__qpdb_locknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;

	RWLOCK(&qpdb->node_locks[rbtnode->locknum].lock, type);
}

void
dns__qpdb_unlocknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;

	RWUNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, type);
}

isc_result_t
dns__qpdb_nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	isc_result_t result;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(node != NULL);
	REQUIRE(name != NULL);

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	result = dns_rbt_fullnamefromnode(rbtnode, name);
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return (result);
}

isc_result_t
dns__qpdb_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	dns_qpdb_t *qpdb = NULL;
	isc_result_t result;
	int i;
	isc_mem_t *hmctx = mctx;

	qpdb = isc_mem_get(mctx, sizeof(*qpdb));
	*qpdb = (dns_qpdb_t){
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.current_serial = 1,
		.least_serial = 1,
		.next_serial = 2,
		.open_versions = ISC_LIST_INITIALIZER,
	};

	isc_refcount_init(&qpdb->common.references, 1);

	/*
	 * If argv[0] exists, it points to a memory context to use for heap
	 */
	if (argc != 0) {
		hmctx = (isc_mem_t *)argv[0];
	}

	if (type == dns_dbtype_cache) {
		qpdb->common.methods = &dns__qpdb_cachemethods;
		qpdb->common.attributes |= DNS_DBATTR_CACHE;
	} else if (type == dns_dbtype_stub) {
		qpdb->common.methods = &dns__qpdb_zonemethods;
		qpdb->common.attributes |= DNS_DBATTR_STUB;
	} else {
		qpdb->common.methods = &dns__qpdb_zonemethods;
	}

	isc_rwlock_init(&qpdb->lock);
	TREE_INITLOCK(&qpdb->tree_lock);

	/*
	 * Initialize node_lock_count in a generic way to support future
	 * extension which allows the user to specify this value on creation.
	 * Note that when specified for a cache DB it must be larger than 1
	 * as commented with the definition of DEFAULT_CACHE_NODE_LOCK_COUNT.
	 */
	if (qpdb->node_lock_count == 0) {
		if (IS_CACHE(qpdb)) {
			qpdb->node_lock_count = DEFAULT_CACHE_NODE_LOCK_COUNT;
		} else {
			qpdb->node_lock_count = DEFAULT_NODE_LOCK_COUNT;
		}
	} else if (qpdb->node_lock_count < 2 && IS_CACHE(qpdb)) {
		result = ISC_R_RANGE;
		goto cleanup_tree_lock;
	}
	INSIST(qpdb->node_lock_count < (1 << DNS_RBT_LOCKLENGTH));
	qpdb->node_locks = isc_mem_get(mctx, qpdb->node_lock_count *
						     sizeof(db_nodelock_t));

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	if (IS_CACHE(qpdb)) {
		dns_rdatasetstats_create(mctx, &qpdb->rrsetstats);
		qpdb->lru = isc_mem_get(mctx,
					qpdb->node_lock_count *
						sizeof(dns_slabheaderlist_t));
		for (i = 0; i < (int)qpdb->node_lock_count; i++) {
			ISC_LIST_INIT(qpdb->lru[i]);
		}
	}

	/*
	 * Create the heaps.
	 */
	qpdb->heaps = isc_mem_get(hmctx,
				  qpdb->node_lock_count * sizeof(isc_heap_t *));
	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		qpdb->heaps[i] = NULL;
	}

	qpdb->sooner = IS_CACHE(qpdb) ? ttl_sooner : resign_sooner;
	for (i = 0; i < (int)qpdb->node_lock_count; i++) {
		isc_heap_create(hmctx, qpdb->sooner, set_index, 0,
				&qpdb->heaps[i]);
	}

	/*
	 * Create deadnode lists.
	 */
	qpdb->deadnodes = isc_mem_get(mctx, qpdb->node_lock_count *
						    sizeof(dns_rbtnodelist_t));
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

	/*
	 * In order to set the node callback bit correctly in zone databases,
	 * we need to know if the node has the origin name of the zone.
	 * In loading_addrdataset() we could simply compare the new name
	 * to the origin name, but this is expensive.  Also, we don't know the
	 * node name in dns__qpdb_addrdataset(), so we need another way of
	 * knowing the zone's top.
	 *
	 * We now explicitly create a node for the zone's origin, and then
	 * we simply remember the node's address.  This is safe, because
	 * the top-of-zone node can never be deleted, nor can its address
	 * change.
	 */
	if (!IS_CACHE(qpdb)) {
		qpdb->origin_node = dns_qpdata_create(qpdb,
						      &qpdb->common.origin);
		result = dns_qp_insert(qpdb->tree, qpdb->origin_node, 0);
		INSIST(result == ISC_R_SUCCESS);
		INSIST(qpdb->origin_node != NULL);
		qpdb->origin_node->nsec = DNS_DB_NSEC_NORMAL;

		/*
		 * Add an apex node to the NSEC3 tree so that NSEC3 searches
		 * return partial matches when there is only a single NSEC3
		 * record in the tree.
		 */
		qpdb->nsec3_origin_node =
			dns_qpdata_create(qpdb, &qpdb->common.origin);
		result = dns_qp_insert(qpdb->nsec3, qpdb->nsec3_origin_node, 0);
		INSIST(result == ISC_R_SUCCESS);
		INSIST(qpdb->nsec3_origin_node != NULL);
		qpdb->nsec3_origin_node->nsec = DNS_DB_NSEC_NSEC3;
	}

	/*
	 * Version Initialization.
	 */
	qpdb->current_version = allocate_version(mctx, 1, 1, false);
	qpdb->current_version->qpdb = qpdb;
	isc_rwlock_init(&qpdb->current_version->rwlock);

	/*
	 * Keep the current version in the open list so that list operation
	 * won't happen in normal lookup operations.
	 */
	PREPEND(qpdb->open_versions, qpdb->current_version, link);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPDB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return (ISC_R_SUCCESS);

cleanup_tree_lock:
	TREE_DESTROYLOCK(&qpdb->tree_lock);
	isc_rwlock_destroy(&qpdb->lock);
	isc_mem_put(mctx, qpdb, sizeof(*qpdb));
	return (result);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = NULL;

	rbtiterator = (qpdb_rdatasetiter_t *)(*iteratorp);

	if (rbtiterator->common.version != NULL) {
		dns__qpdb_closeversion(rbtiterator->common.db,
				       &rbtiterator->common.version,
				       false DNS__DB_FLARG_PASS);
	}
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
	 * If this is a zone or this header still active then return it.
	 */
	if (!IS_CACHE(qpdb) || ACTIVE(header, rbtiterator->common.now)) {
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
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	dns_qpdb_version_t *rbtversion = rbtiterator->common.version;
	dns_slabheader_t *header = NULL, *top_next = NULL;
	uint32_t serial = IS_CACHE(qpdb) ? 1 : rbtversion->serial;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	NODE_RDLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	for (header = rbtnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (EXPIREDOK(rbtiterator)) {
				if (!NONEXISTENT(header)) {
					break;
				}
				header = header->down;
			} else if (header->serial <= serial && !IGNORE(header))
			{
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

	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

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
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	dns_qpdb_version_t *rbtversion = rbtiterator->common.version;
	dns_slabheader_t *header = NULL, *top_next = NULL;
	uint32_t serial = IS_CACHE(qpdb) ? 1 : rbtversion->serial;
	dns_typepair_t type, negtype;
	dns_rdatatype_t rdtype, covers;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	bool expiredok = EXPIREDOK(rbtiterator);

	header = rbtiterator->current;
	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	NODE_RDLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

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
			} else if (header->serial <= serial && !IGNORE(header))
			{
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

	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

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
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	header = rbtiterator->current;
	REQUIRE(header != NULL);

	NODE_RDLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);

	dns__qpdb_bindrdataset(qpdb, rbtnode, header, rbtiterator->common.now,
			       isc_rwlocktype_read,
			       rdataset DNS__DB_FLARG_PASS);

	NODE_UNLOCK(&qpdb->node_locks[rbtnode->locknum].lock, &nlocktype);
}

/*
 * Database Iterator Methods
 */

static void
reference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	dns_rbtnode_t *node = qpdbiter->node;

	if (node == NULL) {
		return;
	}

	INSIST(qpdbiter->tree_locked != isc_rwlocktype_none);
	reactivate_node(qpdb, node, qpdbiter->tree_locked DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	dns_rbtnode_t *node = qpdbiter->node;
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
resume_iteration(qpdb_dbiterator_t *qpdbiter) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;

	REQUIRE(qpdbiter->paused);
	REQUIRE(qpdbiter->tree_locked == isc_rwlocktype_none);

	TREE_RDLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);

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

	dns_rbtnodechain_reset(&qpdbiter->chain);
	dns_rbtnodechain_reset(&qpdbiter->nsec3chain);
	isc_mem_put(db->mctx, qpdbiter, sizeof(*qpdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;
	dns_name_t *name = NULL, *origin = NULL;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	name = dns_fixedname_name(&qpdbiter->name);
	origin = dns_fixedname_name(&qpdbiter->origin);
	dns_rbtnodechain_reset(&qpdbiter->chain);
	dns_rbtnodechain_reset(&qpdbiter->nsec3chain);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3chain;
		result = dns_rbtnodechain_first(qpdbiter->current, qpdb->nsec3,
						name, origin);
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->chain;
		result = dns_rbtnodechain_first(qpdbiter->current, qpdb->tree,
						name, origin);
		break;
	case full:
		qpdbiter->current = &qpdbiter->chain;
		result = dns_rbtnodechain_first(qpdbiter->current, qpdb->tree,
						name, origin);
		if (result == ISC_R_NOTFOUND) {
			qpdbiter->current = &qpdbiter->nsec3chain;
			result = dns_rbtnodechain_first(
				qpdbiter->current, qpdb->nsec3, name, origin);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		result = dns_rbtnodechain_current(qpdbiter->current, NULL, NULL,
						  &qpdbiter->node);

		/* If we're in the NSEC3 tree, skip the origin */
		if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
			qpdbiter->node = NULL;
			result = dns_rbtnodechain_next(qpdbiter->current, name,
						       origin);
			if (result == ISC_R_SUCCESS ||
			    result == DNS_R_NEWORIGIN)
			{
				result = dns_rbtnodechain_current(
					qpdbiter->current, NULL, NULL,
					&qpdbiter->node);
			}
		}
		if (result == ISC_R_SUCCESS) {
			qpdbiter->new_origin = true;
			reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
		}
	} else {
		INSIST(result == ISC_R_NOTFOUND);
		result = ISC_R_NOMORE; /* The tree is empty. */
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
	dns_name_t *name = NULL, *origin = NULL;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	name = dns_fixedname_name(&qpdbiter->name);
	origin = dns_fixedname_name(&qpdbiter->origin);
	dns_rbtnodechain_reset(&qpdbiter->chain);
	dns_rbtnodechain_reset(&qpdbiter->nsec3chain);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3chain;
		result = dns_rbtnodechain_last(qpdbiter->current, qpdb->nsec3,
					       name, origin);
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->chain;
		result = dns_rbtnodechain_last(qpdbiter->current, qpdb->tree,
					       name, origin);
		break;
	case full:
		qpdbiter->current = &qpdbiter->nsec3chain;
		result = dns_rbtnodechain_last(qpdbiter->current, qpdb->nsec3,
					       name, origin);
		if (result == ISC_R_NOTFOUND) {
			qpdbiter->current = &qpdbiter->chain;
			result = dns_rbtnodechain_last(
				qpdbiter->current, qpdb->tree, name, origin);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		result = dns_rbtnodechain_current(qpdbiter->current, NULL, NULL,
						  &qpdbiter->node);
		if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
			/*
			 * NSEC3 tree only has an origin node.
			 */
			qpdbiter->node = NULL;
			switch (qpdbiter->nsec3mode) {
			case nsec3only:
				result = ISC_R_NOMORE;
				break;
			case nonsec3:
			case full:
				qpdbiter->current = &qpdbiter->chain;
				result = dns_rbtnodechain_last(
					qpdbiter->current, qpdb->tree, name,
					origin);
				if (result == ISC_R_SUCCESS ||
				    result == DNS_R_NEWORIGIN)
				{
					result = dns_rbtnodechain_current(
						qpdbiter->current, NULL, NULL,
						&qpdbiter->node);
				}
				break;
			default:
				UNREACHABLE();
			}
		}
		if (result == ISC_R_SUCCESS) {
			qpdbiter->new_origin = true;
			reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
		}
	} else {
		INSIST(result == ISC_R_NOTFOUND);
		result = ISC_R_NOMORE; /* The tree is empty. */
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
	dns_name_t *iname = NULL, *origin = NULL;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	iname = dns_fixedname_name(&qpdbiter->name);
	origin = dns_fixedname_name(&qpdbiter->origin);
	dns_rbtnodechain_reset(&qpdbiter->chain);
	dns_rbtnodechain_reset(&qpdbiter->nsec3chain);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3chain;
		result = dns_qp_lookup(qpdb->nsec3, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->chain;
		result = dns_qp_lookup(qpdb->tree, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case full:
		/*
		 * Stay on main chain if not found on
		 * either chain.
		 */
		qpdbiter->current = &qpdbiter->chain;
		result = dns_qp_lookup(qpdb->tree, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		if (result == DNS_R_PARTIALMATCH) {
			dns_rbtnode_t *node = NULL;
			tresult = dns_qp_lookup(qpdb->nsec3, name, NULL,
						&qpdbiter->nsec3chain, NULL,
						(void **)&node, NULL);
			if (tresult == ISC_R_SUCCESS) {
				qpdbiter->node = node;
				qpdbiter->current = &qpdbiter->nsec3chain;
				result = tresult;
			}
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		tresult = dns_rbtnodechain_current(qpdbiter->current, iname,
						   origin, NULL);
		if (tresult == ISC_R_SUCCESS) {
			qpdbiter->new_origin = true;
			reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
		} else {
			result = tresult;
			qpdbiter->node = NULL;
		}
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
	dns_name_t *name = NULL, *origin = NULL;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	name = dns_fixedname_name(&qpdbiter->name);
	origin = dns_fixedname_name(&qpdbiter->origin);
	result = dns_rbtnodechain_prev(qpdbiter->current, name, origin);
	if (qpdbiter->current == &qpdbiter->nsec3chain &&
	    (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN))
	{
		/*
		 * If we're in the NSEC3 tree, it's empty or we've
		 * reached the origin, then we're done with it.
		 */
		result = dns_rbtnodechain_current(qpdbiter->current, NULL, NULL,
						  &qpdbiter->node);
		if (result == ISC_R_NOTFOUND ||
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			qpdbiter->node = NULL;
			result = ISC_R_NOMORE;
		}
	}
	if (result == ISC_R_NOMORE && qpdbiter->nsec3mode != nsec3only &&
	    &qpdbiter->nsec3chain == qpdbiter->current)
	{
		qpdbiter->current = &qpdbiter->chain;
		dns_rbtnodechain_reset(qpdbiter->current);
		result = dns_rbtnodechain_last(qpdbiter->current, qpdb->tree,
					       name, origin);
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_NOMORE;
		}
	}

	if (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		qpdbiter->new_origin = (result == DNS_R_NEWORIGIN);
		result = dns_rbtnodechain_current(qpdbiter->current, NULL, NULL,
						  &qpdbiter->node);
	}

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_name_t *name = NULL, *origin = NULL;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	name = dns_fixedname_name(&qpdbiter->name);
	origin = dns_fixedname_name(&qpdbiter->origin);
	result = dns_rbtnodechain_next(qpdbiter->current, name, origin);
	if (result == ISC_R_NOMORE && qpdbiter->nsec3mode != nonsec3 &&
	    &qpdbiter->chain == qpdbiter->current)
	{
		qpdbiter->current = &qpdbiter->nsec3chain;
		dns_rbtnodechain_reset(qpdbiter->current);
		result = dns_rbtnodechain_first(qpdbiter->current, qpdb->nsec3,
						name, origin);
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_NOMORE;
		}
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	if (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		/*
		 * If we've just started the NSEC3 tree,
		 * skip over the origin.
		 */
		qpdbiter->new_origin = (result == DNS_R_NEWORIGIN);
		result = dns_rbtnodechain_current(qpdbiter->current, NULL, NULL,
						  &qpdbiter->node);
		if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
			qpdbiter->node = NULL;
			result = dns_rbtnodechain_next(qpdbiter->current, name,
						       origin);
			if (result == ISC_R_SUCCESS ||
			    result == DNS_R_NEWORIGIN)
			{
				result = dns_rbtnodechain_current(
					qpdbiter->current, NULL, NULL,
					&qpdbiter->node);
			}
		}
	}
	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	dns_rbtnode_t *node = qpdbiter->node;
	isc_result_t result;
	dns_name_t *nodename = dns_fixedname_name(&qpdbiter->name);
	dns_name_t *origin = dns_fixedname_name(&qpdbiter->origin);

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter);
	}

	if (name != NULL) {
		if (qpdbiter->common.relative_names) {
			origin = NULL;
		}
		result = dns_name_concatenate(nodename, origin, name, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
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
dns__qpdb_freeglue(dns_glue_t *glue_list) {
	if (glue_list == (void *)-1) {
		return;
	}

	dns_glue_t *glue = glue_list;
	while (glue != NULL) {
		dns_glue_t *next = glue->next;

		if (dns_rdataset_isassociated(&glue->rdataset_a)) {
			dns_rdataset_disassociate(&glue->rdataset_a);
		}
		if (dns_rdataset_isassociated(&glue->sigrdataset_a)) {
			dns_rdataset_disassociate(&glue->sigrdataset_a);
		}

		if (dns_rdataset_isassociated(&glue->rdataset_aaaa)) {
			dns_rdataset_disassociate(&glue->rdataset_aaaa);
		}
		if (dns_rdataset_isassociated(&glue->sigrdataset_aaaa)) {
			dns_rdataset_disassociate(&glue->sigrdataset_aaaa);
		}

		dns_rdataset_invalidate(&glue->rdataset_a);
		dns_rdataset_invalidate(&glue->sigrdataset_a);
		dns_rdataset_invalidate(&glue->rdataset_aaaa);
		dns_rdataset_invalidate(&glue->sigrdataset_aaaa);

		isc_mem_putanddetach(&glue->mctx, glue, sizeof(*glue));

		glue = next;
	}
}

static void
free_gluelist_rcu(struct rcu_head *rcu_head) {
	dns_glue_t *glue = caa_container_of(rcu_head, dns_glue_t, rcu_head);

	dns__qpdb_freeglue(glue);
}

static void
free_gluetable(dns_qpdb_version_t *rbtversion) {
	struct cds_wfs_head *head = __cds_wfs_pop_all(&rbtversion->glue_stack);
	struct cds_wfs_node *node = NULL, *next = NULL;

	rcu_read_lock();
	cds_wfs_for_each_blocking_safe(head, node, next) {
		dns_slabheader_t *header =
			caa_container_of(node, dns_slabheader_t, wfs_node);
		dns_glue_t *glue = rcu_xchg_pointer(&header->glue_list, NULL);

		call_rcu(&glue->rcu_head, free_gluelist_rcu);
	}
	rcu_read_unlock();
}

void
dns__qpdb_deletedata(dns_db_t *db ISC_ATTR_UNUSED,
		     dns_dbnode_t *node ISC_ATTR_UNUSED, void *data) {
	dns_slabheader_t *header = data;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

	if (header->heap != NULL && header->heap_index != 0) {
		isc_heap_delete(header->heap, header->heap_index);
	}

	if (IS_CACHE(qpdb)) {
		update_rrsetstats(qpdb->rrsetstats, header->type,
				  atomic_load_acquire(&header->attributes),
				  false);

		if (ISC_LINK_LINKED(header, link)) {
			int idx = QPDB_HEADERNODE(header)->locknum;
			INSIST(IS_CACHE(qpdb));
			ISC_LIST_UNLINK(qpdb->lru[idx], header, link);
		}

		if (header->noqname != NULL) {
			dns_slabheader_freeproof(db->mctx, &header->noqname);
		}
		if (header->closest != NULL) {
			dns_slabheader_freeproof(db->mctx, &header->closest);
		}
	} else {
		if (header->glue_list) {
			dns__qpdb_freeglue(header->glue_list);
		}
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
	dns_name_free(data->name, data->mctx);
	isc_mem_putanddetach(&data->mctx, data, sizeof(dns_qpdata_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_TRACE_IMPL(dns_qpdata, dns_qpdata_destroy);
#else
ISC_REFCOUNT_IMPL(dns_qpdata, dns_qpdata_destroy);
#endif
