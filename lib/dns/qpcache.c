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
#include <stdalign.h>
#include <stdbool.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/file.h>
#include <isc/hex.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/queue.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/sieve.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/qp.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/types.h>
#include <dns/view.h>

#include "db_p.h"
#include "qpcache_p.h"
#include "rdataslab_p.h"

#ifndef DNS_QPCACHE_LOG_STATS_LEVEL
#define DNS_QPCACHE_LOG_STATS_LEVEL 3
#endif

#define STALE_TTL(header, qpdb) \
	(NXDOMAIN(header) ? 0 : qpdb->common.serve_stale_ttl)

#define ACTIVE(header, now)            \
	(((header)->expire > (now)) || \
	 ((header)->expire == (now) && ZEROTTL(header)))

#define EXPIREDOK(iterator) \
	(((iterator)->common.options & DNS_DB_EXPIREDOK) != 0)

#define STALEOK(iterator) (((iterator)->common.options & DNS_DB_STALEOK) != 0)

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPDB_MAGIC ISC_MAGIC('Q', 'P', 'D', '4')
#define VALID_QPDB(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPDB_MAGIC)

#define HEADERNODE(h) ((qpcnode_t *)((h)->node))

/*%
 * Forward declarations
 */
typedef struct qpcache qpcache_t;

/*%
 * This is the structure that is used for each node in the qp trie of
 * trees.
 */
typedef struct qpcnode qpcnode_t;
struct qpcnode {
	DBNODE_FIELDS;

	qpcache_t *qpdb;

	uint8_t		      : 0;
	unsigned int nspace   : 2; /*%< range is 0..3 */
	unsigned int havensec : 1;
	uint8_t		      : 0;

	/*
	 * 'erefs' counts external references held by a caller: for
	 * example, it could be incremented by dns_db_findnode(),
	 * and decremented by dns_db_detachnode().
	 *
	 * 'references' counts internal references to the node object,
	 * including the one held by the QP trie so the node won't be
	 * deleted while it's quiescently stored in the database - even
	 * though 'erefs' may be zero because no external caller is
	 * using it at the time.
	 *
	 * Generally when 'erefs' is incremented or decremented,
	 * 'references' is too. When both go to zero (meaning callers
	 * and the database have both released the object) the object
	 * is freed.
	 *
	 * Whenever 'erefs' is incremented from zero, we also acquire a
	 * node use reference (see 'qpcache->references' below), and
	 * release it when 'erefs' goes back to zero. This prevents the
	 * database from being shut down until every caller has released
	 * all nodes.
	 */
	isc_refcount_t references;
	isc_refcount_t erefs;

	struct cds_list_head headers;

	/*%
	 * Used for dead nodes cleaning.  This linked list is used to mark nodes
	 * which have no data any longer, but we cannot unlink at that exact
	 * moment because we did not or could not obtain a write lock on the
	 * tree.
	 */
	isc_queue_node_t deadlink;
};

/*%
 * One bucket structure will be created for each loop, and
 * nodes in the database will evenly distributed among buckets
 * to reduce contention between threads.
 */
typedef struct qpcache_bucket {
	union {
		struct {
			/*%
			 * Temporary storage for stale cache nodes and
			 * dynamically deleted nodes that await being cleaned
			 * up.
			 */
			isc_queue_t deadnodes;

			/* Per-bucket lock. */
			isc_rwlock_t lock;

			/* SIEVE-LRU cache cleaning state. */
			ISC_SIEVE(dns_slabheader_t) sieve;
		};
		uint8_t __padding[ISC_OS_CACHELINE_SIZE];
	};
} qpcache_bucket_t;

struct qpcache {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;
	/* Locks the tree structure (prevents nodes appearing/disappearing) */
	isc_rwlock_t tree_lock;

	/*
	 * NOTE: 'references' is NOT the global reference counter for
	 * the database object handled by dns_db_attach() and _detach();
	 * that one is 'common.references'.
	 *
	 * Instead, 'references' counts the number of nodes being used by
	 * at least one external caller. (It's called 'references' to
	 * leverage the ISC_REFCOUNT_STATIC macros, but 'nodes_in_use'
	 * might be a clearer name.)
	 *
	 * One additional reference to this counter is held by the database
	 * object itself. When 'common.references' goes to zero, that
	 * reference is released. When in turn 'references' goes to zero,
	 * the database is shut down and freed.
	 */
	isc_refcount_t references;

	dns_stats_t *rrsetstats;
	isc_stats_t *cachestats;

	uint32_t maxrrperset;	 /* Maximum RRs per RRset */
	uint32_t maxtypepername; /* Maximum number of RR types per owner */

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	/* Locked by tree_lock. */
	dns_qp_t *tree;

	size_t buckets_count;
	qpcache_bucket_t buckets[]; /* attribute((counted_by(buckets_count))) */
};

#ifdef DNS_DB_NODETRACE
#define qpcache_ref(ptr)   qpcache__ref(ptr, __func__, __FILE__, __LINE__)
#define qpcache_unref(ptr) qpcache__unref(ptr, __func__, __FILE__, __LINE__)
#define qpcache_attach(ptr, ptrp) \
	qpcache__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpcache_detach(ptrp) qpcache__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpcache);
#else
ISC_REFCOUNT_STATIC_DECL(qpcache);
#endif

/*%
 * Search Context
 */
typedef struct {
	qpcache_t *qpdb;
	unsigned int options;
	dns_qpchain_t chain;
	dns_qpiter_t iter;
	bool need_cleanup;
	qpcnode_t *zonecut;
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	isc_stdtime_t now;
} qpc_search_t;

#ifdef DNS_DB_NODETRACE
#define qpcnode_ref(ptr)   qpcnode__ref(ptr, __func__, __FILE__, __LINE__)
#define qpcnode_unref(ptr) qpcnode__unref(ptr, __func__, __FILE__, __LINE__)
#define qpcnode_attach(ptr, ptrp) \
	qpcnode__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpcnode_detach(ptrp) qpcnode__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpcnode);
#else
ISC_REFCOUNT_STATIC_DECL(qpcnode);
#endif

/*
 * Node methods forward declarations
 */
static void
qpcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG);
static void
qpcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG);
static void
qpcnode_expiredata(dns_dbnode_t *node, void *data);

static dns_dbnode_methods_t qpcnode_methods = (dns_dbnode_methods_t){
	.attachnode = qpcnode_attachnode,
	.detachnode = qpcnode_detachnode,
	.expiredata = qpcnode_expiredata,
};

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
	qpcnode_t *data = pval;
	qpcnode_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpcnode_t *data = pval;
	qpcnode_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	qpcnode_t *data = pval;
	return dns_qpkey_fromname(key, &data->name, data->nspace);
}

static void
qp_triename(void *uctx ISC_ATTR_UNUSED, char *buf, size_t size) {
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

typedef struct qpc_rditer {
	dns_rdatasetiter_t common;
	dns_rdataset_t *current;
	ISC_LIST(dns_rdataset_t) rdatasets;
} qpc_rditer_t;

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
dbiterator_seek3(dns_dbiterator_t *iterator,
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
	dbiterator_destroy, dbiterator_first,	dbiterator_last,
	dbiterator_seek,    dbiterator_seek3,	dbiterator_prev,
	dbiterator_next,    dbiterator_current, dbiterator_pause,
	dbiterator_origin
};

/*
 * In the cache, NSEC3 records are currently stored in the NORMAL
 * namespace.  If we ever implement synth-from-dnssec using NSEC3 records,
 * they'll need be moved into the NSEC3 namespace for efficiency, and
 * the iterator implementation will need to be more complex, as in
 * qpzone.
 */
typedef struct qpc_dbit {
	dns_dbiterator_t common;
	bool paused;
	isc_rwlocktype_t tree_locked;
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name;
	dns_qpiter_t iter;
	qpcnode_t *node;
} qpc_dbit_t;

static void
qpcache__destroy(qpcache_t *qpdb);

static dns_dbmethods_t qpdb_cachemethods;

static void
cleanup_deadnodes_cb(void *arg);

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
 * Cache-eviction routines.
 */

static size_t
header_delete(qpcnode_t *node, dns_slabheader_t *header);

static size_t
rdataset_size(dns_slabheader_t *header) {
	if (EXISTS(header)) {
		return dns_rdataslab_size(header);
	}

	return sizeof(*header);
}

static void
flush_node(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   isc_rwlocktype_t *tlocktypep, dns_expire_t reason DNS__DB_FLARG);

static size_t
expire_header(qpcache_t *qpdb, qpcnode_t *node, dns_slabheader_t *header,
	      isc_rwlocktype_t *nlocktypep,
	      isc_rwlocktype_t *tlocktypep DNS__DB_FLARG) {
	size_t expired = 0;

	if (header->related != NULL) {
		expired += header_delete(node, header->related);
	}
	expired += header_delete(node, header);

	flush_node(qpdb, node, nlocktypep, tlocktypep,
		   dns_expire_lru DNS__DB_FLARG_PASS);

	return expired;
}

static void
expire_lru_headers(qpcache_t *qpdb, dns_slabheader_t *newheader, uint32_t idx,
		   size_t requested, isc_rwlocktype_t *nlocktypep,
		   isc_rwlocktype_t *tlocktypep DNS__DB_FLARG) {
	size_t expired = 0;

	do {
		dns_slabheader_t *header = ISC_SIEVE_NEXT(
			qpdb->buckets[idx].sieve, visited, lrulink);
		if (header == NULL) {
			return;
		}

		/* newheader is protected from removal */
		if (header == newheader || header->related == newheader) {
			return;
		}

		qpcnode_t *node = HEADERNODE(header);

		expired += expire_header(qpdb, node, header, nlocktypep,
					 tlocktypep DNS__DB_FLARG_PASS);

	} while (expired < requested);
}

static void
qpcache_miss(qpcache_t *qpdb, dns_slabheader_t *newheader,
	     isc_rwlocktype_t *nlocktypep,
	     isc_rwlocktype_t *tlocktypep DNS__DB_FLARG) {
	uint32_t idx = HEADERNODE(newheader)->locknum;

	if (isc_mem_isovermem(qpdb->common.mctx)) {
		/*
		 * Maximum estimated size of the data being added: The size
		 * of the rdataset, plus a new QP database node and nodename,
		 * and a possible additional NSEC node and nodename. Also add
		 * a 12k margin for a possible QP-trie chunk allocation.
		 * (It's okay to overestimate, we want to get cache memory
		 * down quickly.)
		 */

		size_t purgesize =
			2 * (sizeof(qpcnode_t) +
			     dns_name_size(&HEADERNODE(newheader)->name)) +
			rdataset_size(newheader) + QP_SAFETY_MARGIN;

		expire_lru_headers(qpdb, newheader, idx, purgesize, nlocktypep,
				   tlocktypep DNS__DB_FLARG_PASS);
	}

	ISC_SIEVE_INSERT(qpdb->buckets[idx].sieve, newheader, lrulink);
}

static void
qpcache_hit(qpcache_t *qpdb ISC_ATTR_UNUSED, dns_slabheader_t *header) {
	ISC_SIEVE_MARK(header, visited);
	if (header->related) {
		ISC_SIEVE_MARK(header->related, visited);
	}
}

/*
 * DB Routines
 */

/*
 * tree_lock(write) must be held.
 */
static void
delete_node(qpcache_t *qpdb, qpcnode_t *node) {
	isc_result_t result = ISC_R_UNEXPECTED;

	if (isc_log_wouldlog(ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL))) {
		char printname[DNS_NAME_FORMATSIZE];
		dns_name_format(&node->name, printname, sizeof(printname));
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL),
			      "delete_node(): %p %s (bucket %d)", node,
			      printname, node->locknum);
	}

	switch (node->nspace) {
	case DNS_DBNAMESPACE_NORMAL:
		if (node->havensec) {
			/*
			 * Delete the corresponding node from the auxiliary NSEC
			 * tree before deleting from the main tree.
			 */
			result = dns_qp_deletename(qpdb->tree, &node->name,
						   DNS_DBNAMESPACE_NSEC, NULL,
						   NULL);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(DNS_LOGCATEGORY_DATABASE,
					      DNS_LOGMODULE_CACHE,
					      ISC_LOG_WARNING,
					      "delete_node(): "
					      "dns_qp_deletename: %s",
					      isc_result_totext(result));
			}
		}
		result = dns_qp_deletename(qpdb->tree, &node->name,
					   node->nspace, NULL, NULL);
		break;
	case DNS_DBNAMESPACE_NSEC:
		result = dns_qp_deletename(qpdb->tree, &node->name,
					   node->nspace, NULL, NULL);
		break;
	}
	if (result != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      ISC_LOG_WARNING,
			      "delete_node(): "
			      "dns_qp_deletename: %s",
			      isc_result_totext(result));
	}
}

/*
 * The caller must specify its currect node and tree lock status.
 * It's okay for neither lock to be held if there are existing external
 * references to the node, but if this is the first external reference,
 * then the caller must be holding at least one lock.
 *
 * If incrementing erefs from zero, we also increment the node use counter
 * in the qpcache object.
 *
 * This function is called from qpcnode_acquire(), so that internal
 * and external references are acquired at the same time, and from
 * qpcnode_release() when we only need to increase the internal references.
 */
static void
qpcnode_erefs_increment(qpcache_t *qpdb, qpcnode_t *node,
			isc_rwlocktype_t nlocktype,
			isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_increment0(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#endif

	if (refs > 0) {
		return;
	}

	/*
	 * this is the first external reference to the node.
	 *
	 * we need to hold the node or tree lock to avoid
	 * incrementing the reference count while also deleting
	 * the node. delete_node() is always protected by both
	 * tree and node locks being write-locked.
	 */
	INSIST(nlocktype != isc_rwlocktype_none ||
	       tlocktype != isc_rwlocktype_none);

	qpcache_ref(qpdb);
}

static void
qpcnode_acquire(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t nlocktype,
		isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	qpcnode_ref(node);
	qpcnode_erefs_increment(qpdb, node, nlocktype,
				tlocktype DNS__DB_FLARG_PASS);
}

/*
 * Decrement the external references to a node. If the counter
 * goes to zero, decrement the node use counter in the qpcache object
 * as well, and return true. Otherwise return false.
 */
static bool
qpcnode_erefs_decrement(qpcache_t *qpdb, qpcnode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif
	if (refs > 1) {
		return false;
	}

	qpcache_unref(qpdb);
	return true;
}

/*
 * Caller must be holding a node lock, either read or write.
 *
 * Note that the lock must be held even when node references are
 * atomically modified; in that case the decrement operation itself does not
 * have to be protected, but we must avoid a race condition where multiple
 * threads are decreasing the reference to zero simultaneously and at least
 * one of them is going to free the node.
 *
 * This calls dec_erefs() to decrement the external node reference counter,
 * (and possibly the node use counter), cleans up and deletes the node
 * if necessary, then decrements the internal reference counter as well.
 */
static void
qpcnode_release(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
		isc_rwlocktype_t *tlocktypep DNS__DB_FLARG) {
	REQUIRE(*nlocktypep != isc_rwlocktype_none);

	if (!qpcnode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS)) {
		goto unref;
	}

	/* Handle easy and typical case first. */
	if (!cds_list_empty(&node->headers)) {
		goto unref;
	}

	if (*nlocktypep == isc_rwlocktype_read) {
		/*
		 * The external reference count went to zero and the node
		 * is dirty or has no data, so we might want to delete it.
		 * To do that, we'll need a write lock. If we don't already
		 * have one, we have to make sure nobody else has
		 * acquired a reference in the meantime, so we increment
		 * erefs (but NOT references!), upgrade the node lock,
		 * decrement erefs again, and see if it's still zero.
		 *
		 * We can't really assume anything about the result code of
		 * erefs_increment.  If another thread acquires reference it
		 * will be larger than 0, if it doesn't it is going to be 0.
		 */
		isc_rwlock_t *nlock = &qpdb->buckets[node->locknum].lock;
		qpcnode_erefs_increment(qpdb, node, *nlocktypep,
					*tlocktypep DNS__DB_FLARG_PASS);
		NODE_FORCEUPGRADE(nlock, nlocktypep);
		if (!qpcnode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS)) {
			goto unref;
		}
	}

	if (!cds_list_empty(&node->headers)) {
		goto unref;
	}

	if (*tlocktypep == isc_rwlocktype_write) {
		/*
		 * We can delete the node if we have the tree write lock.
		 */
		delete_node(qpdb, node);
	} else {
		/*
		 * If we don't have the tree lock, we will add this node to a
		 * linked list of nodes in this locking bucket which we will
		 * free later.
		 */
		qpcnode_acquire(qpdb, node, *nlocktypep,
				*tlocktypep DNS__DB_FLARG_PASS);

		isc_queue_node_init(&node->deadlink);
		if (!isc_queue_enqueue_entry(
			    &qpdb->buckets[node->locknum].deadnodes, node,
			    deadlink))
		{
			/* Queue was empty, trigger new cleaning */
			isc_loop_t *loop = isc_loop_get(node->locknum);

			qpcache_ref(qpdb);
			isc_async_run(loop, cleanup_deadnodes_cb, qpdb);
		}
	}

unref:
	qpcnode_unref(node);
}

static void
update_rrsetstats(dns_stats_t *stats, const dns_typepair_t typepair,
		  const uint_least16_t hattributes, const bool increment) {
	dns_rdatastatstype_t statattributes = 0;
	dns_rdatastatstype_t base = 0;
	dns_rdatastatstype_t type;
	dns_slabheader_t *header = &(dns_slabheader_t){
		.typepair = typepair,
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
			base = DNS_TYPEPAIR_TYPE(header->typepair);
		}
	} else {
		base = DNS_TYPEPAIR_TYPE(header->typepair);
	}

	if (STALE(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_STALE;
	}

	type = DNS_RDATASTATSTYPE_VALUE(base, statattributes);
	if (increment) {
		dns_rdatasetstats_increment(stats, type);
	} else {
		dns_rdatasetstats_decrement(stats, type);
	}
}

static void
mark(dns_slabheader_t *header, uint_least16_t flag) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;
	qpcache_t *qpdb = HEADERNODE(header)->qpdb;

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
	update_rrsetstats(qpdb->rrsetstats, header->typepair, attributes,
			  false);
	update_rrsetstats(qpdb->rrsetstats, header->typepair, newattributes,
			  true);
}

static void
setttl(dns_slabheader_t *header, isc_stdtime_t newts) {
	header->expire = newts;
}

static size_t
header_delete(qpcnode_t *node, dns_slabheader_t *header) {
	/* The slabheader has already been removed from the node headers */
	if (cds_list_empty(&header->headers_link)) {
		return 0;
	}

	size_t expired = rdataset_size(header);
	qpcache_t *qpdb = node->qpdb;

	cds_list_del_init(&header->headers_link);

	/*
	 * This place is the only place where we actually need header->typepair.
	 */
	update_rrsetstats(qpdb->rrsetstats, header->typepair,
			  atomic_load_acquire(&header->attributes), false);

	ISC_SIEVE_UNLINK(qpdb->buckets[node->locknum].sieve, header, lrulink);

	if (header->related != NULL) {
		INSIST(header->related->related == header);
		dns_slabheader_detach(&header->related->related);
		dns_slabheader_detach(&header->related);
	}

	dns_slabheader_detach(&header);

	return expired;
}

/*
 * Caller must hold the node (write) lock.
 */

static void
flush_node(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   isc_rwlocktype_t *tlocktypep, dns_expire_t reason DNS__DB_FLARG) {
	if (isc_refcount_current(&node->erefs) != 0) {
		return;
	}

	/*
	 * If no one else is using the node, we can clean it up now.
	 * We first need to gain a new reference to the node to meet a
	 * requirement of qpcnode_release().
	 */
	qpcnode_acquire(qpdb, node, *nlocktypep,
			*tlocktypep DNS__DB_FLARG_PASS);
	qpcnode_release(qpdb, node, nlocktypep, tlocktypep DNS__DB_FLARG_PASS);

	if (qpdb->cachestats == NULL) {
		return;
	}

	switch (reason) {
	case dns_expire_lru:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_deletelru);
		break;
	default:
		break;
	}
}

static void
update_cachestats(qpcache_t *qpdb, isc_result_t result) {
	if (qpdb->cachestats == NULL) {
		return;
	}

	switch (result) {
	case DNS_R_COVERINGNSEC:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_coveringnsec);
		FALLTHROUGH;
	case ISC_R_SUCCESS:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_hits);
		break;
	default:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_misses);
	}
}

static void
bindrdataset(qpcache_t *qpdb, qpcnode_t *node, dns_slabheader_t *header,
	     isc_stdtime_t now, isc_rwlocktype_t nlocktype,
	     isc_rwlocktype_t tlocktype,
	     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	bool stale = STALE(header);

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

	dns_slabheader_ref(header);

	qpcnode_acquire(qpdb, node, nlocktype, tlocktype DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (!ZEROTTL(header) && KEEPSTALE(qpdb) && stale_ttl > now) {
			stale = true;
		}
	}

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	if (NEGATIVE(header)) {
		rdataset->type = dns_rdatatype_none;
		rdataset->covers = DNS_TYPEPAIR_TYPE(header->typepair);
		INSIST(DNS_TYPEPAIR_COVERS(header->typepair) ==
		       dns_rdatatype_none);
	} else {
		rdataset->type = DNS_TYPEPAIR_TYPE(header->typepair);
		rdataset->covers = DNS_TYPEPAIR_COVERS(header->typepair);
	}
	rdataset->ttl = !ZEROTTL(header) ? header->expire - now : 0;
	rdataset->trust = atomic_load(&header->trust);
	rdataset->resign = 0;

	if (NEGATIVE(header)) {
		rdataset->attributes.negative = true;
	}
	if (NXDOMAIN(header)) {
		rdataset->attributes.nxdomain = true;
	}
	if (OPTOUT(header)) {
		rdataset->attributes.optout = true;
	}
	if (PREFETCH(header)) {
		rdataset->attributes.prefetch = true;
	}

	if (stale) {
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);
		if (stale_ttl > now) {
			rdataset->ttl = stale_ttl - now;
		} else {
			rdataset->ttl = 0;
		}
		if (STALE_WINDOW(header)) {
			rdataset->attributes.stale_window = true;
		}
		rdataset->attributes.stale = true;
		rdataset->expire = header->expire;
	} else if (!ACTIVE(header, now)) {
		/*
		 * The entry is expired but still present in the cache (it has
		 * not yet been removed); flag it so that, e.g., a cache dump
		 * including expired entries can mark it.
		 */
		rdataset->attributes.ancient = true;
		rdataset->ttl = 0;
	}

	rdataset->slab.node = (dns_dbnode_t *)node;
	rdataset->slab.raw = header->raw;
	rdataset->slab.iter_pos = NULL;
	rdataset->slab.iter_count = 0;

	/*
	 * Add noqname proof.
	 */
	rdataset->slab.noqname = header->noqname;
	if (header->noqname != NULL) {
		rdataset->attributes.noqname = true;
	}
	rdataset->slab.closest = header->closest;
	if (header->closest != NULL) {
		rdataset->attributes.closest = true;
	}
}

static void
bindrdatasets(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *found,
	      dns_slabheader_t *foundsig, isc_stdtime_t now,
	      isc_rwlocktype_t nlocktype, isc_rwlocktype_t tlocktype,
	      dns_rdataset_t *rdataset,
	      dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	bindrdataset(qpdb, qpnode, found, now, nlocktype, tlocktype,
		     rdataset DNS__DB_FLARG_PASS);
	qpcache_hit(qpdb, found);
	if (!NEGATIVE(found) && foundsig != NULL) {
		bindrdataset(qpdb, qpnode, foundsig, now, nlocktype, tlocktype,
			     sigrdataset DNS__DB_FLARG_PASS);
		qpcache_hit(qpdb, foundsig);
	}
}

static isc_result_t
setup_delegation(qpc_search_t *search, dns_dbnode_t **nodep,
		 dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		 isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	dns_typepair_t typepair;
	qpcnode_t *node = NULL;

	REQUIRE(search != NULL);
	REQUIRE(search->zonecut != NULL);
	REQUIRE(search->zonecut_header != NULL);

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	typepair = search->zonecut_header->typepair;

	if (nodep != NULL) {
		/*
		 * Note that we don't have to increment the node's reference
		 * count here because we're going to use the reference we
		 * already have in the search block.
		 */
		*nodep = (dns_dbnode_t *)node;
		search->need_cleanup = false;
	}
	if (rdataset != NULL) {
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		isc_rwlock_t *nlock =
			&search->qpdb->buckets[node->locknum].lock;
		NODE_RDLOCK(nlock, &nlocktype);
		bindrdatasets(search->qpdb, node, search->zonecut_header,
			      search->zonecut_sigheader, search->now, nlocktype,
			      tlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (typepair == DNS_TYPEPAIR_VALUE(dns_rdatatype_dname, 0)) {
		return DNS_R_DNAME;
	}
	return DNS_R_DELEGATION;
}

static bool
check_stale_header(dns_slabheader_t *header, qpc_search_t *search) {
	if (ACTIVE(header, search->now)) {
		return false;
	}

	isc_stdtime_t stale = header->expire + STALE_TTL(header, search->qpdb);
	/*
	 * If this data is in the stale window keep it and if
	 * DNS_DBFIND_STALEOK is not set we tell the caller to
	 * skip this record.  We skip the records with ZEROTTL
	 * (these records should not be cached anyway).
	 */

	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_STALE_WINDOW);
	if (!ZEROTTL(header) && KEEPSTALE(search->qpdb) && stale > search->now)
	{
		mark(header, DNS_SLABHEADERATTR_STALE);
		/*
		 * If DNS_DBFIND_STALESTART is set then it means we
		 * failed to resolve the name during recursion, in
		 * this case we mark the time in which the refresh
		 * failed.
		 */
		if ((search->options & DNS_DBFIND_STALESTART) != 0) {
			atomic_store_release(&header->last_refresh_fail_ts,
					     search->now);
		} else if ((search->options & DNS_DBFIND_STALEENABLED) != 0 &&
			   search->now <
				   (atomic_load_acquire(
					    &header->last_refresh_fail_ts) +
				    search->qpdb->serve_stale_refresh))
		{
			/*
			 * If we are within interval between last
			 * refresh failure time + 'stale-refresh-time',
			 * then don't skip this stale entry but use it
			 * instead.
			 */
			DNS_SLABHEADER_SETATTR(header,
					       DNS_SLABHEADERATTR_STALE_WINDOW);
			return false;
		} else if ((search->options & DNS_DBFIND_STALETIMEOUT) != 0) {
			/*
			 * We want stale RRset due to timeout, so we
			 * don't skip it.
			 */
			return false;
		}
		return (search->options & DNS_DBFIND_STALEOK) == 0;
	}

	return true;
}

static bool
invalid_header(dns_slabheader_t *header, qpc_search_t *search) {
	return header == NULL || check_stale_header(header, search) ||
	       !EXISTS(header);
}

/*
 * Return true if we've found headers for both 'type' and RRSIG('type'),
 * or (optionally, if 'negtype' is nonzero) if we've found a single
 * negative header covering either 'negtype' or ANY.
 */
static bool
related_headers(dns_slabheader_t *header, dns_slabheader_t *sigheader,
		dns_typepair_t typepair, dns_slabheader_t **foundp,
		dns_slabheader_t **foundsigp) {
	if (header != NULL) {
		REQUIRE(DNS_TYPEPAIR_TYPE(header->typepair) !=
			dns_rdatatype_rrsig);
		REQUIRE(DNS_TYPEPAIR_COVERS(header->typepair) ==
			dns_rdatatype_none);
	}
	if (sigheader != NULL) {
		REQUIRE(DNS_TYPEPAIR_TYPE(sigheader->typepair) ==
			dns_rdatatype_rrsig);
		REQUIRE(DNS_TYPEPAIR_COVERS(sigheader->typepair) !=
				dns_rdatatype_none ||
			NEGATIVE(sigheader));
	}

	/*
	 * Nothing exists if there's a NEGATIVE(dns_typepair_any).
	 */
	if (header != NULL && header->typepair == dns_typepair_any) {
		INSIST(NEGATIVE(header));
		INSIST(sigheader == NULL);
		*foundp = header;
		*foundsigp = NULL;
		return true;
	}

	/*
	 * Use the sigheader if we are looking for RRSIG.
	 */
	if (DNS_TYPEPAIR_TYPE(typepair) == dns_rdatatype_rrsig) {
		if (sigheader == NULL) {
			return false;
		}

		REQUIRE(EXISTS(sigheader));
		if (sigheader->typepair == typepair) {
			*foundp = sigheader;
			*foundsigp = NULL;
			return true;
		}
		return false;
	} else {
		if (header == NULL) {
			return false;
		}

		REQUIRE(EXISTS(header));
		REQUIRE(!NEGATIVE(header) || sigheader == NULL);

		if (header->typepair == typepair) {
			*foundp = header;
			*foundsigp = sigheader;
			return true;
		}
	}

	return false;
}

static void
store_headers(dns_slabheader_t *tmp, dns_slabheader_t **headerp,
	      dns_slabheader_t **sigheaderp, qpc_search_t *search) {
	dns_slabheader_t *header = NULL, *sigheader = NULL;
	if (DNS_TYPEPAIR_TYPE(tmp->typepair) == dns_rdatatype_rrsig) {
		header = tmp->related;
		sigheader = tmp;
	} else {
		header = tmp;
		sigheader = tmp->related;
	}

	if (invalid_header(header, search)) {
		return;
	}

	*headerp = header;

	if (invalid_header(sigheader, search)) {
		return;
	}
	*sigheaderp = sigheader;
}

static void
find_headers(qpcnode_t *node, qpc_search_t *search, dns_rdatatype_t type,
	     dns_slabheader_t **foundp, dns_slabheader_t **foundsigp) {
	DNS_SLABHEADER_FOREACH(tmp, &node->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		if (tmp->typepair == dns_typepair_any) {
			INSIST(tmp->related == NULL);
			INSIST(NEGATIVE(tmp));
			if (invalid_header(tmp, search)) {
				/*
				 * NEGATIVE(ANY), but it is no longer valid.
				 */
				continue;
			}
			*foundp = NULL;
			*foundsigp = NULL;
			return;
		}

		if (tmp->typepair != DNS_TYPEPAIR(type) &&
		    tmp->typepair != DNS_SIGTYPEPAIR(type))
		{
			/* Not our type; continue with next slabtop */
			continue;
		}

		store_headers(tmp, &header, &sigheader, search);

		/*
		 * This function only sets positive headers.
		 */
		if (header != NULL && !NEGATIVE(header)) {
			*foundp = header;
			*foundsigp = sigheader;
		}

		return;
	}
}

static isc_result_t
check_dname(qpcnode_t *node, void *arg DNS__DB_FLARG) {
	qpc_search_t *search = arg;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	isc_result_t result;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(search->zonecut == NULL);

	nlock = &search->qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	find_headers(node, search, dns_rdatatype_dname, &found, &foundsig);

	if (found != NULL && (!DNS_TRUST_PENDING(atomic_load(&found->trust)) ||
			      (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_header will still be valid later.
		 */
		qpcnode_acquire(search->qpdb, node, nlocktype,
				isc_rwlocktype_none DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = found;
		search->zonecut_sigheader = foundsig;
		search->need_cleanup = true;
		result = DNS_R_PARTIALMATCH;
	} else {
		result = DNS_R_CONTINUE;
	}

	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

/*
 * Look for a potentially covering NSEC in the cache where `name`
 * is known not to exist.  This uses the auxiliary NSEC tree to find
 * the potential NSEC owner. If found, we update 'foundname', 'nodep',
 * 'rdataset' and 'sigrdataset', and return DNS_R_COVERINGNSEC.
 * Otherwise, return ISC_R_NOTFOUND.
 */
static isc_result_t
find_coveringnsec(qpc_search_t *search, const dns_name_t *name,
		  dns_dbnode_t **nodep, dns_name_t *foundname,
		  dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_fixedname_t fpredecessor, fixed;
	dns_name_t *predecessor = NULL, *fname = NULL;
	qpcnode_t *node = NULL;
	dns_qpiter_t iter;
	isc_result_t result;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;

	/*
	 * Look for the node in the auxiliary NSEC namespace.
	 */
	result = dns_qp_lookup(search->qpdb->tree, name, DNS_DBNAMESPACE_NSEC,
			       &iter, NULL, (void **)&node, NULL);
	/*
	 * When DNS_R_PARTIALMATCH or ISC_R_NOTFOUND is returned from
	 * dns_qp_lookup there is potentially a covering NSEC present
	 * in the cache so we need to search for it.  Otherwise we are
	 * done here.
	 */
	if (result != DNS_R_PARTIALMATCH && result != ISC_R_NOTFOUND) {
		return ISC_R_NOTFOUND;
	}

	fname = dns_fixedname_initname(&fixed);
	predecessor = dns_fixedname_initname(&fpredecessor);

	/*
	 * Extract predecessor from iterator.
	 */
	result = dns_qpiter_current(&iter, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		return ISC_R_NOTFOUND;
	}
	dns_name_copy(&node->name, predecessor);

	/*
	 * Lookup the predecessor in the normal namespace.
	 */
	node = NULL;
	RETERR(dns_qp_getname(search->qpdb->tree, predecessor,
			      DNS_DBNAMESPACE_NORMAL, (void **)&node, NULL));
	dns_name_copy(&node->name, fname);

	nlock = &search->qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	find_headers(node, search, dns_rdatatype_nsec, &found, &foundsig);

	if (found != NULL) {
		if (nodep != NULL) {
			qpcnode_acquire(search->qpdb, node, nlocktype,
					isc_rwlocktype_none DNS__DB_FLARG_PASS);
			*nodep = (dns_dbnode_t *)node;
		}
		bindrdatasets(search->qpdb, node, found, foundsig, search->now,
			      nlocktype, isc_rwlocktype_none, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
		dns_name_copy(fname, foundname);

		result = DNS_R_COVERINGNSEC;
	} else {
		result = ISC_R_NOTFOUND;
	}
	NODE_UNLOCK(nlock, &nlocktype);
	return result;
}

static inline bool
missing_answer(dns_slabheader_t *found, unsigned int options) {
	if (found == NULL) {
		return true;
	}

	dns_trust_t trust = atomic_load(&found->trust);
	return (DNS_TRUST_ADDITIONAL(trust) &&
		(options & DNS_DBFIND_ADDITIONALOK) == 0) ||
	       (DNS_TRUST_GLUE(trust) && (options & DNS_DBFIND_GLUEOK) == 0) ||
	       (DNS_TRUST_PENDING(trust) &&
		(options & DNS_DBFIND_PENDINGOK) == 0);
}

static void
qpc_search_init(qpc_search_t *search, qpcache_t *db, unsigned int options,
		isc_stdtime_t now) {
	/*
	 * qpc_search_t contains two structures with large buffers (dns_qpiter_t
	 * and dns_qpchain_t). Those two structures will be initialized later by
	 * dns_qp_lookup anyway.
	 * To avoid the overhead of zero initialization, we avoid designated
	 * initializers and initialize all "small" fields manually.
	 */
	search->qpdb = (qpcache_t *)db;
	search->options = options;
	/*
	 * qpch->in - Init by dns_qp_lookup
	 * qpiter - Init by dns_qp_lookup
	 */
	search->need_cleanup = false;
	search->now = now ? now : isc_stdtime_now();
	search->zonecut = NULL;
	search->zonecut_header = NULL;
	search->zonecut_sigheader = NULL;
}

static isc_result_t
qpcache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	     dns_rdatatype_t type, unsigned int options, isc_stdtime_t __now,
	     dns_dbnode_t **nodep, dns_name_t *foundname,
	     dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
	     dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpcnode_t *node = NULL;
	isc_result_t result;
	bool cname_ok = true;
	bool found_noqname = false;
	bool all_negative = true;
	bool empty_node = true;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_slabheader_t *nsecheader = NULL, *nsecsig = NULL;
	dns_typepair_t typepair = DNS_TYPEPAIR(type);

	if (type == dns_rdatatype_none) {
		/* We can't search negative cache directly */
		return ISC_R_NOTFOUND;
	}

	qpc_search_t search;
	qpc_search_init(&search, (qpcache_t *)db, options, __now);

	REQUIRE(VALID_QPDB((qpcache_t *)db));
	REQUIRE(version == NULL);

	TREE_RDLOCK(&search.qpdb->tree_lock, &tlocktype);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(search.qpdb->tree, name, DNS_DBNAMESPACE_NORMAL,
			       NULL, &search.chain, (void **)&node, NULL);
	if (result != ISC_R_NOTFOUND && foundname != NULL) {
		dns_name_copy(&node->name, foundname);
	}

	/*
	 * Check the QP chain to see if there's a node above us with an
	 * active DNAME rdataset.
	 *
	 * We're only interested in nodes above QNAME, so if the result
	 * was success, then we skip the last item in the chain.
	 */
	unsigned int len = dns_qpchain_length(&search.chain);
	if (result == ISC_R_SUCCESS) {
		len--;
	}

	for (unsigned int i = 0; i < len; i++) {
		isc_result_t tresult;
		qpcnode_t *encloser = NULL;

		dns_qpchain_node(&search.chain, i, (void **)&encloser, NULL);

		tresult = check_dname(encloser,
				      (void *)&search DNS__DB_FLARG_PASS);
		if (tresult != DNS_R_CONTINUE) {
			result = DNS_R_PARTIALMATCH;
			search.chain.len = i - 1;
			node = encloser;
			if (foundname != NULL) {
				dns_name_copy(&node->name, foundname);
			}
			break;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		/*
		 * If we discovered a covering DNAME skip looking for a covering
		 * NSEC.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    (search.zonecut_header == NULL ||
		     search.zonecut_header->typepair != dns_rdatatype_dname))
		{
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		if (search.zonecut != NULL) {
			result = setup_delegation(&search, nodep, rdataset,
						  sigrdataset,
						  tlocktype DNS__DB_FLARG_PASS);
			goto tree_exit;
		} else {
			result = ISC_R_NOTFOUND;
			goto tree_exit;
		}
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5).
	 */
	if (type == dns_rdatatype_nsec || type == dns_rdatatype_rrsig) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	nlock = &search.qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	DNS_SLABHEADER_FOREACH(tmp, &node->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		store_headers(tmp, &header, &sigheader, &search);

		if (header == NULL && sigheader == NULL) {
			continue;
		}

		/*
		 * We now know that there is at least one active
		 * rdataset at this node.
		 */
		empty_node = false;

		if (header != NULL && header->noqname != NULL &&
		    atomic_load(&header->trust) == dns_trust_secure)
		{
			found_noqname = true;
		}

		if (header != NULL && !NEGATIVE(header)) {
			all_negative = false;
		}

		if (sigheader != NULL && !NEGATIVE(sigheader)) {
			all_negative = false;
		}

		if (related_headers(header, sigheader, typepair, &found,
				    &foundsig))
		{
			/*
			 * We can't exit early until we have an answer with
			 * sufficient trust level - see missing_answer()
			 * for details - because we might need NS or NSEC
			 * records.
			 */
			if (missing_answer(found, options) || STALE(found)) {
				continue;
			}

			/* We found something, continue with next header */
			break;
		}

		if (header == NULL || NEGATIVE(header)) {
			/*
			 * We are not interested in the negative headers for the
			 * auxiliary types, only for the main type we are
			 * looking for.
			 */
			continue;
		}

		switch (tmp->typepair) {
		case dns_rdatatype_cname:
		case DNS_SIGTYPEPAIR(dns_rdatatype_cname):
			if (cname_ok) {
				found = header;
				foundsig = sigheader;
			}
			break;

		case dns_rdatatype_nsec:
		case DNS_SIGTYPEPAIR(dns_rdatatype_nsec):
			nsecheader = header;
			nsecsig = sigheader;
			break;

		default:
			if (typepair == dns_typepair_any) {
				/* QTYPE==ANY, so any anwers will do */
				found = header;
				break;
			}
		}

		if (!missing_answer(found, options) && !STALE(found)) {
			break;
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		NODE_UNLOCK(nlock, &nlocktype);
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0) {
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}

		result = ISC_R_NOTFOUND;
		goto tree_exit;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (missing_answer(found, options)) {
		/*
		 * Return covering NODATA NSEC record.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    nsecheader != NULL)
		{
			if (nodep != NULL) {
				qpcnode_acquire(search.qpdb, node, nlocktype,
						tlocktype DNS__DB_FLARG_PASS);
				*nodep = (dns_dbnode_t *)node;
			}
			bindrdatasets(search.qpdb, node, nsecheader, nsecsig,
				      search.now, nlocktype, tlocktype,
				      rdataset, sigrdataset DNS__DB_FLARG_PASS);
			result = DNS_R_COVERINGNSEC;
			goto node_exit;
		}

		/*
		 * This name was from a wild card.  Look for a covering NSEC.
		 */
		if (found == NULL && (found_noqname || all_negative) &&
		    (search.options & DNS_DBFIND_COVERINGNSEC) != 0)
		{
			NODE_UNLOCK(nlock, &nlocktype);
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result != DNS_R_COVERINGNSEC) {
				result = ISC_R_NOTFOUND;
			}
			goto tree_exit;
		}

		result = ISC_R_NOTFOUND;
		goto node_exit;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		qpcnode_acquire(search.qpdb, node, nlocktype,
				tlocktype DNS__DB_FLARG_PASS);
		*nodep = (dns_dbnode_t *)node;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	} else if (typepair != found->typepair &&
		   typepair != dns_typepair_any &&
		   found->typepair == DNS_TYPEPAIR(dns_rdatatype_cname))
	{
		/*
		 * We weren't doing an ANY query and we found a CNAME instead
		 * of the type we were looking for, so we need to indicate
		 * that result to the caller.
		 */
		result = DNS_R_CNAME;
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = ISC_R_SUCCESS;
	}

	if (typepair != dns_typepair_any || result == DNS_R_NCACHENXDOMAIN ||
	    result == DNS_R_NCACHENXRRSET)
	{
		bindrdatasets(search.qpdb, node, found, foundsig, search.now,
			      nlocktype, tlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
	}

node_exit:
	NODE_UNLOCK(nlock, &nlocktype);

tree_exit:
	TREE_UNLOCK(&search.qpdb->tree_lock, &tlocktype);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);
		nlock = &search.qpdb->buckets[node->locknum].lock;

		NODE_RDLOCK(nlock, &nlocktype);
		qpcnode_release(search.qpdb, node, &nlocktype,
				&tlocktype DNS__DB_FLARG_PASS);
		NODE_UNLOCK(nlock, &nlocktype);
		INSIST(tlocktype == isc_rwlocktype_none);
	}

	update_cachestats(search.qpdb, result);
	return result;
}

static isc_result_t
qpcache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     dns_rdatatype_t type, dns_rdatatype_t covers,
		     isc_stdtime_t __now, dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_typepair_t typepair, sigpair;
	isc_result_t result = ISC_R_SUCCESS;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	qpc_search_t search = (qpc_search_t){
		.qpdb = (qpcache_t *)db,
		.now = __now ? __now : isc_stdtime_now(),
	};

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);
	REQUIRE(type != dns_rdatatype_any);

	if (type == dns_rdatatype_none) {
		/* We can't search negative cache directly */
		return ISC_R_NOTFOUND;
	}

	nlock = &qpdb->buckets[qpnode->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	typepair = DNS_TYPEPAIR_VALUE(type, covers);
	sigpair = (type != dns_rdatatype_rrsig) ? DNS_SIGTYPEPAIR(type)
						: dns_typepair_none;

	DNS_SLABHEADER_FOREACH(tmp, &qpnode->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		if (tmp->typepair != typepair && tmp->typepair != sigpair &&
		    tmp->typepair != dns_typepair_any)
		{
			continue;
		}

		store_headers(tmp, &header, &sigheader, &search);

		(void)related_headers(header, sigheader, typepair, &found,
				      &foundsig);
		break;
	}

	if (found != NULL) {
		bindrdatasets(qpdb, qpnode, found, foundsig, search.now,
			      nlocktype, isc_rwlocktype_none, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (found == NULL) {
		return ISC_R_NOTFOUND;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	}

	update_cachestats(qpdb, result);

	return result;
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &qpdb->cachestats);
	return ISC_R_SUCCESS;
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	return qpdb->rrsetstats;
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->common.serve_stale_ttl = ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*ttl = qpdb->common.serve_stale_ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->serve_stale_refresh = interval;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*interval = qpdb->serve_stale_refresh;
	return ISC_R_SUCCESS;
}

static void
qpcnode_expiredata(dns_dbnode_t *node, void *data) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = (qpcache_t *)qpnode->qpdb;

	dns_slabheader_t *header = data;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	(void)expire_header(qpdb, qpnode, header, &nlocktype,
			    &tlocktype DNS__DB_FILELINE);
	NODE_UNLOCK(nlock, &nlocktype);
	INSIST(tlocktype == isc_rwlocktype_none);
}

static void
qpcache__destroy(qpcache_t *qpdb) {
	unsigned int i;
	char buf[DNS_NAME_FORMATSIZE];

	dns_qp_destroy(&qpdb->tree);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
	} else {
		strlcpy(buf, "<UNKNOWN>", sizeof(buf));
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
		      ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL), "done %s(%s)",
		      __func__, buf);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}
	for (i = 0; i < qpdb->buckets_count; i++) {
		NODE_DESTROYLOCK(&qpdb->buckets[i].lock);

		INSIST(ISC_SIEVE_EMPTY(qpdb->buckets[i].sieve));

		INSIST(isc_queue_empty(&qpdb->buckets[i].deadnodes));
		isc_queue_destroy(&qpdb->buckets[i].deadnodes);
	}

	dns_stats_detach(&qpdb->rrsetstats);

	if (qpdb->cachestats != NULL) {
		isc_stats_detach(&qpdb->cachestats);
	}

	TREE_DESTROYLOCK(&qpdb->tree_lock);
	isc_refcount_destroy(&qpdb->references);
	isc_refcount_destroy(&qpdb->common.references);

	isc_rwlock_destroy(&qpdb->lock);
	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb,
			     sizeof(*qpdb) + qpdb->buckets_count *
						     sizeof(qpdb->buckets[0]));
}

static void
qpcache_destroy(dns_db_t *arg) {
	qpcache_t *qpdb = (qpcache_t *)arg;

	qpcache_detach(&qpdb);
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not or chose not to delete
 * them when we deleted all the data at that node because we did not want
 * to wait for the tree write lock.
 */
static void
cleanup_deadnodes(qpcache_t *qpdb, uint16_t locknum) {
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[locknum].lock;
	qpcnode_t *qpnode = NULL, *qpnext = NULL;
	isc_queue_t deadnodes;

	INSIST(locknum < qpdb->buckets_count);

	isc_queue_init(&deadnodes);

	TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
	NODE_WRLOCK(nlock, &nlocktype);

	isc_queue_splice(&deadnodes, &qpdb->buckets[locknum].deadnodes);
	isc_queue_for_each_entry_safe(&deadnodes, qpnode, qpnext, deadlink) {
		qpcnode_release(qpdb, qpnode, &nlocktype,
				&tlocktype DNS__DB_FILELINE);
	}

	NODE_UNLOCK(nlock, &nlocktype);
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
}

static void
cleanup_deadnodes_cb(void *arg) {
	qpcache_t *qpdb = arg;
	uint16_t locknum = isc_tid();

	cleanup_deadnodes(qpdb, locknum);
	qpcache_unref(qpdb);
}
/*
 * This function is assumed to be called when a node is newly referenced
 * and can be in the deadnode list.  In that case the node will be references
 * and cleanup_deadnodes() will remove it from the list when the cleaning
 * happens.
 * Note: while a new reference is gained in multiple places, there are only very
 * few cases where the node can be in the deadnode list (only empty nodes can
 * have been added to the list).
 */
static void
reactivate_node(qpcache_t *qpdb, qpcnode_t *node,
		isc_rwlocktype_t tlocktype ISC_ATTR_UNUSED DNS__DB_FLARG) {
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[node->locknum].lock;

	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_acquire(qpdb, node, nlocktype, tlocktype DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
}

static qpcnode_t *
new_qpcnode(qpcache_t *qpdb, const dns_name_t *name, dns_namespace_t nspace) {
	qpcnode_t *newdata = isc_mem_get(qpdb->common.mctx, sizeof(*newdata));
	*newdata = (qpcnode_t){
		.headers = CDS_LIST_HEAD_INIT(newdata->headers),
		.methods = &qpcnode_methods,
		.qpdb = qpdb,
		.name = DNS_NAME_INITEMPTY,
		.nspace = nspace,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.locknum = isc_random_uniform(qpdb->buckets_count),
	};

	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);
	dns_name_dup(name, newdata->mctx, &newdata->name);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "new_qpcnode:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return newdata;
}

static isc_result_t
qpcache_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		 dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
		 dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
		 dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *node = NULL;
	isc_result_t result;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	dns_namespace_t nspace = DNS_DBNAMESPACE_NORMAL;

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	result = dns_qp_getname(qpdb->tree, name, nspace, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		if (!create) {
			goto unlock;
		}
		/*
		 * Try to upgrade the lock and if that fails unlock then relock.
		 */
		TREE_FORCEUPGRADE(&qpdb->tree_lock, &tlocktype);
		result = dns_qp_getname(qpdb->tree, name, nspace,
					(void **)&node, NULL);
		if (result != ISC_R_SUCCESS) {
			node = new_qpcnode(qpdb, name, nspace);
			result = dns_qp_insert(qpdb->tree, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			qpcnode_unref(node);
		}
	}

	reactivate_node(qpdb, node, tlocktype DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)node;
unlock:
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return result;
}

static isc_result_t
qpcache_createiterator(dns_db_t *db, unsigned int options ISC_ATTR_UNUSED,
		       dns_dbiterator_t **iteratorp) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpc_dbit_t *qpdbiter = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	qpdbiter = isc_mem_get(qpdb->common.mctx, sizeof(*qpdbiter));
	*qpdbiter = (qpc_dbit_t){
		.common.methods = &dbiterator_methods,
		.common.magic = DNS_DBITERATOR_MAGIC,
		.paused = true,
	};

	qpdbiter->name = dns_fixedname_initname(&qpdbiter->fixed);
	dns_db_attach(db, &qpdbiter->common.db);
	dns_qpiter_init(qpdb->tree, &qpdbiter->iter);

	*iteratorp = (dns_dbiterator_t *)qpdbiter;
	return ISC_R_SUCCESS;
}

static bool
iterator_active(qpcache_t *qpdb, qpc_rditer_t *iterator,
		dns_slabheader_t *header) {
	dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);

	/*
	 * If this header is still active then return it.
	 */
	if (ACTIVE(header, iterator->common.now)) {
		return true;
	}

	/*
	 * If we are not returning stale records or the rdataset is
	 * too old don't return it.
	 */
	if (!STALEOK(iterator) || (iterator->common.now > stale_ttl)) {
		return false;
	}
	return true;
}

static isc_result_t
qpcache_allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     unsigned int options, isc_stdtime_t __now,
		     dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpc_rditer_t *iterator = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));
	*iterator = (qpc_rditer_t){
		.common.magic = DNS_RDATASETITER_MAGIC,
		.common.methods = &rdatasetiter_methods,
		.common.db = db,
		.common.node = node,
		.common.options = options,
		.common.now = __now ? __now : isc_stdtime_now(),
		.rdatasets = ISC_LIST_INITIALIZER,
	};

	qpcnode_acquire(qpdb, qpnode, isc_rwlocktype_none,
			isc_rwlocktype_none DNS__DB_FLARG_PASS);

	NODE_RDLOCK(nlock, &nlocktype);

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (EXPIREDOK(iterator) ||
		    iterator_active(qpdb, iterator, header))
		{
			dns_rdataset_t *rdataset =
				isc_mem_get(qpnode->mctx, sizeof(*rdataset));
			dns_rdataset_init(rdataset);

			bindrdataset(qpdb, qpnode, header, iterator->common.now,
				     nlocktype, isc_rwlocktype_none,
				     rdataset DNS__DB_FLARG_PASS);

			ISC_LIST_APPEND(iterator->rdatasets, rdataset, link);
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return ISC_R_SUCCESS;
}

static bool
overmaxtype(qpcache_t *qpdb, uint32_t ntypes) {
	if (qpdb->maxtypepername == 0) {
		return false;
	}

	return ntypes >= qpdb->maxtypepername;
}

static bool
prio_header(dns_slabheader_t *header) {
	return prio_type(header->typepair);
}

static void
qpcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(targetp != NULL && *targetp == NULL);

	qpcnode_t *node = (qpcnode_t *)source;
	qpcache_t *qpdb = (qpcache_t *)node->qpdb;

	qpcnode_acquire(qpdb, node, isc_rwlocktype_none,
			isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
qpcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpcnode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(nodep != NULL && *nodep != NULL);

	node = (qpcnode_t *)(*nodep);
	qpcache_t *qpdb = (qpcache_t *)node->qpdb;
	*nodep = NULL;
	nlock = &qpdb->buckets[node->locknum].lock;

	REQUIRE(VALID_QPDB(qpdb));

	/*
	 * We can't destroy qpcache while holding a nodelock, so we need to
	 * reference it before acquiring the lock and release it afterward.
	 * Additionally, we must ensure that we don't destroy the database while
	 * the NODE_LOCK is locked.
	 */
	qpcache_ref(qpdb);

	rcu_read_lock();
	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_release(qpdb, node, &nlocktype, &tlocktype DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
	rcu_read_unlock();

	qpcache_detach(&qpdb);
}

static isc_result_t
check_ncache_block(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *header,
		   dns_slabheader_t *newheader, dns_trust_t trust,
		   dns_rdataset_t *addedrdataset, isc_stdtime_t now,
		   isc_rwlocktype_t nlocktype,
		   isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	bool block = false;

	/*
	 * 1. If we have a cached NXDOMAIN, we won't cache
	 *    anything else here (dns_typepair_any).
	 * 2. If we have a cached NODATA for a given type,
	 *    we won't cache an RRSIG covering the same type.
	 */
	if (header->typepair == dns_typepair_any) {
		block = true;
	} else if (DNS_TYPEPAIR_TYPE(newheader->typepair) ==
			   dns_rdatatype_rrsig &&
		   DNS_TYPEPAIR_COVERS(newheader->typepair) ==
			   DNS_TYPEPAIR_TYPE(header->typepair))
	{
		block = true;
	}

	if (block) {
		/*
		 * If the ncache entry causing the block is less trusted
		 * than the new data, evict it from the cache. Otherwise,
		 * bind to it and leave the cache unchanged.
		 */
		if (trust >= header->trust) {
			header_delete(qpnode, header);
			return DNS_R_CONTINUE;
		} else {
			qpcache_hit(qpdb, header);
			bindrdataset(qpdb, qpnode, header, now, nlocktype,
				     tlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			return DNS_R_UNCHANGED;
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
add(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *newheader,
    unsigned int options, dns_rdataset_t *addedrdataset, isc_stdtime_t now,
    isc_rwlocktype_t nlocktype, isc_rwlocktype_t tlocktype DNS__DB_FLARG) {
	dns_slabheader_t *prioheader = NULL, *evictheader = NULL;
	dns_slabheader_t *oldheader = NULL, *related = NULL;
	dns_trust_t trust;
	uint32_t ntypes = 0;
	dns_rdatatype_t rdtype = DNS_TYPEPAIR_TYPE(newheader->typepair);
	dns_rdatatype_t covers = DNS_TYPEPAIR_COVERS(newheader->typepair);
	qpc_search_t search = (qpc_search_t){
		.qpdb = qpdb,
		.now = now,
	};

	REQUIRE(rdtype != dns_rdatatype_none);
	if (dns_rdatatype_issig(rdtype)) {
		/*
		 * signature must be either negative or cover something
		 * that's not a signature
		 */
		REQUIRE(NEGATIVE(newheader) || (covers != dns_rdatatype_none &&
						!dns_rdatatype_issig(covers)));
	} else {
		/* non-signature it must cover nothing */
		REQUIRE(covers == dns_rdatatype_none);
	}
	/* positive header can't be for type ANY */
	REQUIRE(rdtype != dns_rdatatype_any || NEGATIVE(newheader));

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	/*
	 * An unvalidated negative entry covering all types (NXDOMAIN or
	 * NODATA(QTYPE=ANY)) must not purge secure data. Check for it in a
	 * separate pass first: evicting as we go and bailing out later would
	 * destroy lower-trust siblings before we found the secure header.
	 */
	if (EXISTS(newheader) && NEGATIVE(newheader) &&
	    rdtype == dns_rdatatype_any && trust < dns_trust_secure)
	{
		DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
			if (header->trust >= dns_trust_secure) {
				qpcache_hit(qpdb, header);
				bindrdataset(qpdb, qpnode, header, now,
					     nlocktype, tlocktype,
					     addedrdataset DNS__DB_FLARG_PASS);
				return DNS_R_UNCHANGED;
			}
		}
	}

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (EXISTS(newheader) && NEGATIVE(newheader)) {
			if (rdtype == dns_rdatatype_any) {
				/*
				 * We're adding a negative cache entry which
				 * covers all types (NXDOMAIN,
				 * NODATA(QTYPE=ANY)).
				 *
				 * Delete all other data so that the only
				 * rdataset that can be found at this node is
				 * the negative cache entry.
				 */
				header_delete(qpnode, header);
				continue;
			} else if (rdtype == dns_rdatatype_rrsig) {
				/*
				 * We're adding a proof that a signature doesn't
				 * exist.
				 *
				 * Delete all existing signatures.
				 */
				if (DNS_TYPEPAIR_TYPE(header->typepair) ==
				    dns_rdatatype_rrsig)
				{
					header_delete(qpnode, header);
					continue;
				}
			}
		}
		if (EXISTS(header) && EXISTS(newheader) && NEGATIVE(header) &&
		    !NEGATIVE(newheader) && ACTIVE(header, now))
		{
			/*
			 * There's an existing NXDOMAIN or negative
			 * covered type in the cache. If it's more
			 * trusted than the new data, keep it, but
			 * if not, purge and replace it.
			 */
			isc_result_t result = check_ncache_block(
				qpdb, qpnode, header, newheader, trust,
				addedrdataset, now, nlocktype, tlocktype);
			if (result == DNS_R_UNCHANGED) {
				return result;
			}
			if (result == DNS_R_CONTINUE) {
				/* the header has been invalidated */
				continue;
			}
			INSIST(result == ISC_R_SUCCESS);
		}

		if (check_stale_header(header, &search)) {
			header_delete(qpnode, header);
			continue;
		}

		++ntypes;

		if (prio_header(header)) {
			prioheader = header;
		}

		if (header->typepair == newheader->typepair) {
			INSIST(oldheader == NULL);
			oldheader = header;
		}

		if ((rdtype == dns_rdatatype_rrsig &&
		     DNS_TYPEPAIR_TYPE(header->typepair) == covers) ||
		    header->typepair == DNS_SIGTYPEPAIR(rdtype))
		{
			INSIST(related == NULL);
			related = header;
		}

		/*
		 * This simple condition works here because:
		 *
		 * 1. if related is the last header then we won't progress
		 * evictheader
		 *
		 * 2. if related is not the last header then we progress
		 * evictheader.
		 */
		if (header != related) {
			evictheader = header;
		}
	}

	if (oldheader != NULL) {
		/*
		 * Deleting an already non-existent rdataset has no effect.
		 */
		if (!EXISTS(oldheader) && !EXISTS(newheader)) {
			return DNS_R_UNCHANGED;
		}

		/*
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		dns_trust_t oldtrust = atomic_load(&oldheader->trust);
		if (trust < oldtrust &&
		    (ACTIVE(oldheader, now) || !EXISTS(oldheader)))
		{
			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
				     tlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if (ACTIVE(oldheader, now) &&
			    (options & DNS_DBADD_EQUALOK) != 0 &&
			    dns_rdataslab_equalx(
				    oldheader, newheader, qpdb->common.rdclass,
				    DNS_TYPEPAIR_TYPE(oldheader->typepair)))
			{
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		/*
		 * Don't replace existing NS in the cache if they already exist
		 * and replacing the existing one would increase the TTL. This
		 * prevents named being locked to old servers. Don't lower trust
		 * of existing record if the update is forced. Nothing special
		 * to be done w.r.t stale data; it gets replaced normally
		 * further down.
		 */
		if (ACTIVE(oldheader, now) &&
		    oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ns) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust < oldtrust &&
		    oldheader->expire < newheader->expire &&
		    dns_rdataslab_equalx(
			    oldheader, newheader, qpdb->common.rdclass,
			    DNS_TYPEPAIR_TYPE(oldheader->typepair)))
		{
			if (oldheader->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				oldheader->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (oldheader->closest == NULL &&
			    newheader->closest != NULL)
			{
				oldheader->closest = newheader->closest;
				newheader->closest = NULL;
			}

			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
				     tlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if ((options & DNS_DBADD_EQUALOK) != 0) {
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		/*
		 * If we will be replacing an NS RRset, force its TTL
		 * to be no more than the current NS RRset's TTL.  This
		 * ensures the delegations that are withdrawn are honoured.
		 */
		if (ACTIVE(oldheader, now) &&
		    oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ns) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust > oldtrust)
		{
			if (newheader->expire > oldheader->expire) {
				if (ZEROTTL(oldheader)) {
					DNS_SLABHEADER_SETATTR(
						newheader,
						DNS_SLABHEADERATTR_ZEROTTL);
				}
				newheader->expire = oldheader->expire;
			}
		}
		if (ACTIVE(oldheader, now) &&
		    (options & DNS_DBADD_PREFETCH) == 0 &&
		    (oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_a) ||
		     oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_aaaa) ||
		     oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ds) ||
		     oldheader->typepair ==
			     DNS_SIGTYPEPAIR(dns_rdatatype_ds)) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust < oldtrust &&
		    oldheader->expire < newheader->expire &&
		    dns_rdataslab_equal(oldheader, newheader))
		{
			if (oldheader->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				oldheader->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (oldheader->closest == NULL &&
			    newheader->closest != NULL)
			{
				oldheader->closest = newheader->closest;
				newheader->closest = NULL;
			}

			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
				     tlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if ((options & DNS_DBADD_EQUALOK) != 0) {
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		INSIST(oldheader->related == related);
		header_delete(qpnode, oldheader);

	} else if (!EXISTS(newheader)) {
		/*
		 * The type already doesn't exist; no point trying
		 * to delete it.
		 */
		return DNS_R_UNCHANGED;
	}

	/*
	 * No rdatasets of the given type exist at the node or we removed the
	 * oldheader.
	 */

	if (prio_header(newheader)) {
		/* This is a priority type, prepend it */
		cds_list_add(&newheader->headers_link, &qpnode->headers);
	} else if (prioheader != NULL) {
		/* Append after the priority headers */
		cds_list_add(&newheader->headers_link,
			     &prioheader->headers_link);
	} else {
		/* There were no priority headers */
		cds_list_add(&newheader->headers_link, &qpnode->headers);
	}

	if (related != NULL) {
		INSIST(related->related == NULL);
		/* protect the related from LRU eviction */
		qpcache_hit(qpdb, related);
		related->related = dns_slabheader_ref(newheader);
		newheader->related = dns_slabheader_ref(related);
	}

	bindrdataset(qpdb, qpnode, newheader, now, nlocktype, tlocktype,
		     addedrdataset DNS__DB_FLARG_PASS);

	if (oldheader == NULL && overmaxtype(qpdb, ntypes)) {
		INSIST(evictheader != newheader);

		if (evictheader != NULL) {
			INSIST(evictheader->related != newheader);
			if (evictheader->related != NULL) {
				header_delete(qpnode, evictheader->related);
			}
			header_delete(qpnode, evictheader);
		}
	}

	qpcache_miss(qpdb, newheader, &nlocktype,
		     &tlocktype DNS__DB_FLARG_PASS);

	/*
	 * We've added a proof that a rdtype doesn't exist.
	 *
	 * Delete the related rrsig in the cache.
	 */
	if (EXISTS(newheader) && NEGATIVE(newheader) &&
	    !dns_rdatatype_issig(rdtype) && related != NULL)
	{
		header_delete(qpnode, related);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
addnoqname(isc_mem_t *mctx, dns_slabheader_t *newheader, uint32_t maxrrperset,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *noqname = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1 = { .base = NULL }, r2 = { .base = NULL };

	result = dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	CHECK(dns_rdataslab_fromrdataset(&neg, mctx, &r1, maxrrperset));

	CHECK(dns_rdataslab_fromrdataset(&negsig, mctx, &r2, maxrrperset));

	noqname = isc_mem_get(mctx, sizeof(*noqname));
	*noqname = (dns_slabheader_proof_t){
		.neg = ((dns_slabheader_t *)r1.base)->raw,
		.negsig = ((dns_slabheader_t *)r2.base)->raw,
		.type = neg.type,
		.name = DNS_NAME_INITEMPTY,
	};
	dns_name_dup(&name, mctx, &noqname->name);
	newheader->noqname = noqname;

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (r1.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r1.base;
			dns_slabheader_detach(&header);
		}
		if (r2.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r2.base;
			dns_slabheader_detach(&header);
		}
	}
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);

	return result;
}

static isc_result_t
addclosest(isc_mem_t *mctx, dns_slabheader_t *newheader, uint32_t maxrrperset,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *closest = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1 = { .base = NULL }, r2 = { .base = NULL };

	result = dns_rdataset_getclosest(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	CHECK(dns_rdataslab_fromrdataset(&neg, mctx, &r1, maxrrperset));

	CHECK(dns_rdataslab_fromrdataset(&negsig, mctx, &r2, maxrrperset));

	closest = isc_mem_get(mctx, sizeof(*closest));
	*closest = (dns_slabheader_proof_t){
		.neg = ((dns_slabheader_t *)r1.base)->raw,
		.negsig = ((dns_slabheader_t *)r2.base)->raw,
		.name = DNS_NAME_INITEMPTY,
		.type = neg.type,
	};
	dns_name_dup(&name, mctx, &closest->name);
	newheader->closest = closest;

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (r1.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r1.base;
			dns_slabheader_detach(&header);
		}
		if (r2.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r2.base;
			dns_slabheader_detach(&header);
		}
	}
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	return result;
}

static isc_result_t
qpcache_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    isc_stdtime_t __now, dns_rdataset_t *rdataset,
		    unsigned int options,
		    dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	bool newnsec = false;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	isc_stdtime_t now = __now ? __now : isc_stdtime_now();

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	result = dns_rdataslab_fromrdataset(rdataset, qpnode->mctx, &region,
					    qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)qpdb,
						  &qpnode->name, rdataset->type,
						  "adding", qpdb->maxrrperset);
		}
		return result;
	}

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(&qpnode->name, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, node);

	/*
	 * Set the correct expire time.
	 */
	setttl(newheader, now + rdataset->ttl);
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}

	if (rdataset->attributes.prefetch) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_PREFETCH);
	}
	if (rdataset->attributes.negative) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NEGATIVE);
	}
	if (rdataset->attributes.nxdomain) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NXDOMAIN);
	}
	if (rdataset->attributes.optout) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_OPTOUT);
	}
	if (rdataset->attributes.noqname) {
		CHECK(addnoqname(newheader->mctx, newheader, qpdb->maxrrperset,
				 rdataset));
	}
	if (rdataset->attributes.closest) {
		CHECK(addclosest(newheader->mctx, newheader, qpdb->maxrrperset,
				 rdataset));
	}

	nlock = &qpdb->buckets[qpnode->locknum].lock;

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	if (rdataset->type == dns_rdatatype_nsec) {
		NODE_RDLOCK(nlock, &nlocktype);
		if (!qpnode->havensec) {
			newnsec = true;
		}
		NODE_UNLOCK(nlock, &nlocktype);
	}

	/*
	 * If we're adding a delegation type or adding to the auxiliary
	 * NSEC tree, hold an exclusive lock on the tree.
	 */
	if (newnsec) {
		TREE_WRLOCK(&qpdb->tree_lock, &tlocktype);
	}

	NODE_WRLOCK(nlock, &nlocktype);

	if (newnsec && !qpnode->havensec) {
		qpcnode_t *nsecnode = NULL;

		result = dns_qp_getname(qpdb->tree, name, DNS_DBNAMESPACE_NSEC,
					(void **)&nsecnode, NULL);
		if (result != ISC_R_SUCCESS) {
			INSIST(nsecnode == NULL);
			nsecnode = new_qpcnode(qpdb, name,
					       DNS_DBNAMESPACE_NSEC);
			result = dns_qp_insert(qpdb->tree, nsecnode, 0);
			INSIST(result == ISC_R_SUCCESS);
			qpcnode_detach(&nsecnode);
		}
		qpnode->havensec = true;
	}

	result = add(qpdb, qpnode, newheader, options, addedrdataset, now,
		     nlocktype, tlocktype DNS__DB_FLARG_PASS);

	if (result == ISC_R_SUCCESS) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->typepair,
				  newheader->attributes, true);
	} else {
		dns_slabheader_detach(&newheader);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (result == ISC_R_EXISTS) {
		result = ISC_R_SUCCESS;
	}

	if (tlocktype != isc_rwlocktype_none) {
		TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);
	}

	INSIST(tlocktype == isc_rwlocktype_none);

	return result;
cleanup:
	dns_slabheader_detach(&newheader);
	return result;
}

static isc_result_t
qpcache_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, dns_rdatatype_t type,
		       dns_rdatatype_t covers DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	isc_result_t result;
	dns_slabheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	uint16_t attributes = DNS_SLABHEADERATTR_NONEXISTENT;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	/* Positive ANY type can't be in the cache. */
	if (type == dns_rdatatype_any) {
		return ISC_R_NOTIMPLEMENTED;
	}

	/* Convert the negative type into positive type. */
	if (type == dns_rdatatype_none && covers != dns_rdatatype_none) {
		type = covers;
		covers = dns_rdatatype_none;
		attributes |= DNS_SLABHEADERATTR_NEGATIVE;
	}

	newheader = dns_slabheader_new(db->mctx, node);
	newheader->typepair = DNS_TYPEPAIR_VALUE(type, covers);
	setttl(newheader, 0);
	atomic_init(&newheader->attributes, attributes);

	nlock = &qpdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	result = add(qpdb, qpnode, newheader, DNS_DBADD_FORCE, NULL, 0,
		     nlocktype, isc_rwlocktype_none DNS__DB_FLARG_PASS);
	if (result != ISC_R_SUCCESS) {
		dns_slabheader_detach(&newheader);
	}
	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static unsigned int
nodecount(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	dns_qp_memusage_t mu;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));

	TREE_RDLOCK(&qpdb->tree_lock, &tlocktype);
	mu = dns_qp_memusage(qpdb->tree);
	TREE_UNLOCK(&qpdb->tree_lock, &tlocktype);

	return mu.leaves;
}

isc_result_t
dns__qpcache_create(isc_mem_t *mctx, const dns_name_t *origin,
		    dns_dbtype_t type, dns_rdataclass_t rdclass,
		    unsigned int argc, char *argv[],
		    void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	qpcache_t *qpdb = NULL;
	isc_loop_t *loop = isc_loop();
	int i;
	size_t nloops = isc_loopmgr_nloops();

	/* This database implementation only supports cache semantics */
	REQUIRE(type == dns_dbtype_cache);
	REQUIRE(loop != NULL);
	REQUIRE(argc == 0);
	REQUIRE(argv == NULL);

	qpdb = isc_mem_get(mctx,
			   sizeof(*qpdb) + nloops * sizeof(qpdb->buckets[0]));
	*qpdb = (qpcache_t){
		.common.methods = &qpdb_cachemethods,
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.attributes = DNS_DBATTR_CACHE,
		.common.references = 1,
		.references = 1,
		.buckets_count = nloops,
	};

	isc_rwlock_init(&qpdb->lock);
	TREE_INITLOCK(&qpdb->tree_lock);

	qpdb->buckets_count = isc_loopmgr_nloops();

	dns_rdatasetstats_create(mctx, &qpdb->rrsetstats);
	for (i = 0; i < (int)qpdb->buckets_count; i++) {
		ISC_SIEVE_INIT(qpdb->buckets[i].sieve);

		isc_queue_init(&qpdb->buckets[i].deadnodes);

		NODE_INITLOCK(&qpdb->buckets[i].lock);
	}

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &qpdb->common.mctx);

	/*
	 * Make a copy of the origin name.
	 */
	dns_name_dup(origin, mctx, &qpdb->common.origin);

	/*
	 * Make the qp trie.
	 */
	dns_qp_create(mctx, &qpmethods, qpdb, &qpdb->tree);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPDB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return ISC_R_SUCCESS;
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpc_rditer_t *iterator = NULL;

	iterator = (qpc_rditer_t *)(*iteratorp);

	ISC_LIST_FOREACH(iterator->rdatasets, rdataset, link) {
		dns_rdataset_disassociate(rdataset);
		isc_mem_put(iterator->common.db->mctx, rdataset,
			    sizeof(*rdataset));
	}

	dns__db_detachnode(&iterator->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(iterator->common.db->mctx, iterator, sizeof(*iterator));

	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *it DNS__DB_FLARG) {
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

	iterator->current = ISC_LIST_HEAD(iterator->rdatasets);

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *it DNS__DB_FLARG) {
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	iterator->current = ISC_LIST_NEXT(iterator->current, link);

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static void
rdatasetiter_current(dns_rdatasetiter_t *it,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

	REQUIRE(iterator->current != NULL);

	dns_rdataset_clone(iterator->current, rdataset);
}

/*
 * Database Iterator Methods
 */

static void
reference_iter_node(qpc_dbit_t *qpdbiter DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
	qpcnode_t *node = qpdbiter->node;

	if (node == NULL) {
		return;
	}

	INSIST(qpdbiter->tree_locked != isc_rwlocktype_none);
	reactivate_node(qpdb, node, qpdbiter->tree_locked DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpc_dbit_t *qpdbiter DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
	qpcnode_t *node = qpdbiter->node;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = qpdbiter->tree_locked;

	if (node == NULL) {
		return;
	}

	REQUIRE(tlocktype != isc_rwlocktype_write);

	nlock = &qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_release(qpdb, node, &nlocktype,
			&qpdbiter->tree_locked DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	INSIST(qpdbiter->tree_locked == tlocktype);

	qpdbiter->node = NULL;
}

static void
resume_iteration(qpc_dbit_t *qpdbiter, bool continuing) {
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;

	REQUIRE(qpdbiter->paused);
	REQUIRE(qpdbiter->tree_locked == isc_rwlocktype_none);

	TREE_RDLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);

	/*
	 * If we're being called from dbiterator_next, we may need
	 * to reinitialize the iterator to the current name. The
	 * tree could have changed while it was unlocked, which
	 * would make the iterator traversal inconsistent.
	 *
	 * As long as the iterator is holding a reference to
	 * qpdbiter->node, the node won't be removed from the tree,
	 * so the lookup should always succeed.
	 */
	if (continuing && qpdbiter->node != NULL) {
		isc_result_t result;
		result = dns_qp_lookup(qpdb->tree, qpdbiter->name,
				       DNS_DBNAMESPACE_NORMAL, &qpdbiter->iter,
				       NULL, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
	}

	qpdbiter->paused = false;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)(*iteratorp);
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
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
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;
	qpcache_t *qpdb = (qpcache_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_qpiter_init(qpdb->tree, &qpdbiter->iter);
	result = dns_qpiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	if (result == ISC_R_SUCCESS &&
	    qpdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else if (result == ISC_R_SUCCESS) {
		result = ISC_R_NOMORE;
		qpdbiter->node = NULL;
	} else {
		/* The tree is empty. */
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	if (result != ISC_R_SUCCESS) {
		ENSURE(!qpdbiter->paused);
	}

	return result;
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;
	qpcache_t *qpdb = (qpcache_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qp_lookup(qpdb->tree, name, DNS_DBNAMESPACE_NORMAL,
			       &qpdbiter->iter, NULL, (void **)&qpdbiter->node,
			       NULL);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							  : result;
	return result;
}

static isc_result_t
dbiterator_seek3(dns_dbiterator_t *iterator ISC_ATTR_UNUSED,
		 const dns_name_t *name ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, true);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	if (result == ISC_R_SUCCESS &&
	    qpdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else if (result == ISC_R_SUCCESS) {
		result = ISC_R_NOMORE;
		qpdbiter->node = NULL;
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)iterator->db;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;
	qpcnode_t *node = qpdbiter->node;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(node != NULL);

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	if (name != NULL) {
		dns_name_copy(&node->name, name);
	}

	qpcnode_acquire(qpdb, node, isc_rwlocktype_none,
			qpdbiter->tree_locked DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)qpdbiter->node;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	qpcache_t *qpdb = (qpcache_t *)iterator->db;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		return ISC_R_SUCCESS;
	}

	qpdbiter->paused = true;

	if (qpdbiter->tree_locked == isc_rwlocktype_read) {
		TREE_UNLOCK(&qpdb->tree_lock, &qpdbiter->tree_locked);
	}
	INSIST(qpdbiter->tree_locked == isc_rwlocktype_none);

	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	dns_name_copy(dns_rootname, name);
	return ISC_R_SUCCESS;
}

static void
setmaxrrperset(dns_db_t *db, uint32_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	qpdb->maxrrperset = value;
}

static void
setmaxtypepername(dns_db_t *db, uint32_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	qpdb->maxtypepername = value;
}

static dns_dbmethods_t qpdb_cachemethods = {
	.destroy = qpcache_destroy,
	.findnode = qpcache_findnode,
	.find = qpcache_find,
	.createiterator = qpcache_createiterator,
	.findrdataset = qpcache_findrdataset,
	.allrdatasets = qpcache_allrdatasets,
	.addrdataset = qpcache_addrdataset,
	.deleterdataset = qpcache_deleterdataset,
	.nodecount = nodecount,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.setmaxrrperset = setmaxrrperset,
	.setmaxtypepername = setmaxtypepername,
};

static void
qpcnode_destroy(qpcnode_t *qpnode) {
	dns_slabheader_t *header = NULL, *header_next = NULL;
	cds_list_for_each_entry_safe(header, header_next, &qpnode->headers,
				     headers_link)
	{
		header_delete(qpnode, header);
	}

	dns_name_free(&qpnode->name, qpnode->mctx);
	isc_mem_putanddetach(&qpnode->mctx, qpnode, sizeof(qpcnode_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpcnode, qpcnode_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpcnode, qpcnode_destroy);
#endif

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpcache, qpcache__destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpcache, qpcache__destroy);
#endif
