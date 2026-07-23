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
#include <sys/mman.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/file.h>
#include <isc/hashmap.h>
#include <isc/heap.h>
#include <isc/hex.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/serial.h>
#include <isc/slist.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/diff.h>
#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/masterdump.h>
#include <dns/name.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/qp.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatavec.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>

#include "db_p.h"
#include "qpzone_p.h"
#include "rdatavec_p.h"

#define QPDB_ATTR_LOADED  0x01
#define QPDB_ATTR_LOADING 0x02

#define QPDBITER_ORIGIN_NODE(qpdb, iterator) \
	((iterator)->node == (qpdb)->origin)
#define QPDBITER_NSEC_ORIGIN_NODE(qpdb, iterator) \
	((iterator)->node == (qpdb)->nsec_origin)
#define QPDBITER_NSEC3_ORIGIN_NODE(qpdb, iterator) \
	((iterator)->node == (qpdb)->nsec3_origin)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPZONE_DB_MAGIC ISC_MAGIC('Q', 'Z', 'D', 'B')
#define VALID_QPZONE(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPZONE_DB_MAGIC)

typedef struct qpzonedb qpzonedb_t;
typedef struct qpznode qpznode_t;

typedef struct qpzone_bucket {
	/* Per-bucket lock. */
	isc_rwlock_t lock;

	/* Padding to prevent false sharing between locks. */
	uint8_t __padding[ISC_OS_CACHELINE_SIZE -
			  (sizeof(isc_rwlock_t)) % ISC_OS_CACHELINE_SIZE];
} qpzone_bucket_t;

/*
 * Qpzone-specific update context that extends dns_updatectx_t, used in IXFR.
 */
typedef struct qpzone_updatectx {
	dns_updatectx_t base;
	dns_qp_t *qp;
	dns_qpread_t qpr;
} qpzone_updatectx_t;

static qpzone_bucket_t qpzone_buckets_g[1024];

typedef struct qpz_changed {
	qpznode_t *node;
	bool dirty;
	ISC_LINK(struct qpz_changed) link;
} qpz_changed_t;

typedef ISC_LIST(qpz_changed_t) qpz_changedlist_t;

typedef struct qpz_resigned {
	qpznode_t *node;
	dns_vecheader_t *header;
	ISC_LINK(struct qpz_resigned) link;
} qpz_resigned_t;

typedef ISC_LIST(qpz_resigned_t) qpz_resignedlist_t;

typedef struct qpz_version qpz_version_t;
struct qpz_version {
	/* Not locked */
	uint32_t serial;
	qpzonedb_t *qpdb;
	isc_refcount_t references;
	/* Locked by database lock. */
	bool writer;
	qpz_changedlist_t changed_list;
	qpz_resignedlist_t resigned_list;
	ISC_LINK(qpz_version_t) link;
	bool secure;
	bool havensec3;
	/* NSEC3 parameters */
	dns_hash_t hash;
	uint8_t flags;
	uint16_t iterations;
	uint8_t salt_length;
	unsigned char salt[DNS_NSEC3_SALTSIZE];

	/*
	 * records and xfrsize are covered by rwlock.
	 */
	isc_rwlock_t rwlock;
	uint64_t records;
	uint64_t xfrsize;

	struct cds_wfs_stack glue_stack;
};

typedef ISC_LIST(qpz_version_t) qpz_versionlist_t;

/* Resigning heap indirection to allow ref counting */
typedef struct qpz_heap {
	isc_mem_t *mctx;
	isc_refcount_t references;
	/* Locks the data in this struct */
	isc_mutex_t lock;
	isc_heap_t *heap;
	isc_hashmap_t *hashmap;
} qpz_heap_t;

typedef struct qpz_resign {
	qpznode_t *node;
	dns_vecheader_t *header;
	unsigned int heap_index;
} qpz_resign_t;

ISC_REFCOUNT_STATIC_DECL(qpz_heap);

struct qpznode {
	DBNODE_FIELDS;
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
	 * node use reference (see 'qpzonedb->references' below), and
	 * release it when 'erefs' goes back to zero. This prevents the
	 * database from being shut down until every caller has released
	 * all nodes.
	 */
	isc_refcount_t references;
	isc_refcount_t erefs;

	_Atomic(dns_namespace_t) nspace;
	atomic_bool havensec;
	atomic_bool wild;
	atomic_bool delegating;
	atomic_bool dirty;

	ISC_SLIST(dns_vectop_t) next_type;
};

struct qpzonedb {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;

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

	qpznode_t *origin;
	qpznode_t *nsec_origin;
	qpznode_t *nsec3_origin;
	isc_stats_t *gluecachestats;
	/* Locked by lock. */
	unsigned int attributes;
	uint32_t current_serial;
	uint32_t least_serial;
	uint32_t next_serial;
	uint32_t maxrrperset;	 /* Maximum RRs per RRset */
	uint32_t maxtypepername; /* Maximum number of RR types per owner */
	qpz_version_t *current_version;
	qpz_version_t *future_version;
	qpz_versionlist_t open_versions;
	struct rcu_head rcu_head;

	qpz_heap_t *heap; /* Resigning heap */

	dns_qpmulti_t *tree; /* QP trie for data storage */
};

/*%
 * Search Context
 */
typedef struct {
	qpzonedb_t *qpdb;
	qpz_version_t *version;
	dns_qpread_t qpr;
	uint32_t serial;
	unsigned int options;
	dns_qpchain_t chain;
	dns_qpiter_t iter;
	bool copy_name;
	bool need_cleanup;
	bool wild;
	qpznode_t *zonecut;
	dns_vecheader_t *zonecut_header;
	dns_vecheader_t *zonecut_sigheader;
	dns_fixedname_t zonecut_name;
} qpz_search_t;

/*%
 * Load Context
 */
typedef struct {
	dns_db_t *db;
	dns_qp_t *tree;
} qpz_load_t;

static dns_dbmethods_t qpdb_zonemethods;
static dns_dbnode_methods_t qpznode_methods;

#if DNS_DB_NODETRACE
#define qpznode_ref(ptr)   qpznode__ref(ptr, __func__, __FILE__, __LINE__)
#define qpznode_unref(ptr) qpznode__unref(ptr, __func__, __FILE__, __LINE__)
#define qpznode_attach(ptr, ptrp) \
	qpznode__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpznode_detach(ptrp) qpznode__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpznode);
#else
ISC_REFCOUNT_STATIC_DECL(qpznode);
#endif

/* Forward declarations for functions used in constructors */
static void
qpznode_acquire(qpznode_t *node DNS__DB_FLARG);
static bool
qpznode_release(qpznode_t *node DNS__DB_FLARG);
static void
qpznode_erefs_increment(qpznode_t *node DNS__DB_FLARG);

/*%
 * Constructor and destructor for qpz_changed_t
 */
static qpz_changed_t *
qpz_changed_new(isc_mem_t *mctx, qpznode_t *node DNS__DB_FLARG) {
	qpz_changed_t *changed = isc_mem_get(mctx, sizeof(qpz_changed_t));
	*changed = (qpz_changed_t){
		.node = node,
		.dirty = false,
		.link = ISC_LINK_INITIALIZER,
	};
	qpznode_acquire(node DNS__DB_FLARG_PASS);
	return changed;
}

/*%
 * Constructor and destructor for qpz_resigned_t
 */
static qpz_resigned_t *
qpz_resigned_new(isc_mem_t *mctx, qpznode_t *node, dns_vecheader_t *header) {
	qpz_resigned_t *resigned = isc_mem_get(mctx, sizeof(qpz_resigned_t));
	*resigned = (qpz_resigned_t){
		.node = node,
		.header = header,
		.link = ISC_LINK_INITIALIZER,
	};
	qpznode_ref(node);
	dns_vecheader_ref(header);
	return resigned;
}

static void
qpz_resigned_destroy(isc_mem_t *mctx, qpz_resigned_t **resignedp) {
	qpz_resigned_t *resigned = *resignedp;
	*resignedp = NULL;
	qpznode_unref(resigned->node);
	dns_vecheader_unref(resigned->header);
	isc_mem_put(mctx, resigned, sizeof(qpz_resigned_t));
}

/*%
 * Constructor and destructor for qpz_resign_t
 */
static qpz_resign_t *
qpz_resign_new(isc_mem_t *mctx, qpznode_t *node, dns_vecheader_t *header) {
	qpz_resign_t *elem = isc_mem_get(mctx, sizeof(qpz_resign_t));
	*elem = (qpz_resign_t){
		.node = node,
		.header = header,
		.heap_index = 0,
	};
	qpznode_ref(node);
	dns_vecheader_ref(header);
	return elem;
}

static void
qpz_resign_destroy(isc_mem_t *mctx, qpz_resign_t **elemp) {
	qpz_resign_t *elem = *elemp;
	*elemp = NULL;
	qpznode_unref(elem->node);
	dns_vecheader_unref(elem->header);
	isc_mem_put(mctx, elem, sizeof(qpz_resign_t));
}

/* QP trie methods */
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
	dns_vectop_t *currenttop;
	dns_vecheader_t *current;
} qpdb_rdatasetiter_t;

/*
 * Note that these iterators, unless created with either DNS_DB_NSEC3ONLY
 * or DNS_DB_NONSEC3, will transparently move between the last node of the
 * "regular" QP trie and the root node of the NSEC3 QP trie of the database
 * in question, as if the latter was a successor to the former in lexical
 * order.  The "current" field always holds the address of either "iter".
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

typedef struct qpdb_dbiterator {
	dns_dbiterator_t common;
	isc_result_t result;
	dns_qpsnap_t *snap; /* tree snapshot */
	dns_qpiter_t iter;  /* tree iterator */
	qpznode_t *node;
	enum { full, nonsec3, nsec3only } nsec3mode;
} qpdb_dbiterator_t;

/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

void
dns__qpzone_initialize(void) {
	for (size_t idx = 0; idx < ARRAY_SIZE(qpzone_buckets_g); ++idx) {
		NODE_INITLOCK(&qpzone_buckets_g[idx].lock);
	}
}

void
dns__qpzone_shutdown(void) {
	for (size_t idx = 0; idx < ARRAY_SIZE(qpzone_buckets_g); ++idx) {
		NODE_DESTROYLOCK(&qpzone_buckets_g[idx].lock);
	}
}

static isc_rwlock_t *
qpzone_get_lock(qpznode_t *node) {
	return &qpzone_buckets_g[node->locknum].lock;
}

static uint16_t
qpzone_get_locknum(void) {
	return isc_random_uniform(ARRAY_SIZE(qpzone_buckets_g));
}

static void
free_glue(isc_mem_t *mctx, dns_glue_t *glue) {
	while (glue != NULL) {
		dns_glue_t *next = glue->next;

		if (glue->header_a != NULL) {
			dns_vecheader_unref(glue->header_a);
		}
		if (glue->sigheader_a != NULL) {
			dns_vecheader_unref(glue->sigheader_a);
		}
		if (glue->header_aaaa != NULL) {
			dns_vecheader_unref(glue->header_aaaa);
		}
		if (glue->sigheader_aaaa != NULL) {
			dns_vecheader_unref(glue->sigheader_aaaa);
		}

		dns_name_free(&glue->name, mctx);

		isc_mem_put(mctx, glue, sizeof(*glue));

		glue = next;
	}
}

static void
destroy_gluelist(dns_gluelist_t **gluelistp) {
	REQUIRE(gluelistp != NULL);
	if (*gluelistp == NULL) {
		return;
	}

	dns_gluelist_t *gluelist = *gluelistp;

	free_glue(gluelist->mctx, gluelist->glue);

	isc_mem_putanddetach(&gluelist->mctx, gluelist, sizeof(*gluelist));
}

static void
free_gluelist_rcu(struct rcu_head *rcu_head) {
	dns_gluelist_t *gluelist = caa_container_of(rcu_head, dns_gluelist_t,
						    rcu_head);
	destroy_gluelist(&gluelist);
}

static void
cleanup_gluelists(struct cds_wfs_stack *glue_stack) {
	struct cds_wfs_head *head = __cds_wfs_pop_all(glue_stack);
	struct cds_wfs_node *node = NULL, *next = NULL;

	rcu_read_lock();
	cds_wfs_for_each_blocking_safe(head, node, next) {
		dns_gluelist_t *gluelist =
			caa_container_of(node, dns_gluelist_t, wfs_node);
		dns_vecheader_t *header = rcu_xchg_pointer(&gluelist->header,
							   NULL);
		(void)rcu_cmpxchg_pointer(&header->gluelist, gluelist, NULL);

		call_rcu(&gluelist->rcu_head, free_gluelist_rcu);
	}
	rcu_read_unlock();
}

static void
free_db_rcu(struct rcu_head *rcu_head) {
	qpzonedb_t *qpdb = caa_container_of(rcu_head, qpzonedb_t, rcu_head);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}

	qpz_heap_detach(&qpdb->heap);

	if (qpdb->gluecachestats != NULL) {
		isc_stats_detach(&qpdb->gluecachestats);
	}

	isc_rwlock_destroy(&qpdb->lock);
	isc_refcount_destroy(&qpdb->common.references);

	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;

	if (qpdb->common.update_listeners != NULL) {
		INSIST(!cds_lfht_destroy(qpdb->common.update_listeners, NULL));
	}

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb, sizeof(*qpdb));
}

static void
qpzone_destroy(qpzonedb_t *qpdb) {
	REQUIRE(qpdb->future_version == NULL);
	REQUIRE(qpdb->current_version != NULL);

	isc_refcount_decrementz(&qpdb->current_version->references);

	isc_refcount_destroy(&qpdb->current_version->references);
	ISC_LIST_UNLINK(qpdb->open_versions, qpdb->current_version, link);
	cds_wfs_destroy(&qpdb->current_version->glue_stack);
	isc_rwlock_destroy(&qpdb->current_version->rwlock);
	isc_mem_put(qpdb->common.mctx, qpdb->current_version,
		    sizeof(*qpdb->current_version));

	dns_qpmulti_destroy(&qpdb->tree);

	char buf[DNS_NAME_FORMATSIZE];
	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
	} else {
		strlcpy(buf, "<UNKNOWN>", sizeof(buf));
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DB,
		      ISC_LOG_DEBUG(1), "called %s(%s)", __func__, buf);

	call_rcu(&qpdb->rcu_head, free_db_rcu);
}

static void
qpdb_destroy(dns_db_t *arg) {
	qpzonedb_t *qpdb = (qpzonedb_t *)arg;

	if (qpdb->origin != NULL) {
		qpznode_detach(&qpdb->origin);
	}
	if (qpdb->nsec_origin != NULL) {
		qpznode_detach(&qpdb->nsec_origin);
	}
	if (qpdb->nsec3_origin != NULL) {
		qpznode_detach(&qpdb->nsec3_origin);
	}

	/*
	 * The current version's glue table needs to be freed early
	 * so the nodes are dereferenced before we check the active
	 * node count below.
	 */
	if (qpdb->current_version != NULL) {
		cleanup_gluelists(&qpdb->current_version->glue_stack);
	}

	qpzone_destroy(qpdb);
}

/*%
 * Compare resign times with SOA priority logic.
 * Returns true if lhs should be resigned sooner than rhs.
 * When resign times are equal, non-SOA RRsets sort before the SOA RRset.
 */
static bool
resign_sooner_values(int64_t lhs_resign, dns_typepair_t lhs_typepair,
		     int64_t rhs_resign, dns_typepair_t rhs_typepair) {
	bool lhs_is_soa = lhs_typepair == DNS_SIGTYPEPAIR(dns_rdatatype_soa);
	bool rhs_is_soa = rhs_typepair == DNS_SIGTYPEPAIR(dns_rdatatype_soa);

	return lhs_resign < rhs_resign ||
	       (lhs_resign == rhs_resign && lhs_is_soa < rhs_is_soa);
}

/*%
 * Return which RRset should be resigned sooner.  If the RRsets have the
 * same signing time, prefer the other RRset over the SOA RRset.
 */
static bool
resign_sooner(void *v1, void *v2) {
	qpz_resign_t *elem1 = v1;
	qpz_resign_t *elem2 = v2;

	return resign_sooner_values(
		elem1->header->resign, elem1->header->typepair,
		elem2->header->resign, elem2->header->typepair);
}

/*%
 * This function sets the heap index into the qpz_resign_t.
 */
static void
set_index(void *what, unsigned int idx) {
	qpz_resign_t *elem = what;

	elem->heap_index = idx;
}

/*%
 * Hashmap matching function for qpz_resign_t entries.
 * Matches based on header and node pointers.
 */
static bool
resign_match(void *elem_ptr, const void *key) {
	qpz_resign_t *elem = elem_ptr;
	const qpz_resign_t *search_elem = key;

	return elem->header == search_elem->header &&
	       elem->node == search_elem->node;
}

/*%
 * Generate hash value for a heap element based on header pointer.
 */
static uint32_t
resign_hash(dns_vecheader_t *header) {
	uintptr_t headerptr = (uintptr_t)header;
	return isc_hash32(&headerptr, sizeof(headerptr), true);
}

/*%
 * Find an element in the heap/hashmap by header and node.
 * Returns ISC_R_SUCCESS if found, ISC_R_NOTFOUND if not found.
 * If found, *found_elem will point to the element.
 * Assumes heap lock is already held.
 */
static isc_result_t
resign_lookup(qpz_heap_t *heap, dns_vecheader_t *header, qpznode_t *node,
	      qpz_resign_t **found_elem) {
	qpz_resign_t search_elem = {
		.header = header,
		.node = node,
	};
	uint32_t hashval = resign_hash(header);

	return isc_hashmap_find(heap->hashmap, hashval, resign_match,
				&search_elem, (void **)found_elem);
}

/*%
 * Add an element to the heap/hashmap.
 * Assumes heap lock is already held.
 */
static void
resign_register(qpz_heap_t *heap, qpznode_t *node, dns_vecheader_t *header) {
	qpz_resign_t *elem = qpz_resign_new(heap->mctx, node, header);
	uint32_t hashval = resign_hash(header);

	/* Verify invariant: element should not already be in hashmap */
	isc_result_t result = isc_hashmap_add(heap->hashmap, hashval,
					      resign_match, elem, elem, NULL);
	INSIST(result == ISC_R_SUCCESS);

	isc_heap_insert(heap->heap, elem);
}

/*%
 * Remove an element from the heap/hashmap.
 * Assumes heap lock is already held.
 */
static void
resign_unregister(qpz_heap_t *heap, qpznode_t *node, dns_vecheader_t *header) {
	if (header == NULL) {
		return;
	}

	qpz_resign_t *found_elem = NULL;
	uint32_t hashval = resign_hash(header);
	qpz_resign_t search_elem = {
		.header = header,
		.node = node,
	};
	isc_result_t result = isc_hashmap_find(heap->hashmap, hashval,
					       resign_match, &search_elem,
					       (void **)&found_elem);

	if (result == ISC_R_SUCCESS) {
		isc_heap_delete(heap->heap, found_elem->heap_index);
		isc_hashmap_delete(heap->hashmap, hashval, resign_match,
				   found_elem);
		qpz_resign_destroy(heap->mctx, &found_elem);
	}
}

static qpz_heap_t *
new_qpz_heap(isc_mem_t *mctx) {
	qpz_heap_t *new_heap = isc_mem_get(mctx, sizeof(*new_heap));
	*new_heap = (qpz_heap_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	isc_mutex_init(&new_heap->lock);
	isc_heap_create(mctx, resign_sooner, set_index, 0, &new_heap->heap);
	isc_mem_attach(mctx, &new_heap->mctx);

	isc_hashmap_create(mctx, 1u, &new_heap->hashmap);

	return new_heap;
}

static void
resign_rollback(qpzonedb_t *qpdb, qpznode_t *node, qpz_version_t *version,
		dns_vecheader_t *header DNS__DB_FLARG) {
	if (header == NULL) {
		return;
	}

	qpz_resigned_t *resigned = qpz_resigned_new(((dns_db_t *)qpdb)->mctx,
						    node, header);

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	ISC_LIST_APPEND(version->resigned_list, resigned, link);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
}

static void
qpz_heap_destroy(qpz_heap_t *qpheap) {
	/* Clean up hashmap entries */
	isc_hashmap_iter_t *iter = NULL;
	isc_hashmap_iter_create(qpheap->hashmap, &iter);
	for (isc_result_t result = isc_hashmap_iter_first(iter);
	     result == ISC_R_SUCCESS; result = isc_hashmap_iter_next(iter))
	{
		qpz_resign_t *elem = NULL;
		isc_hashmap_iter_current(iter, (void **)&elem);
		/* Release the node reference and deallocate */
		qpz_resign_destroy(qpheap->mctx, &elem);
	}
	isc_hashmap_iter_destroy(&iter);
	isc_hashmap_destroy(&qpheap->hashmap);

	isc_mutex_destroy(&qpheap->lock);
	isc_heap_destroy(&qpheap->heap);
	isc_mem_putanddetach(&qpheap->mctx, qpheap, sizeof(*qpheap));
}

static qpznode_t *
new_qpznode(qpzonedb_t *qpdb, const dns_name_t *name, dns_namespace_t nspace) {
	qpznode_t *newdata = isc_mem_get(qpdb->common.mctx, sizeof(*newdata));
	*newdata = (qpznode_t){
		.next_type = ISC_SLIST_INITIALIZER,
		.methods = &qpznode_methods,
		.name = DNS_NAME_INITEMPTY,
		.nspace = nspace,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.locknum = qpzone_get_locknum(),
	};

	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);
	dns_name_dup(name, qpdb->common.mctx, &newdata->name);

#if DNS_DB_NODETRACE
	fprintf(stderr, "new_qpznode:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return newdata;
}

static qpz_version_t *
allocate_version(isc_mem_t *mctx, uint32_t serial, unsigned int references,
		 bool writer) {
	qpz_version_t *version = isc_mem_get(mctx, sizeof(*version));
	*version = (qpz_version_t){
		.serial = serial,
		.writer = writer,
		.changed_list = ISC_LIST_INITIALIZER,
		.resigned_list = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
		.references = ISC_REFCOUNT_INITIALIZER(references),
	};

	cds_wfs_init(&version->glue_stack);
	isc_rwlock_init(&version->rwlock);

	return version;
}

isc_result_t
dns__qpzone_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
		   dns_rdataclass_t rdclass, unsigned int argc ISC_ATTR_UNUSED,
		   char **argv ISC_ATTR_UNUSED, void *driverarg ISC_ATTR_UNUSED,
		   dns_db_t **dbp) {
	qpzonedb_t *qpdb = NULL;
	isc_result_t result;
	dns_qp_t *qp = NULL;

	qpdb = isc_mem_get(mctx, sizeof(*qpdb));
	*qpdb = (qpzonedb_t){
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.references = ISC_REFCOUNT_INITIALIZER(1),
		.current_serial = 1,
		.least_serial = 1,
		.next_serial = 2,
		.open_versions = ISC_LIST_INITIALIZER,
	};

	qpdb->common.methods = &qpdb_zonemethods;
	if (type == dns_dbtype_stub) {
		qpdb->common.attributes |= DNS_DBATTR_STUB;
	}

	isc_rwlock_init(&qpdb->lock);

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	qpdb->heap = new_qpz_heap(mctx);

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

	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->tree);

	/*
	 * Version initialization.
	 */
	qpdb->current_version = allocate_version(mctx, 1, 1, false);
	qpdb->current_version->qpdb = qpdb;

	dns_qpmulti_write(qpdb->tree, &qp);

	/*
	 * In order to set the node callback bit correctly in zone databases,
	 * we need to know if the node has the origin name of the zone.
	 * In loading_addrdataset() we could simply compare the new name
	 * to the origin name, but this is expensive.  Also, we don't know the
	 * node name in addrdataset(), so we need another way of knowing the
	 * zone's top.
	 *
	 * We now explicitly create a node for the zone's origin, and then
	 * we simply remember the node data's address.
	 */
	qpdb->origin = new_qpznode(qpdb, &qpdb->common.origin,
				   DNS_DBNAMESPACE_NORMAL);

	result = dns_qp_insert(qp, qpdb->origin, 0);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Add an apex node to the NSEC tree so that we can quickly skip over
	 * the NSEC nodes while iterating over the full tree.
	 */
	qpdb->nsec_origin = new_qpznode(qpdb, &qpdb->common.origin,
					DNS_DBNAMESPACE_NSEC);
	result = dns_qp_insert(qp, qpdb->nsec_origin, 0);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Add an apex node to the NSEC3 tree so that NSEC3 searches
	 * return partial matches when there is only a single NSEC3
	 * record in the tree.
	 */
	qpdb->nsec3_origin = new_qpznode(qpdb, &qpdb->common.origin,
					 DNS_DBNAMESPACE_NSEC3);
	result = dns_qp_insert(qp, qpdb->nsec3_origin, 0);
	INSIST(result == ISC_R_SUCCESS);

	dns_qpmulti_commit(qpdb->tree, &qp);

	/*
	 * Keep the current version in the open list so that list operation
	 * won't happen in normal lookup operations.
	 */
	ISC_LIST_PREPEND(qpdb->open_versions, qpdb->current_version, link);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPZONE_DB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return ISC_R_SUCCESS;
}

/*
 * If incrementing erefs from zero, we also increment the node use counter
 * in the qpzonedb object.
 *
 * This function is called from qpznode_acquire(), so that internal
 * and external references are acquired at the same time, and from
 * qpznode_release() when we only need to increase the internal references.
 */
static void
qpznode_erefs_increment(qpznode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_increment0(&node->erefs);
#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#endif

	if (refs > 0) {
		return;
	}
}

static void
qpznode_acquire(qpznode_t *node DNS__DB_FLARG) {
	qpznode_ref(node);
	qpznode_erefs_increment(node DNS__DB_FLARG_PASS);
}

static dns_vecheader_t *
first_header(dns_vectop_t *top) {
	return ISC_SLIST_HEAD(top->headers);
}

static dns_vecheader_t *
first_existing_header(dns_vectop_t *top, uint32_t serial) {
	ISC_SLIST_FOREACH(header, top->headers, next_header) {
		if (header->serial <= serial && !IGNORE(header)) {
			if (EXISTS(header)) {
				return header;
			}
			break;
		}
	}
	return NULL;
}

static void
clean_multiple_headers(qpz_heap_t *heap, qpznode_t *node, dns_vectop_t *top) {
	uint32_t parent_serial = UINT32_MAX;

	REQUIRE(top != NULL);

	ISC_SLIST_FOREACH_PTR(p, &ISC_SLIST_HEAD(top->headers)) {
		dns_vecheader_t *header = *p;
		INSIST(header->serial <= parent_serial);

		if (header->serial == parent_serial || IGNORE(header)) {
			ISC_SLIST_PTR_REMOVE(p, header, next_header);
			LOCK(&heap->lock);
			resign_unregister(heap, node, header);
			UNLOCK(&heap->lock);
			dns_vecheader_unref(header);
		} else {
			parent_serial = header->serial;
			ISC_SLIST_PTR_ADVANCE(p, next_header);
		}
	}
}

static bool
clean_multiple_versions(qpz_heap_t *heap, qpznode_t *node, dns_vectop_t *top,
			uint32_t least_serial) {
	REQUIRE(top != NULL);

	if (ISC_SLIST_EMPTY(top->headers)) {
		return false;
	}

	bool multiple = false;
	dns_vecheader_t **pointer_to_second_header =
		&ISC_SLIST_NEXT(ISC_SLIST_HEAD(top->headers), next_header);
	ISC_SLIST_FOREACH_PTR(p, pointer_to_second_header) {
		dns_vecheader_t *header = *p;
		if (header->serial < least_serial) {
			ISC_SLIST_PTR_REMOVE(p, header, next_header);
			LOCK(&heap->lock);
			resign_unregister(heap, node, header);
			UNLOCK(&heap->lock);
			dns_vecheader_unref(header);
		} else {
			multiple = true;
			ISC_SLIST_PTR_ADVANCE(p, next_header);
		}
	}
	return multiple;
}

static void
clean_zone_node(qpz_heap_t *heap, qpznode_t *node, uint32_t least_serial) {
	bool still_dirty = false;

	/*
	 * Caller must be holding the node lock.
	 */
	REQUIRE(node != NULL);
	REQUIRE(least_serial != 0);

	/*
	 * First pass: clean all header lists
	 */
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		/*
		 * First, we clean up any instances of multiple rdatasets
		 * with the same serial number, or that have the IGNORE
		 * attribute.
		 */
		clean_multiple_headers(heap, node, top);

		if (first_header(top) != NULL) {
			/*
			 * Try to find the first down node less than the least
			 * serial, and if there are such rdatasets, delete it
			 * and any older versions.
			 *
			 * Note: The serial number of the top header might be
			 * less than least_serial too, but we cannot delete it
			 * because it is the most recent version.
			 */
			still_dirty = clean_multiple_versions(heap, node, top,
							      least_serial);
		}
	}

	/*
	 * Second pass: remove all empty vectops
	 */
	ISC_SLIST_FOREACH_PTR(iter, &ISC_SLIST_HEAD(node->next_type)) {
		dns_vectop_t *next = *iter;
		if (ISC_SLIST_EMPTY(next->headers)) {
			ISC_SLIST_PTR_REMOVE(iter, next, next_type);
			dns_vectop_destroy(node->mctx, &next);
		} else {
			ISC_SLIST_PTR_ADVANCE(iter, next_type);
		}
	}

	if (!still_dirty) {
		node->dirty = false;
	}
}

/*
 * Decrement the external references to a node. If the counter
 * goes to zero, decrement the node use counter in the qpzonedb object
 * as well, and return true. Otherwise return false.
 */
static bool
qpznode_erefs_decrement(qpznode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif
	if (refs > 1) {
		return false;
	}

	return true;
}

/*
 * Caller must be holding the node lock; either the read or write lock.
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
static bool
qpznode_release(qpznode_t *node DNS__DB_FLARG) {
	bool has_erefs = false;

	if (!qpznode_erefs_decrement(node DNS__DB_FLARG_PASS)) {
		has_erefs = true;
		goto unref;
	}

	/* Handle easy and typical case first. */
	if (!node->dirty && !ISC_SLIST_EMPTY(node->next_type)) {
		has_erefs = true;
		goto unref;
	}

unref:
	qpznode_unref(node);
	return has_erefs;
}

static void
bindrdataset(qpzonedb_t *qpdb, dns_vecheader_t *header,
	     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	if (rdataset == NULL) {
		return;
	}

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	rdataset->methods = &dns_rdatavec_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->typepair);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->typepair);
	rdataset->ttl = header->ttl;
	rdataset->trust = atomic_load_acquire(&header->trust);

	if (OPTOUT(header)) {
		rdataset->attributes.optout = true;
	}

	rdataset->vec.header = header;
	dns_vecheader_ref(header);
	rdataset->vec.iter.iter_pos = NULL;
	rdataset->vec.iter.iter_count = 0;

	/*
	 * Add noqname proof.
	 */

	/*
	 * Copy out re-signing information.
	 */
	if (RESIGN(header)) {
		rdataset->attributes.resign = true;
		rdataset->resign = header->resign;
	} else {
		rdataset->resign = 0;
	}
}

static void
setnsec3parameters(dns_db_t *db, qpz_version_t *version) {
	qpznode_t *node = NULL;
	dns_rdata_nsec3param_t nsec3param;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_vecheader_t *found = NULL;

	version->havensec3 = false;
	node = qpdb->origin;
	nlock = qpzone_get_lock(node);

	NODE_RDLOCK(nlock, &nlocktype);

	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		if (top->typepair != dns_rdatatype_nsec3param) {
			continue;
		}
		found = first_existing_header(top, version->serial);
	}

	if (found != NULL) {
		/*
		 * Find an NSEC3PARAM with a supported algorithm.
		 */

		rdatavec_iter_t iter;
		DNS_VECHEADER_FOREACH(&iter, found, qpdb->common.rdclass) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			vecheader_current(&iter, &rdata);

			isc_result_t result =
				dns_rdata_tostruct(&rdata, &nsec3param, NULL);
			INSIST(result == ISC_R_SUCCESS);

			if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG &&
			    !dns_nsec3_supportedhash(nsec3param.hash))
			{
				continue;
			}

			if (nsec3param.flags != 0) {
				continue;
			}

			memmove(version->salt, nsec3param.salt.base,
				nsec3param.salt.length);
			version->hash = nsec3param.hash;
			version->salt_length = nsec3param.salt.length;
			version->iterations = nsec3param.iterations;
			version->flags = nsec3param.flags;
			version->havensec3 = true;
			/*
			 * Look for a better algorithm than the
			 * unknown test algorithm.
			 */
			if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG) {
				break;
			}
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);
}

static void
cleanup_nondirty(qpz_version_t *version, qpz_changedlist_t *cleanup_list) {
	/*
	 * If the changed record is dirty, then an update created multiple
	 * versions of a given rdataset.  We keep this list until we're the
	 * least open version, at which point it's safe to get rid of any
	 * older versions.
	 *
	 * If the changed record isn't dirty, then we don't need it anymore
	 * since we're committing and not rolling back.
	 *
	 * The caller must be holding the database lock.
	 */
	ISC_LIST_FOREACH(version->changed_list, changed, link) {
		if (!changed->dirty) {
			ISC_LIST_UNLINK(version->changed_list, changed, link);
			ISC_LIST_APPEND(*cleanup_list, changed, link);
		}
	}
}

static void
setsecure(dns_db_t *db, qpz_version_t *version, dns_dbnode_t *origin) {
	dns_rdataset_t keyset;
	dns_rdataset_t nsecset, signsecset;
	bool haszonekey = false;
	bool hasnsec = false;
	isc_result_t result;

	version->secure = false;
	version->havensec3 = false;

	dns_rdataset_init(&keyset);
	result = dns_db_findrdataset(db, origin, (dns_dbversion_t *)version,
				     dns_rdatatype_dnskey, 0, 0, &keyset, NULL);
	if (result == ISC_R_SUCCESS) {
		haszonekey = dns_dnssec_haszonekey(&keyset);
		dns_rdataset_disassociate(&keyset);
	}
	if (!haszonekey) {
		return;
	}

	dns_rdataset_init(&nsecset);
	dns_rdataset_init(&signsecset);
	result = dns_db_findrdataset(db, origin, (dns_dbversion_t *)version,
				     dns_rdatatype_nsec, 0, 0, &nsecset,
				     &signsecset);
	if (result == ISC_R_SUCCESS) {
		if (dns_rdataset_isassociated(&signsecset)) {
			hasnsec = true;
			dns_rdataset_disassociate(&signsecset);
		}
		dns_rdataset_disassociate(&nsecset);
	}

	setnsec3parameters(db, version);

	/*
	 * If we don't have a valid NSEC/NSEC3 chain,
	 * clear the secure flag.
	 */
	if (version->havensec3 || hasnsec) {
		version->secure = true;
	}
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = NULL;

	REQUIRE(VALID_QPZONE(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	version = qpdb->current_version;
	isc_refcount_increment(&version->references);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	*versionp = (dns_dbversion_t *)version;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = (qpz_version_t *)source;

	REQUIRE(VALID_QPZONE(qpdb));
	INSIST(version != NULL && version->qpdb == qpdb);

	isc_refcount_increment(&version->references);

	*targetp = source;
}

static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(versionp != NULL && *versionp == NULL);
	REQUIRE(qpdb->future_version == NULL);

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	INSIST(qpdb->next_serial != 0);
	version = allocate_version(qpdb->common.mctx, qpdb->next_serial, 1,
				   true);
	version->qpdb = qpdb;
	version->secure = qpdb->current_version->secure;
	version->havensec3 = qpdb->current_version->havensec3;
	if (version->havensec3) {
		version->flags = qpdb->current_version->flags;
		version->iterations = qpdb->current_version->iterations;
		version->hash = qpdb->current_version->hash;
		version->salt_length = qpdb->current_version->salt_length;
		memmove(version->salt, qpdb->current_version->salt,
			version->salt_length);
	}

	version->records = qpdb->current_version->records;
	version->xfrsize = qpdb->current_version->xfrsize;

	qpdb->next_serial++;
	qpdb->future_version = version;
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	*versionp = (dns_dbversion_t *)version;

	return ISC_R_SUCCESS;
}

static void
make_least_version(qpzonedb_t *qpdb, qpz_version_t *version,
		   qpz_changedlist_t *cleanup_list) {
	qpdb->least_serial = version->serial;
	*cleanup_list = version->changed_list;
	ISC_LIST_INIT(version->changed_list);
}

static void
rollback_node(qpznode_t *node, uint32_t serial) {
	bool make_dirty = false;

	/*
	 * We set the IGNORE attribute on rdatasets with serial number
	 * 'serial'.  When the reference count goes to zero, these rdatasets
	 * will be cleaned up; until that time, they will be ignored.
	 */
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		ISC_SLIST_FOREACH(header, top->headers, next_header) {
			if (header->serial == serial) {
				DNS_VECHEADER_SETATTR(header,
						      DNS_VECHEADERATTR_IGNORE);
				make_dirty = true;
			}
		}
	}
	if (make_dirty) {
		node->dirty = true;
	}
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp,
	     bool commit DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = NULL, *cleanup_version = NULL;
	qpz_version_t *least_greater = NULL;
	qpznode_t *node = NULL;
	bool rollback = false;
	qpz_changedlist_t cleanup_list;
	qpz_resignedlist_t resigned_list;
	uint32_t serial, least_serial;

	REQUIRE(VALID_QPZONE(qpdb));
	version = (qpz_version_t *)*versionp;
	INSIST(version->qpdb == qpdb);

	if (isc_refcount_decrement(&version->references) > 1) {
		*versionp = NULL;
		return;
	}

	ISC_LIST_INIT(cleanup_list);
	ISC_LIST_INIT(resigned_list);

	/*
	 * Update the zone's secure status in version before making
	 * it the current version.
	 */
	if (version->writer && commit) {
		setsecure(db, version, (dns_dbnode_t *)qpdb->origin);
	}

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	serial = version->serial;
	if (version->writer) {
		if (commit) {
			unsigned int cur_ref;
			qpz_version_t *cur_version = NULL;

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
					INSIST(ISC_LIST_EMPTY(
						cur_version->changed_list));
				}
				ISC_LIST_UNLINK(qpdb->open_versions,
						cur_version, link);
			}
			if (ISC_LIST_EMPTY(qpdb->open_versions)) {
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
				ISC_LIST_APPENDLIST(
					version->changed_list,
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
			ISC_LIST_PREPEND(qpdb->open_versions,
					 qpdb->current_version, link);
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
			least_greater = ISC_LIST_PREV(version, link);
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
				ISC_LIST_APPENDLIST(least_greater->changed_list,
						    version->changed_list,
						    link);
			}
		} else if (version->serial == qpdb->least_serial) {
			INSIST(ISC_LIST_EMPTY(version->changed_list));
		}
		ISC_LIST_UNLINK(qpdb->open_versions, version, link);
	}
	least_serial = qpdb->least_serial;
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	if (cleanup_version != NULL) {
		isc_refcount_destroy(&cleanup_version->references);
		INSIST(ISC_LIST_EMPTY(cleanup_version->changed_list));
		cleanup_gluelists(&cleanup_version->glue_stack);
		cds_wfs_destroy(&cleanup_version->glue_stack);
		isc_rwlock_destroy(&cleanup_version->rwlock);
		isc_mem_put(qpdb->common.mctx, cleanup_version,
			    sizeof(*cleanup_version));
	}

	/*
	 * Commit/rollback re-signed headers.
	 */
	ISC_LIST_FOREACH(resigned_list, resigned, link) {
		isc_rwlock_t *nlock = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		dns_vecheader_t *header = resigned->header;
		qpznode_t *resigned_node = resigned->node;

		ISC_LIST_UNLINK(resigned_list, resigned, link);

		nlock = qpzone_get_lock(resigned_node);
		NODE_WRLOCK(nlock, &nlocktype);
		if (rollback && !IGNORE(header)) {
			LOCK(&qpdb->heap->lock);
			resign_register(qpdb->heap, resigned_node, header);
			UNLOCK(&qpdb->heap->lock);
		}
		qpz_resigned_destroy(db->mctx, &resigned);
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (ISC_LIST_EMPTY(cleanup_list)) {
		*versionp = NULL;
		return;
	}

	ISC_LIST_FOREACH(cleanup_list, changed, link) {
		isc_rwlock_t *nlock = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

		node = changed->node;
		nlock = qpzone_get_lock(node);

		NODE_WRLOCK(nlock, &nlocktype);
		if (rollback) {
			rollback_node(node, serial);
		}
		bool has_erefs = qpznode_release(node DNS__DB_FILELINE);
		if (!has_erefs) {
			clean_zone_node(qpdb->heap, node, least_serial);
		}

		NODE_UNLOCK(nlock, &nlocktype);

		/*
		 * The node reference is released separately above, so
		 * we just free the changed structure here.
		 */
		isc_mem_put(qpdb->common.mctx, changed, sizeof(*changed));
	}

	*versionp = NULL;
}

static isc_result_t
qpzone_findrdataset(dns_db_t *db, dns_dbnode_t *dbnode,
		    dns_dbversion_t *dbversion, dns_rdatatype_t type,
		    dns_rdatatype_t covers, isc_stdtime_t now ISC_ATTR_UNUSED,
		    dns_rdataset_t *rdataset,
		    dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	dns_vecheader_t *found = NULL, *foundsig = NULL;
	uint32_t serial;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	bool close_version = false;
	dns_typepair_t typepair, sigpair;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(type != dns_rdatatype_any);
	INSIST(version == NULL || version->qpdb == qpdb);

	if (type == dns_rdatatype_none && covers == dns_rdatatype_none) {
		return ISC_R_NOTFOUND;
	}

	if (version == NULL) {
		currentversion(db, (dns_dbversion_t **)&version);
		close_version = true;
	}
	serial = version->serial;

	nlock = qpzone_get_lock(node);
	NODE_RDLOCK(nlock, &nlocktype);

	typepair = DNS_TYPEPAIR_VALUE(type, covers);
	if (covers == dns_rdatatype_none) {
		sigpair = DNS_SIGTYPEPAIR(type);
	} else {
		sigpair = dns_typepair_none;
	}

	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		dns_vecheader_t *header = first_existing_header(top, serial);
		if (header != NULL) {
			/*
			 * We have an active, extant rdataset.  If it's a
			 * type we're looking for, remember it.
			 */
			if (top->typepair == typepair) {
				found = header;
				if (foundsig != NULL) {
					break;
				}
			} else if (top->typepair == sigpair) {
				foundsig = header;
				if (found != NULL) {
					break;
				}
			}
		}
	}
	if (found != NULL) {
		bindrdataset(qpdb, found, rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(qpdb, foundsig,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (close_version) {
		closeversion(db, (dns_dbversion_t **)&version,
			     false DNS__DB_FLARG_PASS);
	}

	if (found == NULL) {
		return ISC_R_NOTFOUND;
	}

	return ISC_R_SUCCESS;
}

static bool
delegating_type(qpzonedb_t *qpdb, qpznode_t *node, dns_typepair_t typepair) {
	return typepair == DNS_TYPEPAIR(dns_rdatatype_dname) ||
	       (typepair == DNS_TYPEPAIR(dns_rdatatype_ns) &&
		(node != qpdb->origin || IS_STUB(qpdb)));
}

static void
loading_addnode(qpz_load_t *loadctx, const dns_name_t *name,
		dns_rdatatype_t type, dns_rdatatype_t covers,
		qpznode_t **nodep) {
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;
	isc_result_t result;
	qpznode_t *node = NULL, *nsecnode = NULL;

	if (type == dns_rdatatype_nsec3 || covers == dns_rdatatype_nsec3) {
		result = dns_qp_getname(loadctx->tree, name,
					DNS_DBNAMESPACE_NSEC3, (void **)&node,
					NULL);
		if (result == ISC_R_SUCCESS) {
			*nodep = node;
		} else {
			node = new_qpznode(qpdb, name, DNS_DBNAMESPACE_NSEC3);
			result = dns_qp_insert(loadctx->tree, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			*nodep = node;
			qpznode_detach(&node);
		}
		return;
	}

	result = dns_qp_getname(loadctx->tree, name, DNS_DBNAMESPACE_NORMAL,
				(void **)&node, NULL);
	if (result == ISC_R_SUCCESS) {
		if (type == dns_rdatatype_nsec && node->havensec) {
			goto done;
		}
	} else {
		INSIST(node == NULL);
		node = new_qpznode(qpdb, name, DNS_DBNAMESPACE_NORMAL);
		result = dns_qp_insert(loadctx->tree, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpznode_unref(node);
	}
	if (type != dns_rdatatype_nsec) {
		goto done;
	}

	/*
	 * We're adding an NSEC record, so create a node in the nsec tree
	 * too. This tree speeds searches for closest NSECs that would
	 * otherwise need to examine many irrelevant nodes in large TLDs.
	 * If dns_qp_insert() fails, it means there's already an NSEC
	 * node there, so we can just detach the new one we created and
	 * move on.
	 */
	node->havensec = true;
	nsecnode = new_qpznode(qpdb, name, DNS_DBNAMESPACE_NSEC);
	(void)dns_qp_insert(loadctx->tree, nsecnode, 0);
	qpznode_detach(&nsecnode);

done:
	*nodep = node;
}

static bool
cname_and_other(qpznode_t *node, uint32_t serial) {
	bool cname = false, other = false;

	/*
	 * Look for CNAME and "other data" rdatasets active in our version.
	 * ("Other data" is any rdataset whose type is not KEY, NSEC, SIG
	 * or RRSIG.
	 */
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		dns_rdatatype_t rdtype = DNS_TYPEPAIR_TYPE(top->typepair);
		if (rdtype == dns_rdatatype_cname) {
			if (first_existing_header(top, serial) != NULL) {
				cname = true;
			}
		} else if (rdtype != dns_rdatatype_nsec &&
			   rdtype != dns_rdatatype_rrsig)
		{
			if (first_existing_header(top, serial) != NULL) {
				if (!prio_type(rdtype)) {
					/*
					 * CNAME is in the priority list, so if
					 * we are done with priority types, we
					 * know there will not be a CNAME, and
					 * are safe to skip the rest.
					 */
					return cname;
				}
				other = true;
			}
		}

		if (cname && other) {
			return true;
		}
	}

	return false;
}

static qpz_changed_t *
add_changed(qpzonedb_t *qpdb, qpznode_t *node,
	    qpz_version_t *version DNS__DB_FLARG) {
	qpz_changed_t *changed = qpz_changed_new(qpdb->common.mctx,
						 node DNS__DB_FLARG_PASS);

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	REQUIRE(version->writer);

	ISC_LIST_INITANDAPPEND(version->changed_list, changed, link);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	return changed;
}

static uint64_t
recordsize(dns_vecheader_t *header, unsigned int namelen) {
	return dns_rdatavec_size(header) + sizeof(dns_ttl_t) +
	       sizeof(dns_rdatatype_t) + sizeof(dns_rdataclass_t) + namelen;
}

static void
maybe_update_recordsandsize(bool add, qpz_version_t *version,
			    dns_vecheader_t *header, unsigned int namelen) {
	if (!EXISTS(header)) {
		return;
	}

	RWLOCK(&version->rwlock, isc_rwlocktype_write);
	if (add) {
		version->records += dns_rdatavec_count(header);
		version->xfrsize += recordsize(header, namelen);
	} else {
		version->records -= dns_rdatavec_count(header);
		version->xfrsize -= recordsize(header, namelen);
	}
	RWUNLOCK(&version->rwlock, isc_rwlocktype_write);
}

static isc_result_t
add(qpzonedb_t *qpdb, qpznode_t *node, const dns_name_t *nodename,
    qpz_version_t *version, dns_vecheader_t *newheader, unsigned int options,
    bool loading, dns_rdataset_t *addedrdataset,
    isc_stdtime_t now ISC_ATTR_UNUSED DNS__DB_FLARG) {
	qpz_changed_t *changed = NULL;
	dns_vectop_t *foundtop = NULL;
	dns_vectop_t *priotop = NULL;
	dns_vecheader_t *merged = NULL;
	isc_result_t result;
	bool merge = false;
	uint32_t ntypes;

	if ((options & DNS_DBADD_MERGE) != 0) {
		REQUIRE(version != NULL);
		merge = true;
	}

	if (!loading) {
		/*
		 * We always add a changed record, even if no changes end up
		 * being made to this node, because it's harmless and
		 * simplifies the code.
		 */
		changed = add_changed(qpdb, node, version DNS__DB_FLARG_PASS);
	}

	ntypes = 0;
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		++ntypes;
		if (prio_type(top->typepair)) {
			priotop = top;
		}
		if (top->typepair == newheader->typepair) {
			foundtop = top;
			break;
		}
	}

	/*
	 * If topheader isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	dns_vecheader_t **header_p = NULL;
	dns_vecheader_t *header = NULL;
	if (foundtop != NULL) {
		ISC_SLIST_FOREACH_PTR(p, &ISC_SLIST_HEAD(foundtop->headers)) {
			if (!IGNORE(*p)) {
				header_p = p;
				header = *p;
				break;
			}
			ISC_SLIST_PTR_ADVANCE(p, next_header);
		}
	}

	if (header != NULL) {
		/*
		 * If 'merge' is true and header isn't empty/nonexistent,
		 * we'll try to create a new rdataset that is the union
		 * of 'newheader' and 'header'.
		 */
		if (merge && EXISTS(header)) {
			unsigned int flags = 0;
			INSIST(version->serial >= header->serial);
			merged = NULL;
			result = ISC_R_SUCCESS;

			if ((options & DNS_DBADD_EXACT) != 0) {
				flags |= DNS_RDATAVEC_EXACT;
			}
			if ((options & DNS_DBADD_EXACTTTL) != 0 &&
			    newheader->ttl != header->ttl)
			{
				result = DNS_R_NOTEXACT;
			} else if (newheader->ttl != header->ttl) {
				flags |= DNS_RDATAVEC_FORCE;
			}
			if (result == ISC_R_SUCCESS) {
				result = dns_rdatavec_merge(
					header, newheader, qpdb->common.mctx,
					qpdb->common.rdclass,
					DNS_TYPEPAIR_TYPE(header->typepair),
					flags, qpdb->maxrrperset, &merged);
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
				dns_vecheader_unref(newheader);
				newheader = merged;
				/*
				 * dns_rdatavec_subtract takes the header from
				 * the first argument, so it preserves the case
				 */
				if (loading && RESIGN(newheader) &&
				    RESIGN(header) &&
				    resign_sooner_values(header->resign,
							 header->typepair,
							 newheader->resign,
							 newheader->typepair))
				{
					newheader->resign = header->resign;
				}
			} else {
				if (result == DNS_R_TOOMANYRECORDS) {
					dns__db_logtoomanyrecords(
						(dns_db_t *)qpdb, nodename,
						DNS_TYPEPAIR_TYPE(
							header->typepair),
						"updating", qpdb->maxrrperset);
				}
				dns_vecheader_unref(newheader);
				return result;
			}
		}

		INSIST(version->serial >= header->serial);
		INSIST(foundtop->typepair == newheader->typepair);

		if (loading) {
			if (RESIGN(newheader)) {
				LOCK(&qpdb->heap->lock);
				resign_register(qpdb->heap, node, newheader);
				UNLOCK(&qpdb->heap->lock);
				/* resigndelete not needed here */
			}

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			ISC_SLIST_PTR_REMOVE(header_p, header, next_header);
			ISC_SLIST_PREPEND(foundtop->headers, newheader,
					  next_header);
			maybe_update_recordsandsize(false, version, header,
						    nodename->length);

			LOCK(&qpdb->heap->lock);
			resign_unregister(qpdb->heap, node, header);
			UNLOCK(&qpdb->heap->lock);
			dns_vecheader_unref(header);
		} else {
			if (RESIGN(newheader)) {
				LOCK(&qpdb->heap->lock);
				resign_register(qpdb->heap, node, newheader);
				resign_unregister(qpdb->heap, node, header);
				UNLOCK(&qpdb->heap->lock);
				resign_rollback(qpdb, node, version,
						header DNS__DB_FLARG_PASS);
			}

			ISC_SLIST_PREPEND(foundtop->headers, newheader,
					  next_header);

			node->dirty = true;
			if (changed != NULL) {
				changed->dirty = true;
			}
			maybe_update_recordsandsize(false, version, header,
						    nodename->length);
		}
	} else {
		/*
		 * No non-IGNORED rdatasets of the given type exist at
		 * this node.
		 *
		 * If we're trying to delete the type, don't bother.
		 */
		if (!EXISTS(newheader)) {
			dns_vecheader_unref(newheader);
			return DNS_R_UNCHANGED;
		}

		if (RESIGN(newheader)) {
			LOCK(&qpdb->heap->lock);
			resign_register(qpdb->heap, node, newheader);
			resign_unregister(qpdb->heap, node, header);
			UNLOCK(&qpdb->heap->lock);
			resign_rollback(qpdb, node, version,
					header DNS__DB_FLARG_PASS);
		}

		if (foundtop != NULL) {
			/*
			 * We have a list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);

			ISC_SLIST_PREPEND(foundtop->headers, newheader,
					  next_header);

			if (changed != NULL) {
				changed->dirty = true;
			}
			node->dirty = true;
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */

			if (qpdb->maxtypepername > 0 &&
			    ntypes >= qpdb->maxtypepername)
			{
				LOCK(&qpdb->heap->lock);
				resign_unregister(qpdb->heap, node, newheader);
				UNLOCK(&qpdb->heap->lock);
				dns_vecheader_unref(newheader);
				return DNS_R_TOOMANYRECORDS;
			}

			dns_vectop_t *newtop =
				dns_vectop_new(node->mctx, newheader->typepair);

			ISC_SLIST_PREPEND(newtop->headers, newheader,
					  next_header);

			if (prio_type(newheader->typepair)) {
				/* This is a priority type, prepend it */
				ISC_SLIST_PREPEND(node->next_type, newtop,
						  next_type);
			} else if (priotop != NULL) {
				/* Append after the priority headers */
				ISC_SLIST_INSERTAFTER(priotop, newtop,
						      next_type);
			} else {
				/* There were no priority headers */
				ISC_SLIST_PREPEND(node->next_type, newtop,
						  next_type);
			}
		}
	}

	maybe_update_recordsandsize(true, version, newheader, nodename->length);

	/*
	 * Check if the node now contains CNAME and other data.
	 */
	if (cname_and_other(node, version->serial)) {
		return DNS_R_CNAMEANDOTHER;
	}

	bindrdataset(qpdb, newheader, addedrdataset DNS__DB_FLARG_PASS);

	return ISC_R_SUCCESS;
}

static void
wildcardmagic(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	      dns_namespace_t nspace) {
	isc_result_t result;
	dns_name_t foundname;
	unsigned int n;
	qpznode_t *node = NULL;

	dns_name_init(&foundname);
	n = dns_name_countlabels(name);
	INSIST(n >= 2);
	n--;
	dns_name_getlabelsequence(name, 1, n, &foundname);

	/* insert an empty node, if needed, to hold the wildcard bit */
	result = dns_qp_getname(qp, &foundname, nspace, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		INSIST(node == NULL);
		node = new_qpznode(qpdb, &foundname, nspace);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpznode_unref(node);
	}

	node->wild = true;
}

static void
addwildcards(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	     dns_namespace_t nspace) {
	dns_name_t foundname;
	unsigned int n, l, i;

	dns_name_init(&foundname);
	n = dns_name_countlabels(name);
	l = dns_name_countlabels(&qpdb->common.origin);
	i = l + 1;
	while (i < n) {
		dns_name_getlabelsequence(name, n - i, i, &foundname);
		if (dns_name_iswildcard(&foundname)) {
			wildcardmagic(qpdb, qp, &foundname, nspace);
		}

		i++;
	}
}

static isc_result_t
loading_addrdataset(void *arg, const dns_name_t *name, dns_rdataset_t *rdataset,
		    dns_diffop_t op ISC_ATTR_UNUSED DNS__DB_FLARG) {
	qpz_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;
	qpznode_t *node = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_region_t region;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(rdataset->rdclass == qpdb->common.rdclass);

	/*
	 * SOA records are only allowed at top of zone.
	 */
	if (rdataset->type == dns_rdatatype_soa &&
	    !dns_name_equal(name, &qpdb->common.origin))
	{
		return DNS_R_NOTZONETOP;
	}

	if (rdataset->type != dns_rdatatype_nsec3 &&
	    rdataset->covers != dns_rdatatype_nsec3)
	{
		addwildcards(qpdb, loadctx->tree, name, DNS_DBNAMESPACE_NORMAL);
	}

	if (dns_name_iswildcard(name)) {
		if (rdataset->type == dns_rdatatype_ns) {
			/*
			 * NS owners cannot legally be wild cards.
			 */
			return DNS_R_INVALIDNS;
		}

		if (rdataset->type == dns_rdatatype_nsec3) {
			/*
			 * NSEC3 owners cannot legally be wild cards.
			 */
			return DNS_R_INVALIDNSEC3;
		}

		wildcardmagic(qpdb, loadctx->tree, name,
			      DNS_DBNAMESPACE_NORMAL);
	}

	loading_addnode(loadctx, name, rdataset->type, rdataset->covers, &node);
	result = dns_rdatavec_fromrdataset(rdataset, node->mctx, &region,
					   qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)qpdb, name,
						  rdataset->type, "adding",
						  qpdb->maxrrperset);
		}
		return result;
	}

	dns_vecheader_t *newheader = (dns_vecheader_t *)region.base;
	newheader->ttl = rdataset->ttl;
	newheader->serial = 1;
	atomic_store_release(&newheader->trust, rdataset->trust);

	dns_vecheader_setownercase(newheader, name);

	if (rdataset->attributes.resign) {
		DNS_VECHEADER_SETATTR(newheader, DNS_VECHEADERATTR_RESIGN);
		newheader->resign = dns_time64_from32(rdataset->resign);
	}

	nlock = qpzone_get_lock(node);
	NODE_WRLOCK(nlock, &nlocktype);
	result = add(qpdb, node, name, qpdb->current_version, newheader,
		     DNS_DBADD_MERGE, true, NULL, 0 DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	if (result == ISC_R_SUCCESS &&
	    delegating_type(qpdb, node, rdataset->type))
	{
		node->delegating = true;
	} else if (result == DNS_R_UNCHANGED) {
		result = ISC_R_SUCCESS;
	}

	return result;
}

static void
loading_setup(void *arg) {
	qpz_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;

	dns_qpmulti_write(qpdb->tree, &loadctx->tree);
}

static void
loading_commit(void *arg) {
	qpz_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;

	if (loadctx->tree != NULL) {
		dns_qp_compact(loadctx->tree, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &loadctx->tree);
	}
}

static isc_result_t
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpz_load_t *loadctx = NULL;
	qpzonedb_t *qpdb = NULL;
	qpdb = (qpzonedb_t *)db;

	REQUIRE(DNS_CALLBACK_VALID(callbacks));
	REQUIRE(VALID_QPZONE(qpdb));

	loadctx = isc_mem_get(qpdb->common.mctx, sizeof(*loadctx));
	*loadctx = (qpz_load_t){ .db = db };

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);

	REQUIRE((qpdb->attributes & (QPDB_ATTR_LOADED | QPDB_ATTR_LOADING)) ==
		0);
	qpdb->attributes |= QPDB_ATTR_LOADING;

	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	callbacks->update = loading_addrdataset;
	callbacks->setup = loading_setup;
	callbacks->commit = loading_commit;
	callbacks->add_private = loadctx;

	return ISC_R_SUCCESS;
}

static isc_result_t
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpz_load_t *loadctx = NULL;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(DNS_CALLBACK_VALID(callbacks));
	loadctx = callbacks->add_private;
	REQUIRE(loadctx != NULL);
	REQUIRE(loadctx->db == db);

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);

	REQUIRE((qpdb->attributes & QPDB_ATTR_LOADING) != 0);
	REQUIRE((qpdb->attributes & QPDB_ATTR_LOADED) == 0);

	qpdb->attributes &= ~QPDB_ATTR_LOADING;
	qpdb->attributes |= QPDB_ATTR_LOADED;

	if (qpdb->origin != NULL) {
		qpz_version_t *version = qpdb->current_version;
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
		setsecure(db, version, (dns_dbnode_t *)qpdb->origin);
	} else {
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
	}

	callbacks->update = NULL;
	callbacks->setup = NULL;
	callbacks->commit = NULL;
	callbacks->add_private = NULL;

	isc_mem_put(qpdb->common.mctx, loadctx, sizeof(*loadctx));

	return ISC_R_SUCCESS;
}

static bool
issecure(dns_db_t *db) {
	qpzonedb_t *qpdb = NULL;
	bool secure;

	qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	secure = qpdb->current_version->secure;
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	return secure;
}

static isc_result_t
getnsec3parameters(dns_db_t *db, dns_dbversion_t *dbversion, dns_hash_t *hash,
		   uint8_t *flags, uint16_t *iterations, unsigned char *salt,
		   size_t *salt_length) {
	qpzonedb_t *qpdb = NULL;
	isc_result_t result = ISC_R_NOTFOUND;
	qpz_version_t *version = (qpz_version_t *)dbversion;

	qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	INSIST(version == NULL || version->qpdb == qpdb);

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	if (version == NULL) {
		version = qpdb->current_version;
	}

	if (version->havensec3) {
		SET_IF_NOT_NULL(hash, version->hash);
		if (salt != NULL && salt_length != NULL) {
			REQUIRE(*salt_length >= version->salt_length);
			memmove(salt, version->salt, version->salt_length);
		}
		SET_IF_NOT_NULL(salt_length, version->salt_length);
		SET_IF_NOT_NULL(iterations, version->iterations);
		SET_IF_NOT_NULL(flags, version->flags);
		result = ISC_R_SUCCESS;
	}
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	return result;
}

static isc_result_t
getsize(dns_db_t *db, dns_dbversion_t *dbversion, uint64_t *records,
	uint64_t *xfrsize) {
	qpzonedb_t *qpdb = NULL;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	isc_result_t result = ISC_R_SUCCESS;

	qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	INSIST(version == NULL || version->qpdb == qpdb);

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	if (version == NULL) {
		version = qpdb->current_version;
	}

	RWLOCK(&version->rwlock, isc_rwlocktype_read);
	SET_IF_NOT_NULL(records, version->records);

	SET_IF_NOT_NULL(xfrsize, version->xfrsize);
	RWUNLOCK(&version->rwlock, isc_rwlocktype_read);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	return result;
}

static isc_result_t
setsigningtime(dns_db_t *db, dns_dbnode_t *dbnode, dns_rdataset_t *rdataset,
	       isc_stdtime_t resign) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	dns_vecheader_t *header = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(rdataset != NULL);
	REQUIRE(rdataset->methods == &dns_rdatavec_rdatasetmethods);

	header = dns_vecheader_getheader(rdataset);

	nlock = qpzone_get_lock(node);
	NODE_WRLOCK(nlock, &nlocktype);

	/*
	 * Check if element is in the heap using hashmap lookup.
	 */
	qpz_resign_t *found_elem = NULL;
	isc_result_t find_result;

	LOCK(&qpdb->heap->lock);
	find_result = resign_lookup(qpdb->heap, header, node, &found_elem);

	if (find_result == ISC_R_SUCCESS) {
		/* Element is in heap */
		INSIST(RESIGN(header));
		if (resign == 0) {
			resign_unregister(qpdb->heap, node, header);
		} else {
			int64_t old_resign = header->resign;
			int64_t new_resign = dns_time64_from32(resign);

			header->resign = new_resign;

			if (resign_sooner_values(new_resign, header->typepair,
						 old_resign, header->typepair))
			{
				isc_heap_increased(qpdb->heap->heap,
						   found_elem->heap_index);
			} else if (resign_sooner_values(
					   old_resign, header->typepair,
					   new_resign, header->typepair))
			{
				isc_heap_decreased(qpdb->heap->heap,
						   found_elem->heap_index);
			}
			/* No heap adjustment needed if neither direction
			 * indicates sooner */
		}
	} else if (resign != 0) {
		/* Element not in heap, add it */
		header->resign = dns_time64_from32(resign);
		DNS_VECHEADER_SETATTR(header, DNS_VECHEADERATTR_RESIGN);

		resign_register(qpdb->heap, node, header);
	}
	UNLOCK(&qpdb->heap->lock);
	NODE_UNLOCK(nlock, &nlocktype);
	return ISC_R_SUCCESS;
}

static isc_result_t
getsigningtime(dns_db_t *db, isc_stdtime_t *resign, dns_name_t *foundname,
	       dns_typepair_t *typepair) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_resign_t *elem = NULL;
	dns_vecheader_t *header = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(resign != NULL);
	REQUIRE(foundname != NULL);
	REQUIRE(typepair != NULL);

	LOCK(&qpdb->heap->lock);
	elem = isc_heap_element(qpdb->heap->heap, 1);
	if (elem == NULL) {
		UNLOCK(&qpdb->heap->lock);
		return ISC_R_NOTFOUND;
	}
	nlock = qpzone_get_lock(elem->node);
	UNLOCK(&qpdb->heap->lock);

again:
	NODE_RDLOCK(nlock, &nlocktype);

	LOCK(&qpdb->heap->lock);
	elem = isc_heap_element(qpdb->heap->heap, 1);

	isc_rwlock_t *new_nlock = (elem != NULL) ? qpzone_get_lock(elem->node)
						 : NULL;
	if (new_nlock != NULL && new_nlock != nlock) {
		UNLOCK(&qpdb->heap->lock);
		NODE_UNLOCK(nlock, &nlocktype);

		nlock = new_nlock;
		goto again;
	}

	if (elem != NULL) {
		header = elem->header;
		*resign = RESIGN(header) ? (uint32_t)header->resign : 0;
		dns_name_copy(&elem->node->name, foundname);
		*typepair = header->typepair;
		result = ISC_R_SUCCESS;
	}
	UNLOCK(&qpdb->heap->lock);
	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static isc_result_t
setgluecachestats(dns_db_t *db, isc_stats_t *stats) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(!IS_STUB(qpdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &qpdb->gluecachestats);
	return ISC_R_SUCCESS;
}

static dns_qp_t *
begin_transaction(qpzonedb_t *qpdb, dns_qpread_t *qprp, bool create) {
	dns_qp_t *qp = NULL;

	if (create) {
		dns_qpmulti_write(qpdb->tree, &qp);
	} else {
		dns_qpmulti_query(qpdb->tree, qprp);
		qp = (dns_qp_t *)qprp;
	}

	return qp;
}

static void
end_transaction(qpzonedb_t *qpdb, dns_qp_t *qp, bool create) {
	if (create) {
		dns_qp_compact(qp, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &qp);
	} else {
		dns_qpread_t *qprp = (dns_qpread_t *)qp;
		dns_qpread_destroy(qpdb->tree, qprp);
	}
}

static isc_result_t
findnodeintree(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	       bool create, bool nsec3, dns_dbnode_t **nodep DNS__DB_FLARG) {
	isc_result_t result;
	qpznode_t *node = NULL;
	dns_namespace_t nspace = nsec3 ? DNS_DBNAMESPACE_NSEC3
				       : DNS_DBNAMESPACE_NORMAL;
	/*
	 * findnodeintree is a wrapper around dns_qp_getname that does some
	 * qpzone-specific bookkeeping before returning the lookup result to the
	 * caller.
	 *
	 * First, we do a lookup ...
	 */
	result = dns_qp_getname(qp, name, nspace, (void **)&node, NULL);
	if (result == ISC_R_SUCCESS) {
		/*
		 * ... if the lookup is successful, we need to increase both the
		 * internal and external reference count before returning to
		 * the caller. qpznode_acquire takes care of that.
		 */
		qpznode_acquire(node DNS__DB_FLARG_PASS);

		INSIST(node->nspace == DNS_DBNAMESPACE_NSEC3 || !nsec3);
	} else if (result != ISC_R_SUCCESS && create) {
		/*
		 * ... if the lookup is unsuccessful, but the caller asked us to
		 * create a new node, create one and insert it into the tree.
		 */
		node = new_qpznode(qpdb, name, nspace);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);

		/*
		 * The new node now has two internal references:
		 *  - One from new_qpznode, that initializes references at 1.
		 *  - One from attach_leaf, that increases the reference by
		 *    one at insertion in the qp-tree.
		 * We want the node to have two internal and one external
		 * reference:
		 *  - One internal reference from the qp-tree.
		 *  - One internal and one external reference from the caller.
		 *
		 * So we increase the external reference count by one.
		 */
		qpznode_erefs_increment(node DNS__DB_FLARG_PASS);

		if (!nsec3) {
			/*
			 * Add empty non-terminal nodes to help with wildcards.
			 */
			addwildcards(qpdb, qp, name, nspace);
			if (dns_name_iswildcard(name)) {
				wildcardmagic(qpdb, qp, name, nspace);
			}
		}

		INSIST(node->nspace == DNS_DBNAMESPACE_NSEC3 || !nsec3);
	}
	/*
	 * ... if the lookup is unsuccessful, and the caller didn't ask us
	 * to create a new node, there is nothing to do. Return the result
	 * of the lookup to the caller, and set *nodep to NULL
	 */

	*nodep = (dns_dbnode_t *)node;

	return result;
}

static isc_result_t
qpzone_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
		dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
		dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	dns_qpread_t qpr = { 0 };
	dns_qp_t *qp = begin_transaction(qpdb, &qpr, create);

	isc_result_t result = findnodeintree(qpdb, qp, name, create, false,
					     nodep DNS__DB_FLARG_PASS);

	end_transaction(qpdb, qp, create);

	return result;
}

static isc_result_t
qpzone_findnsec3node(dns_db_t *db, const dns_name_t *name, bool create,
		     dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	dns_qpread_t qpr = { 0 };
	dns_qp_t *qp = begin_transaction(qpdb, &qpr, create);

	isc_result_t result = findnodeintree(qpdb, qp, name, create, true,
					     nodep DNS__DB_FLARG_PASS);

	end_transaction(qpdb, qp, create);

	return result;
}

static bool
matchparams(dns_vecheader_t *header, qpz_search_t *search) {
	dns_rdata_nsec3_t nsec3;
	isc_result_t result;

	REQUIRE(header->typepair == DNS_TYPEPAIR(dns_rdatatype_nsec3));

	rdatavec_iter_t iter;
	DNS_VECHEADER_FOREACH(&iter, header, search->qpdb->common.rdclass) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		vecheader_current(&iter, &rdata);

		result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
		INSIST(result == ISC_R_SUCCESS);

		if (nsec3.hash == search->version->hash &&
		    nsec3.iterations == search->version->iterations &&
		    nsec3.salt.length == search->version->salt_length &&
		    memcmp(nsec3.salt.base, search->version->salt,
			   nsec3.salt.length) == 0)
		{
			return true;
		}
	}

	return false;
}

static isc_result_t
qpzone_setup_delegation(qpz_search_t *search, dns_dbnode_t **nodep,
			dns_name_t *foundname, dns_rdataset_t *rdataset,
			dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_name_t *zcname = NULL;
	dns_typepair_t typepair;
	qpznode_t *node = NULL;

	REQUIRE(search != NULL);
	REQUIRE(search->zonecut != NULL);
	REQUIRE(search->zonecut_header != NULL);

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	typepair = search->zonecut_header->typepair;

	/*
	 * If we have to set foundname, we do it before anything else.
	 * If we were to set foundname after we had set nodep or bound the
	 * rdataset, then we'd have to undo that work if dns_name_copy()
	 * failed.  By setting foundname first, there's nothing to undo if
	 * we have trouble.
	 */
	if (foundname != NULL && search->copy_name) {
		zcname = dns_fixedname_name(&search->zonecut_name);
		dns_name_copy(zcname, foundname);
	}
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
		isc_rwlock_t *nlock = qpzone_get_lock(node);
		NODE_RDLOCK(nlock, &nlocktype);
		bindrdataset(search->qpdb, search->zonecut_header,
			     rdataset DNS__DB_FLARG_PASS);
		if (sigrdataset != NULL && search->zonecut_sigheader != NULL) {
			bindrdataset(search->qpdb, search->zonecut_sigheader,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (typepair == DNS_TYPEPAIR(dns_rdatatype_dname)) {
		return DNS_R_DNAME;
	}
	return DNS_R_DELEGATION;
}

typedef enum { FORWARD, BACK } direction_t;

/*
 * Step backwards or forwards through the database until we find a
 * node with data in it for the desired version. If 'nextname' is not NULL,
 * and we found a predecessor or successor, save the name we found in it.
 * Return true if we found a predecessor or successor.
 */
static bool
step(qpz_search_t *search, dns_qpiter_t *it, direction_t direction,
     qpznode_t **node_p) {
	REQUIRE(node_p != NULL && *node_p == NULL);

	qpznode_t *node = NULL, *previous_node = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	result = dns_qpiter_current(it, (void **)&node, NULL);
	while (result == ISC_R_SUCCESS) {
		previous_node = node;

		isc_rwlock_t *nlock = qpzone_get_lock(node);
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		dns_vecheader_t *found = NULL;

		NODE_RDLOCK(nlock, &nlocktype);
		ISC_SLIST_FOREACH(top, node->next_type, next_type) {
			found = first_existing_header(top, search->serial);
		}
		NODE_UNLOCK(nlock, &nlocktype);
		if (found != NULL) {
			break;
		}

		if (direction == FORWARD) {
			result = dns_qpiter_next(it, (void **)&node, NULL);
		} else {
			result = dns_qpiter_prev(it, (void **)&node, NULL);
		}
	};

	if (result == ISC_R_SUCCESS) {
		if (previous_node != NULL) {
			*node_p = previous_node;
		}
		return true;
	}

	return false;
}

static bool
activeempty(qpz_search_t *search, dns_qpiter_t *it, const dns_name_t *current) {
	qpznode_t *next_node = NULL;

	/*
	 * The iterator is currently pointed at the predecessor
	 * of the name we were searching for. Step the iterator
	 * forward, then step() will continue forward until it
	 * finds a node with active data. If that node is a
	 * subdomain of the one we were looking for, then we're
	 * at an active empty nonterminal node.
	 */
	isc_result_t result = dns_qpiter_next(it, NULL, NULL);
	if (result != ISC_R_SUCCESS) {
		/* An ENT at the end of the zone is impossible */
		return false;
	}
	return step(search, it, FORWARD, &next_node) &&
	       dns_name_issubdomain(&next_node->name, current);
}

static bool
wildcard_blocked(qpz_search_t *search, const dns_name_t *qname,
		 dns_name_t *wname) {
	isc_result_t result;
	qpznode_t *next_node = NULL, *prev_node = NULL;
	dns_name_t name;
	dns_name_t rname;
	dns_name_t tname;
	dns_qpiter_t it;
	bool check_next = false;
	bool check_prev = false;
	unsigned int n;

	dns_name_init(&name);
	dns_name_init(&tname);
	dns_name_init(&rname);

	/*
	 * The qname seems to have matched a wildcard, but we
	 * need to find out if there's an empty nonterminal node
	 * between the wildcard level and the qname.
	 *
	 * search->iter should now be pointing at the predecessor
	 * of the searched-for name. We are using a local copy of the
	 * iterator so as not to change the state of search->iter.
	 * step() will walk backward until we find a predecessor with
	 * data.
	 */
	it = search->iter;
	check_prev = step(search, &it, BACK, &prev_node);

	/* Now reset the iterator and look for a successor with data. */
	it = search->iter;
	result = dns_qpiter_next(&it, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		check_next = step(search, &it, FORWARD, &next_node);
	}

	if (!check_prev && !check_next) {
		/* No predecessor or successor was found at all? */
		return false;
	}

	dns_name_clone(qname, &rname);

	/*
	 * Remove the wildcard label to find the terminal name.
	 */
	n = dns_name_countlabels(wname);
	dns_name_getlabelsequence(wname, 1, n - 1, &tname);

	do {
		if ((check_prev &&
		     dns_name_issubdomain(&prev_node->name, &rname)) ||
		    (check_next &&
		     dns_name_issubdomain(&next_node->name, &rname)))
		{
			return true;
		}

		/*
		 * Remove the leftmost label from the qname and check again.
		 */
		n = dns_name_countlabels(&rname);
		dns_name_getlabelsequence(&rname, 1, n - 1, &rname);
	} while (!dns_name_equal(&rname, &tname));

	return false;
}

static bool
node_active(qpz_search_t *search, qpznode_t *node) {
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		if (first_existing_header(top, search->serial) != NULL) {
			return true;
		}
	}
	return false;
}

static isc_result_t
find_wildcard(qpz_search_t *search, qpznode_t **nodep, const dns_name_t *qname,
	      dns_namespace_t nspace) {
	isc_result_t result = ISC_R_NOTFOUND;

	/*
	 * Examine each ancestor level.  If the level's wild bit
	 * is set, then construct the corresponding wildcard name and
	 * search for it.  If the wildcard node exists, and is active in
	 * this version, we're done.  If not, then we next check to see
	 * if the ancestor is active in this version.  If so, then there
	 * can be no possible wildcard match and again we're done.  If not,
	 * continue the search.
	 */
	for (int i = dns_qpchain_length(&search->chain) - 1; i >= 0; i--) {
		qpznode_t *node = NULL;
		isc_rwlock_t *nlock = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		bool wild, active;

		dns_qpchain_node(&search->chain, i, (void **)&node, NULL);

		nlock = qpzone_get_lock(node);
		NODE_RDLOCK(nlock, &nlocktype);
		/*
		 * First we try to figure out if this node is active in
		 * the search's version.  We do this now, even though we
		 * may not need the information, because it simplifies the
		 * locking and code flow.
		 */
		active = node_active(search, node);
		wild = node->wild;
		NODE_UNLOCK(nlock, &nlocktype);

		if (wild) {
			qpznode_t *wnode = NULL;
			dns_fixedname_t fwname;
			dns_name_t *wname = dns_fixedname_initname(&fwname);
			dns_qpiter_t wit;
			bool wactive;

			/*
			 * Construct the wildcard name for this level.
			 */
			result = dns_name_concatenate(dns_wildcardname,
						      &node->name, wname);
			if (result != ISC_R_SUCCESS) {
				break;
			}

			result = dns_qp_lookup(&search->qpr, wname, nspace,
					       &wit, NULL, (void **)&wnode,
					       NULL);
			if (result == ISC_R_SUCCESS) {
				/*
				 * We have found the wildcard node.  If it
				 * is active in the search's version, we're
				 * done.
				 */
				nlock = qpzone_get_lock(wnode);
				NODE_RDLOCK(nlock, &nlocktype);
				wactive = node_active(search, wnode);
				NODE_UNLOCK(nlock, &nlocktype);
				if (wactive || activeempty(search, &wit, wname))
				{
					if (wildcard_blocked(search, qname,
							     wname))
					{
						return ISC_R_NOTFOUND;
					}

					/*
					 * The wildcard node is active!
					 *
					 * Note: result is still ISC_R_SUCCESS
					 * so we don't have to set it.
					 */
					*nodep = wnode;
					break;
				}
			} else if (result != ISC_R_NOTFOUND &&
				   result != DNS_R_PARTIALMATCH)
			{
				/*
				 * An error has occurred.  Bail out.
				 */
				break;
			}
		}

		if (active) {
			/*
			 * The level node is active.  Any wildcarding
			 * present at higher levels has no
			 * effect and we're done.
			 */
			result = ISC_R_NOTFOUND;
			break;
		}
	}

	return result;
}

/*
 * Find node of the NSEC/NSEC3 record preceding 'name'.
 */
static isc_result_t
previous_closest_nsec(dns_rdatatype_t type, qpz_search_t *search,
		      dns_name_t *name, qpznode_t **nodep, dns_qpiter_t *nit,
		      bool *firstp) {
	isc_result_t result;

	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE(type == dns_rdatatype_nsec3 || firstp != NULL);

	if (type == dns_rdatatype_nsec3) {
		result = dns_qpiter_prev(&search->iter, (void **)nodep, NULL);
		if (result == ISC_R_SUCCESS) {
			dns_name_copy(&(*nodep)->name, name);
		}
		return result;
	}

	for (;;) {
		qpznode_t *nsec_node = NULL;

		if (*firstp) {
			/*
			 * This is the first attempt to find 'name' in the
			 * NSEC namespace.
			 */
			*firstp = false;
			result = dns_qp_lookup(&search->qpr, name,
					       DNS_DBNAMESPACE_NSEC, nit, NULL,
					       NULL, NULL);

			INSIST(result != ISC_R_NOTFOUND);
			if (result == ISC_R_SUCCESS) {
				/*
				 * If we find an exact match in the NSEC
				 * namespace on our first attempt, it
				 * implies that the corresponding node in
				 * the normal namespace had an unacceptable
				 * NSEC record; we want the previous node
				 * in the NSEC tree.
				 */
				result = dns_qpiter_prev(
					nit, (void **)&nsec_node, NULL);
			} else if (result == DNS_R_PARTIALMATCH) {
				/*
				 * This was a partial match, so the
				 * iterator is already at the previous
				 * node in the NSEC namespace, which is
				 * what we want.
				 */
				isc_result_t iresult = dns_qpiter_current(
					nit, (void **)&nsec_node, NULL);
				REQUIRE(iresult == ISC_R_SUCCESS);
				result = ISC_R_SUCCESS;
			}
		} else {
			/*
			 * We've taken at least two steps back through the
			 * NSEC namespace. The previous steps must have
			 * found nodes with NSEC records, but they didn't
			 * work; perhaps they lacked signature records.
			 * Keep searching.
			 */
			result = dns_qpiter_prev(nit, (void **)&nsec_node,
						 NULL);
		}

		if (result != ISC_R_SUCCESS) {
			break;
		}

		*nodep = NULL;
		result = dns_qp_lookup(&search->qpr, &nsec_node->name,
				       DNS_DBNAMESPACE_NORMAL, &search->iter,
				       &search->chain, (void **)nodep, NULL);
		if (result == ISC_R_SUCCESS) {
			dns_name_copy(&nsec_node->name, name);
			break;
		}

		/*
		 * There should always be a node in the normal namespace
		 * with the same name as the node in the NSEC namespace,
		 * except when nodes in the NSEC namespace are awaiting
		 * deletion.
		 */
		if (result != DNS_R_PARTIALMATCH && result != ISC_R_NOTFOUND) {
			isc_log_write(DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DB, ISC_LOG_ERROR,
				      "previous_closest_nsec(): %s",
				      isc_result_totext(result));
			result = DNS_R_BADDB;
			break;
		}
	}

	return result;
}

/*
 * Find the NSEC/NSEC3 which is at or before the name being sought.
 * For NSEC3 records only NSEC3 records that match the
 * current NSEC3PARAM record are considered.
 */
static isc_result_t
find_closest_nsec(qpz_search_t *search, dns_dbnode_t **nodep,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset, bool nsec3,
		  bool secure DNS__DB_FLARG) {
	qpznode_t *node = NULL, *prevnode = NULL;
	dns_qpiter_t nseciter;
	bool empty_node;
	isc_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_rdatatype_t matchtype = nsec3 ? dns_rdatatype_nsec3
					  : dns_rdatatype_nsec;
	dns_typepair_t typepair = DNS_TYPEPAIR(matchtype);
	dns_typepair_t sigpair = DNS_SIGTYPEPAIR(matchtype);
	bool wraps = nsec3;
	bool first = true;
	bool need_sig = secure;

	/*
	 * When a lookup is unsuccessful, the QP iterator will already
	 * be pointing at the node preceding the searched-for name in
	 * the normal namespace. We'll check there first, assuming it will
	 * be right much of the time. If we don't find an NSEC there,
	 * then we start using the auxiliary NSEC namespace to find
	 * the next predecessor.
	 */
	result = dns_qpiter_current(&search->iter, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	dns_name_copy(&node->name, name);
again:
	do {
		dns_vecheader_t *found = NULL, *foundsig = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		isc_rwlock_t *nlock = qpzone_get_lock(node);
		NODE_RDLOCK(nlock, &nlocktype);
		empty_node = true;
		ISC_SLIST_FOREACH(top, node->next_type, next_type) {
			/*
			 * Look for an active, extant NSEC or RRSIG NSEC.
			 */
			dns_vecheader_t *header =
				first_existing_header(top, search->serial);
			if (header != NULL) {
				/*
				 * We now know that there is at least one
				 * active rdataset at this node.
				 */
				empty_node = false;
				if (top->typepair == typepair) {
					found = header;
					if (foundsig != NULL) {
						break;
					}
				} else if (top->typepair == sigpair) {
					foundsig = header;
					if (found != NULL) {
						break;
					}
				}
			}
		}
		if (!empty_node) {
			if (found != NULL && search->version->havensec3 &&
			    found->typepair ==
				    DNS_TYPEPAIR(dns_rdatatype_nsec3) &&
			    !matchparams(found, search))
			{
				empty_node = true;
				found = NULL;
				foundsig = NULL;
				result = previous_closest_nsec(typepair, search,
							       name, &prevnode,
							       NULL, NULL);
			} else if (found != NULL &&
				   (foundsig != NULL || !need_sig))
			{
				/*
				 * We've found the right NSEC/NSEC3 record.
				 *
				 * Note: for this to really be the right
				 * NSEC record, it's essential that the NSEC
				 * records of any nodes obscured by a zone
				 * cut have been removed; we assume this is
				 * the case.
				 */
				dns_name_copy(name, foundname);
				if (nodep != NULL) {
					qpznode_acquire(
						node DNS__DB_FLARG_PASS);
					*nodep = (dns_dbnode_t *)node;
				}
				bindrdataset(search->qpdb, found,
					     rdataset DNS__DB_FLARG_PASS);
				if (foundsig != NULL) {
					bindrdataset(
						search->qpdb, foundsig,
						sigrdataset DNS__DB_FLARG_PASS);
				}
			} else if (found == NULL && foundsig == NULL) {
				/*
				 * This node is active, but has no NSEC or
				 * RRSIG NSEC.  That means it's glue or
				 * other obscured zone data that isn't
				 * relevant for our search.  Treat the
				 * node as if it were empty and keep looking.
				 */
				empty_node = true;
				result = previous_closest_nsec(
					typepair, search, name, &prevnode,
					&nseciter, &first);
			} else {
				/*
				 * We found an active node, but either the
				 * NSEC or the RRSIG NSEC is missing.  This
				 * shouldn't happen.
				 */
				result = DNS_R_BADDB;
			}
		} else {
			/*
			 * This node isn't active.  We've got to keep
			 * looking.
			 */
			result = previous_closest_nsec(typepair, search, name,
						       &prevnode, &nseciter,
						       &first);
		}
		NODE_UNLOCK(nlock, &nlocktype);
		node = prevnode;
		prevnode = NULL;
	} while (empty_node && result == ISC_R_SUCCESS);

	if (result == ISC_R_NOMORE && wraps) {
		result = dns_qpiter_prev(&search->iter, (void **)&node, NULL);
		if (result == ISC_R_SUCCESS) {
			dns_name_copy(&node->name, name);
			wraps = false;
			goto again;
		}
	}

	/*
	 * If the result is ISC_R_NOMORE, then we got to the beginning of
	 * the database and didn't find a NSEC record.  This shouldn't
	 * happen.
	 */
	if (result == ISC_R_NOMORE) {
		result = DNS_R_BADDB;
	}

	return result;
}

static isc_result_t
qpzone_check_zonecut(qpznode_t *node, void *arg DNS__DB_FLARG) {
	qpz_search_t *search = arg;
	dns_vecheader_t *dname_header = NULL, *sigdname_header = NULL;
	dns_vecheader_t *ns_header = NULL;
	dns_vecheader_t *found = NULL;
	isc_result_t result = DNS_R_CONTINUE;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = qpzone_get_lock(node);

	NODE_RDLOCK(nlock, &nlocktype);

	/*
	 * Look for an NS or DNAME rdataset active in our version.
	 */
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		if (top->typepair == DNS_TYPEPAIR(dns_rdatatype_ns) ||
		    top->typepair == DNS_TYPEPAIR(dns_rdatatype_dname) ||
		    top->typepair == DNS_SIGTYPEPAIR(dns_rdatatype_dname))
		{
			dns_vecheader_t *header =
				first_existing_header(top, search->serial);
			if (header != NULL) {
				if (top->typepair ==
				    DNS_TYPEPAIR(dns_rdatatype_dname))
				{
					dname_header = header;
				} else if (top->typepair ==
					   DNS_SIGTYPEPAIR(dns_rdatatype_dname))
				{
					sigdname_header = header;
				} else if (node != search->qpdb->origin ||
					   IS_STUB(search->qpdb))
				{
					/*
					 * We've found an NS rdataset that
					 * isn't at the origin node.
					 */
					ns_header = header;
				}
			}
		}
	}

	/*
	 * Did we find anything?
	 */
	if (!IS_STUB(search->qpdb) && ns_header != NULL) {
		/*
		 * Note that NS has precedence over DNAME if both exist
		 * in a zone.  Otherwise DNAME take precedence over NS.
		 */
		found = ns_header;
		search->zonecut_sigheader = NULL;
	} else if (dname_header != NULL) {
		found = dname_header;
		search->zonecut_sigheader = sigdname_header;
	} else if (ns_header != NULL) {
		found = ns_header;
		search->zonecut_sigheader = NULL;
	}

	if (found != NULL) {
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_header will still be valid later.
		 */
		qpznode_acquire(node DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = found;
		search->need_cleanup = true;
		/*
		 * Since we've found a zonecut, anything beneath it is
		 * glue and is not subject to wildcard matching, so we
		 * may clear search->wild.
		 */
		search->wild = false;
		if ((search->options & DNS_DBFIND_GLUEOK) == 0) {
			/*
			 * If the caller does not want to find glue, then
			 * this is the best answer and the search should
			 * stop now.
			 */
			result = DNS_R_PARTIALMATCH;
		} else {
			dns_name_t *zcname = NULL;

			/*
			 * The search will continue beneath the zone cut.
			 * This may or may not be the best match.  In case it
			 * is, we need to remember the node name.
			 */
			zcname = dns_fixedname_name(&search->zonecut_name);
			dns_name_copy(&node->name, zcname);
			search->copy_name = true;
		}
	} else {
		/*
		 * There is no zonecut at this node which is active in this
		 * version.
		 *
		 * If this is a "wild" node and the caller hasn't disabled
		 * wildcard matching, remember that we've seen a wild node
		 * in case we need to go searching for wildcard matches
		 * later on.
		 */
		if (node->wild && (search->options & DNS_DBFIND_NOWILD) == 0) {
			search->wild = true;
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static void
qpz_search_init(qpz_search_t *search, qpzonedb_t *db, qpz_version_t *version,
		unsigned int options) {
	/*
	 * qpz_search_t contains two structures with large buffers (dns_qpiter_t
	 * and dns_qpchain_t). Those two structures will be initialized later by
	 * dns_qp_lookup anyway.
	 * To avoid the overhead of zero initialization, we avoid designated
	 * initializers and initialize all "small" fields manually.
	 */
	search->qpdb = db;
	search->version = version;
	search->qpr = (dns_qpread_t){};
	search->serial = version->serial;
	search->options = options;
	/*
	 * qpch->in -- init in dns_qp_lookup
	 * qpiter -- init in dns_qp_lookup
	 */
	search->copy_name = false;
	search->need_cleanup = false;
	search->wild = false;
	search->zonecut = NULL;
	search->zonecut_header = NULL;
	search->zonecut_sigheader = NULL;
	dns_fixedname_init(&search->zonecut_name);
}

static isc_result_t
qpzone_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	    dns_rdatatype_t type, unsigned int options,
	    isc_stdtime_t now ISC_ATTR_UNUSED, dns_dbnode_t **nodep,
	    dns_name_t *foundname,
	    dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
	    dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
	    dns_rdataset_t *rdataset,
	    dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_result_t result;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = NULL;
	bool cname_ok = true, close_version = false;
	bool maybe_zonecut = false, at_zonecut = false;
	bool wild = false, empty_node = false;
	bool nsec3 = false;
	dns_vecheader_t *found = NULL, *nsecheader = NULL;
	dns_vecheader_t *foundsig = NULL, *cnamesig = NULL, *nsecsig = NULL;
	dns_typepair_t sigpair;
	bool active;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPZONE((qpzonedb_t *)db));
	INSIST(version == NULL ||
	       ((qpz_version_t *)version)->qpdb == (qpzonedb_t *)db);

	/*
	 * If the caller didn't supply a version, attach to the current
	 * version.
	 */
	if (version == NULL) {
		currentversion(db, &version);
		close_version = true;
	}

	dns_namespace_t nspace;
	qpz_search_t search;
	qpz_search_init(&search, (qpzonedb_t *)db, (qpz_version_t *)version,
			options);

	if ((options & DNS_DBFIND_FORCENSEC3) != 0) {
		nsec3 = true;
		nspace = DNS_DBNAMESPACE_NSEC3;
	} else {
		nspace = DNS_DBNAMESPACE_NORMAL;
	}
	dns_qpmulti_query(qpdb->tree, &search.qpr);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(&search.qpr, name, nspace, &search.iter,
			       &search.chain, (void **)&node, NULL);
	if (result != ISC_R_NOTFOUND) {
		dns_name_copy(&node->name, foundname);
	}

	/*
	 * Check the QP chain to see if there's a node above us with a
	 * active DNAME or NS rdatasets.
	 *
	 * We're only interested in nodes above QNAME, so if the result
	 * was success, then we skip the last item in the chain.
	 */
	unsigned int clen = dns_qpchain_length(&search.chain);
	if (result == ISC_R_SUCCESS) {
		clen--;
	}
	for (unsigned int i = 0; i < clen && search.zonecut == NULL; i++) {
		qpznode_t *n = NULL;
		isc_result_t tresult;

		dns_qpchain_node(&search.chain, i, (void **)&n, NULL);
		tresult = qpzone_check_zonecut(n, &search DNS__DB_FLARG_PASS);
		if (tresult != DNS_R_CONTINUE) {
			result = tresult;
			search.chain.len = i - 1;
			dns_name_copy(&n->name, foundname);
			node = n;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
	partial_match:
		if (search.zonecut != NULL) {
			result = qpzone_setup_delegation(
				&search, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		}

		if (search.wild) {
			/*
			 * At least one of the levels in the search chain
			 * potentially has a wildcard.  For each such level,
			 * we must see if there's a matching wildcard active
			 * in the current version.
			 */
			result = find_wildcard(&search, &node, name, nspace);
			if (result == ISC_R_SUCCESS) {
				dns_name_copy(name, foundname);
				wild = true;
				goto found;
			} else if (result != ISC_R_NOTFOUND) {
				goto tree_exit;
			}
		}

		active = false;
		if (!nsec3) {
			/*
			 * The NSEC3 tree won't have empty nodes,
			 * so it isn't necessary to check for them.
			 */
			dns_qpiter_t iter = search.iter;
			active = activeempty(&search, &iter, name);
		}

		/*
		 * If we're here, then the name does not exist, is not
		 * beneath a zonecut, and there's no matching wildcard.
		 */
		if ((search.version->secure && !search.version->havensec3) ||
		    nsec3)
		{
			result = find_closest_nsec(
				&search, nodep, foundname, rdataset,
				sigrdataset, nsec3,
				search.version->secure DNS__DB_FLARG_PASS);
			if (result == ISC_R_SUCCESS) {
				result = active ? DNS_R_EMPTYNAME
						: DNS_R_NXDOMAIN;
			}
		} else {
			result = active ? DNS_R_EMPTYNAME : DNS_R_NXDOMAIN;
		}
		goto tree_exit;
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

found:
	/*
	 * We have found a node whose name is the desired name, or we
	 * have matched a wildcard.
	 */

	nlock = qpzone_get_lock(node);
	NODE_RDLOCK(nlock, &nlocktype);

	if (search.zonecut != NULL) {
		/*
		 * If we're beneath a zone cut, we don't want to look for
		 * CNAMEs because they're not legitimate zone glue.
		 */
		cname_ok = false;
	} else {
		/*
		 * The node may be a zone cut itself.  If it might be one,
		 * make sure we check for it later.
		 *
		 * DS records live above the zone cut in ordinary zone so
		 * we want to ignore any referral.
		 *
		 * Stub zones don't have anything "above" the delegation so
		 * we always return a referral.
		 */
		if (node->delegating && ((node != search.qpdb->origin &&
					  !dns_rdatatype_atparent(type)) ||
					 IS_STUB(search.qpdb)))
		{
			maybe_zonecut = true;
		}
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5).
	 *
	 * We don't check for RRSIG, because we don't store RRSIG records
	 * directly.
	 */
	if (type == dns_rdatatype_nsec) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	sigpair = DNS_SIGTYPEPAIR(type);
	empty_node = true;
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		/*
		 * Look for an active, extant rdataset.
		 */
		dns_vecheader_t *header = first_existing_header(top,
								search.serial);
		if (header != NULL) {
			/*
			 * We now know that there is at least one active
			 * rdataset at this node.
			 */
			empty_node = false;

			/*
			 * Do special zone cut handling, if requested.
			 */
			if (maybe_zonecut &&
			    top->typepair == DNS_TYPEPAIR(dns_rdatatype_ns))
			{
				/*
				 * We increment the reference count on node to
				 * ensure that search->zonecut_header will
				 * still be valid later.
				 */
				qpznode_acquire(node DNS__DB_FLARG_PASS);
				search.zonecut = node;
				search.zonecut_header = header;
				search.zonecut_sigheader = NULL;
				search.need_cleanup = true;
				maybe_zonecut = false;
				at_zonecut = true;

				if ((search.options & DNS_DBFIND_GLUEOK) == 0 &&
				    type != dns_rdatatype_nsec)
				{
					/*
					 * Glue is not OK, but any answer we
					 * could return would be glue.  Return
					 * the delegation.
					 */
					found = NULL;
					break;
				}
				if (found != NULL && foundsig != NULL) {
					break;
				}
			}

			/*
			 * If the NSEC3 record doesn't match the chain
			 * we are using behave as if it isn't here.
			 */
			if (top->typepair ==
				    DNS_TYPEPAIR(dns_rdatatype_nsec3) &&
			    !matchparams(header, &search))
			{
				NODE_UNLOCK(nlock, &nlocktype);
				goto partial_match;
			}
			/*
			 * If we found a type we were looking for,
			 * remember it.
			 */
			if (top->typepair == type ||
			    type == dns_rdatatype_any ||
			    (top->typepair ==
				     DNS_TYPEPAIR(dns_rdatatype_cname) &&
			     cname_ok))
			{
				/*
				 * We've found the answer!
				 */
				found = header;
				if (top->typepair ==
					    DNS_TYPEPAIR(dns_rdatatype_cname) &&
				    cname_ok)
				{
					/*
					 * We may be finding a CNAME instead
					 * of the desired type.
					 *
					 * If we've already got the CNAME RRSIG,
					 * use it, otherwise change sigtype
					 * so that we find it.
					 */
					if (cnamesig != NULL) {
						foundsig = cnamesig;
					} else {
						sigpair = DNS_SIGTYPEPAIR(
							dns_rdatatype_cname);
					}
				}
				/*
				 * If we've got all we need, end the search.
				 */
				if (!maybe_zonecut && foundsig != NULL) {
					break;
				}
			} else if (top->typepair == sigpair) {
				/*
				 * We've found the RRSIG rdataset for our
				 * target type.  Remember it.
				 */
				foundsig = header;
				/*
				 * If we've got all we need, end the search.
				 */
				if (!maybe_zonecut && found != NULL) {
					break;
				}
			} else if (top->typepair ==
					   DNS_TYPEPAIR(dns_rdatatype_nsec) &&
				   !search.version->havensec3)
			{
				/*
				 * Remember a NSEC rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nsecheader = header;
			} else if (top->typepair ==
					   DNS_SIGTYPEPAIR(
						   dns_rdatatype_nsec) &&
				   !search.version->havensec3)
			{
				/*
				 * If we need the NSEC rdataset, we'll also
				 * need its signature.
				 */
				nsecsig = header;
			} else if (cname_ok &&
				   top->typepair ==
					   DNS_SIGTYPEPAIR(dns_rdatatype_cname))
			{
				/*
				 * If we get a CNAME match, we'll also need
				 * its signature.
				 */
				cnamesig = header;
			}
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * active rdatasets in the desired version.  That means that
		 * this node doesn't exist in the desired version.
		 * If there's a node above this one, reassign the
		 * foundname to the parent and treat this as a partial
		 * match.
		 */
		if (!wild) {
			unsigned int len = search.chain.len - 1;
			if (len > 0) {
				NODE_UNLOCK(nlock, &nlocktype);
				dns_qpchain_node(&search.chain, len - 1,
						 (void **)&node, NULL);
				dns_name_copy(&node->name, foundname);
				goto partial_match;
			}
		}
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL) {
		if (search.zonecut != NULL) {
			/*
			 * We were trying to find glue at a node beneath a
			 * zone cut, but didn't.
			 *
			 * Return the delegation.
			 */
			NODE_UNLOCK(nlock, &nlocktype);
			result = qpzone_setup_delegation(
				&search, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		}
		/*
		 * The desired type doesn't exist.
		 */
		result = DNS_R_NXRRSET;
		if (search.version->secure && !search.version->havensec3 &&
		    (nsecheader == NULL || nsecsig == NULL))
		{
			/*
			 * The zone is secure but there's no NSEC,
			 * or the NSEC has no signature!
			 */
			if (!wild) {
				result = DNS_R_BADDB;
				goto node_exit;
			}

			NODE_UNLOCK(nlock, &nlocktype);
			result = find_closest_nsec(
				&search, nodep, foundname, rdataset,
				sigrdataset, false,
				search.version->secure DNS__DB_FLARG_PASS);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_EMPTYWILD;
			}
			goto tree_exit;
		}
		if (nodep != NULL) {
			qpznode_acquire(node DNS__DB_FLARG_PASS);
			*nodep = (dns_dbnode_t *)node;
		}
		if (search.version->secure && !search.version->havensec3) {
			bindrdataset(search.qpdb, nsecheader,
				     rdataset DNS__DB_FLARG_PASS);
			if (nsecsig != NULL) {
				bindrdataset(search.qpdb, nsecsig,
					     sigrdataset DNS__DB_FLARG_PASS);
			}
		}
		if (wild) {
			foundname->attributes.wildcard = true;
		}
		goto node_exit;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */
	if (type != found->typepair && type != dns_rdatatype_any &&
	    found->typepair == DNS_TYPEPAIR(dns_rdatatype_cname))
	{
		/*
		 * We weren't doing an ANY query and we found a CNAME instead
		 * of the type we were looking for, so we need to indicate
		 * that result to the caller.
		 */
		result = DNS_R_CNAME;
	} else if (search.zonecut != NULL) {
		/*
		 * If we're beneath a zone cut, we must indicate that the
		 * result is glue, unless we're actually at the zone cut
		 * and the type is NSEC.
		 */
		if (search.zonecut == node) {
			if (dns_rdatatype_isnsec(type)) {
				result = ISC_R_SUCCESS;
			} else if (type == dns_rdatatype_any) {
				result = DNS_R_ZONECUT;
			} else {
				result = DNS_R_GLUE;
			}
		} else {
			result = DNS_R_GLUE;
		}
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = ISC_R_SUCCESS;
	}

	if (nodep != NULL) {
		if (!at_zonecut) {
			qpznode_acquire(node DNS__DB_FLARG_PASS);
		} else {
			search.need_cleanup = false;
		}
		*nodep = (dns_dbnode_t *)node;
	}

	if (type != dns_rdatatype_any) {
		bindrdataset(search.qpdb, found, rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(search.qpdb, foundsig,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	if (wild) {
		foundname->attributes.wildcard = true;
	}

node_exit:
	NODE_UNLOCK(nlock, &nlocktype);

tree_exit:
	dns_qpread_destroy(qpdb->tree, &search.qpr);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);
		nlock = qpzone_get_lock(node);

		NODE_RDLOCK(nlock, &nlocktype);
		(void)qpznode_release(node DNS__DB_FLARG_PASS);
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (close_version) {
		closeversion(db, &version, false DNS__DB_FLARG_PASS);
	}

	return result;
}

static isc_result_t
qpzone_allrdatasets(dns_db_t *db, dns_dbnode_t *dbnode,
		    dns_dbversion_t *dbversion, unsigned int options,
		    isc_stdtime_t now ISC_ATTR_UNUSED,
		    dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	qpdb_rdatasetiter_t *iterator = NULL;

	REQUIRE(VALID_QPZONE(qpdb));

	if (version == NULL) {
		currentversion(db, (dns_dbversion_t **)(void *)(&version));
	} else {
		INSIST(version->qpdb == qpdb);
		isc_refcount_increment(&version->references);
	}

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));
	*iterator = (qpdb_rdatasetiter_t){
		.common.methods = &rdatasetiter_methods,
		.common.db = db,
		.common.node = (dns_dbnode_t *)node,
		.common.version = (dns_dbversion_t *)version,
		.common.options = options,
		.common.magic = DNS_RDATASETITER_MAGIC,
	};

	qpznode_acquire(node DNS__DB_FLARG_PASS);

	*iteratorp = (dns_rdatasetiter_t *)iterator;
	return ISC_R_SUCCESS;
}

static void
qpzone_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG) {
	qpznode_t *node = (qpznode_t *)source;

	REQUIRE(targetp != NULL && *targetp == NULL);

	qpznode_acquire(node DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
qpzone_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpznode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(nodep != NULL && *nodep != NULL);

	node = (qpznode_t *)(*nodep);

	*nodep = NULL;
	nlock = qpzone_get_lock(node);

	/*
	 * qpzone_destroy() uses call_rcu() API to destroy the node locks, so it
	 * is safe to call it in the middle of NODE_LOCK, but we need to acquire
	 * the database reference to prevent destroying the database while the
	 * NODE_LOCK is locked.
	 */

	rcu_read_lock();
	NODE_RDLOCK(nlock, &nlocktype);
	(void)qpznode_release(node DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
	rcu_read_unlock();
}

static unsigned int
nodecount(dns_db_t *db) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_qp_memusage_t mu;

	REQUIRE(VALID_QPZONE(qpdb));

	mu = dns_qpmulti_memusage(qpdb->tree);

	return mu.leaves;
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to the origin node doesn't require a DB lock */
	INSIST(qpdb->origin != NULL);
	qpznode_acquire(qpdb->origin DNS__DB_FLARG_PASS);
	*nodep = (dns_dbnode_t *)qpdb->origin;

	return ISC_R_SUCCESS;
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = NULL;

	qrditer = (qpdb_rdatasetiter_t *)(*iteratorp);

	if (qrditer->common.version != NULL) {
		closeversion(qrditer->common.db, &qrditer->common.version,
			     false DNS__DB_FLARG_PASS);
	}
	dns__db_detachnode(&qrditer->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(qrditer->common.db->mctx, qrditer, sizeof(*qrditer));

	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpznode_t *node = (qpznode_t *)qrditer->common.node;
	qpz_version_t *version = (qpz_version_t *)qrditer->common.version;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = qpzone_get_lock(node);

	qrditer->currenttop = NULL;
	qrditer->current = NULL;

	NODE_RDLOCK(nlock, &nlocktype);

	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		qrditer->current = first_existing_header(top, version->serial);

		if (qrditer->current != NULL) {
			qrditer->currenttop = top;
			break;
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (qrditer->currenttop == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpznode_t *node = (qpznode_t *)qrditer->common.node;
	qpz_version_t *version = (qpz_version_t *)qrditer->common.version;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = qpzone_get_lock(node);
	dns_vectop_t *from = NULL;

	if (qrditer->currenttop == NULL) {
		return ISC_R_NOMORE;
	}

	NODE_RDLOCK(nlock, &nlocktype);

	from = ISC_SLIST_NEXT(qrditer->currenttop, next_type);
	qrditer->currenttop = NULL;
	qrditer->current = NULL;

	/*
	 * Find the start of the header chain for the next type.
	 */
	if (from != NULL) {
		ISC_SLIST_FOREACH_FROM(top, node->next_type, next_type, from) {
			qrditer->current =
				first_existing_header(top, version->serial);
			if (qrditer->current != NULL) {
				qrditer->currenttop = top;
				break;
			}
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (qrditer->currenttop == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)(qrditer->common.db);
	qpznode_t *qpnode = (qpznode_t *)qrditer->common.node;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = qpzone_get_lock(qpnode);
	dns_vecheader_t *header = qrditer->current;

	REQUIRE(header != NULL);

	NODE_RDLOCK(nlock, &nlocktype);

	bindrdataset(qpdb, header, rdataset DNS__DB_FLARG_PASS);

	NODE_UNLOCK(nlock, &nlocktype);
}

/*
 * Database Iterator Methods
 */
static void
reference_iter_node(qpdb_dbiterator_t *iter DNS__DB_FLARG) {
	qpznode_t *node = iter->node;

	if (node == NULL) {
		return;
	}

	qpznode_acquire(node DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpdb_dbiterator_t *iter DNS__DB_FLARG) {
	qpznode_t *node = iter->node;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	if (node == NULL) {
		return;
	}

	iter->node = NULL;
	nlock = qpzone_get_lock(node);

	NODE_RDLOCK(nlock, &nlocktype);
	(void)qpznode_release(node DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpdb_dbiterator_t *iter = (qpdb_dbiterator_t *)(*iteratorp);
	dns_db_t *db = NULL;

	dereference_iter_node(iter DNS__DB_FLARG_PASS);

	dns_db_attach(iter->common.db, &db);
	dns_db_detach(&iter->common.db);

	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_qpsnap_destroy(qpdb->tree, &iter->snap);

	isc_mem_put(db->mctx, iter, sizeof(*iter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_qpiter_init(qpdbiter->snap, &qpdbiter->iter);
	result = dns_qpiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	switch (qpdbiter->nsec3mode) {
	case nonsec3:
		if (result == ISC_R_SUCCESS) {
			/*
			 * If we immediately hit an NSEC/NSEC3 node,
			 * we don't have any non-nsec nodes.
			 */
			if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NORMAL) {
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			}
		}
		break;
	case full:
		/* skip the NSEC3 origin node. */
		if (result == ISC_R_SUCCESS &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			result = dns_qpiter_next(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		if (result != ISC_R_SUCCESS) {
			qpdbiter->node = NULL;
			break;
		}

		/*
		 * If we hit an NSEC node, we need to start at the NSEC3 part of
		 * the tree.
		 */
		if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NSEC) {
			break;
		}
		INSIST(qpdbiter->node->nspace == DNS_DBNAMESPACE_NSEC);

		/* FALLTHROUGH */
	case nsec3only:
		/*
		 * NSEC3 follows after all non-nsec3 nodes, seek the NSEC3
		 * origin node.
		 */
		result = dns_qp_lookup(qpdbiter->snap, &qpdb->common.origin,
				       DNS_DBNAMESPACE_NSEC3, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		if (result != ISC_R_SUCCESS ||
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			/* skip the NSEC3 origin node (or its predecessor) */
			result = dns_qpiter_next(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}
	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_qpiter_init(qpdbiter->snap, &qpdbiter->iter);
	result = dns_qpiter_prev(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		if (result == ISC_R_SUCCESS) {
			if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
				/* tree only has NSEC3 origin node. */
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			} else if (qpdbiter->node->nspace !=
				   DNS_DBNAMESPACE_NSEC3)
			{
				/* tree has no NSEC3 nodes at all. */
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			}
		}
		break;
	case full:
		/* skip the NSEC3 origin node. */
		if (result == ISC_R_SUCCESS &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			result = dns_qpiter_prev(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		if (result != ISC_R_SUCCESS) {
			qpdbiter->node = NULL;
			break;
		}

		/*
		 * If we hit an NSEC node, we need to seek the final normal node
		 * of the tree.
		 */
		if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NSEC) {
			break;
		}
		INSIST(qpdbiter->node->nspace == DNS_DBNAMESPACE_NSEC);

		/* FALLTHROUGH */
	case nonsec3:
		/*
		 * The final non-nsec node is before the NSEC origin node.
		 */
		result = dns_qp_lookup(qpdbiter->snap, &qpdb->common.origin,
				       DNS_DBNAMESPACE_NSEC, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		if (result == ISC_R_SUCCESS) {
			INSIST(QPDBITER_NSEC_ORIGIN_NODE(qpdb, qpdbiter));
			/* skip the NSEC origin node */
			result = dns_qpiter_prev(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		} else {
			/*
			 * The NSEC origin node was not found, but the iterator
			 * should point to its predecessor, which is the node we
			 * want.
			 */
			result = dns_qpiter_current(&qpdbiter->iter,
						    (void **)&qpdbiter->node,
						    NULL);
			INSIST(result == ISC_R_SUCCESS);
			INSIST(qpdbiter->node->nspace ==
			       DNS_DBNAMESPACE_NORMAL);
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}
	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result, tresult;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		result = dns_qp_lookup(qpdbiter->snap, name,
				       DNS_DBNAMESPACE_NSEC3, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		break;
	case nonsec3:
		result = dns_qp_lookup(qpdbiter->snap, name,
				       DNS_DBNAMESPACE_NORMAL, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		break;
	case full:
		result = dns_qp_lookup(qpdbiter->snap, name,
				       DNS_DBNAMESPACE_NORMAL, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		if (result != ISC_R_SUCCESS) {
			tresult = dns_qp_lookup(qpdbiter->snap, name,
						DNS_DBNAMESPACE_NSEC3,
						&qpdbiter->iter, NULL,
						(void **)&qpdbiter->node, NULL);
			if (tresult == ISC_R_SUCCESS) {
				result = tresult;
			}
		}
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							  : result;
	return result;
}

static isc_result_t
dbiterator_seek3(dns_dbiterator_t *iterator,
		 const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->nsec3mode != nsec3only) {
		return ISC_R_NOTIMPLEMENTED;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qp_lookup(qpdbiter->snap, name, DNS_DBNAMESPACE_NSEC3,
			       &qpdbiter->iter, NULL, (void **)&qpdbiter->node,
			       NULL);

	switch (result) {
	case ISC_R_SUCCESS:
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
		break;
	case DNS_R_PARTIALMATCH:
		/* dbiterator_next() will dereference the node */
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

		result = dbiterator_next(iterator);
		if (result == ISC_R_NOMORE) {
			result = dbiterator_first(iterator);
		}
		break;
	case ISC_R_NOTFOUND:
	default:
		break;
	}

	qpdbiter->result = result;

	return qpdbiter->result;
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;
	qpznode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	/*
	 * Defer the release of the current node until we have the prev node
	 * from the QP tree.
	 */
	node = qpdbiter->node;
	qpdbiter->node = NULL;

	result = dns_qpiter_prev(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		if (result == ISC_R_SUCCESS) {
			if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
				/* we hit the NSEC3 origin node. */
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			} else if (qpdbiter->node->nspace !=
				   DNS_DBNAMESPACE_NSEC3)
			{
				/* we hit a non-NSEC3 node. */
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			}
		}
		break;
	case full:
		/* skip the NSEC3 origin node. */
		if (result == ISC_R_SUCCESS &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			result = dns_qpiter_prev(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		if (result != ISC_R_SUCCESS) {
			qpdbiter->node = NULL;
			break;
		}

		/*
		 * If we hit an NSEC node, we need to seek the final normal node
		 * of the tree.
		 */
		if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NSEC) {
			break;
		}

		INSIST(qpdbiter->node->nspace == DNS_DBNAMESPACE_NSEC);
		result = dns_qp_lookup(qpdbiter->snap, &qpdb->common.origin,
				       DNS_DBNAMESPACE_NSEC, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);

		if (result == ISC_R_SUCCESS) {
			INSIST(QPDBITER_NSEC_ORIGIN_NODE(qpdb, qpdbiter));
			/* skip the NSEC origin node */
			result = dns_qpiter_prev(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		} else {
			/*
			 * The NSEC origin node was not found, but the iterator
			 * should point to its predecessor, which is the node we
			 * want.
			 */
			result = dns_qpiter_current(&qpdbiter->iter,
						    (void **)&qpdbiter->node,
						    NULL);
			INSIST(result == ISC_R_SUCCESS);
			INSIST(qpdbiter->node->nspace ==
			       DNS_DBNAMESPACE_NORMAL);
		}
		break;
	case nonsec3:
		break;
	default:
		UNREACHABLE();
	}

	/*
	 * We have the prev node, we can release the previous current.
	 */
	nlock = qpzone_get_lock(node);
	NODE_RDLOCK(nlock, &nlocktype);
	(void)qpznode_release(node DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;
	qpznode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	/*
	 * Defer the release of the current node until we have the next node
	 * from the QP tree.
	 */
	node = qpdbiter->node;
	qpdbiter->node = NULL;

	result = dns_qpiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	switch (qpdbiter->nsec3mode) {
	case nonsec3:
		if (result == ISC_R_SUCCESS) {
			/* we hit an NSEC or NSEC3 node. */
			if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NORMAL) {
				qpdbiter->node = NULL;
				result = ISC_R_NOMORE;
			}
		}
		break;
	case full:
		/* skip the NSEC3 origin node. */
		if (result == ISC_R_SUCCESS &&
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			result = dns_qpiter_next(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		if (result != ISC_R_SUCCESS) {
			qpdbiter->node = NULL;
			break;
		}

		/*
		 * If we hit an NSEC node, we need to start at the NSEC3 part of
		 * the tree.
		 */
		if (qpdbiter->node->nspace != DNS_DBNAMESPACE_NSEC) {
			break;
		}
		INSIST(qpdbiter->node->nspace == DNS_DBNAMESPACE_NSEC);

		result = dns_qp_lookup(qpdbiter->snap, &qpdb->common.origin,
				       DNS_DBNAMESPACE_NSEC3, &qpdbiter->iter,
				       NULL, (void **)&qpdbiter->node, NULL);
		if (result != ISC_R_SUCCESS ||
		    QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter))
		{
			/* skip the NSEC3 origin node (or its predecessor). */
			result = dns_qpiter_next(&qpdbiter->iter,
						 (void **)&qpdbiter->node,
						 NULL);
		}
		break;
	case nsec3only:
		break;
	default:
		UNREACHABLE();
	}

	/*
	 * We have the next node, we can release the previous current.
	 */
	nlock = qpzone_get_lock(node);
	NODE_RDLOCK(nlock, &nlocktype);
	(void)qpznode_release(node DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpznode_t *node = qpdbiter->node;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(qpdbiter->node != NULL);

	if (name != NULL) {
		dns_name_copy(&qpdbiter->node->name, name);
	}

	qpznode_acquire(node DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)qpdbiter->node;

	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator ISC_ATTR_UNUSED) {
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	dns_name_copy(dns_rootname, name);
	return ISC_R_SUCCESS;
}

static isc_result_t
qpzone_createiterator(dns_db_t *db, unsigned int options,
		      dns_dbiterator_t **iteratorp) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdb_dbiterator_t *iter = NULL;
	isc_result_t result;

	REQUIRE(VALID_QPZONE(qpdb));

	iter = isc_mem_get(qpdb->common.mctx, sizeof(*iter));
	*iter = (qpdb_dbiterator_t){
		.common.magic = DNS_DBITERATOR_MAGIC,
		.common.methods = &dbiterator_methods,
		.common.relative_names = ((options & DNS_DB_RELATIVENAMES) !=
					  0),
	};

	if ((options & DNS_DB_NSEC3ONLY) != 0) {
		iter->nsec3mode = nsec3only;
	} else if ((options & DNS_DB_NONSEC3) != 0) {
		iter->nsec3mode = nonsec3;
	} else {
		iter->nsec3mode = full;
	}

	dns_db_attach(db, &iter->common.db);

	dns_qpmulti_snapshot(qpdb->tree, &iter->snap);

	switch (iter->nsec3mode) {
	case nonsec3:
	case full:
		dns_qpiter_init(iter->snap, &iter->iter);
		break;
	case nsec3only:
		/*
		 * NSEC3 follows after all non-nsec3 nodes,
		 * seek the NSEC3 origin node.
		 */
		result = dns_qp_lookup(iter->snap, &qpdb->common.origin,
				       DNS_DBNAMESPACE_NSEC3, &iter->iter, NULL,
				       NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
		break;
	default:
		UNREACHABLE();
	}

	*iteratorp = (dns_dbiterator_t *)iter;
	return ISC_R_SUCCESS;
}

/*
 * Main logic to add a new rdataset to a node.
 *
 * The reason this is split from qpzone_addrdataset is to allow the reuse of
 * the same qp transaction for multiple adds.
 *
 * If the rdataset is of type NSEC, 'nsec' must point to the qp trie for the
 * zone, otherwise it must be NULL.
 *
 * qpzone_subtractrdataset doesn't have the same problem since it cannot delete
 * nodes, only rdatasets.
 */
static isc_result_t
qpzone_addrdataset_inner(qpzonedb_t *qpdb, qpznode_t *node,
			 dns_dbversion_t *dbversion, dns_rdataset_t *rdataset,
			 unsigned int options, dns_rdataset_t *addedrdataset,
			 dns_qp_t *nsec) {
	isc_result_t result;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	isc_region_t region;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_initname(&fn);

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	/*
	 * SOA records are only allowed at top of zone.
	 */
	if (rdataset->type == dns_rdatatype_soa && node != qpdb->origin) {
		return DNS_R_NOTZONETOP;
	}

	REQUIRE((node->nspace == DNS_DBNAMESPACE_NSEC3 &&
		 (rdataset->type == dns_rdatatype_nsec3 ||
		  rdataset->covers == dns_rdatatype_nsec3)) ||
		(node->nspace != DNS_DBNAMESPACE_NSEC3 &&
		 rdataset->type != dns_rdatatype_nsec3 &&
		 rdataset->covers != dns_rdatatype_nsec3));

	result = dns_rdatavec_fromrdataset(rdataset, node->mctx, &region,
					   qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)qpdb, &node->name,
						  rdataset->type, "adding",
						  qpdb->maxrrperset);
		}
		return result;
	}

	dns_name_copy(&node->name, name);
	dns_rdataset_getownercase(rdataset, name);

	dns_vecheader_t *newheader = (dns_vecheader_t *)region.base;

	dns_vecheader_setownercase(newheader, name);

	newheader->ttl = rdataset->ttl;
	if (rdataset->ttl == 0U) {
		DNS_VECHEADER_SETATTR(newheader, DNS_VECHEADERATTR_ZEROTTL);
	}

	newheader->serial = version->serial;
	if (rdataset->attributes.resign) {
		DNS_VECHEADER_SETATTR(newheader, DNS_VECHEADERATTR_RESIGN);
		newheader->resign = dns_time64_from32(rdataset->resign);
	}

	/*
	 * If we're adding a delegation type or adding to the auxiliary NSEC
	 * namespace, hold an exclusive lock on the tree.  In the latter case
	 * the lock does not necessarily have to be acquired but it will help
	 * purge ancient entries more effectively.
	 *
	 * (Note: node lock must be acquired after starting
	 * the QPDB transaction and released before committing.)
	 */
	nlock = qpzone_get_lock(node);

	NODE_WRLOCK(nlock, &nlocktype);

	result = ISC_R_SUCCESS;
	if (nsec != NULL) {
		node->havensec = true;

		/*
		 * If it fails, there was already an NSEC node,
		 * so we can detach the new one we created and
		 * move on.
		 */
		qpznode_t *nsecnode = new_qpznode(qpdb, name,
						  DNS_DBNAMESPACE_NSEC);
		/*
		 * We don't need a separate transaction since the NSEC tree and
		 * the normal tree are part of the same qp-tree.
		 */
		(void)dns_qp_insert(nsec, nsecnode, 0);
		qpznode_detach(&nsecnode);
	}

	if (result == ISC_R_SUCCESS) {
		result = add(qpdb, node, name, version, newheader, options,
			     false, addedrdataset, 0 DNS__DB_FLARG_PASS);
	}

	/*
	 * If we're adding a delegation type (e.g. NS or DNAME),
	 * then we need to set the callback bit on the node.
	 */
	if (result == ISC_R_SUCCESS &&
	    delegating_type(qpdb, node, rdataset->type))
	{
		node->delegating = true;
	}

	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static isc_result_t
qpzone_addrdataset(dns_db_t *db, dns_dbnode_t *dbnode,
		   dns_dbversion_t *dbversion,
		   isc_stdtime_t now ISC_ATTR_UNUSED, dns_rdataset_t *rdataset,
		   unsigned int options,
		   dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	dns_qp_t *nsec = NULL;

	REQUIRE(VALID_QPZONE(qpdb));

	/*
	 * Open a new write transaction if we're adding to the auxiliary
	 * NSEC namespace.
	 */
	if (!node->havensec && rdataset->type == dns_rdatatype_nsec) {
		dns_qpmulti_write(qpdb->tree, &nsec);
	}

	isc_result_t result = qpzone_addrdataset_inner(
		qpdb, node, dbversion, rdataset, options, addedrdataset, nsec);

	if (nsec != NULL) {
		dns_qpmulti_commit(qpdb->tree, &nsec);
	}

	return result;
}

static isc_result_t
qpzone_subtractrdataset(dns_db_t *db, dns_dbnode_t *dbnode,
			dns_dbversion_t *dbversion, dns_rdataset_t *rdataset,
			unsigned int options,
			dns_rdataset_t *newrdataset DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	dns_vectop_t *foundtop = NULL;
	dns_vecheader_t *newheader = NULL;
	dns_vecheader_t *subresult = NULL;
	isc_region_t region;
	isc_result_t result;
	qpz_changed_t *changed = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	REQUIRE((node->nspace == DNS_DBNAMESPACE_NSEC3 &&
		 (rdataset->type == dns_rdatatype_nsec3 ||
		  rdataset->covers == dns_rdatatype_nsec3)) ||
		(node->nspace != DNS_DBNAMESPACE_NSEC3 &&
		 rdataset->type != dns_rdatatype_nsec3 &&
		 rdataset->covers != dns_rdatatype_nsec3));

	dns_name_copy(&node->name, nodename);
	result = dns_rdatavec_fromrdataset(rdataset, node->mctx, &region, 0);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	newheader = (dns_vecheader_t *)region.base;
	newheader->ttl = rdataset->ttl;
	atomic_init(&newheader->attributes, 0);
	newheader->serial = version->serial;
	if (rdataset->attributes.resign) {
		DNS_VECHEADER_SETATTR(newheader, DNS_VECHEADERATTR_RESIGN);
		newheader->resign = dns_time64_from32(rdataset->resign);
	}

	nlock = qpzone_get_lock(node);
	NODE_WRLOCK(nlock, &nlocktype);

	changed = add_changed(qpdb, node, version DNS__DB_FLARG_PASS);
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		if (top->typepair == newheader->typepair) {
			foundtop = top;
			break;
		}
	}
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	dns_vecheader_t *header = NULL;
	if (foundtop != NULL) {
		ISC_SLIST_FOREACH(tmp, foundtop->headers, next_header) {
			if (!IGNORE(tmp)) {
				header = tmp;
				break;
			}
		}
	}
	if (header != NULL && EXISTS(header)) {
		unsigned int flags = 0;
		subresult = NULL;
		result = ISC_R_SUCCESS;
		if ((options & DNS_DBSUB_EXACT) != 0) {
			flags |= DNS_RDATAVEC_EXACT;
			if (newheader->ttl != header->ttl) {
				result = DNS_R_NOTEXACT;
			}
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_rdatavec_subtract(
				header, newheader, qpdb->common.mctx,
				qpdb->common.rdclass,
				DNS_TYPEPAIR_TYPE(foundtop->typepair), flags,
				&subresult);
		}
		if (result == ISC_R_SUCCESS) {
			LOCK(&qpdb->heap->lock);
			resign_unregister(qpdb->heap, node, newheader);
			UNLOCK(&qpdb->heap->lock);
			dns_vecheader_unref(newheader);
			newheader = subresult;
			/*
			 * dns_rdatavec_subtract takes the header from the first
			 * argument, so it preserves the case
			 */
			if (RESIGN(header)) {
				DNS_VECHEADER_SETATTR(newheader,
						      DNS_VECHEADERATTR_RESIGN);
				newheader->resign = header->resign;
				LOCK(&qpdb->heap->lock);
				resign_register(qpdb->heap, node, newheader);
				UNLOCK(&qpdb->heap->lock);
			}
			/*
			 * We have to set the serial since the rdatavec
			 * subtraction routine copies the reserved portion of
			 * header, not newheader.
			 */
			newheader->serial = version->serial;
			/*
			 * XXXJT: dns_rdatavec_subtract() copied the pointers
			 * to additional info.  We need to clear these fields
			 * to avoid having duplicated references.
			 */
			maybe_update_recordsandsize(true, version, newheader,
						    nodename->length);
		} else if (result == DNS_R_NXRRSET) {
			/*
			 * This subtraction would remove all of the rdata;
			 * add a nonexistent header instead.
			 */
			LOCK(&qpdb->heap->lock);
			resign_unregister(qpdb->heap, node, newheader);
			UNLOCK(&qpdb->heap->lock);
			dns_vecheader_unref(newheader);
			newheader = dns_vecheader_new(db->mctx);
			newheader->ttl = 0;
			newheader->typepair = foundtop->typepair;
			atomic_init(&newheader->attributes,
				    DNS_VECHEADERATTR_NONEXISTENT);
			newheader->serial = version->serial;
		} else {
			LOCK(&qpdb->heap->lock);
			resign_unregister(qpdb->heap, node, newheader);
			UNLOCK(&qpdb->heap->lock);
			dns_vecheader_unref(newheader);
			goto unlock;
		}

		/*
		 * If we're here, we want to link newheader at the top.
		 */
		maybe_update_recordsandsize(false, version, header,
					    nodename->length);

		ISC_SLIST_PREPEND(foundtop->headers, newheader, next_header);

		node->dirty = true;
		changed->dirty = true;
		LOCK(&qpdb->heap->lock);
		resign_unregister(qpdb->heap, node, header);
		UNLOCK(&qpdb->heap->lock);
		resign_rollback(qpdb, node, version, header DNS__DB_FLARG_PASS);
	} else {
		/*
		 * The rdataset doesn't exist, so we don't need to do anything
		 * to satisfy the deletion request.
		 */
		LOCK(&qpdb->heap->lock);
		resign_unregister(qpdb->heap, node, newheader);
		UNLOCK(&qpdb->heap->lock);
		dns_vecheader_unref(newheader);
		if ((options & DNS_DBSUB_EXACT) != 0) {
			result = DNS_R_NOTEXACT;
		} else {
			result = DNS_R_UNCHANGED;
		}
	}

	if (result == ISC_R_SUCCESS && newrdataset != NULL) {
		bindrdataset(qpdb, newheader, newrdataset DNS__DB_FLARG_PASS);
	}

	if (result == DNS_R_NXRRSET && newrdataset != NULL &&
	    (options & DNS_DBSUB_WANTOLD) != 0)
	{
		bindrdataset(qpdb, header, newrdataset DNS__DB_FLARG_PASS);
	}

unlock:
	NODE_UNLOCK(nlock, &nlocktype);
	return result;
}

static isc_result_t
qpzone_deleterdataset(dns_db_t *db, dns_dbnode_t *dbnode,
		      dns_dbversion_t *dbversion, dns_rdatatype_t type,
		      dns_rdatatype_t covers DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	isc_result_t result;
	dns_vecheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	if (type == dns_rdatatype_any) {
		return ISC_R_NOTIMPLEMENTED;
	}
	if (type == dns_rdatatype_rrsig && covers == dns_rdatatype_none) {
		return ISC_R_NOTIMPLEMENTED;
	}

	newheader = dns_vecheader_new(db->mctx);
	newheader->typepair = DNS_TYPEPAIR_VALUE(type, covers);
	newheader->ttl = 0;
	atomic_init(&newheader->attributes, DNS_VECHEADERATTR_NONEXISTENT);
	newheader->serial = version->serial;

	dns_name_copy(&node->name, nodename);

	nlock = qpzone_get_lock(node);
	NODE_WRLOCK(nlock, &nlocktype);
	result = add(qpdb, node, nodename, version, newheader, DNS_DBADD_FORCE,
		     false, NULL, 0 DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
	return result;
}

static dns_glue_t *
new_glue(isc_mem_t *mctx, const dns_name_t *name) {
	dns_glue_t *glue = isc_mem_get(mctx, sizeof(*glue));
	*glue = (dns_glue_t){
		.name = DNS_NAME_INITEMPTY,
	};

	dns_name_dup(name, mctx, &glue->name);

	return glue;
}

static dns_gluelist_t *
new_gluelist(dns_db_t *db, dns_vecheader_t *header,
	     const dns_dbversion_t *dbversion) {
	dns_gluelist_t *gluelist = isc_mem_get(db->mctx, sizeof(*gluelist));
	*gluelist = (dns_gluelist_t){
		.version = dbversion,
		.header = header,
	};

	isc_mem_attach(db->mctx, &gluelist->mctx);

	cds_wfs_node_init(&gluelist->wfs_node);

	return gluelist;
}

static isc_result_t
glue_nsdname_cb(void *arg, const dns_name_t *name, dns_rdatatype_t qtype,
		dns_rdataset_t *rdataset ISC_ATTR_UNUSED DNS__DB_FLARG) {
	dns_glue_additionaldata_ctx_t *ctx = arg;
	isc_result_t result;
	dns_fixedname_t fixedname_a;
	dns_name_t *name_a = NULL;
	dns_rdataset_t rdataset_a, sigrdataset_a;
	dns_fixedname_t fixedname_aaaa;
	dns_name_t *name_aaaa = NULL;
	dns_rdataset_t rdataset_aaaa, sigrdataset_aaaa;
	dns_glue_t *glue = NULL;

	/*
	 * NS records want addresses in additional records.
	 */
	INSIST(qtype == dns_rdatatype_a);

	name_a = dns_fixedname_initname(&fixedname_a);
	dns_rdataset_init(&rdataset_a);
	dns_rdataset_init(&sigrdataset_a);

	name_aaaa = dns_fixedname_initname(&fixedname_aaaa);
	dns_rdataset_init(&rdataset_aaaa);
	dns_rdataset_init(&sigrdataset_aaaa);

	result = qpzone_find(ctx->db, name, ctx->version, dns_rdatatype_a,
			     DNS_DBFIND_GLUEOK, 0, NULL, name_a, NULL, NULL,
			     &rdataset_a, &sigrdataset_a DNS__DB_FLARG_PASS);
	if (result == DNS_R_GLUE) {
		glue = new_glue(ctx->db->mctx, name_a);

		/*
		 * Move the header out of the rdataset, transferring
		 * ownership of the reference to the glue structure.
		 */
		glue->header_a = dns_vecheader_moveheader(&rdataset_a);
		if (dns_rdataset_isassociated(&sigrdataset_a)) {
			glue->sigheader_a =
				dns_vecheader_moveheader(&sigrdataset_a);
		}
	}

	result = qpzone_find(ctx->db, name, ctx->version, dns_rdatatype_aaaa,
			     DNS_DBFIND_GLUEOK, 0, NULL, name_aaaa, NULL, NULL,
			     &rdataset_aaaa,
			     &sigrdataset_aaaa DNS__DB_FLARG_PASS);
	if (result == DNS_R_GLUE) {
		if (glue == NULL) {
			glue = new_glue(ctx->db->mctx, name_aaaa);
		} else {
			INSIST(dns_name_equal(name_a, name_aaaa));
		}

		/*
		 * Move the header out of the rdataset, transferring
		 * ownership of the reference to the glue structure.
		 */
		glue->header_aaaa = dns_vecheader_moveheader(&rdataset_aaaa);
		if (dns_rdataset_isassociated(&sigrdataset_aaaa)) {
			glue->sigheader_aaaa =
				dns_vecheader_moveheader(&sigrdataset_aaaa);
		}
	}

	/*
	 * If the currently processed NS record is in-bailiwick, mark the
	 * glue as 'required'.  The flag is later propagated to the rdataset
	 * attributes when the glue is bound.  Note that for simplicity, glue
	 * for all in-bailiwick NS records is marked this way, even though
	 * dns_message_rendersection() only checks the attributes for the
	 * first rdataset associated with the first name added to the
	 * ADDITIONAL section.
	 */
	if (glue != NULL && dns_name_issubdomain(name, ctx->owner_name)) {
		glue->required = true;
	}

	if (glue != NULL) {
		glue->next = ctx->glue;
		ctx->glue = glue;
	}

	/*
	 * Clean up any rdatasets that were not consumed by moveheader().
	 * This handles the ISC_R_SUCCESS (in-zone, not glue) case where
	 * the rdataset is associated but its header was not moved into
	 * the glue structure.
	 */
	dns_rdataset_cleanup(&rdataset_a);
	dns_rdataset_cleanup(&sigrdataset_a);
	dns_rdataset_cleanup(&rdataset_aaaa);
	dns_rdataset_cleanup(&sigrdataset_aaaa);

	return ISC_R_SUCCESS;
}

/*
 * This calls bindrdataset, so it must be protected by an rcu read lock.
 */
static void
addglue_to_message(qpzonedb_t *qpdb, dns_glue_t *ge, dns_message_t *msg) {
	for (; ge != NULL; ge = ge->next) {
		dns_name_t *name = NULL;
		dns_rdataset_t *rdataset_a = NULL;
		dns_rdataset_t *sigrdataset_a = NULL;
		dns_rdataset_t *rdataset_aaaa = NULL;
		dns_rdataset_t *sigrdataset_aaaa = NULL;
		bool prepend_name = false;

		dns_message_gettempname(msg, &name);

		dns_name_copy(&ge->name, name);

		if (ge->header_a != NULL) {
			dns_message_gettemprdataset(msg, &rdataset_a);
		}

		if (ge->sigheader_a != NULL) {
			dns_message_gettemprdataset(msg, &sigrdataset_a);
		}

		if (ge->header_aaaa != NULL) {
			dns_message_gettemprdataset(msg, &rdataset_aaaa);
		}

		if (ge->sigheader_aaaa != NULL) {
			dns_message_gettemprdataset(msg, &sigrdataset_aaaa);
		}

		if (rdataset_a != NULL) {
			bindrdataset(qpdb, ge->header_a, rdataset_a);
			ISC_LIST_APPEND(name->list, rdataset_a, link);
			if (ge->required) {
				rdataset_a->attributes.required = true;
				prepend_name = true;
			}
		}

		if (sigrdataset_a != NULL) {
			bindrdataset(qpdb, ge->sigheader_a, sigrdataset_a);
			ISC_LIST_APPEND(name->list, sigrdataset_a, link);
		}

		if (rdataset_aaaa != NULL) {
			bindrdataset(qpdb, ge->header_aaaa, rdataset_aaaa);
			ISC_LIST_APPEND(name->list, rdataset_aaaa, link);
			if (ge->required) {
				rdataset_aaaa->attributes.required = true;
				prepend_name = true;
			}
		}
		if (sigrdataset_aaaa != NULL) {
			bindrdataset(qpdb, ge->sigheader_aaaa,
				     sigrdataset_aaaa);
			ISC_LIST_APPEND(name->list, sigrdataset_aaaa, link);
		}

		dns_message_addname(msg, name, DNS_SECTION_ADDITIONAL);

		/*
		 * When looking for required glue, dns_message_rendersection()
		 * only processes the first rdataset associated with the first
		 * name added to the ADDITIONAL section.  dns_message_addname()
		 * performs an append on the list of names in a given section,
		 * so if any glue record was marked as required, we need to
		 * move the name it is associated with to the beginning of the
		 * list for the ADDITIONAL section or else required glue might
		 * not be rendered.
		 */
		if (prepend_name) {
			ISC_LIST_UNLINK(msg->sections[DNS_SECTION_ADDITIONAL],
					name, link);
			ISC_LIST_PREPEND(msg->sections[DNS_SECTION_ADDITIONAL],
					 name, link);
		}
	}
}

static dns_gluelist_t *
create_gluelist(qpzonedb_t *qpdb, qpz_version_t *version,
		const dns_name_t *owner_name, dns_rdataset_t *rdataset) {
	dns_vecheader_t *header = dns_vecheader_getheader(rdataset);
	dns_glue_additionaldata_ctx_t ctx = {
		.db = (dns_db_t *)qpdb,
		.version = (dns_dbversion_t *)version,
		.owner_name = owner_name,
	};
	dns_gluelist_t *gluelist = new_gluelist(ctx.db, header, ctx.version);

	/*
	 * Get the owner name of the NS RRset - it will be necessary for
	 * identifying required glue in glue_nsdname_cb() (by
	 * determining which NS records in the delegation are
	 * in-bailiwick).
	 */

	(void)dns_rdataset_additionaldata(rdataset, dns_rootname,
					  glue_nsdname_cb, &ctx, 0);

	CMM_STORE_SHARED(gluelist->glue, ctx.glue);

	return gluelist;
}

static void
addglue(dns_db_t *db, dns_dbversion_t *dbversion, const dns_name_t *owner_name,
	dns_rdataset_t *rdataset, dns_message_t *msg) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	dns_vecheader_t *header = dns_vecheader_getheader(rdataset);
	dns_glue_t *glue = NULL;
	isc_statscounter_t counter = dns_gluecachestatscounter_hits_absent;

	REQUIRE(rdataset->type == dns_rdatatype_ns);
	REQUIRE(qpdb == version->qpdb);
	REQUIRE(!IS_STUB(qpdb));

	rcu_read_lock();

	dns_gluelist_t *gluelist = rcu_dereference(header->gluelist);
	if (gluelist == NULL || gluelist->version != dbversion) {
		/* No or old glue list was found in the table. */

		dns_gluelist_t *xchg_gluelist = gluelist;
		dns_gluelist_t *old_gluelist = (void *)-1;
		dns_gluelist_t *new_gluelist =
			create_gluelist(qpdb, version, owner_name, rdataset);

		while (old_gluelist != xchg_gluelist &&
		       (xchg_gluelist == NULL ||
			xchg_gluelist->version != dbversion))
		{
			old_gluelist = xchg_gluelist;
			xchg_gluelist = rcu_cmpxchg_pointer(
				&header->gluelist, old_gluelist, new_gluelist);
		}

		if (old_gluelist == xchg_gluelist) {
			/* CAS was successful */
			cds_wfs_push(&version->glue_stack,
				     &new_gluelist->wfs_node);
			gluelist = new_gluelist;
		} else {
			destroy_gluelist(&new_gluelist);
			gluelist = xchg_gluelist;
		}
	}

	glue = CMM_LOAD_SHARED(gluelist->glue);

	if (glue != NULL) {
		addglue_to_message(qpdb, glue, msg);
		counter = dns_gluecachestatscounter_hits_present;
	}

	rcu_read_unlock();

	/* We have a cached result. Add it to the message and return. */
	if (qpdb->gluecachestats != NULL) {
		isc_stats_increment(qpdb->gluecachestats, counter);
	}
}

static void
setmaxrrperset(dns_db_t *db, uint32_t value) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	qpdb->maxrrperset = value;
}

static void
setmaxtypepername(dns_db_t *db, uint32_t value) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	qpdb->maxtypepername = value;
}

/*
 * Qpzone specialization of the update function from dns_rdatacallbacks_t,
 * meant to reuse the same qp transaction for multiple operations.
 */
static isc_result_t
qpzone_update_rdataset(qpzonedb_t *qpdb, qpz_version_t *version, dns_qp_t *qp,
		       dns_name_t *name, dns_rdataset_t *rds, dns_diffop_t op) {
	isc_result_t result;
	unsigned int options;
	dns_rdataset_t ardataset;
	qpznode_t *node = NULL;
	dns_qp_t *nsec = NULL;
	bool is_nsec3;

	dns_rdataset_init(&ardataset);

	is_nsec3 = (rds->type == dns_rdatatype_nsec3 ||
		    rds->covers == dns_rdatatype_nsec3);

	result = findnodeintree(qpdb, qp, name, true, is_nsec3,
				(dns_dbnode_t **)&node DNS__DB_FLARG_PASS);

	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	switch (op) {
	case DNS_DIFFOP_ADD:
	case DNS_DIFFOP_ADDRESIGN:
		/*
		 * See the comment on qpzone_addrdataset_inner for why we
		 * cannot use qpzone_addrdataset directly.
		 */
		options = DNS_DBADD_MERGE | DNS_DBADD_EXACT |
			  DNS_DBADD_EXACTTTL;
		if (!node->havensec && rds->type == dns_rdatatype_nsec) {
			nsec = qp;
		}
		result = qpzone_addrdataset_inner(
			qpdb, node, (dns_dbversion_t *)version, rds, options,
			&ardataset, nsec DNS__DB_FLARG_PASS);
		break;
	case DNS_DIFFOP_DEL:
	case DNS_DIFFOP_DELRESIGN:
		options = DNS_DBSUB_EXACT | DNS_DBSUB_WANTOLD;
		result = qpzone_subtractrdataset(
			(dns_db_t *)qpdb, (dns_dbnode_t *)node,
			(dns_dbversion_t *)version, rds, options,
			&ardataset DNS__DB_FLARG_PASS);
		break;
	default:
		UNREACHABLE();
	}

	bool is_resign = rds->type == dns_rdatatype_rrsig &&
			 (op == DNS_DIFFOP_DELRESIGN ||
			  op == DNS_DIFFOP_ADDRESIGN);

	if (result == ISC_R_SUCCESS && is_resign) {
		isc_stdtime_t resign;
		resign = dns_rdataset_minresign(&ardataset);
		dns_db_setsigningtime((dns_db_t *)qpdb, (dns_dbnode_t *)node,
				      &ardataset, resign);
	}

failure:
	if (node != NULL) {
		dns_db_detachnode((dns_dbnode_t **)&node);
	}
	dns_rdataset_cleanup(&ardataset);
	return result;
}

static isc_result_t
qpzone_update_callback(void *arg, const dns_name_t *name, dns_rdataset_t *rds,
		       dns_diffop_t op DNS__DB_FLARG) {
	qpzone_updatectx_t *ctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)ctx->base.db;
	qpz_version_t *version = (qpz_version_t *)ctx->base.ver;

	return qpzone_update_rdataset(qpdb, version, ctx->qp,
				      (dns_name_t *)name, rds, op);
}

static isc_result_t
qpzone_beginupdate(dns_db_t *db, dns_dbversion_t *ver,
		   dns_rdatacallbacks_t *callbacks) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(ver != NULL);
	REQUIRE(DNS_CALLBACK_VALID(callbacks));

	qpzone_updatectx_t *ctx = isc_mem_get(qpdb->common.mctx, sizeof(*ctx));
	*ctx = (qpzone_updatectx_t){
		.base.db = db,
		.base.ver = ver,
		.base.warn = true,
		.qpr = (dns_qpread_t){ 0 },
	};
	ctx->qp = begin_transaction(qpdb, &ctx->qpr, true);

	callbacks->update = qpzone_update_callback;
	callbacks->add_private = ctx;

	return ISC_R_SUCCESS;
}

static isc_result_t
qpzone_commitupdate(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpzone_updatectx_t *ctx;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(DNS_CALLBACK_VALID(callbacks));

	ctx = (qpzone_updatectx_t *)callbacks->add_private;
	if (ctx != NULL) {
		end_transaction(qpdb, ctx->qp, true);

		isc_mem_put(qpdb->common.mctx, ctx, sizeof(*ctx));
		/*
		 * We need to allow the context to be committed or aborted
		 * multiple times, so we set the callback data to NULL
		 * to signal that nothing needs to be done with this context.
		 */
		callbacks->add_private = NULL;
	}

	return ISC_R_SUCCESS;
}

/*
 * For now, abortupdate needs to *commit* the results, so that closeversion
 * cleanup might work.
 */
static isc_result_t
qpzone_abortupdate(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpzone_updatectx_t *ctx;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(DNS_CALLBACK_VALID(callbacks));

	ctx = (qpzone_updatectx_t *)callbacks->add_private;
	if (ctx != NULL) {
		end_transaction(qpdb, ctx->qp, true);

		isc_mem_put(qpdb->common.mctx, ctx, sizeof(*ctx));
		/*
		 * See qpzone_commitupdate.
		 */
		callbacks->add_private = NULL;
	}

	return ISC_R_SUCCESS;
}

static dns_dbmethods_t qpdb_zonemethods = {
	.destroy = qpdb_destroy,
	.beginload = beginload,
	.endload = endload,
	.beginupdate = qpzone_beginupdate,
	.commitupdate = qpzone_commitupdate,
	.abortupdate = qpzone_abortupdate,
	.currentversion = currentversion,
	.newversion = newversion,
	.attachversion = attachversion,
	.closeversion = closeversion,
	.findnode = qpzone_findnode,
	.find = qpzone_find,
	.createiterator = qpzone_createiterator,
	.findrdataset = qpzone_findrdataset,
	.allrdatasets = qpzone_allrdatasets,
	.addrdataset = qpzone_addrdataset,
	.subtractrdataset = qpzone_subtractrdataset,
	.deleterdataset = qpzone_deleterdataset,
	.issecure = issecure,
	.nodecount = nodecount,
	.getoriginnode = getoriginnode,
	.getnsec3parameters = getnsec3parameters,
	.findnsec3node = qpzone_findnsec3node,
	.setsigningtime = setsigningtime,
	.getsigningtime = getsigningtime,
	.getsize = getsize,
	.setgluecachestats = setgluecachestats,
	.addglue = addglue,
	.setmaxrrperset = setmaxrrperset,
	.setmaxtypepername = setmaxtypepername,
};

static dns_dbnode_methods_t qpznode_methods = (dns_dbnode_methods_t){
	.attachnode = qpzone_attachnode,
	.detachnode = qpzone_detachnode,
};

static void
destroy_qpznode(qpznode_t *node) {
	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		ISC_SLIST_FOREACH(header, top->headers, next_header) {
			dns_vecheader_unref(header);
		}

		dns_vectop_destroy(node->mctx, &top);
	}

	dns_name_free(&node->name, node->mctx);
	isc_mem_putanddetach(&node->mctx, node, sizeof(qpznode_t));
}

#if DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpznode, destroy_qpznode);
#else
ISC_REFCOUNT_STATIC_IMPL(qpznode, destroy_qpznode);
#endif

ISC_REFCOUNT_STATIC_IMPL(qpz_heap, qpz_heap_destroy);

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpznode_t *data = pval;
	qpznode_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpznode_t *data = pval;
	qpznode_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	qpznode_t *data = pval;
	return dns_qpkey_fromname(key, &data->name, data->nspace);
}

static void
qp_triename(void *uctx ISC_ATTR_UNUSED, char *buf, size_t size) {
	snprintf(buf, size, "QPDB");
}
