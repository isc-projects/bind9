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
#include <isc/heap.h>
#include <isc/hex.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/serial.h>
#include <isc/spinlock.h>
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
#include <dns/name.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/qp.h>
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
#include "qpzone_p.h"

/*
 * FIXME: Undefine the macros to be sure there's no usage here.
 */
#undef NODE_INITLOCK
#undef NODE_DESTROYLOCK
#undef NODE_LOCK
#undef NODE_UNLOCK
#undef NODE_RDLOCK
#undef NODE_WRLOCK
#undef NODE_TRYRDLOCK
#undef NODE_TRYWRLOCK
#undef NODE_TRYUPGRADE
#undef NODE_FORCEUPGRADE

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

#define NONEXISTENT(header)                            \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) != 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_IGNORE) != 0)
#define RESIGN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_RESIGN) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_OPTOUT) != 0)
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STATCOUNT) != 0)

#define HEADERNODE(h) ((qpznode_t *)((h)->node))

#define QPDB_ATTR_LOADED  0x01
#define QPDB_ATTR_LOADING 0x02

#define QPDBITER_NSEC3_ORIGIN_NODE(qpdb, iterator)        \
	((iterator)->current == &(iterator)->nsec3iter && \
	 (iterator)->node == (qpdb)->nsec3_origin)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPZONE_DB_MAGIC ISC_MAGIC('Q', 'Z', 'D', 'B')
#define VALID_QPZONE(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPZONE_DB_MAGIC)

typedef struct qpzonedb qpzonedb_t;
typedef struct qpznode qpznode_t;

typedef struct qpz_changed {
	qpznode_t *node;
	bool dirty;
	ISC_LINK(struct qpz_changed) link;
} qpz_changed_t;

typedef ISC_LIST(qpz_changed_t) qpz_changedlist_t;

typedef struct qpz_version qpz_version_t;
struct qpz_version {
	/* Not locked */
	uint32_t serial;
	qpzonedb_t *qpdb;
	isc_refcount_t references;
	/* Locked by database lock. */
	bool writer;
	qpz_changedlist_t changed_list;
	dns_slabheaderlist_t resigned_list;
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

struct qpznode {
	dns_name_t name;
	isc_mem_t *mctx;

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
	 * Whenever 'erefs' is incremented from zero, we also aquire a
	 * node use reference (see 'qpzonedb->references' below), and
	 * release it when 'erefs' goes back to zero. This prevents the
	 * database from being shut down until every caller has released
	 * all nodes.
	 */
	isc_refcount_t references;
	isc_refcount_t erefs;

	atomic_uint_fast8_t nsec;

	bool wild;
	bool delegating;
	bool dirty;

	isc_spinlock_t spinlock;

	struct cds_list_head headers;

	struct rcu_head rcu_head;
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
	isc_refcount_t references;

	qpznode_t *origin;
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
	isc_loop_t *loop;
	struct rcu_head rcu_head;

	isc_heap_t *heap; /* Resigning heap */

	dns_qpmulti_t *tree;  /* Main QP trie for data storage */
	dns_qpmulti_t *nsec;  /* NSEC nodes only */
	dns_qpmulti_t *nsec3; /* NSEC3 nodes only */
};

#ifdef DNS_DB_NODETRACE
#define qpzonedb_ref(ptr)   qpzonedb__ref(ptr, __func__, __FILE__, __LINE__)
#define qpzonedb_unref(ptr) qpzonedb__unref(ptr, __func__, __FILE__, __LINE__)
#define qpzonedb_attach(ptr, ptrp) \
	qpzonedb__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpzonedb_detach(ptrp) \
	qpzonedb__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpzonedb);
#else
ISC_REFCOUNT_STATIC_DECL(qpzonedb);
#endif

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
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	dns_fixedname_t zonecut_name;
} qpz_search_t;

/*%
 * Load Context
 */
typedef struct {
	dns_db_t *db;
	dns_qp_t *tree;
	dns_qp_t *nsec;
	dns_qp_t *nsec3;
} qpz_load_t;

static dns_dbmethods_t qpdb_zonemethods;

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
	dns_slabheader_list_t *hlist;
	dns_slabheader_t *header;
} qpdb_rdatasetiter_t;

/*
 * Note that these iterators, unless created with either DNS_DB_NSEC3ONLY
 * or DNS_DB_NONSEC3, will transparently move between the last node of the
 * "regular" QP trie and the root node of the NSEC3 QP trie of the database
 * in question, as if the latter was a successor to the former in lexical
 * order.  The "current" field always holds the address of either
 * "mainiter" or "nsec3iter", depending on which trie is being traversed
 * at given time.
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

typedef struct qpdb_dbiterator {
	dns_dbiterator_t common;
	isc_result_t result;
	dns_qpsnap_t *tsnap;	/* main tree snapshot */
	dns_qpsnap_t *nsnap;	/* nsec3 tree snapshot */
	dns_qpiter_t *current;	/* current iterator, which is one of: */
	dns_qpiter_t mainiter;	/* - main tree iterator */
	dns_qpiter_t nsec3iter; /* - nsec3 tree iterator */
	qpznode_t *node;
	enum { full, nonsec3, nsec3only } nsec3mode;
} qpdb_dbiterator_t;

/*%
 * 'init_count' is used to initialize 'newheader->count' which inturn
 * is used to determine where in the cycle rrset-order cyclic starts.
 * We don't lock this as we don't care about simultaneous updates.
 */
static atomic_uint_fast16_t init_count = 0;

/*%
 * Return which RRset should be resigned sooner.  If the RRsets have the
 * same signing time, prefer the other RRset over the SOA RRset.
 */
static bool
resign_sooner(void *v1, void *v2) {
	dns_slabheader_t *h1 = v1;
	dns_slabheader_t *h2 = v2;

	return h1->resign < h2->resign ||
	       (h1->resign == h2->resign && h1->resign_lsb < h2->resign_lsb) ||
	       (h1->resign == h2->resign && h1->resign_lsb == h2->resign_lsb &&
		h2->type == DNS_SIGTYPE(dns_rdatatype_soa));
}

/*%
 * This function sets the heap index into the header.
 */
static void
set_index(void *what, unsigned int idx) {
	dns_slabheader_t *h = what;

	/* Locked by the heap lock */
	h->heap_index = idx;
}

static void
free_glue(isc_mem_t *mctx, dns_glue_t *glue) {
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
		dns_slabheader_t *header = rcu_xchg_pointer(&gluelist->header,
							    NULL);
		(void)rcu_cmpxchg_pointer(&header->gluelist, gluelist, NULL);

		call_rcu(&gluelist->rcu_head, free_gluelist_rcu);
	}
	rcu_read_unlock();
}

static void
qpzonedb__destroy_rcu(struct rcu_head *rcu_head) {
	qpzonedb_t *qpdb = caa_container_of(rcu_head, qpzonedb_t, rcu_head);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}

	isc_heap_destroy(&qpdb->heap);

	if (qpdb->gluecachestats != NULL) {
		isc_stats_detach(&qpdb->gluecachestats);
	}

	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
	}

	isc_rwlock_destroy(&qpdb->lock);
	isc_refcount_destroy(&qpdb->references);
	isc_refcount_destroy(&qpdb->common.references);

	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;

	if (qpdb->common.update_listeners != NULL) {
		INSIST(!cds_lfht_destroy(qpdb->common.update_listeners, NULL));
	}

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb, sizeof(*qpdb));
}

static void
qpzonedb__destroy(qpzonedb_t *qpdb) {
	REQUIRE(qpdb->future_version == NULL);

	isc_refcount_decrementz(&qpdb->current_version->references);

	isc_refcount_destroy(&qpdb->current_version->references);
	ISC_LIST_UNLINK(qpdb->open_versions, qpdb->current_version, link);
	cds_wfs_destroy(&qpdb->current_version->glue_stack);
	isc_rwlock_destroy(&qpdb->current_version->rwlock);
	isc_mem_put(qpdb->common.mctx, qpdb->current_version,
		    sizeof(*qpdb->current_version));

	dns_qpmulti_destroy(&qpdb->tree);
	dns_qpmulti_destroy(&qpdb->nsec);
	dns_qpmulti_destroy(&qpdb->nsec3);

	char buf[DNS_NAME_FORMATSIZE];
	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
	} else {
		strlcpy(buf, "<UNKNOWN>", sizeof(buf));
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DB,
		      ISC_LOG_DEBUG(1), "called %s(%s)", __func__, buf);

	call_rcu(&qpdb->rcu_head, qpzonedb__destroy_rcu);
}

static void
qpzonedb_destroy(dns_db_t *arg) {
	qpzonedb_t *qpdb = (qpzonedb_t *)arg;

	if (qpdb->origin != NULL) {
		qpznode_detach(&qpdb->origin);
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

	qpzonedb_detach(&qpdb);
}

static void
qpznode_create(qpzonedb_t *qpdb, const dns_name_t *name,
	       qpznode_t **qpznodep DNS__DB_FLARG) {
	REQUIRE(qpznodep != NULL && *qpznodep == NULL);
	qpznode_t *qpznode = isc_mem_get(qpdb->common.mctx, sizeof(*qpznode));
	*qpznode = (qpznode_t){
		.name = DNS_NAME_INITEMPTY,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.headers = CDS_LIST_HEAD_INIT(qpznode->headers),
	};

	isc_spinlock_init(&qpznode->spinlock);
	isc_mem_attach(qpdb->common.mctx, &qpznode->mctx);
	dns_name_dup(name, qpdb->common.mctx, &qpznode->name);

#if DNS_DB_NODETRACE
	fprintf(stderr, "new:qpznode:%s:%s:%d:%p->references = 1\n", func, file,
		line, qpznode);
#endif
	*qpznodep = qpznode;
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
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	qpdb->common.methods = &qpdb_zonemethods;
	if (type == dns_dbtype_stub) {
		qpdb->common.attributes |= DNS_DBATTR_STUB;
	}

	isc_rwlock_init(&qpdb->lock);

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	isc_heap_create(mctx, resign_sooner, set_index, 0, &qpdb->heap);

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
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->nsec);
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->nsec3);

	/*
	 * Version initialization.
	 */
	qpdb->current_version = allocate_version(mctx, 1, 1, false);
	qpdb->current_version->qpdb = qpdb;

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

	dns_qpmulti_write(qpdb->tree, &qp);
	qpznode_create(qpdb, &qpdb->common.origin, &qpdb->origin);
	result = dns_qp_insert(qp, qpdb->origin, 0);
	INSIST(result == ISC_R_SUCCESS);
	qpdb->origin->nsec = DNS_DB_NSEC_NORMAL;
	dns_qpmulti_commit(qpdb->tree, &qp);

	/*
	 * Add an apex node to the NSEC3 tree so that NSEC3 searches
	 * return partial matches when there is only a single NSEC3
	 * record in the tree.
	 */
	dns_qpmulti_write(qpdb->nsec3, &qp);
	qpznode_create(qpdb, &qpdb->common.origin, &qpdb->nsec3_origin);
	qpdb->nsec3_origin->nsec = DNS_DB_NSEC_NSEC3;
	result = dns_qp_insert(qp, qpdb->nsec3_origin, 0);
	INSIST(result == ISC_R_SUCCESS);
	dns_qpmulti_commit(qpdb->nsec3, &qp);

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

static void
clean_zone_node(qpznode_t *node, uint32_t least_serial) {
	REQUIRE(least_serial != 0);

	/*
	 * When cleaning up the node headers, we need to keep all the active
	 * (non-IGNORE) headers with the serial larger or equal to the
	 * `least_serial`.
	 *
	 * If no such header exists we need to keep a single header with the
	 * serial smaller than least_version.
	 */

	/*
	 * When cleaning up the node headers, we need to keep all the active
	 * (non-IGNORE) headers with the serial larger or equal to the
	 * `least_serial`.
	 *
	 * If no such header exists we need to keep a single header with the
	 * serial smaller than least_version.
	 */

	dns_slabheader_list_t *hlist = NULL, *hnext = NULL;
	cds_list_for_each_entry_safe (hlist, hnext, &node->headers, nnode) {
		bool empty = true;

		dns_slabheader_t *header = NULL, *next = NULL;
		dns_slabheader_t *parent = NULL;
		cds_list_for_each_entry_safe (header, next, &hlist->versions,
					      dnode)
		{
			if (IGNORE(header)) {
				/* were rolled back */
				cds_list_del_rcu(&header->dnode);
				dns_slabheader_destroy(&header);
			} else if (parent != NULL &&
				   header->serial == parent->serial)
			{
				/* with the same serial number */
				cds_list_del_rcu(&header->dnode);
				dns_slabheader_destroy(&header);
			} else if (parent != NULL &&
				   header->serial < least_serial)
			{
				/*
				 * with the serial number less than least_serial
				 * except when this would be the last header
				 * left
				 */
				cds_list_del_rcu(&header->dnode);
				dns_slabheader_destroy(&header);
			} else {
				parent = header;
				empty = false;
			}
		}

		if (empty) {
			cds_list_del_rcu(&hlist->nnode);
			dns_slabheader_destroylist(&hlist);
		}
	}

	/*
	 * The code above has cleaned everything it could.
	 */
	CMM_STORE_SHARED(node->dirty, false);
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
qpznode_erefs_increment(qpzonedb_t *qpdb, qpznode_t *node DNS__DB_FLARG) {
	uint_fast32_t erefs = atomic_fetch_add_release(&node->erefs, 1);
	INSIST(erefs < UINT32_MAX);
#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, erefs + 1);
#endif

	if (erefs > 0) {
		return;
	}

	qpzonedb_ref(qpdb);
}

static void
qpznode_acquire(qpzonedb_t *qpdb, qpznode_t *node DNS__DB_FLARG) {
	qpznode_ref(node);
	qpznode_erefs_increment(qpdb, node DNS__DB_FLARG_PASS);
}

/*
 * Decrement the external references to a node. If the counter
 * goes to zero, decrement the node use counter in the qpzonedb object
 * as well, and return true. Otherwise return false.
 */
static bool
qpznode_erefs_decrement(qpzonedb_t *qpdb, qpznode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif
	if (refs > 1) {
		return false;
	}

	qpzonedb_unref(qpdb);

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
static void
qpznode_release(qpzonedb_t *qpdb, qpznode_t *node,
		uint32_t least_serial DNS__DB_FLARG) {
	if (qpznode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS) &&
	    CMM_LOAD_SHARED(node->dirty))
	{
		isc_spinlock_lock(&node->spinlock);

		if (least_serial == 0) {
			least_serial = CMM_LOAD_SHARED(qpdb->least_serial);
		}
		clean_zone_node(node, least_serial);
		isc_spinlock_unlock(&node->spinlock);
	}

	qpznode_unref(node);
}

static void
bindrdataset(qpzonedb_t *qpdb, qpznode_t *node, dns_slabheader_t *header,
	     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	if (rdataset == NULL) {
		return;
	}

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->type);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->type);
	rdataset->ttl = header->ttl;
	rdataset->trust = header->trust;

	if (OPTOUT(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_OPTOUT;
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

static void
setnsec3parameters(dns_db_t *db, qpz_version_t *version) {
	qpznode_t *node = NULL;
	dns_rdata_nsec3param_t nsec3param;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_region_t region;
	isc_result_t result;
	dns_slabheader_list_t *hlist = NULL;
	unsigned char *raw; /* RDATASLAB */
	unsigned int count, length;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	version->havensec3 = false;
	node = qpdb->origin;

	rcu_read_lock();
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		if (hlist->type != dns_rdatatype_nsec3param) {
			continue;
		}

		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= version->serial &&
			    !IGNORE(current))
			{
				header = current;
				break;
			}
		}

		if (header == NULL || NONEXISTENT(current)) {
			/* There is no extant NSEC3PARAM header */
			break;
		}

		/*
		 * Find an NSEC3PARAM with a supported algorithm.
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
			dns_rdata_fromregion(&rdata, qpdb->common.rdclass,
					     dns_rdatatype_nsec3param, &region);
			result = dns_rdata_tostruct(&rdata, &nsec3param, NULL);
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
unlock:
	rcu_read_unlock();
}

static void
cleanup_nondirty(qpz_version_t *version, qpz_changedlist_t *cleanup_list) {
	qpz_changed_t *changed = NULL, *next_changed = NULL;

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
	for (changed = ISC_LIST_HEAD(version->changed_list); changed != NULL;
	     changed = next_changed)
	{
		next_changed = ISC_LIST_NEXT(changed, link);
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

	dns_rdataset_init(&keyset);
	result = dns_db_findrdataset(db, origin, (dns_dbversion_t *)version,
				     dns_rdatatype_dnskey, 0, 0, &keyset, NULL);
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
	 * Do we have a valid NSEC/NSEC3 chain?
	 */
	if (version->havensec3 || hasnsec) {
		version->secure = true;
	} else {
		version->secure = false;
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
resigninsert(qpzonedb_t *qpdb, dns_slabheader_t *newheader) {
	REQUIRE(newheader->heap_index == 0);
	REQUIRE(!ISC_LINK_LINKED(newheader, link));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	isc_heap_insert(qpdb->heap, newheader);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	newheader->heap = qpdb->heap;
}

static void
resigndelete(qpzonedb_t *qpdb, qpz_version_t *version,
	     dns_slabheader_t *header DNS__DB_FLARG) {
	if (header == NULL || header->heap_index == 0) {
		return;
	}

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	isc_heap_delete(qpdb->heap, header->heap_index);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	header->heap_index = 0;
	qpznode_acquire(qpdb, HEADERNODE(header) DNS__DB_FLARG_PASS);
	ISC_LIST_APPEND(version->resigned_list, header, link);
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
	dns_slabheader_list_t *hlist = NULL;
	bool make_dirty = false;

	/*
	 * We set the IGNORE attribute on rdatasets with serial number
	 * 'serial'.  When the reference count goes to zero, these rdatasets
	 * will be cleaned up; until that time, they will be ignored.
	 */
	rcu_read_lock();
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		dns_slabheader_t *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial == serial) {
				DNS_SLABHEADER_SETATTR(
					current, DNS_SLABHEADERATTR_IGNORE);
				make_dirty = true;
			} else if (current->serial < serial) {
				break;
			}
		}
	}
	rcu_read_unlock();

	if (make_dirty) {
		CMM_STORE_SHARED(node->dirty, true);
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
	qpz_changed_t *changed = NULL, *next_changed = NULL;
	qpz_changedlist_t cleanup_list;
	dns_slabheaderlist_t resigned_list;
	dns_slabheader_t *header = NULL;
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
	if (version->writer && commit) {
		unsigned int cur_ref;
		qpz_version_t *cur_version = NULL;

		INSIST(version == qpdb->future_version);
		/*
		 * The current version is going to be replaced.
		 * Release the (likely last) reference to it from the
		 * DB itself and unlink it from the open list.
		 */
		cur_version = qpdb->current_version;
		cur_ref = isc_refcount_decrement(&cur_version->references);
		if (cur_ref == 1) {
			(void)isc_refcount_current(&cur_version->references);
			if (cur_version->serial == qpdb->least_serial) {
				INSIST(ISC_LIST_EMPTY(
					cur_version->changed_list));
			}
			ISC_LIST_UNLINK(qpdb->open_versions, cur_version, link);
		}
		if (ISC_LIST_EMPTY(qpdb->open_versions)) {
			/*
			 * We're going to become the least open
			 * version.
			 */
			make_least_version(qpdb, version, &cleanup_list);
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
			ISC_LIST_APPENDLIST(version->changed_list,
					    cleanup_version->changed_list,
					    link);
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
		INSIST(isc_refcount_increment0(&version->references) == 0);
		ISC_LIST_PREPEND(qpdb->open_versions, qpdb->current_version,
				 link);
		resigned_list = version->resigned_list;
		ISC_LIST_INIT(version->resigned_list);
	} else if (version->writer && !commit) {
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
	} else if (version != qpdb->current_version) {
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
			make_least_version(qpdb, least_greater, &cleanup_list);
		} else {
			/*
			 * Add any unexecuted cleanups to
			 * those of the least greater version.
			 */
			ISC_LIST_APPENDLIST(least_greater->changed_list,
					    version->changed_list, link);
		}
	} else if (version->serial == qpdb->least_serial) {
		INSIST(ISC_LIST_EMPTY(version->changed_list));
	}

	if (!version->writer && version != qpdb->current_version) {
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
	for (header = ISC_LIST_HEAD(resigned_list); header != NULL;
	     header = ISC_LIST_HEAD(resigned_list))
	{
		ISC_LIST_UNLINK(resigned_list, header, link);

		if (rollback && !IGNORE(header)) {
			resigninsert(qpdb, header);
		}
		qpznode_release(qpdb, HEADERNODE(header),
				least_serial DNS__DB_FLARG_PASS);
	}

	dns_qp_t *tree = NULL, *nsec = NULL, *nsec3 = NULL;
	bool need_tree = false, need_nsec = false, need_nsec3 = false;

	for (changed = ISC_LIST_HEAD(cleanup_list); changed != NULL;
	     changed = next_changed)
	{
		next_changed = ISC_LIST_NEXT(changed, link);
		node = changed->node;

		if (rollback) {
			rollback_node(node, serial);
		}

		qpznode_ref(node);
		qpznode_release(qpdb, node, least_serial DNS__DB_FILELINE);

		/* If the node is now empty, we can delete it. */
		if (commit && cds_list_empty_rcu(&node->headers)) {
			switch ((int)node->nsec) {
			case DNS_DB_NSEC_HAS_NSEC:
				/*
				 * Delete the matching node from the NSEC tree
				 * first, then fall through to the main tree.
				 */
				if (nsec == NULL) {
					need_nsec = true;
					next_changed = changed;
				} else {
					dns_qp_deletename(nsec, &node->name,
							  NULL, NULL);
				}
				FALLTHROUGH;
			case DNS_DB_NSEC_NORMAL:
				if (tree == NULL) {
					need_tree = true;
					next_changed = changed;
				} else {
					dns_qp_deletename(tree, &node->name,
							  NULL, NULL);
				}
				break;
			case DNS_DB_NSEC_NSEC:
				if (nsec == NULL) {
					need_nsec = true;
					next_changed = changed;
				} else {
					dns_qp_deletename(nsec, &node->name,
							  NULL, NULL);
				}
				break;
			case DNS_DB_NSEC_NSEC3:
				if (nsec3 == NULL) {
					need_nsec3 = true;
					next_changed = changed;
				} else {
					dns_qp_deletename(nsec3, &node->name,
							  NULL, NULL);
				}
				break;
			default:
				UNREACHABLE();
			}
		}

		qpznode_detach(&node);

		if (next_changed == changed) {
			/*
			 * We found a node to delete but didn't have a
			 * QP writer open, so we open one now, then go
			 * back to delete the node. If there's a next
			 * time, we'll already have the writer open,
			 * so we won't need this extra step.
			 */
			if (need_tree && tree == NULL) {
				dns_qpmulti_write(qpdb->tree, &tree);
			}
			if (need_nsec && nsec == NULL) {
				dns_qpmulti_write(qpdb->nsec, &nsec);
			}
			if (need_nsec3 && nsec3 == NULL) {
				dns_qpmulti_write(qpdb->nsec3, &nsec3);
			}

			continue;
		}

		isc_mem_put(qpdb->common.mctx, changed, sizeof(*changed));
	}

	if (tree != NULL) {
		dns_qp_compact(tree, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &tree);
	}
	if (nsec != NULL) {
		dns_qp_compact(nsec, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec, &nsec);
	}
	if (nsec3 != NULL) {
		dns_qp_compact(nsec3, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec3, &nsec3);
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
	dns_slabheader_list_t *hlist = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	uint32_t serial;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	bool close_version = false;
	dns_typepair_t matchtype, sigmatchtype;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(type != dns_rdatatype_any);
	INSIST(version == NULL || version->qpdb == qpdb);

	if (version == NULL) {
		currentversion(db, (dns_dbversion_t **)&version);
		close_version = true;
	}
	serial = version->serial;

	matchtype = DNS_TYPEPAIR_VALUE(type, covers);
	if (covers == 0) {
		sigmatchtype = DNS_SIGTYPE(type);
	} else {
		sigmatchtype = 0;
	}

	rcu_read_lock();
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		if (hlist->type != matchtype && hlist->type != sigmatchtype) {
			continue;
		}

		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= serial && !IGNORE(current)) {
				header = current;
				break;
			}
		}
		if (header == NULL || NONEXISTENT(header)) {
			continue;
		}

		if (hlist->type == matchtype) {
			found = header;
			if (foundsig != NULL) {
				break;
			}
		} else if (hlist->type == sigmatchtype) {
			foundsig = header;
			if (found != NULL) {
				break;
			}
		}
	}

	if (found != NULL) {
		bindrdataset(qpdb, node, found, rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(qpdb, node, foundsig,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	rcu_read_unlock();

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
delegating_type(qpzonedb_t *qpdb, qpznode_t *node, dns_typepair_t type) {
	return type == dns_rdatatype_dname ||
	       (type == dns_rdatatype_ns &&
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
		result = dns_qp_getname(loadctx->nsec3, name, (void **)&node,
					NULL);
		if (result == ISC_R_SUCCESS) {
			*nodep = node;
		} else {
			qpznode_create(qpdb, name, &node);
			result = dns_qp_insert(loadctx->nsec3, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			node->nsec = DNS_DB_NSEC_NSEC3;
			*nodep = node;
			qpznode_detach(&node);
		}
		return;
	}

	result = dns_qp_getname(loadctx->tree, name, (void **)&node, NULL);
	if (result == ISC_R_SUCCESS) {
		if (type == dns_rdatatype_nsec &&
		    node->nsec == DNS_DB_NSEC_HAS_NSEC)
		{
			goto done;
		}
	} else {
		qpznode_create(qpdb, name, &node);
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
	node->nsec = DNS_DB_NSEC_HAS_NSEC;
	qpznode_create(qpdb, name, &nsecnode);
	nsecnode->nsec = DNS_DB_NSEC_NSEC;
	(void)dns_qp_insert(loadctx->nsec, nsecnode, 0);
	qpznode_detach(&nsecnode);

done:
	*nodep = node;
}

static bool
cname_and_other(qpznode_t *node, uint32_t serial) {
	dns_slabheader_list_t *hlist = NULL;
	bool cname = false, other = false;
	dns_rdatatype_t rdtype;

	/*
	 * Look for CNAME and "other data" rdatasets active in our version.
	 * ("Other data" is any rdataset whose type is not KEY, NSEC, SIG
	 * or RRSIG.
	 */
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		rdtype = DNS_TYPEPAIR_TYPE(hlist->type);
		if (rdtype == dns_rdatatype_key ||
		    rdtype == dns_rdatatype_sig ||
		    rdtype == dns_rdatatype_nsec ||
		    rdtype == dns_rdatatype_rrsig)
		{
			/* These types can coexist with CNAME, skip them. */
			continue;
		}

		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= serial && !IGNORE(current)) {
				header = current;
				break;
			}
		}
		if (header == NULL || NONEXISTENT(header)) {
			continue;
		}

		if (rdtype == dns_rdatatype_cname) {
			cname = true;
		} else {
			other = true;
		}

		if (cname && other) {
			/* We've seen CNAME, but now found other type. */
			return true;
		}
	}

	return false;
}

static qpz_changed_t *
add_changed(dns_slabheader_t *header, qpz_version_t *version DNS__DB_FLARG) {
	qpz_changed_t *changed = NULL;
	qpzonedb_t *qpdb = (qpzonedb_t *)header->db;
	qpznode_t *node = (qpznode_t *)header->node;

	changed = isc_mem_get(qpdb->common.mctx, sizeof(*changed));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	REQUIRE(version->writer);

	*changed = (qpz_changed_t){
		.node = node,
		.link = ISC_LINK_INITIALIZER,
	};
	ISC_LIST_APPEND(version->changed_list, changed, link);

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	return changed;
}

static uint64_t
recordsize(dns_slabheader_t *header, unsigned int namelen) {
	return dns_rdataslab_size(header) + sizeof(dns_ttl_t) +
	       sizeof(dns_rdatatype_t) + sizeof(dns_rdataclass_t) + namelen;
}

static void
maybe_update_recordsandsize(bool add, qpz_version_t *version,
			    dns_slabheader_t *header, unsigned int namelen) {
	if (NONEXISTENT(header)) {
		return;
	}

	RWLOCK(&version->rwlock, isc_rwlocktype_write);
	if (add) {
		version->records += dns_rdataslab_count(header);
		version->xfrsize += recordsize(header, namelen);
	} else {
		version->records -= dns_rdataslab_count(header);
		version->xfrsize -= recordsize(header, namelen);
	}
	RWUNLOCK(&version->rwlock, isc_rwlocktype_write);
}

static isc_result_t
add(qpzonedb_t *qpdb, qpznode_t *node, const dns_name_t *nodename,
    qpz_version_t *version, dns_slabheader_t *newheader, unsigned int options,
    bool loading, dns_rdataset_t *addedrdataset,
    isc_stdtime_t now ISC_ATTR_UNUSED DNS__DB_FLARG) {
	qpz_changed_t *changed = NULL;
	dns_slabheader_list_t *hlist = NULL, *hcurrent = NULL;
	dns_slabheader_t *topheader = NULL, *header = NULL, *current = NULL;
	dns_slabheader_t *merged = NULL;
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
		changed = add_changed(newheader, version DNS__DB_FLARG_PASS);
	}

	ntypes = 0;
	cds_list_for_each_entry_rcu (hcurrent, &node->headers, nnode) {
		++ntypes;

		if (hcurrent->type == newheader->type) {
			hlist = hcurrent;

			/*
			 * We can break early because `ntypes` is only used when
			 * the slabheader list for the type is not found, e.g.
			 * hlist == NULL && header == NULL below.
			 */
			break;
		}
	}

	/*
	 * If hlist isn't NULL, we've found the right type.
	 */
	if (hlist != NULL) {
		/*
		 * There may be IGNORE rdatasets between the top of the
		 * chain and the first real data.  We skip over them.
		 */
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (!IGNORE(current)) {
				header = current;
				break;
			}
		}
	}

	topheader = header;
	if (header != NULL) {
		/*
		 * If 'merge' is true and header isn't empty/nonexistent,
		 * we'll try to create a new rdataset that is the union
		 * of 'newheader' and 'header'.
		 */
		if (merge && !NONEXISTENT(header)) {
			unsigned int flags = 0;
			INSIST(version->serial >= header->serial);
			merged = NULL;
			result = ISC_R_SUCCESS;

			if ((options & DNS_DBADD_EXACT) != 0) {
				flags |= DNS_RDATASLAB_EXACT;
			}
			if ((options & DNS_DBADD_EXACTTTL) != 0 &&
			    newheader->ttl != header->ttl)
			{
				result = DNS_R_NOTEXACT;
			} else if (newheader->ttl != header->ttl) {
				flags |= DNS_RDATASLAB_FORCE;
			}
			if (result == ISC_R_SUCCESS) {
				result = dns_rdataslab_merge(
					header, newheader, qpdb->common.mctx,
					qpdb->common.rdclass,
					(dns_rdatatype_t)header->type, flags,
					qpdb->maxrrperset, &merged);
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
				newheader = merged;
				dns_slabheader_reset(newheader,
						     (dns_db_t *)qpdb,
						     (dns_dbnode_t *)node);
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
				if (result == DNS_R_TOOMANYRECORDS) {
					dns__db_logtoomanyrecords(
						(dns_db_t *)qpdb, nodename,
						(dns_rdatatype_t)header->type,
						"updating", qpdb->maxrrperset);
				}
				dns_slabheader_destroy(&newheader);
				return result;
			}
		}

		INSIST(version->serial >= topheader->serial);
		if (loading) {
			if (RESIGN(newheader)) {
				resigninsert(qpdb, newheader);
				/* resigndelete not needed here */
			}

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			cds_list_del_rcu(&header->dnode);
			cds_list_add_rcu(&newheader->dnode, &hlist->versions);
			maybe_update_recordsandsize(false, version, header,
						    nodename->length);
			dns_slabheader_destroy(&header);
		} else {
			if (RESIGN(newheader)) {
				resigninsert(qpdb, newheader);
				resigndelete(qpdb, version,
					     header DNS__DB_FLARG_PASS);
			}

			cds_list_add_rcu(&newheader->dnode, &hlist->versions);

			CMM_STORE_SHARED(node->dirty, true);

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
		if (NONEXISTENT(newheader)) {
			dns_slabheader_destroy(&newheader);
			return DNS_R_UNCHANGED;
		}

		if (hlist != NULL) {
			/*
			 * We have a list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);
		} else if (qpdb->maxtypepername > 0 &&
			   ntypes >= qpdb->maxtypepername)
		{
			dns_slabheader_destroy(&newheader);
			return DNS_R_TOOMANYRECORDS;
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */

			dns_slabheader_createlist(qpdb->common.mctx, &hlist);
			hlist->type = newheader->type;
			cds_list_add_rcu(&hlist->nnode, &node->headers);
		}

		if (RESIGN(newheader)) {
			resigninsert(qpdb, newheader);
			resigndelete(qpdb, version, header DNS__DB_FLARG_PASS);
		}

		cds_list_add_rcu(&newheader->dnode, &hlist->versions);

		CMM_STORE_SHARED(node->dirty, true);

		if (changed != NULL) {
			changed->dirty = true;
		}

		/*
		 * Check if the node now contains CNAME and other data.
		 *
		 * FIXME: Do this earlier before adding the new header
		 * to the node.
		 */
		if (cname_and_other(node, version->serial)) {
			return DNS_R_CNAMEANDOTHER;
		}
	}

	maybe_update_recordsandsize(true, version, newheader, nodename->length);

	if (addedrdataset != NULL) {
		bindrdataset(qpdb, node, newheader,
			     addedrdataset DNS__DB_FLARG_PASS);
	}

	return ISC_R_SUCCESS;
}

static void
wildcardmagic(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name) {
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
	result = dns_qp_getname(qp, &foundname, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		qpznode_create(qpdb, &foundname, &node);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpznode_unref(node);
	}

	CMM_STORE_SHARED(node->wild, true);
}

static void
addwildcards(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name) {
	dns_name_t foundname;
	unsigned int n, l, i;

	dns_name_init(&foundname);
	n = dns_name_countlabels(name);
	l = dns_name_countlabels(&qpdb->common.origin);
	i = l + 1;
	while (i < n) {
		dns_name_getlabelsequence(name, n - i, i, &foundname);
		if (dns_name_iswildcard(&foundname)) {
			wildcardmagic(qpdb, qp, &foundname);
		}

		i++;
	}
}

static isc_result_t
loading_addrdataset(void *arg, const dns_name_t *name,
		    dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpz_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;
	qpznode_t *node = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;

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
		addwildcards(qpdb, loadctx->tree, name);
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

		wildcardmagic(qpdb, loadctx->tree, name);
	}

	loading_addnode(loadctx, name, rdataset->type, rdataset->covers, &node);
	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)qpdb, name,
						  rdataset->type, "adding",
						  qpdb->maxrrperset);
		}
		return result;
	}

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, (dns_db_t *)qpdb, (dns_dbnode_t *)node);

	newheader->ttl = rdataset->ttl;
	newheader->trust = rdataset->trust;
	newheader->serial = 1;
	newheader->count = 1;

	dns_slabheader_setownercase(newheader, name);

	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	}

	isc_spinlock_lock(&node->spinlock);
	rcu_read_lock();
	result = add(qpdb, node, name, qpdb->current_version, newheader,
		     DNS_DBADD_MERGE, true, NULL, 0 DNS__DB_FLARG_PASS);
	rcu_read_unlock();
	isc_spinlock_unlock(&node->spinlock);

	if (result == ISC_R_SUCCESS &&
	    delegating_type(qpdb, node, rdataset->type))
	{
		CMM_STORE_SHARED(node->delegating, true);
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
	dns_qpmulti_write(qpdb->nsec, &loadctx->nsec);
	dns_qpmulti_write(qpdb->nsec3, &loadctx->nsec3);
}

static void
loading_commit(void *arg) {
	qpz_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;

	if (loadctx->tree != NULL) {
		dns_qp_compact(loadctx->tree, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &loadctx->tree);
	}
	if (loadctx->nsec != NULL) {
		dns_qp_compact(loadctx->nsec, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec, &loadctx->nsec);
	}
	if (loadctx->nsec3 != NULL) {
		dns_qp_compact(loadctx->nsec3, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec3, &loadctx->nsec3);
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

	callbacks->add = loading_addrdataset;
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

	callbacks->add = NULL;
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
		if (hash != NULL) {
			*hash = version->hash;
		}
		if (salt != NULL && salt_length != NULL) {
			REQUIRE(*salt_length >= version->salt_length);
			memmove(salt, version->salt, version->salt_length);
		}
		if (salt_length != NULL) {
			*salt_length = version->salt_length;
		}
		if (iterations != NULL) {
			*iterations = version->iterations;
		}
		if (flags != NULL) {
			*flags = version->flags;
		}
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
setsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, isc_stdtime_t resign) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_slabheader_t *header = NULL, oldheader;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(rdataset != NULL);
	REQUIRE(rdataset->methods == &dns_rdataslab_rdatasetmethods);

	/* FIXME: This should be (in theory) serialized via zone TID */

	header = dns_rdataset_getheader(rdataset);

	/* FIXME: This is so so so weird */
	oldheader = *header;

	/*
	 * Only break the heap invariant (by adjusting resign and resign_lsb)
	 * if we are going to be restoring it by calling isc_heap_increased
	 * or isc_heap_decreased.
	 */
	if (resign != 0) {
		header->resign = (isc_stdtime_t)(dns_time64_from32(resign) >>
						 1);
		header->resign_lsb = resign & 0x1;
	}
	if (header->heap_index != 0) {
		INSIST(RESIGN(header));
		RWLOCK(&qpdb->lock, isc_rwlocktype_write);
		if (resign == 0) {
			isc_heap_delete(qpdb->heap, header->heap_index);
			header->heap_index = 0;
			header->heap = NULL;
		} else if (resign_sooner(header, &oldheader)) {
			isc_heap_increased(qpdb->heap, header->heap_index);
		} else if (resign_sooner(&oldheader, header)) {
			isc_heap_decreased(qpdb->heap, header->heap_index);
		}
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
	} else if (resign != 0) {
		DNS_SLABHEADER_SETATTR(header, DNS_SLABHEADERATTR_RESIGN);
		resigninsert(qpdb, header);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
getsigningtime(dns_db_t *db, isc_stdtime_t *resign, dns_name_t *foundname,
	       dns_typepair_t *typepair) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_slabheader_t *header = NULL;
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(resign != NULL);
	REQUIRE(foundname != NULL);
	REQUIRE(typepair != NULL);

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	header = isc_heap_element(qpdb->heap, 1);
	if (header != NULL) {
		*resign = RESIGN(header)
				  ? (header->resign << 1) | header->resign_lsb
				  : 0;
		dns_name_copy(&HEADERNODE(header)->name, foundname);
		*typepair = header->type;
		result = ISC_R_SUCCESS;
	}
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

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

static isc_result_t
findnodeintree(qpzonedb_t *qpdb, const dns_name_t *name, bool create,
	       bool nsec3, dns_dbnode_t **nodep DNS__DB_FLARG) {
	isc_result_t result;
	qpznode_t *node = NULL;
	dns_qpmulti_t *dbtree = nsec3 ? qpdb->nsec3 : qpdb->tree;
	dns_qpread_t qpr = { 0 };
	dns_qp_t *qp = NULL;

	if (create) {
		dns_qpmulti_write(dbtree, &qp);
	} else {
		dns_qpmulti_query(dbtree, &qpr);
		qp = (dns_qp_t *)&qpr;
	}

	result = dns_qp_getname(qp, name, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		if (!create) {
			dns_qpread_destroy(dbtree, &qpr);
			return result;
		}

		qpznode_create(qpdb, name, &node);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpznode_unref(node);

		if (nsec3) {
			node->nsec = DNS_DB_NSEC_NSEC3;
		} else {
			addwildcards(qpdb, qp, name);
			if (dns_name_iswildcard(name)) {
				wildcardmagic(qpdb, qp, name);
			}
		}
	}

	INSIST(node->nsec == DNS_DB_NSEC_NSEC3 || !nsec3);

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);

	if (create) {
		dns_qp_compact(qp, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(dbtree, &qp);
	} else {
		dns_qpread_destroy(dbtree, &qpr);
	}

	*nodep = (dns_dbnode_t *)node;

	return ISC_R_SUCCESS;
}

static isc_result_t
qpzone_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	return findnodeintree(qpdb, name, create, false,
			      nodep DNS__DB_FLARG_PASS);
}

static isc_result_t
qpzone_findnsec3node(dns_db_t *db, const dns_name_t *name, bool create,
		     dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	return findnodeintree(qpdb, name, create, true,
			      nodep DNS__DB_FLARG_PASS);
}

static bool
matchparams(dns_slabheader_t *header, qpz_search_t *search) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_nsec3_t nsec3;
	unsigned char *raw = NULL;
	unsigned int rdlen, count;
	isc_region_t region;
	isc_result_t result;

	REQUIRE(header->type == dns_rdatatype_nsec3);

	raw = (unsigned char *)header + sizeof(*header);
	count = raw[0] * 256 + raw[1]; /* count */
	raw += DNS_RDATASET_COUNT + DNS_RDATASET_LENGTH;

	while (count-- > 0) {
		rdlen = raw[0] * 256 + raw[1];
		raw += DNS_RDATASET_ORDER + DNS_RDATASET_LENGTH;
		region.base = raw;
		region.length = rdlen;
		dns_rdata_fromregion(&rdata, search->qpdb->common.rdclass,
				     dns_rdatatype_nsec3, &region);
		raw += rdlen;
		result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
		INSIST(result == ISC_R_SUCCESS);
		if (nsec3.hash == search->version->hash &&
		    nsec3.iterations == search->version->iterations &&
		    nsec3.salt_length == search->version->salt_length &&
		    memcmp(nsec3.salt, search->version->salt,
			   nsec3.salt_length) == 0)
		{
			return true;
		}
		dns_rdata_reset(&rdata);
	}
	return false;
}

static isc_result_t
qpzone_setup_delegation(qpz_search_t *search, dns_dbnode_t **nodep,
			dns_name_t *foundname, dns_rdataset_t *rdataset,
			dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_name_t *zcname = NULL;
	dns_typepair_t type;
	qpznode_t *node = NULL;

	REQUIRE(search != NULL);
	REQUIRE(search->zonecut != NULL);
	REQUIRE(search->zonecut_header != NULL);

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	type = search->zonecut_header->type;

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
		bindrdataset(search->qpdb, node, search->zonecut_header,
			     rdataset DNS__DB_FLARG_PASS);
		if (sigrdataset != NULL && search->zonecut_sigheader != NULL) {
			bindrdataset(search->qpdb, node,
				     search->zonecut_sigheader,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	if (type == dns_rdatatype_dname) {
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
     dns_name_t *nextname) {
	dns_fixedname_t fnodename;
	dns_name_t *nodename = dns_fixedname_initname(&fnodename);
	qpznode_t *node = NULL;
	isc_result_t result;

	result = dns_qpiter_current(it, nodename, (void **)&node, NULL);
	while (result == ISC_R_SUCCESS) {
		dns_slabheader_list_t *hlist = NULL;
		dns_slabheader_t *found = NULL;

		cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
			dns_slabheader_t *header = NULL, *current = NULL;
			cds_list_for_each_entry_rcu (current, &hlist->versions,
						     dnode)
			{
				if (current->serial <= search->serial &&
				    !IGNORE(current))
				{
					header = current;
					break;
				}
			}
			if (header == NULL || NONEXISTENT(header)) {
				continue;
			}

			found = header;
			break;
		}

		if (found != NULL) {
			break;
		}

		if (direction == FORWARD) {
			result = dns_qpiter_next(it, nodename, (void **)&node,
						 NULL);
		} else {
			result = dns_qpiter_prev(it, nodename, (void **)&node,
						 NULL);
		}
	};
	if (result == ISC_R_SUCCESS) {
		if (nextname != NULL) {
			dns_name_copy(nodename, nextname);
		}
		return true;
	}

	return false;
}

static bool
activeempty(qpz_search_t *search, dns_qpiter_t *it, const dns_name_t *current) {
	dns_fixedname_t fnext;
	dns_name_t *next = dns_fixedname_initname(&fnext);

	/*
	 * The iterator is currently pointed at the predecessor
	 * of the name we were searching for. Step the iterator
	 * forward, then step() will continue forward until it
	 * finds a node with active data. If that node is a
	 * subdomain of the one we were looking for, then we're
	 * at an active empty nonterminal node.
	 */
	isc_result_t result = dns_qpiter_next(it, NULL, NULL, NULL);
	if (result != ISC_R_SUCCESS) {
		/* An ENT at the end of the zone is impossible */
		return false;
	}
	return step(search, it, FORWARD, next) &&
	       dns_name_issubdomain(next, current);
}

static bool
wildcard_blocked(qpz_search_t *search, const dns_name_t *qname,
		 dns_name_t *wname) {
	isc_result_t result;
	dns_fixedname_t fnext;
	dns_fixedname_t fprev;
	dns_name_t *next = NULL, *prev = NULL;
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
	next = dns_fixedname_initname(&fnext);
	prev = dns_fixedname_initname(&fprev);

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
	check_prev = step(search, &it, BACK, prev);

	/* Now reset the iterator and look for a successor with data. */
	it = search->iter;
	result = dns_qpiter_next(&it, NULL, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		check_next = step(search, &it, FORWARD, next);
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
		if ((check_prev && dns_name_issubdomain(prev, &rname)) ||
		    (check_next && dns_name_issubdomain(next, &rname)))
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

static isc_result_t
find__wildcard(qpz_search_t *search, qpznode_t *snode, qpznode_t **nodep,
	       const dns_name_t *qname) {
	dns_slabheader_list_t *hlist = NULL;
	qpznode_t *node = NULL;
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_qpiter_t it;
	isc_result_t result;
	dns_slabheader_t *found = NULL;

	/*
	 * Construct the wildcard name for this level.
	 */
	result = dns_name_concatenate(dns_wildcardname, &snode->name, name);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_qp_lookup(&search->qpr, name, NULL, &it, NULL,
			       (void **)&node, NULL);
	if (result != ISC_R_NOTFOUND && result != DNS_R_PARTIALMATCH) {
		return result;
	}

	INSIST(result == ISC_R_SUCCESS);
	/*
	 * We have found the wildcard node.  If it is active in
	 * the search's version, we're done.
	 */
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= search->serial &&
			    !IGNORE(current))
			{
				header = current;
			}
		}
		if (header == NULL || NONEXISTENT(header)) {
			continue;
		}

		found = header;
	}
	if (found != NULL || activeempty(search, &it, name)) {
		if (wildcard_blocked(search, qname, name)) {
			return ISC_R_NOTFOUND;
		}

		/*
		 * The wildcard node is active!
		 */
		*nodep = node;
		return ISC_R_SUCCESS;
	}

	return DNS_R_CONTINUE;
}

static isc_result_t
find_wildcard(qpz_search_t *search, qpznode_t **nodep,
	      const dns_name_t *qname) {
	isc_result_t result = ISC_R_NOTFOUND;

	/*
	 * Examine each ancestor level.  If the level's wild bit
	 * is set, then construct the corresponding wildcard name and
	 * search for it.  If the wildcard node exists, and is active in
	 * this version, we're done.  If not, then we next check to see
	 * if the ancestor is active in this version.  If so, then there
	 * can be no possible wildcard match and again we're done.  If
	 * not, continue the search.
	 */
	for (int i = dns_qpchain_length(&search->chain) - 1; i >= 0; i--) {
		qpznode_t *node = NULL;
		dns_slabheader_list_t *hlist = NULL;

		dns_qpchain_node(&search->chain, i, NULL, (void **)&node, NULL);

		if (CMM_LOAD_SHARED(node->wild)) {
			result = find__wildcard(search, node, nodep, qname);
			if (result != DNS_R_CONTINUE) {
				break;
			}
		}

		cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
			dns_slabheader_t *header = NULL, *current = NULL;
			cds_list_for_each_entry_rcu (current, &hlist->versions,
						     dnode)
			{
				if (current->serial <= search->serial &&
				    !IGNORE(current))
				{
					header = current;
					break;
				}
			}
			if (header == NULL || NONEXISTENT(header)) {
				continue;
			}

			/*
			 * The level node is active.  Any wildcarding
			 * present at higher levels has no
			 * effect and we're done.
			 */
			return ISC_R_NOTFOUND;
		}
	}

	return result;
}

/*
 * Find node of the NSEC/NSEC3 record that is 'name'.
 */
static isc_result_t
previous_closest_nsec(dns_rdatatype_t type, qpz_search_t *search,
		      dns_name_t *name, qpznode_t **nodep, dns_qpiter_t *nit,
		      bool *firstp) {
	isc_result_t result;
	dns_qpread_t qpr;

	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE(type == dns_rdatatype_nsec3 || firstp != NULL);

	if (type == dns_rdatatype_nsec3) {
		result = dns_qpiter_prev(&search->iter, name, (void **)nodep,
					 NULL);
		return result;
	}

	dns_qpmulti_query(search->qpdb->nsec, &qpr);

	for (;;) {
		if (*firstp) {
			/*
			 * Construct the name of the second node to check.
			 * It is the first node sought in the NSEC tree.
			 */
			*firstp = false;
			result = dns_qp_lookup(&qpr, name, NULL, nit, NULL,
					       NULL, NULL);
			INSIST(result != ISC_R_NOTFOUND);
			if (result == ISC_R_SUCCESS) {
				/*
				 * Since this was the first loop, finding the
				 * name in the NSEC tree implies that the first
				 * node checked in the main tree had an
				 * unacceptable NSEC record.
				 * Try the previous node in the NSEC tree.
				 */
				result = dns_qpiter_prev(nit, name, NULL, NULL);
			} else if (result == DNS_R_PARTIALMATCH) {
				/*
				 * The iterator is already where we want it.
				 */
				dns_qpiter_current(nit, name, NULL, NULL);
				result = ISC_R_SUCCESS;
			}
		} else {
			/*
			 * This is a second or later trip through the auxiliary
			 * tree for the name of a third or earlier NSEC node in
			 * the main tree.  Previous trips through the NSEC tree
			 * must have found nodes in the main tree with NSEC
			 * records.  Perhaps they lacked signature records.
			 */
			result = dns_qpiter_prev(nit, name, NULL, NULL);
		}
		if (result != ISC_R_SUCCESS) {
			break;
		}

		*nodep = NULL;
		result = dns_qp_lookup(&search->qpr, name, NULL, &search->iter,
				       &search->chain, (void **)nodep, NULL);
		if (result == ISC_R_SUCCESS) {
			break;
		}

		/*
		 * There should always be a node in the main tree with the
		 * same name as the node in the auxiliary NSEC tree, except for
		 * nodes in the auxiliary tree that are awaiting deletion.
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

	dns_qpread_destroy(search->qpdb->nsec, &qpr);
	return result;
}

/*
 * Find the NSEC/NSEC3 which is or before the current point on the
 * search chain.  For NSEC3 records only NSEC3 records that match the
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
	dns_rdatatype_t type = dns_rdatatype_nsec;
	dns_typepair_t sigtype = DNS_SIGTYPE(dns_rdatatype_nsec);
	bool wraps = false;
	bool first = true;
	bool need_sig = secure;

	if (nsec3) {
		type = dns_rdatatype_nsec3;
		sigtype = DNS_SIGTYPE(dns_rdatatype_nsec3);
		wraps = true;
	}

	/*
	 * Use the auxiliary tree only starting with the second node in the
	 * hope that the original node will be right much of the time.
	 */
	result = dns_qpiter_current(&search->iter, name, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
again:
	do {
		dns_slabheader_t *found = NULL, *foundsig = NULL;
		dns_slabheader_list_t *hlist = NULL;

		empty_node = true;

		rcu_read_lock();
		cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
			dns_slabheader_t *header = NULL, *current = NULL;
			cds_list_for_each_entry_rcu (current, &hlist->versions,
						     dnode)
			{
				if (current->serial <= search->serial &&
				    !IGNORE(current))
				{
					header = current;
					break;
				}
			}
			if (header == NULL || NONEXISTENT(header)) {
				continue;
			}

			/*
			 * We now know that there is at least one
			 * active rdataset at this node.
			 */
			empty_node = false;
			if (header->type == type) {
				found = header;
				if (foundsig != NULL) {
					break;
				}
			} else if (header->type == sigtype) {
				foundsig = header;
				if (found != NULL) {
					break;
				}
			}
		}
		if (!empty_node) {
			if (found != NULL && search->version->havensec3 &&
			    found->type == dns_rdatatype_nsec3 &&
			    !matchparams(found, search))
			{
				empty_node = true;
				found = NULL;
				foundsig = NULL;
				result = previous_closest_nsec(type, search,
							       name, &prevnode,
							       NULL, NULL);
			} else if (found != NULL &&
				   (foundsig != NULL || !need_sig))
			{
				/*
				 * We've found the right NSEC/NSEC3
				 * record.
				 *
				 * Note: for this to really be the right
				 * NSEC record, it's essential that the
				 * NSEC records of any nodes obscured by
				 * a zone cut have been removed; we
				 * assume this is the case.
				 */
				dns_name_copy(name, foundname);
				if (nodep != NULL) {
					qpznode_acquire(
						search->qpdb,
						node DNS__DB_FLARG_PASS);
					*nodep = (dns_dbnode_t *)node;
				}
				bindrdataset(search->qpdb, node, found,

					     rdataset DNS__DB_FLARG_PASS);
				if (foundsig != NULL) {
					bindrdataset(
						search->qpdb, node, foundsig,

						sigrdataset DNS__DB_FLARG_PASS);
				}
			} else if (found == NULL && foundsig == NULL) {
				/*
				 * This node is active, but has no NSEC
				 * or RRSIG NSEC.  That means it's glue
				 * or other obscured zone data that
				 * isn't relevant for our search.  Treat
				 * the node as if it were empty and keep
				 * looking.
				 */
				empty_node = true;
				result = previous_closest_nsec(
					type, search, name, &prevnode,
					&nseciter, &first);
			} else {
				/*
				 * We found an active node, but either
				 * the NSEC or the RRSIG NSEC is
				 * missing.  This shouldn't happen.
				 */
				result = DNS_R_BADDB;
			}
		} else {
			/*
			 * This node isn't active.  We've got to keep
			 * looking.
			 */
			result = previous_closest_nsec(type, search, name,
						       &prevnode, &nseciter,
						       &first);
		}
		rcu_read_unlock();

		node = prevnode;
		prevnode = NULL;
	} while (empty_node && result == ISC_R_SUCCESS);

	if (result == ISC_R_NOMORE && wraps) {
		result = dns_qpiter_prev(&search->iter, name, (void **)&node,
					 NULL);
		if (result == ISC_R_SUCCESS) {
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
	dns_slabheader_list_t *hlist = NULL;
	dns_slabheader_t *dname_header = NULL, *sigdname_header = NULL;
	dns_slabheader_t *ns_header = NULL;
	dns_slabheader_t *found = NULL;
	isc_result_t result = DNS_R_CONTINUE;

	/*
	 * Look for an NS or DNAME rdataset active in our version.
	 */
	rcu_read_lock();
	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		if (hlist->type != dns_rdatatype_ns &&
		    hlist->type != dns_rdatatype_dname &&
		    hlist->type == DNS_SIGTYPE(dns_rdatatype_dname))
		{
			continue;
		}
		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= search->serial &&
			    !IGNORE(current))
			{
				header = current;
				break;
			}
		}
		if (header == NULL || NONEXISTENT(current)) {
			continue;
		}
		if (header->type == dns_rdatatype_dname) {
			dname_header = header;
		} else if (header->type == DNS_SIGTYPE(dns_rdatatype_dname)) {
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
		qpznode_acquire(search->qpdb, node DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = found;
		search->need_cleanup = true;
		/*
		 * Since we've found a zonecut, anything beneath it is
		 * glue and is not subject to wildcard matching, so we
		 * may clear search->wild.
		 */
		CMM_STORE_SHARED(search->wild, false);
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
		if (CMM_LOAD_SHARED(node->wild) &&
		    (search->options & DNS_DBFIND_NOWILD) == 0)
		{
			search->wild = true;
		}
	}

	rcu_read_unlock();

	return result;
}

static isc_result_t
qpzone_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	    dns_rdatatype_t type, unsigned int options,
	    isc_stdtime_t now ISC_ATTR_UNUSED, dns_dbnode_t **nodep,
	    dns_name_t *foundname, dns_rdataset_t *rdataset,
	    dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_result_t result;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = NULL;
	qpz_search_t search;
	bool cname_ok = true, close_version = false;
	bool maybe_zonecut = false, at_zonecut = false;
	bool wild = false, empty_node = false;
	bool nsec3 = false;
	dns_slabheader_list_t *hlist = NULL;
	dns_slabheader_t *found = NULL, *nsecheader = NULL;
	dns_slabheader_t *foundsig = NULL, *cnamesig = NULL, *nsecsig = NULL;
	dns_typepair_t sigtype;
	bool active;

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

	search = (qpz_search_t){
		.qpdb = (qpzonedb_t *)db,
		.version = (qpz_version_t *)version,
		.serial = ((qpz_version_t *)version)->serial,
		.options = options,
	};
	dns_fixedname_init(&search.zonecut_name);

	if ((options & DNS_DBFIND_FORCENSEC3) != 0) {
		dns_qpmulti_query(qpdb->nsec3, &search.qpr);
		nsec3 = true;
	} else {
		dns_qpmulti_query(qpdb->tree, &search.qpr);
	}

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(&search.qpr, name, NULL, &search.iter,
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

		dns_qpchain_node(&search.chain, i, NULL, (void **)&n, NULL);
		tresult = qpzone_check_zonecut(n, &search DNS__DB_FLARG_PASS);
		if (tresult != DNS_R_CONTINUE) {
			result = tresult;
			search.chain.len = i - 1;
			dns_name_copy(&n->name, foundname);
			node = n;
		}
	}

	rcu_read_lock();
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
			result = find_wildcard(&search, &node, name);
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
		if (CMM_LOAD_SHARED(node->delegating) &&
		    ((node != search.qpdb->origin &&
		      !dns_rdatatype_atparent(type)) ||
		     IS_STUB(search.qpdb)))
		{
			maybe_zonecut = true;
		}
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5 and RFC3007).
	 *
	 * We don't check for RRSIG, because we don't store RRSIG records
	 * directly.
	 */
	if (type == dns_rdatatype_key || type == dns_rdatatype_nsec) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	sigtype = DNS_SIGTYPE(type);
	empty_node = true;

	cds_list_for_each_entry_rcu (hlist, &node->headers, nnode) {
		dns_slabheader_t *header = NULL, *current = NULL;
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (current->serial <= search.serial &&
			    !IGNORE(current))
			{
				header = current;
				break;
			}
		}
		if (header == NULL || NONEXISTENT(header)) {
			continue;
		}

		/*
		 * We now know that there is at least one active
		 * rdataset at this node.
		 */
		empty_node = false;

		/*
		 * Do special zone cut handling, if requested.
		 */
		if (maybe_zonecut && header->type == dns_rdatatype_ns) {
			/*
			 * We increment the reference count on node to
			 * ensure that search->zonecut_header will
			 * still be valid later.
			 */
			qpznode_acquire(search.qpdb, node DNS__DB_FLARG_PASS);
			search.zonecut = node;
			search.zonecut_header = header;
			search.zonecut_sigheader = NULL;
			search.need_cleanup = true;
			maybe_zonecut = false;
			at_zonecut = true;
			/*
			 * It is not clear if KEY should still be
			 * allowed at the parent side of the zone
			 * cut or not.  It is needed for RFC3007
			 * validated updates.
			 */
			if ((search.options & DNS_DBFIND_GLUEOK) == 0 &&
			    type != dns_rdatatype_nsec &&
			    type != dns_rdatatype_key)
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
		if (header->type == dns_rdatatype_nsec3 &&
		    !matchparams(header, &search))
		{
			goto partial_match;
		}
		/*
		 * If we found a type we were looking for,
		 * remember it.
		 */
		if (header->type == type || type == dns_rdatatype_any ||
		    (header->type == dns_rdatatype_cname && cname_ok))
		{
			/*
			 * We've found the answer!
			 */
			found = header;
			if (header->type == dns_rdatatype_cname && cname_ok) {
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
					sigtype = DNS_SIGTYPE(
						dns_rdatatype_cname);
				}
			}
			/*
			 * If we've got all we need, end the search.
			 */
			if (!maybe_zonecut && foundsig != NULL) {
				break;
			}
		} else if (header->type == sigtype) {
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
		} else if (header->type == dns_rdatatype_nsec &&
			   !search.version->havensec3)
		{
			/*
			 * Remember a NSEC rdataset even if we're
			 * not specifically looking for it, because
			 * we might need it later.
			 */
			nsecheader = header;
		} else if (header->type == DNS_SIGTYPE(dns_rdatatype_nsec) &&
			   !search.version->havensec3)
		{
			/*
			 * If we need the NSEC rdataset, we'll also
			 * need its signature.
			 */
			nsecsig = header;
		} else if (cname_ok &&
			   header->type == DNS_SIGTYPE(dns_rdatatype_cname))
		{
			/*
			 * If we get a CNAME match, we'll also need
			 * its signature.
			 */
			cnamesig = header;
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
				dns_qpchain_node(&search.chain, len - 1, NULL,
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
				goto tree_exit;
			}

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
			qpznode_acquire(search.qpdb, node DNS__DB_FLARG_PASS);
			*nodep = (dns_dbnode_t *)node;
		}
		if (search.version->secure && !search.version->havensec3) {
			bindrdataset(search.qpdb, node, nsecheader,
				     rdataset DNS__DB_FLARG_PASS);
			if (nsecsig != NULL) {
				bindrdataset(search.qpdb, node, nsecsig,
					     sigrdataset DNS__DB_FLARG_PASS);
			}
		}
		if (wild) {
			foundname->attributes.wildcard = true;
		}
		goto tree_exit;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */
	if (type != found->type && type != dns_rdatatype_any &&
	    found->type == dns_rdatatype_cname)
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
		 * and the type is NSEC or KEY.
		 */
		if (search.zonecut == node) {
			/*
			 * It is not clear if KEY should still be
			 * allowed at the parent side of the zone
			 * cut or not.  It is needed for RFC3007
			 * validated updates.
			 */
			if (type == dns_rdatatype_nsec ||
			    type == dns_rdatatype_nsec3 ||
			    type == dns_rdatatype_key)
			{
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
			qpznode_acquire(search.qpdb, node DNS__DB_FLARG_PASS);
		} else {
			search.need_cleanup = false;
		}
		*nodep = (dns_dbnode_t *)node;
	}

	if (type != dns_rdatatype_any) {
		bindrdataset(search.qpdb, node, found,
			     rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(search.qpdb, node, foundsig,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	if (wild) {
		foundname->attributes.wildcard = true;
	}

tree_exit:
	rcu_read_unlock();

	if (nsec3) {
		dns_qpread_destroy(qpdb->nsec3, &search.qpr);
	} else {
		dns_qpread_destroy(qpdb->tree, &search.qpr);
	}

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);
		qpznode_release(search.qpdb, node, 0 DNS__DB_FLARG_PASS);
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

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);

	/*
	 * Clean the dirty node when acquiring the reference.  This is
	 * required because 'clean_zone_node()' might be running at the
	 * same time as acquiring the new reference and this would lead
	 * to an inconsistent state later.
	 *
	 * Thus either the qpznode_acquire() or qpznode_release() will
	 * clean the dirty node.
	 */
	if (CMM_LOAD_SHARED(node->dirty)) {
		isc_spinlock_lock(&node->spinlock);
		uint32_t least_serial = CMM_LOAD_SHARED(qpdb->least_serial);
		clean_zone_node(node, least_serial);
		isc_spinlock_unlock(&node->spinlock);
	}

	*iteratorp = (dns_rdatasetiter_t *)iterator;
	return ISC_R_SUCCESS;
}

static void
qpzone_attachnode(dns_db_t *db, dns_dbnode_t *source,
		  dns_dbnode_t **targetp DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)source;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(targetp != NULL && *targetp == NULL);

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
qpzone_detachnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	REQUIRE(VALID_QPZONE((qpzonedb_t *)db));
	REQUIRE(nodep != NULL && *nodep != NULL);

	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)(*nodep);
	*nodep = NULL;

	/*
	 * qpzone_destroy() uses call_rcu() API to destroy the node locks, so it
	 * is safe to call it in the middle of NODE_LOCK, but we need to acquire
	 * the database reference to prevent destroying the database while the
	 * NODE_LOCK is locked.
	 */

	qpzonedb_ref(qpdb);

	rcu_read_lock();
	qpznode_release(qpdb, node, 0 DNS__DB_FLARG_PASS);
	rcu_read_unlock();

	qpzonedb_unref(qpdb);
}

static unsigned int
nodecount(dns_db_t *db, dns_dbtree_t tree) {
	qpzonedb_t *qpdb = NULL;
	dns_qp_memusage_t mu;

	qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	switch (tree) {
	case dns_dbtree_main:
		mu = dns_qpmulti_memusage(qpdb->tree);
		break;
	case dns_dbtree_nsec:
		mu = dns_qpmulti_memusage(qpdb->nsec);
		break;
	case dns_dbtree_nsec3:
		mu = dns_qpmulti_memusage(qpdb->nsec3);
		break;
	default:
		UNREACHABLE();
	}

	return mu.leaves;
}

static void
setloop(dns_db_t *db, isc_loop_t *loop) {
	qpzonedb_t *qpdb = NULL;

	qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
	}
	if (loop != NULL) {
		isc_loop_attach(loop, &qpdb->loop);
	}
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to the origin node doesn't require a DB lock */
	INSIST(qpdb->origin != NULL);
	qpznode_acquire(qpdb, qpdb->origin DNS__DB_FLARG_PASS);
	*nodep = (dns_dbnode_t *)qpdb->origin;

	return ISC_R_SUCCESS;
}

static void
locknode(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *dbnode,
	 isc_rwlocktype_t type ISC_ATTR_UNUSED) {
	qpznode_t *node = (qpznode_t *)dbnode;

	SPINLOCK(&node->spinlock);
}

static void
unlocknode(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *dbnode,
	   isc_rwlocktype_t type ISC_ATTR_UNUSED) {
	qpznode_t *node = (qpznode_t *)dbnode;

	SPINUNLOCK(&node->spinlock);
}

static void
deletedata(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node ISC_ATTR_UNUSED,
	   void *data) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_slabheader_t *header = data;

	if (header->heap != NULL && header->heap_index != 0) {
		RWLOCK(&qpdb->lock, isc_rwlocktype_write);
		isc_heap_delete(header->heap, header->heap_index);
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
	}
	header->heap_index = 0;
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)(*iteratorp);
	*iteratorp = NULL;

	if (qrditer->common.version != NULL) {
		closeversion(qrditer->common.db, &qrditer->common.version,
			     false DNS__DB_FLARG_PASS);
	}
	dns__db_detachnode(qrditer->common.db,
			   &qrditer->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(qrditer->common.db->mctx, qrditer, sizeof(*qrditer));
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpznode_t *node = (qpznode_t *)qrditer->common.node;
	qpz_version_t *version = (qpz_version_t *)qrditer->common.version;
	dns_slabheader_list_t *hcurrent = NULL;

	rcu_read_lock();
	cds_list_for_each_entry_rcu (hcurrent, &node->headers, nnode) {
		dns_slabheader_t *current = NULL;
		cds_list_for_each_entry_rcu (current, &hcurrent->versions,
					     dnode)
		{
			if (current->serial <= version->serial &&
			    !IGNORE(current) && !NONEXISTENT(current))
			{
				qrditer->hlist = hcurrent;
				qrditer->header = current;
				rcu_read_unlock();
				return ISC_R_SUCCESS;
			}
		}
	}
	rcu_read_unlock();

	return ISC_R_NOMORE;
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpznode_t *node = (qpznode_t *)qrditer->common.node;
	qpz_version_t *version = (qpz_version_t *)qrditer->common.version;
	dns_slabheader_list_t *hcurrent = NULL;

	if (qrditer->hlist == NULL || qrditer->header == NULL) {
		return ISC_R_NOMORE;
	}

	/*
	 * Find the start of the header chain for the next type.
	 */

	/*
	 * NOTE: No header will be removed during iterator as we hold to node
	 * reference, so it should be safe to just enter critical section while
	 * we are reading the list.  This of course means that any new header
	 * that gets inserted while iterating will show up here.  That said -
	 * any new inserted header will have larger serial number.
	 */
	rcu_read_lock();
	for (hcurrent =
		     cds_list_entry(rcu_dereference(qrditer->hlist->nnode.next),
				    dns_slabheader_list_t, nnode);
	     &hcurrent->nnode != &node->headers;
	     hcurrent = cds_list_entry(rcu_dereference(hcurrent->nnode.next),
				       dns_slabheader_list_t, nnode))
	{
		dns_slabheader_t *current = NULL;
		cds_list_for_each_entry_rcu (current, &hcurrent->versions,
					     dnode)
		{
			if (current->serial <= version->serial &&
			    !IGNORE(current) && !NONEXISTENT(current))
			{
				qrditer->hlist = hcurrent;
				qrditer->header = current;
				rcu_read_unlock();
				return ISC_R_SUCCESS;
			}
		}
	}
	rcu_read_unlock();

	return ISC_R_NOMORE;
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *qrditer = (qpdb_rdatasetiter_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)(qrditer->common.db);
	qpznode_t *node = (qpznode_t *)qrditer->common.node;
	dns_slabheader_t *header = NULL;

	header = qrditer->header;
	REQUIRE(header != NULL);

	/*
	 * The node is reference counted, so no header will be removed
	 * when any iterator is active.
	 */
	bindrdataset(qpdb, node, header, rdataset DNS__DB_FLARG_PASS);
}

/*
 * Database Iterator Methods
 */
static void
reference_iter_node(qpdb_dbiterator_t *iter DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)iter->common.db;
	qpznode_t *node = iter->node;

	if (node == NULL) {
		return;
	}

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpdb_dbiterator_t *iter DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)iter->common.db;
	qpznode_t *node = iter->node;

	if (node == NULL) {
		return;
	}

	iter->node = NULL;
	qpznode_release(qpdb, node, 0 DNS__DB_FLARG_PASS);
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpdb_dbiterator_t *iter = (qpdb_dbiterator_t *)(*iteratorp);
	dns_db_t *db = NULL;

	dereference_iter_node(iter DNS__DB_FLARG_PASS);

	dns_db_attach(iter->common.db, &db);
	dns_db_detach(&iter->common.db);

	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	dns_qpsnap_destroy(qpdb->tree, &iter->tsnap);
	dns_qpsnap_destroy(qpdb->nsec3, &iter->nsnap);

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

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdbiter->nsnap, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, NULL,
					 (void **)&qpdbiter->node, NULL);
		if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
			/* If we're in the NSEC3 tree, skip the origin */
			if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
				result = dns_qpiter_next(
					qpdbiter->current, NULL,
					(void **)&qpdbiter->node, NULL);
			}
		}
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->mainiter;
		dns_qpiter_init(qpdbiter->tsnap, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, NULL,
					 (void **)&qpdbiter->node, NULL);
		break;
	case full:
		qpdbiter->current = &qpdbiter->mainiter;
		dns_qpiter_init(qpdbiter->tsnap, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, NULL,
					 (void **)&qpdbiter->node, NULL);
		if (result == ISC_R_NOMORE) {
			qpdbiter->current = &qpdbiter->nsec3iter;
			dns_qpiter_init(qpdbiter->nsnap, qpdbiter->current);
			result = dns_qpiter_next(qpdbiter->current, NULL,
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

	switch (qpdbiter->nsec3mode) {
	case nsec3only:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdbiter->nsnap, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, NULL,
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
		qpdbiter->current = &qpdbiter->mainiter;
		dns_qpiter_init(qpdbiter->tsnap, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, NULL,
					 (void **)&qpdbiter->node, NULL);
		break;
	case full:
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdbiter->nsnap, qpdbiter->current);
		result = dns_qpiter_prev(qpdbiter->current, NULL,
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
			qpdbiter->current = &qpdbiter->mainiter;
			dns_qpiter_init(qpdbiter->tsnap, qpdbiter->current);
			result = dns_qpiter_prev(qpdbiter->current, NULL,
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
		qpdbiter->current = &qpdbiter->nsec3iter;
		result = dns_qp_lookup(qpdbiter->nsnap, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case nonsec3:
		qpdbiter->current = &qpdbiter->mainiter;
		result = dns_qp_lookup(qpdbiter->tsnap, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		break;
	case full:
		/*
		 * Stay on main chain if not found on
		 * either iterator.
		 */
		qpdbiter->current = &qpdbiter->mainiter;
		result = dns_qp_lookup(qpdbiter->tsnap, name, NULL,
				       qpdbiter->current, NULL,
				       (void **)&qpdbiter->node, NULL);
		if (result == DNS_R_PARTIALMATCH) {
			tresult = dns_qp_lookup(qpdbiter->nsnap, name, NULL,
						&qpdbiter->nsec3iter, NULL,
						NULL, NULL);
			if (tresult == ISC_R_SUCCESS) {
				qpdbiter->current = &qpdbiter->nsec3iter;
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
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_prev(qpdbiter->current, NULL,
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
			qpdbiter->current = &qpdbiter->mainiter;
			dns_qpiter_init(qpdbiter->tsnap, qpdbiter->current);
			result = dns_qpiter_prev(qpdbiter->current, NULL,
						 (void **)&qpdbiter->node,
						 NULL);
		}
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
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_next(qpdbiter->current, NULL,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_NOMORE && qpdbiter->nsec3mode == full &&
	    qpdbiter->current == &qpdbiter->mainiter)
	{
		qpdbiter->current = &qpdbiter->nsec3iter;
		dns_qpiter_init(qpdbiter->nsnap, qpdbiter->current);
		result = dns_qpiter_next(qpdbiter->current, NULL,
					 (void **)&qpdbiter->node, NULL);
	}

	if (result == ISC_R_SUCCESS) {
		/*
		 * If we've just started the NSEC3 tree,
		 * skip over the origin.
		 */
		if (QPDBITER_NSEC3_ORIGIN_NODE(qpdb, qpdbiter)) {
			switch (qpdbiter->nsec3mode) {
			case nsec3only:
			case full:
				result = dns_qpiter_next(
					qpdbiter->current, NULL,
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
	qpzonedb_t *qpdb = (qpzonedb_t *)iterator->db;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpznode_t *node = qpdbiter->node;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(qpdbiter->node != NULL);

	if (name != NULL) {
		dns_name_copy(&qpdbiter->node->name, name);
	}

	qpznode_acquire(qpdb, node DNS__DB_FLARG_PASS);

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
		iter->current = &iter->nsec3iter;
	} else if ((options & DNS_DB_NONSEC3) != 0) {
		iter->nsec3mode = nonsec3;
		iter->current = &iter->mainiter;
	} else {
		iter->nsec3mode = full;
		iter->current = &iter->mainiter;
	}

	dns_db_attach(db, &iter->common.db);

	dns_qpmulti_snapshot(qpdb->tree, &iter->tsnap);
	dns_qpiter_init(iter->tsnap, &iter->mainiter);

	dns_qpmulti_snapshot(qpdb->nsec3, &iter->nsnap);
	dns_qpiter_init(iter->nsnap, &iter->nsec3iter);

	*iteratorp = (dns_dbiterator_t *)iter;
	return ISC_R_SUCCESS;
}

static isc_result_t
qpzone_addrdataset(dns_db_t *db, dns_dbnode_t *dbnode,
		   dns_dbversion_t *dbversion,
		   isc_stdtime_t now ISC_ATTR_UNUSED, dns_rdataset_t *rdataset,
		   unsigned int options,
		   dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	isc_result_t result;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *node = (qpznode_t *)dbnode;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_qp_t *nsec = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	/*
	 * SOA records are only allowed at top of zone.
	 */
	if (rdataset->type == dns_rdatatype_soa && node != qpdb->origin) {
		return DNS_R_NOTZONETOP;
	}

	REQUIRE((node->nsec == DNS_DB_NSEC_NSEC3 &&
		 (rdataset->type == dns_rdatatype_nsec3 ||
		  rdataset->covers == dns_rdatatype_nsec3)) ||
		(node->nsec != DNS_DB_NSEC_NSEC3 &&
		 rdataset->type != dns_rdatatype_nsec3 &&
		 rdataset->covers != dns_rdatatype_nsec3));

	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, qpdb->maxrrperset);
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

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, db, (dns_dbnode_t *)node);
	newheader->ttl = rdataset->ttl;
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}

	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));

	newheader->serial = version->serial;
	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	}

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	if (node->nsec != DNS_DB_NSEC_HAS_NSEC &&
	    rdataset->type == dns_rdatatype_nsec)
	{
		dns_qpmulti_write(qpdb->nsec, &nsec);
	}

	/*
	 * If we're adding a delegation type or adding to the auxiliary NSEC
	 * tree hold an exclusive lock on the tree.  In the latter case the
	 * lock does not necessarily have to be acquired but it will help
	 * purge ancient entries more effectively.
	 */

	result = ISC_R_SUCCESS;
	if (nsec != NULL) {
		node->nsec = DNS_DB_NSEC_HAS_NSEC;

		/*
		 * If it fails, there was already an NSEC node,
		 * so we can detach the new one we created and
		 * move on.
		 */
		qpznode_t *nsecnode = NULL;
		qpznode_create(qpdb, name, &nsecnode);
		nsecnode->nsec = DNS_DB_NSEC_NSEC;
		(void)dns_qp_insert(nsec, nsecnode, 0);
		qpznode_detach(&nsecnode);
	}

	if (result == ISC_R_SUCCESS) {
		isc_spinlock_lock(&node->spinlock);
		rcu_read_lock();
		result = add(qpdb, node, name, version, newheader, options,
			     false, addedrdataset, 0 DNS__DB_FLARG_PASS);
		rcu_read_unlock();
		isc_spinlock_unlock(&node->spinlock);
	}

	/*
	 * If we're adding a delegation type (e.g. NS or DNAME),
	 * then we need to set the callback bit on the node.
	 */
	if (result == ISC_R_SUCCESS &&
	    delegating_type(qpdb, node, rdataset->type))
	{
		CMM_STORE_SHARED(node->delegating, true);
	}

	if (nsec != NULL) {
		dns_qpmulti_commit(qpdb->nsec, &nsec);
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
	dns_slabheader_list_t *hlist = NULL, *hcurrent = NULL;
	dns_slabheader_t *header = NULL, *current = NULL;
	dns_slabheader_t *newheader = NULL;
	dns_slabheader_t *subresult = NULL;
	isc_region_t region;
	isc_result_t result;
	qpz_changed_t *changed = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	REQUIRE((node->nsec == DNS_DB_NSEC_NSEC3 &&
		 (rdataset->type == dns_rdatatype_nsec3 ||
		  rdataset->covers == dns_rdatatype_nsec3)) ||
		(node->nsec != DNS_DB_NSEC_NSEC3 &&
		 rdataset->type != dns_rdatatype_nsec3 &&
		 rdataset->covers != dns_rdatatype_nsec3));

	dns_name_copy(&node->name, nodename);
	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, 0);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, db, (dns_dbnode_t *)node);
	newheader->ttl = rdataset->ttl;
	atomic_init(&newheader->attributes, 0);
	newheader->serial = version->serial;
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	}

	isc_spinlock_lock(&node->spinlock);
	rcu_read_lock();

	changed = add_changed(newheader, version DNS__DB_FLARG_PASS);
	cds_list_for_each_entry_rcu (hcurrent, &node->headers, nnode) {
		if (hcurrent->type == newheader->type) {
			hlist = hcurrent;
			break;
		}
	}
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	if (hlist != NULL) {
		cds_list_for_each_entry_rcu (current, &hlist->versions, dnode) {
			if (!IGNORE(current)) {
				header = current;
				break;
			}
		}
	}

	if (header != NULL && !NONEXISTENT(header)) {
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
				header, newheader, qpdb->common.mctx,
				qpdb->common.rdclass,
				(dns_rdatatype_t)header->type, flags,
				&subresult);
		}
		if (result == ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			newheader = subresult;
			dns_slabheader_reset(newheader, db,
					     (dns_dbnode_t *)node);
			dns_slabheader_copycase(newheader, header);
			if (RESIGN(header)) {
				DNS_SLABHEADER_SETATTR(
					newheader, DNS_SLABHEADERATTR_RESIGN);
				newheader->resign = header->resign;
				newheader->resign_lsb = header->resign_lsb;
				resigninsert(qpdb, newheader);
			}
			/*
			 * We have to set the serial since the rdataslab
			 * subtraction routine copies the reserved portion of
			 * header, not newheader.
			 */
			newheader->serial = version->serial;
			/*
			 * XXXJT: dns_rdataslab_subtract() copied the pointers
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
			dns_slabheader_destroy(&newheader);
			newheader = dns_slabheader_new((dns_db_t *)qpdb,
						       (dns_dbnode_t *)node);
			newheader->ttl = 0;
			newheader->type = hlist->type;
			atomic_init(&newheader->attributes,
				    DNS_SLABHEADERATTR_NONEXISTENT);
			newheader->serial = version->serial;
		} else {
			dns_slabheader_destroy(&newheader);
			goto unlock;
		}

		/*
		 * If we're here, we want to link newheader in front of
		 * topheader.
		 */
		INSIST(version->serial >= header->serial);
		maybe_update_recordsandsize(false, version, header,
					    nodename->length);

		cds_list_add_rcu(&newheader->dnode, &hlist->versions);

		CMM_STORE_SHARED(node->dirty, true);
		if (changed != NULL) {
			changed->dirty = true;
		}

		resigndelete(qpdb, version, header DNS__DB_FLARG_PASS);
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
		bindrdataset(qpdb, node, newheader,
			     newrdataset DNS__DB_FLARG_PASS);
	}

	if (result == DNS_R_NXRRSET && newrdataset != NULL &&
	    (options & DNS_DBSUB_WANTOLD) != 0)
	{
		bindrdataset(qpdb, node, header,
			     newrdataset DNS__DB_FLARG_PASS);
	}

unlock:
	rcu_read_unlock();
	isc_spinlock_unlock(&node->spinlock);

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
	dns_slabheader_t *newheader = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(version != NULL && version->qpdb == qpdb);

	if (type == dns_rdatatype_any) {
		return ISC_R_NOTIMPLEMENTED;
	}
	if (type == dns_rdatatype_rrsig && covers == 0) {
		return ISC_R_NOTIMPLEMENTED;
	}

	newheader = dns_slabheader_new(db, (dns_dbnode_t *)node);
	newheader->type = DNS_TYPEPAIR_VALUE(type, covers);
	newheader->ttl = 0;
	atomic_init(&newheader->attributes, DNS_SLABHEADERATTR_NONEXISTENT);
	newheader->serial = version->serial;

	dns_name_copy(&node->name, nodename);

	isc_spinlock_lock(&node->spinlock);
	rcu_read_lock();
	result = add(qpdb, node, nodename, version, newheader, DNS_DBADD_FORCE,
		     false, NULL, 0 DNS__DB_FLARG_PASS);
	rcu_read_unlock();
	isc_spinlock_unlock(&node->spinlock);
	return result;
}

static isc_result_t
nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpznode_t *qpnode = (qpznode_t *)node;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(node != NULL);
	REQUIRE(name != NULL);

	/* FIXME: is RCU read lock enough? */
	rcu_read_lock();
	dns_name_copy(&qpnode->name, name);
	rcu_read_unlock();

	return ISC_R_SUCCESS;
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
new_gluelist(dns_db_t *db, dns_slabheader_t *header,
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
	dns_glue_additionaldata_ctx_t *ctx = NULL;
	isc_result_t result;
	dns_fixedname_t fixedname_a;
	dns_name_t *name_a = NULL;
	dns_rdataset_t rdataset_a, sigrdataset_a;
	const qpznode_t *node = NULL;
	qpznode_t *node_a = NULL;
	dns_fixedname_t fixedname_aaaa;
	dns_name_t *name_aaaa = NULL;
	dns_rdataset_t rdataset_aaaa, sigrdataset_aaaa;
	qpznode_t *node_aaaa = NULL;
	dns_glue_t *glue = NULL;

	/*
	 * NS records want addresses in additional records.
	 */
	INSIST(qtype == dns_rdatatype_a);

	ctx = (dns_glue_additionaldata_ctx_t *)arg;

	node = (qpznode_t *)ctx->node;

	name_a = dns_fixedname_initname(&fixedname_a);
	dns_rdataset_init(&rdataset_a);
	dns_rdataset_init(&sigrdataset_a);

	name_aaaa = dns_fixedname_initname(&fixedname_aaaa);
	dns_rdataset_init(&rdataset_aaaa);
	dns_rdataset_init(&sigrdataset_aaaa);

	result = qpzone_find(ctx->db, name, ctx->version, dns_rdatatype_a,
			     DNS_DBFIND_GLUEOK, 0, (dns_dbnode_t **)&node_a,
			     name_a, &rdataset_a,
			     &sigrdataset_a DNS__DB_FLARG_PASS);
	if (result == DNS_R_GLUE) {
		glue = new_glue(ctx->db->mctx, name_a);

		dns_rdataset_init(&glue->rdataset_a);
		dns_rdataset_init(&glue->sigrdataset_a);
		dns_rdataset_init(&glue->rdataset_aaaa);
		dns_rdataset_init(&glue->sigrdataset_aaaa);

		dns_rdataset_clone(&rdataset_a, &glue->rdataset_a);
		if (dns_rdataset_isassociated(&sigrdataset_a)) {
			dns_rdataset_clone(&sigrdataset_a,
					   &glue->sigrdataset_a);
		}
	}

	result = qpzone_find(ctx->db, name, ctx->version, dns_rdatatype_aaaa,
			     DNS_DBFIND_GLUEOK, 0, (dns_dbnode_t **)&node_aaaa,
			     name_aaaa, &rdataset_aaaa,
			     &sigrdataset_aaaa DNS__DB_FLARG_PASS);
	if (result == DNS_R_GLUE) {
		if (glue == NULL) {
			glue = new_glue(ctx->db->mctx, name_aaaa);

			dns_rdataset_init(&glue->rdataset_a);
			dns_rdataset_init(&glue->sigrdataset_a);
			dns_rdataset_init(&glue->rdataset_aaaa);
			dns_rdataset_init(&glue->sigrdataset_aaaa);
		} else {
			INSIST(node_a == node_aaaa);
			INSIST(dns_name_equal(name_a, name_aaaa));
		}

		dns_rdataset_clone(&rdataset_aaaa, &glue->rdataset_aaaa);
		if (dns_rdataset_isassociated(&sigrdataset_aaaa)) {
			dns_rdataset_clone(&sigrdataset_aaaa,
					   &glue->sigrdataset_aaaa);
		}
	}

	/*
	 * If the currently processed NS record is in-bailiwick, mark any glue
	 * RRsets found for it with DNS_RDATASETATTR_REQUIRED.  Note that for
	 * simplicity, glue RRsets for all in-bailiwick NS records are marked
	 * this way, even though dns_message_rendersection() only checks the
	 * attributes for the first rdataset associated with the first name
	 * added to the ADDITIONAL section.
	 */
	if (glue != NULL && dns_name_issubdomain(name, &node->name)) {
		if (dns_rdataset_isassociated(&glue->rdataset_a)) {
			glue->rdataset_a.attributes |=
				DNS_RDATASETATTR_REQUIRED;
		}
		if (dns_rdataset_isassociated(&glue->rdataset_aaaa)) {
			glue->rdataset_aaaa.attributes |=
				DNS_RDATASETATTR_REQUIRED;
		}
	}

	if (glue != NULL) {
		glue->next = ctx->glue;
		ctx->glue = glue;
	}

	result = ISC_R_SUCCESS;

	if (dns_rdataset_isassociated(&rdataset_a)) {
		dns_rdataset_disassociate(&rdataset_a);
	}
	if (dns_rdataset_isassociated(&sigrdataset_a)) {
		dns_rdataset_disassociate(&sigrdataset_a);
	}

	if (dns_rdataset_isassociated(&rdataset_aaaa)) {
		dns_rdataset_disassociate(&rdataset_aaaa);
	}
	if (dns_rdataset_isassociated(&sigrdataset_aaaa)) {
		dns_rdataset_disassociate(&sigrdataset_aaaa);
	}

	if (node_a != NULL) {
		dns__db_detachnode(ctx->db,
				   (dns_dbnode_t **)&node_a DNS__DB_FLARG_PASS);
	}
	if (node_aaaa != NULL) {
		dns__db_detachnode(
			ctx->db,
			(dns_dbnode_t **)&node_aaaa DNS__DB_FLARG_PASS);
	}

	return result;
}

#define IS_REQUIRED_GLUE(r) (((r)->attributes & DNS_RDATASETATTR_REQUIRED) != 0)

static void
addglue_to_message(dns_glue_t *ge, dns_message_t *msg) {
	for (; ge != NULL; ge = ge->next) {
		dns_name_t *name = NULL;
		dns_rdataset_t *rdataset_a = NULL;
		dns_rdataset_t *sigrdataset_a = NULL;
		dns_rdataset_t *rdataset_aaaa = NULL;
		dns_rdataset_t *sigrdataset_aaaa = NULL;
		bool prepend_name = false;

		dns_message_gettempname(msg, &name);

		dns_name_copy(&ge->name, name);

		if (dns_rdataset_isassociated(&ge->rdataset_a)) {
			dns_message_gettemprdataset(msg, &rdataset_a);
		}

		if (dns_rdataset_isassociated(&ge->sigrdataset_a)) {
			dns_message_gettemprdataset(msg, &sigrdataset_a);
		}

		if (dns_rdataset_isassociated(&ge->rdataset_aaaa)) {
			dns_message_gettemprdataset(msg, &rdataset_aaaa);
		}

		if (dns_rdataset_isassociated(&ge->sigrdataset_aaaa)) {
			dns_message_gettemprdataset(msg, &sigrdataset_aaaa);
		}

		if (rdataset_a != NULL) {
			dns_rdataset_clone(&ge->rdataset_a, rdataset_a);
			ISC_LIST_APPEND(name->list, rdataset_a, link);
			if (IS_REQUIRED_GLUE(rdataset_a)) {
				prepend_name = true;
			}
		}

		if (sigrdataset_a != NULL) {
			dns_rdataset_clone(&ge->sigrdataset_a, sigrdataset_a);
			ISC_LIST_APPEND(name->list, sigrdataset_a, link);
		}

		if (rdataset_aaaa != NULL) {
			dns_rdataset_clone(&ge->rdataset_aaaa, rdataset_aaaa);
			ISC_LIST_APPEND(name->list, rdataset_aaaa, link);
			if (IS_REQUIRED_GLUE(rdataset_aaaa)) {
				prepend_name = true;
			}
		}
		if (sigrdataset_aaaa != NULL) {
			dns_rdataset_clone(&ge->sigrdataset_aaaa,
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
create_gluelist(qpzonedb_t *qpdb, qpz_version_t *version, qpznode_t *node,
		dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);
	dns_glue_additionaldata_ctx_t ctx = {
		.db = (dns_db_t *)qpdb,
		.version = (dns_dbversion_t *)version,
		.node = (dns_dbnode_t *)node,
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
addglue(dns_db_t *db, dns_dbversion_t *dbversion, dns_rdataset_t *rdataset,
	dns_message_t *msg) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpz_version_t *version = (qpz_version_t *)dbversion;
	qpznode_t *node = (qpznode_t *)rdataset->slab.node;
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);
	dns_glue_t *glue = NULL;
	isc_statscounter_t counter = dns_gluecachestatscounter_hits_absent;

	REQUIRE(rdataset->type == dns_rdatatype_ns);
	REQUIRE(qpdb == (qpzonedb_t *)rdataset->slab.db);
	REQUIRE(qpdb == version->qpdb);
	REQUIRE(!IS_STUB(qpdb));

	rcu_read_lock();

	dns_gluelist_t *gluelist = rcu_dereference(header->gluelist);
	if (gluelist == NULL || gluelist->version != dbversion) {
		/* No or old glue list was found in the table. */

		dns_gluelist_t *xchg_gluelist = gluelist;
		dns_gluelist_t *old_gluelist = (void *)-1;
		dns_gluelist_t *new_gluelist = create_gluelist(qpdb, version,
							       node, rdataset);

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
		addglue_to_message(glue, msg);
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

static dns_dbmethods_t qpdb_zonemethods = {
	.destroy = qpzonedb_destroy,
	.beginload = beginload,
	.endload = endload,
	.currentversion = currentversion,
	.newversion = newversion,
	.attachversion = attachversion,
	.closeversion = closeversion,
	.findnode = qpzone_findnode,
	.find = qpzone_find,
	.attachnode = qpzone_attachnode,
	.detachnode = qpzone_detachnode,
	.createiterator = qpzone_createiterator,
	.findrdataset = qpzone_findrdataset,
	.allrdatasets = qpzone_allrdatasets,
	.addrdataset = qpzone_addrdataset,
	.subtractrdataset = qpzone_subtractrdataset,
	.deleterdataset = qpzone_deleterdataset,
	.issecure = issecure,
	.nodecount = nodecount,
	.setloop = setloop,
	.getoriginnode = getoriginnode,
	.getnsec3parameters = getnsec3parameters,
	.findnsec3node = qpzone_findnsec3node,
	.setsigningtime = setsigningtime,
	.getsigningtime = getsigningtime,
	.getsize = getsize,
	.setgluecachestats = setgluecachestats,
	.locknode = locknode,
	.unlocknode = unlocknode,
	.addglue = addglue,
	.deletedata = deletedata,
	.nodefullname = nodefullname,
	.setmaxrrperset = setmaxrrperset,
	.setmaxtypepername = setmaxtypepername,
};

static void
qpznode_destroy_rcu(struct rcu_head *rcu_head) {
	qpznode_t *node = caa_container_of(rcu_head, qpznode_t, rcu_head);

	isc_spinlock_destroy(&node->spinlock);
	dns_name_free(&node->name, node->mctx);
	isc_mem_putanddetach(&node->mctx, node, sizeof(qpznode_t));
}

static void
qpznode_destroy(qpznode_t *node) {
	dns_slabheader_list_t *hlist = NULL, *hnext = NULL;
	dns_slabheader_t *header = NULL, *next = NULL;

	cds_list_for_each_entry_safe (hlist, hnext, &node->headers, nnode) {
		cds_list_for_each_entry_safe (header, next, &hlist->versions,
					      dnode)
		{
			cds_list_del_rcu(&header->dnode);
			dns_slabheader_destroy(&header);
		}

		cds_list_del_rcu(&hlist->nnode);
		dns_slabheader_destroylist(&hlist);
	}

	call_rcu(&node->rcu_head, qpznode_destroy_rcu);
}

#if DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpznode, qpznode_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpznode, qpznode_destroy);
#endif

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpzonedb, qpzonedb__destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpzonedb, qpzonedb__destroy);
#endif

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
	return dns_qpkey_fromname(key, &data->name);
}

static void
qp_triename(void *uctx ISC_ATTR_UNUSED, char *buf, size_t size) {
	snprintf(buf, size, "QPDB");
}
