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

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) == 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_IGNORE) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NXDOMAIN) != 0)
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
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STATCOUNT) != 0)

#define QPDB_ATTR_LOADED  0x01
#define QPDB_ATTR_LOADING 0x02

#define DEFAULT_NODE_LOCK_COUNT 7 /*%< Should be prime. */

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPZONE_DB_MAGIC ISC_MAGIC('Q', 'Z', 'D', 'B')
#define VALID_QPZONE(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPZONE_DB_MAGIC)

typedef struct qpzonedb qpzonedb_t;

typedef struct qpdb_changed {
	dns_rbtnode_t *node;
	bool dirty;
	ISC_LINK(struct qpdb_changed) link;
} qpdb_changed_t;

typedef ISC_LIST(qpdb_changed_t) qpdb_changedlist_t;

typedef struct qpdb_version qpdb_version_t;
struct qpdb_version {
	/* Not locked */
	uint32_t serial;
	qpzonedb_t *qpdb;
	isc_refcount_t references;
	/* Locked by database lock. */
	bool writer;
	qpdb_changedlist_t changed_list;
	dns_slabheaderlist_t resigned_list;
	ISC_LINK(qpdb_version_t) link;
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

typedef ISC_LIST(qpdb_version_t) qpdb_versionlist_t;

typedef struct qpdata {
	dns_fixedname_t fn;
	dns_name_t *name;
	isc_mem_t *mctx;
	isc_refcount_t references;
	uint16_t locknum;
	unsigned int	  : 0;
	unsigned int nsec : 2; /*%< range is 0..3 */
	unsigned int	  : 0;
} qpdata_t;

struct qpzonedb {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;
	/* Locks for tree nodes */
	int node_lock_count;
	db_nodelock_t *node_locks;
	qpdata_t *origin;
	qpdata_t *nsec3_origin;
	dns_stats_t *rrsetstats;     /* cache DB only */
	isc_stats_t *cachestats;     /* cache DB only */
	isc_stats_t *gluecachestats; /* zone DB only */
	/* Locked by lock. */
	unsigned int active;
	unsigned int attributes;
	uint32_t current_serial;
	uint32_t least_serial;
	uint32_t next_serial;
	qpdb_version_t *current_version;
	qpdb_version_t *future_version;
	qpdb_versionlist_t open_versions;
	isc_loop_t *loop;

	isc_heap_t **heaps; /* Resigning heaps, one per nodelock bucket */

	dns_qpmulti_t *tree;  /* Main QP trie for data storage */
	dns_qpmulti_t *nsec;  /* NSEC nodes only */
	dns_qpmulti_t *nsec3; /* NSEC3 nodes only */
};

static dns_dbmethods_t qpdb_zonemethods;

#if DNS_DB_NODETRACE
#define qpdata_ref(ptr)	  qpdata__ref(ptr, __func__, __FILE__, __LINE__)
#define qpdata_unref(ptr) qpdata__unref(ptr, __func__, __FILE__, __LINE__)
#define qpdata_attach(ptr, ptrp) \
	qpdata__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpdata_detach(ptrp) qpdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(qpdata);
#else
ISC_REFCOUNT_DECL(qpdata);
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
freeglue(dns_glue_t *glue_list) {
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

	freeglue(glue);
}

static void
free_gluetable(struct cds_wfs_stack *glue_stack) {
	struct cds_wfs_head *head = __cds_wfs_pop_all(glue_stack);
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

static void
free_qpdb(qpzonedb_t *qpdb, bool log) {
	char buf[DNS_NAME_FORMATSIZE];
	dns_qpmulti_t **treep = NULL;

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

	for (;;) {
		/*
		 * pick the next tree to destroy
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

		dns_qpmulti_destroy(treep);
	}

	if (log) {
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DB, ISC_LOG_DEBUG(1),
			      "done free_qpdb(%s)", buf);
	}
	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}
	for (int i = 0; i < qpdb->node_lock_count; i++) {
		isc_refcount_destroy(&qpdb->node_locks[i].references);
		NODE_DESTROYLOCK(&qpdb->node_locks[i].lock);
	}

	/*
	 * Clean up heap objects.
	 */
	if (qpdb->heaps != NULL) {
		for (int i = 0; i < qpdb->node_lock_count; i++) {
			isc_heap_destroy(&qpdb->heaps[i]);
		}
		isc_mem_cput(qpdb->common.mctx, qpdb->heaps,
			     qpdb->node_lock_count, sizeof(isc_heap_t *));
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
	isc_refcount_destroy(&qpdb->common.references);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
	}

	isc_rwlock_destroy(&qpdb->lock);
	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;

	if (qpdb->common.update_listeners != NULL) {
		INSIST(!cds_lfht_destroy(qpdb->common.update_listeners, NULL));
	}

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb, sizeof(*qpdb));
}

static void
qpzonedb_destroy(dns_db_t *arg) {
	qpzonedb_t *qpdb = (qpzonedb_t *)arg;
	unsigned int inactive = 0;

	if (qpdb->origin != NULL) {
		qpdata_detach(&qpdb->origin);
	}
	if (qpdb->nsec3_origin != NULL) {
		qpdata_detach(&qpdb->nsec3_origin);
	}

	/*
	 * The current version's glue table needs to be freed early
	 * so the nodes are dereferenced before we check the active
	 * node count below.
	 */
	if (qpdb->current_version != NULL) {
		free_gluetable(&qpdb->current_version->glue_stack);
	}

	/*
	 * Even though there are no external direct references, there still
	 * may be nodes in use.
	 */
	for (int i = 0; i < qpdb->node_lock_count; i++) {
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
		bool want_free = false;

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
				      DNS_LOGMODULE_DB, ISC_LOG_DEBUG(1),
				      "calling free_qpdb(%s)", buf);
			free_qpdb(qpdb, true);
		}
	}
}

static qpdata_t *
new_qpdata(isc_mem_t *mctx, const dns_name_t *name) {
	qpdata_t *newdata = isc_mem_get(mctx, sizeof(*newdata));
	*newdata = (qpdata_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};
	newdata->name = dns_fixedname_initname(&newdata->fn);
	dns_name_copy(name, newdata->name);
	isc_mem_attach(mctx, &newdata->mctx);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "new_qpdata:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return (newdata);
}

static qpdb_version_t *
allocate_version(isc_mem_t *mctx, uint32_t serial, unsigned int references,
		 bool writer) {
	qpdb_version_t *version = isc_mem_get(mctx, sizeof(*version));
	*version = (qpdb_version_t){
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
dns__qpzone_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
		   dns_rdataclass_t rdclass, unsigned int argc ISC_ATTR_UNUSED,
		   char **argv ISC_ATTR_UNUSED, void *driverarg ISC_ATTR_UNUSED,
		   dns_db_t **dbp) {
	qpzonedb_t *qpdb = NULL;
	isc_result_t result;
	dns_qp_t *qp = NULL;

	REQUIRE(type != dns_dbtype_cache);

	qpdb = isc_mem_get(mctx, sizeof(*qpdb));
	*qpdb = (qpzonedb_t){
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.node_lock_count = DEFAULT_NODE_LOCK_COUNT,
		.current_serial = 1,
		.least_serial = 1,
		.next_serial = 2,
		.open_versions = ISC_LIST_INITIALIZER,
	};

	isc_refcount_init(&qpdb->common.references, 1);

	qpdb->common.methods = &qpdb_zonemethods;
	if (type == dns_dbtype_stub) {
		qpdb->common.attributes |= DNS_DBATTR_STUB;
	}

	isc_rwlock_init(&qpdb->lock);

	qpdb->node_locks = isc_mem_cget(mctx, qpdb->node_lock_count,
					sizeof(db_nodelock_t));

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	/*
	 * Create the heaps.
	 */
	qpdb->heaps = isc_mem_cget(mctx, qpdb->node_lock_count,
				   sizeof(isc_heap_t *));
	for (int i = 0; i < qpdb->node_lock_count; i++) {
		qpdb->heaps[i] = NULL;
	}

	for (int i = 0; i < (int)qpdb->node_lock_count; i++) {
		isc_heap_create(mctx, resign_sooner, set_index, 0,
				&qpdb->heaps[i]);
	}

	qpdb->active = qpdb->node_lock_count;

	for (int i = 0; i < qpdb->node_lock_count; i++) {
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

	/*
	 * Make a copy of the origin name.
	 */
	result = dns_name_dupwithoffsets(origin, mctx, &qpdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		free_qpdb(qpdb, false);
		return (result);
	}

	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->tree);
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->nsec);
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->nsec3);

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
	qpdb->origin = new_qpdata(mctx, &qpdb->common.origin);
	result = dns_qp_insert(qp, qpdb->origin, 0);
	qpdb->origin->nsec = DNS_DB_NSEC_NORMAL;
	dns_qpmulti_commit(qpdb->tree, &qp);

	if (result != ISC_R_SUCCESS) {
		INSIST(result != ISC_R_EXISTS);
		free_qpdb(qpdb, false);
		return (result);
	}

	INSIST(qpdb->origin != NULL);

	/*
	 * Add an apex node to the NSEC3 tree so that NSEC3 searches
	 * return partial matches when there is only a single NSEC3
	 * record in the tree.
	 */
	dns_qpmulti_write(qpdb->nsec3, &qp);
	qpdb->nsec3_origin = new_qpdata(mctx, &qpdb->common.origin);
	qpdb->nsec3_origin->nsec = DNS_DB_NSEC_NSEC3;
	result = dns_qp_insert(qp, qpdb->nsec3_origin, 0);
	dns_qpmulti_commit(qpdb->nsec3, &qp);

	if (result != ISC_R_SUCCESS) {
		INSIST(result != ISC_R_EXISTS);
		free_qpdb(qpdb, false);
		return (result);
	}

	/*
	 * We need to give the origin nodes the right locknum.
	 */
	qpdb->origin->locknum = qpdb->nsec3_origin->locknum =
		dns_name_hash(&qpdb->common.origin) % qpdb->node_lock_count;

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
	qpdb->common.impmagic = QPZONE_DB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return (ISC_R_SUCCESS);
}

static dns_dbmethods_t qpdb_zonemethods = {
	.destroy = qpzonedb_destroy,
};

static void
destroy_qpdata(qpdata_t *data) {
	isc_mem_putanddetach(&data->mctx, data, sizeof(qpdata_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_TRACE_IMPL(qpdata, destroy_qpdata);
#else
ISC_REFCOUNT_IMPL(qpdata, destroy_qpdata);
#endif

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	qpdata_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	qpdata_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	return (dns_qpkey_fromname(key, data->name));
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	UNUSED(uctx); /* XXX */
	snprintf(buf, size, "QPDB");
}
