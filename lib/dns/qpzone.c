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
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NEGATIVE) != 0)

#define HEADERNODE(h) ((qpdata_t *)((h)->node))

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
typedef struct qpdata qpdata_t;

typedef struct qpdb_changed {
	qpdata_t *node;
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

struct qpdata {
	dns_fixedname_t fn;
	dns_name_t *name;
	isc_mem_t *mctx;
	isc_refcount_t references;
	uint16_t locknum;
	void *data;
	unsigned int		: 0;
	unsigned int nsec	: 2; /*%< range is 0..3 */
	unsigned int wild	: 1;
	unsigned int delegating : 1;
	unsigned int dirty	: 1;
	unsigned int		: 0;
};

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
	struct rcu_head rcu_head;

	isc_heap_t **heaps; /* Resigning heaps, one per nodelock bucket */

	dns_qpmulti_t *tree;  /* Main QP trie for data storage */
	dns_qpmulti_t *nsec;  /* NSEC nodes only */
	dns_qpmulti_t *nsec3; /* NSEC3 nodes only */
};

/*%
 * Search Context
 */
typedef struct {
	qpzonedb_t *qpdb;
	qpdb_version_t *version;
	dns_qpread_t qpr;
	uint32_t serial;
	unsigned int options;
	dns_qpchain_t chain;
	dns_qpiter_t iter;
	bool copy_name;
	bool need_cleanup;
	bool wild;
	qpdata_t *zonecut;
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	dns_fixedname_t zonecut_name;
	isc_stdtime_t now;
} qpdb_search_t;

/*%
 * Load Context
 */
typedef struct {
	dns_db_t *db;
	isc_stdtime_t now;
	dns_qp_t *tree;
	dns_qp_t *nsec;
	dns_qp_t *nsec3;
} qpdb_load_t;

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
	case dns_rdatatype_ns:
	case DNS_SIGTYPE(dns_rdatatype_ns):
	case dns_rdatatype_ds:
	case DNS_SIGTYPE(dns_rdatatype_ds):
	case dns_rdatatype_nsec3:
	case DNS_SIGTYPE(dns_rdatatype_nsec3):
	case dns_rdatatype_cname:
	case DNS_SIGTYPE(dns_rdatatype_cname):
		return (true);
	}

	return (false);
}

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
free_db_rcu(struct rcu_head *rcu_head) {
	qpzonedb_t *qpdb = caa_container_of(rcu_head, qpzonedb_t, rcu_head);

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
free_qpdb(qpzonedb_t *qpdb, bool log) {
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

	if (qpdb->tree != NULL) {
		dns_qpmulti_destroy(&qpdb->tree);
	}
	if (qpdb->nsec != NULL) {
		dns_qpmulti_destroy(&qpdb->nsec);
	}
	if (qpdb->nsec3 != NULL) {
		dns_qpmulti_destroy(&qpdb->nsec3);
	}

	if (log) {
		char buf[DNS_NAME_FORMATSIZE];
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DB, ISC_LOG_DEBUG(1),
			      "called free_qpdb(%s)", buf);
	}

	call_rcu(&qpdb->rcu_head, free_db_rcu);
}

static void
qpdb_destroy(dns_db_t *arg) {
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
new_qpdata(qpzonedb_t *qpdb, const dns_name_t *name) {
	qpdata_t *newdata = isc_mem_get(qpdb->common.mctx, sizeof(*newdata));
	*newdata = (qpdata_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};
	newdata->locknum = dns_name_hash(name) % qpdb->node_lock_count;
	newdata->name = dns_fixedname_initname(&newdata->fn);
	dns_name_copy(name, newdata->name);
	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);

#if DNS_DB_NODETRACE
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
	qpdb->origin = new_qpdata(qpdb, &qpdb->common.origin);
	result = dns_qp_insert(qp, qpdb->origin, 0);
	qpdb->origin->nsec = DNS_DB_NSEC_NORMAL;
	dns_qpmulti_commit(qpdb->tree, &qp);

	if (result != ISC_R_SUCCESS) {
		INSIST(result != ISC_R_EXISTS);
		free_qpdb(qpdb, false);
		return (result);
	}

	/*
	 * Add an apex node to the NSEC3 tree so that NSEC3 searches
	 * return partial matches when there is only a single NSEC3
	 * record in the tree.
	 */
	dns_qpmulti_write(qpdb->nsec3, &qp);
	qpdb->nsec3_origin = new_qpdata(qpdb, &qpdb->common.origin);
	qpdb->nsec3_origin->nsec = DNS_DB_NSEC_NSEC3;
	result = dns_qp_insert(qp, qpdb->nsec3_origin, 0);
	dns_qpmulti_commit(qpdb->nsec3, &qp);

	if (result != ISC_R_SUCCESS) {
		INSIST(result != ISC_R_EXISTS);
		free_qpdb(qpdb, false);
		return (result);
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
	qpdb->common.impmagic = QPZONE_DB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return (ISC_R_SUCCESS);
}

static void
newref(qpzonedb_t *qpdb, qpdata_t *node DNS__DB_FLARG) {
	uint_fast32_t refs;

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

static void
clean_zone_node(qpdata_t *node, uint32_t least_serial) {
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
		 * the most recent version.
		 */
		if (current->down != NULL) {
			still_dirty = true;
		}
		top_prev = current;
	}
	if (!still_dirty) {
		node->dirty = 0;
	}
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
static bool
decref(qpzonedb_t *qpdb, qpdata_t *node, uint32_t least_serial,
       isc_rwlocktype_t *nlocktypep DNS__DB_FLARG) {
	db_nodelock_t *nodelock = NULL;
	int bucket = node->locknum;
	uint_fast32_t refs;

	REQUIRE(*nlocktypep != isc_rwlocktype_none);

	nodelock = &qpdb->node_locks[bucket];

#define KEEP_NODE(n, r) \
	((n)->data != NULL || (n) == (r)->origin || (n) == (r)->nsec3_origin)

	/* Handle easy and typical case first. */
	if (!node->dirty && KEEP_NODE(node, qpdb)) {
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
		}

		return (false);
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

	refs = isc_refcount_decrement(&nodelock->references);
#if DNS_DB_NODETRACE
	fprintf(stderr,
		"decr:nodelock:%s:%s:%u:%p:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, nodelock, refs - 1);
#else
	UNUSED(refs);
#endif

	if (KEEP_NODE(node, qpdb)) {
		return (true);
	}
#undef KEEP_NODE

	return (true);
}

static void
bindrdataset(qpzonedb_t *qpdb, qpdata_t *node, dns_slabheader_t *header,
	     isc_stdtime_t now, dns_rdataset_t *rdataset DNS__DB_FLARG) {
	if (rdataset == NULL) {
		return;
	}

	newref(qpdb, node DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->type);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->type);
	rdataset->ttl = header->ttl - now;
	rdataset->trust = header->trust;

	if (NEGATIVE(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NEGATIVE;
	}
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
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdb_version_t *version = NULL;

	REQUIRE(VALID_QPZONE(qpdb));

	RWLOCK(&qpdb->lock, isc_rwlocktype_read);
	version = qpdb->current_version;
	isc_refcount_increment(&version->references);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_read);

	*versionp = (dns_dbversion_t *)version;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp,
	     bool commit ISC_ATTR_UNUSED DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdb_version_t *version = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	version = (qpdb_version_t *)*versionp;
	INSIST(version->qpdb == qpdb);

	/*
	 * XXX: currently only current_version works.
	 */
	INSIST(version == qpdb->current_version);

	if (isc_refcount_decrement(&version->references) > 1) {
		*versionp = NULL;
		return;
	}

	INSIST(EMPTY(version->changed_list));
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *dbnode, dns_dbversion_t *dbversion,
	     dns_rdatatype_t type, dns_rdatatype_t covers,
	     isc_stdtime_t now ISC_ATTR_UNUSED, dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdata_t *node = (qpdata_t *)dbnode;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	uint32_t serial;
	qpdb_version_t *version = dbversion;
	bool close_version = false;
	dns_typepair_t matchtype, sigmatchtype;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(type != dns_rdatatype_any);
	INSIST(version == NULL || version->qpdb == qpdb);

	if (version == NULL) {
		currentversion(db, (dns_dbversion_t **)&version);
		close_version = true;
	}
	serial = version->serial;

	NODE_RDLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);

	matchtype = DNS_TYPEPAIR_VALUE(type, covers);
	if (covers == 0) {
		sigmatchtype = DNS_SIGTYPE(type);
	} else {
		sigmatchtype = 0;
	}

	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		do {
			if (header->serial <= serial && !IGNORE(header)) {
				if (NONEXISTENT(header)) {
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			/*
			 * We have an active, extant rdataset.  If it's a
			 * type we're looking for, remember it.
			 */
			if (header->type == matchtype) {
				found = header;
				if (foundsig != NULL) {
					break;
				}
			} else if (header->type == sigmatchtype) {
				foundsig = header;
				if (found != NULL) {
					break;
				}
			}
		}
	}
	if (found != NULL) {
		bindrdataset(qpdb, node, found, 0, rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(qpdb, node, foundsig, 0,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	NODE_UNLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);

	if (close_version) {
		closeversion(db, (dns_dbversion_t **)&version,
			     false DNS__DB_FLARG_PASS);
	}

	if (found == NULL) {
		return (ISC_R_NOTFOUND);
	}

	return (ISC_R_SUCCESS);
}

static bool
delegating_type(qpzonedb_t *qpdb, qpdata_t *node, dns_typepair_t type) {
	return (type == dns_rdatatype_dname ||
		(type == dns_rdatatype_ns &&
		 (node != qpdb->origin || IS_STUB(qpdb))));
}

static void
loading_addnode(qpzonedb_t *qpdb, const dns_name_t *name, dns_rdatatype_t type,
		dns_rdatatype_t covers, qpdata_t **nodep) {
	isc_result_t result;
	qpdata_t *node = NULL, *nsecnode = NULL;
	dns_qp_t *qp = NULL, *nsec = NULL;

	if (type == dns_rdatatype_nsec3 || covers == dns_rdatatype_nsec3) {
		dns_qpmulti_write(qpdb->nsec3, &qp);
		result = dns_qp_getname(qp, name, (void **)&node, NULL);
		if (result == ISC_R_SUCCESS) {
			*nodep = node;
		} else {
			node = new_qpdata(qpdb, name);
			result = dns_qp_insert(qp, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			node->nsec = DNS_DB_NSEC_NSEC3;
			*nodep = node;
			qpdata_detach(&node);
		}
		dns_qp_compact(qp, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec3, &qp);
		return;
	}

	dns_qpmulti_write(qpdb->tree, &qp);
	result = dns_qp_getname(qp, name, (void **)&node, NULL);
	if (result == ISC_R_SUCCESS) {
		if (type == dns_rdatatype_nsec &&
		    node->nsec == DNS_DB_NSEC_HAS_NSEC)
		{
			goto done;
		}
	} else {
		INSIST(node == NULL);
		node = new_qpdata(qpdb, name);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpdata_unref(node);
	}
	if (type != dns_rdatatype_nsec) {
		goto done;
	}

	/*
	 * We're adding an NSEC record, so create a node in the nsec tree
	 * too. This tree speeds searches for closest NSECs that would
	 * otherwise need to examine many irrelevant nodes in large TLDs.
	 */
	dns_qpmulti_write(qpdb->nsec, &nsec);
	nsecnode = new_qpdata(qpdb, name);
	result = dns_qp_insert(nsec, nsecnode, 0);
	node->nsec = DNS_DB_NSEC_HAS_NSEC;
	if (result == ISC_R_SUCCESS) {
		nsecnode->nsec = DNS_DB_NSEC_NSEC;
	}
	qpdata_detach(&nsecnode);

done:
	if (nsec != NULL) {
		dns_qp_compact(nsec, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->nsec, &nsec);
	}

	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->tree, &qp);
	*nodep = node;
}

static bool
cname_and_other(qpdata_t *node, uint32_t serial) {
	dns_slabheader_t *header = NULL, *header_next = NULL;
	bool cname = false, other = false;
	dns_rdatatype_t rdtype;

	/*
	 * Look for CNAME and "other data" rdatasets active in our version.
	 * ("Other data" is any rdataset whose type is not KEY, NSEC, SIG
	 * or RRSIG.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;

		if (!prio_type(header->type)) {
			/*
			 * CNAME is in the priority list, so if we are done
			 * with priority types, we know there will not be a
			 * CNAME, and are safe to skip the rest.
			 */
			return (false);
		}

		rdtype = DNS_TYPEPAIR_TYPE(header->type);
		if (rdtype == dns_rdatatype_cname) {
			do {
				if (header->serial <= serial && !IGNORE(header))
				{
					if (NONEXISTENT(header)) {
						header = NULL;
					}
					break;
				}
				header = header->down;
			} while (header != NULL);
			if (header != NULL) {
				cname = true;
			}
		} else if (rdtype != dns_rdatatype_key &&
			   rdtype != dns_rdatatype_sig &&
			   rdtype != dns_rdatatype_nsec &&
			   rdtype != dns_rdatatype_rrsig)
		{
			do {
				if (header->serial <= serial && !IGNORE(header))
				{
					if (NONEXISTENT(header)) {
						header = NULL;
					}
					break;
				}
				header = header->down;
			} while (header != NULL);
			if (header != NULL) {
				other = true;
			}
		}

		if (cname && other) {
			return (true);
		}
	}

	return (false);
}

static qpdb_changed_t *
add_changed(dns_slabheader_t *header, qpdb_version_t *version DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	qpzonedb_t *qpdb = (qpzonedb_t *)header->db;

	changed = isc_mem_get(qpdb->common.mctx, sizeof(*changed));

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);
	REQUIRE(version->writer);
	qpdata_t *node = (qpdata_t *)header->node;
	uint_fast32_t refs = isc_refcount_increment(&node->references);
#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif
	*changed = (qpdb_changed_t){ .node = node };
	ISC_LIST_INITANDAPPEND(version->changed_list, changed, link);
	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	return (changed);
}

static void
resigninsert(qpzonedb_t *qpdb, int idx, dns_slabheader_t *newheader) {
	INSIST(newheader->heap_index == 0);
	INSIST(!ISC_LINK_LINKED(newheader, link));

	isc_heap_insert(qpdb->heaps[idx], newheader);
	newheader->heap = qpdb->heaps[idx];
}

static void
resigndelete(qpzonedb_t *qpdb, qpdb_version_t *version,
	     dns_slabheader_t *header DNS__DB_FLARG) {
	if (header != NULL && header->heap_index != 0) {
		isc_heap_delete(qpdb->heaps[HEADERNODE(header)->locknum],
				header->heap_index);
		header->heap_index = 0;
		if (version != NULL) {
			newref(qpdb, HEADERNODE(header) DNS__DB_FLARG_PASS);
			ISC_LIST_APPEND(version->resigned_list, header, link);
		}
	}
}

static uint64_t
recordsize(dns_slabheader_t *header, unsigned int namelen) {
	return (dns_rdataslab_rdatasize((unsigned char *)header,
					sizeof(*header)) +
		sizeof(dns_ttl_t) + sizeof(dns_rdatatype_t) +
		sizeof(dns_rdataclass_t) + namelen);
}

static void
maybe_update_recordsandsize(bool add, qpdb_version_t *version,
			    dns_slabheader_t *header, unsigned int namelen) {
	unsigned char *hdr = (unsigned char *)header;
	size_t hdrsize = sizeof(*header);

	if (version == NULL || NONEXISTENT(header)) {
		return;
	}

	RWLOCK(&version->rwlock, isc_rwlocktype_write);
	if (add) {
		version->records += dns_rdataslab_count(hdr, hdrsize);
		version->xfrsize += recordsize(header, namelen);
	} else {
		version->records -= dns_rdataslab_count(hdr, hdrsize);
		version->xfrsize -= recordsize(header, namelen);
	}
	RWUNLOCK(&version->rwlock, isc_rwlocktype_write);
}

static isc_result_t
add(qpzonedb_t *qpdb, qpdata_t *node, const dns_name_t *nodename,
    qpdb_version_t *version, dns_slabheader_t *newheader, unsigned int options,
    bool loading, dns_rdataset_t *addedrdataset,
    isc_stdtime_t now DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	dns_slabheader_t *topheader = NULL, *topheader_prev = NULL;
	dns_slabheader_t *prioheader = NULL;
	dns_slabheader_t *header = NULL;
	unsigned char *merged = NULL;
	isc_result_t result;
	bool merge = false;
	int idx;

	if ((options & DNS_DBADD_MERGE) != 0) {
		REQUIRE(version != NULL);
		merge = true;
	}

	if (version != NULL && !loading) {
		/*
		 * We always add a changed record, even if no changes end up
		 * being made to this node, because it's harmless and
		 * simplifies the code.
		 */
		changed = add_changed(newheader, version DNS__DB_FLARG_PASS);
	}

	for (topheader = node->data; topheader != NULL;
	     topheader = topheader->next)
	{
		if (prio_type(topheader->type)) {
			prioheader = topheader;
		}
		if (topheader->type == newheader->type) {
			break;
		}
		topheader_prev = topheader;
	}

	/*
	 * If topheader isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
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
				dns_slabheader_destroy(&newheader);
				return (result);
			}
		}

		INSIST(version == NULL || version->serial >= topheader->serial);
		if (loading) {
			newheader->down = NULL;
			idx = HEADERNODE(newheader)->locknum;
			if (RESIGN(newheader)) {
				resigninsert(qpdb, idx, newheader);
				/* resigndelete not needed here */
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
				node->data = newheader;
			}
			newheader->next = topheader->next;
			maybe_update_recordsandsize(false, version, header,
						    nodename->length);
			dns_slabheader_destroy(&header);
		} else {
			idx = HEADERNODE(newheader)->locknum;
			if (RESIGN(newheader)) {
				resigninsert(qpdb, idx, newheader);
				resigndelete(qpdb, version,
					     header DNS__DB_FLARG_PASS);
			}
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				node->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			node->dirty = 1;
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
			return (DNS_R_UNCHANGED);
		}

		idx = HEADERNODE(newheader)->locknum;
		if (RESIGN(newheader)) {
			resigninsert(qpdb, idx, newheader);
			resigndelete(qpdb, version, header DNS__DB_FLARG_PASS);
		}

		if (topheader != NULL) {
			/*
			 * We have a list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);
			INSIST(version == NULL ||
			       version->serial >= topheader->serial);
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				node->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			if (changed != NULL) {
				changed->dirty = true;
			}
			node->dirty = 1;
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */
			INSIST(newheader->down == NULL);

			if (prio_type(newheader->type)) {
				/* This is a priority type, prepend it */
				newheader->next = node->data;
				node->data = newheader;
			} else if (prioheader != NULL) {
				/* Append after the priority headers */
				newheader->next = prioheader->next;
				prioheader->next = newheader;
			} else {
				/* There were no priority headers */
				newheader->next = node->data;
				node->data = newheader;
			}
		}
	}

	maybe_update_recordsandsize(true, version, newheader, nodename->length);

	/*
	 * Check if the node now contains CNAME and other data.
	 */
	if (version != NULL && cname_and_other(node, version->serial)) {
		return (DNS_R_CNAMEANDOTHER);
	}

	if (addedrdataset != NULL) {
		bindrdataset(qpdb, node, newheader, now,
			     addedrdataset DNS__DB_FLARG_PASS);
	}

	return (ISC_R_SUCCESS);
}

static void
wildcardmagic(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	      bool lock) {
	isc_result_t result;
	dns_name_t foundname;
	dns_offsets_t offsets;
	unsigned int n;
	qpdata_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	dns_name_init(&foundname, offsets);
	n = dns_name_countlabels(name);
	INSIST(n >= 2);
	n--;
	dns_name_getlabelsequence(name, 1, n, &foundname);

	/* insert an empty node, if needed, to hold the wildcard bit */
	result = dns_qp_getname(qp, &foundname, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		INSIST(node == NULL);
		node = new_qpdata(qpdb, &foundname);
		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		qpdata_unref(node);
	}

	/* set the bit, locking if necessary */
	if (lock) {
		NODE_WRLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);
	}
	node->wild = 1;
	if (lock) {
		NODE_UNLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);
	}
}

static void
addwildcards(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	     bool lock) {
	dns_name_t foundname;
	dns_offsets_t offsets;
	unsigned int n, l, i;

	dns_name_init(&foundname, offsets);
	n = dns_name_countlabels(name);
	l = dns_name_countlabels(&qpdb->common.origin);
	i = l + 1;
	while (i < n) {
		dns_name_getlabelsequence(name, n - i, i, &foundname);
		if (dns_name_iswildcard(&foundname)) {
			wildcardmagic(qpdb, qp, &foundname, lock);
		}

		i++;
	}
}

static isc_result_t
loading_addrdataset(void *arg, const dns_name_t *name,
		    dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpdb_load_t *loadctx = arg;
	qpzonedb_t *qpdb = (qpzonedb_t *)loadctx->db;
	qpdata_t *node = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	dns_qp_t *qp = NULL;

	REQUIRE(rdataset->rdclass == qpdb->common.rdclass);

	/*
	 * SOA records are only allowed at top of zone.
	 */
	if (rdataset->type == dns_rdatatype_soa &&
	    !dns_name_equal(name, &qpdb->common.origin))
	{
		return (DNS_R_NOTZONETOP);
	}

	dns_qpmulti_write(qpdb->tree, &qp);
	if (rdataset->type != dns_rdatatype_nsec3 &&
	    rdataset->covers != dns_rdatatype_nsec3)
	{
		addwildcards(qpdb, qp, name, false);
	}

	if (dns_name_iswildcard(name)) {
		if (rdataset->type == dns_rdatatype_ns) {
			/*
			 * NS owners cannot legally be wild cards.
			 */
			result = DNS_R_INVALIDNS;
		} else if (rdataset->type == dns_rdatatype_nsec3) {
			/*
			 * NSEC3 owners cannot legally be wild cards.
			 */
			result = DNS_R_INVALIDNSEC3;
		} else {
			wildcardmagic(qpdb, qp, name, false);
		}
	}
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->tree, &qp);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	loading_addnode(qpdb, name, rdataset->type, rdataset->covers, &node);
	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, sizeof(dns_slabheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	newheader = (dns_slabheader_t *)region.base;
	*newheader = (dns_slabheader_t){
		.type = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers),
		.ttl = rdataset->ttl + loadctx->now,
		.trust = rdataset->trust,
		.node = node,
		.serial = 1,
		.count = 1,
	};

	dns_slabheader_reset(newheader, (dns_db_t *)qpdb, node);
	dns_slabheader_setownercase(newheader, name);

	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	}

	NODE_WRLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);
	result = add(qpdb, node, name, qpdb->current_version, newheader,
		     DNS_DBADD_MERGE, true, NULL, 0 DNS__DB_FLARG_PASS);
	NODE_UNLOCK(&qpdb->node_locks[node->locknum].lock, &nlocktype);

	if (result == ISC_R_SUCCESS &&
	    delegating_type(qpdb, node, rdataset->type))
	{
		node->delegating = 1;
	} else if (result == DNS_R_UNCHANGED) {
		result = ISC_R_SUCCESS;
	}

	return (result);
}

static isc_result_t
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpdb_load_t *loadctx = NULL;
	qpzonedb_t *qpdb = NULL;
	qpdb = (qpzonedb_t *)db;

	REQUIRE(DNS_CALLBACK_VALID(callbacks));
	REQUIRE(VALID_QPZONE(qpdb));

	loadctx = isc_mem_get(qpdb->common.mctx, sizeof(*loadctx));

	loadctx->db = db;
	loadctx->now = 0;

	RWLOCK(&qpdb->lock, isc_rwlocktype_write);

	REQUIRE((qpdb->attributes & (QPDB_ATTR_LOADED | QPDB_ATTR_LOADING)) ==
		0);
	qpdb->attributes |= QPDB_ATTR_LOADING;

	RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);

	callbacks->add = loading_addrdataset;
	callbacks->add_private = loadctx;

	return (ISC_R_SUCCESS);
}

static void
setnsec3parameters(dns_db_t *db, qpdb_version_t *version) {
	qpdata_t *node = NULL;
	dns_rdata_nsec3param_t nsec3param;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_region_t region;
	isc_result_t result;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	unsigned char *raw; /* RDATASLAB */
	unsigned int count, length;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	version->havensec3 = false;
	node = qpdb->origin;
	NODE_RDLOCK(&(qpdb->node_locks[node->locknum].lock), &nlocktype);
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		do {
			if (header->serial <= version->serial &&
			    !IGNORE(header))
			{
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);

		if (header != NULL &&
		    (header->type == dns_rdatatype_nsec3param))
		{
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
}

static void
setsecure(dns_db_t *db, qpdb_version_t *version, dns_dbnode_t *origin) {
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

static isc_result_t
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	qpdb_load_t *loadctx = NULL;
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
		dns_dbversion_t *version = qpdb->current_version;
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
		setsecure(db, version, qpdb->origin);
	} else {
		RWUNLOCK(&qpdb->lock, isc_rwlocktype_write);
	}

	callbacks->add = NULL;
	callbacks->add_private = NULL;

	isc_mem_put(qpdb->common.mctx, loadctx, sizeof(*loadctx));

	return (ISC_R_SUCCESS);
}

static isc_result_t
findnodeintree(qpzonedb_t *qpdb, dns_qp_t *qp, const dns_name_t *name,
	       bool create, bool nsec3, dns_dbnode_t **nodep DNS__DB_FLARG) {
	isc_result_t result;
	qpdata_t *node = NULL;

	result = dns_qp_getname(qp, name, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		if (!create) {
			return (result);
		}

		node = new_qpdata(qpdb, name);
		result = dns_qp_insert(qp, node, 0);
		qpdata_unref(node);

		if (result == ISC_R_SUCCESS) {
			if (nsec3) {
				node->nsec = DNS_DB_NSEC_NSEC3;
			} else {
				addwildcards(qpdb, qp, name, true);
				if (dns_name_iswildcard(name)) {
					wildcardmagic(qpdb, qp, name, true);
				}
			}
		} else if (result == ISC_R_EXISTS) {
			result = ISC_R_SUCCESS;
		}
	}

	if (nsec3) {
		INSIST(node->nsec == DNS_DB_NSEC_NSEC3);
	}

	newref(qpdb, node DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)node;
	return (result);
}

static isc_result_t
findnode(dns_db_t *db, const dns_name_t *name, bool create,
	 dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	isc_result_t result;
	dns_qpread_t qpr = { 0 };
	dns_qp_t *qp = NULL;

	REQUIRE(VALID_QPZONE(qpdb));

	if (create) {
		dns_qpmulti_write(qpdb->tree, &qp);
	} else {
		dns_qpmulti_query(qpdb->tree, &qpr);
		qp = (dns_qp_t *)&qpr;
	}

	result = findnodeintree(qpdb, qp, name, create, false,
				nodep DNS__DB_FLARG_PASS);

	if (create) {
		dns_qp_compact(qp, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &qp);
	} else {
		dns_qpread_destroy(qpdb->tree, &qpr);
	}

	return (result);
}

static bool
matchparams(dns_slabheader_t *header, qpdb_search_t *search) {
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
			return (true);
		}
		dns_rdata_reset(&rdata);
	}
	return (false);
}

static isc_result_t
setup_delegation(qpdb_search_t *search, dns_dbnode_t **nodep,
		 dns_name_t *foundname, dns_rdataset_t *rdataset,
		 dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_name_t *zcname = NULL;
	dns_typepair_t type;
	qpdata_t *node = NULL;

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
		*nodep = node;
		search->need_cleanup = false;
	}
	if (rdataset != NULL) {
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		NODE_RDLOCK(&(search->qpdb->node_locks[node->locknum].lock),
			    &nlocktype);
		bindrdataset(search->qpdb, node, search->zonecut_header,
			     search->now, rdataset DNS__DB_FLARG_PASS);
		if (sigrdataset != NULL && search->zonecut_sigheader != NULL) {
			bindrdataset(search->qpdb, node,
				     search->zonecut_sigheader, search->now,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
		NODE_UNLOCK(&(search->qpdb->node_locks[node->locknum].lock),
			    &nlocktype);
	}

	if (type == dns_rdatatype_dname) {
		return (DNS_R_DNAME);
	}
	return (DNS_R_DELEGATION);
}

typedef enum { FORWARD, BACK } direction_t;

/*
 * Step backwards or forwards through the database until we find a
 * node with data in it for the desired version. If 'nextname' is not NULL,
 * and we found a predecessor or successor, save the name we found in it.
 * Return true if we found a predecessor or successor.
 */
static bool
step(qpdb_search_t *search, dns_qpiter_t *it, direction_t direction,
     dns_name_t *nextname) {
	dns_fixedname_t fnodename;
	dns_name_t *nodename = dns_fixedname_initname(&fnodename);
	qpzonedb_t *qpdb = NULL;
	qpdata_t *node = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	dns_slabheader_t *header = NULL;

	qpdb = search->qpdb;

	result = dns_qpiter_current(it, nodename, (void **)&node, NULL);
	while (result == ISC_R_SUCCESS) {
		isc_rwlock_t *nodelock = &qpdb->node_locks[node->locknum].lock;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

		NODE_RDLOCK(nodelock, &nlocktype);
		for (header = node->data; header != NULL; header = header->next)
		{
			if (header->serial <= search->serial &&
			    !IGNORE(header) && !NONEXISTENT(header))
			{
				break;
			}
		}
		NODE_UNLOCK(nodelock, &nlocktype);
		if (header != NULL) {
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
		return (true);
	}

	return (false);
}

static bool
activeempty(qpdb_search_t *search, dns_qpiter_t *it,
	    const dns_name_t *current) {
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
	dns_qpiter_next(it, NULL, NULL, NULL);
	return (step(search, it, FORWARD, next) &&
		dns_name_issubdomain(next, current));
}

static bool
wildcard_blocked(qpdb_search_t *search, const dns_name_t *qname,
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

	dns_name_init(&name, NULL);
	dns_name_init(&tname, NULL);
	dns_name_init(&rname, NULL);
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
		return (false);
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
			return (true);
		}

		/*
		 * Remove the leftmost label from the qname and check again.
		 */
		n = dns_name_countlabels(&rname);
		dns_name_getlabelsequence(&rname, 1, n - 1, &rname);
	} while (!dns_name_equal(&rname, &tname));

	return (false);
}

static isc_result_t
find_wildcard(qpdb_search_t *search, qpdata_t **nodep,
	      const dns_name_t *qname) {
	dns_slabheader_t *header = NULL;
	isc_result_t result = ISC_R_NOTFOUND;
	qpzonedb_t *qpdb = search->qpdb;

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
		qpdata_t *node = NULL;
		isc_rwlock_t *lock = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		bool wild, active;

		dns_qpchain_node(&search->chain, i, NULL, (void **)&node, NULL);

		lock = &qpdb->node_locks[node->locknum].lock;
		NODE_RDLOCK(lock, &nlocktype);
		/*
		 * First we try to figure out if this node is active in
		 * the search's version.  We do this now, even though we
		 * may not need the information, because it simplifies the
		 * locking and code flow.
		 */
		for (header = node->data; header != NULL; header = header->next)
		{
			if (header->serial <= search->serial &&
			    !IGNORE(header) && !NONEXISTENT(header))
			{
				break;
			}
		}

		active = (header != NULL);
		wild = node->wild;
		NODE_UNLOCK(lock, &nlocktype);

		if (wild) {
			qpdata_t *wnode = NULL;
			dns_fixedname_t fwname;
			dns_name_t *wname = dns_fixedname_initname(&fwname);
			dns_qpiter_t wit;

			/*
			 * Construct the wildcard name for this level.
			 */
			result = dns_name_concatenate(dns_wildcardname,
						      node->name, wname, NULL);
			if (result != ISC_R_SUCCESS) {
				break;
			}

			result = dns_qp_lookup(&search->qpr, wname, NULL, &wit,
					       NULL, (void **)&wnode, NULL);
			if (result == ISC_R_SUCCESS) {
				/*
				 * We have found the wildcard node.  If it
				 * is active in the search's version, we're
				 * done.
				 */
				lock = &qpdb->node_locks[wnode->locknum].lock;
				NODE_RDLOCK(lock, &nlocktype);
				for (header = wnode->data; header != NULL;
				     header = header->next)
				{
					if (header->serial <= search->serial &&
					    !IGNORE(header) &&
					    !NONEXISTENT(header))
					{
						break;
					}
				}
				NODE_UNLOCK(lock, &nlocktype);
				if (header != NULL ||
				    activeempty(search, &wit, wname))
				{
					if (wildcard_blocked(search, qname,
							     wname))
					{
						return (ISC_R_NOTFOUND);
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

	return (result);
}

/*
 * Find node of the NSEC/NSEC3 record that is 'name'.
 */
static isc_result_t
previous_closest_nsec(dns_rdatatype_t type, qpdb_search_t *search,
		      dns_name_t *name, qpdata_t **nodep, dns_qpiter_t *nit,
		      bool *firstp) {
	isc_result_t result;
	dns_qpread_t qpr;

	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE(type == dns_rdatatype_nsec3 || firstp != NULL);

	if (type == dns_rdatatype_nsec3) {
		result = dns_qpiter_prev(&search->iter, name, (void **)nodep,
					 NULL);
		return (result);
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
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_ERROR,
				      "previous_closest_nsec(): %s",
				      isc_result_totext(result));
			result = DNS_R_BADDB;
			break;
		}
	}

	dns_qpread_destroy(search->qpdb->nsec, &qpr);
	return (result);
}

/*
 * Find the NSEC/NSEC3 which is or before the current point on the
 * search chain.  For NSEC3 records only NSEC3 records that match the
 * current NSEC3PARAM record are considered.
 */
static isc_result_t
find_closest_nsec(qpdb_search_t *search, dns_dbnode_t **nodep,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset, bool nsec3,
		  bool secure DNS__DB_FLARG) {
	qpdata_t *node = NULL, *prevnode = NULL;
	dns_slabheader_t *header = NULL, *header_next = NULL;
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
		return (result);
	}
again:
	do {
		dns_slabheader_t *found = NULL, *foundsig = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		NODE_RDLOCK(&(search->qpdb->node_locks[node->locknum].lock),
			    &nlocktype);
		empty_node = true;
		for (header = node->data; header != NULL; header = header_next)
		{
			header_next = header->next;
			/*
			 * Look for an active, extant NSEC or RRSIG NSEC.
			 */
			do {
				if (header->serial <= search->serial &&
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
			if (header != NULL) {
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
					newref(search->qpdb,
					       node DNS__DB_FLARG_PASS);
					*nodep = node;
				}
				bindrdataset(search->qpdb, node, found,
					     search->now,
					     rdataset DNS__DB_FLARG_PASS);
				if (foundsig != NULL) {
					bindrdataset(
						search->qpdb, node, foundsig,
						search->now,
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
					type, search, name, &prevnode,
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
			result = previous_closest_nsec(type, search, name,
						       &prevnode, &nseciter,
						       &first);
		}
		NODE_UNLOCK(&(search->qpdb->node_locks[node->locknum].lock),
			    &nlocktype);
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

	return (result);
}

static isc_result_t
check_zonecut(qpdata_t *node, void *arg DNS__DB_FLARG) {
	qpdb_search_t *search = arg;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	dns_slabheader_t *dname_header = NULL, *sigdname_header = NULL;
	dns_slabheader_t *ns_header = NULL;
	dns_slabheader_t *found = NULL;
	isc_result_t result = DNS_R_CONTINUE;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	NODE_RDLOCK(&(search->qpdb->node_locks[node->locknum].lock),
		    &nlocktype);

	/*
	 * Look for an NS or DNAME rdataset active in our version.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->type == dns_rdatatype_ns ||
		    header->type == dns_rdatatype_dname ||
		    header->type == DNS_SIGTYPE(dns_rdatatype_dname))
		{
			do {
				if (header->serial <= search->serial &&
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
			if (header != NULL) {
				if (header->type == dns_rdatatype_dname) {
					dname_header = header;
				} else if (header->type ==
					   DNS_SIGTYPE(dns_rdatatype_dname))
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
		newref(search->qpdb, node DNS__DB_FLARG_PASS);
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
			dns_name_copy(node->name, zcname);
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

	NODE_UNLOCK(&(search->qpdb->node_locks[node->locknum].lock),
		    &nlocktype);

	return (result);
}

static isc_result_t
find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options,
     isc_stdtime_t now ISC_ATTR_UNUSED, dns_dbnode_t **nodep,
     dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_result_t result;
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdata_t *node = NULL;
	qpdb_search_t search;
	bool cname_ok = true, close_version = false;
	bool maybe_zonecut = false, at_zonecut = false;
	bool wild = false, empty_node = false;
	bool nsec3 = false;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *nsecheader = NULL;
	dns_slabheader_t *foundsig = NULL, *cnamesig = NULL, *nsecsig = NULL;
	dns_typepair_t sigtype;
	bool active;
	isc_rwlock_t *lock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPZONE((qpzonedb_t *)db));
	INSIST(version == NULL ||
	       ((qpdb_version_t *)version)->qpdb == (qpzonedb_t *)db);

	/*
	 * If the caller didn't supply a version, attach to the current
	 * version.
	 */
	if (version == NULL) {
		currentversion(db, &version);
		close_version = true;
	}

	search = (qpdb_search_t){
		.qpdb = (qpzonedb_t *)db,
		.version = version,
		.serial = ((qpdb_version_t *)version)->serial,
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
	result = dns_qp_lookup(&search.qpr, name, foundname, &search.iter,
			       &search.chain, (void **)&node, NULL);

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
		qpdata_t *n = NULL;
		isc_result_t tresult;

		dns_qpchain_node(&search.chain, i, NULL, (void **)&n, NULL);
		tresult = check_zonecut(n, &search);
		if (tresult != DNS_R_CONTINUE) {
			result = tresult;
			search.chain.len = i - 1;
			node = n;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
	partial_match:
		if (search.zonecut != NULL) {
			result = setup_delegation(
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
		if (node->delegating && ((node != search.qpdb->origin &&
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

	lock = &search.qpdb->node_locks[node->locknum].lock;
	NODE_RDLOCK(lock, &nlocktype);

	found = NULL;
	foundsig = NULL;
	sigtype = DNS_SIGTYPE(type);
	nsecheader = NULL;
	nsecsig = NULL;
	cnamesig = NULL;
	empty_node = true;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		/*
		 * Look for an active, extant rdataset.
		 */
		do {
			if (header->serial <= search.serial && !IGNORE(header))
			{
				if (NONEXISTENT(header)) {
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
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
				newref(search.qpdb, node DNS__DB_FLARG_PASS);
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
				NODE_UNLOCK(lock, &nlocktype);
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
				if (header->type == dns_rdatatype_cname &&
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
			} else if (header->type ==
					   DNS_SIGTYPE(dns_rdatatype_nsec) &&
				   !search.version->havensec3)
			{
				/*
				 * If we need the NSEC rdataset, we'll also
				 * need its signature.
				 */
				nsecsig = header;
			} else if (cname_ok &&
				   header->type ==
					   DNS_SIGTYPE(dns_rdatatype_cname))
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
		 * this node doesn't exist in the desired version, and that
		 * we really have a partial match.
		 */
		if (!wild) {
			NODE_UNLOCK(lock, &nlocktype);
			goto partial_match;
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
			NODE_UNLOCK(lock, &nlocktype);
			result = setup_delegation(
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

			NODE_UNLOCK(lock, &nlocktype);
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
			newref(search.qpdb, node DNS__DB_FLARG_PASS);
			*nodep = node;
		}
		if ((search.version->secure && !search.version->havensec3)) {
			bindrdataset(search.qpdb, node, nsecheader, 0,
				     rdataset DNS__DB_FLARG_PASS);
			if (nsecsig != NULL) {
				bindrdataset(search.qpdb, node, nsecsig, 0,
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
			newref(search.qpdb, node DNS__DB_FLARG_PASS);
		} else {
			search.need_cleanup = false;
		}
		*nodep = node;
	}

	if (type != dns_rdatatype_any) {
		bindrdataset(search.qpdb, node, found, 0,
			     rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(search.qpdb, node, foundsig, 0,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	if (wild) {
		foundname->attributes.wildcard = true;
	}

node_exit:
	NODE_UNLOCK(lock, &nlocktype);

tree_exit:
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
		lock = &(search.qpdb->node_locks[node->locknum].lock);

		NODE_RDLOCK(lock, &nlocktype);
		decref(search.qpdb, node, 0, &nlocktype DNS__DB_FLARG_PASS);
		NODE_UNLOCK(lock, &nlocktype);
	}

	if (close_version) {
		closeversion(db, &version, false DNS__DB_FLARG_PASS);
	}

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source,
	   dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(VALID_QPZONE((qpzonedb_t *)db));
	REQUIRE(targetp != NULL && *targetp == NULL);

	qpdata_t *node = (qpdata_t *)source;
	uint_fast32_t refs = isc_refcount_increment(&node->references);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG) {
	qpzonedb_t *qpdb = (qpzonedb_t *)db;
	qpdata_t *node = NULL;
	bool want_free = false;
	bool inactive = false;
	db_nodelock_t *nodelock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (qpdata_t *)(*targetp);
	nodelock = &qpdb->node_locks[node->locknum];

	NODE_RDLOCK(&nodelock->lock, &nlocktype);
	if (decref(qpdb, node, 0, &nlocktype DNS__DB_FLARG_PASS)) {
		if (isc_refcount_current(&nodelock->references) == 0 &&
		    nodelock->exiting)
		{
			inactive = true;
		}
	}
	NODE_UNLOCK(&nodelock->lock, &nlocktype);

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
	qpdata_t *onode = NULL;

	REQUIRE(VALID_QPZONE(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to the origin node doesn't require a DB lock */
	onode = (qpdata_t *)qpdb->origin;
	INSIST(onode != NULL);
	newref(qpdb, onode DNS__DB_FLARG_PASS);
	*nodep = onode;

	return (ISC_R_SUCCESS);
}

static void
deletedata(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node ISC_ATTR_UNUSED,
	   void *data) {
	dns_slabheader_t *header = data;

	if (header->heap != NULL && header->heap_index != 0) {
		isc_heap_delete(header->heap, header->heap_index);
	}
	header->heap_index = 0;

	if (header->glue_list) {
		freeglue(header->glue_list);
	}
}

static dns_dbmethods_t qpdb_zonemethods = {
	.destroy = qpdb_destroy,
	.beginload = beginload,
	.endload = endload,
	.setloop = setloop,
	.currentversion = currentversion,
	.closeversion = closeversion,
	.findrdataset = findrdataset,
	.findnode = findnode,
	.find = find,
	.attachnode = attachnode,
	.detachnode = detachnode,
	.getoriginnode = getoriginnode,
	.deletedata = deletedata,
};

static void
destroy_qpdata(qpdata_t *data) {
	dns_slabheader_t *current = data->data;
	dns_slabheader_t *next = NULL;

	while (current != NULL) {
		next = current->next;
		dns_slabheader_destroy(&current);
		current = next;
	}

	isc_mem_putanddetach(&data->mctx, data, sizeof(qpdata_t));
}

#if DNS_DB_NODETRACE
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
qp_triename(void *uctx ISC_ATTR_UNUSED, char *buf, size_t size) {
	snprintf(buf, size, "QPDB");
}
