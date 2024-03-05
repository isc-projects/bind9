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

#include <isc/heap.h>
#include <isc/lang.h>
#include <isc/urcu.h>

#include <dns/nsec3.h>
#include <dns/qp.h>
#include <dns/rbt.h>
#include <dns/types.h>

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPDB_MAGIC ISC_MAGIC('Q', 'P', 'D', '4')
#define VALID_QPDB(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPDB_MAGIC)

#define QPDB_HEADERNODE(h) ((dns_rbtnode_t *)((h)->node))

/*
 * Allow clients with a virtual time of up to 5 minutes in the past to see
 * records that would have otherwise have expired.
 */
#define QPDB_VIRTUAL 300

/*****
***** Module Info
*****/

/*! \file
 * \brief
 * DNS QPDB Implementation (minimally adapted from RBTDB)
 */

ISC_LANG_BEGINDECLS

/*%
 * This is the structure that is used for each node in the qp trie of trees.
 * For now it is a copy of the dns_rbtnode structure.
 */
struct dns_qpdata {
	unsigned int magic;
	/*@{*/
	/*!
	 * The following bitfields add up to a total bitwidth of 32.
	 * The range of values necessary for each item is indicated.
	 *
	 * In each case below the "range" indicated is what's _necessary_ for
	 * the bitfield to hold, not what it actually _can_ hold.
	 *
	 * Note: Tree lock must be held before modifying these
	 * bit-fields.
	 *
	 * Note: The two "unsigned int :0;" unnamed bitfields on either
	 * side of the bitfields below are scaffolding that border the
	 * set of bitfields which are accessed after acquiring the tree
	 * lock. Please don't insert any other bitfield members between
	 * the unnamed bitfields unless they should also be accessed
	 * after acquiring the tree lock.
	 */
	unsigned int		   : 0; /* start of bitfields c/o tree lock */
	unsigned int is_root	   : 1; /*%< range is 0..1 */
	unsigned int color	   : 1; /*%< range is 0..1 */
	unsigned int find_callback : 1; /*%< range is 0..1 */
	bool absolute		   : 1; /*%< node with absolute DNS name */
	unsigned int nsec	   : 2; /*%< range is 0..3 */
	unsigned int namelen	   : 8; /*%< range is 1..255 */
	unsigned int offsetlen	   : 8; /*%< range is 1..128 */
	unsigned int oldnamelen	   : 8; /*%< range is 1..255 */
	unsigned int		   : 0; /* end of bitfields c/o tree lock */
	/*@}*/

	/*%
	 * These are needed for hashing. The 'uppernode' points to the
	 * node's superdomain node in the parent subtree, so that it can
	 * be reached from a child that was found by a hash lookup.
	 */
	unsigned int hashval;
	dns_rbtnode_t *uppernode;
	dns_rbtnode_t *hashnext;

	dns_rbtnode_t *parent;
	dns_rbtnode_t *left;
	dns_rbtnode_t *right;
	dns_rbtnode_t *down;

	dns_fixedname_t fn;
	dns_name_t *name;
	isc_mem_t *mctx;

	/*%
	 * Used for LRU cache.  This linked list is used to mark nodes which
	 * have no data any longer, but we cannot unlink at that exact moment
	 * because we did not or could not obtain a write lock on the tree.
	 */
	ISC_LINK(dns_qpdbnode_t) deadlink;

	/*@{*/
	/*!
	 * These values are used in the RBT DB implementation.  The appropriate
	 * node lock must be held before accessing them.
	 *
	 * Note: The two "unsigned int :0;" unnamed bitfields on either
	 * side of the bitfields below are scaffolding that border the
	 * set of bitfields which are accessed after acquiring the node
	 * lock. Please don't insert any other bitfield members between
	 * the unnamed bitfields unless they should also be accessed
	 * after acquiring the node lock.
	 *
	 * NOTE: Do not merge these fields into bitfields above, as
	 * they'll all be put in the same qword that could be accessed
	 * without the node lock as it shares the qword with other
	 * members. Leave these members here so that they occupy a
	 * separate region of memory.
	 */
	void *data;
	uint8_t	      : 0; /* start of bitfields c/o node lock */
	uint8_t dirty : 1;
	uint8_t wild  : 1;
	uint8_t	      : 0; /* end of bitfields c/o node lock */
	uint16_t locknum;  /* note that this is not in the bitfield */
	isc_refcount_t references;
	/*@}*/
};

typedef struct qpdb_changed {
	dns_rbtnode_t *node;
	bool dirty;
	ISC_LINK(struct qpdb_changed) link;
} qpdb_changed_t;

typedef ISC_LIST(qpdb_changed_t) qpdb_changedlist_t;

struct dns_qpdb_version {
	/* Not locked */
	uint32_t serial;
	dns_qpdb_t *qpdb;
	/*
	 * Protected in the refcount routines.
	 * XXXJT: should we change the lock policy based on the refcount
	 * performance?
	 */
	isc_refcount_t references;
	/* Locked by database lock. */
	bool writer;
	bool commit_ok;
	qpdb_changedlist_t changed_list;
	dns_slabheaderlist_t resigned_list;
	ISC_LINK(dns_qpdb_version_t) link;
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

typedef ISC_LIST(dns_qpdb_version_t) qpdb_versionlist_t;

struct dns_qpdb {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;
	/* Locks the tree structure (prevents nodes appearing/disappearing) */
	isc_rwlock_t tree_lock;
	/* Locks for individual tree nodes */
	unsigned int node_lock_count;
	db_nodelock_t *node_locks;
	dns_rbtnode_t *origin_node;
	dns_rbtnode_t *nsec3_origin_node;
	dns_stats_t *rrsetstats;     /* cache DB only */
	isc_stats_t *cachestats;     /* cache DB only */
	isc_stats_t *gluecachestats; /* zone DB only */
	/* Locked by lock. */
	unsigned int active;
	unsigned int attributes;
	uint32_t current_serial;
	uint32_t least_serial;
	uint32_t next_serial;
	dns_qpdb_version_t *current_version;
	dns_qpdb_version_t *future_version;
	qpdb_versionlist_t open_versions;
	isc_loop_t *loop;
	dns_dbnode_t *soanode;
	dns_dbnode_t *nsnode;

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	/*
	 * This is an array of linked lists used to implement the LRU cache.
	 * There will be node_lock_count linked lists here.  Nodes in bucket 1
	 * will be placed on the linked list lru[1].
	 */
	dns_slabheaderlist_t *lru;

	/*
	 * Start point % node_lock_count for next LRU cleanup.
	 */
	atomic_uint lru_sweep;

	/*
	 * When performing LRU cleaning limit cleaning to headers that were
	 * last used at or before this.
	 */
	_Atomic(isc_stdtime_t) last_used;

	/*%
	 * Temporary storage for stale cache nodes and dynamically deleted
	 * nodes that await being cleaned up.
	 */
	dns_rbtnodelist_t *deadnodes;

	/*
	 * Heaps.  These are used for TTL based expiry in a cache,
	 * or for zone resigning in a zone DB.  hmctx is the memory
	 * context to use for the heap (which differs from the main
	 * database memory context in the case of a cache).
	 */
	isc_mem_t *hmctx;
	isc_heap_t **heaps;
	isc_heapcompare_t sooner;

	/* Locked by tree_lock. */
	dns_qp_t *tree;
	dns_qp_t *nsec;
	dns_qp_t *nsec3;

	/* Unlocked */
	unsigned int quantum;
};

/*%
 * Search Context
 */
typedef struct {
	dns_qpdb_t *qpdb;
	dns_qpdb_version_t *rbtversion;
	uint32_t serial;
	unsigned int options;
	dns_rbtnodechain_t chain;
	bool copy_name;
	bool need_cleanup;
	bool wild;
	dns_rbtnode_t *zonecut;
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
} qpdb_load_t;

/*%
 * Prune context
 */
typedef struct {
	dns_db_t *db;
	dns_rbtnode_t *node;
} qpdb_prune_t;

extern dns_dbmethods_t dns__qpdb_zonemethods;
extern dns_dbmethods_t dns__qpdb_cachemethods;

/*
 * Common DB implementation methods shared by both cache and zone RBT
 * databases:
 */

isc_result_t
dns__qpdb_create(isc_mem_t *mctx, const dns_name_t *base, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp);
/*%<
 * Create a new database of type "rbt". Called via dns_db_create();
 * see documentation for that function for more details.
 *
 * If argv[0] is set, it points to a valid memory context to be used for
 * allocation of heap memory.  Generally this is used for cache databases
 * only.
 *
 * Requires:
 *
 * \li argc == 0 or argv[0] is a valid memory context.
 */

void
dns__qpdb_destroy(dns_db_t *arg);
/*%<
 * Implement dns_db_destroy() for RBT databases, see documentation
 * for that function for more details.
 */

void
dns__qpdb_currentversion(dns_db_t *db, dns_dbversion_t **versionp);
isc_result_t
dns__qpdb_newversion(dns_db_t *db, dns_dbversion_t **versionp);
void
dns__qpdb_attachversion(dns_db_t *db, dns_dbversion_t *source,
			dns_dbversion_t **targetp);
void
dns__qpdb_closeversion(dns_db_t *db, dns_dbversion_t **versionp,
		       bool commit DNS__DB_FLARG);
/*%<
 * Implement the dns_db_currentversion(), _newversion(),
 * _attachversion() and _closeversion() methods for RBT databases;
 * see documentation of those functions for more details.
 */

isc_result_t
dns__qpdb_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		   dns_dbnode_t **nodep DNS__DB_FLARG);
isc_result_t
dns__qpdb_findnodeintree(dns_qpdb_t *qpdb, dns_qp_t *tree,
			 const dns_name_t *name, bool create,
			 dns_dbnode_t **nodep DNS__DB_FLARG);
/*%<
 * Implement the dns_db_findnode() and _findnodeintree() methods for
 * RBT databases; see documentation of those functions for more details.
 */

void
dns__qpdb_attachnode(dns_db_t *db, dns_dbnode_t *source,
		     dns_dbnode_t **targetp DNS__DB_FLARG);
void
dns__qpdb_detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG);
/*%<
 * Implement the dns_db_attachnode() and _detachnode() methods for
 * RBT databases; see documentation of those functions for more details.
 */

isc_result_t
dns__qpdb_createiterator(dns_db_t *db, unsigned int options,
			 dns_dbiterator_t **iteratorp);
/*%<
 * Implement dns_db_createiterator() for RBT databases; see documentation of
 * that function for more details.
 */

isc_result_t
dns__qpdb_allrdatasets(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, unsigned int options,
		       isc_stdtime_t now,
		       dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
/*%<
 * Implement dns_db_allrdatasets() for RBT databases; see documentation of
 * that function for more details.
 */
isc_result_t
dns__qpdb_addrdataset(dns_db_t *db, dns_dbnode_t *node,
		      dns_dbversion_t *version, isc_stdtime_t now,
		      dns_rdataset_t *rdataset, unsigned int options,
		      dns_rdataset_t *addedrdataset DNS__DB_FLARG);
isc_result_t
dns__qpdb_subtractrdataset(dns_db_t *db, dns_dbnode_t *node,
			   dns_dbversion_t *version, dns_rdataset_t *rdataset,
			   unsigned int options,
			   dns_rdataset_t *newrdataset DNS__DB_FLARG);
isc_result_t
dns__qpdb_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
			 dns_dbversion_t *version, dns_rdatatype_t type,
			 dns_rdatatype_t covers DNS__DB_FLARG);
/*%<
 * Implement the dns_db_addrdataset(), _subtractrdataset() and
 * _deleterdataset() methods for RBT databases; see documentation of
 * those functions for more details.
 */

unsigned int
dns__qpdb_nodecount(dns_db_t *db, dns_dbtree_t tree);
/*%<
 * Implement dns_db_nodecount() for RBT databases; see documentation of
 * that function for more details.
 */

void
dns__qpdb_setloop(dns_db_t *db, isc_loop_t *loop);
/*%<
 * Implement dns_db_setloop() for RBT databases; see documentation of
 * that function for more details.
 */

isc_result_t
dns__qpdb_getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG);
/*%<
 * Implement dns_db_getoriginnode() for RBT databases; see documentation of
 * that function for more details.
 */

void
dns__qpdb_deletedata(dns_db_t *db ISC_ATTR_UNUSED,
		     dns_dbnode_t *node ISC_ATTR_UNUSED, void *data);
/*%<
 * Implement dns_db_deletedata() for RBT databases; see documentation of
 * that function for more details.
 */

void
dns__qpdb_locknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type);
void
dns__qpdb_unlocknode(dns_db_t *db, dns_dbnode_t *node, isc_rwlocktype_t type);
/*%<
 * Implement the dns_db_locknode() and _unlocknode() methods for
 * RBT databases; see documentation of those functions for more details.
 */

/*%
 * Functions used for the RBT implementation which are defined and
 * used in qpdb.c but may also be called from rbt-zonedb.c or
 * rbt-cachedb.c:
 */
void
dns__qpdb_bindrdataset(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
		       dns_slabheader_t *header, isc_stdtime_t now,
		       isc_rwlocktype_t locktype,
		       dns_rdataset_t *rdataset DNS__DB_FLARG);

isc_result_t
dns__qpdb_nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name);

void
dns__qpdb_freeglue(dns_glue_t *glue_list);

void
dns__qpdb_newref(dns_qpdb_t *qpdb, dns_rbtnode_t *node,
		 isc_rwlocktype_t locktype DNS__DB_FLARG);
/*%<
 * Increment the reference counter to a node in an RBT database.
 * If the caller holds a node lock then its lock type is specified
 * as 'locktype'. If the node is write-locked, then the node can
 * be removed from the dead nodes list. If not, the list can be
 * cleaned up later.
 */

bool
dns__qpdb_decref(dns_qpdb_t *qpdb, dns_rbtnode_t *node, uint32_t least_serial,
		 isc_rwlocktype_t *nlocktypep, isc_rwlocktype_t *tlocktypep,
		 bool tryupgrade, bool pruning DNS__DB_FLARG);
/*%<
 * Decrement the reference counter to a node in an RBT database.
 * 'nlocktypep' and 'tlocktypep' are pointers to the current status
 * of the node lock and tree lock.
 *
 * If references go to 0, the node will be cleaned up, which may
 * necessitate upgrading the locks.
 */

isc_result_t
dns__qpdb_add(dns_qpdb_t *qpdb, dns_rbtnode_t *rbtnode,
	      const dns_name_t *nodename, dns_qpdb_version_t *rbtversion,
	      dns_slabheader_t *newheader, unsigned int options, bool loading,
	      dns_rdataset_t *addedrdataset, isc_stdtime_t now DNS__DB_FLARG);
/*%<
 * Add a slab header 'newheader' to a node in an RBT database.
 * The caller must have the node write-locked.
 */

void
dns__qpdb_setsecure(dns_db_t *db, dns_qpdb_version_t *version,
		    dns_dbnode_t *origin);
/*%<
 * Update the secure status for an RBT database version 'version'.
 * The version will be marked secure if it is fully signed and
 * and contains a complete NSEC/NSEC3 chain.
 */

void
dns__qpdb_mark(dns_slabheader_t *header, uint_least16_t flag);
/*%<
 * Set attribute 'flag' in a slab header 'header' - for example,
 * DNS_SLABHEADERATTR_STALE or DNS_SLABHEADERATTR_ANCIENT - and,
 * in a cache database, update the rrset stats accordingly.
 */

void
dns__qpdb_setttl(dns_slabheader_t *header, dns_ttl_t newttl);
/*%<
 * Set the TTL in a slab header 'header'. In a cache database,
 * also update the TTL heap accordingly.
 */

/*
 * Functions specific to zone databases that are also called from qpdb.c.
 */
void
dns__qpzone_resigninsert(dns_qpdb_t *qpdb, int idx,
			 dns_slabheader_t *newheader);
void
dns__qpzone_resigndelete(dns_qpdb_t *qpdb, dns_qpdb_version_t *version,
			 dns_slabheader_t *header DNS__DB_FLARG);
/*%<
 * Insert/delete a node from the zone database's resigning heap.
 */

isc_result_t
dns__qpzone_wildcardmagic(dns_qpdb_t *qpdb, const dns_name_t *name, bool lock);
/*%<
 * Add the necessary magic for the wildcard name 'name'
 * to be found in 'qpdb'.
 *
 * In order for wildcard matching to work correctly in
 * zone_find(), we must ensure that a node for the wildcarding
 * level exists in the database, and has its 'find_callback'
 * and 'wild' bits set.
 *
 * E.g. if the wildcard name is "*.sub.example." then we
 * must ensure that "sub.example." exists and is marked as
 * a wildcard level.
 *
 * The tree must be write-locked.
 */
isc_result_t
dns__qpzone_addwildcards(dns_qpdb_t *qpdb, const dns_name_t *name, bool lock);
/*%<
 * If 'name' is or contains a wildcard name, create a node for it in the
 * database. The tree must be write-locked.
 */

/*
 * Cache-specific functions that are called from qpdb.c
 */
void
dns__qpcache_expireheader(dns_slabheader_t *header,
			  isc_rwlocktype_t *tlocktypep,
			  dns_expire_t reason DNS__DB_FLARG);
void
dns__qpcache_overmem(dns_qpdb_t *qpdb, dns_slabheader_t *newheader,
		     isc_rwlocktype_t *tlocktypep DNS__DB_FLARG);

/*
 * Create a new qpdata node.
 */
dns_qpdata_t *
dns_qpdata_create(dns_qpdb_t *qpdb, const dns_name_t *name);

/*
 * Destroy a qpdata node.
 */
void
dns_qpdata_destroy(dns_qpdata_t *qpdata);

#ifdef DNS_DB_NODETRACE
#define dns_qpdata_ref(ptr) dns_qpdata__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_qpdata_unref(ptr) \
	dns_qpdata__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_qpdata_attach(ptr, ptrp) \
	dns_qpdata__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_qpdata_detach(ptrp) \
	dns_qpdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_qpdata);
#else
ISC_REFCOUNT_DECL(dns_qpdata);
#endif

ISC_LANG_ENDDECLS
