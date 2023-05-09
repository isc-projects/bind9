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

#include <isc/lang.h>

#include <dns/types.h>

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define RBTDB_MAGIC ISC_MAGIC('R', 'B', 'D', '4')
#define VALID_RBTDB(rbtdb) \
	((rbtdb) != NULL && (rbtdb)->common.impmagic == RBTDB_MAGIC)

#define RBTDB_RDATATYPE_SIGNSEC \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_nsec)
#define RBTDB_RDATATYPE_SIGNSEC3 \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_nsec3)
#define RBTDB_RDATATYPE_SIGNS \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_ns)
#define RBTDB_RDATATYPE_SIGCNAME \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_cname)
#define RBTDB_RDATATYPE_SIGDNAME \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_dname)
#define RBTDB_RDATATYPE_SIGDS \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_ds)
#define RBTDB_RDATATYPE_SIGSOA \
	DNS_TYPEPAIR_VALUE(dns_rdatatype_rrsig, dns_rdatatype_soa)
#define RBTDB_RDATATYPE_NCACHEANY DNS_TYPEPAIR_VALUE(0, dns_rdatatype_any)

#define RBTDB_INITLOCK(l)    isc_rwlock_init((l))
#define RBTDB_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define RBTDB_LOCK(l, t)     RWLOCK((l), (t))
#define RBTDB_UNLOCK(l, t)   RWUNLOCK((l), (t))

#ifdef DNS_RBTDB_STRONG_RWLOCK_CHECK
#define STRONG_RWLOCK_CHECK(cond) REQUIRE(cond)
#else
#define STRONG_RWLOCK_CHECK(cond)
#endif

#define NODE_INITLOCK(l)    isc_rwlock_init((l))
#define NODE_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define NODE_LOCK(l, t, tp)                                      \
	{                                                        \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_none); \
		RWLOCK((l), (t));                                \
		*tp = t;                                         \
	}
#define NODE_UNLOCK(l, tp)                                       \
	{                                                        \
		STRONG_RWLOCK_CHECK(*tp != isc_rwlocktype_none); \
		RWUNLOCK(l, *tp);                                \
		*tp = isc_rwlocktype_none;                       \
	}
#define NODE_RDLOCK(l, tp) NODE_LOCK(l, isc_rwlocktype_read, tp);
#define NODE_WRLOCK(l, tp) NODE_LOCK(l, isc_rwlocktype_write, tp);
#define NODE_TRYLOCK(l, t, tp)                                   \
	({                                                       \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_none); \
		isc_result_t _result = isc_rwlock_trylock(l, t); \
		if (_result == ISC_R_SUCCESS) {                  \
			*tp = t;                                 \
		};                                               \
		_result;                                         \
	})
#define NODE_TRYRDLOCK(l, tp) NODE_TRYLOCK(l, isc_rwlocktype_read, tp)
#define NODE_TRYWRLOCK(l, tp) NODE_TRYLOCK(l, isc_rwlocktype_write, tp)
#define NODE_TRYUPGRADE(l, tp)                                   \
	({                                                       \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_read); \
		isc_result_t _result = isc_rwlock_tryupgrade(l); \
		if (_result == ISC_R_SUCCESS) {                  \
			*tp = isc_rwlocktype_write;              \
		};                                               \
		_result;                                         \
	})
#define NODE_FORCEUPGRADE(l, tp)                       \
	if (NODE_TRYUPGRADE(l, tp) != ISC_R_SUCCESS) { \
		NODE_UNLOCK(l, tp);                    \
		NODE_WRLOCK(l, tp);                    \
	}

#define TREE_INITLOCK(l)    isc_rwlock_init(l)
#define TREE_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define TREE_LOCK(l, t, tp)                                      \
	{                                                        \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_none); \
		RWLOCK(l, t);                                    \
		*tp = t;                                         \
	}
#define TREE_UNLOCK(l, tp)                                       \
	{                                                        \
		STRONG_RWLOCK_CHECK(*tp != isc_rwlocktype_none); \
		RWUNLOCK(l, *tp);                                \
		*tp = isc_rwlocktype_none;                       \
	}
#define TREE_RDLOCK(l, tp) TREE_LOCK(l, isc_rwlocktype_read, tp);
#define TREE_WRLOCK(l, tp) TREE_LOCK(l, isc_rwlocktype_write, tp);
#define TREE_TRYLOCK(l, t, tp)                                   \
	({                                                       \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_none); \
		isc_result_t _result = isc_rwlock_trylock(l, t); \
		if (_result == ISC_R_SUCCESS) {                  \
			*tp = t;                                 \
		};                                               \
		_result;                                         \
	})
#define TREE_TRYRDLOCK(l, tp) TREE_TRYLOCK(l, isc_rwlocktype_read, tp)
#define TREE_TRYWRLOCK(l, tp) TREE_TRYLOCK(l, isc_rwlocktype_write, tp)
#define TREE_TRYUPGRADE(l, tp)                                   \
	({                                                       \
		STRONG_RWLOCK_CHECK(*tp == isc_rwlocktype_read); \
		isc_result_t _result = isc_rwlock_tryupgrade(l); \
		if (_result == ISC_R_SUCCESS) {                  \
			*tp = isc_rwlocktype_write;              \
		};                                               \
		_result;                                         \
	})
#define TREE_FORCEUPGRADE(l, tp)                       \
	if (TREE_TRYUPGRADE(l, tp) != ISC_R_SUCCESS) { \
		TREE_UNLOCK(l, tp);                    \
		TREE_WRLOCK(l, tp);                    \
	}
/*****
***** Module Info
*****/

/*! \file
 * \brief
 * DNS Red-Black Tree DB Implementation
 */

ISC_LANG_BEGINDECLS

extern dns_dbmethods_t dns__rbtdb_zonemethods;
extern dns_dbmethods_t dns__rbtdb_cachemethods;

isc_result_t
dns__rbtdb_create(isc_mem_t *mctx, const dns_name_t *base, dns_dbtype_t type,
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
dns__rbtdb_destroy(dns_db_t *arg);

void
dns__rbtdb_currentversion(dns_db_t *db, dns_dbversion_t **versionp);

isc_result_t
dns__rbtdb_newversion(dns_db_t *db, dns_dbversion_t **versionp);

void
dns__rbtdb_attachversion(dns_db_t *db, dns_dbversion_t *source,
			 dns_dbversion_t **targetp);

void
dns__rbtdb_closeversion(dns_db_t *db, dns_dbversion_t **versionp,
			bool commit DNS__DB_FLARG);

isc_result_t
dns__rbtdb_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		    dns_dbnode_t **nodep DNS__DB_FLARG);

void
dns__rbtdb_attachnode(dns_db_t *db, dns_dbnode_t *source,
		      dns_dbnode_t **targetp DNS__DB_FLARG);
void
dns__rbtdb_detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG);

isc_result_t
dns__rbtdb_createiterator(dns_db_t *db, unsigned int options,
			  dns_dbiterator_t **iteratorp);

isc_result_t
dns__rbtdb_allrdatasets(dns_db_t *db, dns_dbnode_t *node,
			dns_dbversion_t *version, unsigned int options,
			isc_stdtime_t now,
			dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);

isc_result_t
dns__rbtdb_addrdataset(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, isc_stdtime_t now,
		       dns_rdataset_t *rdataset, unsigned int options,
		       dns_rdataset_t *addedrdataset DNS__DB_FLARG);

isc_result_t
dns__rbtdb_subtractrdataset(dns_db_t *db, dns_dbnode_t *node,
			    dns_dbversion_t *version, dns_rdataset_t *rdataset,
			    unsigned int options,
			    dns_rdataset_t *newrdataset DNS__DB_FLARG);

isc_result_t
dns__rbtdb_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
			  dns_dbversion_t *version, dns_rdatatype_t type,
			  dns_rdatatype_t covers DNS__DB_FLARG);

unsigned int
dns__rbtdb_nodecount(dns_db_t *db, dns_dbtree_t tree);

void
dns__rbtdb_setloop(dns_db_t *db, isc_loop_t *loop);

isc_result_t
dns__rbtdb_getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG);

void
dns__rbtdb_bindrdataset(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
			dns_slabheader_t *header, isc_stdtime_t now,
			isc_rwlocktype_t locktype,
			dns_rdataset_t *rdataset DNS__DB_FLARG);

void
dns__rbtdb_expireheader(dns_rbtdb_t *rbtdb, dns_slabheader_t *header,
			isc_rwlocktype_t *nlocktypep,
			isc_rwlocktype_t *tlocktypep,
			dns_expire_t reason DNS__DB_FLARG);
ISC_LANG_ENDDECLS
