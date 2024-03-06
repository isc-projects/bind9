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

/*%
 * Whether to rate-limit updating the LRU to avoid possible thread contention.
 * Updating LRU requires write locking, so we don't do it every time the
 * record is touched - only after some time passes.
 */
#ifndef DNS_QPDB_LIMITLRUUPDATE
#define DNS_QPDB_LIMITLRUUPDATE 1
#endif

/*% Time after which we update LRU for glue records, 5 minutes */
#define DNS_QPDB_LRUUPDATE_GLUE 300
/*% Time after which we update LRU for all other records, 10 minutes */
#define DNS_QPDB_LRUUPDATE_REGULAR 600

#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) == 0)
#define NONEXISTENT(header)                            \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NXDOMAIN) != 0)
#define STALE(header)                                  \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE) != 0)
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NEGATIVE) != 0)
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

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

/*%
 * Routines for LRU-based cache management.
 */

/*%
 * See if a given cache entry that is being reused needs to be updated
 * in the LRU-list.  From the LRU management point of view, this function is
 * expected to return true for almost all cases.  When used with threads,
 * however, this may cause a non-negligible performance penalty because a
 * writer lock will have to be acquired before updating the list.
 * If DNS_QPDB_LIMITLRUUPDATE is defined to be non 0 at compilation time, this
 * function returns true if the entry has not been updated for some period of
 * time.  We differentiate the NS or glue address case and the others since
 * experiments have shown that the former tends to be accessed relatively
 * infrequently and the cost of cache miss is higher (e.g., a missing NS records
 * may cause external queries at a higher level zone, involving more
 * transactions).
 *
 * Caller must hold the node (read or write) lock.
 */
static bool
need_headerupdate(dns_slabheader_t *header, isc_stdtime_t now) {
	if (DNS_SLABHEADER_GETATTR(header, (DNS_SLABHEADERATTR_NONEXISTENT |
					    DNS_SLABHEADERATTR_ANCIENT |
					    DNS_SLABHEADERATTR_ZEROTTL)) != 0)
	{
		return (false);
	}

#if DNS_QPDB_LIMITLRUUPDATE
	if (header->type == dns_rdatatype_ns ||
	    (header->trust == dns_trust_glue &&
	     (header->type == dns_rdatatype_a ||
	      header->type == dns_rdatatype_aaaa)))
	{
		/*
		 * Glue records are updated if at least DNS_QPDB_LRUUPDATE_GLUE
		 * seconds have passed since the previous update time.
		 */
		return (header->last_used + DNS_QPDB_LRUUPDATE_GLUE <= now);
	}

	/*
	 * Other records are updated if DNS_QPDB_LRUUPDATE_REGULAR seconds
	 * have passed.
	 */
	return (header->last_used + DNS_QPDB_LRUUPDATE_REGULAR <= now);
#else
	UNUSED(now);

	return (true);
#endif /* if DNS_QPDB_LIMITLRUUPDATE */
}

/*%
 * Update the timestamp of a given cache entry and move it to the head
 * of the corresponding LRU list.
 *
 * Caller must hold the node (write) lock.
 *
 * Note that the we do NOT touch the heap here, as the TTL has not changed.
 */
static void
update_header(dns_qpdb_t *qpdb, dns_slabheader_t *header, isc_stdtime_t now) {
	INSIST(IS_CACHE(qpdb));

	/* To be checked: can we really assume this? XXXMLG */
	INSIST(ISC_LINK_LINKED(header, link));

	ISC_LIST_UNLINK(qpdb->lru[QPDB_HEADERNODE(header)->locknum], header,
			link);
	header->last_used = now;
	ISC_LIST_PREPEND(qpdb->lru[QPDB_HEADERNODE(header)->locknum], header,
			 link);
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

/*
 * Deleting Nodes
 *
 * For zone databases the node for the origin of the zone MUST NOT be deleted.
 */

/*
 * DB Routines
 */

static void
update_cachestats(dns_qpdb_t *qpdb, isc_result_t result) {
	INSIST(IS_CACHE(qpdb));

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
clean_stale_headers(dns_slabheader_t *top) {
	dns_slabheader_t *d = NULL, *down_next = NULL;

	for (d = top->down; d != NULL; d = down_next) {
		down_next = d->down;
		dns_slabheader_destroy(&d);
	}
	top->down = NULL;
}

static isc_result_t
setup_delegation(qpdb_search_t *search, dns_dbnode_t **nodep,
		 dns_name_t *foundname, dns_rdataset_t *rdataset,
		 dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_name_t *zcname = NULL;
	dns_typepair_t type;
	dns_qpdata_t *node = NULL;

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
		dns__qpdb_bindrdataset(
			search->qpdb, node, search->zonecut_header, search->now,
			isc_rwlocktype_read, rdataset DNS__DB_FLARG_PASS);
		if (sigrdataset != NULL && search->zonecut_sigheader != NULL) {
			dns__qpdb_bindrdataset(search->qpdb, node,
					       search->zonecut_sigheader,
					       search->now, isc_rwlocktype_read,
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

static bool
check_stale_header(dns_qpdata_t *node, dns_slabheader_t *header,
		   isc_rwlocktype_t *nlocktypep, isc_rwlock_t *lock,
		   qpdb_search_t *search, dns_slabheader_t **header_prev) {
	if (!ACTIVE(header, search->now)) {
		dns_ttl_t stale = header->ttl + STALE_TTL(header, search->qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_STALE_WINDOW);
		if (!ZEROTTL(header) && KEEPSTALE(search->qpdb) &&
		    stale > search->now)
		{
			dns__qpdb_mark(header, DNS_SLABHEADERATTR_STALE);
			*header_prev = header;
			/*
			 * If DNS_DBFIND_STALESTART is set then it means we
			 * failed to resolve the name during recursion, in
			 * this case we mark the time in which the refresh
			 * failed.
			 */
			if ((search->options & DNS_DBFIND_STALESTART) != 0) {
				atomic_store_release(
					&header->last_refresh_fail_ts,
					search->now);
			} else if ((search->options &
				    DNS_DBFIND_STALEENABLED) != 0 &&
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
				DNS_SLABHEADER_SETATTR(
					header,
					DNS_SLABHEADERATTR_STALE_WINDOW);
				return (false);
			} else if ((search->options &
				    DNS_DBFIND_STALETIMEOUT) != 0)
			{
				/*
				 * We want stale RRset due to timeout, so we
				 * don't skip it.
				 */
				return (false);
			}
			return ((search->options & DNS_DBFIND_STALEOK) == 0);
		}

		/*
		 * This rdataset is stale.  If no one else is using the
		 * node, we can clean it up right now, otherwise we mark
		 * it as ancient, and the node as dirty, so it will get
		 * cleaned up later.
		 */
		if ((header->ttl < search->now - QPDB_VIRTUAL) &&
		    (*nlocktypep == isc_rwlocktype_write ||
		     NODE_TRYUPGRADE(lock, nlocktypep) == ISC_R_SUCCESS))
		{
			/*
			 * We update the node's status only when we can
			 * get write access; otherwise, we leave others
			 * to this work.  Periodical cleaning will
			 * eventually take the job as the last resort.
			 * We won't downgrade the lock, since other
			 * rdatasets are probably stale, too.
			 */

			if (isc_refcount_current(&node->references) == 0) {
				/*
				 * header->down can be non-NULL if the
				 * refcount has just decremented to 0
				 * but dns__qpdb_decref() has not
				 * performed clean_cache_node(), in
				 * which case we need to purge the stale
				 * headers first.
				 */
				clean_stale_headers(header);
				if (*header_prev != NULL) {
					(*header_prev)->next = header->next;
				} else {
					node->data = header->next;
				}
				dns_slabheader_destroy(&header);
			} else {
				dns__qpdb_mark(header,
					       DNS_SLABHEADERATTR_ANCIENT);
				QPDB_HEADERNODE(header)->dirty = 1;
				*header_prev = header;
			}
		} else {
			*header_prev = header;
		}
		return (true);
	}
	return (false);
}

static isc_result_t
check_zonecut(dns_qpdata_t *node, void *arg DNS__DB_FLARG) {
	qpdb_search_t *search = arg;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *dname_header = NULL, *sigdname_header = NULL;
	isc_result_t result;
	isc_rwlock_t *lock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(search->zonecut == NULL);

	lock = &(search->qpdb->node_locks[node->locknum].lock);
	NODE_RDLOCK(lock, &nlocktype);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &nlocktype, lock, search,
				       &header_prev))
		{
			/* Do nothing. */
		} else if (header->type == dns_rdatatype_dname &&
			   EXISTS(header) && !ANCIENT(header))
		{
			dname_header = header;
			header_prev = header;
		} else if (header->type == DNS_SIGTYPE(dns_rdatatype_dname) &&
			   EXISTS(header) && !ANCIENT(header))
		{
			sigdname_header = header;
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (dname_header != NULL &&
	    (!DNS_TRUST_PENDING(dname_header->trust) ||
	     (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_header will still be valid later.
		 */
		dns__qpdb_newref(search->qpdb, node,
				 nlocktype DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = dname_header;
		search->zonecut_sigheader = sigdname_header;
		search->need_cleanup = true;
		result = DNS_R_PARTIALMATCH;
	} else {
		result = DNS_R_CONTINUE;
	}

	NODE_UNLOCK(lock, &nlocktype);

	return (result);
}

static isc_result_t
find_deepest_zonecut(qpdb_search_t *search, dns_qpdata_t *node,
		     dns_dbnode_t **nodep, dns_name_t *foundname,
		     dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_result_t result = ISC_R_NOTFOUND;
	dns_qpdb_t *qpdb = NULL;

	/*
	 * Caller must be holding the tree lock.
	 */

	qpdb = search->qpdb;

	for (int i = dns_qpchain_length(&search->chain) - 1; i >= 0; i--) {
		dns_slabheader_t *header = NULL;
		dns_slabheader_t *header_prev = NULL, *header_next = NULL;
		dns_slabheader_t *found = NULL, *foundsig = NULL;
		isc_rwlock_t *lock = NULL;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

		dns_qpchain_node(&search->chain, i, NULL, (void **)&node, NULL);
		lock = &qpdb->node_locks[node->locknum].lock;

		NODE_RDLOCK(lock, &nlocktype);

		/*
		 * Look for NS and RRSIG NS rdatasets.
		 */
		for (header = node->data; header != NULL; header = header_next)
		{
			header_next = header->next;
			if (check_stale_header(node, header, &nlocktype, lock,
					       search, &header_prev))
			{
				/* Do nothing. */
			} else if (EXISTS(header) && !ANCIENT(header)) {
				/*
				 * We've found an extant rdataset.  See if
				 * we're interested in it.
				 */
				if (header->type == dns_rdatatype_ns) {
					found = header;
					if (foundsig != NULL) {
						break;
					}
				} else if (header->type ==
					   DNS_SIGTYPE(dns_rdatatype_ns))
				{
					foundsig = header;
					if (found != NULL) {
						break;
					}
				}
				header_prev = header;
			} else {
				header_prev = header;
			}
		}

		if (found != NULL) {
			/*
			 * If we have to set foundname, we do it before
			 * anything else.
			 */
			if (foundname != NULL) {
				dns_name_copy(node->name, foundname);
			}
			result = DNS_R_DELEGATION;
			if (nodep != NULL) {
				dns__qpdb_newref(search->qpdb, node,
						 nlocktype DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			dns__qpdb_bindrdataset(search->qpdb, node, found,
					       search->now, nlocktype,
					       rdataset DNS__DB_FLARG_PASS);
			if (foundsig != NULL) {
				dns__qpdb_bindrdataset(
					search->qpdb, node, foundsig,
					search->now, nlocktype,
					sigrdataset DNS__DB_FLARG_PASS);
			}
			if (need_headerupdate(found, search->now) ||
			    (foundsig != NULL &&
			     need_headerupdate(foundsig, search->now)))
			{
				if (nlocktype != isc_rwlocktype_write) {
					NODE_FORCEUPGRADE(lock, &nlocktype);
					POST(nlocktype);
				}
				if (need_headerupdate(found, search->now)) {
					update_header(search->qpdb, found,
						      search->now);
				}
				if (foundsig != NULL &&
				    need_headerupdate(foundsig, search->now))
				{
					update_header(search->qpdb, foundsig,
						      search->now);
				}
			}
		}

		NODE_UNLOCK(lock, &nlocktype);

		if (found != NULL) {
			break;
		}
	}

	return (result);
}

/*
 * Look for a potentially covering NSEC in the cache where `name`
 * is known not to exist.  This uses the auxiliary NSEC tree to find
 * the potential NSEC owner. If found, we update 'foundname', 'nodep',
 * 'rdataset' and 'sigrdataset', and return DNS_R_COVERINGNSEC.
 * Otherwise, return ISC_R_NOTFOUND.
 */
static isc_result_t
find_coveringnsec(qpdb_search_t *search, const dns_name_t *name,
		  dns_dbnode_t **nodep, isc_stdtime_t now,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_fixedname_t fpredecessor, fixed;
	dns_name_t *predecessor = NULL, *fname = NULL;
	dns_qpdata_t *node = NULL;
	dns_qpiter_t iter;
	isc_result_t result;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *lock = NULL;
	dns_typepair_t matchtype, sigmatchtype;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_next = NULL, *header_prev = NULL;

	/*
	 * Look for the node in the auxilary tree.
	 */
	result = dns_qp_lookup(search->qpdb->nsec, name, NULL, &iter, NULL,
			       (void **)&node, NULL);
	if (result != DNS_R_PARTIALMATCH) {
		return (ISC_R_NOTFOUND);
	}

	fname = dns_fixedname_initname(&fixed);
	predecessor = dns_fixedname_initname(&fpredecessor);
	matchtype = DNS_TYPEPAIR_VALUE(dns_rdatatype_nsec, 0);
	sigmatchtype = DNS_SIGTYPE(dns_rdatatype_nsec);

	/*
	 * Extract predecessor from iterator.
	 */
	result = dns_qpiter_current(&iter, predecessor, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		return (ISC_R_NOTFOUND);
	}

	/*
	 * Lookup the predecessor in the main tree.
	 */
	node = NULL;
	result = dns_qp_lookup(search->qpdb->tree, predecessor, fname, NULL,
			       NULL, (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_NOTFOUND);
	}

	lock = &(search->qpdb->node_locks[node->locknum].lock);
	NODE_RDLOCK(lock, &nlocktype);
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &nlocktype, lock, search,
				       &header_prev))
		{
			continue;
		}
		if (NONEXISTENT(header) || DNS_TYPEPAIR_TYPE(header->type) == 0)
		{
			header_prev = header;
			continue;
		}
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
		header_prev = header;
	}
	if (found != NULL) {
		dns__qpdb_bindrdataset(search->qpdb, node, found, now,
				       nlocktype, rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			dns__qpdb_bindrdataset(search->qpdb, node, foundsig,
					       now, nlocktype,
					       sigrdataset DNS__DB_FLARG_PASS);
		}
		dns__qpdb_newref(search->qpdb, node,
				 nlocktype DNS__DB_FLARG_PASS);

		dns_name_copy(fname, foundname);

		*nodep = node;
		result = DNS_R_COVERINGNSEC;
	} else {
		result = ISC_R_NOTFOUND;
	}
	NODE_UNLOCK(lock, &nlocktype);
	return (result);
}

static isc_result_t
cache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	   dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	   dns_dbnode_t **nodep, dns_name_t *foundname,
	   dns_rdataset_t *rdataset,
	   dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_qpdata_t *node = NULL;
	isc_result_t result;
	qpdb_search_t search;
	bool cname_ok = true;
	bool found_noqname = false;
	bool all_negative = true;
	bool empty_node;
	isc_rwlock_t *lock = NULL;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *nsheader = NULL;
	dns_slabheader_t *foundsig = NULL, *nssig = NULL, *cnamesig = NULL;
	dns_slabheader_t *update = NULL, *updatesig = NULL;
	dns_slabheader_t *nsecheader = NULL, *nsecsig = NULL;
	dns_typepair_t sigtype, negtype;

	UNUSED(version);

	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));
	REQUIRE(version == NULL);

	if (now == 0) {
		now = isc_stdtime_now();
	}

	search = (qpdb_search_t){
		.qpdb = (dns_qpdb_t *)db,
		.serial = 1,
		.options = options,
		.now = now,
	};
	dns_fixedname_init(&search.zonecut_name);

	TREE_RDLOCK(&search.qpdb->tree_lock, &tlocktype);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(search.qpdb->tree, name, foundname, NULL,
			       &search.chain, (void **)&node, NULL);

	/*
	 * Check the QP chain to see if there's a node above us with a
	 * active DNAME or NS rdatasets.
	 *
	 * We're only interested in nodes above QNAME, so if the result
	 * was success, then we skip the last item in the chain.
	 */
	unsigned int len = dns_qpchain_length(&search.chain);
	if (result == ISC_R_SUCCESS) {
		len--;
	}

	for (unsigned int i = 0; i < len; i++) {
		isc_result_t zcresult;
		dns_qpdata_t *encloser = NULL;

		dns_qpchain_node(&search.chain, i, NULL, (void **)&encloser,
				 NULL);

		if (encloser->find_callback) {
			zcresult = check_zonecut(
				encloser, (void *)&search DNS__DB_FLARG_PASS);
			if (zcresult != DNS_R_CONTINUE) {
				result = DNS_R_PARTIALMATCH;
				search.chain.len = i - 1;
				node = encloser;
				break;
			}
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		/*
		 * If we discovered a covering DNAME skip looking for a covering
		 * NSEC.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    (search.zonecut_header == NULL ||
		     search.zonecut_header->type != dns_rdatatype_dname))
		{
			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		if (search.zonecut != NULL) {
			result = setup_delegation(
				&search, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		} else {
		find_ns:
			result = find_deepest_zonecut(
				&search, node, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		}
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
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

	lock = &(search.qpdb->node_locks[node->locknum].lock);
	NODE_RDLOCK(lock, &nlocktype);

	/*
	 * These pointers need to be reset here in case we did
	 * 'goto find_ns' from somewhere below.
	 */
	found = NULL;
	foundsig = NULL;
	sigtype = DNS_SIGTYPE(type);
	negtype = DNS_TYPEPAIR_VALUE(0, type);
	nsheader = NULL;
	nsecheader = NULL;
	nssig = NULL;
	nsecsig = NULL;
	cnamesig = NULL;
	empty_node = true;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &nlocktype, lock, &search,
				       &header_prev))
		{
			/* Do nothing. */
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * We now know that there is at least one active
			 * non-stale rdataset at this node.
			 */
			empty_node = false;
			if (header->noqname != NULL &&
			    header->trust == dns_trust_secure)
			{
				found_noqname = true;
			}
			if (!NEGATIVE(header)) {
				all_negative = false;
			}

			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == type ||
			    (type == dns_rdatatype_any &&
			     DNS_TYPEPAIR_TYPE(header->type) != 0) ||
			    (cname_ok && header->type == dns_rdatatype_cname))
			{
				/*
				 * We've found the answer.
				 */
				found = header;
				if (header->type == dns_rdatatype_cname &&
				    cname_ok)
				{
					/*
					 * If we've already got the
					 * CNAME RRSIG, use it.
					 */
					if (cnamesig != NULL) {
						foundsig = cnamesig;
					} else {
						sigtype = DNS_SIGTYPE(
							dns_rdatatype_cname);
					}
				}
			} else if (header->type == sigtype) {
				/*
				 * We've found the RRSIG rdataset for our
				 * target type.  Remember it.
				 */
				foundsig = header;
			} else if (header->type == RDATATYPE_NCACHEANY ||
				   header->type == negtype)
			{
				/*
				 * We've found a negative cache entry.
				 */
				found = header;
			} else if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nsheader = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_ns))
			{
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				nssig = header;
			} else if (header->type == dns_rdatatype_nsec) {
				nsecheader = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_nsec))
			{
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
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		NODE_UNLOCK(lock, &nlocktype);
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0) {
			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		goto find_ns;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL ||
	    (DNS_TRUST_ADDITIONAL(found->trust) &&
	     ((options & DNS_DBFIND_ADDITIONALOK) == 0)) ||
	    (found->trust == dns_trust_glue &&
	     ((options & DNS_DBFIND_GLUEOK) == 0)) ||
	    (DNS_TRUST_PENDING(found->trust) &&
	     ((options & DNS_DBFIND_PENDINGOK) == 0)))
	{
		/*
		 * Return covering NODATA NSEC record.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    nsecheader != NULL)
		{
			if (nodep != NULL) {
				dns__qpdb_newref(search.qpdb, node,
						 nlocktype DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			dns__qpdb_bindrdataset(search.qpdb, node, nsecheader,
					       search.now, nlocktype,
					       rdataset DNS__DB_FLARG_PASS);
			if (need_headerupdate(nsecheader, search.now)) {
				update = nsecheader;
			}
			if (nsecsig != NULL) {
				dns__qpdb_bindrdataset(
					search.qpdb, node, nsecsig, search.now,
					nlocktype,
					sigrdataset DNS__DB_FLARG_PASS);
				if (need_headerupdate(nsecsig, search.now)) {
					updatesig = nsecsig;
				}
			}
			result = DNS_R_COVERINGNSEC;
			goto node_exit;
		}

		/*
		 * This name was from a wild card.  Look for a covering NSEC.
		 */
		if (found == NULL && (found_noqname || all_negative) &&
		    (search.options & DNS_DBFIND_COVERINGNSEC) != 0)
		{
			NODE_UNLOCK(lock, &nlocktype);
			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
			goto find_ns;
		}

		/*
		 * If there is an NS rdataset at this node, then this is the
		 * deepest zone cut.
		 */
		if (nsheader != NULL) {
			if (nodep != NULL) {
				dns__qpdb_newref(search.qpdb, node,
						 nlocktype DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			dns__qpdb_bindrdataset(search.qpdb, node, nsheader,
					       search.now, nlocktype,
					       rdataset DNS__DB_FLARG_PASS);
			if (need_headerupdate(nsheader, search.now)) {
				update = nsheader;
			}
			if (nssig != NULL) {
				dns__qpdb_bindrdataset(
					search.qpdb, node, nssig, search.now,
					nlocktype,
					sigrdataset DNS__DB_FLARG_PASS);
				if (need_headerupdate(nssig, search.now)) {
					updatesig = nssig;
				}
			}
			result = DNS_R_DELEGATION;
			goto node_exit;
		}

		/*
		 * Go find the deepest zone cut.
		 */
		NODE_UNLOCK(lock, &nlocktype);
		goto find_ns;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		dns__qpdb_newref(search.qpdb, node,
				 nlocktype DNS__DB_FLARG_PASS);
		*nodep = node;
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
	} else if (type != found->type && type != dns_rdatatype_any &&
		   found->type == dns_rdatatype_cname)
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

	if (type != dns_rdatatype_any || result == DNS_R_NCACHENXDOMAIN ||
	    result == DNS_R_NCACHENXRRSET)
	{
		dns__qpdb_bindrdataset(search.qpdb, node, found, search.now,
				       nlocktype, rdataset DNS__DB_FLARG_PASS);
		if (need_headerupdate(found, search.now)) {
			update = found;
		}
		if (!NEGATIVE(found) && foundsig != NULL) {
			dns__qpdb_bindrdataset(search.qpdb, node, foundsig,
					       search.now, nlocktype,
					       sigrdataset DNS__DB_FLARG_PASS);
			if (need_headerupdate(foundsig, search.now)) {
				updatesig = foundsig;
			}
		}
	}

node_exit:
	if ((update != NULL || updatesig != NULL) &&
	    nlocktype != isc_rwlocktype_write)
	{
		NODE_FORCEUPGRADE(lock, &nlocktype);
		POST(nlocktype);
	}
	if (update != NULL && need_headerupdate(update, search.now)) {
		update_header(search.qpdb, update, search.now);
	}
	if (updatesig != NULL && need_headerupdate(updatesig, search.now)) {
		update_header(search.qpdb, updatesig, search.now);
	}

	NODE_UNLOCK(lock, &nlocktype);

tree_exit:
	TREE_UNLOCK(&search.qpdb->tree_lock, &tlocktype);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);
		lock = &(search.qpdb->node_locks[node->locknum].lock);

		NODE_RDLOCK(lock, &nlocktype);
		dns__qpdb_decref(search.qpdb, node, 0, &nlocktype, &tlocktype,
				 true, false DNS__DB_FLARG_PASS);
		NODE_UNLOCK(lock, &nlocktype);
		INSIST(tlocktype == isc_rwlocktype_none);
	}

	update_cachestats(search.qpdb, result);
	return (result);
}

static isc_result_t
cache_findzonecut(dns_db_t *db, const dns_name_t *name, unsigned int options,
		  isc_stdtime_t now, dns_dbnode_t **nodep,
		  dns_name_t *foundname, dns_name_t *dcname,
		  dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_qpdata_t *node = NULL;
	isc_rwlock_t *lock = NULL;
	isc_result_t result;
	qpdb_search_t search;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	bool dcnull = (dcname == NULL);

	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	search = (qpdb_search_t){
		.qpdb = (dns_qpdb_t *)db,
		.serial = 1,
		.options = options,
		.now = now,
	};
	dns_fixedname_init(&search.zonecut_name);

	if (dcnull) {
		dcname = foundname;
	}

	TREE_RDLOCK(&search.qpdb->tree_lock, &tlocktype);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(search.qpdb->tree, name, dcname, NULL,
			       &search.chain, (void **)&node, NULL);
	if ((options & DNS_DBFIND_NOEXACT) != 0 && result == ISC_R_SUCCESS) {
		int len = dns_qpchain_length(&search.chain);
		if (len >= 2) {
			node = NULL;
			dns_qpchain_node(&search.chain, len - 2, NULL,
					 (void **)&node, NULL);
			search.chain.len = len - 1;
			result = DNS_R_PARTIALMATCH;
		} else {
			result = ISC_R_NOTFOUND;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset,
					      sigrdataset DNS__DB_FLARG_PASS);
		goto tree_exit;
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	} else if (!dcnull) {
		dns_name_copy(dcname, foundname);
	}

	/*
	 * We now go looking for an NS rdataset at the node.
	 */

	lock = &(search.qpdb->node_locks[node->locknum].lock);
	NODE_RDLOCK(lock, &nlocktype);

	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &nlocktype, lock, &search,
				       &header_prev))
		{
			/*
			 * The function dns_qp_lookup found us a matching
			 * node for 'name' and stored the result in 'dcname'.
			 * This is the deepest known zonecut in our database.
			 * However, this node may be stale and if serve-stale
			 * is not enabled (in other words 'stale-answer-enable'
			 * is set to no), this node may not be used as a
			 * zonecut we know about. If so, find the deepest
			 * zonecut from this node up and return that instead.
			 */
			NODE_UNLOCK(lock, &nlocktype);
			result = find_deepest_zonecut(
				&search, node, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			dns_name_copy(foundname, dcname);
			goto tree_exit;
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				found = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_ns))
			{
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				foundsig = header;
			}
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (found == NULL) {
		/*
		 * No NS records here.
		 */
		NODE_UNLOCK(lock, &nlocktype);
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset,
					      sigrdataset DNS__DB_FLARG_PASS);
		goto tree_exit;
	}

	if (nodep != NULL) {
		dns__qpdb_newref(search.qpdb, node,
				 nlocktype DNS__DB_FLARG_PASS);
		*nodep = node;
	}

	dns__qpdb_bindrdataset(search.qpdb, node, found, search.now, nlocktype,
			       rdataset DNS__DB_FLARG_PASS);
	if (foundsig != NULL) {
		dns__qpdb_bindrdataset(search.qpdb, node, foundsig, search.now,
				       nlocktype,
				       sigrdataset DNS__DB_FLARG_PASS);
	}

	if (need_headerupdate(found, search.now) ||
	    (foundsig != NULL && need_headerupdate(foundsig, search.now)))
	{
		if (nlocktype != isc_rwlocktype_write) {
			NODE_FORCEUPGRADE(lock, &nlocktype);
			POST(nlocktype);
		}
		if (need_headerupdate(found, search.now)) {
			update_header(search.qpdb, found, search.now);
		}
		if (foundsig != NULL && need_headerupdate(foundsig, search.now))
		{
			update_header(search.qpdb, foundsig, search.now);
		}
	}

	NODE_UNLOCK(lock, &nlocktype);

tree_exit:
	TREE_UNLOCK(&search.qpdb->tree_lock, &tlocktype);

	INSIST(!search.need_cleanup);

	if (result == DNS_R_DELEGATION) {
		result = ISC_R_SUCCESS;
	}

	return (result);
}

static isc_result_t
cache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdatatype_t type, dns_rdatatype_t covers,
		   isc_stdtime_t now, dns_rdataset_t *rdataset,
		   dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_typepair_t matchtype, sigmatchtype, negtype;
	isc_result_t result;
	isc_rwlock_t *lock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(type != dns_rdatatype_any);

	UNUSED(version);

	result = ISC_R_SUCCESS;

	if (now == 0) {
		now = isc_stdtime_now();
	}

	lock = &qpdb->node_locks[qpnode->locknum].lock;
	NODE_RDLOCK(lock, &nlocktype);

	matchtype = DNS_TYPEPAIR_VALUE(type, covers);
	negtype = DNS_TYPEPAIR_VALUE(0, type);
	if (covers == 0) {
		sigmatchtype = DNS_SIGTYPE(type);
	} else {
		sigmatchtype = 0;
	}

	for (header = qpnode->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (!ACTIVE(header, now)) {
			if ((header->ttl + STALE_TTL(header, qpdb) <
			     now - QPDB_VIRTUAL) &&
			    (nlocktype == isc_rwlocktype_write ||
			     NODE_TRYUPGRADE(lock, &nlocktype) ==
				     ISC_R_SUCCESS))
			{
				/*
				 * We update the node's status only when we
				 * can get write access.
				 *
				 * We don't check if refcurrent(qpnode) == 0
				 * and try to free like we do in cache_find(),
				 * because refcurrent(qpnode) must be
				 * non-zero.  This is so because 'node' is an
				 * argument to the function.
				 */
				dns__qpdb_mark(header,
					       DNS_SLABHEADERATTR_ANCIENT);
				QPDB_HEADERNODE(header)->dirty = 1;
			}
		} else if (EXISTS(header) && !ANCIENT(header)) {
			if (header->type == matchtype) {
				found = header;
			} else if (header->type == RDATATYPE_NCACHEANY ||
				   header->type == negtype)
			{
				found = header;
			} else if (header->type == sigmatchtype) {
				foundsig = header;
			}
		}
	}
	if (found != NULL) {
		dns__qpdb_bindrdataset(qpdb, qpnode, found, now, nlocktype,
				       rdataset DNS__DB_FLARG_PASS);
		if (!NEGATIVE(found) && foundsig != NULL) {
			dns__qpdb_bindrdataset(qpdb, qpnode, foundsig, now,
					       nlocktype,
					       sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	NODE_UNLOCK(lock, &nlocktype);

	if (found == NULL) {
		return (ISC_R_NOTFOUND);
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

	return (result);
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb)); /* current restriction */
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &qpdb->cachestats);
	return (ISC_R_SUCCESS);
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb)); /* current restriction */

	return (qpdb->rrsetstats);
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->common.serve_stale_ttl = ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb));

	*ttl = qpdb->common.serve_stale_ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->serve_stale_refresh = interval;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(IS_CACHE(qpdb));

	*interval = qpdb->serve_stale_refresh;
	return (ISC_R_SUCCESS);
}

static void
expiredata(dns_db_t *db, dns_dbnode_t *node, void *data) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpdata_t *qpnode = (dns_qpdata_t *)node;
	dns_slabheader_t *header = data;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlocktype_t tlocktype = isc_rwlocktype_none;

	NODE_WRLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);
	dns__qpcache_expireheader(header, &tlocktype,
				  dns_expire_flush DNS__DB_FILELINE);
	NODE_UNLOCK(&qpdb->node_locks[qpnode->locknum].lock, &nlocktype);
	INSIST(tlocktype == isc_rwlocktype_none);
}

dns_dbmethods_t dns__qpdb_cachemethods = {
	.destroy = dns__qpdb_destroy,
	.findnode = dns__qpdb_findnode,
	.find = cache_find,
	.findzonecut = cache_findzonecut,
	.attachnode = dns__qpdb_attachnode,
	.detachnode = dns__qpdb_detachnode,
	.createiterator = dns__qpdb_createiterator,
	.findrdataset = cache_findrdataset,
	.allrdatasets = dns__qpdb_allrdatasets,
	.addrdataset = dns__qpdb_addrdataset,
	.deleterdataset = dns__qpdb_deleterdataset,
	.nodecount = dns__qpdb_nodecount,
	.setloop = dns__qpdb_setloop,
	.getoriginnode = dns__qpdb_getoriginnode,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.locknode = dns__qpdb_locknode,
	.unlocknode = dns__qpdb_unlocknode,
	.expiredata = expiredata,
	.deletedata = dns__qpdb_deletedata,
};

/*
 * Caller must hold the node (write) lock.
 */
void
dns__qpcache_expireheader(dns_slabheader_t *header,
			  isc_rwlocktype_t *tlocktypep,
			  dns_expire_t reason DNS__DB_FLARG) {
	dns__qpdb_setttl(header, 0);
	dns__qpdb_mark(header, DNS_SLABHEADERATTR_ANCIENT);
	QPDB_HEADERNODE(header)->dirty = 1;

	if (isc_refcount_current(&QPDB_HEADERNODE(header)->erefs) == 0) {
		isc_rwlocktype_t nlocktype = isc_rwlocktype_write;
		dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

		/*
		 * If no one else is using the node, we can clean it up now.
		 * We first need to gain a new reference to the node to meet a
		 * requirement of dns__qpdb_decref().
		 */
		dns__qpdb_newref(qpdb, QPDB_HEADERNODE(header),
				 nlocktype DNS__DB_FLARG_PASS);
		dns__qpdb_decref(qpdb, QPDB_HEADERNODE(header), 0, &nlocktype,
				 tlocktypep, true, false DNS__DB_FLARG_PASS);

		if (qpdb->cachestats == NULL) {
			return;
		}

		switch (reason) {
		case dns_expire_ttl:
			isc_stats_increment(qpdb->cachestats,
					    dns_cachestatscounter_deletettl);
			break;
		case dns_expire_lru:
			isc_stats_increment(qpdb->cachestats,
					    dns_cachestatscounter_deletelru);
			break;
		default:
			break;
		}
	}
}

static size_t
rdataset_size(dns_slabheader_t *header) {
	if (!NONEXISTENT(header)) {
		return (dns_rdataslab_size((unsigned char *)header,
					   sizeof(*header)));
	}

	return (sizeof(*header));
}

static size_t
expire_lru_headers(dns_qpdb_t *qpdb, unsigned int locknum,
		   isc_rwlocktype_t *tlocktypep,
		   size_t purgesize DNS__DB_FLARG) {
	dns_slabheader_t *header = NULL;
	size_t purged = 0;

	for (header = ISC_LIST_TAIL(qpdb->lru[locknum]);
	     header != NULL && header->last_used <= qpdb->last_used &&
	     purged <= purgesize;
	     header = ISC_LIST_TAIL(qpdb->lru[locknum]))
	{
		size_t header_size = rdataset_size(header);

		/*
		 * Unlink the entry at this point to avoid checking it
		 * again even if it's currently used someone else and
		 * cannot be purged at this moment.  This entry won't be
		 * referenced any more (so unlinking is safe) since the
		 * TTL will be reset to 0.
		 */
		ISC_LIST_UNLINK(qpdb->lru[locknum], header, link);
		dns__qpcache_expireheader(header, tlocktypep,
					  dns_expire_lru DNS__DB_FLARG_PASS);
		purged += header_size;
	}

	return (purged);
}

/*%
 * Purge some expired and/or stale (i.e. unused for some period) cache entries
 * due to an overmem condition.  To recover from this condition quickly,
 * we clean up entries up to the size of newly added rdata that triggered
 * the overmem; this is accessible via newheader.
 *
 * The LRU lists tails are processed in LRU order to the nearest second.
 *
 * A write lock on the tree must be held.
 */
void
dns__qpcache_overmem(dns_qpdb_t *qpdb, dns_slabheader_t *newheader,
		     isc_rwlocktype_t *tlocktypep DNS__DB_FLARG) {
	uint32_t locknum_start = qpdb->lru_sweep++ % qpdb->node_lock_count;
	uint32_t locknum = locknum_start;
	/* Size of added data, possible node and possible ENT node. */
	size_t purgesize = rdataset_size(newheader) + 2 * sizeof(dns_qpdata_t);
	size_t purged = 0;
	isc_stdtime_t min_last_used = 0;
	size_t max_passes = 8;

again:
	do {
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		NODE_WRLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);

		purged += expire_lru_headers(qpdb, locknum, tlocktypep,
					     purgesize -
						     purged DNS__DB_FLARG_PASS);

		/*
		 * Work out the oldest remaining last_used values of the list
		 * tails as we walk across the array of lru lists.
		 */
		dns_slabheader_t *header = ISC_LIST_TAIL(qpdb->lru[locknum]);
		if (header != NULL &&
		    (min_last_used == 0 || header->last_used < min_last_used))
		{
			min_last_used = header->last_used;
		}
		NODE_UNLOCK(&qpdb->node_locks[locknum].lock, &nlocktype);
		locknum = (locknum + 1) % qpdb->node_lock_count;
	} while (locknum != locknum_start && purged <= purgesize);

	/*
	 * Update qpdb->last_used if we have walked all the list tails and have
	 * not freed the required amount of memory.
	 */
	if (purged < purgesize) {
		if (min_last_used != 0) {
			qpdb->last_used = min_last_used;
			if (max_passes-- > 0) {
				goto again;
			}
		}
	}
}
