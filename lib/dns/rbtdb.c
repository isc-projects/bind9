/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Principal Author: Bob Halley
 */

#include <config.h>

#include <stddef.h>
#include <string.h>
#include <limits.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>
#include <isc/rwlock.h>

#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rbt.h>
#include <dns/master.h>
#include <dns/rdataslab.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/masterdump.h>

#ifdef DNS_RBTDB_VERSION64
#include "rbtdb64.h"
#else
#include "rbtdb.h"
#endif

/* Lame.  Move util.h to <isc/util.h> */
#include "../isc/util.h"

#ifdef DNS_RBTDB_VERSION64
#define RBTDB_MAGIC			0x52424438U	/* RBD8. */
#else
#define RBTDB_MAGIC			0x52424434U	/* RBD4. */
#endif

#define VALID_RBTDB(rbtdb)		((rbtdb) != NULL && \
					 (rbtdb)->common.impmagic == \
						RBTDB_MAGIC)

#ifdef DNS_RBTDB_VERSION64
typedef isc_uint64_t			rbtdb_serial_t;
#else
typedef isc_uint32_t			rbtdb_serial_t;
#endif

typedef struct rdatasetheader {
	/*
	 * Locked by the owning node's lock.
	 */
	dns_ttl_t			ttl;
	rbtdb_serial_t			serial;
	dns_rdatatype_t			type;
	isc_uint16_t			attributes;
	/*
	 * We don't use the LIST macros, because the LIST structure has
	 * both head and tail pointers, and is doubly linked.
	 */
	struct rdatasetheader		*next;
	struct rdatasetheader		*down;
} rdatasetheader_t;

#define RDATASET_ATTR_NONEXISTENT	0x01
#define RDATASET_ATTR_STALE		0x02
#define RDATASET_ATTR_IGNORE		0x04

#define IGNORE(header)	(((header)->attributes & RDATASET_ATTR_IGNORE) != 0)

#define DEFAULT_NODE_LOCK_COUNT		7		/* Should be prime. */

typedef struct {
	isc_mutex_t			lock;
	unsigned int			references;
} rbtdb_nodelock_t;

typedef struct rbtdb_changed {
	dns_rbtnode_t *			node;
	isc_boolean_t			dirty;
	ISC_LINK(struct rbtdb_changed)	link;
} rbtdb_changed_t;

typedef ISC_LIST(rbtdb_changed_t)	rbtdb_changedlist_t;

typedef struct rbtdb_version {
	/* Not locked */
	rbtdb_serial_t			serial;
	/* Locked by database lock. */
	isc_boolean_t			writer;
	unsigned int			references;
	isc_boolean_t			commit_ok;
	rbtdb_changedlist_t		changed_list;
	ISC_LINK(struct rbtdb_version)	link;
} rbtdb_version_t;

typedef ISC_LIST(rbtdb_version_t)	rbtdb_versionlist_t;

typedef struct {
	/* Unlocked. */
	dns_db_t			common;
	isc_mutex_t			lock;
	isc_rwlock_t			tree_lock;
	unsigned int			node_lock_count;
	rbtdb_nodelock_t *	       	node_locks;
	dns_rbtnode_t *			origin_node;
	/* Locked by lock. */
	unsigned int			references;
	unsigned int			attributes;
	rbtdb_serial_t			current_serial;
	rbtdb_serial_t			least_serial;
	rbtdb_serial_t			next_serial;
	rbtdb_version_t *		current_version;
	rbtdb_version_t *		future_version;
	rbtdb_versionlist_t		open_versions;
	/* Locked by tree_lock. */
	dns_rbt_t *			tree;
} dns_rbtdb_t;

#define RBTDB_ATTR_LOADED		0x01

/*
 * Search Context
 */
typedef struct {
	dns_rbtdb_t *		rbtdb;
	rbtdb_version_t *	rbtversion;
	rbtdb_serial_t		serial;
	unsigned int		options;
	dns_rbtnodechain_t	chain;
	isc_boolean_t		copy_name;
	isc_boolean_t		need_cleanup;
	dns_rbtnode_t *	       	zonecut;
	rdatasetheader_t *	zonecut_rdataset;
	dns_fixedname_t		zonecut_name;
	isc_stdtime_t		now;
} rbtdb_search_t;

/*
 * Load Context
 */
typedef struct {
	dns_rbtdb_t *		rbtdb;
	isc_stdtime_t		now;
} rbtdb_load_t;

static dns_result_t rdataset_disassociate(dns_rdataset_t *rdatasetp);
static dns_result_t rdataset_first(dns_rdataset_t *rdataset);
static dns_result_t rdataset_next(dns_rdataset_t *rdataset);
static void rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);

static dns_rdatasetmethods_t rdataset_methods = {
	rdataset_disassociate,
	rdataset_first,
	rdataset_next,
	rdataset_current
};

static void rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp);
static dns_result_t rdatasetiter_first(dns_rdatasetiter_t *iterator);
static dns_result_t rdatasetiter_next(dns_rdatasetiter_t *iterator);
static void rdatasetiter_current(dns_rdatasetiter_t *iterator,
				 dns_rdataset_t *rdataset);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy,
	rdatasetiter_first,
	rdatasetiter_next,
	rdatasetiter_current
};

typedef struct rbtdb_rdatasetiter {
	dns_rdatasetiter_t		common;
	rdatasetheader_t *		current;
} rbtdb_rdatasetiter_t;

static void		dbiterator_destroy(dns_dbiterator_t **iteratorp);
static dns_result_t	dbiterator_first(dns_dbiterator_t *iterator);
static dns_result_t	dbiterator_next(dns_dbiterator_t *iterator);
static dns_result_t	dbiterator_current(dns_dbiterator_t *iterator,
					   dns_dbnode_t **nodep,
					   dns_name_t *name);
static dns_result_t	dbiterator_pause(dns_dbiterator_t *iterator);
static dns_result_t	dbiterator_origin(dns_dbiterator_t *iterator,
					  dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy,
	dbiterator_first,
	dbiterator_next,
	dbiterator_current,
	dbiterator_pause,
	dbiterator_origin
};

typedef struct rbtdb_dbiterator {
	dns_dbiterator_t		common;
	isc_boolean_t			paused;
	isc_boolean_t			new_origin;
	isc_boolean_t			tree_locked;
	dns_result_t			result;
	dns_fixedname_t			name;
	dns_fixedname_t			origin;
	dns_rbtnode_t			*node;
	dns_rbtnodechain_t		chain;
} rbtdb_dbiterator_t;


/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *	Tree Lock
 *
 *	Node Lock	(Only one from the set may be locked at one time by
 *			 any caller)
 *
 *	Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

/*
 * Deleting Nodes
 *
 * Currently there is no deletion of nodes from the database, except when
 * the database is being destroyed.
 *
 * If node deletion is added in the future, then for zone databases the node
 * for the origin of the zone MUST NOT be deleted.
 */


/*
 * DB Routines
 */

static void
attach(dns_db_t *source, dns_db_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)source;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);
	REQUIRE(rbtdb->references > 0);
	rbtdb->references++;
	UNLOCK(&rbtdb->lock);

	*targetp = source;
}

static void
free_rbtdb(dns_rbtdb_t *rbtdb) {
	unsigned int i;
	isc_region_t r;

	REQUIRE(EMPTY(rbtdb->open_versions));
	REQUIRE(rbtdb->future_version == NULL);

	isc_mem_put(rbtdb->common.mctx, rbtdb->current_version,
		    sizeof (rbtdb_version_t));
	dns_name_toregion(&rbtdb->common.origin, &r);
	if (r.base != NULL)
		isc_mem_put(rbtdb->common.mctx, r.base, r.length);
	if (rbtdb->tree != NULL)
		dns_rbt_destroy(&rbtdb->tree);
	for (i = 0; i < rbtdb->node_lock_count; i++)
		isc_mutex_destroy(&rbtdb->node_locks[i].lock);
	isc_mem_put(rbtdb->common.mctx, rbtdb->node_locks,
		    rbtdb->node_lock_count * sizeof (rbtdb_nodelock_t));
	isc_rwlock_destroy(&rbtdb->tree_lock);
	isc_mutex_destroy(&rbtdb->lock);
	rbtdb->common.magic = 0;
	rbtdb->common.impmagic = 0;
	isc_mem_put(rbtdb->common.mctx, rbtdb, sizeof *rbtdb);
}

static inline void
maybe_free_rbtdb(dns_rbtdb_t *rbtdb) {
	isc_boolean_t want_free = ISC_TRUE;
	unsigned int i;
	
	/* XXX check for open versions here */

	/*
	 * Even though there are no external direct references, there still
	 * may be nodes in use.
	 */
	for (i = 0; i < rbtdb->node_lock_count; i++) {
		LOCK(&rbtdb->node_locks[i].lock);
		if (rbtdb->node_locks[i].references != 0)
			want_free = ISC_FALSE;
		UNLOCK(&rbtdb->node_locks[i].lock);
	}

	if (want_free)
		free_rbtdb(rbtdb);
}

static void
detach(dns_db_t **dbp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(*dbp);
	isc_boolean_t maybe_free = ISC_FALSE;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);
	REQUIRE(rbtdb->references > 0);
	rbtdb->references--;
	if (rbtdb->references == 0)
		maybe_free = ISC_TRUE;
	UNLOCK(&rbtdb->lock);

	if (maybe_free)
		maybe_free_rbtdb(rbtdb);

	*dbp = NULL;
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);
	version = rbtdb->current_version;
	if (version->references == 0)
		PREPEND(rbtdb->open_versions, version, link);
	version->references++;
	UNLOCK(&rbtdb->lock);

	*versionp = (dns_dbversion_t *)version;
}

static inline rbtdb_version_t *
allocate_version(isc_mem_t *mctx, unsigned int serial,
		 unsigned int references, isc_boolean_t writer)
{
	rbtdb_version_t *version;

	version = isc_mem_get(mctx, sizeof *version);
	if (version == NULL)
		return (NULL);
	version->serial = serial;
	version->references = references;
	version->writer = writer;
	version->commit_ok = ISC_FALSE;
	ISC_LIST_INIT(version->changed_list);
	ISC_LINK_INIT(version, link);
	
	return (version);
}

static dns_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp == NULL);
	REQUIRE(rbtdb->future_version == NULL);

	LOCK(&rbtdb->lock);
	RUNTIME_CHECK(rbtdb->next_serial != 0);		/* XXX Error? */
	version = allocate_version(rbtdb->common.mctx, rbtdb->next_serial, 1,
				   ISC_TRUE);
	if (version != NULL) {
		version->commit_ok = ISC_TRUE;
		rbtdb->next_serial++;
		rbtdb->future_version = version;
	}
	UNLOCK(&rbtdb->lock);

	if (version == NULL)
		return (DNS_R_NOMEMORY);

	*versionp = version;

	return (DNS_R_SUCCESS);
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *rbtversion = source;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);

	INSIST(rbtversion->references > 0);
	rbtversion->references++;
	INSIST(rbtversion->references != 0);

	UNLOCK(&rbtdb->lock);

	*targetp = rbtversion;
}

static rbtdb_changed_t *
add_changed(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
	    dns_rbtnode_t *node)
{
	rbtdb_changed_t *changed;

	/*
	 * Caller must be holding the node lock.
	 */

	changed = isc_mem_get(rbtdb->common.mctx, sizeof *changed);

	LOCK(&rbtdb->lock);

	REQUIRE(version->writer);

	if (changed != NULL) {
		INSIST(node->references > 0);
		node->references++;
		INSIST(node->references != 0);
		changed->node = node;
		changed->dirty = ISC_FALSE;
		APPEND(version->changed_list, changed, link);
	} else
		version->commit_ok = ISC_FALSE;

	UNLOCK(&rbtdb->lock);

	return (changed);
}

static inline void
free_rdataset(isc_mem_t *mctx, rdatasetheader_t *rdataset) {
	unsigned int size;

	if ((rdataset->attributes & RDATASET_ATTR_NONEXISTENT) != 0)
		size = sizeof *rdataset;
	else
		size = dns_rdataslab_size((unsigned char *)rdataset,
					  sizeof *rdataset);
	isc_mem_put(mctx, rdataset, size);
}

static inline void
rollback_node(dns_rbtnode_t *node, rbtdb_serial_t serial) {
	rdatasetheader_t *header, *dcurrent;
	isc_boolean_t make_dirty = ISC_FALSE;

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
			header->attributes |= RDATASET_ATTR_IGNORE;
			make_dirty = ISC_TRUE;
		}
		for (dcurrent = header->down;
		     dcurrent != NULL;
		     dcurrent = dcurrent->down) {
			if (dcurrent->serial == serial) {
				dcurrent->attributes |= RDATASET_ATTR_IGNORE;
				make_dirty = ISC_TRUE;
			}
		}
	}
	if (make_dirty)
		node->dirty = 1;
}

static inline void
clean_cache_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node) {
	rdatasetheader_t *current, *dcurrent, *top_prev, *top_next, *down_next;
	isc_mem_t *mctx = rbtdb->common.mctx;

	/*
	 * Caller must be holding the node lock.
	 */

	top_prev = NULL;
	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;
		dcurrent = current->down;
		if (dcurrent != NULL) {
			do {
				down_next = dcurrent->down;
				free_rdataset(mctx, dcurrent);
				dcurrent = down_next;
			} while (dcurrent != NULL);
			current->down = NULL;
		}
		/*
		 * If current is nonexistent or stale, we can clean it up.
		 */
		if ((current->attributes &
		     (RDATASET_ATTR_NONEXISTENT|RDATASET_ATTR_STALE)) != 0) {
			if (top_prev != NULL)
				top_prev->next = current->next;
			else
				node->data = current->next;
			free_rdataset(mctx, current);
		} else
			top_prev = current;
	}
	node->dirty = 0;
}

static inline void
clean_zone_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		rbtdb_serial_t least_serial)
{
	rdatasetheader_t *current, *dcurrent, *down_next, *dparent;
	rdatasetheader_t *top_prev, *top_next;
	isc_mem_t *mctx = rbtdb->common.mctx;
	isc_boolean_t still_dirty = ISC_FALSE;

	/*
	 * Caller must be holding the node lock.
	 */
	REQUIRE(least_serial != 0);

	top_prev = NULL;
	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;

		/*
		 * Find the first rdataset less than the least serial, if
		 * any.  On the way down, clean up any instances of multiple
		 * rdatasets with the same serial number, or that have the
		 * IGNORE attribute.
		 */
		dparent = current;
		for (dcurrent = current->down;
		     dcurrent != NULL;
		     dcurrent = down_next) {
			down_next = dcurrent->down;
			INSIST(dcurrent->serial <= dparent->serial);
			if (dcurrent->serial < least_serial)
				break;
			if (dcurrent->serial == dparent->serial ||
			    IGNORE(dcurrent)) {
				if (down_next != NULL)
					down_next->next = dparent;
				dparent->down = down_next;
				free_rdataset(mctx, dcurrent);
			} else
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
				free_rdataset(mctx, dcurrent);
				dcurrent = down_next;
			} while (dcurrent != NULL);
			dparent->down = NULL;
		}

		/*
		 * We've eliminated all IGNORE datasets with the possible
		 * exception of current, which we now check.
		 */
		if (IGNORE(current)) {
			down_next = current->down;
			if (down_next == NULL) {
				if (top_prev != NULL)
					top_prev->next = current->next;
				else
					node->data = current->next;
				free_rdataset(mctx, current);
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
				if (top_prev != NULL)
					top_prev->next = down_next;
				else
					node->data = down_next;
				down_next->next = top_next;
				free_rdataset(mctx, current);
				current = down_next;
			}
		}

		/*
		 * Note.  The serial number of 'current' might be less than
		 * least_serial too, but we cannot delete it because it is
		 * the most recent version, unless it is a NONEXISTENT
		 * rdataset or is IGNOREd.
		 */
		if (current->down != NULL) {
			still_dirty = ISC_TRUE;
			top_prev = current;
		} else {
			/*
			 * If this is a NONEXISTENT rdataset, we can delete it.
			 */
			if ((current->attributes & RDATASET_ATTR_NONEXISTENT)
			    != 0) {
				if (top_prev != NULL)
					top_prev->next = current->next;
				else
					node->data = current->next;
				free_rdataset(mctx, current);
			} else
				top_prev = current;
		}
	}
	if (!still_dirty)
		node->dirty = 0;
}

static inline void
new_reference(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node) {
	if (node->references == 0) {
		rbtdb->node_locks[node->locknum].references++;
		INSIST(rbtdb->node_locks[node->locknum].references != 0);
	}
	node->references++;
	INSIST(node->references != 0);
}

static void
no_references(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
	      rbtdb_serial_t least_serial)
{
	/*
	 * Caller must be holding the node lock.
	 */

	REQUIRE(node->references == 0);

	if (node->dirty) {
		if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) != 0)
			clean_cache_node(rbtdb, node);
		else {
			if (least_serial == 0) {
				/*
				 * Caller doesn't know the least serial.
				 * Get it.
				 */
				LOCK(&rbtdb->lock);
				least_serial = rbtdb->least_serial;
				UNLOCK(&rbtdb->lock);
			}
			clean_zone_node(rbtdb, node, least_serial);
		}
	}

	INSIST(rbtdb->node_locks[node->locknum].references > 0);
	rbtdb->node_locks[node->locknum].references--;
}

static inline void
make_least_version(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
		   rbtdb_changedlist_t *cleanup_list)
{
	/*
	 * Caller must be holding the database lock.
	 */

	rbtdb->least_serial = version->serial;
	*cleanup_list = version->changed_list;
	ISC_LIST_INIT(version->changed_list);
}

static inline void
cleanup_nondirty(rbtdb_version_t *version, rbtdb_changedlist_t *cleanup_list) {
	rbtdb_changed_t *changed, *next_changed;

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
	for (changed = HEAD(version->changed_list);
	     changed != NULL;
	     changed = next_changed) {
		next_changed = NEXT(changed, link);
		if (!changed->dirty) {
			UNLINK(version->changed_list,
			       changed, link);
			APPEND(*cleanup_list,
			       changed, link);
		}
	}
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, isc_boolean_t commit) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version, *cleanup_version, *least_greater;
	isc_boolean_t rollback = ISC_FALSE;
	rbtdb_changedlist_t cleanup_list;
	rbtdb_changed_t *changed, *next_changed;
	rbtdb_serial_t serial, least_serial;
	dns_rbtnode_t *rbtnode;
	
	REQUIRE(VALID_RBTDB(rbtdb));
	version = (rbtdb_version_t *)*versionp;

	cleanup_version = NULL;
	ISC_LIST_INIT(cleanup_list);

	LOCK(&rbtdb->lock);
	INSIST(version->references > 0);
	INSIST(!version->writer || !(commit && version->references > 1));
	version->references--;
	serial = version->serial;
	if (version->references == 0) {
		if (version->writer) {
			if (commit) {
				INSIST(version->commit_ok);
				INSIST(version == rbtdb->future_version);
				if (EMPTY(rbtdb->open_versions)) {
					/*
					 * We're going to become the least open
					 * version.
					 */
					make_least_version(rbtdb, version,
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
					cleanup_nondirty(version,
							 &cleanup_list);
				}
				/*
				 * If the (soon to be former) current version
				 * isn't being used by anyone, we can clean
				 * it up.
				 */
				if (rbtdb->current_version->references == 0)
					cleanup_version =
						rbtdb->current_version;
				/*
				 * Become the current version.
				 */
				version->writer = ISC_FALSE;
				rbtdb->current_version = version;
				rbtdb->current_serial = version->serial;
				rbtdb->future_version = NULL;
			} else {
				/*
				 * We're rolling back this transaction.
				 */
				cleanup_list = version->changed_list;
				rollback = ISC_TRUE;
				cleanup_version = version;
				rbtdb->future_version = NULL;
			}
		} else {
			if (version != rbtdb->current_version) {
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
				if (least_greater == NULL)
					least_greater = rbtdb->current_version;

				/*
				 * Is this the least open version?
				 */
				if (version->serial == rbtdb->least_serial) {
					/*
					 * Yes.  Install the new least open
					 * version.
					 */
					make_least_version(rbtdb,
							   least_greater,
							   &cleanup_list);
				} else {
					/*
					 * Add any unexecuted cleanups to
					 * those of the least greater version.
					 */
					APPENDLIST(least_greater->changed_list,
						   version->changed_list,
						   link);
				}
			}
			UNLINK(rbtdb->open_versions, version, link);
		}
	}
	least_serial = rbtdb->least_serial;
	UNLOCK(&rbtdb->lock);

	if (cleanup_version != NULL)
		isc_mem_put(rbtdb->common.mctx, cleanup_version,
			    sizeof *cleanup_version);

	if (!EMPTY(cleanup_list)) {
		for (changed = HEAD(cleanup_list);
		     changed != NULL;
		     changed = next_changed) {
			next_changed = NEXT(changed, link);
			rbtnode = changed->node;

			LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

			INSIST(rbtnode->references > 0);
			rbtnode->references--;
			if (rollback)
				rollback_node(rbtnode, serial);

			if (rbtnode->references == 0)
				no_references(rbtdb, rbtnode, least_serial);

			UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

			isc_mem_put(rbtdb->common.mctx, changed,
				    sizeof *changed);
		}
	}

	*versionp = NULL;
}

static dns_result_t
findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
	 dns_dbnode_t **nodep)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node = NULL;
	dns_name_t nodename;
	unsigned int locknum;
	dns_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(VALID_RBTDB(rbtdb));

	dns_name_init(&nodename, NULL);
	RWLOCK(&rbtdb->tree_lock, locktype);
	result = dns_rbt_findnode(rbtdb->tree, name, NULL, &node, NULL,
				  ISC_TRUE, NULL, NULL);
 again:
	if (result == DNS_R_SUCCESS) {
		locknum = node->locknum;
		LOCK(&rbtdb->node_locks[locknum].lock);
		new_reference(rbtdb, node);
		UNLOCK(&rbtdb->node_locks[locknum].lock);
	} else {
		RWUNLOCK(&rbtdb->tree_lock, locktype);
		if (!create) {
			if (result == DNS_R_PARTIALMATCH)
				result = DNS_R_NOTFOUND;
			return (result);
		}
		locktype = isc_rwlocktype_write;
		/*
		 * It would be nice to try to upgrade the lock instead of
		 * unlocking then relocking.
		 */
		RWLOCK(&rbtdb->tree_lock, locktype);
		result = dns_rbt_addnode(rbtdb->tree, name, &node);
		if (result != DNS_R_SUCCESS && result != DNS_R_EXISTS) {
			RWUNLOCK(&rbtdb->tree_lock, locktype);
			return (result);
		}
		dns_rbt_namefromnode(node, &nodename);
		node->locknum = dns_name_hash(&nodename, ISC_TRUE) %
			rbtdb->node_lock_count;
		/*
		 * Turning off creation mode ensures that we can 'goto again'
		 * only once.  If we didn't do this and dns_rbt_findnode()
		 * was always failing, then we could loop forever.
		 */
		create = ISC_FALSE;
		goto again;
	}
	RWUNLOCK(&rbtdb->tree_lock, locktype);

	*nodep = (dns_dbnode_t *)node;

	return (result);
}

static dns_result_t
zone_zonecut_callback(dns_rbtnode_t *node, dns_name_t *name, void *arg) {
	rbtdb_search_t *search = arg;
	rdatasetheader_t *header, *header_next;
	rdatasetheader_t *found;
	dns_result_t result;

	/* XXX comment */

	if (search->zonecut != NULL)
		return (DNS_R_CONTINUE);

	found = NULL;
	result = DNS_R_CONTINUE;

	LOCK(&(search->rbtdb->node_locks[node->locknum].lock));
	
	/*
	 * Look for an NS or DNAME rdataset active in our version.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->type == dns_rdatatype_ns ||
		    header->type == dns_rdatatype_dname) {
			do {
				if (header->serial <= search->serial &&
				    !IGNORE(header)) {
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 */
					if ((header->attributes &
					     RDATASET_ATTR_NONEXISTENT) != 0)
						header = NULL;
					break;
				} else
					header = header->down;
			} while (header != NULL);
			if (header != NULL) {
				found = header;
				/*
				 * If we found a DNAME, then we don't need
				 * to keep looking for NS records, because the
				 * DNAME has precedence.
				 */
				if (found->type == dns_rdatatype_dname)
					break;
			}
		}
	}

	if (found != NULL) {
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_rdataset will still be valid later.
		 */
		new_reference(search->rbtdb, node);
		search->zonecut = node;
		search->zonecut_rdataset = found;
		search->need_cleanup = ISC_TRUE;
		if (found->type == dns_rdatatype_dname) {
			/*
			 * Finding a DNAME stops all further searching.
			 *
			 * Note: We return DNS_R_PARTIALMATCH instead of
			 * DNS_R_DNAME here because that way zone_find()
			 * does fewer result code comparisions.
			 */
			result = DNS_R_PARTIALMATCH;
		} else if ((search->options & DNS_DBFIND_GLUEOK) == 0) {
			/*
			 * If the caller does not want to find glue, then
			 * this is the best answer and the search should
			 * stop now.
			 *
			 * Note: We return DNS_R_PARTIALMATCH instead of
			 * DNS_R_DELEGATION here because that way zone_find()
			 * does fewer result code comparisions.
			 */
			result = DNS_R_PARTIALMATCH;
		} else {
			dns_name_t *zcname;

			/*
			 * The search will continue beneath the zone cut.
			 * This may or may not be the best match.  In case it
			 * is, we need to remember the node name.
			 */
			zcname = dns_fixedname_name(&search->zonecut_name);
			RUNTIME_CHECK(dns_name_concatenate(name, NULL, zcname,
							   NULL) ==
				      DNS_R_SUCCESS);
			search->copy_name = ISC_TRUE;
		}
	}

	UNLOCK(&(search->rbtdb->node_locks[node->locknum].lock));

	return (result);
}

static inline void
bind_rdataset(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
	      rdatasetheader_t *header, isc_stdtime_t now,
	      dns_rdataset_t *rdataset)
{
	unsigned char *raw;
	unsigned int count;

	/*
	 * Caller must be holding the node lock.
	 */

	new_reference(rbtdb, node);

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = rbtdb->common.rdclass;
	rdataset->type = header->type;
	rdataset->ttl = header->ttl - now;
	rdataset->private1 = rbtdb;
	rdataset->private2 = node;
	raw = (unsigned char *)header + sizeof *header;
	rdataset->private3 = raw;
	count = raw[0] * 256 + raw[1];
	raw += 2;
	if (count == 0) {
		rdataset->private4 = (void *)0;
		rdataset->private5 = NULL;
	} else {
		/*
		 * The private4 field is the number of rdata beyond
		 * the cursor position, so we decrement the total
		 * count by one before storing it.
		 */
		count--;
		rdataset->private4 = (void *)count; 
		rdataset->private5 = raw;
	}
}

static inline dns_result_t
setup_delegation(rbtdb_search_t *search, dns_dbnode_t **nodep,
		 dns_name_t *foundname, dns_rdataset_t *rdataset)
{
	dns_result_t result;
	dns_name_t *zcname;
	dns_rdatatype_t type;
	dns_rbtnode_t *node;

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	type = search->zonecut_rdataset->type;

	/*
	 * If we have to set foundname, we do it before anything else.
	 * If we were to set foundname after we had set nodep or bound the
	 * rdataset, then we'd have to undo that work if dns_name_concatenate()
	 * failed.  By setting foundname first, there's nothing to undo if
	 * we have trouble.
	 */
	if (foundname != NULL && search->copy_name) {
		zcname = dns_fixedname_name(&search->zonecut_name);
		result = dns_name_concatenate(zcname, NULL, foundname, NULL);
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (nodep != NULL) {
		/*
		 * Note that we don't have to increment the node's reference
		 * count here because we're going to use the reference we
		 * already have in the search block.
		 */
		*nodep = node;
		search->need_cleanup = ISC_FALSE;
	}
	if (rdataset != NULL) {
		LOCK(&(search->rbtdb->node_locks[node->locknum].lock));
		bind_rdataset(search->rbtdb, node, search->zonecut_rdataset,
			      search->now, rdataset);
		UNLOCK(&(search->rbtdb->node_locks[node->locknum].lock));
	}

	if (type == dns_rdatatype_dname)
		return (DNS_R_DNAME);
	return (DNS_R_DELEGATION);
}

static inline isc_boolean_t
valid_glue(rbtdb_search_t *search, dns_name_t *name, dns_rdatatype_t type,
	   dns_rbtnode_t *node)
{
	unsigned char *raw;
	unsigned int count, size;
	dns_name_t ns_name;
	isc_boolean_t valid = ISC_FALSE;
	dns_offsets_t offsets;
	isc_region_t region;
	rdatasetheader_t *header;

	/*
	 * No additional locking is required.
	 */

	/*
	 * Valid glue types are A, AAAA, A6.  NS is also a valid glue type
	 * if it occurs at a zone cut, but is not valid below it.
	 */
	if (type == dns_rdatatype_ns) {
		if (node != search->zonecut) {
			return (ISC_FALSE);
		}
	} else if (type != dns_rdatatype_a &&
		   type != dns_rdatatype_aaaa &&
		   type != dns_rdatatype_a6) {
		return (ISC_FALSE);
	}

	header = search->zonecut_rdataset;
	raw = (unsigned char *)header + sizeof *header;
	count = raw[0] * 256 + raw[1];
	raw += 2;

	while (count > 0) {
		count--;
		size = raw[0] * 256 + raw[1];
		raw += 2;
		region.base = raw;
		region.length = size;
		raw += size;
		/*
		 * XXX Until we have rdata structures, we have no choice but
		 * to directly access the rdata format.
		 */
		dns_name_init(&ns_name, offsets);
		dns_name_fromregion(&ns_name, &region);
		if (dns_name_compare(&ns_name, name) == 0) {
			valid = ISC_TRUE;
			break;
		}
	}

	return (valid);
}

static dns_result_t
zone_find(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
	  dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	  dns_dbnode_t **nodep, dns_name_t *foundname,
	  dns_rdataset_t *rdataset)
{
	dns_rbtnode_t *node = NULL;
	dns_result_t result;
	rbtdb_search_t search;
	isc_boolean_t cname_ok = ISC_TRUE;
	isc_boolean_t must_succeed = ISC_FALSE;
	isc_boolean_t close_version = ISC_FALSE;
	isc_boolean_t maybe_zonecut = ISC_FALSE;
	isc_boolean_t at_zonecut = ISC_FALSE;
	isc_boolean_t secure_zone;
	isc_boolean_t empty_node;
	rdatasetheader_t *header, *header_next, *found, *nxtheader;

	search.rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(search.rbtdb));

	/*
	 * We don't care about 'now'.  We set it to zero so compilers won't
	 * complain about it being unused.
	 */
	now = 0;

	/*
	 * If the caller didn't supply a version, attach to the current
	 * version.
	 */
	if (version == NULL) {
		currentversion(db, &version);
		close_version = ISC_TRUE;
	}

	search.rbtversion = version;
	search.serial = search.rbtversion->serial;
	search.options = options;
	search.copy_name = ISC_FALSE;
	search.need_cleanup = ISC_FALSE;
	search.zonecut = NULL;
	dns_fixedname_init(&search.zonecut_name);
	dns_rbtnodechain_init(&search.chain, search.rbtdb->common.mctx);
	search.now = 0;

	/*
	 * XXXDNSSEC Set secure_zone properly when implementing DNSSEC.
	 */
	secure_zone = ISC_FALSE;

	RWLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * Search down from the root of the tree.  If, while going down, we
	 * encounter a callback node, zone_zonecut_callback() will search the
	 * rdatasets at the zone cut for active DNAME or NS rdatasets.
	 */
	result = dns_rbt_findnode(search.rbtdb->tree, name, foundname, &node,
				  &search.chain, ISC_TRUE,
				  zone_zonecut_callback, &search);

	if (result == DNS_R_PARTIALMATCH) {
	partial_match:
		if (search.zonecut != NULL) {
		    result = setup_delegation(&search, nodep, foundname,
					      rdataset);
		    goto tree_exit;
		} else {
			/*
			 * XXX We need to add wildcard support as another
			 * 'else' clause.
			 */
			result = DNS_R_NXDOMAIN;
			if (secure_zone)
				result = DNS_R_NOTIMPLEMENTED; /* XXXDNSSEC */
			if (nodep != NULL)
				*nodep = NULL;
			goto tree_exit;
		}
	} else if (result != DNS_R_SUCCESS)
		goto tree_exit;

	/*
	 * We have found a node whose name is the desired name.
	 */

	if (search.zonecut != NULL) {
		/*
		 * If we're beneath a zone cut, we don't want to look for
		 * CNAMEs because they're not legitimate zone glue.
		 */
		cname_ok = ISC_FALSE;
	} else {
		/*
		 * The node may be a zone cut itself.  If it might be one,
		 * make sure we check for it later.
		 */
		if (node->find_callback && node != search.rbtdb->origin_node)
			maybe_zonecut = ISC_TRUE;
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC 2535, section 2.3.5).
	 *
	 * We don't check for SIG, because we don't store SIG records
	 * directly.
	 *
	 * XXX This should be a general purpose subroutine in the rdata
	 * module.
	 *
	 * XXX This 'if' could be an 'else if' of the 'if' above.
	 */
	if (type == dns_rdatatype_key || type == dns_rdatatype_nxt)
		cname_ok = ISC_FALSE;

	/*
	 * We now go looking for rdata...
	 */

	LOCK(&(search.rbtdb->node_locks[node->locknum].lock));
	
	found = NULL;
	nxtheader = NULL;
	empty_node = ISC_TRUE;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		/*
		 * Look for an active, extant rdataset.
		 */
		do {
			if (header->serial <= search.serial &&
			    !IGNORE(header)) {
				/*
				 * Is this a "this rdataset doesn't
				 * exist" record?
				 */
				if ((header->attributes &
				     RDATASET_ATTR_NONEXISTENT) != 0)
					header = NULL;
				break;
			} else
				header = header->down;
		} while (header != NULL);
		if (header != NULL) {
			/*
			 * We now know that there is at least one active
			 * rdataset at this node.
			 */
			empty_node = ISC_FALSE;

			/*
			 * Do special zone cut handling, if requested.
			 */
			if (maybe_zonecut &&
			    header->type == dns_rdatatype_ns) {
				/*
				 * We increment the reference count on node to
				 * ensure that search->zonecut_rdataset will
				 * still be valid later.
				 */
				new_reference(search.rbtdb, node);
				search.zonecut = node;
				search.zonecut_rdataset = header;
				search.need_cleanup = ISC_TRUE;
				maybe_zonecut = ISC_FALSE;
				at_zonecut = ISC_TRUE;
				if ((search.options & DNS_DBFIND_GLUEOK) == 0
				    && type != dns_rdatatype_nxt
				    && type != dns_rdatatype_key
				    && type != dns_rdatatype_any) {
					/*
					 * Glue is not OK, but any answer we
					 * could return would be glue.  Return
					 * the delegation.
					 */
					found = NULL;
					break;
				}
				if (found != NULL)
					break;
			}

			/*
			 * If we found a type we were looking for, we're done.
			 */
			if (header->type == type ||
			    type == dns_rdatatype_any ||
			    (cname_ok &&
			     header->type == dns_rdatatype_cname)) {
				found = header;
				if (!maybe_zonecut)
					break;
			} else if (header->type == dns_rdatatype_nxt) {
				/*
				 * Remember a NXT rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nxtheader = header;
			}
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * active rdatasets the desired version.  That means that
		 * this node doesn't exist in the desired version, and that
		 * we really have a partial match.
		 */
		UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		goto partial_match;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL) {
		if (must_succeed) {
			/*
			 * We were looking for a type which must be in the
			 * database, but isn't for some reason.
			 */
			result = DNS_R_BADDB;
		} else if (search.zonecut != NULL) {
		    /*
		     * We were trying to find glue at a node beneath a
		     * zone cut, but didn't, so we return the delegation.
		     */
		    UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		    result = setup_delegation(&search, nodep, foundname,
					      rdataset);
		    goto tree_exit;
		} else {
			/*
			 * The desired type doesn't exist.
			 */
			result = DNS_R_NXRDATASET;
			if (secure_zone && nxtheader == NULL) {
				/*
				 * The zone is secure but there's no NXT
				 * rdataset!
				 */
				result = DNS_R_BADDB;
			} else if (nodep != NULL) {
				new_reference(search.rbtdb, node);
				*nodep = node;
			}
		}
		goto node_exit;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (type != found->type &&
	    type != dns_rdatatype_any &&
	    found->type == dns_rdatatype_cname) {
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
		 * and the type is NXT or KEY.
		 */
		if (search.zonecut == node) {
			if (type == dns_rdatatype_nxt ||
			    type == dns_rdatatype_key)
				result = DNS_R_SUCCESS;
			else if (type == dns_rdatatype_any)
				result = DNS_R_ZONECUT;
			else
				result = DNS_R_GLUE;
		} else
			result = DNS_R_GLUE;
		/*
		 * We might have found data that isn't glue, but was occluded
		 * by a dynamic update.  If the caller cares about this, they
		 * will have told us to validate glue.
		 *
		 * XXX We should cache the glue validity state!
		 */
		if (result == DNS_R_GLUE &&
		    (search.options & DNS_DBFIND_VALIDATEGLUE) != 0 &&
		    !valid_glue(&search, foundname, type, node)) {
		    UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		    result = setup_delegation(&search, nodep, foundname,
					      rdataset);
		    goto tree_exit;
		}
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = DNS_R_SUCCESS;
	}

	if (nodep != NULL) {
		if (!at_zonecut)
			new_reference(search.rbtdb, node);
		else
			search.need_cleanup = ISC_FALSE;
		*nodep = node;
	}

	if (rdataset != NULL && type != dns_rdatatype_any)
		bind_rdataset(search.rbtdb, node, found, 0, rdataset);

 node_exit:
	UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
	
 tree_exit:
	RWUNLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;

		LOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		INSIST(node->references > 0);
		node->references--;
		if (node->references == 0)
			no_references(search.rbtdb, node, 0);
		UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
	}

	if (close_version)
		closeversion(db, &version, ISC_FALSE);

	dns_rbtnodechain_reset(&search.chain);

	return (result);
}

static dns_result_t
cache_zonecut_callback(dns_rbtnode_t *node, dns_name_t *name, void *arg) {
	rbtdb_search_t *search = arg;
	rdatasetheader_t *header, *header_prev, *header_next;
	dns_result_t result;

	/* XXX comment */

	REQUIRE(search->zonecut == NULL);

	/*
	 * Keep compiler silent.
	 */
	(void)name;

	LOCK(&(search->rbtdb->node_locks[node->locknum].lock));
	
	/*
	 * Look for DNAME rdataset.
	 */
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->ttl <= search->now) {
			/*
			 * This rdataset is stale.  If no one else is
			 * using the node, we can clean it up right
			 * now, otherwise we mark it as stale, and
			 * the node as dirty, so it will get cleaned
			 * up later.
			 */
			if (node->references == 0) {
				INSIST(header->down == NULL);
				if (header_prev != NULL)
					header_prev->next =
						header->next;
				else
					node->data = header->next;
				free_rdataset(search->rbtdb->common.mctx,
					      header);
			} else {
				header->attributes |=
					RDATASET_ATTR_STALE;
				node->dirty = 1;
				header_prev = header;
			}
		} else if (header->type == dns_rdatatype_dname &&
			   (header->attributes & RDATASET_ATTR_NONEXISTENT) ==
			   0)
			break;
		else
			header_prev = header;
	}

	if (header != NULL) {
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_rdataset will still be valid later.
		 */
		new_reference(search->rbtdb, node);
		search->zonecut = node;
		search->zonecut_rdataset = header;
		search->need_cleanup = ISC_TRUE;
		result = DNS_R_PARTIALMATCH;
	} else
		result = DNS_R_CONTINUE;

	UNLOCK(&(search->rbtdb->node_locks[node->locknum].lock));

	return (result);
}

static inline dns_result_t
find_deepest_zonecut(rbtdb_search_t *search, dns_dbnode_t **nodep,
		     dns_name_t *foundname, dns_rdataset_t *rdataset)
{
	unsigned int i;
	dns_rbtnode_t *node, *level_node;
	rdatasetheader_t *header, *header_prev, *header_next;
	dns_result_t result = DNS_R_NOTFOUND;
	dns_name_t name;
	dns_rbtdb_t *rbtdb;

	/*
	 * Caller must be holding the tree lock.
	 */

	rbtdb = search->rbtdb;
	i = search->chain.level_matches;
	while (i > 0) {
		i--;
		node = search->chain.levels[i];

		LOCK(&(rbtdb->node_locks[node->locknum].lock));
		
		/*
		 * Look for NS rdataset.
		 */
		header_prev = NULL;
		for (header = node->data;
		     header != NULL;
		     header = header_next) {
			header_next = header->next;
			if (header->ttl <= search->now) {
				/*
				 * This rdataset is stale.  If no one else is
				 * using the node, we can clean it up right
				 * now, otherwise we mark it as stale, and
				 * the node as dirty, so it will get cleaned
				 * up later.
				 */
				if (node->references == 0) {
					INSIST(header->down == NULL);
					if (header_prev != NULL)
						header_prev->next =
							header->next;
					else
						node->data = header->next;
					free_rdataset(rbtdb->common.mctx,
						      header);
				} else {
					header->attributes |=
						RDATASET_ATTR_STALE;
					node->dirty = 1;
					header_prev = header;
				}
			} else if (header->type == dns_rdatatype_ns &&
				   (header->attributes &
				    RDATASET_ATTR_NONEXISTENT) == 0)
				break;
			else
				header_prev = header;
		}

		if (header != NULL) {
			/*
			 * If we have to set foundname, we do it before
			 * anything else.  If we were to set foundname after
			 * we had set nodep or bound the rdataset, then we'd
			 * have to undo that work if dns_name_concatenate()
			 * failed.  By setting foundname first, there's
			 * nothing to undo if we have trouble.
			 */
			if (foundname != NULL) {
				dns_name_init(&name, NULL);
				dns_rbt_namefromnode(node, &name);
				result = dns_name_concatenate(&name, NULL,
							      foundname, NULL);
				while (result == DNS_R_SUCCESS && i != 0) {
					i--;
					level_node = search->chain.levels[i];
					dns_name_init(&name, NULL);
					dns_rbt_namefromnode(level_node,
							     &name);
					result =
						dns_name_concatenate(foundname,
								     &name,
								     foundname,
								     NULL);
				}
				if (result != DNS_R_SUCCESS) {
					*nodep = NULL;
					goto node_exit;
				}
			}
			result = DNS_R_DELEGATION;
			if (nodep != NULL) {
				new_reference(search->rbtdb, node);
				*nodep = node;
			}
			if (rdataset != NULL)
				bind_rdataset(search->rbtdb, node, header,
					      search->now, rdataset);
		}

	node_exit:
		UNLOCK(&(search->rbtdb->node_locks[node->locknum].lock));

		if (header != NULL)
			break;
	}

	return (result);
}

static dns_result_t
cache_find(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
	   dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	   dns_dbnode_t **nodep, dns_name_t *foundname,
	   dns_rdataset_t *rdataset)
{
	dns_rbtnode_t *node = NULL;
	dns_result_t result;
	rbtdb_search_t search;
	isc_boolean_t cname_ok = ISC_TRUE;
	isc_boolean_t empty_node;
	rdatasetheader_t *header, *header_prev, *header_next;
	rdatasetheader_t *found, *nsheader, *nxtheader;

	/*
	 * XXXRTH Currently this code has no support for negative caching.
	 */

	search.rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(search.rbtdb));
	REQUIRE(version == NULL);

	if (now == 0 && isc_stdtime_get(&now) != ISC_R_SUCCESS) {
		/*
		 * We don't need to call UNEXPECTED_ERROR() because
		 * isc_stdtime_get() will already have done so.
		 */
		return (DNS_R_UNEXPECTED);
	}

	search.rbtversion = NULL;
	search.serial = 1;
	search.options = options;
	search.copy_name = ISC_FALSE;
	search.need_cleanup = ISC_FALSE;
	search.zonecut = NULL;
	dns_fixedname_init(&search.zonecut_name);
	dns_rbtnodechain_init(&search.chain, search.rbtdb->common.mctx);
	search.now = now;

	RWLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * Search down from the root of the tree.  If, while going down, we
	 * encounter a callback node, cache_zonecut_callback() will search the
	 * rdatasets at the zone cut for a DNAME rdataset.
	 */
	result = dns_rbt_findnode(search.rbtdb->tree, name, foundname, &node,
				  &search.chain, ISC_TRUE,
				  cache_zonecut_callback, &search);

	if (result == DNS_R_PARTIALMATCH) {
		if (search.zonecut != NULL) {
		    result = setup_delegation(&search, nodep, foundname,
					      rdataset);
		    goto tree_exit;
		} else {
		find_ns:
			result = find_deepest_zonecut(&search, nodep,
						      foundname, rdataset);
			goto tree_exit;
		}
	} else if (result != DNS_R_SUCCESS)
		goto tree_exit;

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC 2535, section 2.3.5).
	 *
	 * XXX This should be a general purpose subroutine in the rdata
	 * module.
	 *
	 * XXX This 'if' could be an 'else if' of the 'if' above.
	 */
	if (type == dns_rdatatype_key ||
	    type == dns_rdatatype_sig ||
	    type == dns_rdatatype_nxt)
		cname_ok = ISC_FALSE;

	/*
	 * We now go looking for rdata...
	 */

	LOCK(&(search.rbtdb->node_locks[node->locknum].lock));
	
	found = NULL;
	nsheader = NULL;
	nxtheader = NULL;
	empty_node = ISC_TRUE;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->ttl <= now) {
			/*
			 * This rdataset is stale.  If no one else is using the
			 * node, we can clean it up right now, otherwise we
			 * mark it as stale, and the node as dirty, so it will
			 * get cleaned up later.
			 */
			if (node->references == 0) {
				INSIST(header->down == NULL);
				if (header_prev != NULL)
					header_prev->next = header->next;
				else
					node->data = header->next;
				free_rdataset(search.rbtdb->common.mctx,
					      header);
			} else {
				header->attributes |= RDATASET_ATTR_STALE;
				node->dirty = 1;
				header_prev = header;
			}
		} else if ((header->attributes & RDATASET_ATTR_NONEXISTENT)
			   == 0) {
			/*
			 * We now know that there is at least one active
			 * non-stale rdataset at this node.
			 */
			empty_node = ISC_FALSE;

			/*
			 * If we found a type we were looking for, we're done.
			 */
			if (header->type == type ||
			    type == dns_rdatatype_any ||
			    (cname_ok && header->type ==
			     dns_rdatatype_cname)) {
				found = header;
			} else if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nsheader = header;
			} else if (header->type == dns_rdatatype_nxt) {
				/*
				 * Remember a NXT rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nxtheader = header;
			}
			header_prev = header;
		} else
			header_prev = header;
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		goto find_ns;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL) {
		/*
		 * XXXDNSSEC  If we found an NXT record for this name, we
		 * can tell whether the desired type exists or not.  We don't
		 * yet try to use the NXT that way, but this is the place to
		 * do it.
		 */

		/*
		 * If there is an NS rdataset at this node, then this is the
		 * deepest zone cut.
		 */
		if (nsheader != NULL) {
			new_reference(search.rbtdb, node);
			*nodep = node;
			bind_rdataset(search.rbtdb, node, nsheader, search.now,
				      rdataset);
			result = DNS_R_DELEGATION;
			goto node_exit;
		}

		/*
		 * Go find the deepest zone cut.
		 */
		UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
		goto find_ns;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		new_reference(search.rbtdb, node);
		*nodep = node;
	}

	if (type != found->type &&
	    type != dns_rdatatype_any &&
	    found->type == dns_rdatatype_cname) {
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
		result = DNS_R_SUCCESS;
	}

	if (rdataset != NULL && type != dns_rdatatype_any)
		bind_rdataset(search.rbtdb, node, found, search.now,
			      rdataset);

 node_exit:
	UNLOCK(&(search.rbtdb->node_locks[node->locknum].lock));
	
 tree_exit:
	RWUNLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	INSIST(!search.need_cleanup);

	dns_rbtnodechain_reset(&search.chain);

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node = (dns_rbtnode_t *)source;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->node_locks[node->locknum].lock);
	INSIST(node->references > 0);
	node->references++;
	INSIST(node->references != 0);			/* Catch overflow. */
	UNLOCK(&rbtdb->node_locks[node->locknum].lock);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (dns_rbtnode_t *)(*targetp);

	LOCK(&rbtdb->node_locks[node->locknum].lock);

	INSIST(node->references > 0);
	node->references--;
	if (node->references == 0)
		no_references(rbtdb, node, 0);

	UNLOCK(&rbtdb->node_locks[node->locknum].lock);

	*targetp = NULL;
}

static dns_result_t
expirenode(dns_db_t *db, dns_dbnode_t *node, isc_stdtime_t now) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = node;
	rdatasetheader_t *header;

	REQUIRE(VALID_RBTDB(rbtdb));

	if (now == 0 && isc_stdtime_get(&now) != ISC_R_SUCCESS) {
		/*
		 * We don't need to call UNEXPECTED_ERROR() because
		 * isc_stdtime_get() will already have done so.
		 */
		return (DNS_R_UNEXPECTED);
	}

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->ttl <= now) {
			/*
			 * We don't check if rbtnode->references == 0 and try
			 * to free like we do in cache_find(), because
			 * rbtnode->references must be non-zero.  This is so
			 * because 'node' is an argument to the function.
			 */
			header->attributes |= RDATASET_ATTR_STALE;
			rbtnode->dirty = 1;
		}
	}

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	return (DNS_R_SUCCESS);
}

static void
printnode(dns_db_t *db, dns_dbnode_t *node, FILE *out) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = node;
	isc_boolean_t first;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	fprintf(out, "node %p, %u references, locknum = %u\n",
		rbtnode, rbtnode->references, rbtnode->locknum);
	if (rbtnode->data != NULL) {
		rdatasetheader_t *current, *top_next;

		for (current = rbtnode->data; current != NULL;
		     current = top_next) {
			top_next = current->next;
			first = ISC_TRUE;
			fprintf(out, "\ttype %u", current->type);
			do {
				if (!first)
					fprintf(out, "\t");
				first = ISC_FALSE;
				fprintf(out,
				"\tserial = %lu, ttl = %u, attributes = %u\n",
					(unsigned long)current->serial,
					current->ttl,
					current->attributes);
				current = current->down;
			} while (current != NULL);
		}
	} else
		fprintf(out, "(empty)\n");

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
}

static dns_result_t
createiterator(dns_db_t *db, isc_boolean_t relative_names,
	       dns_dbiterator_t **iteratorp)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_dbiterator_t *rbtdbiter;

	REQUIRE(VALID_RBTDB(rbtdb));

	rbtdbiter = isc_mem_get(rbtdb->common.mctx, sizeof *rbtdbiter);
	if (rbtdbiter == NULL)
		return (DNS_R_NOMEMORY);

	rbtdbiter->common.methods = &dbiterator_methods;
	dns_db_attach(db, &rbtdbiter->common.db);
	rbtdbiter->common.relative_names = relative_names;
	rbtdbiter->common.magic = DNS_DBITERATOR_MAGIC;
	rbtdbiter->paused = ISC_FALSE;
	rbtdbiter->tree_locked = ISC_FALSE;
	rbtdbiter->result = DNS_R_SUCCESS;
	dns_fixedname_init(&rbtdbiter->name);
	dns_fixedname_init(&rbtdbiter->origin);
	rbtdbiter->node = NULL;
	dns_rbtnodechain_init(&rbtdbiter->chain, db->mctx);

	*iteratorp = (dns_dbiterator_t *)rbtdbiter;

	return (DNS_R_SUCCESS);
}

static dns_result_t
zone_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		  dns_rdatatype_t type, isc_stdtime_t now,
		  dns_rdataset_t *rdataset)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rdatasetheader_t *header;
	rbtdb_serial_t serial;
	rbtdb_version_t *rbtversion = version;
	isc_boolean_t close_version = ISC_FALSE;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(type != dns_rdatatype_any);

	if (rbtversion == NULL) {
		currentversion(db, (dns_dbversion_t **)(&rbtversion));
		close_version = ISC_TRUE;
	}
	serial = rbtversion->serial;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->type == type) {
			do {
				if (header->serial <= serial &&
				    !IGNORE(header)) {
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 */
					if ((header->attributes &
					     RDATASET_ATTR_NONEXISTENT) != 0)
						header = NULL;
					break;
				} else
					header = header->down;
			} while (header != NULL);
			break;
		}
	}
	if (header != NULL)
		bind_rdataset(rbtdb, rbtnode, header, now, rdataset);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	if (close_version)
		closeversion(db, (dns_dbversion_t **)(&rbtversion), ISC_FALSE);

	if (header == NULL)
		return (DNS_R_NOTFOUND);

	return (DNS_R_SUCCESS);
}

static dns_result_t
cache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdatatype_t type, isc_stdtime_t now,
		   dns_rdataset_t *rdataset)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rdatasetheader_t *header, *header_next, *found;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(type != dns_rdatatype_any);

	version = NULL;		/* Keep compilers quiet. */

	if (now == 0 && isc_stdtime_get(&now) != ISC_R_SUCCESS) {
		/*
		 * We don't need to call UNEXPECTED_ERROR() because
		 * isc_stdtime_get() will already have done so.
		 */
		return (DNS_R_UNEXPECTED);
	}

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	found = NULL;
	for (header = rbtnode->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->ttl <= now) {
			/*
			 * We don't check if rbtnode->references == 0 and try
			 * to free like we do in cache_find(), because
			 * rbtnode->references must be non-zero.  This is so
			 * because 'node' is an argument to the function.
			 */
			header->attributes |= RDATASET_ATTR_STALE;
			rbtnode->dirty = 1;
		} else if (header->type == type &&
			   (header->attributes & RDATASET_ATTR_NONEXISTENT) ==
			   0) {
			found = header;
		}
	}
	if (found != NULL)
		bind_rdataset(rbtdb, rbtnode, found, now, rdataset);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	if (found == NULL)
		return (DNS_R_NOTFOUND);

	return (DNS_R_SUCCESS);
}

static dns_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, dns_rdatasetiter_t **iteratorp)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	rbtdb_rdatasetiter_t *iterator;

	REQUIRE(VALID_RBTDB(rbtdb));

	iterator = isc_mem_get(rbtdb->common.mctx, sizeof *iterator);
	if (iterator == NULL)
		return (DNS_R_NOMEMORY);

	if ((db->attributes & DNS_DBATTR_CACHE) == 0) {
		now = 0;
		if (rbtversion == NULL)
			currentversion(db, (dns_dbversion_t **)(&rbtversion));
		else {
			LOCK(&rbtdb->lock);
			INSIST(rbtversion->references > 0);
			rbtversion->references++;
			INSIST(rbtversion->references != 0);
			UNLOCK(&rbtdb->lock);
		}
	} else {
		if (now == 0 && isc_stdtime_get(&now) != ISC_R_SUCCESS) {
			/*
			 * We don't need to call UNEXPECTED_ERROR() because
			 * isc_stdtime_get() will already have done so.
			 */
			isc_mem_put(rbtdb->common.mctx, iterator,
				    sizeof *iterator);
			return (DNS_R_UNEXPECTED);
		}
		rbtversion = NULL;
	}

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = (dns_dbversion_t *)rbtversion;
	iterator->common.now = now;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
	
	INSIST(rbtnode->references > 0);
	rbtnode->references++;
	INSIST(rbtnode->references != 0);
	iterator->current = NULL;

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (DNS_R_SUCCESS);
}

static dns_result_t
add(dns_rbtdb_t *rbtdb, dns_rbtnode_t *rbtnode, rbtdb_version_t *rbtversion,
    rdatasetheader_t *newheader, isc_boolean_t merge, isc_boolean_t loading,
    dns_rdataset_t *addedrdataset, isc_stdtime_t now)
{
	rbtdb_changed_t *changed = NULL;
	rdatasetheader_t *header, *header_prev;
	unsigned char *merged;
	dns_result_t result;

	/*
	 * Add an rdatasetheader_t to a node.
	 */

	/*
	 * Caller must be holding the node lock.
	 */

	if (rbtversion != NULL && !loading) {
		changed = add_changed(rbtdb, rbtversion, rbtnode);
		if (changed == NULL)
			return (DNS_R_NOMEMORY);
	}

	header_prev = NULL;
	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->type == newheader->type)
			break;
		header_prev = header;
	}
	if (header != NULL) {
		/*
		 * Don't merge if a nonexistent rdataset is involved.
		 */
		if (merge &&
		    ((newheader->attributes & RDATASET_ATTR_NONEXISTENT) != 0
		     || (header->attributes & RDATASET_ATTR_NONEXISTENT) != 0))
			merge = ISC_FALSE;
		/*
		 * If 'merge' is ISC_TRUE, we'll try to create a new rdataset
		 * that is the union of 'newheader' and 'header'.
		 */
		if (merge) {
			INSIST(rbtversion->serial >= header->serial);
			merged = NULL;
			result = dns_rdataslab_merge(
					     (unsigned char *)header,
					     (unsigned char *)newheader,
					     (unsigned int)(sizeof *newheader),
					     rbtdb->common.mctx,
					     rbtdb->common.rdclass,
					     header->type,
					     &merged);
			if (result == DNS_R_SUCCESS) {
				/*
				 * If 'header' has the same serial number as
				 * we do, we could clean it up now if we knew
				 * that our caller had no references to it.
				 * We don't know this, however, so we leave it
				 * alone.  It will get cleaned up when
				 * clean_zone_node() runs.
				 */
				free_rdataset(rbtdb->common.mctx, newheader);
				newheader = (rdatasetheader_t *)merged;
			} else {
				free_rdataset(rbtdb->common.mctx, newheader);
				if (result == DNS_R_UNCHANGED) {
					if (addedrdataset != NULL)
						bind_rdataset(rbtdb, rbtnode,
							      header, now,
							      addedrdataset);
					return (DNS_R_SUCCESS);
				}
				return (result);
			}
		}
		INSIST(rbtversion == NULL ||
		       rbtversion->serial >= header->serial);
		if (header_prev != NULL)
			header_prev->next = newheader;
		else
			rbtnode->data = newheader;
		newheader->next = header->next;
		if (loading) {
			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			newheader->down = NULL;
			free_rdataset(rbtdb->common.mctx, header);
		} else {
			newheader->down = header;
			header->next = newheader;
			rbtnode->dirty = 1;
			if (changed != NULL)
				changed->dirty = ISC_TRUE;
		}
	} else {
		/*
		 * The rdataset type doesn't exist at this node.
		 */
		newheader->next = rbtnode->data;
		newheader->down = NULL;
		rbtnode->data = newheader;
	}

	if (addedrdataset != NULL)
		bind_rdataset(rbtdb, rbtnode, newheader, now, addedrdataset);

	return (DNS_R_SUCCESS);
}

static inline isc_boolean_t
delegating_type(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		dns_rdatatype_t type)
{
	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) != 0 &&
	    type == dns_rdatatype_dname)
		return (ISC_TRUE);
	else if (type == dns_rdatatype_dname ||
		 (type == dns_rdatatype_ns && node != rbtdb->origin_node))
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static dns_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset,
	    dns_rdataset_t *addedrdataset)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	isc_region_t region;
	rdatasetheader_t *newheader;
	dns_result_t result;
	isc_boolean_t merge, delegating;

	REQUIRE(VALID_RBTDB(rbtdb));

	if (rbtversion == NULL) {
		if (now == 0 && isc_stdtime_get(&now) != ISC_R_SUCCESS)
			return (DNS_R_UNEXPECTED);
	} else
		now = 0;

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region,
					    sizeof (rdatasetheader_t));
	if (result != DNS_R_SUCCESS)
		return (result);

	newheader = (rdatasetheader_t *)region.base;
	newheader->ttl = rdataset->ttl + now;
	newheader->type = rdataset->type;
	newheader->attributes = 0;
	if (rbtversion != NULL) {
		newheader->serial = rbtversion->serial;
		merge = ISC_TRUE;
		now = 0;
	} else {
		newheader->serial = 1;
		merge = ISC_FALSE;
	}

	/*
	 * If we're adding a delegation type (e.g. NS or DNAME for a zone,
	 * just DNAME for the cache), then we need to set the callback bit
	 * on the node, and to do that we must be holding an exclusive lock
	 * on the tree.
	 */
	if (delegating_type(rbtdb, rbtnode, rdataset->type)) {
		delegating = ISC_TRUE;
		RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	} else
		delegating = ISC_FALSE;
		
	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	result = add(rbtdb, rbtnode, rbtversion, newheader, merge, ISC_FALSE,
		     addedrdataset, now);
	if (result == DNS_R_SUCCESS && delegating)
		rbtnode->find_callback = 1;

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	if (delegating)
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);

	return (result);
}

static dns_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	dns_result_t result;
	rdatasetheader_t *newheader;

	REQUIRE(VALID_RBTDB(rbtdb));

	if (type == dns_rdatatype_any)
		return (DNS_R_NOTIMPLEMENTED);

	newheader = isc_mem_get(rbtdb->common.mctx, sizeof *newheader);
	if (newheader == NULL)
		return (DNS_R_NOMEMORY);
	newheader->ttl = 0;
	newheader->type = type;
	newheader->attributes = RDATASET_ATTR_NONEXISTENT;
	if (rbtversion != NULL)
		newheader->serial = rbtversion->serial;
	else
		newheader->serial = 0;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	result = add(rbtdb, rbtnode, rbtversion, newheader, ISC_FALSE,
		     ISC_FALSE, NULL, 0);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	return (result);
}

static dns_result_t
add_rdataset_callback(dns_rdatacallbacks_t *callbacks, dns_name_t *name,
		      dns_rdataset_t *rdataset)
{
	rbtdb_load_t *loadctx = callbacks->commit_private;
	dns_rbtdb_t *rbtdb = loadctx->rbtdb;
	dns_rbtnode_t *node = NULL;
	dns_result_t result;
	isc_region_t region;
	rdatasetheader_t *newheader;
	dns_name_t foundname;

	/*
	 * This routine does no node locking.  See comments in
	 * 'load' below for more information on loading and
	 * locking.
	 */

	result = dns_rbt_addnode(rbtdb->tree, name, &node);
	if (result != DNS_R_SUCCESS && result != DNS_R_EXISTS)
		return (result);
	if (result != DNS_R_EXISTS) {
		dns_name_init(&foundname, NULL);
		dns_rbt_namefromnode(node, &foundname);
		node->locknum = dns_name_hash(&foundname, ISC_TRUE) %
			rbtdb->node_lock_count;
	}

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region,
					    sizeof (rdatasetheader_t));
	if (result != DNS_R_SUCCESS)
		return (result);
	newheader = (rdatasetheader_t *)region.base;
	newheader->ttl = rdataset->ttl + loadctx->now; /* XXX overflow check */
	newheader->type = rdataset->type;
	newheader->attributes = 0;
	newheader->serial = 1;

	result = add(rbtdb, node, rbtdb->current_version, newheader, ISC_TRUE,
		     ISC_TRUE, NULL, 0);
	if (result == DNS_R_SUCCESS &&
	    delegating_type(rbtdb, node, rdataset->type))
		node->find_callback = 1;

	return (result);
}

static dns_result_t
load(dns_db_t *db, char *filename) {
	rbtdb_load_t loadctx;
	dns_rbtdb_t *rbtdb;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;
	dns_result_t result;
	dns_name_t name;
	isc_boolean_t age_ttl;
	
	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	loadctx.rbtdb = rbtdb;
	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) != 0) {
		if (isc_stdtime_get(&loadctx.now) != DNS_R_SUCCESS)
			return (DNS_R_UNEXPECTED);
		age_ttl = ISC_TRUE;
	} else {
		loadctx.now = 0;
		age_ttl = ISC_FALSE;
	}

	LOCK(&rbtdb->lock);

	REQUIRE((rbtdb->attributes & RBTDB_ATTR_LOADED) == 0);
	/*
	 * We set RBTDB_ATTR_LOADED even though we don't know the
	 * load is going to succeed because we don't want someone to try
	 * again with partial prior load results if a load fails.
	 */
	rbtdb->attributes |= RBTDB_ATTR_LOADED;

	UNLOCK(&rbtdb->lock);

	/*
	 * In order to set the node callback bit correctly in zone databases,
	 * we need to know if the node has the origin name of the zone.
	 * In add_rdataset_callback(), we could simply compare the new name
	 * to the origin name, but this is expensive.  Also, we don't know the
	 * node name in addrdataset(), so we need another way of knowing the
	 * zone's top.
	 *
	 * We now explicitly create a node for the zone's origin, and then
	 * we simply remember the node's address.  This is safe, because
	 * the top-of-zone node can never be deleted, nor can its address
	 * change.
	 */
	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) == 0) {
		result = dns_rbt_addnode(rbtdb->tree, &rbtdb->common.origin,
					 &rbtdb->origin_node);
		if (result != DNS_R_SUCCESS) {
			INSIST(result != DNS_R_EXISTS);
			return (result);
		}
		dns_name_init(&name, NULL);
		dns_rbt_namefromnode(rbtdb->origin_node, &name);
		rbtdb->origin_node->locknum =
			dns_name_hash(&name, ISC_TRUE) %
			rbtdb->node_lock_count;
	}

	dns_rdatacallbacks_init(&callbacks);
	callbacks.commit = add_rdataset_callback;
	callbacks.commit_private = &loadctx;

	return (dns_master_load(filename, &rbtdb->common.origin, 
				&rbtdb->common.origin, rbtdb->common.rdclass,
				age_ttl, &soacount, &nscount, &callbacks,
				rbtdb->common.mctx));
}

static dns_result_t
dump(dns_db_t *db, dns_dbversion_t *version, char *filename) {
	dns_rbtdb_t *rbtdb;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	return (dns_master_dump(rbtdb->common.mctx, db, version, 
				&dns_master_style_default,
				filename));
}

static void
delete_callback(void *data, void *arg) {
	dns_rbtdb_t *rbtdb = arg;
	rdatasetheader_t *current, *next;

	for (current = data; current != NULL; current = next) {
		next = current->next;
		free_rdataset(rbtdb->common.mctx, current);
	}
}

static dns_dbmethods_t zone_methods = {
	attach,
	detach,
	load,
	dump,
	currentversion,
	newversion,
	attachversion,
	closeversion,
	findnode,
	zone_find,
	attachnode,
	detachnode,
	expirenode,
	printnode,
	createiterator,
	zone_findrdataset,
	allrdatasets,
	addrdataset,
	deleterdataset
};

static dns_dbmethods_t cache_methods = {
	attach,
	detach,
	load,
	dump,
	currentversion,
	newversion,
	attachversion,
	closeversion,
	findnode,
	cache_find,
	attachnode,
	detachnode,
	expirenode,
	printnode,
	createiterator,
	cache_findrdataset,
	allrdatasets,
	addrdataset,
	deleterdataset
};

dns_result_t
#ifdef DNS_RBTDB_VERSION64
dns_rbtdb64_create
#else
dns_rbtdb_create
#endif
		(isc_mem_t *mctx, dns_name_t *origin, isc_boolean_t cache,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 dns_db_t **dbp)
{
	dns_rbtdb_t *rbtdb;
	isc_result_t iresult;
	dns_result_t dresult;
	int i;
	isc_region_t r1, r2;

	/* Keep the compiler happy. */
	(void)argc;
	(void)argv;

	rbtdb = isc_mem_get(mctx, sizeof *rbtdb);
	if (rbtdb == NULL)
		return (DNS_R_NOMEMORY);
	memset(rbtdb, '\0', sizeof *rbtdb);
	rbtdb->common.attributes = 0;
	if (cache) {
		rbtdb->common.methods = &cache_methods;
		rbtdb->common.attributes |= DNS_DBATTR_CACHE;
	} else
		rbtdb->common.methods = &zone_methods;
	rbtdb->common.rdclass = rdclass;
	rbtdb->common.mctx = mctx;

	iresult = isc_mutex_init(&rbtdb->lock);
	if (iresult != ISC_R_SUCCESS) {
		isc_mem_put(rbtdb->common.mctx, rbtdb, sizeof *rbtdb);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	iresult = isc_rwlock_init(&rbtdb->tree_lock, 0, 0);
	if (iresult != ISC_R_SUCCESS) {
		isc_mutex_destroy(&rbtdb->lock);
		isc_mem_put(rbtdb->common.mctx, rbtdb, sizeof *rbtdb);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	INSIST(rbtdb->node_lock_count < (1 << DNS_RBT_LOCKLENGTH));

	if (rbtdb->node_lock_count == 0)
		rbtdb->node_lock_count = DEFAULT_NODE_LOCK_COUNT;
	rbtdb->node_locks = isc_mem_get(mctx, rbtdb->node_lock_count * 
					sizeof (rbtdb_nodelock_t));
	for (i = 0; i < (int)(rbtdb->node_lock_count); i++) {
		iresult = isc_mutex_init(&rbtdb->node_locks[i].lock);
		if (iresult != ISC_R_SUCCESS) {
			i--;
			while (i >= 0) {
				isc_mutex_destroy(&rbtdb->node_locks[i].lock);
				i--;
			}
			isc_mem_put(mctx, rbtdb->node_locks,
				    rbtdb->node_lock_count *  
				    sizeof (rbtdb_nodelock_t));
			isc_rwlock_destroy(&rbtdb->tree_lock);
			isc_mutex_destroy(&rbtdb->lock);
			isc_mem_put(rbtdb->common.mctx, rbtdb, sizeof *rbtdb);
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_mutex_init() failed: %s",
					 isc_result_totext(iresult));
			return (DNS_R_UNEXPECTED);
		}
		rbtdb->node_locks[i].references = 0;
	}

	/*
	 * Make a copy of the origin name.
	 */
	dns_name_init(&rbtdb->common.origin, NULL);
	dns_name_toregion(origin, &r1);
	r2.base = isc_mem_get(mctx, r1.length);
	if (r2.base == NULL) {
		free_rbtdb(rbtdb);
		return (DNS_R_NOMEMORY);
	}
	r2.length = r1.length;
	memcpy(r2.base, r1.base, r1.length);
	dns_name_fromregion(&rbtdb->common.origin, &r2);

	rbtdb->origin_node = NULL;

	/*
	 * Make the Red-Black Tree.
	 */
	dresult = dns_rbt_create(mctx, delete_callback, rbtdb, &rbtdb->tree);
	if (dresult != DNS_R_SUCCESS) {
		free_rbtdb(rbtdb);
		return (dresult);
	}

	rbtdb->references = 1;
	rbtdb->attributes = 0;

	/*
	 * Version Initialization.
	 */
	rbtdb->current_serial = 1;
	rbtdb->least_serial = 1;
	rbtdb->next_serial = 2;
	rbtdb->current_version = allocate_version(mctx, 1, 0, ISC_FALSE);
	if (rbtdb->current_version == NULL) {
		free_rbtdb(rbtdb);
		return (DNS_R_NOMEMORY);
	}
	rbtdb->future_version = NULL;
	ISC_LIST_INIT(rbtdb->open_versions);

	rbtdb->common.magic = DNS_DB_MAGIC;
	rbtdb->common.impmagic = RBTDB_MAGIC;

	*dbp = (dns_db_t *)rbtdb;

	return (ISC_R_SUCCESS);
}


/*
 * Slabbed Rdataset Methods
 */

static dns_result_t
rdataset_disassociate(dns_rdataset_t *rdataset) {
	dns_db_t *db = rdataset->private1;
	dns_dbnode_t *node = rdataset->private2;

	detachnode(db, &node);

	return (DNS_R_SUCCESS);
}

static dns_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3;
	unsigned int count;

	count = raw[0] * 256 + raw[1];
	if (count == 0) {
		rdataset->private5 = NULL;
		return (DNS_R_NOMORE);
	}
	raw += 2;
	/*
	 * The private4 field is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before storing
	 * it.
	 */
	count--;
	rdataset->private4 = (void *)count;
	rdataset->private5 = raw;

	return (DNS_R_SUCCESS);
}

static dns_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	unsigned int count;
	unsigned int length;
	unsigned char *raw;

	count = (unsigned int)rdataset->private4;
	if (count == 0)
		return (DNS_R_NOMORE);
	count--;
	rdataset->private4 = (void *)count;
	raw = rdataset->private5;
	length = raw[0] * 256 + raw[1];
	raw += length + 2;
	rdataset->private5 = raw;

	return (DNS_R_SUCCESS);
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->private5;
	isc_region_t r;

	REQUIRE(raw != NULL);

	r.length = raw[0] * 256 + raw[1];
	raw += 2;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
}


/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	rbtdb_rdatasetiter_t *rbtiterator;

	rbtiterator = (rbtdb_rdatasetiter_t *)(*iteratorp);

	if (rbtiterator->common.version != NULL)
		closeversion(rbtiterator->common.db,
			     &rbtiterator->common.version, ISC_FALSE);
	detachnode(rbtiterator->common.db, &rbtiterator->common.node);
	isc_mem_put(rbtiterator->common.db->mctx, rbtiterator,
		    sizeof *rbtiterator);
	
	*iteratorp = NULL;
}

static dns_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rbtdb_version_t *rbtversion = rbtiterator->common.version;
	rdatasetheader_t *header, *top_next;
	rbtdb_serial_t serial;
	isc_stdtime_t now;

	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) == 0) {
		serial = rbtversion->serial;
		now = 0;
	} else {
		serial = 1;
		now = rbtiterator->common.now;
	}

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = rbtnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (header->serial <= serial && !IGNORE(header)) {
				/*
				 * Is this a "this rdataset doesn't
				 * exist" record?
				 */
				if ((header->attributes &
				     RDATASET_ATTR_NONEXISTENT) != 0 ||
				    (now != 0 && now >= header->ttl))
					header = NULL;
				break;
			} else
				header = header->down;
		} while (header != NULL);
		if (header != NULL)
			break;
	}

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	rbtiterator->current = header;

	if (header == NULL)
		return (DNS_R_NOMORE);

	return (DNS_R_SUCCESS);
}

static dns_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rbtdb_version_t *rbtversion = rbtiterator->common.version;
	rdatasetheader_t *header, *top_next;
	rbtdb_serial_t serial;
	isc_stdtime_t now;
	dns_rdatatype_t type;

	header = rbtiterator->current;
	if (header == NULL)
		return (DNS_R_NOMORE);

	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) == 0) {
		serial = rbtversion->serial;
		now = 0;
	} else {
		serial = 1;
		now = rbtiterator->common.now;
	}

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	type = header->type;
	for (header = header->next; header != NULL; header = top_next) {
		top_next = header->next;
		if (header->type != type) {
			do {
				if (header->serial <= serial &&
				    !IGNORE(header)) {
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 */
					if ((header->attributes &
					     RDATASET_ATTR_NONEXISTENT) != 0 ||
					    (now != 0 && now >= header->ttl))
						header = NULL;
					break;
				} else
					header = header->down;
			} while (header != NULL);
			if (header != NULL)
				break;
		}
	}

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	rbtiterator->current = header;

	if (header == NULL)
		return (DNS_R_NOMORE);

	return (DNS_R_SUCCESS);
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rdatasetheader_t *header;

	header = rbtiterator->current;
	REQUIRE(header != NULL);
	
	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	bind_rdataset(rbtdb, rbtnode, header, rbtiterator->common.now,
		      rdataset);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
}


/*
 * Database Iterator Methods
 */

static inline void
unpause(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;
	dns_rbtnode_t *node = rbtdbiter->node;

	if (rbtdbiter->paused) {
		LOCK(&rbtdb->node_locks[node->locknum].lock);
		INSIST(node->references > 0);
		node->references--;
		if (node->references == 0)
			no_references(rbtdb, node, 0);
		UNLOCK(&rbtdb->node_locks[node->locknum].lock);
		rbtdbiter->paused = ISC_FALSE;
	}
}

static inline void
resume_iteration(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;

	REQUIRE(rbtdbiter->paused);
	REQUIRE(!rbtdbiter->tree_locked);

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	rbtdbiter->tree_locked = ISC_TRUE;

	unpause(rbtdbiter);
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp) {
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)(*iteratorp);
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;

	if (rbtdbiter->tree_locked)
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);

	unpause(rbtdbiter);

	dns_db_detach(&rbtdbiter->common.db);

	dns_rbtnodechain_reset(&rbtdbiter->chain);
	isc_mem_put(rbtdb->common.mctx, rbtdbiter, sizeof *rbtdbiter);

	*iteratorp = NULL;
}

static dns_result_t
dbiterator_first(dns_dbiterator_t *iterator) {
	dns_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	dns_name_t *name, *origin;
	
	if (rbtdbiter->result != DNS_R_SUCCESS &&
	    rbtdbiter->result != DNS_R_NOMORE)
		return (rbtdbiter->result);

	unpause(rbtdbiter);

	if (!rbtdbiter->tree_locked) {
		RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
		rbtdbiter->tree_locked = ISC_TRUE;
	}

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	dns_rbtnodechain_reset(&rbtdbiter->chain);
	result = dns_rbtnodechain_first(&rbtdbiter->chain, rbtdb->tree, name,
					origin);
	if (result != DNS_R_NEWORIGIN) {
		INSIST(result != DNS_R_SUCCESS);
		if (result == DNS_R_NOTFOUND) {
			/*
			 * The tree is empty.
			 */
			result = DNS_R_NOMORE;
		}
		rbtdbiter->node = NULL;
	} else {
		result = dns_rbtnodechain_current(&rbtdbiter->chain, NULL,
						  NULL, &rbtdbiter->node);
		if (result == DNS_R_SUCCESS)
			rbtdbiter->new_origin = ISC_TRUE;
		else
			rbtdbiter->node = NULL;
	}
	rbtdbiter->result = result;

	return (result);
}

static dns_result_t
dbiterator_next(dns_dbiterator_t *iterator) {
	dns_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_name_t *name, *origin;

	REQUIRE(rbtdbiter->node != NULL);

	if (rbtdbiter->result != DNS_R_SUCCESS)
		return (rbtdbiter->result);

	if (rbtdbiter->paused)
		resume_iteration(rbtdbiter);

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	result = dns_rbtnodechain_next(&rbtdbiter->chain, name, origin);
	if (result == DNS_R_NEWORIGIN || result == DNS_R_SUCCESS) {
		if (result == DNS_R_NEWORIGIN)
			rbtdbiter->new_origin = ISC_TRUE;
		else
			rbtdbiter->new_origin = ISC_FALSE;
		result = dns_rbtnodechain_current(&rbtdbiter->chain, NULL,
						  NULL, &rbtdbiter->node);
		if (result != DNS_R_SUCCESS) {
			rbtdbiter->result = result;
			rbtdbiter->node = NULL;
		}
	} else
		rbtdbiter->result = result;

	return (result);
}

static inline isc_boolean_t
rootname(dns_name_t *name) {
	if (dns_name_countlabels(name) == 1 && dns_name_isabsolute(name))
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static dns_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtnode_t *node = rbtdbiter->node;
	dns_result_t result;
	dns_name_t *nodename = dns_fixedname_name(&rbtdbiter->name);
	dns_name_t *origin = dns_fixedname_name(&rbtdbiter->origin);

	REQUIRE(rbtdbiter->result == DNS_R_SUCCESS);
	REQUIRE(rbtdbiter->node != NULL);

	if (rbtdbiter->paused)
		resume_iteration(rbtdbiter);

	if (name != NULL) {
		if (rbtdbiter->common.relative_names || rootname(nodename))
			origin = NULL;
		result = dns_name_concatenate(nodename, origin, name, NULL);
		if (result != DNS_R_SUCCESS)
			return (result);
		if (rbtdbiter->common.relative_names && rbtdbiter->new_origin)
			result = DNS_R_NEWORIGIN;
	} else
		result = DNS_R_SUCCESS;
		
	LOCK(&rbtdb->node_locks[node->locknum].lock);
	new_reference(rbtdb, node);
	UNLOCK(&rbtdb->node_locks[node->locknum].lock);

	*nodep = rbtdbiter->node;

	return (result);
}

static dns_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtnode_t *node = rbtdbiter->node;

	if (rbtdbiter->result != DNS_R_SUCCESS)
		return (rbtdbiter->result);

	REQUIRE(!rbtdbiter->paused);
	REQUIRE(rbtdbiter->tree_locked);
	REQUIRE(node != NULL);

	LOCK(&rbtdb->node_locks[node->locknum].lock);
	new_reference(rbtdb, node);
	UNLOCK(&rbtdb->node_locks[node->locknum].lock);

	rbtdbiter->paused = ISC_TRUE;

	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	rbtdbiter->tree_locked = ISC_FALSE;

	return (DNS_R_SUCCESS);
}

static dns_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_name_t *origin = dns_fixedname_name(&rbtdbiter->origin);

	if (rbtdbiter->result != DNS_R_SUCCESS)
		return (rbtdbiter->result);

	return (dns_name_concatenate(origin, NULL, name, NULL));
}
