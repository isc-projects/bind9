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

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>
#include <isc/rwlock.h>

#include <dns/name.h>
#include <dns/rbt.h>
#include <dns/master.h>
#include <dns/rdataslab.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>

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

static const rbtdb_serial_t		max_serial = ~((rbtdb_serial_t)0);

typedef struct rdatasetheader {
	/* Not locked. */
	dns_ttl_t			ttl;
	rbtdb_serial_t			serial;
	dns_rdatatype_t			type;
	isc_uint16_t			attributes;
	/*
	 * We don't use the LIST macros, because the LIST structure has
	 * both head and tail pointers.  We only have a head pointer in
	 * the node to save space.
	 */
	struct rdatasetheader		*prev;
	struct rdatasetheader		*next;
	struct rdatasetheader		*down;
} rdatasetheader_t;

#define RDATASET_ATTR_NONEXISTENT	0x01

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
	rbtdb_serial_t			serial;
	unsigned int			references;
	isc_boolean_t			writer;
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

static void
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

static rbtdb_changed_t *
add_changed(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
	    dns_rbtnode_t *node)
{
	rbtdb_changed_t *changed;

	/*
	 * Caller must be holding the node lock.
	 */

	changed = isc_mem_get(rbtdb->common.mctx, sizeof *changed);
	if (changed == NULL) {
		version->commit_ok = ISC_FALSE;
		return (NULL);
	}
	node->references++;
	changed->node = node;
	changed->dirty = ISC_FALSE;
	APPEND(version->changed_list, changed, link);

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

static void
rollback_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node, rbtdb_serial_t serial) {
	rdatasetheader_t *header, *header_next;

	/*
	 * Caller must hold the node lock.
	 */

	REQUIRE(node->references == 0);

	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->serial == serial) {
			if (header->down != NULL) {
				header->down->prev = header->prev;
				if (header->prev != NULL)
					header->prev->next = header->down;
				else
					node->data = header->down;
				header->down->next = header->next;
				if (header->next != NULL)
					header->next->prev = header->down;
			} else {
				if (header->prev != NULL)
					header->prev->next = header->next;
				else
					node->data = header->next;
				if (header->next != NULL)
					header->next->prev = header->prev;
			}
			free_rdataset(rbtdb->common.mctx, header);
		}
	}
}

static inline void
clean_cache_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node) {
	rdatasetheader_t *current, *dcurrent, *top_next, *down_next;
	isc_mem_t *mctx = rbtdb->common.mctx;

	/*
	 * Caller must be holding the node lock.
	 */

	/* XXX should remove stale data. */

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
	}
}

static inline void
clean_zone_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		rbtdb_serial_t least_serial)
{
	rdatasetheader_t *current, *dcurrent, *top_next, *down_next, *dparent;
	isc_mem_t *mctx = rbtdb->common.mctx;
	isc_boolean_t still_dirty = ISC_FALSE;

	/*
	 * Caller must be holding the node lock.
	 */
	REQUIRE(least_serial != 0);

	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;
		/*
		 * Find the first rdataset less than the least serial, if
		 * any.
		 */
		dparent = current;
		for (dcurrent = current->down;
		     dcurrent != NULL;
		     dcurrent = dcurrent->down) {
			INSIST(dcurrent->serial < dparent->serial);
			if (dcurrent->serial < least_serial)
				break;
			dparent = dcurrent;
		}
		/*
		 * If there is a such an rdataset, delete it and any older
		 * versions.
		 */
		if (dcurrent != NULL) {
			do {
				down_next = dcurrent->down;
				INSIST(dcurrent->serial < least_serial);
				free_rdataset(mctx, dcurrent);
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
		if (current->down != NULL)
			still_dirty = ISC_TRUE;
		else {
			/*
			 * If this is a NONEXISTENT rdataset, we can delete it.
			 */
			if ((current->attributes & RDATASET_ATTR_NONEXISTENT)
			    != 0) {
				if (current->prev != NULL)
					current->prev->next = current->next;
				else
					node->data = current->next;
				if (current->next != NULL)
					current->next->prev = current->prev;
				free_rdataset(mctx, current);
			}
		}
	}
	if (!still_dirty)
		node->dirty = 0;
}

static inline void
no_references(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
	      rbtdb_serial_t least_serial)
{
	/*
	 * Caller must be holding the node lock.
	 */
	REQUIRE(node->references == 0);

	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) != 0)
		clean_cache_node(rbtdb, node);
	else if (node->dirty) {
		if (least_serial == 0) {
			/*
			 * Caller doesn't know the least serial.  Get it.
			 */
			LOCK(&rbtdb->lock);
			least_serial = rbtdb->least_serial;
			UNLOCK(&rbtdb->lock);
		}
		clean_zone_node(rbtdb, node, least_serial);
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
	rbtdb_version_t *version, *cleanup_version, *next_greater_version;
	isc_boolean_t rollback = ISC_FALSE;
	rbtdb_changedlist_t cleanup_list;
	rbtdb_changed_t *changed, *next_changed;
	rbtdb_serial_t serial, least_serial;
	dns_rbtnode_t *rbtnode;
	
	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp != NULL);
	version = (rbtdb_version_t *)*versionp;

	cleanup_version = NULL;
	ISC_LIST_INIT(cleanup_list);

	LOCK(&rbtdb->lock);
	INSIST((version->writer && version->references == 1) ||
	       version->references > 0);
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
			/* XXX wake up waiting updates */
		} else {
			if (version != rbtdb->current_version) {
				/*
				 * There are no external or internal references
				 * to this version and it can be cleaned up.
				 */
				cleanup_version = version;
			}
			/*
			 * Find the open version with the next-greater serial
			 * number than ours.
			 */
			next_greater_version = PREV(version, link);
			if (next_greater_version == NULL)
				next_greater_version = rbtdb->current_version;
			/*
			 * Is this the least open version?
			 */
			if (version->serial == rbtdb->least_serial) {
				/*
				 * Yes.  Install the new least open version.
				 */
				make_least_version(rbtdb,
						   next_greater_version,
						   &cleanup_list);
			} else if (version != rbtdb->current_version) {
				/*
				 * Add any unexecuted cleanups to those of
				 * the next-greater version.
				 */
				APPENDLIST(next_greater_version->changed_list,
					   version->changed_list, link);
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

			/* 
			 * XXX Like the rest of this module, this code doesn't
			 * deal with node splits.
			 */

			INSIST(rbtnode->references > 0);
			rbtnode->references--;
			if (rollback)
				rollback_node(rbtdb, rbtnode, serial);

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
	dns_name_t foundname;
	unsigned int locknum;
	dns_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(VALID_RBTDB(rbtdb));

	dns_name_init(&foundname, NULL);
	RWLOCK(&rbtdb->tree_lock, locktype);
	result = dns_rbt_findnode(rbtdb->tree, name, &node, NULL);
 again:
	if (result == DNS_R_SUCCESS) {
		locknum = node->locknum;
		LOCK(&rbtdb->node_locks[locknum].lock);
		if (node->data == NULL && !create) {
			UNLOCK(&rbtdb->node_locks[locknum].lock);
			RWUNLOCK(&rbtdb->tree_lock, locktype);
			return (DNS_R_NOTFOUND);
		}
		if (node->references == 0)
			rbtdb->node_locks[locknum].references++;
		node->references++;
		UNLOCK(&rbtdb->node_locks[locknum].lock);
	} else {
		RWUNLOCK(&rbtdb->tree_lock, locktype);
		if (!create)
			return (DNS_R_NOTFOUND);
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
		dns_rbt_namefromnode(node, &foundname);
		node->locknum = dns_name_hash(&foundname, ISC_TRUE) %
			rbtdb->node_lock_count;
		goto again;
	}
	RWUNLOCK(&rbtdb->tree_lock, locktype);

	*nodep = (dns_dbnode_t *)node;

	return (DNS_R_SUCCESS);
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
createiterator(dns_db_t *db, dns_dbversion_t *version,
	       isc_boolean_t relative_names, dns_dbiterator_t **iteratorp)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *rbtversion = version;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(rbtversion == NULL || !rbtversion->writer);

	(void)relative_names;
	(void)iteratorp;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdataset_t *rdataset)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rdatasetheader_t *header;
	unsigned char *raw;
	unsigned int count;
	rbtdb_serial_t serial;
	rbtdb_version_t *rbtversion = version;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(type != dns_rdatatype_any);

	if ((db->attributes & DNS_DBATTR_CACHE) == 0) {
		if (rbtversion == NULL) {
			LOCK(&rbtdb->lock);
			serial = rbtdb->current_serial;
			UNLOCK(&rbtdb->lock);
		} else
			serial = rbtversion->serial;
	} else
		serial = max_serial;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->type == type) {
			do {
				if (header->serial <= serial) {
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
	if (header != NULL) {
		INSIST(rbtnode->references > 0);
		rbtnode->references++;
		INSIST(rbtnode->references != 0);	/* Catch overflow. */

		rdataset->methods = &rdataset_methods;
		rdataset->rdclass = rbtdb->common.rdclass;
		rdataset->type = header->type;
		rdataset->ttl = header->ttl;
		rdataset->private1 = rbtdb;
		rdataset->private2 = rbtnode;
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

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	if (header == NULL)
		return (DNS_R_NOTFOUND);

	return (DNS_R_SUCCESS);
}

static dns_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatasetiter_t **iteratorp)
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
		LOCK(&rbtdb->lock);
		if (rbtversion == NULL) {
			rbtversion = rbtdb->current_version;
			if (rbtversion->references == 0)
				PREPEND(rbtdb->open_versions, rbtversion,
					link);
		}
		rbtversion->references++;
		INSIST(rbtversion->references != 0);
		UNLOCK(&rbtdb->lock);
	} else
		rbtversion = NULL;

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = (dns_dbversion_t *)rbtversion;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
	
	INSIST(rbtnode->references > 0);
	rbtnode->references++;
	INSIST(rbtnode->references != 0);
	iterator->current = NULL;

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (DNS_R_SUCCESS);
}

static inline dns_result_t
add(dns_rbtdb_t *rbtdb, dns_rbtnode_t *rbtnode, rbtdb_version_t *rbtversion,
    rdatasetheader_t *newheader)
{
	rbtdb_changed_t *changed = NULL;
	rdatasetheader_t *header;

	/*
	 * Add an rdatasetheader_t to a node.
	 */

	/*
	 * Caller must be holding the node lock.
	 */

	if (rbtversion != NULL) {
		changed = add_changed(rbtdb, rbtversion, rbtnode);
		if (changed == NULL)
			return (DNS_R_NOMEMORY);
	}

	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->type == newheader->type)
			break;
	}
	if (header != NULL) {
		if (rbtversion != NULL) {
			INSIST(rbtversion->serial >= header->serial);
			if (rbtversion->serial == header->serial) {
				/*
				 * XXX created merged rdataset, make
				 * newheader point to it
				 */
			}
		}
		INSIST(rbtversion == NULL ||
		       rbtversion->serial > header->serial);
		newheader->prev = header->prev;
		if (header->prev != NULL)
			header->prev->next = newheader;
		else
			rbtnode->data = newheader;
		newheader->next = header->next;
		if (header->next != NULL)
			header->next->prev = newheader;
		newheader->down = header;
		header->prev = newheader;
		header->next = NULL;
		if (changed != NULL) {
			rbtnode->dirty = 1;
			changed->dirty = ISC_TRUE;
		}
	} else {
		/*
		 * The rdataset type doesn't exist at this node.
		 */
		newheader->prev = NULL;
		newheader->next = rbtnode->data;
		if (newheader->next != NULL)
			newheader->next->prev = newheader;
		newheader->down = NULL;
		rbtnode->data = newheader;
	}

	return (DNS_R_SUCCESS);
}

static dns_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    dns_rdataset_t *rdataset)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	isc_region_t region;
	rdatasetheader_t *newheader;
	dns_result_t result;

	REQUIRE(VALID_RBTDB(rbtdb));

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region,
					    sizeof (rdatasetheader_t));
	if (result != DNS_R_SUCCESS)
		return (result);

	newheader = (rdatasetheader_t *)region.base;
	newheader->ttl = rdataset->ttl;
	newheader->type = rdataset->type;
	newheader->attributes = 0;
	if (rbtversion != NULL)
		newheader->serial = rbtversion->serial;
	else
		newheader->serial = 0;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	result = add(rbtdb, rbtnode, rbtversion, newheader);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

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

	result = add(rbtdb, rbtnode, rbtversion, newheader);

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	return (result);
}

static dns_result_t
add_rdataset_callback(dns_rdatacallbacks_t *callbacks, dns_name_t *name,
		      dns_rdataset_t *rdataset)
{
	dns_rbtdb_t *rbtdb = callbacks->commit_private;
	dns_rbtnode_t *node = NULL;
	dns_result_t result;
	isc_region_t region;
	rdatasetheader_t *header, *newheader;
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

	/*
	 * The following is basically addrdataset(), with no locking.
	 *
	 * XXX We should look for an rdataset of this type and merge if
	 * we find it.
	 */

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region,
					    sizeof (rdatasetheader_t));
	if (result != DNS_R_SUCCESS)
		return (result);
	newheader = (rdatasetheader_t *)region.base;
	newheader->ttl = rdataset->ttl;
	newheader->type = rdataset->type;
	newheader->attributes = 0;
	newheader->serial = 1;
	newheader->prev = NULL;
	newheader->down = NULL;

	header = node->data;
	newheader->next = header;
	if (header != NULL)
		header->prev = newheader;
	node->data = newheader;

	return (DNS_R_SUCCESS);
}

static dns_result_t
load(dns_db_t *db, char *filename) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);

	REQUIRE((rbtdb->common.attributes & RBTDB_ATTR_LOADED) == 0);
	/*
	 * We set RBTDB_ATTR_LOADED even though we don't know the
	 * load is going to succeed because we don't want someone to try
	 * again with partial prior load results if a load fails.
	 */
	rbtdb->attributes |= RBTDB_ATTR_LOADED;

	UNLOCK(&rbtdb->lock);

	dns_rdatacallbacks_init(&callbacks);
	callbacks.commit = add_rdataset_callback;
	callbacks.commit_private = rbtdb;

	return (dns_master_load(filename, &rbtdb->common.origin,
				&rbtdb->common.origin, rbtdb->common.rdclass,
				&soacount, &nscount, &callbacks,
				rbtdb->common.mctx));
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

static dns_dbmethods_t methods = {
	attach,
	detach,
	load,
	currentversion,
	newversion,
	closeversion,
	findnode,
	attachnode,
	detachnode,
	printnode,
	createiterator,
	findrdataset,
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
	rbtdb->common.methods = &methods;
	rbtdb->common.attributes = 0;
	if (cache)
		rbtdb->common.attributes |= DNS_DBATTR_CACHE;
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

	/*
	 * Make the Red-Black Tree.
	 */
	dresult = dns_rbt_create(mctx, delete_callback, rbtdb, &rbtdb->tree);
	if (dresult != DNS_R_SUCCESS) {
		free_rbtdb(rbtdb);
		return (dresult);
	}

	rbtdb->references = 1;

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

	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) == 0)
		serial = rbtversion->serial;
	else
		serial = max_serial;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = rbtnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (header->serial <= serial) {
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

	header = rbtiterator->current;
	if (header == NULL)
		return (DNS_R_NOMORE);

	if ((rbtdb->common.attributes & DNS_DBATTR_CACHE) == 0)
		serial = rbtversion->serial;
	else
		serial = max_serial;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	for (header = header->next; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (header->serial <= serial) {
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
		if (header != NULL)
			break;
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
	unsigned char *raw;
	unsigned int count;

	header = rbtiterator->current;
	REQUIRE(header != NULL);
	
	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	INSIST(rbtnode->references > 0);
	rbtnode->references++;
	INSIST(rbtnode->references != 0);	/* Catch overflow. */

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = rbtdb->common.rdclass;
	rdataset->type = header->type;
	rdataset->ttl = header->ttl;
	rdataset->private1 = rbtdb;
	rdataset->private2 = rbtnode;
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

	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
}
