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

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>
#include <isc/rwlock.h>

#include <dns/name.h>
#include <dns/rbt.h>

#include "rbtdb.h"

/* Lame.  Move util.h to <isc/util.h> */
#include "../isc/util.h"

#define RBTDB_MAGIC			0x52424442U	/* RBDB. */
#define VALID_RBTDB(rbtdb)		((rbtdb) != NULL && \
					 (rbtdb)->common.impmagic == \
						RBTDB_MAGIC)

#define DEFAULT_NODE_LOCK_COUNT		7

typedef struct {
	isc_mutex_t			lock;
	unsigned int			references;
} node_lock;

typedef struct {
	/* Unlocked */
	dns_db_t			common;
	isc_mem_t *			mctx;
	isc_mutex_t			lock;
	isc_rwlock_t			tree_lock;
	unsigned int			node_lock_count;
	node_lock *		       	node_locks;
	/* Locked by lock */
	unsigned int			references;
	isc_boolean_t			shutting_down;
	/* Locked by tree_lock */
	dns_rbt_t *			tree;
} dns_rbtdb_t;

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

	if (rbtdb->tree != NULL)
		dns_rbt_destroy(&rbtdb->tree);
	for (i = 0; i < rbtdb->node_lock_count; i++)
		isc_mutex_destroy(&rbtdb->node_locks[i].lock);
	isc_mem_put(rbtdb->mctx, rbtdb->node_locks,
		    rbtdb->node_lock_count * sizeof (node_lock));
	isc_rwlock_destroy(&rbtdb->tree_lock);
	isc_mutex_destroy(&rbtdb->lock);
	rbtdb->common.magic = 0;
	rbtdb->common.impmagic = 0;
	isc_mem_put(rbtdb->mctx, rbtdb, sizeof *rbtdb);
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

	dbp = NULL;
}

static void
shutdown(dns_db_t *db) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	LOCK(&rbtdb->lock);
	rbtdb->shutting_down = ISC_TRUE;
	UNLOCK(&rbtdb->lock);
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp == NULL);

	*versionp = NULL;
}

static dns_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp == NULL);

	return (DNS_R_NOTIMPLEMENTED);
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp != NULL);

	*versionp = NULL;
}

static dns_result_t
findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
	 dns_dbnode_t **nodep) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node = NULL;
	dns_name_t foundname;
	unsigned int locknum;
	dns_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(VALID_RBTDB(rbtdb));

	dns_name_init(&foundname, NULL);
	RWLOCK(&rbtdb->tree_lock, locktype);
	node = dns_rbt_findnode(rbtdb->tree, name);
 again:
	if (node != NULL) {
		dns_rbt_namefromnode(node, &foundname);
		locknum = dns_name_hash(&foundname) % rbtdb->node_lock_count;
		LOCK(&rbtdb->node_locks[locknum].lock);
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
		/* XXX rework once we have dns_rbt_addnode() */
		result = dns_rbt_addname(rbtdb->tree, name, NULL);
		if (result != DNS_R_SUCCESS) {
			RWUNLOCK(&rbtdb->tree_lock, locktype);
			return (result);
		}
		node = dns_rbt_findnode(rbtdb->tree, name);
		INSIST(node != NULL);
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
	unsigned int locknum;
	dns_name_t name;

	REQUIRE(VALID_RBTDB(rbtdb));

	dns_name_init(&name, NULL);
	dns_rbt_namefromnode(node, &name);
	locknum = dns_name_hash(&name) % rbtdb->node_lock_count;
	LOCK(&rbtdb->node_locks[locknum].lock);
	INSIST(node->references != 0);
	node->references++;
	UNLOCK(&rbtdb->node_locks[locknum].lock);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node;
	unsigned int locknum;
	dns_name_t name;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (dns_rbtnode_t *)(*targetp);
	dns_name_init(&name, NULL);
	dns_rbt_namefromnode(node, &name);
	locknum = dns_name_hash(&name) % rbtdb->node_lock_count;
	LOCK(&rbtdb->node_locks[locknum].lock);
	INSIST(node->references > 0);
	node->references--;
	if (node->references == 0) {
		INSIST(rbtdb->node_locks[locknum].references > 0);
		rbtdb->node_locks[locknum].references--;
		/* XXX other detach stuff here */
	}
	UNLOCK(&rbtdb->node_locks[locknum].lock);

	*targetp = NULL;
}

static dns_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdataset_t *rdataset) {
	db = NULL;
	node = NULL;
	version = NULL;
	type = 0;
	rdataset = NULL;
	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    dns_rdataset_t *rdataset, dns_addmode_t mode) {
	db = NULL;
	node = NULL;
	version = NULL;
	rdataset = NULL;
	mode = dns_addmode_replace;
	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type) {
	db = NULL;
	node = NULL;
	version = NULL;
	type = 0;
	return (DNS_R_NOTIMPLEMENTED);
}

static dns_dbmethods_t methods = {
	attach,
	detach,
	shutdown,
	currentversion,
	newversion,
	closeversion,
	findnode,
	attachnode,
	detachnode,
	findrdataset,
	addrdataset,
	deleterdataset
};

dns_result_t
dns_rbtdb_create(isc_mem_t *mctx, isc_boolean_t cache,
		 dns_rdataclass_t class, unsigned int argc, char *argv[],
		 dns_db_t **dbp)
{
	dns_rbtdb_t *rbtdb;
	isc_result_t iresult;
	dns_result_t dresult;
	int i;

	rbtdb = isc_mem_get(mctx, sizeof *rbtdb);
	if (rbtdb == NULL)
		return (DNS_R_NOMEMORY);
	memset(rbtdb, '\0', sizeof *rbtdb);
	rbtdb->common.methods = &methods;
	rbtdb->common.cache = cache;
	rbtdb->common.class = class;
	rbtdb->mctx = mctx;

	iresult = isc_mutex_init(&rbtdb->lock);
	if (iresult != ISC_R_SUCCESS) {
		isc_mem_put(rbtdb->mctx, rbtdb, sizeof *rbtdb);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	iresult = isc_rwlock_init(&rbtdb->tree_lock, 0, 0);
	if (iresult != ISC_R_SUCCESS) {
		isc_mutex_destroy(&rbtdb->lock);
		isc_mem_put(rbtdb->mctx, rbtdb, sizeof *rbtdb);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	if (rbtdb->node_lock_count == 0)
		rbtdb->node_lock_count = DEFAULT_NODE_LOCK_COUNT;
	rbtdb->node_locks = isc_mem_get(mctx, rbtdb->node_lock_count * 
					sizeof (node_lock));
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
				    sizeof (node_lock));
			isc_rwlock_destroy(&rbtdb->tree_lock);
			isc_mutex_destroy(&rbtdb->lock);
			isc_mem_put(rbtdb->mctx, rbtdb, sizeof *rbtdb);
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_mutex_init() failed: %s",
					 isc_result_totext(iresult));
			return (DNS_R_UNEXPECTED);
		}
		rbtdb->node_locks[i].references = 0;
	}

	dresult = dns_rbt_create(mctx, &rbtdb->tree);
	if (dresult != DNS_R_SUCCESS) {
		free_rbtdb(rbtdb);
		return (dresult);
	}

	rbtdb->shutting_down = ISC_FALSE;
	rbtdb->references = 1;

	/* XXX Version init here */

	rbtdb->common.magic = DNS_DB_MAGIC;
	rbtdb->common.impmagic = RBTDB_MAGIC;

	*dbp = (dns_db_t *)rbtdb;

	return (ISC_R_SUCCESS);
}
