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
#include <dns/master.h>
#include <dns/rdataslab.h>
#include <dns/rdata.h>

#include "rbtdb.h"

/* Lame.  Move util.h to <isc/util.h> */
#include "../isc/util.h"

#define RBTDB_MAGIC			0x52424442U	/* RBDB. */
#define VALID_RBTDB(rbtdb)		((rbtdb) != NULL && \
					 (rbtdb)->common.impmagic == \
						RBTDB_MAGIC)

typedef struct rdatasetheader {
	dns_ttl_t			ttl;
	dns_rdatatype_t			type;
	/*
	 * We don't use the LIST macros, because the LIST structure has
	 * both head and tail pointers.  We only have a head pointer in
	 * the node to save space.
	 */
	unsigned int			version;
	struct rdatasetheader		*prev;
	struct rdatasetheader		*next;
} rdatasetheader_t;

#define DEFAULT_NODE_LOCK_COUNT		7		/* Should be prime. */

typedef struct {
	isc_mutex_t			lock;
	unsigned int			references;
} node_lock;

typedef struct {
	/* Unlocked */
	dns_db_t			common;
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

static dns_result_t disassociate(dns_rdataset_t *rdatasetp);
static dns_result_t first(dns_rdataset_t *rdataset);
static dns_result_t next(dns_rdataset_t *rdataset);
static void current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);

static dns_rdatasetmethods_t rdataset_methods = {
	disassociate,
	first,
	next,
	current
};

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

	dns_name_toregion(&rbtdb->common.base, &r);
	if (r.base != NULL)
		isc_mem_put(rbtdb->common.mctx, r.base, r.length);
	if (rbtdb->tree != NULL)
		dns_rbt_destroy(&rbtdb->tree);
	for (i = 0; i < rbtdb->node_lock_count; i++)
		isc_mutex_destroy(&rbtdb->node_locks[i].lock);
	isc_mem_put(rbtdb->common.mctx, rbtdb->node_locks,
		    rbtdb->node_lock_count * sizeof (node_lock));
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
	REQUIRE(dns_name_issubdomain(name, &rbtdb->common.base));

	dns_name_init(&foundname, NULL);
	RWLOCK(&rbtdb->tree_lock, locktype);
	node = dns_rbt_findnode(rbtdb->tree, name, NULL);
 again:
	if (node != NULL) {
		locknum = node->locknum;
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
		node = dns_rbt_findnode(rbtdb->tree, name, NULL);
		INSIST(node != NULL);
		node->dirty = 0;
		node->references = 0;
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
	if (node->references == 0) {
		INSIST(rbtdb->node_locks[node->locknum].references > 0);
		rbtdb->node_locks[node->locknum].references--;
		/* XXX other detach stuff here */
	}
	UNLOCK(&rbtdb->node_locks[node->locknum].lock);

	*targetp = NULL;
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

	(void)version;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
	for (header = rbtnode->data; header != NULL; header = header->next) {
		/* XXX version */
		if (header->type == type)
			break;
	}
	if (header != NULL) {
		INSIST(rbtnode->references > 0);
		rbtnode->references++;
		INSIST(rbtnode->references != 0);	/* Catch overflow. */

		rdataset->methods = &rdataset_methods;
		rdataset->class = rbtdb->common.class;
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
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    dns_rdataset_t *rdataset, dns_addmode_t mode)
{
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	isc_region_t region;
	rdatasetheader_t *header, *newheader;
	dns_result_t result;

	(void)version;
	(void)mode;
	
	REQUIRE(VALID_RBTDB(rbtdb));

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region,
					    sizeof (rdatasetheader_t));
	if (result != DNS_R_SUCCESS)
		return (result);
	newheader = (rdatasetheader_t *)region.base;
	newheader->ttl = rdataset->ttl;
	newheader->type = rdataset->type;
	newheader->version = 0;			/* XXX version */
	newheader->prev = NULL;

	LOCK(&rbtdb->node_locks[rbtnode->locknum].lock);
	header = rbtnode->data;
	newheader->next = header;
	if (header != NULL)
		header->prev = newheader;
	rbtnode->data = newheader;
	UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock);

	return (DNS_R_SUCCESS);
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

static dns_result_t
add_rdataset_callback(dns_name_t *name, dns_rdataset_t *rdataset,
		      void *private)
{
	dns_rbtdb_t *rbtdb = private;
	dns_dbnode_t *node = NULL;
	dns_result_t result;

	result = findnode((dns_db_t *)rbtdb, name, ISC_TRUE, &node);
	if (result != DNS_R_SUCCESS)
		return (result);
	result = addrdataset((dns_db_t *)rbtdb, node, NULL, rdataset,
			     dns_addmode_merge);
	detachnode((dns_db_t *)rbtdb, &node);
	return (result);
}

static dns_result_t
load(dns_db_t *db, char *filename) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	int soacount, nscount;

	REQUIRE(VALID_RBTDB(rbtdb));

	return (dns_load_master(filename, &rbtdb->common.base,
				&rbtdb->common.base, rbtdb->common.class,
				&soacount, &nscount, add_rdataset_callback,
				rbtdb, rbtdb->common.mctx));
}

static dns_dbmethods_t methods = {
	attach,
	detach,
	shutdown,
	load,
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
dns_rbtdb_create(isc_mem_t *mctx, dns_name_t *base, isc_boolean_t cache,
		 dns_rdataclass_t class, unsigned int argc, char *argv[],
		 dns_db_t **dbp)
{
	dns_rbtdb_t *rbtdb;
	isc_result_t iresult;
	dns_result_t dresult;
	int i;
	isc_region_t r1, r2;

	(void)argc;
	(void)argv;

	rbtdb = isc_mem_get(mctx, sizeof *rbtdb);
	if (rbtdb == NULL)
		return (DNS_R_NOMEMORY);
	memset(rbtdb, '\0', sizeof *rbtdb);
	rbtdb->common.methods = &methods;
	rbtdb->common.cache = cache;
	rbtdb->common.class = class;
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
			isc_mem_put(rbtdb->common.mctx, rbtdb, sizeof *rbtdb);
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_mutex_init() failed: %s",
					 isc_result_totext(iresult));
			return (DNS_R_UNEXPECTED);
		}
		rbtdb->node_locks[i].references = 0;
	}

	/*
	 * Make a copy of the base name.
	 */
	dns_name_init(&rbtdb->common.base, NULL);
	dns_name_toregion(base, &r1);
	r2.base = isc_mem_get(mctx, r1.length);
	if (r2.base == NULL) {
		free_rbtdb(rbtdb);
		return (DNS_R_NOMEMORY);
	}
	r2.length = r1.length;
	memcpy(r2.base, r1.base, r1.length);
	dns_name_fromregion(&rbtdb->common.base, &r2);

	/*
	 * Make the Red-Black Tree.
	 * XXX NULL should (possibly) be replaced with the method that frees
	 * the data pointer for a node that is deleted.
	 */
	dresult = dns_rbt_create(mctx, NULL, &rbtdb->tree);
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



/*
 * Slabbed Rdataset Methods
 */

static dns_result_t
disassociate(dns_rdataset_t *rdataset) {
	dns_db_t *db = rdataset->private1;
	dns_dbnode_t *node = rdataset->private2;

	detachnode(db, &node);

	return (DNS_R_SUCCESS);
}

static dns_result_t
first(dns_rdataset_t *rdataset) {
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
next(dns_rdataset_t *rdataset) {
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
current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->private5;
	isc_region_t r;

	REQUIRE(raw != NULL);

	r.length = raw[0] * 256 + raw[1];
	raw += 2;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->class, rdataset->type, &r);
}
