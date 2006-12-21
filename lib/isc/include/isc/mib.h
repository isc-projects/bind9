/*
 * Copyright (C) 2006  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: mib.h,v 1.4 2006/12/21 06:02:30 marka Exp $ */

#ifndef ISC_MIB_H
#define ISC_MIB_H

/*! \file mib.h
 * \brief Statistics structures.
 *
 * \li MP:
 *	The statistics structures defined in this file handle all locking
 *	provided the API is used properly.
 *
 * This module defines a MIB database.
 *
 * Two entities are defined:  providers and consumers.  Providers will
 * create and attach mib elements to the root or to other nodes, and update
 * the MIB elements themselves.  Consumers will read this data.
 *
 * Note that consumers cannot currently update the MIB, just read it.  We
 * may want to add this later.
 *
 * General assumptions about the use of the mib system, and design
 * requirements:
 *
 * (1)	Mib must be fast to update, with as little locking as feasable.
 *	On simple integers, this should require no locks if the system
 *	supports atomic increments and reads of integers.
 *
 * (2)	Mib must be fast to read, also with as little locking as possible.
 *	The mib tree has a read/write lock to protect the structure of
 *	the entire mib tree.
 *
 * (3)	The mib tree itself is expected to be updated infrequently, and
 *	so a simple read/write lock is used to protect the struture.
 *
 * (4)	Sometimes complicated data will require special handling to protect
 *	during read or updates.  When this is necessary, a pointer to a lock
 *	structure can be associated with each mib variable.  This lock
 *	can be shared (for space savings).
 *
 * Constraints of use:
 *
 * (1)	Each mib structure has an implied owner, which may be a module, an
 *	"object" like a zone, or other distinct object.  It is required the
 *	owner of the mib node will be the one to create, modify the structure
 *	of, and delete it as needed.
 *
 * (2)	The mib structure must be fully configured before inserting it into
 *	the tree.  However, mib objects can be added and removed dynamically
 *	as required.
 *
 * (3)	Mib have names.  These names cannot contain periods, as this is
 *	used as the delimiter between names.
 *
 * (4)	Walking a list of nodes must be done in the forward order only, never
 *	in the reverse direction.  This is to avoid deadlocks, and to optimize
 *	locking.  Locking will only be performed as needed while walking the
 *	mibnode list, and if the lock needed does not change it will not
 *	be unlocked until isc_mib_iterunlock() is called to explicitly
 *	unlock, or isc_mib_iterdestroy() is called to implicitly unlock it.
 *
 * (5)  When walking the tree, or updating statistics, it is required that
 *	the mibnode locks be held for as little a time as possible.  Any
 *	data should be copied quickly or the lock should be explicitly
 *	released.
 *
 * (6)	When updating mib, the mibnode lock should be held as little as
 *	possible.
 *
 * (7)	Even with locks there is no guarantee they will always be used, so
 *	users of this cannot assume reading two or more variables which
 *	share the same statistics lock will result in consistent data.  For
 *	example, if there are three data items, "a", "b", and "total", where
 *	total = a + b, it is possible "a" will be updated using atomic
 *	operations, and then "total" will be incremented using the same
 *	operations.  Atomic operations on integers will not always use the
 *	node's lock, so it is possible that total will not always be the sum
 *	of "a" and "b".
 *
 * (8)  Consumers are read-only -- no modification is allowed.  Search
 *	functions will return data that must not be modified.  Removal of
 *	a node implies that the node's exact pointer is known.  That is,
 *	no search is needed.  Searching then removing a node is considered
 *	a misuse of this API.
 */

#include <isc/lang.h>
#include <isc/list.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/types.h>

#define ISC_MIB_MAXNAME	12   /* max mib length */
#define ISC_MIB_NAMELEN	32   /* longest ASCII name length per node */
#define ISC_MIB_DEFSIZE	 8   /* default object set size */

/*
 * Node types.
 */
#define ISC_MIBNODETYPE_INVALID	0   /* Invalid node */
#define ISC_MIBNODETYPE_NODE	1   /* node is a node */
#define ISC_MIBNODETYPE_UINT32	2   /* node is an unsigned 32-bit integer */
#define ISC_MIBNODETYPE_INT32	3   /* node is an signed 32-bit integer */
#define ISC_MIBNODETYPE_UINT64	4   /* node is an unsigned 64-bit integer */
#define ISC_MIBNODETYPE_INT64	5   /* node is an signed 64-bit integer */
#define ISC_MIBNODETYPE_STRING	6   /* node is a string */

/*
 * Node flags.  These define flags used on isc_mibnode_t.
 */
#define ISC_MIBNODEFLAG_PERMANENT	0x00000001 /* cannot free */

typedef struct isc_mibnode isc_mibnode_t;
typedef struct isc_mib isc_mib_t;

/*
 * This is a description of the data element we are tracking.  We call this
 * a "node."
 */
struct isc_mibnode {
	isc_uint32_t type;
	isc_uint32_t flags;
	char *name;
	isc_mibnode_t *parent;
	isc_mutex_t *lock;
	void *data; /* used if we are a data node */
	ISC_LIST(isc_mibnode_t) nodes;  /* used if we are a list node */
	ISC_LINK(isc_mibnode_t) link;
};

/*
 * Initialize a tree's root node.
 */
isc_result_t isc_mib_create(isc_mem_t *mem, isc_mib_t **rootp);

/*
 * Destroy a MIB.
 */
void isc_mib_destroy(isc_mib_t **rootp);

/*
 * FUNCTIONS BELOW THIS POINT SHOULD BE CALLED ONLY FROM PROVIDERS.
 */

/*
 * Create and initialize a new node.  This will allocate a node structure,
 * and call isc_mibnode_init() to initialize it.
 *
 * This function allocates memory, so a corresponding call to
 * isc_mibnode_destroy() must be made to free the memory allocated by
 * this function and by isc_mibnode_init().
 */
isc_result_t isc_mibnode_create(isc_mib_t *mib, isc_uint32_t type,
				const char *name,
				isc_uint32_t flags, isc_mutex_t *lock,
				void *item, unsigned int itemlen,
				isc_mibnode_t **nodep);

/*
 * Initialize a static or pre-allocated node.
 * This will set it up but NOT link it into the tree.
 *
 * This function allocates memory from the mib's memory context, so a
 * call to isc_mibnode_invalidate() must be called to destroy it.
 */
isc_result_t isc_mibnode_init(isc_mib_t *mib, isc_mibnode_t *node,
			      isc_uint32_t type, const char *name,
			      isc_mutex_t *lock, isc_uint32_t flags,
			      void *item, unsigned int itemlen);

void isc_mibnode_invalidate(isc_mib_t *mib, isc_mibnode_t *node);

void isc_mib_add(isc_mib_t *root, isc_mibnode_t *parent, isc_mibnode_t *node);
void isc_mib_remove(isc_mib_t *root, isc_mibnode_t *node);

void isc_mibnode_destroy(isc_mib_t *mib, isc_mibnode_t **nodep);
isc_boolean_t isc_mibnode_haschildren(isc_mibnode_t *node);

/*
 * Walk a mib.  This performs a depth-first traversal of the mib tree.
 * Locking is automatic.  After walking is completed, isc_mib_release()
 * must be called.
 *
 * Also, have a way to find a node's parent.
 */
isc_mibnode_t *isc_mib_firstnode(isc_mib_t *mib, isc_mibnode_t *parent);
isc_mibnode_t *isc_mib_nextnode(isc_mib_t *mib, isc_mibnode_t *previous);
isc_mibnode_t *isc_mib_parent(isc_mib_t *mib, isc_mibnode_t *node);

/*
 * Release any locks held on the mib and node.
 * This is the last step in searching and tree-walking.
 *
 * If 'node' is NULL, only the tree is unlocked.
 */
void isc_mib_unlock(isc_mib_t *mib, isc_mibnode_t *node);
void isc_mib_lock(isc_mib_t *mib, isc_mibnode_t *node);

void
isc_mibnode_getdata(isc_mibnode_t *node,
		    isc_mibnode_t *previous,
		    isc_boolean_t lock,
		    void *item, unsigned int itemlen);

#endif /* ISC_MIB_H */
