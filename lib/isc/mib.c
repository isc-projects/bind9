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

/* $Id: mib.c,v 1.4 2006/12/21 06:02:30 marka Exp $ */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mib.h>
#include <isc/util.h>
#include <isc/list.h>

/*
 * The root of a statistics tree.
 *
 * We use a isc_refcount_t for reference counting, which is a self-locked
 * type.  It is very efficient and may use atomic operations rather than
 * locks.
 */
struct isc_mib {
	isc_mem_t *mem;
	isc_rwlock_t rwlock;
	ISC_LIST(isc_mibnode_t) nodes;
	isc_refcount_t refs;
};

isc_result_t
isc_mib_create(isc_mem_t *mem, isc_mib_t **rootp)
{
	isc_result_t result;
	isc_mib_t *root;

	REQUIRE(rootp != NULL && *rootp == NULL);

	root = isc_mem_get(mem, sizeof *root);
	if (root == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_rwlock_init(&root->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mem, root, sizeof *root);
		return (result);
	}

	ISC_LIST_INIT(root->nodes);

	root->mem = NULL;
	isc_mem_attach(mem, &root->mem);

	isc_refcount_init(&root->refs, 1);

	*rootp = root;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mibnode_create(isc_mib_t *mib, isc_uint32_t type,
		   const char *name, isc_uint32_t flags,
		   isc_mutex_t *lock, void *item, unsigned int itemlen,
		   isc_mibnode_t **nodep)
{
	isc_result_t result;
	isc_mibnode_t *node;

	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE((flags & ISC_MIBNODEFLAG_PERMANENT) == 0);

	node = isc_mem_get(mib->mem, sizeof *node);
	if (node == NULL)
		return (ISC_R_NOMEMORY);

	*nodep = node;

	result = isc_mibnode_init(mib, node, type, name, lock, flags,
				  item, itemlen);

	return (result);
}

void
isc_mibnode_destroy(isc_mib_t *mib, isc_mibnode_t **nodep)
{
	isc_mibnode_t *node;

	REQUIRE(nodep != NULL && *nodep != NULL);

	node = *nodep;
	REQUIRE((node->flags & ISC_MIBNODEFLAG_PERMANENT) == 0);
	isc_mibnode_invalidate(mib, node);
	*nodep = NULL;

	isc_mem_put(mib->mem, node, sizeof *node);
}

/*
 * XXXMLG Should break this out into two functions, one which is used
 * internally for most of the setting, and another which simply makes
 * certain that the ISC_MIBNODEFLAG_PERMANENT is set when the client calls
 * _init() and _invalidate() directly.
 */
void
isc_mibnode_invalidate(isc_mib_t *mib, isc_mibnode_t *node)
{
	REQUIRE(node != NULL);
	REQUIRE(!ISC_LINK_LINKED(node, link));

	switch (node->type) {
	case ISC_MIBNODETYPE_NODE:
		REQUIRE(ISC_LIST_EMPTY(node->nodes));
		break;
	}

	isc_mem_free(mib->mem, node->name);
	node = ISC_MIBNODETYPE_INVALID;
}

/*
 * Initialize a statically allocated mibnode.  The caller will need to call
 * isc_mibnode_invalidate() after it is no longer in use.
 */
isc_result_t
isc_mibnode_init(isc_mib_t *mib, isc_mibnode_t *node, isc_uint32_t type,
		 const char *name, isc_mutex_t *lock, isc_uint32_t flags,
		 void *item, unsigned int itemlen)
{
	REQUIRE(mib != NULL);
	REQUIRE(node != NULL);
	REQUIRE(name != NULL);

	ISC_LINK_INIT(node, link);
	node->type = type;
	node->name = isc_mem_strdup(mib->mem, name);
	if (node->name == NULL)
		return (ISC_R_NOMEMORY);
	node->parent = NULL;
	node->lock = NULL;
	node->flags = flags;
	node->lock = lock;
	ISC_LIST_INIT(node->nodes);

	switch (type) {
	case ISC_MIBNODETYPE_NODE:
		break;
	case ISC_MIBNODETYPE_STRING:
		REQUIRE(itemlen >= sizeof(char *));
		node->data = item;
		break;
	case ISC_MIBNODETYPE_UINT32:
	case ISC_MIBNODETYPE_INT32:
		REQUIRE(itemlen >= sizeof(isc_uint32_t));
		node->data = item;
		break;
	case ISC_MIBNODETYPE_UINT64:
	case ISC_MIBNODETYPE_INT64:
		REQUIRE(itemlen >= sizeof(isc_uint64_t));
		node->data = item;
		break;
	default:
		isc_error_runtimecheck(__FILE__, __LINE__,
				       "Invalid type");
	}

	return (ISC_R_SUCCESS);
}

void
isc_mib_destroy(isc_mib_t **rootp)
{
	isc_mib_t *root;
	isc_mem_t *mem;
	unsigned int refs;

	REQUIRE(rootp != NULL && *rootp != NULL);

	root = *rootp;
	rootp = NULL;

	isc_refcount_decrement(&root->refs, &refs);
	INSIST(refs == 0);
	isc_refcount_destroy(&root->refs);

	REQUIRE(ISC_LIST_EMPTY(root->nodes));

	/* record and then forget the root's memory context */
	mem = root->mem;
	root->mem = NULL;

	isc_rwlock_destroy(&root->rwlock);

	isc_mem_putanddetach(&mem, root, sizeof *root);
}

void
isc_mib_add(isc_mib_t *root, isc_mibnode_t *parent, isc_mibnode_t *node)
{
	REQUIRE(root != NULL);
	REQUIRE(node != NULL);

	RWLOCK(&root->rwlock, isc_rwlocktype_write);
	isc_refcount_increment(&root->refs, NULL);

	if (parent == NULL) {
		ISC_LIST_APPEND(root->nodes, node, link);
		node->parent = NULL;
	} else {
		REQUIRE(parent->type == ISC_MIBNODETYPE_NODE);
		ISC_LIST_APPEND(parent->nodes, node, link);
		node->parent = parent;
	}

	RWUNLOCK(&root->rwlock, isc_rwlocktype_write);
}

void
isc_mib_remove(isc_mib_t *root, isc_mibnode_t *node)
{
	REQUIRE(root != NULL);
	REQUIRE(node != NULL);

	RWLOCK(&root->rwlock, isc_rwlocktype_write);
	isc_refcount_decrement(&root->refs, NULL);

	if (node->parent == NULL)
		ISC_LIST_UNLINK(root->nodes, node, link);
	else
		ISC_LIST_UNLINK(node->parent->nodes, node, link);
	node->parent = NULL;

	RWUNLOCK(&root->rwlock, isc_rwlocktype_write);
}

isc_boolean_t
isc_mibnode_haschildren(isc_mibnode_t *node)
{
	REQUIRE(node != NULL);
	REQUIRE(node->type == ISC_MIBNODETYPE_NODE);

	if (ISC_LIST_HEAD(node->nodes) == NULL)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_mibnode_t *
isc_mib_firstnode(isc_mib_t *mib, isc_mibnode_t *parent)
{
	isc_mibnode_t *node;

	if (parent != NULL) {
		node = ISC_LIST_HEAD(parent->nodes);
	} else {
		node = ISC_LIST_HEAD(mib->nodes);
	}
	if (node != NULL && node->lock != NULL)
		LOCK(node->lock);

	return (node);
}

isc_mibnode_t *
isc_mib_nextnode(isc_mib_t *mib, isc_mibnode_t *previous)
{
	isc_mibnode_t *node;

	UNUSED(mib);

	node = ISC_LIST_NEXT(previous, link);

	/*
	 * Could optimize this...  XXXMLG
	 */
	if (previous != NULL && previous->lock != NULL)
		UNLOCK(previous->lock);
	if (node != NULL && node->lock != NULL)
		LOCK(node->lock);

	return (node);
}

isc_mibnode_t *
isc_mib_parent(isc_mib_t *mib, isc_mibnode_t *node)
{
	UNUSED(mib);

	return (node->parent);
}

void
isc_mib_lock(isc_mib_t *mib, isc_mibnode_t *node)
{
	RWLOCK(&mib->rwlock, isc_rwlocktype_read);
	isc_refcount_increment(&mib->refs, NULL);

	if (node != NULL && node->lock != NULL)
		LOCK(node->lock);
}

void
isc_mib_unlock(isc_mib_t *mib, isc_mibnode_t *node)
{
	if (node != NULL && node->lock != NULL)
		UNLOCK(node->lock);
	if (mib != NULL) {
		RWUNLOCK(&mib->rwlock, isc_rwlocktype_read);
		isc_refcount_decrement(&mib->refs, NULL);
	}
}

void
isc_mibnode_getdata(isc_mibnode_t *node, isc_mibnode_t *previous,
		    isc_boolean_t lock, void *item, unsigned int itemlen)
{
	if (previous != NULL && previous->lock != NULL)
		UNLOCK(previous->lock);
	if (lock && node != NULL && node->lock != NULL)
		LOCK(node->lock);

	switch (node->type) {
	case ISC_MIBNODETYPE_NODE:
		break;
	case ISC_MIBNODETYPE_STRING:
		REQUIRE(itemlen >= sizeof(char *));
		*((char **)(item)) = *((char **)(node->data));
		break;
	case ISC_MIBNODETYPE_UINT32:
	case ISC_MIBNODETYPE_INT32:
		REQUIRE(itemlen >= sizeof(isc_uint32_t));
		*((isc_uint32_t *)(item)) = *((isc_uint32_t *)(node->data));
		break;
	case ISC_MIBNODETYPE_UINT64:
	case ISC_MIBNODETYPE_INT64:
		REQUIRE(itemlen >= sizeof(isc_uint64_t));
		*((isc_uint64_t *)(item)) = *((isc_uint64_t *)(node->data));
		break;
	default:
		isc_error_runtimecheck(__FILE__, __LINE__,
				       "Invalid type");
	}
}
