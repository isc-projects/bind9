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
#include <isc/async.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/sieve.h>
#include <isc/stdtime.h>
#include <isc/urcu.h>
#include <isc/uv.h>

#include <dns/deleg.h>
#include <dns/name.h>
#include <dns/qp.h>
#include <dns/view.h>

#include "probes-dns.h"

#define DELEGDB_NODE_MAGIC	 ISC_MAGIC('D', 'e', 'G', 'N')
#define VALID_DELEGDB_NODE(node) ISC_MAGIC_VALID(node, DELEGDB_NODE_MAGIC)

#define DELEGDB_MAGIC	  ISC_MAGIC('D', 'e', 'G', 'D')
#define VALID_DELEGDB(db) ISC_MAGIC_VALID(db, DELEGDB_MAGIC)

#define DELEGDB_MINSIZE (1024 * 1024) /* 1MiB */

typedef struct delegdb_node delegdb_node_t;

struct dns_delegdb {
	unsigned int magic;

	/*
	 * The DB uses its own memory context in order to easily enforce
	 * overmem policies based on allocations made from this memory context.
	 */
	isc_mem_t *mctx;
	isc_refcount_t references;

	size_t nloops;
	ISC_SIEVE(delegdb_node_t) * lru;

	dns_qpmulti_t *nodes;

	/*
	 * Keep track of now many owners are actually using the delegdb. For
	 * instance:
	 *
	 * - During a server reload, the new view will (by default)
	 *   start owning the existing delegdb from the previous instance of the
	 *   same view using `dns_delegdb_reuse()`. This will increase `owners`
	 *   by one.
	 *
	 * - Later on, either the old instance of the view (or the new one,
	 *   in case of reload failure) will call `dns_delegdb_shutdown()` on
	 *   the delegdb. This will decrement `owners` by one.
	 *
	 * If `owners` is bigger than 1 when `dns_delegdb_shutdown()` is called,
	 * it means the delegdb must not be shutdown because there are other
	 * owners using it, so `dns_delegdb_shutdown()` bails off in this case.
	 * (After decrementing `owners`.)
	 */
	isc_refcount_t owners;

	dns_delegdb_config_t config;
};

static void
delegdb_destroy(dns_delegdb_t *delegdb) {
	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(delegdb->nodes == NULL);

	delegdb->magic = 0;
	isc_mem_cput(delegdb->mctx, delegdb->lru, delegdb->nloops,
		     sizeof(delegdb->lru[0]));

	isc_mem_putanddetach(&delegdb->mctx, delegdb, sizeof(*delegdb));
}

ISC_REFCOUNT_IMPL(dns_delegdb, delegdb_destroy);

struct delegdb_node {
	unsigned int magic;
	dns_delegdb_t *delegdb;
	isc_refcount_t references;

	/* LRU */
	isc_loop_t *loop;
	ISC_LINK(delegdb_node_t) link;
	bool visited;

	/*
	 * Used to build a list of nodes to be deleted (when running the
	 * delete tree flow).
	 */
	ISC_LINK(delegdb_node_t) deadlink;

	/*
	 * Immutable node data
	 */
	size_t size;
	dns_name_t zonecut;
	dns_delegset_t *delegset;
};

/*
 * All node cleanup is done on the node's owning loop so that the node
 * remains fully valid (name, delegset, SIEVE link) until it is actually
 * destroyed.  This is important because after a node is removed from the
 * QP trie, it may still be linked in the owning loop's SIEVE list; if
 * another thread's eviction could encounter a half-destroyed node, we
 * would get a use-after-free.  By deferring everything to the owning
 * loop, the node is intact until the SIEVE unlink happens.
 */
static void
delegdb_node_destroy_async(void *arg) {
	delegdb_node_t *node = arg;
	isc_mem_t *mctx = NULL;

	REQUIRE(VALID_DELEGDB_NODE(node));
	REQUIRE(DNS_DELEGSET_VALID(node->delegset));

	node->magic = 0;

	isc_mem_attach(node->delegdb->mctx, &mctx);

	if (ISC_SIEVE_LINKED(node, link)) {
		ISC_SIEVE_UNLINK(node->delegdb->lru[isc_tid()], node, link);
	}

	dns_name_free(&node->zonecut, mctx);
	dns_delegset_detach(&node->delegset);

	dns_delegdb_detach(&node->delegdb);
	isc_loop_unref(node->loop);
	isc_mem_putanddetach(&mctx, node, sizeof(*node));
}

static void
delegdb_node_destroy(delegdb_node_t *node) {
	REQUIRE(VALID_DELEGDB_NODE(node));

	if (node->loop == isc_loop()) {
		delegdb_node_destroy_async(node);
	} else {
		isc_async_run(node->loop, delegdb_node_destroy_async, node);
	}
}

#ifdef DNS_DELEGDB_NODETRACE
#define delegdb_node_ref(ptr) \
	delegdb_node__ref(ptr, __func__, __FILE__, __LINE__)
#define delegdb_node_unref(ptr) \
	delegdb_node__unref(ptr, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(delegdb_node);
ISC_REFCOUNT_STATIC_TRACE_IMPL(delegdb_node, delegdb_node_destroy);
#else
ISC_REFCOUNT_STATIC_DECL(delegdb_node);
ISC_REFCOUNT_STATIC_IMPL(delegdb_node, delegdb_node_destroy);
#endif

static void
dbnode_attach(ISC_ATTR_UNUSED void *uctx, void *pval,
	      ISC_ATTR_UNUSED uint32_t ival) {
	delegdb_node_t *node = pval;

	REQUIRE(VALID_DELEGDB_NODE(node));
	delegdb_node_ref(node);
}

static void
dbnode_detach(ISC_ATTR_UNUSED void *uctx, void *pval,
	      ISC_ATTR_UNUSED uint32_t ival) {
	delegdb_node_t *node = pval;

	REQUIRE(VALID_DELEGDB_NODE(node));
	delegdb_node_unref(node);
}

static size_t
makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	uint32_t ival ISC_ATTR_UNUSED) {
	delegdb_node_t *data = pval;
	return dns_qpkey_fromname(key, &data->zonecut, DNS_DBNAMESPACE_NORMAL);
}

static void
triename(ISC_ATTR_UNUSED void *uctx, char *buf, size_t size) {
	(void)strncpy(buf, "delegdb", size);
}

static dns_qpmethods_t qpmethods = { .attach = dbnode_attach,
				     .detach = dbnode_detach,
				     .makekey = makekey,
				     .triename = triename };

void
dns_delegdb_create(dns_delegdb_t **delegdbp) {
	isc_mem_t *mctx = NULL;
	dns_delegdb_t *delegdb = NULL;

	REQUIRE(isc_loop_get(isc_tid()) == isc_loop_main());
	REQUIRE(delegdbp != NULL && *delegdbp == NULL);

	isc_mem_create("dns_delegdb", &mctx);
	isc_mem_setdestroycheck(mctx, true);

	delegdb = isc_mem_get(mctx, sizeof(*delegdb));
	*delegdb = (dns_delegdb_t){ .magic = DELEGDB_MAGIC,
				    .mctx = mctx,
				    .references = ISC_REFCOUNT_INITIALIZER(1),
				    .nloops = isc_loopmgr_nloops(),
				    .owners = ISC_REFCOUNT_INITIALIZER(1),
				    .config = {} };

	dns_qpmulti_create(mctx, &qpmethods, &delegdb->nodes, &delegdb->nodes);

	delegdb->lru = isc_mem_cget(mctx, delegdb->nloops,
				    sizeof(delegdb->lru[0]));
	for (size_t i = 0; i < delegdb->nloops; i++) {
		ISC_SIEVE_INIT(delegdb->lru[i]);
	}

	LIBDNS_DELEGDB_CREATE(delegdb);

	*delegdbp = delegdb;
}

void
dns_delegdb_reuse(dns_view_t *oldview, dns_view_t *newview) {
	REQUIRE(isc_loop_get(isc_tid()) == isc_loop_main());
	REQUIRE(DNS_VIEW_VALID(oldview));
	REQUIRE(DNS_VIEW_VALID(newview));

	dns_delegdb_attach(oldview->deleg, &newview->deleg);
	isc_refcount_increment(&oldview->deleg->owners);

	LIBDNS_DELEGDB_REUSE(newview->deleg);
}

typedef struct nodes_rcu_head {
	isc_mem_t *mctx;
	dns_qpmulti_t *nodes;
	struct rcu_head rcu_head;
} nodes_rcu_head_t;

static void
deleg_destroy_qpmulti(struct rcu_head *rcu_head) {
	nodes_rcu_head_t *nrh = caa_container_of(rcu_head, nodes_rcu_head_t,
						 rcu_head);

	dns_qpmulti_destroy(&nrh->nodes);

	isc_mem_putanddetach(&nrh->mctx, nrh, sizeof(*nrh));
}

inline static bool
isactive(delegdb_node_t *node, dns_ttl_t now) {
	return node->delegset->expires > now;
}

static void
getparentnode(dns_qpchain_t *chain, delegdb_node_t **node, dns_ttl_t now) {
	size_t len = dns_qpchain_length(chain);

	while (len >= 2) {
		delegdb_node_t *parent = NULL;
		dns_qpchain_node(chain, len - 2, (void **)&parent, NULL);

		if (isactive(parent, now)) {
			*node = parent;
			return;
		}
		len--;
	}

	/*
	 * No active proper ancestor was found in the chain.  Signal
	 * "no parent" so the caller does not mistake the original
	 * matched node for an ancestor.
	 */
	*node = NULL;
}

/*
 * NOTE: Caller needs to hold a RCU read critical section.
 */
static isc_result_t
dns__deleg_lookup(dns_delegdb_t *delegdb, dns_qpread_t *qpr,
		  const dns_name_t *name, isc_stdtime_t optnow,
		  unsigned int options, dns_name_t *zonecut,
		  dns_name_t *deepestzonecut, dns_delegset_t **delegsetp) {
	isc_result_t result = ISC_R_SUCCESS;
	delegdb_node_t *node = NULL;
	isc_stdtime_t now = optnow > 0 ? optnow : isc_stdtime_now();

	dns_qpchain_t chain = {};
	bool above = (options & DNS_DBFIND_ABOVE) != 0;

	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(dns_name_hasbuffer(zonecut));
	REQUIRE(deepestzonecut == NULL || dns_name_hasbuffer(deepestzonecut));

	result = dns_qp_lookup(qpr, name, DNS_DBNAMESPACE_NORMAL, NULL, &chain,
			       (void **)&node, NULL);

	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		return ISC_R_NOTFOUND;
	}
	INSIST(VALID_DELEGDB_NODE(node));

	if (deepestzonecut != NULL) {
		dns_name_copy(&node->zonecut, deepestzonecut);
	}

	/*
	 * Walk up the chain when:
	 *  - we have an exact match but the caller asked for DNS_DBFIND_ABOVE
	 *    (i.e. the caller wants the deepest *proper* ancestor), or
	 *  - the matched node is no longer active and we need to fall
	 *    back to the closest still-active ancestor (this applies
	 *    equally to exact and partial matches).
	 *
	 * getparentnode() sets 'node' to NULL when no active ancestor
	 * exists in the chain, so we must NULL-check before dereferencing
	 * 'node' below.
	 */
	if ((result == ISC_R_SUCCESS && above) || !isactive(node, now)) {
		getparentnode(&chain, &node, now);
	}

	if (node != NULL && isactive(node, now)) {
		dns_name_copy(&node->zonecut, zonecut);
		INSIST(node->delegset);
		dns_delegset_attach(node->delegset, delegsetp);
		ISC_SIEVE_MARK(node, visited);
		return ISC_R_SUCCESS;
	}

	/*
	 * The expired node will be replaced when the resolver fetches
	 * a fresh delegation, so there is no need to schedule explicit
	 * cleanup here.  Stale nodes that are never replaced will
	 * eventually be evicted by the SIEVE policy under memory
	 * pressure.
	 */
	return ISC_R_NOTFOUND;
}

isc_result_t
dns_delegdb_lookup(dns_delegdb_t *delegdb, const dns_name_t *name,
		   isc_stdtime_t now, unsigned int options, dns_name_t *zonecut,
		   dns_name_t *deepestzonecut, dns_delegset_t **delegsetp) {
	isc_result_t result = ISC_R_SHUTTINGDOWN;
	dns_qpmulti_t *nodes = NULL;
	dns_qpread_t qpr = {};
	char namebuf[DNS_NAME_FORMATSIZE];

	if (LIBDNS_DELEGDB_LOOKUP_START_ENABLED() ||
	    LIBDNS_DELEGDB_LOOKUP_DONE_ENABLED())
	{
		dns_name_format(name, namebuf, sizeof(namebuf));
	}
	LIBDNS_DELEGDB_LOOKUP_START(delegdb, namebuf);

	rcu_read_lock();
	nodes = rcu_dereference(delegdb->nodes);
	if (nodes != NULL) {
		dns_qpmulti_query(nodes, &qpr);

		result = dns__deleg_lookup(delegdb, &qpr, name, now, options,
					   zonecut, deepestzonecut, delegsetp);
		dns_qpread_destroy(nodes, &qpr);
	}
	rcu_read_unlock();

	LIBDNS_DELEGDB_LOOKUP_DONE(delegdb, namebuf, result);

	return result;
}

void
dns_delegset_allocset(dns_delegdb_t *delegdb, dns_delegset_t **delegsetp) {
	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(delegsetp != NULL && *delegsetp == NULL);

	dns_delegset_t *delegset = isc_mem_get(delegdb->mctx,
					       sizeof(*delegset));
	*delegset = (dns_delegset_t){
		.magic = DNS_DELEGSET_MAGIC,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.delegs = ISC_LIST_INITIALIZER,
	};
	isc_mem_attach(delegdb->mctx, &delegset->mctx);

	*delegsetp = delegset;
}

void
dns_delegset_allocdeleg(dns_delegset_t *delegset, dns_deleg_type_t type,
			dns_deleg_t **delegp) {
	dns_deleg_t *deleg = NULL;

	REQUIRE(DNS_DELEGSET_VALID(delegset));
	REQUIRE(delegp != NULL && *delegp == NULL);
	REQUIRE(type != DNS_DELEGTYPE_UNDEFINED);

	deleg = isc_mem_get(delegset->mctx, sizeof(*deleg));
	*deleg = (dns_deleg_t){ .addresses = ISC_LIST_INITIALIZER,
				.names = ISC_LIST_INITIALIZER,
				.type = type,
				.link = ISC_LINK_INITIALIZER };

	ISC_LIST_APPEND(delegset->delegs, deleg, link);
	*delegp = deleg;
}

void
dns_delegset_freedeleg(dns_delegset_t *delegset, dns_deleg_t **delegp) {
	REQUIRE(DNS_DELEGSET_VALID(delegset));
	REQUIRE(delegp != NULL && *delegp != NULL);
	REQUIRE(ISC_LIST_EMPTY((*delegp)->addresses));
	REQUIRE(ISC_LIST_EMPTY((*delegp)->names));

	dns_deleg_t *deleg = *delegp;
	*delegp = NULL;

	ISC_LIST_UNLINK(delegset->delegs, deleg, link);

	isc_mem_put(delegset->mctx, deleg, sizeof(*deleg));
}

void
dns_delegset_addaddr(dns_delegset_t *delegset, dns_deleg_t *deleg,
		     const isc_netaddr_t *addr) {
	isc_netaddrlink_t *addrlink = NULL;

	REQUIRE(DNS_DELEGSET_VALID(delegset));
	REQUIRE(deleg != NULL);
	REQUIRE(addr != NULL);
	REQUIRE(deleg->type == DNS_DELEGTYPE_DELEG_ADDRESSES ||
		deleg->type == DNS_DELEGTYPE_NS_GLUES);

	addrlink = isc_mem_get(delegset->mctx, sizeof(*addrlink));
	*addrlink = (isc_netaddrlink_t){ .addr = *addr,
					 .link = ISC_LINK_INITIALIZER };

	ISC_LIST_APPEND(deleg->addresses, addrlink, link);
}

static void
addname(dns_delegset_t *delegset, dns_namelist_t *list,
	const dns_name_t *name) {
	dns_name_t *clone = NULL;

	REQUIRE(DNS_DELEGSET_VALID(delegset));
	REQUIRE(DNS_NAME_VALID(name));

	clone = isc_mem_get(delegset->mctx, sizeof(*clone));
	dns_name_init(clone);
	dns_name_dup(name, delegset->mctx, clone);
	ISC_LIST_APPEND(*list, clone, link);
}

void
dns_delegset_adddelegparam(dns_delegset_t *delegset, dns_deleg_t *deleg,
			   const dns_name_t *name) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->type == DNS_DELEGTYPE_DELEG_PARAMS);
	addname(delegset, &deleg->names, name);
}

void
dns_delegset_addns(dns_delegset_t *delegset, dns_deleg_t *deleg,
		   const dns_name_t *name) {
	REQUIRE(deleg != NULL);

	REQUIRE(deleg->type == DNS_DELEGTYPE_DELEG_NAMES ||
		deleg->type == DNS_DELEGTYPE_NS_NAMES);
	addname(delegset, &deleg->names, name);
}

static void
delegdb_cleanup(dns_qp_t *qp, dns_delegdb_t *delegdb, size_t requested) {
	delegdb_node_t *node = NULL;
	size_t reclaimed = 0;

	if (!isc_mem_isovermem(delegdb->mctx)) {
		return;
	}

	LIBDNS_DELEGDB_CLEANUP_START(delegdb, (int)requested);

	while (reclaimed < requested) {
		node = ISC_SIEVE_NEXT(delegdb->lru[isc_tid()], visited, link);

		if (node == NULL) {
			break;
		}
		reclaimed += node->size;

		if (LIBDNS_DELEGDB_EVICT_ENABLED()) {
			char namebuf[DNS_NAME_FORMATSIZE];
			dns_name_format(&node->zonecut, namebuf,
					sizeof(namebuf));
			LIBDNS_DELEGDB_EVICT(delegdb, node, namebuf);
		}

		ISC_SIEVE_UNLINK(delegdb->lru[isc_tid()], node, link);
		(void)dns_qp_deletename(qp, &node->zonecut,
					DNS_DBNAMESPACE_NORMAL, NULL, NULL);
	}

	LIBDNS_DELEGDB_CLEANUP_DONE(delegdb, (int)reclaimed);
}

static size_t
delegset_size(dns_delegset_t *delegset) {
	size_t sz = 0;

	sz += sizeof(*delegset);
	ISC_LIST_FOREACH(delegset->delegs, deleg, link) {
		sz += sizeof(*deleg);
		ISC_LIST_FOREACH(deleg->addresses, address, link) {
			sz += sizeof(*address);
		}
		ISC_LIST_FOREACH(deleg->names, name, link) {
			sz += sizeof(*name) + dns_name_size(name);
		}
	}

	return sz;
}

static size_t
delegdb_node_size(const dns_name_t *zonecut, dns_delegset_t *delegset) {
	size_t sz = 0;

	sz += sizeof(delegdb_node_t);
	sz += dns_name_size(zonecut);
	sz += delegset_size(delegset);

	return sz;
}

static size_t
delegdb_node_prepare(dns_delegdb_t *delegdb, isc_stdtime_t now, dns_ttl_t ttl,
		     const dns_name_t *zonecut, dns_delegset_t *delegset,
		     delegdb_node_t **nodep) {
	if (ttl == 0) {
		ttl = 1;
	}
	delegset->expires = ttl + now;

	*nodep = isc_mem_get(delegdb->mctx, sizeof(**nodep));
	**nodep =
		(delegdb_node_t){ .magic = DELEGDB_NODE_MAGIC,
				  .references = ISC_REFCOUNT_INITIALIZER(1),
				  .zonecut = DNS_NAME_INITEMPTY,
				  .link = ISC_LINK_INITIALIZER,
				  .deadlink = ISC_LINK_INITIALIZER,
				  .size = delegdb_node_size(zonecut, delegset),
				  .loop = isc_loop_ref(isc_loop()) };

	dns_delegdb_attach(delegdb, &(*nodep)->delegdb);
	dns_delegset_attach(delegset, &(*nodep)->delegset);
	dns_name_dup(zonecut, delegdb->mctx, &(*nodep)->zonecut);

	return sizeof(**nodep) + (*nodep)->size;
}

isc_result_t
dns_delegset_insert(dns_delegdb_t *delegdb, const dns_name_t *zonecut,
		    dns_ttl_t ttl, dns_delegset_t *delegset) {
	isc_result_t result;
	delegdb_node_t *node = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t qpr = {};
	isc_stdtime_t now = isc_stdtime_now();
	dns_qpmulti_t *nodes = NULL;
	char zonecutbuf[DNS_NAME_FORMATSIZE];

	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(DNS_NAME_VALID(zonecut));
	REQUIRE(DNS_DELEGSET_VALID(delegset));

	/*
	 * Only delegset allocated by the delegdb memory context can be added in
	 * the delegdb. This exclude transient delegset built from rdataset (see
	 * dns_delegset_fromrdataset()).
	 */
	REQUIRE(delegset->mctx == delegdb->mctx);

	if (LIBDNS_DELEGDB_INSERT_START_ENABLED() ||
	    LIBDNS_DELEGDB_INSERT_DONE_ENABLED())
	{
		dns_name_format(zonecut, zonecutbuf, sizeof(zonecutbuf));
	}
	LIBDNS_DELEGDB_INSERT_START(delegdb, zonecutbuf);

	rcu_read_lock();
	nodes = rcu_dereference(delegdb->nodes);
	if (nodes == NULL) {
		CLEANUP(ISC_R_SHUTTINGDOWN);
	}

	/*
	 * First, check (without write txn) if the node already exists and is
	 * still valid.
	 */
	dns_qpmulti_query(nodes, &qpr);
	result = dns_qp_lookup(&qpr, zonecut, DNS_DBNAMESPACE_NORMAL, NULL,
			       NULL, (void **)&node, NULL);
	if (result == ISC_R_SUCCESS) {
		INSIST(VALID_DELEGDB_NODE(node));
		if (node->delegset->expires > now) {
			dns_qpread_destroy(nodes, &qpr);
			CLEANUP(ISC_R_EXISTS);
		}
	}
	dns_qpread_destroy(nodes, &qpr);

	/*
	 * We're about to add a new delegation, check for state of overmem, and
	 * clean up expired/least recently used delegation, then allocate and
	 * initialize a new node.
	 */
	size_t requested = delegdb_node_prepare(delegdb, now, ttl, zonecut,
						delegset, &node);

	/*
	 * Add the node in the DB
	 */
	dns_qpmulti_write(nodes, &qp);

	delegdb_cleanup(qp, delegdb, requested);

	if (result == ISC_R_SUCCESS) {
		/*
		 * A node at the same zonecut exists, and it is expired. Ignore
		 * the return value, in case the overriden node would be removed
		 * in meantime by someone else.
		 */
		(void)dns_qp_deletename(qp, zonecut, DNS_DBNAMESPACE_NORMAL,
					NULL, NULL);
	}

	result = dns_qp_insert(qp, node, 0);
	if (result != ISC_R_SUCCESS) {
		/*
		 * Someone else added the node before (and there was no node to
		 * delete).
		 */

		delegdb_node_unref(node);

		/*
		 * Since not using an update (but write) transaction,
		 * _rollback() won't work here.
		 */
		dns_qpmulti_commit(nodes, &qp);
		CLEANUP(ISC_R_EXISTS);
	}

	/*
	 * The new delegation is added, and can be referenced by SIEVE
	 */
	ISC_SIEVE_INSERT(delegdb->lru[isc_tid()], node, link);

	delegdb_node_unref(node);
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(nodes, &qp);

cleanup:
	rcu_read_unlock();

	LIBDNS_DELEGDB_INSERT_DONE(delegdb, zonecutbuf, result);

	return result;
}

static void
delegset_destroy(dns_delegset_t *delegset) {
	REQUIRE(DNS_DELEGSET_VALID(delegset));

	delegset->magic = 0;
	ISC_LIST_FOREACH(delegset->delegs, deleg, link) {
		deleg->type = DNS_DELEGTYPE_UNDEFINED;

		ISC_LIST_UNLINK(delegset->delegs, deleg, link);

		ISC_LIST_FOREACH(deleg->addresses, address, link) {
			ISC_LIST_UNLINK(deleg->addresses, address, link);
			isc_mem_put(delegset->mctx, address, sizeof(*address));
		}

		ISC_LIST_FOREACH(deleg->names, nameserver, link) {
			ISC_LIST_UNLINK(deleg->names, nameserver, link);
			dns_name_free(nameserver, delegset->mctx);
			isc_mem_put(delegset->mctx, nameserver,
				    sizeof(*nameserver));
		}

		isc_mem_put(delegset->mctx, deleg, sizeof(*deleg));
	}

	isc_mem_putanddetach(&delegset->mctx, delegset, sizeof(*delegset));
}
ISC_REFCOUNT_IMPL(dns_delegset, delegset_destroy);

static void
tostring_namelist(dns_namelist_t *namelist, const char *id, FILE *fp) {
	if (!ISC_LIST_EMPTY(*namelist)) {
		fprintf(fp, " %s=", id);
		ISC_LIST_FOREACH(*namelist, name, link) {
			isc_buffer_t nameb;
			char bdata[DNS_NAME_MAXWIRE] = { 0 };

			isc_buffer_init(&nameb, bdata, sizeof(bdata));
			dns_name_totext(name, 0, &nameb);
			fprintf(fp, "%s", bdata);

			if (name != ISC_LIST_TAIL(*namelist)) {
				fprintf(fp, ",");
			}
		}
	}
}

static void
deleg_tostring_addresses(dns_deleg_t *deleg, FILE *fp) {
	bool hasv4 = false;
	bool hasv6 = false;

	ISC_LIST_FOREACH(deleg->addresses, address, link) {
		if (address->addr.family == AF_INET) {
			hasv4 = true;
		} else {
			hasv6 = true;
		}
	}

	if (hasv4) {
		bool first = true;

		fprintf(fp, " server-ipv4=");
		ISC_LIST_FOREACH(deleg->addresses, address, link) {
			char addrstr[] = "255.255.255.255";

			if (address->addr.family == AF_INET6) {
				continue;
			}

			if (!first) {
				fprintf(fp, ",");
			}
			first = false;

			inet_ntop(AF_INET, &address->addr.type, addrstr,
				  sizeof(addrstr));
			fprintf(fp, "%s", addrstr);
		}
	}

	if (hasv6) {
		bool first = true;

		fprintf(fp, " server-ipv6=");
		ISC_LIST_FOREACH(deleg->addresses, address, link) {
			char addrstr[INET6_ADDRSTRLEN];

			if (address->addr.family == AF_INET) {
				continue;
			}

			if (!first) {
				fprintf(fp, ",");
			}
			first = false;

			inet_ntop(AF_INET6, &address->addr.type, addrstr,
				  sizeof(addrstr));
			fprintf(fp, "%s", addrstr);
		}
	}
}

static void
delegset_tostring(const dns_name_t *zonecut, dns_delegset_t *delegset,
		  isc_stdtime_t now, bool expired, FILE *fp) {
	ISC_LIST_FOREACH(delegset->delegs, deleg, link) {
		isc_buffer_t zonecutb;
		char bdata[DNS_NAME_MAXWIRE];
		dns_ttl_t ttl = 0;

		if (delegset->expires > now) {
			ttl = delegset->expires - now;
		} else {
			INSIST(expired);
		}

		isc_buffer_init(&zonecutb, bdata, sizeof(bdata));
		dns_name_totext(zonecut, 0, &zonecutb);
		fprintf(fp, "%s %u DELEG", bdata, ttl);

		if (deleg->type == DNS_DELEGTYPE_DELEG_ADDRESSES ||
		    deleg->type == DNS_DELEGTYPE_NS_GLUES)
		{
			deleg_tostring_addresses(deleg, fp);
		} else if (deleg->type == DNS_DELEGTYPE_DELEG_NAMES ||
			   deleg->type == DNS_DELEGTYPE_NS_NAMES)
		{
			tostring_namelist(&deleg->names, "server-name", fp);
		} else if (deleg->type == DNS_DELEGTYPE_DELEG_PARAMS) {
			tostring_namelist(&deleg->names, "include-delegparam",
					  fp);
		} else {
			UNREACHABLE();
		}

		fprintf(fp, "\n");
	}
}

void
dns_delegdb_dump(dns_delegdb_t *delegdb, bool expired, FILE *fp) {
	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(fp != NULL);

	dns_qpiter_t it;
	dns_qpread_t qpr = {};
	delegdb_node_t *node = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_qpmulti_t *nodes = NULL;

	rcu_read_lock();
	nodes = rcu_dereference(delegdb->nodes);
	if (nodes == NULL) {
		rcu_read_unlock();
		return;
	}

	dns_qpmulti_query(nodes, &qpr);

	dns_qpiter_init(&qpr, &it);
	while (dns_qpiter_next(&it, (void **)&node, NULL) == ISC_R_SUCCESS) {
		if (!expired && !isactive(node, now)) {
			continue;
		}

		delegset_tostring(&node->zonecut, node->delegset, now, expired,
				  fp);
	}

	dns_qpread_destroy(nodes, &qpr);

	rcu_read_unlock();
}

void
dns_delegset_fromnsrdataset(isc_mem_t *mctx, dns_rdataset_t *rdataset,
			    dns_delegset_t **delegsetp) {
	dns_delegset_t *delegset = NULL;
	dns_deleg_t *deleg = NULL;

	if (rdataset == NULL || !dns_rdataset_isassociated(rdataset) ||
	    delegsetp == NULL || *delegsetp != NULL)
	{
		return;
	}

	REQUIRE(rdataset->type == dns_rdatatype_ns);

	delegset = isc_mem_get(mctx, sizeof(*delegset));
	*delegset = (dns_delegset_t){
		.magic = DNS_DELEGSET_MAGIC,
		.mctx = isc_mem_ref(mctx),
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.delegs = ISC_LIST_INITIALIZER,
		.expires = rdataset->ttl + isc_stdtime_now(),
		.staticstub = rdataset->attributes.staticstub
	};

	deleg = isc_mem_get(delegset->mctx, sizeof(*deleg));
	*deleg = (dns_deleg_t){ .addresses = ISC_LIST_INITIALIZER,
				.names = ISC_LIST_INITIALIZER,
				.type = DNS_DELEGTYPE_NS_NAMES,
				.link = ISC_LINK_INITIALIZER };
	ISC_LIST_APPEND(delegset->delegs, deleg, link);

	DNS_RDATASET_FOREACH(rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_ns_t ns;

		dns_rdataset_current(rdataset, &rdata);
		dns_rdata_tostruct(&rdata, &ns, NULL);
		dns_delegset_addns(delegset, deleg, &ns.name);
	}

	*delegsetp = delegset;
}

static isc_result_t
deleg_deletetree(dns_qp_t *qp, const dns_name_t *name) {
	isc_result_t result;
	delegdb_node_t *node = NULL;
	dns_qpiter_t it;
	ISC_LIST(delegdb_node_t) deadnodes = ISC_LIST_INITIALIZER;

	result = dns_qp_lookup(qp, name, DNS_DBNAMESPACE_NORMAL, &it, NULL,
			       (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		goto out;
	}

	INSIST(VALID_DELEGDB_NODE(node));
	do {
		/*
		 * Because QP doesn't allow deleting a node while using the
		 * iterator, the approach is different than `deleg_deletenode()`
		 * here. Instead of removing the node immediately, we add it
		 * into a list that we'll go through after, then delete each
		 * node.
		 */
		ISC_LIST_APPEND(deadnodes, node, deadlink);

		result = dns_qpiter_next(&it, (void **)&node, NULL);
		if (result == ISC_R_NOMORE) {
			result = ISC_R_SUCCESS;
			break;
		}

		INSIST(VALID_DELEGDB_NODE(node));
		if (!dns_name_issubdomain(&node->zonecut, name)) {
			break;
		}
	} while (result == ISC_R_SUCCESS);

out:
	if (ISC_LIST_EMPTY(deadnodes)) {
		result = ISC_R_NOTFOUND;
	} else {
		/*
		 * Let's actually delete the deadnodes!
		 */
		ISC_LIST_FOREACH(deadnodes, deadnode, deadlink) {
			result = dns_qp_deletename(qp, &deadnode->zonecut,
						   DNS_DBNAMESPACE_NORMAL, NULL,
						   NULL);
			INSIST(result == ISC_R_SUCCESS);
		}
	}

	return result;
}

static isc_result_t
deleg_deletenode(dns_qp_t *qp, const dns_name_t *name) {
	return dns_qp_deletename(qp, name, DNS_DBNAMESPACE_NORMAL, NULL, NULL);
}

isc_result_t
dns_delegdb_delete(dns_delegdb_t *delegdb, const dns_name_t *name, bool tree) {
	REQUIRE(VALID_DELEGDB(delegdb));
	REQUIRE(DNS_NAME_VALID(name));

	dns_qpmulti_t *nodes = NULL;
	dns_qp_t *qp = NULL;
	isc_result_t result = ISC_R_SHUTTINGDOWN;
	char namebuf[DNS_NAME_FORMATSIZE];

	if (LIBDNS_DELEGDB_DELETE_ENABLED()) {
		dns_name_format(name, namebuf, sizeof(namebuf));
	}

	rcu_read_lock();
	nodes = rcu_dereference(delegdb->nodes);
	if (nodes != NULL) {
		dns_qpmulti_write(nodes, &qp);
		if (tree) {
			result = deleg_deletetree(qp, name);
		} else {
			result = deleg_deletenode(qp, name);
		}
		if (result == ISC_R_SUCCESS) {
			dns_qp_compact(qp, DNS_QPGC_MAYBE);
		}
		dns_qpmulti_commit(nodes, &qp);
	}
	rcu_read_unlock();

	LIBDNS_DELEGDB_DELETE(delegdb, namebuf, (int)tree, result);

	return result;
}

static void
delegdb_shutdown_async(void *arg) {
	dns_delegdb_t *delegdb = arg;

	REQUIRE(isc_loop_get(isc_tid()) == isc_loop_main());
	REQUIRE(delegdb != NULL && VALID_DELEGDB(delegdb));

	if (isc_refcount_decrement(&delegdb->owners) == 1) {
		dns_qpmulti_t *nodes = rcu_xchg_pointer(&delegdb->nodes, NULL);

		if (nodes != NULL) {
			nodes_rcu_head_t *nrh = isc_mem_get(delegdb->mctx,
							    sizeof(*nrh));
			*nrh = (nodes_rcu_head_t){
				.mctx = isc_mem_ref(delegdb->mctx),
				.nodes = nodes,
			};
			call_rcu(&nrh->rcu_head, deleg_destroy_qpmulti);
		}
		LIBDNS_DELEGDB_SHUTDOWN(delegdb);
	}
}

void
dns_delegdb_shutdown(dns_delegdb_t *delegdb) {
	if (isc_loop_get(isc_tid()) == isc_loop_main()) {
		delegdb_shutdown_async(delegdb);
	} else {
		isc_async_run(isc_loop_main(), delegdb_shutdown_async, delegdb);
	}
}

static void
delegdb_setsize(dns_delegdb_t *delegdb, size_t size) {
	size_t lowater;
	size_t hiwater;

	REQUIRE(VALID_DELEGDB(delegdb));

	if (size != 0 && size < DELEGDB_MINSIZE) {
		size = DELEGDB_MINSIZE;
	}

	hiwater = size - (size >> 3); /* Approximately 7/8ths. */
	lowater = size - (size >> 2); /* Approximately 3/4ths. */

	if (size == 0 || hiwater == 0 || lowater == 0) {
		isc_mem_clearwater(delegdb->mctx);

		/*
		 * TODO: Is it worth a warning if size > 0? Sounds like
		 * implicit overmem bypass, so the user should be warned...
		 */
	} else {
		isc_mem_setwater(delegdb->mctx, hiwater, lowater);
	}
}

dns_delegdb_config_t
dns_delegdb_getconfig(dns_delegdb_t *delegdb) {
	REQUIRE(VALID_DELEGDB(delegdb));
	return delegdb->config;
}

void
dns_delegdb_setconfig(dns_delegdb_t *delegdb,
		      const dns_delegdb_config_t *config) {
	REQUIRE(isc_loop_get(isc_tid()) == isc_loop_main());
	REQUIRE(VALID_DELEGDB(delegdb));

	delegdb->config = *config;

	delegdb_setsize(delegdb, delegdb->config.dbsize);
}
