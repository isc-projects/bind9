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

#include <stdbool.h>

#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/nametree.h>
#include <dns/qp.h>

#define NAMETREE_MAGIC	   ISC_MAGIC('N', 'T', 'r', 'e')
#define VALID_NAMETREE(kt) ISC_MAGIC_VALID(kt, NAMETREE_MAGIC)

struct dns_nametree {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_qpmulti_t *table;
	char name[64];
};

struct dns_ntnode {
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_fixedname_t fn;
	dns_name_t *name;
	union {
		bool value;
		unsigned char *bits;
	};
};

/* QP trie methods */
static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static void
destroy_ntnode(dns_ntnode_t *node) {
	isc_refcount_destroy(&node->references);
	isc_mem_putanddetach(&node->mctx, node, sizeof(dns_ntnode_t));
}

#if DNS_NAMETREE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_ntnode, destroy_ntnode);
#else
ISC_REFCOUNT_IMPL(dns_ntnode, destroy_ntnode);
#endif

void
dns_nametree_create(isc_mem_t *mctx, const char *name, dns_nametree_t **ntp) {
	dns_nametree_t *nametree = NULL;

	REQUIRE(ntp != NULL && *ntp == NULL);

	nametree = isc_mem_get(mctx, sizeof(*nametree));
	*nametree = (dns_nametree_t){
		.magic = NAMETREE_MAGIC,
	};
	isc_mem_attach(mctx, &nametree->mctx);
	isc_refcount_init(&nametree->references, 1);

	if (name != NULL) {
		strlcpy(nametree->name, name, sizeof(nametree->name));
	}

	dns_qpmulti_create(mctx, &qpmethods, nametree, &nametree->table);
	*ntp = nametree;
}

static void
destroy_nametree(dns_nametree_t *nametree) {
	nametree->magic = 0;

	dns_qpmulti_destroy(&nametree->table);
	isc_refcount_destroy(&nametree->references);

	isc_mem_putanddetach(&nametree->mctx, nametree, sizeof(*nametree));
}

#if DNS_NAMETREE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_nametree, destroy_nametree);
#else
ISC_REFCOUNT_IMPL(dns_nametree, destroy_nametree);
#endif

static dns_ntnode_t *
newnode(isc_mem_t *mctx, const dns_name_t *name) {
	dns_ntnode_t *node = isc_mem_get(mctx, sizeof(*node));
	*node = (dns_ntnode_t){ 0 };
	isc_mem_attach(mctx, &node->mctx);
	isc_refcount_init(&node->references, 1);

	node->name = dns_fixedname_initname(&node->fn);
	dns_name_copy(name, node->name);

	return (node);
}

isc_result_t
dns_nametree_add(dns_nametree_t *nametree, const dns_name_t *name, bool value) {
	isc_result_t result;
	dns_qp_t *qp = NULL;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);

	dns_qpmulti_write(nametree->table, &qp);

	result = dns_qp_getname(qp, name, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		result = ISC_R_EXISTS;
	} else {
		dns_ntnode_t *node = newnode(nametree->mctx, name);
		node->value = value;
		result = dns_qp_insert(qp, node, 0);

		/*
		 * We detach the node here, so any dns_qp_deletename() will
		 * destroy the node directly.
		 */
		dns_ntnode_detach(&node);
	}

	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(nametree->table, &qp);
	return (result);
}

isc_result_t
dns_nametree_delete(dns_nametree_t *nametree, const dns_name_t *name) {
	isc_result_t result;
	dns_qp_t *qp = NULL;
	void *pval = NULL;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);

	dns_qpmulti_write(nametree->table, &qp);
	result = dns_qp_deletename(qp, name, &pval, NULL);
	if (result == ISC_R_SUCCESS) {
		dns_ntnode_t *n = pval;
		dns_ntnode_detach(&n);
	}
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(nametree->table, &qp);

	return (result);
}

isc_result_t
dns_nametree_find(dns_nametree_t *nametree, const dns_name_t *name,
		  dns_ntnode_t **ntnodep) {
	isc_result_t result;
	dns_qpread_t qpr;
	void *pval = NULL;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);
	REQUIRE(ntnodep != NULL && *ntnodep == NULL);

	dns_qpmulti_query(nametree->table, &qpr);
	result = dns_qp_getname(&qpr, name, &pval, NULL);
	if (result == ISC_R_SUCCESS) {
		dns_ntnode_t *knode = pval;
		dns_ntnode_attach(knode, ntnodep);
	}
	dns_qpread_destroy(nametree->table, &qpr);

	return (result);
}

bool
dns_nametree_covered(dns_nametree_t *nametree, const dns_name_t *name) {
	isc_result_t result;
	dns_qpread_t qpr;
	dns_ntnode_t *ntnode = NULL;
	void *pval = NULL;
	bool value = false;

	REQUIRE(nametree == NULL || VALID_NAMETREE(nametree));

	if (nametree == NULL) {
		return (false);
	}

	dns_qpmulti_query(nametree->table, &qpr);
	result = dns_qp_findname_ancestor(&qpr, name, 0, &pval, NULL);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		ntnode = pval;
		value = ntnode->value;
	}

	dns_qpread_destroy(nametree->table, &qpr);
	return (value);
}

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_ntnode_t *ntnode = pval;
	dns_ntnode_ref(ntnode);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_ntnode_t *ntnode = pval;
	dns_ntnode_detach(&ntnode);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	dns_ntnode_t *ntnode = pval;
	return (dns_qpkey_fromname(key, ntnode->name));
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	dns_nametree_t *nametree = uctx;
	snprintf(buf, size, "%s nametree", nametree->name);
}
