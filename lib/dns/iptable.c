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

#include <inttypes.h>
#include <stdbool.h>

#include <isc/mem.h>
#include <isc/radix.h>
#include <isc/util.h>

#include <dns/acl.h>

/*
 * Create a new IP table and the underlying radix structure
 */
void
dns_iptable_create(isc_mem_t *mctx, dns_iptable_t **target) {
	dns_iptable_t *tab = isc_mem_get(mctx, sizeof(*tab));
	*tab = (dns_iptable_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.magic = DNS_IPTABLE_MAGIC,
	};
	isc_mem_attach(mctx, &tab->mctx);

	isc_radix_create(mctx, &tab->radix, RADIX_MAXBITS);

	*target = tab;
}

/*
 * Add an IP prefix to an existing IP table
 */
static void
iptable_addentry(dns_iptable_t *tab, isc_prefix_t *pfx,
		 isc_radix_match_t match) {
	isc_radix_node_t *node = NULL;

	isc_radix_insert(tab->radix, &node, NULL, pfx);

	/* Preserve first-match semantics: don't overwrite existing data */
	int fam = ISC_RADIX_FAMILY(pfx);
	if (node->match[fam] == RADIX_UNSET) {
		node->match[fam] = match;
	}
}

void
dns_iptable_addprefix(dns_iptable_t *tab, const isc_netaddr_t *addr,
		      uint16_t bitlen, isc_radix_match_t match) {
	INSIST(DNS_IPTABLE_VALID(tab));
	INSIST(tab->radix != NULL);

	if (addr == NULL) {
		/*
		 * "any" or "none": insert both IPv4 and IPv6 wildcard
		 * entries so they match all addresses.
		 */
		isc_prefix_t pfx4 = { .family = AF_INET, .bitlen = 0 };
		isc_prefix_t pfx6 = { .family = AF_INET6, .bitlen = 0 };

		iptable_addentry(tab, &pfx4, match);
		iptable_addentry(tab, &pfx6, match);
		return;
	}

	isc_prefix_t pfx;
	isc_prefix_from_netaddr(&pfx, addr, bitlen);
	iptable_addentry(tab, &pfx, match);
}

typedef struct {
	dns_iptable_t *tab;
	bool negate;
	int32_t max_node;
} iptable_merge_ctx_t;

static void
iptable_merge_node(isc_radix_node_t *node, void *arg) {
	iptable_merge_ctx_t *ctx = arg;
	isc_radix_node_t *new_node = NULL;

	isc_radix_insert(ctx->tab->radix, &new_node, node, NULL);

	/*
	 * If we're negating a nested ACL, then we should
	 * reverse the sense of every node.  However, this
	 * could lead to a negative node in a nested ACL
	 * becoming a positive match in the parent, which
	 * could be a security risk.  To prevent this, we
	 * just leave the negative nodes negative.
	 */
	for (size_t i = 0; i < RADIX_FAMILIES; i++) {
		if (ctx->negate && node->match[i] == RADIX_ALLOW) {
			new_node->match[i] = RADIX_DENY;
		}
		if (node->node_num[i] > ctx->max_node) {
			ctx->max_node = node->node_num[i];
		}
	}
}

/*
 * Merge one IP table into another one.
 */
void
dns_iptable_merge(dns_iptable_t *tab, dns_iptable_t *source, bool negate) {
	iptable_merge_ctx_t ctx = { .tab = tab, .negate = negate };

	isc_radix_foreach(source->radix, iptable_merge_node, &ctx);

	tab->radix->num_added_node += ctx.max_node;
}

static void
dns__iptable_destroy(dns_iptable_t *dtab) {
	REQUIRE(DNS_IPTABLE_VALID(dtab));

	dtab->magic = 0;

	if (dtab->radix != NULL) {
		isc_radix_destroy(dtab->radix);
		dtab->radix = NULL;
	}

	isc_mem_putanddetach(&dtab->mctx, dtab, sizeof(*dtab));
}

#if DNS_IPTABLE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_iptable, dns__iptable_destroy);
#else
ISC_REFCOUNT_IMPL(dns_iptable, dns__iptable_destroy);
#endif
