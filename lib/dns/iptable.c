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

static bool dns_iptable_neg = false;
static bool dns_iptable_pos = true;

/*
 * Add an IP prefix to an existing IP table
 */
static void
iptable_addentry(dns_iptable_t *tab, isc_prefix_t *pfx, bool pos) {
	isc_radix_node_t *node = NULL;

	isc_radix_insert(tab->radix, &node, NULL, pfx);

	/* Preserve first-match semantics: don't overwrite existing data */
	int fam = ISC_RADIX_FAMILY(pfx);
	if (node->data[fam] == NULL) {
		node->data[fam] = pos ? &dns_iptable_pos : &dns_iptable_neg;
	}
}

void
dns_iptable_addprefix(dns_iptable_t *tab, const isc_netaddr_t *addr,
		      uint16_t bitlen, bool pos) {
	INSIST(DNS_IPTABLE_VALID(tab));
	INSIST(tab->radix != NULL);

	if (addr == NULL) {
		/*
		 * "any" or "none": insert both IPv4 and IPv6 wildcard
		 * entries so they match all addresses.
		 */
		isc_prefix_t pfx4 = { .family = AF_INET, .bitlen = 0 };
		isc_prefix_t pfx6 = { .family = AF_INET6, .bitlen = 0 };

		iptable_addentry(tab, &pfx4, pos);
		iptable_addentry(tab, &pfx6, pos);
		return;
	}

	isc_prefix_t pfx;
	NETADDR_TO_PREFIX_T(addr, pfx, bitlen);
	iptable_addentry(tab, &pfx, pos);
}

/*
 * Merge one IP table into another one.
 */
void
dns_iptable_merge(dns_iptable_t *tab, dns_iptable_t *source, bool pos) {
	isc_radix_node_t *node, *new_node;
	int max_node = 0;

	RADIX_WALK(source->radix->head, node) {
		new_node = NULL;
		isc_radix_insert(tab->radix, &new_node, node, NULL);

		/*
		 * If we're negating a nested ACL, then we should
		 * reverse the sense of every node.  However, this
		 * could lead to a negative node in a nested ACL
		 * becoming a positive match in the parent, which
		 * could be a security risk.  To prevent this, we
		 * just leave the negative nodes negative.
		 */
		for (int i = 0; i < RADIX_FAMILIES; i++) {
			if (!pos) {
				if (node->data[i] != NULL &&
				    *(bool *)node->data[i])
				{
					new_node->data[i] = &dns_iptable_neg;
				}
			}
			if (node->node_num[i] > max_node) {
				max_node = node->node_num[i];
			}
		}
	}
	RADIX_WALK_END;

	tab->radix->num_added_node += max_node;
}

static void
dns__iptable_destroy(dns_iptable_t *dtab) {
	REQUIRE(DNS_IPTABLE_VALID(dtab));

	dtab->magic = 0;

	if (dtab->radix != NULL) {
		isc_radix_destroy(dtab->radix, NULL);
		dtab->radix = NULL;
	}

	isc_mem_putanddetach(&dtab->mctx, dtab, sizeof(*dtab));
}

#if DNS_IPTABLE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_iptable, dns__iptable_destroy);
#else
ISC_REFCOUNT_IMPL(dns_iptable, dns__iptable_destroy);
#endif
