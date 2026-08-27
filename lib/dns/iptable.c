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
isc_result_t
dns_iptable_addprefix(dns_iptable_t *tab, const isc_netaddr_t *addr,
		      uint16_t bitlen, bool pos) {
	isc_prefix_t pfx;
	isc_radix_node_t *node = NULL;
	int i;

	INSIST(DNS_IPTABLE_VALID(tab));
	INSIST(tab->radix != NULL);

	NETADDR_TO_PREFIX_T(addr, pfx, bitlen);

	isc_radix_insert(tab->radix, &node, NULL, &pfx);
	if (pfx.family == AF_UNSPEC) {
		/* "any" or "none" */
		INSIST(pfx.bitlen == 0);
		for (i = 0; i < RADIX_FAMILIES; i++) {
			if (node->data[i] == NULL) {
				node->data[i] = pos ? &dns_iptable_pos
						    : &dns_iptable_neg;
			}
		}
	} else {
		/* any other prefix */
		int fam = ISC_RADIX_FAMILY(&pfx);
		if (node->data[fam] == NULL) {
			node->data[fam] = pos ? &dns_iptable_pos
					      : &dns_iptable_neg;
		}
	}

	isc_refcount_destroy(&pfx.refcount);
	return ISC_R_SUCCESS;
}

/*
 * Merge one IP table into another one.
 */
isc_result_t
dns_iptable_merge(dns_iptable_t *tab, dns_iptable_t *source, bool pos) {
	isc_result_t result;
	isc_radix_node_t *node, *new_node;
	int i, max_node = 0;

	RADIX_WALK(source->radix->head, node) {
		new_node = NULL;
		result = isc_radix_insert(tab->radix, &new_node, node, NULL);

		/*
		 * If we're negating a nested ACL, e.g.,
		 *
		 * { 10.53.0.1; !{ 10/8; }; }
		 *
		 * ... we don't want to reverse the sense of all the nodes,
		 * because then negative nodes would become positive when
		 * merged into the parent, allowing unwanted
		 * addresses to match. Instead, we flip positive entries to
		 * changed to negative, but leave negative entries unchanged.
		 *
		 * Note that if the prefix for this node is an exact match
		 * to an existing prefix (in which case isc_radix_insert()
		 * would have returned ISC_R_EXISTS), then we don't update
		 * the existing node at all.
		 */
		for (i = 0; i < RADIX_FAMILIES; i++) {
			if (!pos) {
				if (result == ISC_R_SUCCESS && node->data[i] &&
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
	return ISC_R_SUCCESS;
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
