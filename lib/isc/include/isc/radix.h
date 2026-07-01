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

#pragma once

#include <inttypes.h>
#include <string.h>

#include <isc/magic.h>
#include <isc/net.h>
#include <isc/netaddr.h>
#include <isc/types.h>

typedef struct isc_prefix {
	sa_family_t family; /* AF_INET | AF_INET6 (0 means no prefix) */
	uint8_t	    bitlen; /* prefix length in bits (max 128) */
	union {
		struct in_addr	sin;
		struct in6_addr sin6;
	} add;
} isc_prefix_t;

static inline void
isc_prefix_from_netaddr(isc_prefix_t *pfx, const isc_netaddr_t *na,
			uint8_t bitlen) {
	*pfx = (isc_prefix_t){ .family = na->family, .bitlen = bitlen };
	if (na->family == AF_INET6) {
		memmove(&pfx->add.sin6, &na->type.in6, (bitlen + 7) / 8);
	} else {
		memmove(&pfx->add.sin, &na->type.in, (bitlen + 7) / 8);
	}
}

#define isc_prefix_touint8(prefix) ((uint8_t *)&(prefix)->add.sin)

/*
 * Test whether bit 'n' (0 = MSB) is set in the byte array 'addr'.
 */
static inline bool
isc_prefix_bit_isset(const uint8_t *addr, unsigned int n) {
	return (addr[n / 8] & (1 << (7 - n % 8))) != 0;
}

/*
 * We need "first match" when we search the radix tree to preserve
 * compatibility with the existing ACL implementation. Radix trees
 * naturally lend themselves to "best match". In order to get "first match"
 * behavior, we keep track of the order in which entries are added to the
 * tree--and when a search is made, we find all matching entries, and
 * return the one that was added first.
 *
 * An IPv4 prefix and an IPv6 prefix may share a radix tree node if they
 * have the same length and bit pattern (e.g., 127/8 and 7f::/8).  To
 * disambiguate between them, node_num and data are two-element arrays:
 *
 *   - node_num[0] and data[0] are used for IPv4 client addresses
 *   - node_num[1] and data[1] are used for IPv6 client addresses
 *
 * A prefix of 0/0 (aka "any" or "none"), is always stored as IPv4,
 * but matches all IPv6 addresses too.
 */

#define RADIX_V4       0
#define RADIX_V6       1
#define RADIX_FAMILIES 2

#define ISC_RADIX_FAMILY(p) (((p)->family == AF_INET6) ? RADIX_V6 : RADIX_V4)

typedef enum {
	RADIX_UNSET = 0, /* no entry for this address family */
	RADIX_ALLOW,	 /* positive match (allow) */
	RADIX_DENY,	 /* negative match (deny) */
} isc_radix_match_t;

typedef struct isc_radix_node {
	struct isc_radix_node *left, *right; /* children */
	struct isc_radix_node *parent;
	isc_prefix_t	       prefix;	  /* family==0 for glue nodes */
	int32_t node_num[RADIX_FAMILIES]; /* insertion order, -1 = glue */
	isc_radix_match_t match[RADIX_FAMILIES];
	uint8_t		  bit; /* bit position in the key */
} isc_radix_node_t;

typedef void (*isc_radix_foreachfunc_t)(isc_radix_node_t *node, void *arg);

#define RADIX_TREE_MAGIC    ISC_MAGIC('R', 'd', 'x', 'T')
#define RADIX_TREE_VALID(a) ISC_MAGIC_VALID(a, RADIX_TREE_MAGIC)

typedef struct isc_radix_tree {
	unsigned int	  magic;
	uint8_t		  maxbits;
	isc_mem_t	 *mctx;
	isc_radix_node_t *head;
	int32_t		  num_active_node; /* for debugging purposes */
	int32_t		  num_added_node;  /* total number of nodes */
} isc_radix_tree_t;

isc_result_t
isc_radix_search(isc_radix_tree_t *radix, isc_radix_node_t **target,
		 isc_prefix_t *prefix);
/*%<
 * Search 'radix' for the best match to 'prefix'.
 * Return the node found in '*target'.
 *
 * Requires:
 * \li	'radix' to be valid.
 * \li	'target' is not NULL and "*target" is NULL.
 * \li	'prefix' to be valid.
 *
 * Returns:
 * \li	ISC_R_NOTFOUND
 * \li	ISC_R_SUCCESS
 */

void
isc_radix_insert(isc_radix_tree_t *radix, isc_radix_node_t **target,
		 isc_radix_node_t *source, isc_prefix_t *prefix);
/*%<
 * Insert 'source' or 'prefix' into the radix tree 'radix'.
 * Return the node added in 'target'.
 *
 * Requires:
 * \li	'radix' to be valid.
 * \li	'target' is not NULL and "*target" is NULL.
 * \li	'prefix' to be valid or 'source' to be non NULL and contain
 *	a valid prefix.
 */

void
isc_radix_remove(isc_radix_tree_t *radix, isc_radix_node_t *node);
/*%<
 * Remove the node 'node' from the radix tree 'radix'.
 *
 * Requires:
 * \li	'radix' to be valid.
 * \li	'node' to be valid.
 */

void
isc_radix_create(isc_mem_t *mctx, isc_radix_tree_t **target, uint8_t maxbits);
/*%<
 * Create a radix tree with a maximum depth of 'maxbits';
 *
 * Requires:
 * \li	'mctx' to be valid.
 * \li	'target' to be non NULL and '*target' to be NULL.
 * \li	'maxbits' to be less than or equal to RADIX_MAXBITS.
 */

void
isc_radix_destroy(isc_radix_tree_t *radix);
/*%<
 * Destroy a radix tree.
 *
 * Requires:
 * \li	'radix' to be valid.
 */

void
isc_radix_foreach(isc_radix_tree_t *radix, isc_radix_foreachfunc_t func,
		  void *arg);
/*%<
 * Walk a radix tree calling 'func' for each node that has a prefix.
 *
 * Requires:
 * \li	'radix' to be valid.
 * \li	'func' to point to a function.
 */

#define RADIX_MAXBITS 128
