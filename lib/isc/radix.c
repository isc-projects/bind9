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

#include <isc/mem.h>
#include <isc/radix.h>
#include <isc/types.h>
#include <isc/util.h>

#define BIT_TEST(f, b) (((f) & (b)) != 0)

static int
comp_with_mask(void *addr, void *dest, u_int mask) {
	/* Mask length of zero matches everything */
	if (mask == 0) {
		return 1;
	}

	if (memcmp(addr, dest, mask / 8) == 0) {
		u_int n = mask / 8;
		u_int m = ((~0U) << (8 - (mask % 8)));

		if ((mask % 8) == 0 ||
		    (((u_char *)addr)[n] & m) == (((u_char *)dest)[n] & m))
		{
			return 1;
		}
	}
	return 0;
}

static isc_radix_node_t *
radix_node_create(isc_mem_t *mctx, isc_prefix_t *prefix, uint32_t bit) {
	isc_radix_node_t *node = isc_mem_get(mctx, sizeof(*node));
	*node = (isc_radix_node_t){
		.bit = bit,
		.node_num = { -1, -1 },
	};
	if (prefix != NULL) {
		node->prefix = *prefix;
	}
	return node;
}

void
isc_radix_create(isc_mem_t *mctx, isc_radix_tree_t **target, int maxbits) {
	REQUIRE(target != NULL && *target == NULL);
	RUNTIME_CHECK(maxbits <= RADIX_MAXBITS);

	isc_radix_tree_t *radix = isc_mem_get(mctx, sizeof(isc_radix_tree_t));
	*radix = (isc_radix_tree_t){
		.maxbits = maxbits,
		.magic = RADIX_TREE_MAGIC,
	};
	isc_mem_attach(mctx, &radix->mctx);
	*target = radix;
}

/*
 * if func is supplied, it will be called as func(node->data)
 * before deleting the node
 */

static void
clear_radix(isc_radix_tree_t *radix, isc_radix_destroyfunc_t func) {
	isc_radix_node_t *stack[RADIX_MAXBITS + 1];
	isc_radix_node_t **sp = stack;
	isc_radix_node_t *cur = radix->head;

	REQUIRE(radix != NULL);

	while (cur != NULL) {
		isc_radix_node_t *l = cur->left;
		isc_radix_node_t *r = cur->right;

		if (cur->prefix.family != 0) {
			if (func != NULL) {
				func(cur->data);
			}
		} else {
			INSIST(cur->data[RADIX_V4] == NULL &&
			       cur->data[RADIX_V6] == NULL);
		}

		isc_mem_put(radix->mctx, cur, sizeof(*cur));
		radix->num_active_node--;

		if (l != NULL) {
			if (r != NULL) {
				*sp++ = r;
			}
			cur = l;
		} else if (r != NULL) {
			cur = r;
		} else if (sp != stack) {
			cur = *(--sp);
		} else {
			cur = NULL;
		}
	}

	RUNTIME_CHECK(radix->num_active_node == 0);
}

void
isc_radix_destroy(isc_radix_tree_t *radix, isc_radix_destroyfunc_t func) {
	REQUIRE(radix != NULL);
	clear_radix(radix, func);
	isc_mem_putanddetach(&radix->mctx, radix, sizeof(*radix));
}

/*
 * func will be called as func(node->prefix, node->data)
 */
void
isc_radix_process(isc_radix_tree_t *radix, isc_radix_processfunc_t func) {
	isc_radix_node_t *node;

	REQUIRE(func != NULL);

	RADIX_WALK(radix->head, node) { func(&node->prefix, node->data); }
	RADIX_WALK_END;
}

isc_result_t
isc_radix_search(isc_radix_tree_t *radix, isc_radix_node_t **target,
		 isc_prefix_t *prefix) {
	isc_radix_node_t *stack[RADIX_MAXBITS + 1];
	int cnt = 0;

	REQUIRE(radix != NULL);
	REQUIRE(prefix != NULL);
	REQUIRE(target != NULL && *target == NULL);
	RUNTIME_CHECK(prefix->bitlen <= radix->maxbits);

	*target = NULL;

	if (radix->head == NULL) {
		return ISC_R_NOTFOUND;
	}

	/* Walk the tree collecting candidate nodes. */
	u_char *addr = isc_prefix_touchar(prefix);
	uint32_t bitlen = prefix->bitlen;
	isc_radix_node_t *node = radix->head;

	while (node != NULL && node->bit < bitlen) {
		if (node->prefix.family != 0) {
			stack[cnt++] = node;
		}

		if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
		{
			node = node->right;
		} else {
			node = node->left;
		}
	}

	if (node != NULL && node->prefix.family != 0) {
		stack[cnt++] = node;
	}

	/* Find the first-inserted matching node among the candidates. */
	int tfam = -1;
	while (cnt-- > 0) {
		node = stack[cnt];

		if (prefix->bitlen < node->bit) {
			continue;
		}

		if (comp_with_mask(isc_prefix_tochar(&node->prefix),
				   isc_prefix_tochar(prefix),
				   node->prefix.bitlen))
		{
			int fam = ISC_RADIX_FAMILY(prefix);
			if (node->node_num[fam] != -1 &&
			    ((*target == NULL) ||
			     (*target)->node_num[tfam] > node->node_num[fam]))
			{
				*target = node;
				tfam = fam;
			}
		}
	}

	if (*target == NULL) {
		return ISC_R_NOTFOUND;
	}

	return ISC_R_SUCCESS;
}

void
isc_radix_insert(isc_radix_tree_t *radix, isc_radix_node_t **target,
		 isc_radix_node_t *source, isc_prefix_t *prefix) {
	isc_radix_node_t *node;

	REQUIRE(radix != NULL);
	REQUIRE(target != NULL && *target == NULL);
	REQUIRE(prefix != NULL ||
		(source != NULL && source->prefix.family != 0));
	RUNTIME_CHECK(prefix == NULL || prefix->bitlen <= radix->maxbits);

	if (prefix == NULL) {
		prefix = &source->prefix;
	}

	INSIST(prefix != NULL);

	uint32_t bitlen = prefix->bitlen;

	if (radix->head == NULL) {
		node = radix_node_create(radix->mctx, prefix, bitlen);
		if (source != NULL) {
			/*
			 * If source is non-NULL, then we're merging in a
			 * node from an existing radix tree.  To keep
			 * the node_num values consistent, the calling
			 * function will add the total number of nodes
			 * added to num_added_node at the end of
			 * the merge operation--we don't do it here.
			 */
			for (size_t i = 0; i < RADIX_FAMILIES; i++) {
				if (source->node_num[i] != -1) {
					node->node_num[i] =
						radix->num_added_node +
						source->node_num[i];
				}
				node->data[i] = source->data[i];
			}
		} else {
			int next = ++radix->num_added_node;
			node->node_num[ISC_RADIX_FAMILY(prefix)] = next;
		}
		radix->head = node;
		radix->num_active_node++;
		*target = node;
		return;
	}

	u_char *addr = isc_prefix_touchar(prefix);
	node = radix->head;

	while (node->bit < bitlen || node->prefix.family == 0) {
		if (node->bit < radix->maxbits &&
		    BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
		{
			if (node->right == NULL) {
				break;
			}
			node = node->right;
		} else {
			if (node->left == NULL) {
				break;
			}
			node = node->left;
		}

		INSIST(node != NULL);
	}

	INSIST(node->prefix.family != 0);

	/* Find the first bit different. */
	u_char *test_addr = isc_prefix_touchar(&node->prefix);
	uint32_t check_bit = (node->bit < bitlen) ? node->bit : bitlen;
	uint32_t differ_bit = 0;
	for (size_t i = 0; i * 8 < check_bit; i++) {
		uint8_t r = addr[i] ^ test_addr[i];
		if (r == 0) {
			differ_bit = (i + 1) * 8;
			continue;
		}
		uint8_t j;
		for (j = 0; j < 8; j++) {
			if (BIT_TEST(r, 0x80 >> j)) {
				break;
			}
		}
		INSIST(j < 8);
		differ_bit = i * 8 + j;
		break;
	}

	if (differ_bit > check_bit) {
		differ_bit = check_bit;
	}

	isc_radix_node_t *parent = node->parent;
	while (parent != NULL && parent->bit >= differ_bit) {
		node = parent;
		parent = node->parent;
	}

	if (differ_bit == bitlen && node->bit == bitlen) {
		if (node->prefix.family != 0) {
			/* Set node_num only if it hasn't been set before */
			if (source != NULL) {
				/* Merging nodes */
				for (size_t i = 0; i < RADIX_FAMILIES; i++) {
					if (node->node_num[i] == -1 &&
					    source->node_num[i] != -1)
					{
						node->node_num[i] =
							radix->num_added_node +
							source->node_num[i];
						node->data[i] = source->data[i];
					}
				}
			} else {
				int foff = ISC_RADIX_FAMILY(prefix);
				if (node->node_num[foff] == -1) {
					node->node_num[foff] =
						++radix->num_added_node;
				}
			}
			*target = node;
			return;
		} else {
			node->prefix = *prefix;
		}
		INSIST(node->data[RADIX_V4] == NULL &&
		       node->node_num[RADIX_V4] == -1 &&
		       node->data[RADIX_V6] == NULL &&
		       node->node_num[RADIX_V6] == -1);
		if (source != NULL) {
			/* Merging node */
			for (size_t i = 0; i < RADIX_FAMILIES; i++) {
				int cur = radix->num_added_node;
				if (source->node_num[i] != -1) {
					node->node_num[i] =
						source->node_num[i] + cur;
					node->data[i] = source->data[i];
				}
			}
		} else {
			int next = ++radix->num_added_node;
			node->node_num[ISC_RADIX_FAMILY(prefix)] = next;
		}
		*target = node;
		return;
	}

	isc_radix_node_t *new_node = radix_node_create(radix->mctx, prefix,
						       bitlen);
	isc_radix_node_t *glue = NULL;
	if (node->bit != differ_bit && bitlen != differ_bit) {
		glue = radix_node_create(radix->mctx, NULL, differ_bit);
	}
	radix->num_active_node++;

	if (source != NULL) {
		/* Merging node */
		for (size_t i = 0; i < RADIX_FAMILIES; i++) {
			int cur = radix->num_added_node;
			if (source->node_num[i] != -1) {
				new_node->node_num[i] = source->node_num[i] +
							cur;
				new_node->data[i] = source->data[i];
			}
		}
	} else {
		int next = ++radix->num_added_node;
		new_node->node_num[ISC_RADIX_FAMILY(prefix)] = next;
	}

	if (node->bit == differ_bit) {
		INSIST(glue == NULL);
		new_node->parent = node;
		if (node->bit < radix->maxbits &&
		    BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
		{
			INSIST(node->right == NULL);
			node->right = new_node;
		} else {
			INSIST(node->left == NULL);
			node->left = new_node;
		}
		*target = new_node;
		return;
	}

	if (bitlen == differ_bit) {
		INSIST(glue == NULL);
		if (bitlen < radix->maxbits &&
		    BIT_TEST(test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07)))
		{
			new_node->right = node;
		} else {
			new_node->left = node;
		}
		new_node->parent = node->parent;
		if (node->parent == NULL) {
			INSIST(radix->head == node);
			radix->head = new_node;
		} else if (node->parent->right == node) {
			node->parent->right = new_node;
		} else {
			node->parent->left = new_node;
		}
		node->parent = new_node;
	} else {
		INSIST(glue != NULL);
		glue->parent = node->parent;
		radix->num_active_node++;
		if (differ_bit < radix->maxbits &&
		    BIT_TEST(addr[differ_bit >> 3], 0x80 >> (differ_bit & 07)))
		{
			glue->right = new_node;
			glue->left = node;
		} else {
			glue->right = node;
			glue->left = new_node;
		}
		new_node->parent = glue;

		if (node->parent == NULL) {
			INSIST(radix->head == node);
			radix->head = glue;
		} else if (node->parent->right == node) {
			node->parent->right = glue;
		} else {
			INSIST(node->parent->left == node);
			node->parent->left = glue;
		}
		node->parent = glue;
	}

	*target = new_node;
	return;
}

void
isc_radix_remove(isc_radix_tree_t *radix, isc_radix_node_t *node) {
	isc_radix_node_t *parent, *child;

	REQUIRE(radix != NULL);
	REQUIRE(node != NULL);

	if (node->right && node->left) {
		/*
		 * This might be a placeholder node -- have to check and
		 * make sure there is a prefix associated with it!
		 */
		memset(&node->prefix, 0, sizeof(node->prefix));
		memset(node->data, 0, sizeof(node->data));
		return;
	}

	if (node->right == NULL && node->left == NULL) {
		parent = node->parent;

		if (parent == NULL) {
			INSIST(radix->head == node);
			radix->head = NULL;
			isc_mem_put(radix->mctx, node, sizeof(*node));
			radix->num_active_node--;
			return;
		}

		if (parent->right == node) {
			parent->right = NULL;
			child = parent->left;
		} else {
			INSIST(parent->left == node);
			parent->left = NULL;
			child = parent->right;
		}

		isc_mem_put(radix->mctx, node, sizeof(*node));
		radix->num_active_node--;

		if (parent->prefix.family != 0) {
			return;
		}

		/* We need to remove parent too. */
		if (parent->parent == NULL) {
			INSIST(radix->head == parent);
			radix->head = child;
		} else if (parent->parent->right == parent) {
			parent->parent->right = child;
		} else {
			INSIST(parent->parent->left == parent);
			parent->parent->left = child;
		}

		child->parent = parent->parent;
		isc_mem_put(radix->mctx, parent, sizeof(*parent));
		radix->num_active_node--;
		return;
	}

	if (node->right) {
		child = node->right;
	} else {
		INSIST(node->left != NULL);
		child = node->left;
	}

	parent = node->parent;
	child->parent = parent;

	if (parent == NULL) {
		INSIST(radix->head == node);
		radix->head = child;
		isc_mem_put(radix->mctx, node, sizeof(*node));
		radix->num_active_node--;
		return;
	}

	if (parent->right == node) {
		parent->right = child;
	} else {
		INSIST(parent->left == node);
		parent->left = child;
	}

	isc_mem_put(radix->mctx, node, sizeof(*node));
	radix->num_active_node--;
}
