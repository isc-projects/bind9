
/*
 * This file is a generic template that can be used to create a red-black
 * tree library for a specified node type.
 */

/*
 * Red-Black Tree algorithms adapted from:
 *
 *	_Introduction to Algorithms_, Cormen, Leiserson, and Rivest,
 *	MIT Press / McGraw Hill, 1990, ISBN 0-262-03141-8, chapter 14.
 */

#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <isc/boolean.h>
#include <isc/assertions.h>

#ifdef RBT_TRACE
#define TRACE_CASE(n)		printf("case %d\n", (n))
#define TRACE_NODE(n) \
	do { \
		printf("%p ", (n)); \
		PRINT_KEY(KEY(n)); \
		printf(" (%s)\n", IS_RED((n)) ? "red" : "black"); \
	} while (0)
#else
#define TRACE_CASE(n)
#define TRACE_NODE(n)
#endif

static inline void
rotate_left(RBT_NODE_T node, RBT_NODE_T parent, RBT_NODE_T *rootp) {
	RBT_NODE_T child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = RIGHT(node);
	REQUIRE(child != NULL);

	SET_RIGHT(node, LEFT(child));
	SET_LEFT(child, node);
	if (parent != NULL) {
		if (LEFT(parent) == node)
			SET_LEFT(parent, child);
		else {
			INSIST(RIGHT(parent) == node);	/* XXX remove */
			SET_RIGHT(parent, child);
		}
	} else
		*rootp = child;
}

static inline void
rotate_right(RBT_NODE_T node, RBT_NODE_T parent, RBT_NODE_T *rootp) {
	RBT_NODE_T child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = LEFT(node);
	REQUIRE(child != NULL);

	SET_LEFT(node, RIGHT(child));
	SET_RIGHT(child, node);
	if (parent != NULL) {
		if (LEFT(parent) == node)
			SET_LEFT(parent, child);
		else {
			INSIST(RIGHT(parent) == node);	/* XXX remove */
			SET_RIGHT(parent, child);
		}
	} else
		*rootp = child;
}

RBT_NODE_T
RBT_SEARCH(RBT_NODE_T current, RBT_KEY_T key) {
	int i;

	while (current != NULL) {
		i = COMPARE_KEYS(key, KEY(current));
		if (i == 0)
			break;
		if (i < 0)
			current = LEFT(current);
		else
			current = RIGHT(current);
	}

	return (current);
}

void
RBT_INSERT(RBT_NODE_T node, RBT_NODE_T *rootp) {
	RBT_NODE_T current, child, root, parent, grandparent, tmp;
	int i;
	unsigned int depth = 0;
	RBT_NODE_T ancestors[MAX_DEPTH];

	REQUIRE(rootp != NULL);
	REQUIRE(LEFT(node) == NULL && RIGHT(node) == NULL);

	root = *rootp;
	if (root == NULL) {
		MAKE_BLACK(node);
		*rootp = node;
		return;
	}

	current = NULL;
	child = root;
	do {
		INSIST(depth < MAX_DEPTH);
		ancestors[depth] = current;
		depth++;
		current = child;
		i = COMPARE_KEYS(KEY(node), KEY(current));
		INSIST(i != 0);
		if (i < 0)
			child = LEFT(current);
		else
			child = RIGHT(current);
	} while (child != NULL);
	INSIST(depth < MAX_DEPTH);
	ancestors[depth] = current;
	if (i < 0)
		SET_LEFT(current, node);
	else
		SET_RIGHT(current, node);
	MAKE_RED(node);

	while (node != root && IS_RED(ancestors[depth])) {
		parent = ancestors[depth];
		grandparent = ancestors[depth - 1];

		TRACE_NODE(n);

		if (parent == LEFT(grandparent)) {
			child = RIGHT(grandparent);
			if (child != NULL && IS_RED(child)) {
				TRACE_CASE(1);
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
				depth -= 2;
			} else {
				if (node == RIGHT(parent)) {
					TRACE_CASE(2);
					tmp = node;
					rotate_left(parent, grandparent,
						    &root);
					node = parent;
					parent = tmp;
					ancestors[depth] = parent;
					/* Note: depth does not change. */
				}
				TRACE_CASE(3);
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				INSIST(depth >= 2);	/* XXX */
				tmp = ancestors[depth - 2];
				rotate_right(grandparent, tmp, &root);
			}
		} else {
			child = LEFT(grandparent);
			if (child != NULL && IS_RED(child)) {
				TRACE_CASE(4);
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
				depth -= 2;
			} else {
				if (node == LEFT(parent)) {
					TRACE_CASE(5);
					tmp = node;
					rotate_right(parent, grandparent,
						     &root);
					node = parent;
					parent = tmp;
					ancestors[depth] = parent;
					/* Note: depth does not change. */
				}
				TRACE_CASE(6);
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				INSIST(depth >= 2);	/* XXX */
				tmp = ancestors[depth - 2];
				rotate_left(grandparent, tmp, &root);
			}
		}
	}

	MAKE_BLACK(root);
	*rootp = root;
}

static inline void
print_tree(RBT_NODE_T root, int depth) {
	int i;

	for (i = 0; i < depth; i++)
		putchar('\t');
	if (root != NULL) {
		PRINT_KEY(KEY(root));
		printf(" (%s)\n", IS_RED(root) ? "red" : "black");
		depth++;
		print_tree(LEFT(root), depth);
		print_tree(RIGHT(root), depth);
	} else
		printf("NULL\n");
}

void
RBT_PRINT(RBT_NODE_T root) {
	print_tree(root, 0);
}
