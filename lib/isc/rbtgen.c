/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <isc/rbtgen.h>
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

#define COLOR(node)		((node)->color)
#define KEY(node)		((node)->data)
#define LEFT(node)		((node)->left)
#define RIGHT(node)		((node)->right)
#define PARENT(node)		((node)->parent)

#define SET_COLOR(node, value)	((node)->color  = (value))
#define SET_KEY(node, value)	((node)->data   = (value))
#define SET_LEFT(node, child)	((node)->left   = (child))
#define SET_RIGHT(node, child)	((node)->right  = (child))
#define SET_PARENT(node, child)	((node)->parent = (child))

#define IS_RED(node)		((node) != NULL && (node)->color == red)
#define IS_BLACK(node)		((node) == NULL || (node)->color == black)
#define MAKE_RED(node)		((node)->color = red)
#define MAKE_BLACK(node)	((node)->color = black)

static inline void
rotate_left(RBT_NODE *node, RBT_NODE **rootp) {
	RBT_NODE *child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = RIGHT(node);
	REQUIRE(child != NULL);

	SET_RIGHT(node, LEFT(child));
	if (LEFT(child) != NULL)
		SET_PARENT(LEFT(child), node);

	SET_LEFT(child, node);
	SET_PARENT(child, PARENT(node));
	if (PARENT(node) != NULL) {
		if (LEFT(PARENT(node)) == node)
			SET_LEFT(PARENT(node), child);
		else {
			SET_RIGHT(PARENT(node), child);
		}
	} else
		*rootp = child;

	SET_PARENT(node, child);
}

static inline void
rotate_right(RBT_NODE *node, RBT_NODE **rootp) {
	RBT_NODE *child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = LEFT(node);
	REQUIRE(child != NULL);

	SET_LEFT(node, RIGHT(child));
	if (RIGHT(child) != NULL)
		SET_PARENT(RIGHT(child), node);

	SET_RIGHT(child, node);
	SET_PARENT(child, PARENT(node));
	if (PARENT(node) != NULL) {
		if (LEFT(PARENT(node)) == node)
			SET_LEFT(PARENT(node), child);
		else
			SET_RIGHT(PARENT(node), child);
	} else
		*rootp = child;

	SET_PARENT(node, child);
}

isc_result_t
RBT_INSERT(RBT_NODE *node, RBT_NODE **rootp, int (*compare)(void *, void *)) {
	RBT_NODE *current, *child, *root, *parent, *grandparent;
	int i;

	REQUIRE(rootp != NULL);
	REQUIRE(LEFT(node) == NULL && RIGHT(node) == NULL);
	REQUIRE(KEY(node) != NULL);

	root = *rootp;
	if (root == NULL) {
		MAKE_BLACK(node);
		*rootp = node;
		return (ISC_R_SUCCESS);
	}

	current = NULL;
	child = root;
	do {
		current = child;
		i = compare(KEY(node), KEY(current));
		if (i == 0)
			return (ISC_R_EXISTS);
		if (i < 0)
			child = LEFT(current);
		else
			child = RIGHT(current);
	} while (child != NULL);
	if (i < 0)
		SET_LEFT(current, node);
	else
		SET_RIGHT(current, node);
	MAKE_RED(node);
	SET_PARENT(node, current);

	while (node != root && IS_RED(PARENT(node))) {
		parent = PARENT(node);
		grandparent = PARENT(PARENT(node));

		TRACE_NODE(n);

		if (parent == LEFT(grandparent)) {
			child = RIGHT(grandparent);
			if (child != NULL && IS_RED(child)) {
				TRACE_CASE(1);
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
			} else {
				if (node == RIGHT(parent)) {
					TRACE_CASE(2);
					node = parent;
					rotate_left(node, &root);
					parent = PARENT(node);
					grandparent = PARENT(PARENT(node));
				}
				TRACE_CASE(3);
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				rotate_right(grandparent, &root);
			}
		} else {
			child = LEFT(grandparent);
			if (child != NULL && IS_RED(child)) {
				TRACE_CASE(4);
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
			} else {
				if (node == LEFT(parent)) {
					TRACE_CASE(5);
					node = parent;
					rotate_right(node, &root);
					parent = PARENT(node);
					grandparent = PARENT(PARENT(node));
				}
				TRACE_CASE(6);
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				rotate_left(grandparent, &root);
			}
		}
	}

	MAKE_BLACK(root);
	*rootp = root;

	return (ISC_R_SUCCESS);
}

/* node must belong to a pointer in the tree; how could this be ensured? */
isc_result_t
RBT_DELETE(RBT_NODE *delete, RBT_NODE **rootp) {
	RBT_NODE *successor, *sibling, *child = NULL;

	REQUIRE(rootp != NULL);
	REQUIRE(delete);

	if (LEFT(delete) == NULL)
		if (RIGHT(delete) == NULL) {
			if (*rootp == delete) {
				/* this is the only item in the tree */
				*rootp = NULL;
				return(ISC_R_SUCCESS);
			}
		} else
			/* this node has one child, on the right */
			child = RIGHT(delete);

	else if (RIGHT(delete) == NULL)
		/* this node has one child, on the left */
		child = LEFT(delete);

	else {
		RBT_NODE holder, *tmp = &holder;

		/* this node has two children, so it cannot be directly
		   deleted.  find its immediate in-order successor and
		   move it to this location, then do the deletion at the
		   old site of the successor */
		successor = RIGHT(delete);
		while (LEFT(successor) != NULL)
			successor = LEFT(successor);

		/* the successor cannot possibly have a left child;
		   if there is any child, it is on the right */
		if (RIGHT(successor))
			child = RIGHT(successor);

		/* swap the two nodes; it would be simpler to just replace
		   the value being deleted with that of the successor,
		   but this rigamarole is done so the caller has complete
		   control over the pointers (and memory allocation) of
		   all of nodes.  if just the key value were removed from
		   the tree, the pointer to the node would would be
		   unchanged. */

		/* first, put the successor in the tree location of the
		   node to be deleted */

		memcpy(tmp, successor, sizeof(RBT_NODE));

		if (LEFT(PARENT(delete)) == delete)
			SET_LEFT(PARENT(delete), successor);
		else
			SET_RIGHT(PARENT(delete), successor);

		SET_PARENT(successor, PARENT(delete));

		if (LEFT(delete) != NULL)
			SET_PARENT(LEFT(delete), successor);

		if (RIGHT(delete) != NULL && RIGHT(delete) != successor)
			SET_PARENT(RIGHT(delete), successor);

		SET_COLOR(successor, COLOR(delete));
		SET_LEFT(successor, LEFT(delete));
		SET_RIGHT(successor, RIGHT(delete));

		/* now relink the node to be deleted into the
		   successor's previous tree location */
		if (PARENT(tmp) != delete) {
			if (LEFT(PARENT(tmp)) == successor)
				SET_LEFT(PARENT(tmp), delete);
			else
				SET_RIGHT(PARENT(tmp), delete);
			SET_PARENT(delete, PARENT(tmp));
		} else
			SET_PARENT(delete, successor);

		/* original successor node has no left */
		if (RIGHT(tmp) != NULL)
			SET_PARENT(RIGHT(tmp), delete);

		SET_COLOR(delete, COLOR(tmp));
		SET_LEFT(delete, LEFT(tmp));
		SET_RIGHT(delete, RIGHT(tmp));

	}


	/* fix the parent chain if a non-leaf is being deleted */
	if (PARENT(delete) != NULL) {
		if (LEFT(PARENT(delete)) == delete) {
			SET_LEFT(PARENT(delete), child);
			sibling = RIGHT(PARENT(delete));
		} else {
			SET_RIGHT(PARENT(delete), child);
			sibling = LEFT(PARENT(delete));
		}

		if (child != NULL)
			SET_PARENT(child, PARENT(delete));
	} else {
		/* this is the root being deleted, with just one child */
		SET_PARENT(child, NULL);
		sibling= NULL;
		*rootp = child;
	} 

	/* fix color violations */
	if (IS_BLACK(delete)) {
		RBT_NODE *parent;
		parent = PARENT(delete);

		while (child != *rootp && IS_BLACK(child)) {
			/* parent = PARENT(parent_pointer); */

			if (LEFT(parent) == child) {
				sibling = RIGHT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_left(parent, rootp);
					sibling = RIGHT(parent);
				}
				if (IS_BLACK(LEFT(sibling)) &&
				    IS_BLACK(RIGHT(sibling))) {
					MAKE_RED(sibling);
					child = parent;
				} else {
					if (IS_BLACK(RIGHT(sibling))) {
						MAKE_BLACK(LEFT(sibling));
						MAKE_RED(sibling);
						rotate_right(sibling, rootp);
						sibling = RIGHT(parent);
					}
					SET_COLOR(sibling, COLOR(parent));
					MAKE_BLACK(parent);
					MAKE_BLACK(RIGHT(sibling));
					rotate_left(parent, rootp);
					child = *rootp;
				}
			} else {
				sibling = LEFT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_right(parent, rootp);
					sibling = LEFT(parent);
				}
				if (IS_BLACK(LEFT(sibling)) &&
				    IS_BLACK(RIGHT(sibling))) {
					MAKE_RED(sibling);
					child = parent;
				} else {
					if (IS_BLACK(LEFT(sibling))) {
						MAKE_BLACK(RIGHT(sibling));
						MAKE_RED(sibling);
						rotate_left(sibling, rootp);
						sibling = LEFT(parent);
					}
					SET_COLOR(sibling, COLOR(parent));
					MAKE_BLACK(parent);
					MAKE_BLACK(LEFT(sibling));
					rotate_right(parent, rootp);
					child = *rootp;
				}
			}
					
			parent = PARENT(child);
		}

		if (IS_RED(child))
			MAKE_BLACK(child);
	}

	return(ISC_R_SUCCESS);
}

RBT_NODE *
RBT_SEARCH(RBT_NODE *current, void *key, int (*compare)(void *, void *)) {
	int i;

	while (current != NULL) {
		i = compare(key, KEY(current));
		if (i == 0)
			break;
		if (i < 0)
			current = LEFT(current);
		else
			current = RIGHT(current);
	}

	return(current);
}

static inline void
print_tree(RBT_NODE *root, void (*print_key)(void *), int depth) {
	int i;

	for (i = 0; i < depth; i++)
		putchar('\t');
	if (root != NULL) {
		print_key(KEY(root));
		printf(" (%s", IS_RED(root) ? "RED" : "black");
		if (root->parent) {
			printf(" from ");
			print_key(KEY(root->parent));
		}
		printf(")\n");
		depth++;

		if (IS_RED(root) && IS_RED(LEFT(root)))
		    printf("** Red/Red color violation on left\n");
		print_tree(LEFT(root), print_key, depth);

		if (IS_RED(root) && IS_RED(RIGHT(root)))
		    printf("** Red/Red color violation on right\n");
		print_tree(RIGHT(root), print_key, depth);
	} else
		printf("NULL\n");
}

void
RBT_PRINT(RBT_NODE *root, void (*print_key)(void *)) {
	print_tree(root, print_key, 0);
}

#ifdef WANT_RBTGEN_MAIN

int compare_int(void *, void *);
void print_int(void *);

int ints[] = {	12679, 26804, 7389, 20562, 24355, 23584,
		10713, 8094, 19071, 6732, 2709, 6058,
		3995, 3896, 15121, 1142, 2679, 26340,
		30541, 29186,
#if 0
		6584, 13201, 21238, 30455, 6500, 30669,
		10370, 2963, 26576, 17353, 19150, 19951,
		12540, 21381, 17882, 23051, 24808, 8961,
		26022, 3047, 9108, 28221, 13874, 32643,
		25856, 12601, 894, 4319, 20780, 10229,
#endif
		0 };

int
compare_int(void *a, void *b) {
	int i = *(int *)a, j = *(int *)b;
	return(i == j ? 0 : (i < j ? -1 : 1));
}

void
print_int(void *num) {
	int i = *(int *)num;
	(void)printf("%d", i);
}

#define KEY_VALUE(node, type)	(*(type *)((node)->data))

void
main() {
	RBT_NODE nodes[sizeof(ints)/sizeof(int)], *p, *root;
	int *i, j;

	setbuf(stdout, NULL);

	printf("For any two successive numbers at the same depth, the\n");
	printf("first number (and all its descendants) should be less than\n");
	printf("the number which immediately precedes it one depth level\n");
	printf("higher, and the second number (and all its descendants)\n");
	printf("should be greater than that preceding number\n\n");

	for (i = &ints[0], p = &nodes[0]; *i != 0; i++, p++) {
		printf("inserting %d\n", *i);
		KEY(p) = i;
		RBT_INSERT(p, &root, compare_int);

		RBT_PRINT(root, print_int);
	}

	j = 2679;
	i = &j;

	printf("searching for %d ...", j);
	p = RBT_SEARCH(root, i, compare_int);
	if (p != NULL) {
		printf("found %d\n", KEY_VALUE(p, int));
	} else {
		printf("not found!\n");
	}

	j = 9999;
	i = &j;

	printf("searching for %d ...", j);
	p = RBT_SEARCH(root, i, compare_int);
	if (p != NULL) {
		printf("found %d\n", KEY_VALUE(p, int));
	} else {
		printf("not found!\n");
	}

	p = &nodes[sizeof(ints) / sizeof(int) - 2];
	do {
		printf("deleting %d\n", KEY_VALUE(p, int));
		RBT_DELETE(p, &root);
		RBT_PRINT(root, print_int);
	} while (p-- != &nodes[0]);

	exit(0);
}
#endif
