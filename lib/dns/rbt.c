/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <dns/rbt.h>
#include <dns/result.h>

#define RBT_MAGIC		0x5242542BU /* RBT+. */
#define VALID_RBT(rbt)		((rbt) != NULL && (rbt)->magic == RBT_MAGIC)

struct dns_rbt {
	unsigned int		magic;
	isc_mem_t *		mctx;
	dns_rbtnode_t *		root;
	dns_rbtnode_t *		ancestors[256]; /* @@@ should be dynamic */
	int ancestor_count;
	/*
	 * The maximum number of labels in a name is 128; need space for 127
	 * to be able to store the down pointer history for the worst case.
	 */
	dns_rbtnode_t *		levels[127];
	int level_count;
};

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define LEFT(node) 	((node)->left)
#define RIGHT(node)	((node)->right)
#define DOWN(node)	((node)->down)
#define NAMELEN(node)	((node)->name_length)
#define NAME(node)	((void *)((node) + 1))
#define DATA(node)	((node)->data)
#define COLOR(node) 	((node)->color)

#define SET_COLOR(node, value)	((node)->color  = (value))
#define SET_LEFT(node, child)	((node)->left   = (child))
#define SET_RIGHT(node, child)	((node)->right  = (child))

#define IS_RED(node)		((node) != NULL && (node)->color == red)
#define IS_BLACK(node)		((node) == NULL || (node)->color == black)
#define MAKE_RED(node)		((node)->color = red)
#define MAKE_BLACK(node)	((node)->color = black)

/*
 * For the return value of cmp_names_for_depth().
 */
#define BOTH_ARE_EQUAL	0
#define FIRST_IS_LESS	-1
#define FIRST_IS_MORE	-2

#ifdef DEBUG
#define inline
/*
 * A little something to help out in GDB.
 */
isc_region_t Name(dns_rbtnode_t *node);
isc_region_t 
Name(dns_rbtnode_t *node) {
	isc_region_t r;

	r.length = NAMELEN(node);
	r.base = NAME(node);

	return(r);
}
#else
#endif

/*
 * Forward declarations.
 */
static dns_result_t create_node(isc_mem_t *mctx,
				dns_name_t *name, dns_rbtnode_t **nodep);

static int cmp_label(dns_label_t *a, dns_label_t *b);
static inline int cmp_names_on_level(dns_name_t *a, dns_name_t *b);
static inline int cmp_names_for_depth(dns_name_t *a, dns_name_t *b);

static inline void rotate_left(dns_rbtnode_t *node, dns_rbtnode_t *parent,
			       dns_rbtnode_t **rootp);
static inline void rotate_right(dns_rbtnode_t *node, dns_rbtnode_t *parent,
				dns_rbtnode_t **rootp);

static dns_result_t dns_rbt_addnode(dns_rbtnode_t *node,
				     dns_rbtnode_t **rootp);
static dns_result_t dns_rbt_delete_workhorse(dns_rbt_t *rbt,
					     dns_rbtnode_t *delete);
static void dns_rbt_deletetree(isc_mem_t *mctx,
				dns_rbtnode_t *node, dns_rbtnode_t **root);


/*
 * Initialize a red/black tree of trees.
 */
dns_result_t
dns_rbt_create(isc_mem_t *mctx, dns_rbt_t **rbtp) {
	dns_rbt_t *rbt;

	REQUIRE(mctx != NULL);
	REQUIRE(rbtp != NULL && *rbtp == NULL);

	rbt = (dns_rbt_t *)isc_mem_get(mctx, sizeof(*rbt));
	if (rbt == NULL)
		return (DNS_R_NOMEMORY);

	rbt->mctx = mctx;
	rbt->root = NULL;
	rbt->magic = RBT_MAGIC;

	*rbtp = rbt;

	return (DNS_R_SUCCESS);
}

/*
 * Initialize a red/black tree of trees.
 */
void
dns_rbt_destroy(dns_rbt_t **rbtp) {
	dns_rbt_t *rbt;

	REQUIRE(rbtp != NULL && VALID_RBT(*rbtp));

	rbt = *rbtp;

	dns_rbt_deletetree(rbt->mctx, rbt->root, &rbt->root);

	rbt->magic = 0;

	isc_mem_put(rbt->mctx, rbt, sizeof(*rbt));

#ifdef ISC_MEM_DEBUG
	isc_mem_stats(rbt->mctx, stderr);
#endif

	*rbtp = NULL;
}

/*
 * Add 'name' to tree, initializing its data pointer with 'data'.
 */

dns_result_t
dns_rbt_addname(dns_rbt_t *rbt, dns_name_t *name, void *data) {
	dns_rbtnode_t **root, *current, *child, *new_node, *new_current, *parent;
	dns_name_t add_name, current_name, new_name, tmp_name;
	int compared, add_labels, current_labels, keep_labels, start_label;
	dns_result_t result;

	REQUIRE(dns_name_isabsolute(name));

	/*
	 * Create a copy of the name so the original name structure is
	 * not modified.
	 */
	memcpy(&add_name, name, sizeof(add_name));

	/* @@@
	 * The following code nearly duplicates a non-trivial
	 * amount of the dns_rbt_addnode algorithm.  It can be
	 * improved by merging the two functions.
	 */

	if (rbt->root == NULL) {
		result = create_node(rbt->mctx, &add_name, &new_node);
		rbt->root = new_node;
		return (result);
	}

	root = &rbt->root;
	parent = NULL;
	child = *root;
	dns_name_init(&current_name, NULL);
	do {
		current = child;

		dns_rbt_namefromnode(current, &current_name);
		compared = cmp_names_for_depth(&add_name, &current_name);

		if (compared == BOTH_ARE_EQUAL)
			if (DATA(current) != NULL)
				return(DNS_R_EXISTS); /* @@@ DNS_R_DISALLOWED */
			else {
				DATA(current) = data;
				return(DNS_R_SUCCESS);
			}

		else if (compared == FIRST_IS_LESS) {
			parent = current;
			child = LEFT(current);
		} else if (compared == FIRST_IS_MORE) {
			parent = current;
			child = RIGHT(current);

		} else {
			/*
			 * This name has some suffix in common with the
			 * name at the current node.  If the name at
			 * the current node is shorter, that means the
			 * new name should be in a subtree.  If the
			 * name at the current node is longer, that means
			 * the down pointer to this tree should point
			 * to a new tree that has the common suffix, and
			 * the non-common parts of these two names should
			 * start a new tree.
			 */
			add_labels   = dns_name_countlabels(&add_name);
			current_labels = dns_name_countlabels(&current_name);

			/*
			 * When *root == rbt->root, the current tree level is
			 * the top of the tree of trees, and the root label is
			 * not counted in this module.
			 */
			if (*root == rbt->root)
				add_labels--, current_labels--;

			if (compared == current_labels) {
				/*
				 * All of the exising labels are in common,
				 * so the new name is in a subtree.
				 * First, turn the non-in-common part of
				 * &add_name into its own dns_name_t to be
				 * searched for in the downtree.
				 */

				start_label = 0;
				keep_labels = add_labels - compared;

				dns_name_init(&new_name, NULL);
				dns_name_getlabelsequence(&add_name,
							  start_label,
							  keep_labels,
							  &add_name);

				/*
				 * Follow the down pointer (possibly NULL).
				 */
				root = &DOWN(current);
				parent = NULL;
				child = DOWN(current);

			} else {
				/*
				 * The number of labels in common is fewer
				 * than the number of labels at the current
				 * node, so the current node must be adjusted
				 * to have just the common suffix, and a down
				 * pointer made to a new tree.
				 */
				
				/*
				 * Get the in common labels of the current
				 * name.  If this is part of the top level
				 * tree, then the root label needs to be
				 * kept in the name.
				 */
				   
				start_label = current_labels - compared;
				keep_labels = compared + (*root == rbt->root);

				dns_name_init(&tmp_name, NULL);
				dns_name_getlabelsequence(&current_name,
							  start_label,
							  keep_labels,
							  &tmp_name);

				result = create_node(rbt->mctx,
						     &tmp_name, &new_current);
				if (result != DNS_R_SUCCESS)
					return (result);

				/* 
				 * Reproduce the current node, but then
				 * fix its name length.
				 */
				memcpy(new_current, current, sizeof(*current));
				NAMELEN(new_current) = tmp_name.length;

				/*
				 * Fix pointers that were to the current node.
				 */
				if (parent != NULL)
					if (LEFT(parent) == current)
						SET_LEFT(parent, new_current);
					else
						SET_RIGHT(parent, new_current);
				if (*root == current)
					*root = new_current;

				/*
				 * Now create the new root of the subtree
				 * as the not-in-common labels of the current
				 * node.  Its down pointer and name data
				 * should be preserved, while left, right
				 * and parent pointers are nullified.
				 */

				start_label = 0;
				keep_labels = current_labels - compared;

				dns_name_init(&new_name, NULL);
				dns_name_getlabelsequence(&current_name,
							  start_label,
							  keep_labels,
							  &new_name);


				result = create_node(rbt->mctx,
						     &new_name, &new_node);
				if (result != DNS_R_SUCCESS)
					return (result);

				DATA(new_node) = DATA(new_current);
				DOWN(new_node) = DOWN(new_current);

				/*
				 * Now that the old name in the existing
				 * node has been disected into two new
				 * nodes, the old node can be freed.
				 */
				isc_mem_put(rbt->mctx, current,
					    sizeof(*current) +
					    NAMELEN(current));
				current = new_current;

				/*
				 * Set up the new root of the next level.
				 */
				DOWN(current) = new_node;
				root = &DOWN(current);

				if (compared == add_labels) {
					/*
					 * The name being added is a strict
					 * superset of the existing name,
					 * so the data coming in needs to be
					 * placed with the current node.
					 */
					DATA(current) = data;
					/*
					 * Since the new name has had its
					 * data placed, the job is done!
					 */
					return(DNS_R_SUCCESS);
				} else {
					/*
					 * The current node has no name data,
					 * because it is just a placeholder.
					 */
					DATA(current) = NULL;
					/* The not-in-common parts of the new
					 * name will be inserted into the new
					 * level following this loop.
					 */
					start_label = 0;
					keep_labels = add_labels - compared;

					dns_name_init(&new_name, NULL);
					dns_name_getlabelsequence(&add_name,
								  start_label,
								  keep_labels,
								  &add_name);

					current = new_node;
					parent = NULL; /* @@@ ? only necessary if used outside loop */
					child = NULL;
				}

			}

		}

	} while (child != NULL);

	result = create_node(rbt->mctx,
			     &add_name, &new_node);
	if (result == DNS_R_SUCCESS) {
		DATA(new_node) = data;
		result = dns_rbt_addnode(new_node, root);
	}

	return (result);
}

/*
 * Find the node for "name" in the tree of trees.
 * If second argument "up" is non-NULL, set it to the node that has
 * the down pointer for the found node.
 */
dns_rbtnode_t *
dns_rbt_findnode(dns_rbt_t *rbt, dns_name_t *name) {
	dns_rbtnode_t *current;
	dns_name_t *search_name, *new_search_name, *current_name;
	dns_name_t holder1, holder2;
	int compared, current_labels, keep_labels, dont_count_root_label;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(dns_name_isabsolute(name));

	/*
	 * search_name is the name segment being sought in each tree level.
	 */
	search_name = name;

	current = rbt->root;
	dont_count_root_label = 1;

	dns_name_init(&holder1, NULL);
	dns_name_init(&holder2, NULL);

	current_name = &holder1;

	rbt->level_count = 0;
	rbt->ancestor_count = 0;
	rbt->ancestors[rbt->ancestor_count++] = NULL;

	while (current != NULL) {
		dns_rbt_namefromnode(current, current_name);
		compared = cmp_names_for_depth(search_name, current_name);

		if (compared == BOTH_ARE_EQUAL)
			break;

		/*
		 * Standard binary search tree movement.
		 */
		if (compared == FIRST_IS_LESS) {
			rbt->ancestors[rbt->ancestor_count++] = current;
			current = LEFT(current);
		} else if (compared == FIRST_IS_MORE) {
			rbt->ancestors[rbt->ancestor_count++] = current;
			current = RIGHT(current);
		}
		/*
		 * The names have some common suffix labels.
		 */

		else {
			/*
			 * If the number in common are equal in length to the
			 * current node's name length (where the root label is
			 * not counted as part of the comparison) then follow
			 * the down pointer and search in the new tree.
			 */

			current_labels = dns_name_countlabels(current_name)
				- dont_count_root_label;

			if (compared == current_labels) {
				/* 
				 * Set up new name to search for as
				 * the not-in-common part.
				 */
				if (search_name == &holder2) {
					new_search_name = &holder1;
					current_name = &holder2;
				} else {
					new_search_name = &holder2;
					current_name = &holder1;
				}

				keep_labels = dns_name_countlabels(search_name)
					- dont_count_root_label
					- compared;

				dns_name_init(new_search_name, NULL);
				dns_name_getlabelsequence(search_name,
							  0,
							  keep_labels,
							  new_search_name);
			
				search_name = new_search_name;

				/*
				 * Search in the next tree level, which
				 * won't be the top level tree anymore, so
				 * there is no root label to ignore.
				 */
				rbt->ancestors[rbt->ancestor_count++] = NULL;
				rbt->levels[rbt->level_count++] = current;

				current = DOWN(current);
				dont_count_root_label = 0;

			} else
				/*
				 * Though there is a suffix in common, it
				 * isn't a down pointer, so the name does
				 * not exist.
				 */
				current = NULL;
		
		}
	}

	return(current);
}

void *
dns_rbt_findname(dns_rbt_t *rbt, dns_name_t *name) {
	dns_rbtnode_t *node;

	REQUIRE(VALID_RBT(rbt));

	node = dns_rbt_findnode(rbt, name);

	if (node != NULL && DATA(node) != NULL)
		return(DATA(node));
	else
		return(NULL);
}

/* @@@ WHEN DELETING, IF A TREE IS LEFT WITH NO RIGHT OR LEFT NODES
   THEN IT SHOULD HAVE ITS NAME GLOMMED INTO THE NAME ABOVE IT.  THIS
   COULD STAND A dns_name_prefix_name FUNCTION OR SOME SUCH. */

/*
 * Delete a name from the tree of trees.
 *
 * This will remove all subnames of the name, too,
 * and if this name is the last name in a level, the name
 * one level up will be removed if it has no data associated with it.
 */
dns_result_t
dns_rbt_deletename(dns_rbt_t *rbt, dns_name_t *name) {
	/*
	 * Find the node, building the ancestor chain.
	 * @@@ When searching, the name might not have an exact match:
	 *    consider a.b.a.com, b.b.a.com and c.b.a.com as the only
	 *    elements of a tree, which would make layer 1 a single
	 *    node tree of "b.a.com" and layer 2 a three node tree of
	 *    a, b, and c.  Deleting a.com would find only a partial depth
	 *    match in the first layer.
	 * deletes ALL subnames of the name.
	 * @@@ delete all ancestors that have no data???
	 */
	dns_rbtnode_t *node;

	REQUIRE(dns_name_isabsolute(name));

	node = dns_rbt_findnode(rbt, name);

	if (node != NULL) {
		if (DOWN(node))
			dns_rbt_deletetree(rbt->mctx, DOWN(node), &DOWN(node));

		dns_rbt_delete_workhorse(rbt, node);
		isc_mem_put(rbt->mctx, node, sizeof(*node) + NAMELEN(node));

		return(DNS_R_SUCCESS);
	} else
		return(DNS_R_NOTFOUND);

}

void
dns_rbt_namefromnode(dns_rbtnode_t *node, dns_name_t *name) {
	isc_region_t r;

	r.length = NAMELEN(node);
	r.base = NAME(node);

	dns_name_fromregion(name, &r);
}

static dns_result_t
create_node(isc_mem_t *mctx, dns_name_t *name, dns_rbtnode_t **nodep) {
	dns_rbtnode_t *node;
	isc_region_t region;

	dns_name_toregion(name, &region);

	node = (dns_rbtnode_t *)isc_mem_get(mctx, sizeof(*node) + region.length);
	if (node == NULL)
		return (DNS_R_NOMEMORY);

	/*	PARENT(node) = NULL; */
	LEFT(node) = NULL;
	RIGHT(node) = NULL;
	DOWN(node) = NULL;

	MAKE_BLACK(node);

	NAMELEN(node) = region.length;
	memcpy(NAME(node), region.base, region.length);

	*nodep = node;

	return (DNS_R_SUCCESS);
}

static inline void
rotate_left(dns_rbtnode_t *node, dns_rbtnode_t *parent, dns_rbtnode_t **rootp) {
	dns_rbtnode_t *child;

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
			SET_RIGHT(parent, child);
		}
	} else
		*rootp = child;
}

static inline void
rotate_right(dns_rbtnode_t *node, dns_rbtnode_t *parent, dns_rbtnode_t **rootp) {
	dns_rbtnode_t *child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = LEFT(node);
	REQUIRE(child != NULL);

	SET_LEFT(node, RIGHT(child));
	SET_RIGHT(child, node);

	if (parent != NULL) {
		if (LEFT(parent) == node)
			SET_LEFT(parent, child);
		else
			SET_RIGHT(parent, child);
	} else
		*rootp = child;
}

/*
 * This is the real workhorse of the insertion code, because it does the
 * true red/black tree on a single level.
 */
static dns_result_t
dns_rbt_addnode(dns_rbtnode_t *node, dns_rbtnode_t **rootp) {
	dns_rbtnode_t *current, *child, *root, *tmp;
	dns_rbtnode_t *ancestors[64], *parent, *grandparent; /* @@@ dynamic 64 */
	dns_name_t add_name, current_name;
	dns_offsets_t offsets;
	int i, depth;

	REQUIRE(rootp != NULL);
	REQUIRE(LEFT(node) == NULL && RIGHT(node) == NULL);

	root = *rootp;
	if (root == NULL) {
		MAKE_BLACK(node);
		*rootp = node;
		return (DNS_R_SUCCESS);
	}

	current = NULL;
	child = root;
	depth = 0;

	dns_name_init(&add_name, offsets);
	dns_rbt_namefromnode(node, &add_name);

	dns_name_init(&current_name, NULL);

	do {
		ancestors[depth++] = current;
		current = child;

		dns_rbt_namefromnode(current, &current_name);

		i = cmp_names_on_level(&add_name, &current_name);
		if (i == 0)
			return (DNS_R_EXISTS);
		if (i < 0)
			child = LEFT(current);
		else
			child = RIGHT(current);
	} while (child != NULL);

	/* insist depth < space available */
	ancestors[depth] = current;

	if (i < 0)
		SET_LEFT(current, node);
	else
		SET_RIGHT(current, node);
	MAKE_RED(node);

	while (node != root && IS_RED(ancestors[depth])) {
		parent = ancestors[depth];
		grandparent = ancestors[depth - 1];

		if (parent == LEFT(grandparent)) {
			child = RIGHT(grandparent);
			if (child != NULL && IS_RED(child)) {
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
				depth -= 2;
			} else {
				if (node == RIGHT(parent)) {
					rotate_left(parent, grandparent, &root);
					tmp = node;
					node = parent;
					parent = tmp;
					ancestors[depth] = parent;
				}
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				rotate_right(grandparent, ancestors[depth - 2],
					     &root);
			}
		} else {
			child = LEFT(grandparent);
			if (child != NULL && IS_RED(child)) {
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
				depth -= 2;
			} else {
				if (node == LEFT(parent)) {
					rotate_right(parent, grandparent, &root);
					tmp = node;
					node = parent;
					parent = tmp;
					ancestors[depth] = parent;
				}
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				rotate_left(grandparent, ancestors[depth - 2],
					    &root);
			}
		}
	}

	MAKE_BLACK(root);
	*rootp = root;

	return (DNS_R_SUCCESS);
}

static dns_result_t
dns_rbt_delete_workhorse(dns_rbt_t *rbt, dns_rbtnode_t *delete) {
	dns_rbtnode_t *sibling, *parent, *grandparent, *child;
	dns_rbtnode_t *successor, **rootp;
	int depth;

	REQUIRE(delete);

	if (rbt->level_count > 0)
		rootp = &DOWN(rbt->levels[rbt->level_count - 1]);
	else
		rootp = &rbt->root;

	child = NULL;

	if (LEFT(delete) == NULL)
		if (RIGHT(delete) == NULL) {
			if (rbt->ancestors[rbt->ancestor_count - 1] == NULL) {
				/*
				 * This is the only item in the tree.
				 */
				*rootp = NULL;
				return(DNS_R_SUCCESS);
			}
		} else
			/*
			 * This node has one child, on the right.
			 */
			child = RIGHT(delete);

	else if (RIGHT(delete) == NULL)
		/*
		 * This node has one child, on the left.
		 */
		child = LEFT(delete);

	else {
		dns_rbtnode_t holder, *tmp = &holder;

		/*
		 * This node has two children, so it cannot be directly
		 * deleted.  Find its immediate in-order successor and
		 * move it to this location, then do the deletion at the
		 * old site of the successor.
		 */
		depth = rbt->ancestor_count++;
		successor = RIGHT(delete);
		while (LEFT(successor) != NULL) {
			rbt->ancestors[rbt->ancestor_count++] = successor;
			successor = LEFT(successor);

		}

		/*
		 * The successor cannot possibly have a left child;
		 * if there is any child, it is on the right.
		 */
		if (RIGHT(successor))
			child = RIGHT(successor);

		/* Swap the two nodes; it would be simpler to just replace
		 * the value being deleted with that of the successor,
		 * but this rigamarole is done so the caller has complete
		 * control over the pointers (and memory allocation) of
		 * all of nodes.  If just the key value were removed from
		 * the tree, the pointer to the node would would be
		 * unchanged.
		 */

		/*
		 * First, put the successor in the tree location of the
		 * node to be deleted.
		 */

		memcpy(tmp, successor, sizeof(dns_rbtnode_t));

		rbt->ancestors[depth] = successor;
		parent = rbt->ancestors[depth - 1];

		if (parent)
			if (LEFT(parent) == delete)
				SET_LEFT(parent, successor);
			else
				SET_RIGHT(parent, successor);


#if 0
		SET_PARENT(successor, PARENT(delete));

		if (LEFT(delete) != NULL)
			SET_PARENT(LEFT(delete), successor);

		if (RIGHT(delete) != NULL && RIGHT(delete) != successor)
			SET_PARENT(RIGHT(delete), successor);
#endif

		SET_LEFT(successor, LEFT(delete));
		SET_RIGHT(successor, RIGHT(delete));
		SET_COLOR(successor, COLOR(delete));

		/*
		 * Now relink the node to be deleted into the
		 * successor's previous tree location.
		 */
		parent = rbt->ancestors[rbt->ancestor_count - 1];
		if (parent == successor)
			SET_RIGHT(parent, delete);
		else
			SET_LEFT(parent, delete);

#if 0
		if (PARENT(tmp) != delete) {
			if (LEFT(PARENT(tmp)) == successor)
				SET_LEFT(PARENT(tmp), delete);
			else
				SET_RIGHT(PARENT(tmp), delete);
			SET_PARENT(delete, PARENT(tmp));
		} else
			SET_PARENT(delete, successor);
#endif

		/*
		 * Original successor node has no left.
		 */
#if 0
		if (RIGHT(tmp) != NULL)
			SET_PARENT(RIGHT(tmp), delete);
#endif

		SET_LEFT(delete, NULL);
		SET_RIGHT(delete, RIGHT(tmp));
		SET_COLOR(delete, COLOR(tmp));
	}

	parent = rbt->ancestors[rbt->ancestor_count - 1];

	/*
	 * Remove the node by removing the links from its parent.
	 */
	if (parent != NULL) {
		if (LEFT(parent) == delete) {
			SET_LEFT(parent, child);
			sibling = RIGHT(parent);
		} else {
			SET_RIGHT(parent, child);
			sibling = LEFT(parent);
		}

#if 0
		if (child != NULL)
			SET_PARENT(child, PARENT(delete));
#endif
	} else {
		/*
		 * This is the root being deleted, and at this point
		 * it is known to have just one child.
		 */
#if 0
		SET_PARENT(child, NULL);
#endif
		sibling = NULL;
		*rootp = child;
	} 

	/*
	 * Fix color violations.
	 */
	if (IS_BLACK(delete)) {
		dns_rbtnode_t *parent;
		depth = rbt->ancestor_count - 1;

		while (child != *rootp && IS_BLACK(child)) {
			parent = rbt->ancestors[depth--];
			grandparent = rbt->ancestors[depth];

			if (LEFT(parent) == child) {
				sibling = RIGHT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_left(parent, grandparent, rootp);
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
						rotate_right(sibling, grandparent, rootp);
						sibling = RIGHT(parent);
					}
					SET_COLOR(sibling, COLOR(parent));
					MAKE_BLACK(parent);
					MAKE_BLACK(RIGHT(sibling));
					rotate_left(parent, grandparent, rootp);
					child = *rootp;
				}
			} else {
				sibling = LEFT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_right(parent, grandparent, rootp);
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
						rotate_left(sibling, grandparent, rootp);
						sibling = LEFT(parent);
					}
					SET_COLOR(sibling, COLOR(parent));
					MAKE_BLACK(parent);
					MAKE_BLACK(LEFT(sibling));
					rotate_right(parent, grandparent, rootp);
					child = *rootp;
				}
			}

#if 0
			parent = PARENT(child);
#endif
		}

		if (IS_RED(child))
			MAKE_BLACK(child);
	}

	return(DNS_R_SUCCESS);
}

/*
 * This should only be used on the root of a tree, because no color fixup
 * is done at all.
 */
static void
dns_rbt_deletetree(isc_mem_t *mctx,
		    dns_rbtnode_t *node, dns_rbtnode_t **root) {

	if (node == NULL)
		return;

	if (LEFT(node) != NULL)
		dns_rbt_deletetree(mctx, LEFT(node), root);
	if (RIGHT(node) != NULL)
		dns_rbt_deletetree(mctx, RIGHT(node), root);
	if (DOWN(node) != NULL)
		dns_rbt_deletetree(mctx, DOWN(node), &DOWN(node));

	isc_mem_put(mctx, node, sizeof(*node) + NAMELEN(node));

	/*
	 * @@@ is this necessary?  only if the function is ever intended
	 * to be used to delete something where the root pointer needs to
	 * be told the tree is gone.  At the moment, this is not the case,
	 * because the function is only used for two cases:
	 * + deleting everything DOWN from a node that is itself being deleted
	 * + deleting the entire tree of trees from dns_rbt_destroy.
	 * In each case, the root pointer is no longer relevant.

	 */
	*root = NULL;
}

/**
 **
 ** Comparison functions.
 **
 **/

/*
 * @@@ This is clearly too simplistic.  I could use a dns_label_compare
 * like dns_name_compare.  Or perhaps i will just have to cast
 * the labels into ad hoc dns_name_t structures and compare them.
 * Note that it does absolutely no special comparison of bitstrings.
 * This whole file as yet does nothing special with bitstrings.
 */

static int
cmp_label(dns_label_t *a, dns_label_t *b) {
	int i;

	i = strncasecmp(a->base, b->base, MIN(a->length, b->length));

	if (i == 0 && a->length != b->length)
		return(a->length < b->length ? -1 : 1);
	else
		return(i);
}

/*
 * Compare a sequence of labels to determine if they are
 *  + FIRST_IS_LESS (a < b, and b.com < a.net)
 *  + FIRST_IS_MORE (a > b, but a.net > b.com)
 *  + BOTH_ARE_EQUAL (all labels in each)
 *  + in common (share suffixes: x.a.com and y.a.com have 2 labels in common;
 *                               x.b.com and x.a.com have 1 label in common)
 *    If there are any common suffix labels, the return value is a natural
 *    number that indicates how many were in common.
 *
 * The root label is no included in the comparison, because it would not
 * be helpful to compare two absolute names and have this function return
 * that they had one element in common.
 *
 * @@@ As with cmp_label, this is too simplistic.  Now lowercasing or
 * bitstring comparisons are done.
 */
static inline int
cmp_names_for_depth(dns_name_t *a, dns_name_t *b) {
	dns_label_t alabel, blabel;
	int aindex, bindex, compared, common;

	aindex = dns_name_countlabels(a) - 1;
	bindex = dns_name_countlabels(b) - 1;

	INSIST(( dns_name_isabsolute(a) &&  dns_name_isabsolute(b)) ||
	       (!dns_name_isabsolute(a) && !dns_name_isabsolute(b)));

	if (dns_name_isabsolute(a))
		aindex--, bindex--;

	common = 0;

	for (; aindex >= 0 && bindex >= 0; aindex--, bindex--) {
		dns_name_getlabel(a, aindex, &alabel);
		dns_name_getlabel(b, bindex, &blabel);

	        compared = cmp_label(&alabel, &blabel);
		if (compared == 0)
			common++;
		else if (common != 0)
			return(common);
		else if (compared < 0)
			return(FIRST_IS_LESS);
		else
			return(FIRST_IS_MORE);
	}

	if (aindex == -1 && bindex == -1)
		return(BOTH_ARE_EQUAL);
	else
		return(common);

}

/*
 * This is meant only to be passed to RBT_INSERT by dns_rbt_addname.
 * Since it is known it will not be called if there any suffixes
 * in common, only the topmost label needs to be compared.
 *
 * @@@ As with cmp_label, this is too simplistic.  Now lowercasing or
 * bitstring comparisons are done.
 */
static inline int
cmp_names_on_level(dns_name_t *a, dns_name_t *b) {
	dns_label_t alabel, blabel;
	int a_last_label, b_last_label;

	a_last_label = dns_name_countlabels(a) - 1;
	b_last_label = dns_name_countlabels(b) - 1;

	INSIST(( dns_name_isabsolute(a) &&  dns_name_isabsolute(b)) ||
	       (!dns_name_isabsolute(a) && !dns_name_isabsolute(b)));

	if (dns_name_isabsolute(a))
		a_last_label--, b_last_label--;

	dns_name_getlabel(a, a_last_label, &alabel);
	dns_name_getlabel(b, b_last_label, &blabel);

	return cmp_label(&alabel, &blabel);
}


isc_mem_t *mctx;

void
dns_rbt_indent(int depth) {
	int i;

	for (i = 0; i < depth; i++)
		putchar('\t');
}

void
dns_rbt_printnodename(dns_rbtnode_t *node) {
	char *buffer[255];
	isc_buffer_t target;
	isc_region_t r;
	dns_name_t name;

	r.length = NAMELEN(node);
	r.base = NAME(node);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);

	isc_buffer_init(&target, buffer, 255, ISC_BUFFERTYPE_TEXT);
	dns_name_totext(&name, 1, &target);

	printf("%.*s", (int)target.used, (char *)target.base);
}


void
dns_rbt_printtree(dns_rbtnode_t *root, dns_rbtnode_t *parent, int depth) {
	dns_rbt_indent(depth);

	if (root != NULL) {
		dns_rbt_printnodename(root);
		printf(" (%s", IS_RED(root) ? "RED" : "black");
		if (parent) {
			printf(" from ");
			dns_rbt_printnodename(parent);
		}
		printf(")\n");
		depth++;

		if (DOWN(root)) {
			dns_rbt_indent(depth);
			printf("++ BEG down from ");
			dns_rbt_printnodename(root);
			printf("\n");
			dns_rbt_printtree(DOWN(root), NULL, depth);
			dns_rbt_indent(depth);
			printf("-- END down from ");
			dns_rbt_printnodename(root);
			printf("\n");
		}

		if (IS_RED(root) && IS_RED(LEFT(root)))
		    printf("** Red/Red color violation on left\n");
		dns_rbt_printtree(LEFT(root), root, depth);

		if (IS_RED(root) && IS_RED(RIGHT(root)))
		    printf("** Red/Red color violation on right\n");
		dns_rbt_printtree(RIGHT(root), root, depth);

	} else
		printf("NULL\n");
}

void
dns_rbt_printall(dns_rbt_t *rbt) {
	dns_rbt_printtree(rbt->root, NULL, 0);
}

/* DCL */
