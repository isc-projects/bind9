/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>

#include <dns/redblack.h>

#define RBT_MAGIC		0x5242542BU /* RBT+. */
#define VALID_RBT(rbt)		((rbt) != NULL && (rbt)->magic == RBT_MAGIC)

struct dns_rbt {
	unsigned int		magic;
	isc_mem_t *		mctx;
	dns_rbt_node_t *	root;
};

#define PARENT(node)	((node)->parent)
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
#define SET_PARENT(node, child)	((node)->parent = (child))

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
isc_region_t Name(dns_rbt_node_t *node);
isc_region_t 
Name(dns_rbt_node_t *node) {
	isc_region_t r;

	r.length = NAMELEN(node);
	r.base = NAME(node);

	return(r);
}
#else
#endif

#if 0
dns_rbt_node_t *Root;			/* The Root of All Ev... er, DNS. */
#endif

/*
 * Forward declarations.
 */
static isc_result_t create_node(isc_mem_t *mctx,
				dns_name_t *name, dns_rbt_node_t **nodep);

static int cmp_label(dns_label_t *a, dns_label_t *b);
static inline int cmp_names_on_level(dns_name_t *a, dns_name_t *b);
static inline int cmp_names_for_depth(dns_name_t *a, dns_name_t *b);

static inline void rotate_left(dns_rbt_node_t *node, dns_rbt_node_t **rootp);
static inline void rotate_right(dns_rbt_node_t *node, dns_rbt_node_t **rootp);

static isc_result_t dns_rbt_add_node(dns_rbt_node_t *node,
				     dns_rbt_node_t **rootp);
static isc_result_t dns_rbt_delete_workhorse(dns_rbt_node_t *delete,
					     dns_rbt_node_t **rootp);
static void dns_rbt_delete_node(isc_mem_t *mctx,
				dns_rbt_node_t *node, dns_rbt_node_t **root);
static void dns_rbt_delete_tree(isc_mem_t *mctx,
				dns_rbt_node_t *node, dns_rbt_node_t **root);


/*
 * Initialize a red/black tree of trees.
 */
isc_result_t
dns_rbt_create(isc_mem_t *mctx, dns_rbt_t **rbtp) {
	dns_rbt_t *rbt;

	REQUIRE(mctx != NULL);
	REQUIRE(rbtp != NULL && *rbtp == NULL);

	rbt = (dns_rbt_t *)isc_mem_get(mctx, sizeof(*rbt));
	if (rbt == NULL)
		return (ISC_R_NOMEMORY);

	rbt->mctx = mctx;
	rbt->root = NULL;
	rbt->magic = RBT_MAGIC;

	*rbtp = rbt;

	return (ISC_R_SUCCESS);
}

/*
 * Initialize a red/black tree of trees.
 */
void
dns_rbt_destroy(dns_rbt_t **rbtp) {
	dns_rbt_t *rbt;

	REQUIRE(rbtp != NULL && VALID_RBT(*rbtp));

	rbt = *rbtp;

	dns_rbt_delete_tree(rbt->mctx, rbt->root, &rbt->root);

	isc_mem_put(rbt->mctx, rbt, sizeof(*rbt));

	*rbtp = NULL;
}

/*
 * Add 'name' to tree, initializing its data pointer with 'data'.
 */

isc_result_t
dns_rbt_add_name(dns_rbt_t *rbt, dns_name_t *name, void *data) {
	dns_rbt_node_t **root, *current, *child, *new_node, *new_current;
	dns_name_t add_name, current_name, new_name, tmp_name;
	int compared, add_labels, current_labels, keep_labels, start_label;
	isc_result_t result;

	REQUIRE(dns_name_isabsolute(name));

	/*
	 * Create a copy of the name so the original name structure is
	 * not modified.
	 */
	memcpy(&add_name, name, sizeof(add_name));

	/* @@@
	 * The following code nearly duplicates a non-trivial
	 * amount of the dns_rbt_add_node algorithm.  It can be
	 * improved by merging the two functions.
	 */

	if (rbt->root == NULL) {
		result = create_node(rbt->mctx, &add_name, &new_node);
		if (result == ISC_R_SUCCESS)
			result = dns_rbt_add_node(new_node, &rbt->root);

		return (result);
	}

	root = &rbt->root;
	child = *root;
	dns_name_init(&current_name, NULL);
	do {
		current = child;

		dns_rbt_namefromnode(current, &current_name);
		compared = cmp_names_for_depth(&add_name, &current_name);

		if (compared == BOTH_ARE_EQUAL)
			if (DATA(current) != NULL)
				return(ISC_R_EXISTS);
			else {
				DATA(current) = data; /* @@@ ? */
				return(ISC_R_SUCCESS);
			}

		else if (compared == FIRST_IS_LESS)
			child = LEFT(current);
		else if (compared == FIRST_IS_MORE)
			child = RIGHT(current);

		else {
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
				child = DOWN(current);
				root = &DOWN(current);

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
				if (result != ISC_R_SUCCESS)
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
				if (PARENT(current) != NULL)
					if (LEFT(PARENT(current)) == current)
						SET_LEFT(PARENT(current),
							 new_current);
					else
						SET_RIGHT(PARENT(current),
							  new_current);
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
				if (result != ISC_R_SUCCESS)
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
				 * Set up the new root of the next level
				 * and start the next tree.
				 */
				DOWN(current) = NULL;
				root = &DOWN(current);
				result = dns_rbt_add_node(new_node, root);
				/*
				 * This should never happen, eh?
				 */
				if (result != ISC_R_SUCCESS)
					return(result);

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
					return(ISC_R_SUCCESS);
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
					child = NULL;
				}

			}

		}

	} while (child != NULL);

	result = create_node(rbt->mctx,
			     &add_name, &new_node);
	if (result == ISC_R_SUCCESS) {
		DATA(new_node) = data;
		result = dns_rbt_add_node(new_node, root);
	}

	return (result);
}

/*
 * Find the node for "name" in the tree of trees.
 * If second argument "up" is non-NULL, set it to the node that has
 * the down pointer for the found node.
 */
dns_rbt_node_t *
dns_rbt_find_node(dns_rbt_t *rbt, dns_name_t *name, dns_rbt_node_t **up) {
	dns_rbt_node_t *current;
	dns_name_t *search_name, *new_search_name, *current_name;
	dns_name_t holder1, holder2;
	int compared, current_labels, keep_labels, dont_count_root_label;

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

	while (current != NULL) {
		dns_rbt_namefromnode(current, current_name);
		compared = cmp_names_for_depth(search_name, current_name);

		if (compared == BOTH_ARE_EQUAL)
			break;

		/*
		 * Standard binary search tree movement.
		 */
		if (compared == FIRST_IS_LESS)
			current = LEFT(current);
		else if (compared == FIRST_IS_MORE)
			current = RIGHT(current);

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
				if (up != NULL)
					*up = current;
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

	if (current == NULL && up != NULL)
		*up = NULL;

	return(current);
}

void *
dns_rbt_find_name(dns_rbt_t *rbt, dns_name_t *name) {
	dns_rbt_node_t *node;

	node = dns_rbt_find_node(rbt, name, NULL);

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
 * This will remove all subnames of the name, too.
 * @@@ (Should it?  If not, what should happen to those subnames?)
 */
isc_result_t
dns_rbt_delete_name(dns_rbt_t *rbt, dns_name_t *name) {
	dns_rbt_node_t *node, *up, **root;

	REQUIRE(dns_name_isabsolute(name));

	node = dns_rbt_find_node(rbt, name, &up);

	if (node != NULL) {
		if (DOWN(node))
			dns_rbt_delete_tree(rbt->mctx,
					    DOWN(node), &DOWN(node));

		if (up != NULL)
			root = &DOWN(up);
		else
			root = &rbt->root;

		dns_rbt_delete_node(rbt->mctx, node, root);

		return(ISC_R_SUCCESS);
	} else
		return(ISC_R_NOTFOUND);

}

void
dns_rbt_namefromnode(dns_rbt_node_t *node, dns_name_t *name) {
	isc_region_t r;

	r.length = NAMELEN(node);
	r.base = NAME(node);

	dns_name_fromregion(name, &r);
}

static isc_result_t
create_node(isc_mem_t *mctx, dns_name_t *name, dns_rbt_node_t **nodep) {
	dns_rbt_node_t *node;
	isc_region_t region;

	dns_name_toregion(name, &region);

	node = (dns_rbt_node_t *)isc_mem_get(mctx,
					     sizeof(*node) + region.length);
	if (node == NULL)
		return (ISC_R_NOMEMORY);

	PARENT(node) = NULL;
	LEFT(node) = NULL;
	RIGHT(node) = NULL;
	DOWN(node) = NULL;

	NAMELEN(node) = region.length;
	memcpy(NAME(node), region.base, region.length);

	*nodep = node;

	return (ISC_R_SUCCESS);
}

static inline void
rotate_left(dns_rbt_node_t *node, dns_rbt_node_t **rootp) {
	dns_rbt_node_t *child;

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
rotate_right(dns_rbt_node_t *node, dns_rbt_node_t **rootp) {
	dns_rbt_node_t *child;

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

static isc_result_t
dns_rbt_add_node(dns_rbt_node_t *node, dns_rbt_node_t **rootp) {
	dns_rbt_node_t *current, *child, *root, *parent, *grandparent;
	dns_name_t add_name, current_name;
	dns_offsets_t offsets;
	int i;

	REQUIRE(rootp != NULL);
	REQUIRE(LEFT(node) == NULL && RIGHT(node) == NULL);

	root = *rootp;
	if (root == NULL) {
		MAKE_BLACK(node);
		*rootp = node;
		return (ISC_R_SUCCESS);
	}

	current = NULL;
	child = root;

	dns_name_init(&add_name, offsets);
	dns_rbt_namefromnode(node, &add_name);

	dns_name_init(&current_name, NULL);

	do {
		current = child;

		dns_rbt_namefromnode(current, &current_name);

		i = cmp_names_on_level(&add_name, &current_name);
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

		if (parent == LEFT(grandparent)) {
			child = RIGHT(grandparent);
			if (child != NULL && IS_RED(child)) {
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
			} else {
				if (node == RIGHT(parent)) {
					node = parent;
					rotate_left(node, &root);
					parent = PARENT(node);
					grandparent = PARENT(PARENT(node));
				}
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				rotate_right(grandparent, &root);
			}
		} else {
			child = LEFT(grandparent);
			if (child != NULL && IS_RED(child)) {
				MAKE_BLACK(parent);
				MAKE_BLACK(child);
				MAKE_RED(grandparent);
				node = grandparent;
			} else {
				if (node == LEFT(parent)) {
					node = parent;
					rotate_right(node, &root);
					parent = PARENT(node);
					grandparent = PARENT(PARENT(node));
				}
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

static isc_result_t
dns_rbt_delete_workhorse(dns_rbt_node_t *delete, dns_rbt_node_t **rootp) {
	dns_rbt_node_t *successor, *sibling, *child = NULL;

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
		dns_rbt_node_t holder, *tmp = &holder;

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

		memcpy(tmp, successor, sizeof(dns_rbt_node_t));

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
		dns_rbt_node_t *parent;
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


static void
dns_rbt_delete_node(isc_mem_t *mctx,
		    dns_rbt_node_t *node, dns_rbt_node_t **root) {

	dns_rbt_delete_workhorse(node, root);

	isc_mem_put(mctx, node, sizeof(*node) + NAMELEN(node));
}

static void
dns_rbt_delete_tree(isc_mem_t *mctx,
		    dns_rbt_node_t *node, dns_rbt_node_t **root) {

	if (LEFT(node) != NULL)
		dns_rbt_delete_tree(mctx, LEFT(node), root);
	if (RIGHT(node) != NULL)
		dns_rbt_delete_tree(mctx, RIGHT(node), root);
	if (DOWN(node) != NULL)
		dns_rbt_delete_tree(mctx, DOWN(node), &DOWN(node));

	dns_rbt_delete_node(mctx, node, root);
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

	i = strncmp(a->base, b->base, MIN(a->length, b->length));

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
 * This is meant only to be passed to RBT_INSERT by dns_rbt_add_name.
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


#ifdef WANT_REDBLACK_MAIN
char *name_strings[] = {
	"a.vix.com",
	"b.vix.com",
	"c.vix.com",
	"a.b.c.d.e.f.vix.com",
	"b.b.c.d.e.f.vix.com",
	"c.b.c.d.e.f.vix.com",
	"a.d.e.f.vix.com",
	"q.d.e.f.vix.com",
	"d.e.f.vix.com",
	"g.h.vix.com",
#if 0
	"rc.vix.com",
	"pa.vix.com",
	"lh.vix.com",
	"dd.org",
	"gro.dd.org",
	"mmuuf.org",
	"vmba.org",
	"isc.org",
	"ftp.isc.org",
	"ftp.uu.net",
	"fugue.com",
	"uunet.uu.net",
	"a1.vix.com",
	"a2.vix.com",
	"a3.vix.com",
#endif
	NULL
};

isc_mem_t *mctx;

static inline void
print_indent(int depth) {
	int i;

	for (i = 0; i < depth; i++)
		putchar('\t');
}

static void
print_node_name(dns_rbt_node_t *node) {
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


static void
print_tree(dns_rbt_node_t *root, int depth) {
	print_indent(depth);
	if (root != NULL) {
		print_node_name(root);
		printf(" (%s", IS_RED(root) ? "RED" : "black");
		if (PARENT(root)) {
			printf(" from ");
			print_node_name(PARENT(root));
		}
		printf(")\n");
		depth++;

		if (DOWN(root)) {
			print_indent(depth);
			printf("++ BEG down from ");
			print_node_name(root);
			printf("\n");
			print_tree(DOWN(root), depth);
			print_indent(depth);
			printf("-- END down from ");
			print_node_name(root);
			printf("\n");
		}

		if (IS_RED(root) && IS_RED(LEFT(root)))
		    printf("** Red/Red color violation on left\n");
		print_tree(LEFT(root), depth);

		if (IS_RED(root) && IS_RED(RIGHT(root)))
		    printf("** Red/Red color violation on right\n");
		print_tree(RIGHT(root), depth);

	} else
		printf("NULL\n");
}

static dns_name_t *
create_name(char *s) {
	int len;
	void *buffer;
	isc_result_t result;
	isc_buffer_t source, target;
	dns_name_t *name;

	len = strlen(s);
	isc_buffer_init(&source, s, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);

#define LEN 255
	/* NOTE: allocated pointer not tracked */
	buffer = malloc(LEN);
	isc_buffer_init(&target, buffer, LEN, ISC_BUFFERTYPE_BINARY);
#undef LEN

	/* NOTE: allocated pointer not tracked */
	name = malloc(sizeof(dns_name_t));
	dns_name_init(name, NULL);

	result = dns_name_fromtext(name, &source, dns_rootname, 0,
				         &target);

	if (result != 0) {
		printf("dns_name_fromtext(%s) failed: %s\n",
		       s, isc_result_totext(result));
		exit(1);
	}

	return name;
}


void main () {
	char **p;
	dns_name_t *name;
	dns_rbt_t *rbt;
	dns_rbt_node_t *node;
	isc_result_t result;

	setbuf(stdout, NULL);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	result = dns_rbt_create(mctx, &rbt);
	if (result != ISC_R_SUCCESS)
		printf("dns_rbt_create: %s: exiting\n",
		      isc_result_totext(result));

	for (p = name_strings; *p; p++) {
		printf("adding name %s\n", *p);

		name = create_name(*p);
		result = dns_rbt_add_name(rbt, name, name);
		if (result == ISC_R_SUCCESS)
			print_tree(rbt->root, 0);
		else
			printf("... %s\n", isc_result_totext(result));
	}

	*p = "q.d.e.f.vix.com";
	name = create_name(*p);
	printf("searching for name %s ... ", *p);
	node = dns_rbt_find_node(rbt, name, NULL);
	if (node != NULL) {
		printf("found it.\n");
	} else
		printf("NOT FOUND!\n");

	*p = "does.not.exist";
	name = create_name(*p);
	printf("searching for name %s ... ", *p);
	node = dns_rbt_find_node(rbt, name, NULL);
	if (node != NULL) {
		printf("found it.\n");
	} else
		printf("NOT FOUND!\n");

	*p = "d.e.f.vix.com";
	name = create_name(*p);
	printf("deleting name %s\n", *p);
	dns_rbt_delete_name(rbt, name);
	print_tree(rbt->root, 0);

	dns_rbt_destroy(&rbt);

	exit(0);
}
#endif /* WANT_REDBLACK_MAIN */
