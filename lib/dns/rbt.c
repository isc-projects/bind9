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
#include <isc/boolean.h>
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
	void			(*data_deleter)(void *);
};

struct node_chain {
	dns_rbtnode_t **	ancestors;
	int			ancestor_count;
	int			ancestor_maxitems;
	/*
	 * The maximum number of labels in a name is 128; need space for 127
	 * to be able to store the down pointer history for the worst case.
	 */
	dns_rbtnode_t *		levels[127];
	int			level_count;
	isc_boolean_t		mem_failure;
};

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define RED 0
#define BLACK 1

#define LEFT(node) 	((node)->left)
#define RIGHT(node)	((node)->right)
#define DOWN(node)	((node)->down)
#define NAMELEN(node)	(*(unsigned char *)((node) + 1))
#define NAME(node)	((void *)((char *)(node) + sizeof(*node) + 1))
#define DATA(node)	((node)->data)
#define COLOR(node) 	((node)->color)
#define DIRTY(node)	((node)->dirty)
#define LOCK(node)	((node)->locknum)
#define REFS(node)	((node)->references)

#define IS_RED(node)		((node) != NULL && (node)->color == RED)
#define IS_BLACK(node)		((node) == NULL || (node)->color == BLACK)
#define MAKE_RED(node)		((node)->color = RED)
#define MAKE_BLACK(node)	((node)->color = BLACK)

#define NODE_SIZE(node)	(sizeof(*node) + 1 + NAMELEN(node))

/*
 * For the return value of cmp_names_for_depth().
 */
#define BOTH_ARE_EQUAL	0
#define FIRST_IS_LESS	-1
#define FIRST_IS_MORE	-2

/*
 * For use in allocating space for the chain of ancestor nodes.
 *
 * The maximum number of ancestors is theoretically not limited by the
 * data tree.  This initial value of 24 ancestors would be able to scan
 * the full height of a single level of 16,777,216 nodes, more than double
 * the current size of .com.
 */
#ifndef ISC_MEM_DEBUG
#define ANCESTOR_BLOCK 24
#else
#define ANCESTOR_BLOCK 1	/* To give the reallocation code a workout. */
#endif

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
#endif

/*
 * Forward declarations.
 */
static dns_result_t create_node(isc_mem_t *mctx,
				dns_name_t *name, dns_rbtnode_t **nodep);

static dns_result_t join_nodes(dns_rbt_t *rbt,
			       dns_rbtnode_t *node, dns_rbtnode_t *parent,
			       dns_rbtnode_t **rootp);

static inline dns_result_t get_ancestor_mem(isc_mem_t *mctx,
					    node_chain_t *chain);

static int cmp_label(dns_label_t *a, dns_label_t *b);
static inline int cmp_names_on_level(dns_name_t *a, dns_name_t *b);
static inline int cmp_names_for_depth(dns_name_t *a, dns_name_t *b);

static inline void rotate_left(dns_rbtnode_t *node, dns_rbtnode_t *parent,
			       dns_rbtnode_t **rootp);
static inline void rotate_right(dns_rbtnode_t *node, dns_rbtnode_t *parent,
				dns_rbtnode_t **rootp);

static dns_result_t dns_rbt_addonlevel(dns_rbt_t *rbt,
				       dns_rbtnode_t *node,
				       dns_rbtnode_t **rootp,
				       node_chain_t *chain);
static void dns_rbt_deletefromlevel(dns_rbt_t *rbt,
				    dns_rbtnode_t *delete,
				    node_chain_t *chain);
static void dns_rbt_deletetree(dns_rbt_t *rbt, dns_rbtnode_t *node);

static dns_result_t zapnode_and_fixlevels(dns_rbt_t *rbt,
					  dns_rbtnode_t *node,
					  isc_boolean_t recurse,
					  node_chain_t *chain);

/*
 * Initialize a red/black tree of trees.
 */
dns_result_t
dns_rbt_create(isc_mem_t *mctx, void (*deleter)(void *), dns_rbt_t **rbtp) {
	dns_rbt_t *rbt;

	REQUIRE(mctx != NULL);
	REQUIRE(rbtp != NULL && *rbtp == NULL);

	rbt = (dns_rbt_t *)isc_mem_get(mctx, sizeof(*rbt));
	if (rbt == NULL)
		return (DNS_R_NOMEMORY);

	rbt->mctx = mctx;
	rbt->data_deleter = deleter;
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

	dns_rbt_deletetree(rbt, rbt->root);

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
dns_rbt_addnode(dns_rbt_t *rbt, dns_name_t *name, dns_rbtnode_t **nodep) {
	dns_rbtnode_t **root, *current, *parent, *child;
	dns_rbtnode_t *new_node, *new_current;
	dns_name_t add_name, current_name, new_name, tmp_name;
	int compared, add_labels, current_labels, keep_labels, start_label;
	dns_result_t result;
	node_chain_t chain;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/*
	 * Create a copy of the name so the original name structure is
	 * not modified.
	 */
	memcpy(&add_name, name, sizeof(add_name));

	if (rbt->root == NULL) {
		result = create_node(rbt->mctx, &add_name, &new_node);
		if (result == DNS_R_SUCCESS) {
			rbt->root = new_node;
			*nodep = new_node;
		}
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

		if (compared == BOTH_ARE_EQUAL) {
			*nodep = current;
			if (DATA(current) != NULL)
				return (DNS_R_EXISTS);
			else
				return (DNS_R_SUCCESS);

		} else if (compared == FIRST_IS_LESS) {
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
				 * Reproduce the tree attributes of the
				 * current node.
				 */
				LEFT(new_current) = LEFT(current);
				RIGHT(new_current) = RIGHT(current);
				COLOR(new_current) = COLOR(current);

				/*
				 * Fix pointers that were to the current node.
				 */
				if (parent != NULL)
					if (LEFT(parent) == current)
						LEFT(parent) = new_current;
					else
						RIGHT(parent) = new_current;
				if (*root == current)
					*root = new_current;

				/*
				 * Now create the new root of the subtree
				 * as the not-in-common labels of the current
				 * node.  Its down pointer and name data
				 * should be preserved, while left, right
				 * and parent pointers are nullified (when
				 * the node is created in create_node()).
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

				DATA(new_node) = DATA(current);
				DOWN(new_node) = DOWN(current);
				REFS(new_node) = REFS(current);	  /* @@@ ? */
				DIRTY(new_node) = DIRTY(current); /* @@@ ? */
				/* @@@ ? locknum */

				/*
				 * Now that the old name in the existing
				 * node has been disected into two new
				 * nodes, the old node can be freed.
				 */
				isc_mem_put(rbt->mctx, current,
					    NODE_SIZE(current));
				current = new_current;

				/*
				 * Set up the new root of the next level.
				 */
				DOWN(current) = new_node;
				root = &DOWN(current);

				if (compared == add_labels) {
					/*
					 * The name has been added by pushing
					 * the not-in-common parts down to
					 * a new level.
					 */
					*nodep = current;
					return (DNS_R_SUCCESS);

				} else {
					/*
					 * The current node has no data,
					 * because it is just a placeholder.
					 * It's data pointer is already NULL
					 * from create_node()).
					 */

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

	result = create_node(rbt->mctx, &add_name, &new_node);

	if (result == DNS_R_SUCCESS)
		result = dns_rbt_addonlevel(rbt, new_node, root, &chain);

	if (chain.ancestor_maxitems > 0)
		isc_mem_put(rbt->mctx, chain.ancestors,
			    chain.ancestor_maxitems * sizeof(dns_rbtnode_t *));

	if (result == DNS_R_SUCCESS)
		*nodep = new_node;

	return (result);
}

dns_result_t
dns_rbt_addname(dns_rbt_t *rbt, dns_name_t *name, void *data) {
	dns_result_t result;
	dns_rbtnode_t *node;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(dns_name_isabsolute(name));

	node = NULL;

	result = dns_rbt_addnode(rbt, name, &node);
	if (result == DNS_R_SUCCESS)
		DATA(node) = data;

	return (result);
}

#define ADD_ANCESTOR(chain, node) \
			(chain)->ancestors[(chain)->ancestor_count++] = (node)
#define ADD_LEVEL(chain, node) \
			(chain)->levels[(chain)->level_count++] = (node)

/*
 * Find the node for "name" in the tree of trees.
 * If second argument "up" is non-NULL, set it to the node that has
 * the down pointer for the found node.
 */
dns_rbtnode_t *
dns_rbt_findnode(dns_rbt_t *rbt, dns_name_t *name, node_chain_t *chain) {
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

	if (chain != NULL) {
		chain->ancestor_maxitems = 0;
		chain->ancestor_count = 0;
		chain->level_count = 0;

		if (get_ancestor_mem(rbt->mctx, chain) != DNS_R_SUCCESS)
			return (NULL);

		ADD_ANCESTOR(chain, NULL);
	}
		
	while (current != NULL) {
		dns_rbt_namefromnode(current, current_name);
		compared = cmp_names_for_depth(search_name, current_name);

		if (compared == BOTH_ARE_EQUAL)
			break;

		/*
		 * Expand the storage space for ancestors, if necessary.
		 */
		if (chain != NULL &&
		    chain->ancestor_count == chain->ancestor_maxitems &&
		    get_ancestor_mem(rbt->mctx, chain) != DNS_R_SUCCESS)
				return (NULL);

		/*
		 * Standard binary search tree movement.
		 */
		if (compared == FIRST_IS_LESS) {
			if (chain != NULL)
				ADD_ANCESTOR(chain, current);
			current = LEFT(current);
		} else if (compared == FIRST_IS_MORE) {
			if (chain != NULL)
				ADD_ANCESTOR(chain, current);
			current = RIGHT(current);

		/*
		 * The names have some common suffix labels.
		 */
		} else {
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
				if (chain != NULL) {
					ADD_ANCESTOR(chain, NULL);
					ADD_LEVEL(chain, current);
				}

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

	return (current);
}

void *
dns_rbt_findname(dns_rbt_t *rbt, dns_name_t *name) {
	dns_rbtnode_t *node;

	REQUIRE(VALID_RBT(rbt));

	node = dns_rbt_findnode(rbt, name, NULL);

	if (node != NULL && DATA(node) != NULL)
		return(DATA(node));
	else
		return(NULL);
}

/*
 * Delete a name from the tree of trees.
 */
dns_result_t
dns_rbt_deletename(dns_rbt_t *rbt, dns_name_t *name, isc_boolean_t recurse) {
	dns_rbtnode_t *node;
	dns_result_t result;
	node_chain_t chain;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(dns_name_isabsolute(name));

	/*
	 * Find the node, building the ancestor chain.
	 *
	 * When searching, the name might not have an exact match:
	 * consider a.b.a.com, b.b.a.com and c.b.a.com as the only
	 * elements of a tree, which would make layer 1 a single
	 * node tree of "b.a.com" and layer 2 a three node tree of
	 * a, b, and c.  Deleting a.com would find only a partial depth
	 * match in the first layer.  Should it be a requirement that
	 * that the name to be deleted have data?  For now, it is.
	 *
	 * @@@ how to ->dirty, ->locknum and ->references figure in?
	 */

	node = dns_rbt_findnode(rbt, name, &chain);

	/*
	 * The guts of this routine are in a separate function (which
	 * is called only once, by this function) to make freeing the
	 * ancestor memory easier, since there are several different
	 * exit points from the level checking logic.
	 */
	result = zapnode_and_fixlevels(rbt, node, recurse, &chain);

	if (chain.ancestor_maxitems > 0)
		isc_mem_put(rbt->mctx, chain.ancestors,
			    chain.ancestor_maxitems * sizeof(dns_rbtnode_t *));

	return (result);
}

static dns_result_t
zapnode_and_fixlevels(dns_rbt_t *rbt, dns_rbtnode_t *node,
		      isc_boolean_t recurse, node_chain_t *chain) {
	dns_rbtnode_t *down, *parent, **rootp;
	dns_result_t result;

	if (node == NULL || DATA(node) == NULL)
		if (chain->mem_failure)
			return (DNS_R_NOMEMORY);
		else
			return (DNS_R_NOTFOUND);

	down = DOWN(node);

	if (down != NULL) {
		if (recurse) {
			dns_rbt_deletetree(rbt, down);
			down = NULL;

		} else {
			if (rbt->data_deleter != NULL)
				rbt->data_deleter(DATA(node));
			DATA(node) = NULL;

			if (LEFT(down) != NULL || RIGHT(down) != NULL)
				/*
				 * This node cannot be removed because it
				 * points down to a level that has more than
				 * one node, so it must continue to serve
				 * as the root for that level.  All that
				 * could be done was to blast its data.
				 */
				return (DNS_R_SUCCESS);

			/*
			 * There is a down pointer to a level with a single
			 * item.  That item's name can be joined with the name
			 * on this level.
			 */
			
			rootp = chain->level_count > 0 ?
				&DOWN(chain->levels[chain->level_count - 1]) :
				&rbt->root;
			parent = chain->ancestors[chain->ancestor_count - 1];

			result = join_nodes(rbt, node, parent, rootp);

			return (result);
		}
	}

	/*
	 * This node now has no down pointer (either because it didn't
	 * have one to start, or because it was recursively removed).
	 * So now the node needs to be removed from this level.
	 */
	dns_rbt_deletefromlevel(rbt, node, chain);

	if (rbt->data_deleter != NULL)
		rbt->data_deleter(DATA(node));
	isc_mem_put(rbt->mctx, node, NODE_SIZE(node));

	/*
	 * Everything is successful, unless the next block fails.
	 */
	result = DNS_R_SUCCESS;

	/*
	 * If there is one node left on this level, and the node one level up
	 * that points down to here has no data, then those two nodes can be
	 * merged.  The focus for exploring this criteria is shifted up one
	 * level.
	 */
	node = chain->level_count > 0 ?
		chain->levels[chain->level_count - 1] : NULL;

	if (node != NULL && DATA(node) == NULL &&
	    LEFT(DOWN(node)) == NULL && RIGHT(DOWN(node)) == NULL) {
		rootp = chain->level_count > 1 ?
			&DOWN(chain->levels[chain->level_count - 2]) :
			&rbt->root;
		/*
		 * The search to find the original node went through the
		 * node that is now being examined.  It might have been
		 *
		 * current_node -down-to-> deleted_node      ... or ...
		 *
		 * current_node -down-to-> remaining_node -left/right-to->
		 *						deleted_node
		 *
		 * In the first case, ancestor_count - 1 is NULL and - 2
		 * is the parent of current_node (possibly also NULL).
		 * In the second case, ancestor_count - 1 is remaining_node,
		 * - 2, is NULL and - 3 is the parent of current_node.
		 */
		parent = chain->ancestors[chain->ancestor_count - 1] == NULL ?
			 chain->ancestors[chain->ancestor_count - 2] :
			 chain->ancestors[chain->ancestor_count - 3];

		result = join_nodes(rbt, node, parent, rootp);
	}

	return (result);
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

	/* 
	 * Allocate space for the node structure, plus the length byte,
	 * plus the length of the name.
	 */
	node = (dns_rbtnode_t *)isc_mem_get(mctx,
					    sizeof(*node) + 1 + region.length);
	if (node == NULL)
		return (DNS_R_NOMEMORY);

	RIGHT(node) = NULL;
	LEFT(node) = NULL;
	DOWN(node) = NULL;
	DATA(node) = NULL;

	LOCK(node) = 0;		/* @@@ ? */
	REFS(node) = 0;
	DIRTY(node) = 0;

	MAKE_BLACK(node);

	NAMELEN(node) = region.length;
	memcpy(NAME(node), region.base, region.length);

	*nodep = node;

	return (DNS_R_SUCCESS);
}

static dns_result_t
join_nodes(dns_rbt_t *rbt,
	   dns_rbtnode_t *node, dns_rbtnode_t *parent, dns_rbtnode_t **rootp) {
	dns_rbtnode_t *down, *newnode;
	dns_result_t result;
	dns_name_t newname;
	isc_region_t r;
	int newsize;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(node != NULL);
	REQUIRE(DATA(node) == NULL && DOWN(node) != NULL);

	down = DOWN(node);

	newsize = NAMELEN(node) + NAMELEN(down);

	r.base = isc_mem_get(rbt->mctx, newsize);
	if (r.base == NULL)
		return (DNS_R_NOMEMORY);

	memcpy(r.base,
	       NAME(down), NAMELEN(down));
	memcpy(r.base + NAMELEN(down),
	       NAME(node), NAMELEN(node));

	r.length = newsize;

	dns_name_init(&newname, NULL);
	dns_name_fromregion(&newname, &r);

	result = create_node(rbt->mctx, &newname, &newnode);
	if (result == DNS_R_SUCCESS) {
		isc_mem_put(rbt->mctx, r.base, r.length);

		COLOR(newnode) = COLOR(node);
		RIGHT(newnode) = RIGHT(node);
		LEFT(newnode)  = LEFT(node);

		DOWN(newnode) = DOWN(down);
		DATA(newnode) = DATA(down);

		/*
		 * Fix the pointers to the original node.
		 */
		if (parent != NULL) {
			if (LEFT(parent) == node)
				LEFT(parent) = newnode;
			else
				RIGHT(parent) = newnode;

		} else
			*rootp = newnode;

		isc_mem_put(rbt->mctx, node, NODE_SIZE(node));
		isc_mem_put(rbt->mctx, down, NODE_SIZE(down));
	}

	return (result);
}

static inline dns_result_t
get_ancestor_mem(isc_mem_t *mctx, node_chain_t *chain) {
	dns_rbtnode_t **ancestor_mem;
	int oldsize, newsize;

	oldsize = chain->ancestor_maxitems * sizeof(dns_rbtnode_t *);
	newsize = oldsize + ANCESTOR_BLOCK * sizeof(dns_rbtnode_t *);

	ancestor_mem = isc_mem_get(mctx, newsize);

	if (ancestor_mem == NULL) {
		chain->mem_failure = ISC_TRUE;
		return (DNS_R_NOMEMORY);
	}

	chain->mem_failure = ISC_FALSE;

	if (oldsize > 0) {
		memcpy(ancestor_mem, chain->ancestors, oldsize);
		isc_mem_put(mctx, chain->ancestors, oldsize);
	}

	chain->ancestors = ancestor_mem;
	chain->ancestor_maxitems += ANCESTOR_BLOCK;

	return (DNS_R_SUCCESS);
}

static inline void
rotate_left(dns_rbtnode_t *node, dns_rbtnode_t *parent, dns_rbtnode_t **rootp) {
	dns_rbtnode_t *child;

	REQUIRE(node != NULL);
	REQUIRE(rootp != NULL);

	child = RIGHT(node);
	REQUIRE(child != NULL);

	RIGHT(node) = LEFT(child);
	LEFT(child) = node;

	if (parent != NULL) {
		if (LEFT(parent) == node)
			LEFT(parent) = child;
		else
			RIGHT(parent) = child;
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

	LEFT(node)   = RIGHT(child);
	RIGHT(child) = node;

	if (parent != NULL) {
		if (LEFT(parent) == node)
			LEFT(parent) = child;
		else
			RIGHT(parent) = child;
	} else
		*rootp = child;
}

/*
 * This is the real workhorse of the insertion code, because it does the
 * true red/black tree on a single level.
 */
static dns_result_t
dns_rbt_addonlevel(dns_rbt_t *rbt, dns_rbtnode_t *node, dns_rbtnode_t **rootp,
		   node_chain_t *chain) {
	dns_rbtnode_t *current, *child, *root, *tmp, *parent, *grandparent;
	dns_name_t add_name, current_name;
	dns_offsets_t offsets;
	int i;
	unsigned int depth;

	REQUIRE(rootp != NULL);
	REQUIRE(LEFT(node) == NULL && RIGHT(node) == NULL);

	chain->ancestor_maxitems = 0;
	chain->ancestor_count = 0;

	root = *rootp;
	if (root == NULL) {
		MAKE_BLACK(node);
		*rootp = node;
		return (DNS_R_SUCCESS);
	}

	current = NULL;
	child = root;

	dns_name_init(&add_name, offsets);
	dns_rbt_namefromnode(node, &add_name);

	dns_name_init(&current_name, NULL);

	do {
		if (chain->ancestor_count == chain->ancestor_maxitems &&
		    get_ancestor_mem(rbt->mctx, chain) != DNS_R_SUCCESS)
				return (DNS_R_NOMEMORY);
		ADD_ANCESTOR(chain, current);

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

	if (chain->ancestor_count == chain->ancestor_maxitems &&
	    get_ancestor_mem(rbt->mctx, chain) != DNS_R_SUCCESS)
		return (DNS_R_NOMEMORY);
	ADD_ANCESTOR(chain, current);
	depth = chain->ancestor_count - 1;

	if (i < 0)
		LEFT(current) = node;
	else
		RIGHT(current) = node;
	MAKE_RED(node);

	while (node != root && IS_RED(chain->ancestors[depth])) {
		INSIST(depth > 0);

		parent = chain->ancestors[depth];
		grandparent = chain->ancestors[depth - 1];

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
					rotate_left(parent, grandparent,
						    &root);
					tmp = node;
					node = parent;
					parent = tmp;
					chain->ancestors[depth] = parent;
				}
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				INSIST(depth > 1);
				rotate_right(grandparent,
					     chain->ancestors[depth - 2],
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
					rotate_right(parent, grandparent,
						     &root);
					tmp = node;
					node = parent;
					parent = tmp;
					chain->ancestors[depth] = parent;
				}
				MAKE_BLACK(parent);
				MAKE_RED(grandparent);
				INSIST(depth > 1);
				rotate_left(grandparent,
					    chain->ancestors[depth - 2],
					    &root);
			}
		}
	}

	MAKE_BLACK(root);
	*rootp = root;

	return (DNS_R_SUCCESS);
}

/*
 * This is the real workhorse of the deletion code, because it does the
 * true red/black tree on a single level.
 *
 * The ancestor and level history _must_ be set with dns_rbt_findnode for
 * this function to work properly.
 */
static void
dns_rbt_deletefromlevel(dns_rbt_t *rbt, dns_rbtnode_t *delete,
			node_chain_t *chain) {
	dns_rbtnode_t *sibling, *parent, *grandparent, *child;
	dns_rbtnode_t *successor, **rootp;
	int depth;

	REQUIRE(VALID_RBT(rbt));
	REQUIRE(delete);
	REQUIRE(chain->ancestor_count > 0);

	parent = chain->ancestors[chain->ancestor_count - 1];

	if (chain->level_count > 0)
		rootp = &DOWN(chain->levels[chain->level_count - 1]);
	else
		rootp = &rbt->root;

	/*
	 * Verify that the ancestor/level history is (apparently) correct.
	 */
	REQUIRE((parent == NULL && *rootp == delete) ||
		(parent != NULL && 
		 (LEFT(parent) == delete || RIGHT(parent) == delete)));

	child = NULL;

	if (LEFT(delete) == NULL)
		if (RIGHT(delete) == NULL) {
			if (chain->ancestors[chain->ancestor_count - 1]
			    == NULL) {
				/*
				 * This is the only item in the tree.
				 */
				*rootp = NULL;
				return;
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
		depth = chain->ancestor_count++;
		successor = RIGHT(delete);
		while (LEFT(successor) != NULL) {
			chain->ancestors[chain->ancestor_count++] = successor;
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

		chain->ancestors[depth] = successor;
		parent = chain->ancestors[depth - 1];

		if (parent)
			if (LEFT(parent) == delete)
				LEFT(parent) = successor;
			else
				RIGHT(parent) = successor;
		else
			*rootp = successor;

		LEFT(successor)  = LEFT(delete);
		RIGHT(successor) = RIGHT(delete);
		COLOR(successor) = COLOR(delete);

		/*
		 * Now relink the node to be deleted into the
		 * successor's previous tree location.
		 */
		parent = chain->ancestors[chain->ancestor_count - 1];
		if (parent == successor)
			RIGHT(parent) = delete;
		else
			LEFT(parent) = delete;

		/*
		 * Original location of successor node has no left.
		 */

		LEFT(delete)  = NULL;
		RIGHT(delete) = RIGHT(tmp);
		COLOR(delete) = COLOR(tmp);
	}

	parent = chain->ancestors[chain->ancestor_count - 1];

	/*
	 * Remove the node by removing the links from its parent.
	 */
	if (parent != NULL) {
		if (LEFT(parent) == delete) {
			LEFT(parent) = child;
			sibling = RIGHT(parent);
		} else {
			RIGHT(parent) = child;
			sibling = LEFT(parent);
		}

	} else {
		/*
		 * This is the root being deleted, and at this point
		 * it is known to have just one child.
		 */
		sibling = NULL;
		*rootp = child;
	} 

	/*
	 * Fix color violations.
	 */
	if (IS_BLACK(delete)) {
		dns_rbtnode_t *parent;
		depth = chain->ancestor_count - 1;

		while (child != *rootp && IS_BLACK(child)) {
			parent = chain->ancestors[depth--];
			grandparent = chain->ancestors[depth];

			if (LEFT(parent) == child) {
				sibling = RIGHT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_left(parent, grandparent,
						    rootp);
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
						rotate_right(sibling,
							     grandparent,
							     rootp);
						sibling = RIGHT(parent);
					}
					COLOR(sibling) = COLOR(parent);
					MAKE_BLACK(parent);
					MAKE_BLACK(RIGHT(sibling));
					rotate_left(parent, grandparent,
						    rootp);
					child = *rootp;
				}
			} else {
				sibling = LEFT(parent);
				if (IS_RED(sibling)) {
					MAKE_BLACK(sibling);
					MAKE_RED(parent);
					rotate_right(parent, grandparent,
						     rootp);
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
						rotate_left(sibling,
							    grandparent,
							    rootp);
						sibling = LEFT(parent);
					}
					COLOR(sibling) = COLOR(parent);
					MAKE_BLACK(parent);
					MAKE_BLACK(LEFT(sibling));
					rotate_right(parent, grandparent,
						     rootp);
					child = *rootp;
				}
			}

		}

		if (IS_RED(child))
			MAKE_BLACK(child);
	}
}

/*
 * This should only be used on the root of a tree, because no color fixup
 * is done at all.
 *
 * NOTE: No root pointer maintenance is done, because the function is only
 * used for two cases:
 * + deleting everything DOWN from a node that is itself being deleted
 * + deleting the entire tree of trees from dns_rbt_destroy.
 * In each case, the root pointer is no longer relevant, so there
 * is no need for a root parameter to this function.
 *
 * If the function is ever intended to be used to delete something where
 * a pointer needs to be told that this tree no longer exists,
 * this function would need to adjusted accordinly.
 */
static void
dns_rbt_deletetree(dns_rbt_t *rbt, dns_rbtnode_t *node) {

	REQUIRE(VALID_RBT(rbt));

	if (node == NULL)
		return;

	if (LEFT(node) != NULL)
		dns_rbt_deletetree(rbt, LEFT(node));
	if (RIGHT(node) != NULL)
		dns_rbt_deletetree(rbt, RIGHT(node));
	if (DOWN(node) != NULL)
		dns_rbt_deletetree(rbt, DOWN(node));

	if (DATA(node) != NULL && rbt->data_deleter != NULL)
		rbt->data_deleter(DATA(node));

	isc_mem_put(rbt->mctx, node, NODE_SIZE(node));
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
