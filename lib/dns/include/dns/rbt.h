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

#include <isc/result.h>
#include <isc/mem.h>

#include <dns/types.h>
#include <dns/name.h>

/*
 * This is the structure that is used for each node in the red/black
 * tree of trees.  NOTE WELL:  the implementation manages this as a variable
 * length structure, with the actual wire-format name being stored as
 * a sequence of "name_length" bytes appended to this structure.  Allocating
 * a contiguous block of memory for multiple dns_rbt_node structures is
 * pretty much guaranteed to be useless.
 *
 * Note that the name_length variable will indicate how long just the length
 * of the label(s) associated with this tree, not the length of the entire
 * name the node is part of.
 */

typedef struct dns_rbt dns_rbt_t;

typedef struct dns_rbt_node {
	struct dns_rbt_node *left;
	struct dns_rbt_node *right;
	struct dns_rbt_node *down;
	enum { red, black } color;
	void *data;
	unsigned int name_length;
} dns_rbtnode_t;

dns_result_t dns_rbt_addname(dns_rbt_t *rbt, dns_name_t *name, void *data);
/*
 * Add 'name' to the tree of trees, associated with 'data'.
 *
 * Notes:
 *	'data' is never required to be non-NULL, but specifying it
 *	when the name is added is faster than searching for 'name'
 *	again and then setting the data pointer.
 *
 * Requires:
 *	dns_name_isabsolute(name) == TRUE
 *
 * Ensures:
 *
 *	'name' is not altered in any way.
 *
 *	If result is success:
 *		'name' is findable in the red/black tree of trees in O(log N).
 *
 * Returns:
 *	Success
 *	Resource Limit: Out of Memory
 */

dns_result_t dns_rbt_deletename(dns_rbt_t *rbt, dns_name_t *name);
/*
 * Delete 'name' from the tree of trees.
 *
 * Notes:
 *	When 'name' is removed, all of its subnames are removed too.
 *
 * Requires:
 *	dns_name_isabsolute(name) == TRUE
 *
 * Ensures:
 *
 *	'name' is not altered in any way.
 *
 *	'name' does not appear in the tree.
 *
 * Returns:
 *	Success
 *	Bad Form: Not Found
 */

void dns_rbt_namefromnode(dns_rbtnode_t *node, dns_name_t *name);
/*
 * Convert the sequence of labels stored at 'node' into a 'name'.
 *
 * Notes:
 *	The name data pointed to by 'name' is the information stored
 *	in the node, not a copy.  Altering the data at this pointer
 *	will likely cause grief.
 *
 */

dns_rbtnode_t *dns_rbt_findnode(dns_rbt_t *rbt, dns_name_t *name);
/*
 * Find the node for 'name'.
 *
 * Notes:
 *	It is _not_ required that the node associated with 'name'
 *	has a non-NULL data pointer.
 */

void *dns_rbt_findname(dns_rbt_t *rbt, dns_name_t *name);
/*
 * Return the data pointer associated with 'name'.
 *
 * Notes:
 *	Returns NULL if either the name could not be found, or
 *	if the name is found but has a NULL data pointer.
 */

void dns_rbt_indent(int depth);
void dns_rbt_printnodename(dns_rbtnode_t *node);
void dns_rbt_printtree(dns_rbtnode_t *root, dns_rbtnode_t *parent, int depth);
void dns_rbt_printall(dns_rbt_t *rbt);

dns_result_t dns_rbt_create(isc_mem_t *mctx, dns_rbt_t **rbtp);
void dns_rbt_destroy(dns_rbt_t **rbtp);
