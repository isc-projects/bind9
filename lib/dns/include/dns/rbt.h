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

#ifndef	DNS_RBT_H
#define	DNS_RBT_H 1

#include <isc/lang.h>
#include <isc/result.h>
#include <isc/mem.h>

#include <dns/types.h>
#include <dns/name.h>

ISC_LANG_BEGINDECLS

/*
 * This is the structure that is used for each node in the red/black
 * tree of trees.  NOTE WELL:  the implementation manages this as a variable
 * length structure, with the actual wire-format name and other data appended
 * appended to this structure.  Allocating a contiguous block of memory for
 * multiple dns_rbtnode structures will not work.
 */

typedef struct dns_rbt dns_rbt_t;

/* These should add up to 31 */

#define DNS_RBT_LOCKLENGTH			11
#define DNS_RBT_REFLENGTH			20

typedef struct dns_rbtnode {
	struct dns_rbtnode *left;
	struct dns_rbtnode *right;
	struct dns_rbtnode *down;
	/*
	 * The following bitfields add up to a total bitwidth of 32.
	 * The range of values necessary for each item is indicated,
	 * but in the case of "attributes" the field is wider to accomodate
	 * possible future expansion.  "offsetlen" could be one bit
	 * narrower by always adjusting its value by 1 to find the real
	 * offsetlen, but doing so does not gain anything (except perhaps
	 * another bit for "attributes", which doesn't yet need any more).
	 */
	unsigned int color:1;	     /* range is 0..1 */
	unsigned int attributes:6;   /* range is 0..2 */
	unsigned int namelen:8;	     /* range is 1..255 */
	unsigned int offsetlen:8;    /* range is 1..128 */
	unsigned int padbytes:9;     /* range is 0..380 */
	/*
	 * These values are used in the RBT DB implementation.  The appropriate
	 * node lock must be held before accessing them.
	 */
	void *data;
	unsigned int dirty:1;
	unsigned int locknum:DNS_RBT_LOCKLENGTH;
	unsigned int references:DNS_RBT_REFLENGTH;
} dns_rbtnode_t;

typedef struct dns_rbtnodechain dns_rbtnodechain_t;

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
 *	rbt is a valid rbt structure.
 *	dns_name_isabsolute(name) == TRUE
 *
 * Ensures:
 *
 *	'name' is not altered in any way.
 *
 *	If result is DNS_R_SUCCESS:
 *		'name' is findable in the red/black tree of trees in O(log N).
 *
 * Returns:
 *	Success
 *	Resource Limit: Out of Memory
 */

dns_result_t dns_rbt_addnode(dns_rbt_t *rbt, dns_name_t *name,
			    dns_rbtnode_t **nodep);
/*
 * Just like dns_rbt_addname, but return the address of the added node,
 * even when the node already existed.
 *
 * Requires:
 *	rbt is a valid rbt structure.
 *	dns_name_isabsolute(name) == TRUE
 *	nodep != NULL && *nodep == NULL
 */

dns_result_t dns_rbt_deletename(dns_rbt_t *rbt, dns_name_t *name,
				isc_boolean_t recurse);
/*
 * Delete 'name' from the tree of trees.
 *
 * Notes:
 *	When 'name' is removed, if recurse is TRUE then all of its
 *      subnames are removed too.
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

dns_result_t dns_rbt_findnode(dns_rbt_t *rbt, dns_name_t *name,
			       dns_rbtnode_t **node,
			       dns_rbtnodechain_t *chain);
/*
 * Find the node for 'name'.
 *
 * Notes:
 *	It is _not_ required that the node associated with 'name'
 *	has a non-NULL data pointer.
 */

dns_result_t dns_rbt_findname(dns_rbt_t *rbt, dns_name_t *name, void **data);
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

dns_result_t dns_rbt_create(isc_mem_t *mctx, void (*deleter)(void *, void *),
			    void *arg, dns_rbt_t **rbtp);
void dns_rbt_destroy(dns_rbt_t **rbtp);

ISC_LANG_ENDDECLS

#endif
