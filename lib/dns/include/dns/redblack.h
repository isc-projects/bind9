#include <isc/result.h>
#include <isc/region.h>

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
	struct dns_rbt_node *parent;
	struct dns_rbt_node *left;
	struct dns_rbt_node *right;
	struct dns_rbt_node *down;
	enum { red, black } color;
	void *data;
	int name_length;
} dns_rbt_node_t;

isc_result_t dns_rbt_create(isc_mem_t *mctx, dns_rbt_t **rbtp);
void dns_rbt_destroy(dns_rbt_t **rbtp);


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
isc_result_t dns_rbt_add_name(dns_rbt_t *rbt, dns_name_t *name, void *data);

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
isc_result_t dns_rbt_delete_name(dns_rbt_t *rbt, dns_name_t *name);

/*
 * Convert the sequence of labels stored at 'node' into a 'name'.
 *
 * Notes:
 *	The name data pointed to by 'name' is the information stored
 *	in the node, not a copy.  Altering the data at this pointer
 *	will likely cause grief.
 *
 */
void dns_rbt_namefromnode(dns_rbt_node_t *node, dns_name_t *name);

/*
 * Find the node for 'name'.
 *
 * Notes:
 *	If 'up' is non-null, it will receive the value of the node
 *	that has the down pointer to the found node.  If 'name' is
 *	not found, then it '*up' is guaranteed to be NULL.  If
 *	'name' is found in the top level tree of trees, '*up' will
 *	also be NULL.
 *
 *	It is _not_ required that the node associated with 'name'
 *	has a non-NULL data pointer.
 */
dns_rbt_node_t *dns_rbt_find_node(dns_rbt_t *rbt,
				  dns_name_t *name, dns_rbt_node_t **up);

/*
 * Return the data pointer associated with 'name'.
 *
 * Notes:
 *	Returns NULL if either the name could not be found, or
 *	if the name is found but has a NULL data pointer.
 */
void *dns_rbt_find_name(dns_rbt_t *rbt, dns_name_t *name);
