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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/db.h>
#include <dns/dbtable.h>
#include <dns/message.h>
#include <dns/rdatastruct.h>
#include <dns/journal.h>
#include <dns/view.h>

#include <named/globals.h>
#include <named/client.h>
#include <named/update.h>

/*
 * This module implements dynamic update as in RFC2136.
 */
  
/*
  XXX TODO:
  - serialization and queueing of update requests
  - forwarding
  - locking?
  - document strict minimality
  - use logging library, not printf
*/

#define FAIL(code) do { result = (code); goto failure; } while (0)
#define FAILMSG(code, msg) do { printf("%s\n", msg); \
				result = (code); goto failure; } while (0)
		
#define CHECK(op) do { result = (op); \
		       if (result != DNS_R_SUCCESS) goto failure; \
		     } while (0)
		
typedef struct rr rr_t;

struct rr {
	/* dns_name_t name; */
	isc_uint32_t ttl;
	dns_rdata_t rdata;
};

/**************************************************************************/

/*
 * Update a single RR in version 'ver' of 'db' and log the
 * update in 'diff'.
 * Ensures:
 *   '*tuple' == NULL.  Either the tuple is freed, or its
 *         ownership has been transferred to the diff.
 */
static dns_result_t
do_one_tuple(dns_difftuple_t **tuple,
	     dns_db_t *db, dns_dbversion_t *ver,
	     dns_diff_t *diff)
{
	dns_diff_t temp_diff;
	dns_result_t result;
	
	/* Create a singleton diff */
	dns_diff_init(diff->mctx, &temp_diff);
	ISC_LIST_APPEND(temp_diff.tuples, *tuple, link);

	/* Apply it to the database. */
	result = dns_diff_apply(&temp_diff, db, ver);
	if (result != DNS_R_SUCCESS) {
		dns_difftuple_free(tuple);
		return (result);
	}

	/* Merge it into the current pending journal entry. */
	dns_diff_appendminimal(diff, tuple);

	/* Do not clear temp_diff. */
	
	return (DNS_R_SUCCESS);
}
	      
static dns_result_t
update_one_rr(dns_db_t *db, dns_dbversion_t *ver, dns_diff_t *diff,
	      dns_diffop_t op, dns_name_t *name, 
	      dns_ttl_t ttl, dns_rdata_t *rdata)
{
	dns_difftuple_t *tuple = NULL;
	dns_result_t result;
	result = dns_difftuple_create(diff->mctx, op,
				      name, ttl, rdata, &tuple);
	if (result != DNS_R_SUCCESS)
		return (result);
	return (do_one_tuple(&tuple, db, ver, diff));
}

/**************************************************************************/
/*
 * Callback-style iteration over rdatasets and rdatas.
 *
 * foreach_rrset() can be used to iterate over the RRsets 
 * of a name and call a callback function with each
 * one.  Similarly, foreach_rr() can be used to iterate
 * over the individual RRs at name, optionally restricted 
 * to RRs of a given type.
 *
 * The callback functions are called "actions" and take
 * two arguments: a void pointer for passing arbitrary
 * context information, and a pointer to the current RRset
 * or RR.  By convention, their names end in "_action".
 */

/*
 * XXXRTH  We might want to make this public somewhere in libdns.
 */

/* Function type for foreach_rrset() iterator actions. */
typedef dns_result_t rrset_func(void *data, dns_rdataset_t *rrset);

/* Function type for foreach_rr() iterator actions. */
typedef dns_result_t rr_func(void *data, rr_t *rr);

/* Internal context struct for foreach_node_rr(). */
typedef struct {
	rr_func *	rr_action;
	void *		rr_action_data;
} foreach_node_rr_ctx_t;

/* Internal helper function for foreach_node_rr(). */
static dns_result_t
foreach_node_rr_action(void *data, dns_rdataset_t *rdataset)
{
	dns_result_t result;
	foreach_node_rr_ctx_t *ctx = data;
	for (result = dns_rdataset_first(rdataset);
	     result == DNS_R_SUCCESS;
	     result = dns_rdataset_next(rdataset))
	{
		rr_t rr;
		dns_rdataset_current(rdataset, &rr.rdata);
		rr.ttl = rdataset->ttl;
		result = (*ctx->rr_action)(ctx->rr_action_data, &rr);
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (result != DNS_R_NOMORE)
		return (result);
	return (DNS_R_SUCCESS);
}

/*
 * For each rdataset of 'name' in 'ver' of 'db', call 'action'
 * with the rdataset and 'action_data' as arguments.  If the name
 * does not exist, do nothing. 
 *
 * If 'action' returns an error, abort iteration and return the error.
 */
static dns_result_t
foreach_rrset(dns_db_t *db,
	      dns_dbversion_t *ver,
	      dns_name_t *name,
	      rrset_func *action,
	      void *action_data)
{
	dns_result_t result;
	dns_dbnode_t *node;
	dns_rdatasetiter_t *iter;
	
	node = NULL;
	result = dns_db_findnode(db, name, ISC_FALSE, &node);
	if (result == DNS_R_NOTFOUND)
		return (DNS_R_SUCCESS);
	if (result != DNS_R_SUCCESS)
		return (result);
	
	iter = NULL;
	result = dns_db_allrdatasets(db, node, ver,
				     (isc_stdtime_t) 0, &iter);
	if (result != DNS_R_SUCCESS)
		goto cleanup_node;

	for (result = dns_rdatasetiter_first(iter);
	     result == DNS_R_SUCCESS;
	     result = dns_rdatasetiter_next(iter))
	{
		dns_rdataset_t rdataset;

		dns_rdataset_init(&rdataset);
		dns_rdatasetiter_current(iter, &rdataset);

		result = (*action)(action_data, &rdataset);

		dns_rdataset_disassociate(&rdataset);
		if (result != DNS_R_SUCCESS)
			goto cleanup_iterator;
	}
	if (result == DNS_R_NOMORE)
		result = DNS_R_SUCCESS;

 cleanup_iterator:
	dns_rdatasetiter_destroy(&iter);

 cleanup_node:
	dns_db_detachnode(db, &node);	

	return (result);
}

/*
 * For each RR of 'name' in 'ver' of 'db', call 'action'
 * with the RR and 'action_data' as arguments.  If the name
 * does not exist, do nothing.
 *
 * If 'action' returns an error, abort iteration
 * and return the error.
 */
static dns_result_t
foreach_node_rr(dns_db_t *db,
	    dns_dbversion_t *ver,
	    dns_name_t *name,
	    rr_func *rr_action,
	    void *rr_action_data)
{
	foreach_node_rr_ctx_t ctx;
	ctx.rr_action = rr_action;
	ctx.rr_action_data = rr_action_data;
	return (foreach_rrset(db, ver, name,
			      foreach_node_rr_action, &ctx));
}


/*
 * For each of the RRs specified by 'db', 'ver', 'name', 'type',
 * (which can be dns_rdatatype_any to match any type), and 'covers', call
 * 'action' with the RR and 'action_data' as arguments. If the name 
 * does not exist, or if no RRset of the given type exists at the name,
 * do nothing.
 * 
 * If 'action' returns an error, abort iteration and return the error.
 */
static dns_result_t
foreach_rr(dns_db_t *db,
	   dns_dbversion_t *ver,
	   dns_name_t *name,
	   dns_rdatatype_t type,
	   dns_rdatatype_t covers,
	   rr_func *rr_action,
	   void *rr_action_data)
{

	dns_result_t result;
	dns_dbnode_t *node;
	dns_rdataset_t rdataset;

	if (type == dns_rdatatype_any)
		return (foreach_node_rr(db, ver, name, 
					rr_action, rr_action_data));
	
	node = NULL;
	result = dns_db_findnode(db, name, ISC_FALSE, &node);
	if (result == DNS_R_NOTFOUND)
		return (DNS_R_SUCCESS);
	if (result != DNS_R_SUCCESS)
		return (result);

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, ver, type, covers,
				     (isc_stdtime_t) 0, &rdataset);
	if (result == DNS_R_NOTFOUND) {
		result = DNS_R_SUCCESS;
		goto cleanup_node;
	}
	if (result != DNS_R_SUCCESS)
		goto cleanup_node;

	for (result = dns_rdataset_first(&rdataset);
	     result == DNS_R_SUCCESS;
	     result = dns_rdataset_next(&rdataset))
	{
		rr_t rr;
		dns_rdataset_current(&rdataset, &rr.rdata);
		rr.ttl = rdataset.ttl;
		result = (*rr_action)(rr_action_data, &rr);
		if (result != DNS_R_SUCCESS)
			goto cleanup_rdataset;
	}
	if (result != DNS_R_NOMORE)
		goto cleanup_rdataset;
	result = DNS_R_SUCCESS;

 cleanup_rdataset:
	dns_rdataset_disassociate(&rdataset);
 cleanup_node:
	dns_db_detachnode(db, &node);	

	return (result);
}


/**************************************************************************/
/*
 * Various tests on the database contents (for prerequisites, etc).
 */

/*
 * Function type for predicate functions that compare a database RR 'db_rr'
 * against an update RR 'update_rr'.
 */
typedef isc_boolean_t rr_predicate(dns_rdata_t *update_rr, dns_rdata_t *db_rr);

/* Helper function for rrset_exists(). */
static dns_result_t
rrset_exists_action(void *data, rr_t *rr) /*ARGSUSED*/
{
	data = data; /* Unused */
	rr = rr; /* Unused */
	return (DNS_R_EXISTS);
}

#define RETURN_EXISTENCE_FLAG 			\
do {						\
	if (result == DNS_R_EXISTS)  { 		\
		*exists = ISC_TRUE; 		\
		return (DNS_R_SUCCESS); 	\
	} else if (result == DNS_R_SUCCESS) { 	\
		*exists = ISC_FALSE; 		\
		return (DNS_R_SUCCESS); 	\
	} else { 				\
		return (result); 		\
	}					\
} while (0)

/*
 * Set '*exists' to true iff an rrset of the given type exists,
 * to false otherwise.
 */
static dns_result_t
rrset_exists(dns_db_t *db, dns_dbversion_t *ver,
	     dns_name_t *name, dns_rdatatype_t type, dns_rdatatype_t covers,
	     isc_boolean_t *exists)
{
	dns_result_t result;
	result = foreach_rr(db, ver, name, type, covers,
			    rrset_exists_action, NULL);
	RETURN_EXISTENCE_FLAG;
}

/* Helper function for cname_incompatible_rrset_exists(). */
/*
 * XXXRTH  We should move this to rdata.c.
 */
static isc_boolean_t
is_dnssec_type(dns_rdatatype_t type) {
	return ((type == dns_rdatatype_sig ||
		 type == dns_rdatatype_key ||
		 type == dns_rdatatype_nxt) ?
		ISC_TRUE : ISC_FALSE);
}

/* Helper function for cname_incompatible_rrset_exists */
static dns_result_t
cname_compatibility_action(void *data, dns_rdataset_t *rrset) 
/*ARGSUSED*/
{
	data = data; /* Unused */
	if (rrset->type != dns_rdatatype_cname &&
	    ! is_dnssec_type(rrset->type))
		return (DNS_R_EXISTS);
	return (DNS_R_SUCCESS);
}

/*
 * Check whether there is an rrset incompatible with adding a CNAME RR,
 * i.e., anything but another CNAME (which can be replaced) or a
 * DNSSEC RR (which can coexist).
 *
 * If such an incompatible rrset exists, set '*exists' to ISC_TRUE.
 * Otherwise, set it to ISC_FALSE.
 */
static dns_result_t
cname_incompatible_rrset_exists(dns_db_t *db, dns_dbversion_t *ver,
				dns_name_t *name, isc_boolean_t *exists) {
	dns_result_t result;	
	result = foreach_rrset(db, ver, name, 
			       cname_compatibility_action, NULL);
	RETURN_EXISTENCE_FLAG;
}

/* Helper function for rr_count(). */
static dns_result_t 
count_rr_action(void *data, rr_t *rr) /*ARGSUSED*/ {
	int *countp = data;
	rr = rr; /* Unused. */
	(*countp)++;
	return (DNS_R_SUCCESS);
}

/*
 * Count the number of RRs of 'type' belonging to 'name' in 'ver' of 'db'.
 */
static dns_result_t
rr_count(dns_db_t *db, dns_dbversion_t *ver, dns_name_t *name,
	 dns_rdatatype_t type, dns_rdatatype_t covers, int *countp)
{
	*countp = 0;
	return (foreach_rr(db, ver, name, type, covers,
			   count_rr_action, countp));
}

/* Context struct for matching_rr_exists(). */

typedef struct {
	rr_predicate *predicate;
	dns_db_t *db;
	dns_dbversion_t *ver;
	dns_name_t *name;
	dns_rdata_t *update_rr;
} matching_rr_exists_ctx_t;

/* Helper function for matching_rr_exists(). */

static dns_result_t 
matching_rr_exists_action(void *data, rr_t *rr) {
	matching_rr_exists_ctx_t *ctx = data;
	if ((*ctx->predicate)(ctx->update_rr, &rr->rdata))
		return (DNS_R_EXISTS);
	return (DNS_R_SUCCESS);
}

/*
 * Compare the 'update_rr' with all RRs in the RRset specified by 'db', 
 * 'ver', 'name', and 'type' using 'predicate'.  If the predicate returns
 * true for at least one of them, set '*exists' to ISC_TRUE.  Otherwise,
 * set it to ISC_FALSE.
 */
static dns_result_t
matching_rr_exists(rr_predicate *predicate,
	     dns_db_t *db,
	     dns_dbversion_t *ver,
	     dns_name_t *name,
	     dns_rdatatype_t type,
	     dns_rdatatype_t covers,
	     dns_rdata_t *update_rr,
	     isc_boolean_t *exists)
{
	dns_result_t result;
	matching_rr_exists_ctx_t ctx;
	ctx.predicate = predicate;
	ctx.db = db;
	ctx.ver = ver;
	ctx.name = name;
	ctx.update_rr = update_rr;
	result = foreach_rr(db, ver, name, type, covers,
			    matching_rr_exists_action, &ctx);
	RETURN_EXISTENCE_FLAG;
}


/* Context struct and helper function for name_exists() */

static dns_result_t
name_exists_action(void *data, dns_rdataset_t *rrset) /*ARGSUSED*/
{
	data = data; /* Unused */
	rrset = rrset; /* Unused */
	return (DNS_R_EXISTS);
}

/*
 * Set '*exists' to true iff the given name exists, to false otherwise.
 */
static dns_result_t
name_exists(dns_db_t *db, dns_dbversion_t *ver, dns_name_t *name,
	    isc_boolean_t *exists)
{
	dns_result_t result;
	result = foreach_rrset(db, ver, name,
			       name_exists_action, NULL);
	RETURN_EXISTENCE_FLAG;
}

/**************************************************************************/
/*
 * Checking of "RRset exists (value dependent)" prerequisites.
 *
 * In the RFC2136 section 3.2.5, this is the pseudocode involving
 * a variable called "temp", a mapping of <name, type> tuples to rrsets.
 *
 * Here, we represent the "temp" data structure as (non-minimial) "dns_diff_t"
 * where each typle has op==DNS_DIFFOP_EXISTS.
 */


/*
 * Append a tuple asserting the existence of the RR with
 * 'name' and 'rdata' to 'diff'.
 */	     
static dns_result_t
temp_append(dns_diff_t *diff, dns_name_t *name, dns_rdata_t *rdata)
{
	dns_result_t result;
	dns_difftuple_t *tuple = NULL;
	
	REQUIRE(VALID_DIFF(diff));
	result = dns_difftuple_create(diff->mctx, DNS_DIFFOP_EXISTS,
				      name, 0, rdata, &tuple);
	if (result != DNS_R_SUCCESS)
		return (result);
	
	ISC_LIST_APPEND(diff->tuples, tuple, link);
	return (DNS_R_SUCCESS);
}

/*
 * Compare two rdatasets represented as sorted lists of tuples.
 * All list elements must have the same owner name and type.
 * Return DNS_R_SUCCESS if the rdatasets are equal, rcode(dns_rcode_nxrrset)
 * if not.
 */
static dns_result_t 
temp_check_rrset(dns_difftuple_t *a, dns_difftuple_t *b) {
	for (;;) {
		if (a == NULL || b == NULL)
			break;
		INSIST(a->op == DNS_DIFFOP_EXISTS && b->op == DNS_DIFFOP_EXISTS);
		INSIST(a->rdata.type == b->rdata.type);
		INSIST(dns_name_equal(&a->name, &b->name));
		if (dns_rdata_compare(&a->rdata, &b->rdata) != 0)
			return (DNS_R_NXRRSET);
		a = ISC_LIST_NEXT(a, link);
		b = ISC_LIST_NEXT(b, link);
	}
	if (a != NULL || b != NULL)
		return (DNS_R_NXRRSET);
	return (DNS_R_SUCCESS);
}

/*
 * A comparison function defining the sorting order for the entries
 * in the "temp" data structure.  The major sort key is the owner name,
 * followed by the type and rdata.
 */
static int 
temp_order(const void *av, const void *bv)
{
	dns_difftuple_t * const *ap = av;
	dns_difftuple_t * const *bp = bv;
	dns_difftuple_t *a = *ap;
	dns_difftuple_t *b = *bp;	
	int r;
	r = dns_name_compare(&a->name, &b->name);
	if (r != 0)
		return (r);
	r = (b->rdata.type - a->rdata.type);
	if (r != 0)
		return (r);
	r = dns_rdata_compare(&a->rdata, &b->rdata);
	return (r);
}

/*
 * Check the "RRset exists (value dependent)" prerequisite information
 * in 'temp' against the contents of the database 'db'.
 *
 * Return DNS_R_SUCCESS if the prerequisites are satisfied,
 * rcode(dns_rcode_nxrrset) if not.
 */

static dns_result_t
temp_check(isc_mem_t *mctx, dns_diff_t *temp, dns_db_t *db,
	   dns_dbversion_t *ver)
{
	dns_result_t result;
	dns_name_t *name;
	dns_dbnode_t *node;
	dns_difftuple_t *t;
	dns_diff_t trash;
	
	/* Exit early if the list is empty (for efficiency only). */
	if (ISC_LIST_HEAD(temp->tuples) == NULL)
		return (DNS_R_SUCCESS);

	/*
	 * Sort the prerequisite records by owner name,
	 * type, and rdata.
	 */
	result = dns_diff_sort(temp, temp_order);
	if (result != DNS_R_SUCCESS)
		return (result);

	dns_diff_init(mctx, &trash);
	
	/*
	 * For each name and type in the prerequisites,
	 * construct a sorted rdata list of the corresponding
	 * database contents, and compare the lists.
	 */
	t = ISC_LIST_HEAD(temp->tuples);
	while (t != NULL) {
		name = &t->name;

		/* A new unique name begins here. */
		node = NULL;
		result = dns_db_findnode(db, name, ISC_FALSE, &node);
		if (result == DNS_R_NOTFOUND)
			return (DNS_R_NXRRSET);
		if (result != DNS_R_SUCCESS)
			return (result);

		/* A new unique type begins here. */		
		while (t != NULL && dns_name_equal(&t->name, name)) {
			dns_rdatatype_t type, covers;
			dns_rdataset_t rdataset;
			dns_diff_t d_rrs; /* Database RRs with 
						this name and type */
 			dns_diff_t u_rrs; /* Update RRs with
						this name and type */

			type = t->rdata.type;
			if (type == dns_rdatatype_sig)
				covers = dns_rdata_covers(&t->rdata);
			else
				covers = 0;

			/*
			 * Collect all database RRs for this name and type
			 * onto d_rrs and sort them.
			 */
			dns_rdataset_init(&rdataset);
			result = dns_db_findrdataset(db, node, ver, type,
						     covers, (isc_stdtime_t) 0,
						     &rdataset);
			if (result != DNS_R_SUCCESS) {
				dns_db_detachnode(db, &node);
				return (DNS_R_NXRRSET);
			}

			dns_diff_init(mctx, &d_rrs);
			dns_diff_init(mctx, &u_rrs);

			for (result = dns_rdataset_first(&rdataset);
			     result == DNS_R_SUCCESS;
			     result = dns_rdataset_next(&rdataset))
			{
				dns_rdata_t rdata;
				dns_rdataset_current(&rdataset, &rdata);
				result = temp_append(&d_rrs, name, &rdata);
				if (result != DNS_R_SUCCESS)
					goto failure;
			}
			if (result != DNS_R_NOMORE)
				goto failure;
			result = dns_diff_sort(&d_rrs, temp_order);
			if (result != DNS_R_SUCCESS) 
				goto failure;

			/*
			 * Collect all update RRs for this name and type
			 * onto u_rrs.  No need to sort them here - 
			 * they are already sorted.
			 */
			while (t != NULL &&
			       dns_name_equal(&t->name, name) &&
			       t->rdata.type == type)
			{
				dns_difftuple_t *next =
					ISC_LIST_NEXT(t, link);
				ISC_LIST_UNLINK(temp->tuples, t, link);
				ISC_LIST_APPEND(u_rrs.tuples, t, link);
				t = next;
			}

			/* Compare the two sorted lists. */
			result = temp_check_rrset(ISC_LIST_HEAD(u_rrs.tuples),
						  ISC_LIST_HEAD(d_rrs.tuples));
			if (result != DNS_R_SUCCESS)
				goto failure;

			/*
			 * We are done with the tuples, but we can't free
			 * them yet because "name" still points into one
			 * of them.  Move them on a temporary list.
			 */
			ISC_LIST_APPENDLIST(trash.tuples, u_rrs.tuples, link);
			ISC_LIST_APPENDLIST(trash.tuples, d_rrs.tuples, link);
			dns_rdataset_disassociate(&rdataset);

			continue;

		    failure:
			dns_diff_clear(&d_rrs);
			dns_diff_clear(&u_rrs);
			dns_diff_clear(&trash);
			dns_rdataset_disassociate(&rdataset);
			dns_db_detachnode(db, &node);
			return (result);
		}

		dns_db_detachnode(db, &node);
	}
	
	dns_diff_clear(&trash);	
	return (DNS_R_SUCCESS);
}

/**************************************************************************/
/*
 * Conditional deletion of RRs.
 */

/* Context structure for delete_if(). */

typedef struct {
	rr_predicate *predicate;
	dns_db_t *db;
	dns_dbversion_t *ver;
	dns_diff_t *diff;
	dns_name_t *name;
	dns_rdata_t *update_rr;
} conditional_delete_ctx_t;

/* Predicate functions for delete_if(). */

/* Return true iff 'update_rr' is neither a SOA nor an NS RR. */
static isc_boolean_t
type_not_soa_nor_ns_p(dns_rdata_t *update_rr, dns_rdata_t *db_rr) /*ARGSUSED*/
{
	update_rr = update_rr; /* Unused */
	return ((db_rr->type != dns_rdatatype_soa &&
		 db_rr->type != dns_rdatatype_ns) ?
		ISC_TRUE : ISC_FALSE);
}

/* Return true always. */
static isc_boolean_t
true_p(dns_rdata_t *update_rr, dns_rdata_t *db_rr) /*ARGSUSED*/
{
	update_rr = update_rr; /* Unused */ 
	db_rr = db_rr; /* Unused */ 
	return (ISC_TRUE);
}

/* Return true iff the two RRs have identical rdata. */
static isc_boolean_t
rr_equal_p(dns_rdata_t *update_rr, dns_rdata_t *db_rr) {
	/*
	 * XXXRTH  This is not a problem, but we should consider creating
	 *         dns_rdata_equal() (that used dns_name_equal()), since it
	 *         would be faster.  Not a priority.
	 */
	return (dns_rdata_compare(update_rr, db_rr) == 0 ?
		ISC_TRUE : ISC_FALSE);
}

/*
 * Return true iff 'update_rr' should replace 'db_rr' according
 * to the special RFC2136 rules for CNAME, SOA, and WKS records.
 */
static isc_boolean_t
replaces_p(dns_rdata_t *update_rr, dns_rdata_t *db_rr) {
	if (db_rr->type != update_rr->type)
		return (ISC_FALSE);
	if (db_rr->type == dns_rdatatype_cname)
		return (ISC_TRUE);
	if (db_rr->type == dns_rdatatype_soa)
		return (ISC_TRUE);
	/*
	 * RFC2136 does not mention NXT, but multiple NXTs make little
	 * sense, so we replace those, too.
	 */
	if (db_rr->type == dns_rdatatype_nxt)
		return (ISC_TRUE);
	if (db_rr->type == dns_rdatatype_wks) {
		/*
		 * Compare the address and protocol fields only.  These
		 * form the first five bytes of the RR data.  Do a 
		 * raw binary comparison; unpacking the WKS RRs using
		 * dns_rdata_tostruct() might be cleaner in some ways,
		 * but it would require us to pass around an mctx.
		 */
		INSIST(db_rr->length >= 5 && update_rr->length >= 5);
		return (memcmp(db_rr->data, update_rr->data, 5) == 0 ?
			ISC_TRUE : ISC_FALSE);
	}
	return (ISC_FALSE);
}

/* Internal helper function for delete_if(). */
static dns_result_t 
delete_if_action(void *data, rr_t *rr) {
	conditional_delete_ctx_t *ctx = data;
	if ((*ctx->predicate)(ctx->update_rr, &rr->rdata)) {
		dns_result_t result;
		result = update_one_rr(ctx->db, ctx->ver, ctx->diff,
				       DNS_DIFFOP_DEL, ctx->name,
				       rr->ttl, &rr->rdata);
		return (result);
	} else {
		return (DNS_R_SUCCESS);
	}
}

/*
 * Conditionally delete RRs.  Apply 'predicate' to the RRs
 * specified by 'db', 'ver', 'name', and 'type' (which can
 * be dns_rdatatype_any to match any type).  Delete those
 * RRs for which the predicate returns true, and log the 
 * deletions in 'diff'.
 */
static dns_result_t
delete_if(rr_predicate *predicate,
	  dns_db_t *db,
	  dns_dbversion_t *ver,
	  dns_name_t *name,
	  dns_rdatatype_t type,
	  dns_rdatatype_t covers,
	  dns_rdata_t *update_rr,
	  dns_diff_t *diff)
{
	conditional_delete_ctx_t ctx;
	ctx.predicate = predicate;
	ctx.db = db;
	ctx.ver = ver;
	ctx.diff = diff;
	ctx.name = name;
	ctx.update_rr = update_rr;
	return (foreach_rr(db, ver, name, type, covers,
			   delete_if_action, &ctx));
}

/**************************************************************************/
/*
 * Miscellaneous subroutines.
 */

/*
 * Extract a single update RR from 'section' of dynamic update message
 * 'msg', with consistency checking.
 *
 * Stores the owner name, rdata, and TTL of the update RR at 'name',
 * 'rdata', and 'ttl', respectively.
 */
static void
get_current_rr(dns_message_t *msg, dns_section_t section,
	       dns_rdataclass_t zoneclass,
	       dns_name_t **name, dns_rdata_t *rdata, dns_rdatatype_t *covers,
	       dns_ttl_t *ttl,
	       dns_rdataclass_t *update_class)
{
	dns_rdataset_t *rdataset;
	dns_result_t result;
	dns_message_currentname(msg, section, name);
	rdataset = ISC_LIST_HEAD((*name)->list);
	INSIST(rdataset != NULL);
	INSIST(ISC_LIST_NEXT(rdataset, link) == NULL);
	*covers = rdataset->covers;
	*ttl = rdataset->ttl;
	result = dns_rdataset_first(rdataset);
	INSIST(result == DNS_R_SUCCESS);
	dns_rdataset_current(rdataset, rdata);
	INSIST(dns_rdataset_next(rdataset) == DNS_R_NOMORE);
	*update_class = rdata->rdclass;
	rdata->rdclass = zoneclass;
}

/*
 * Increment the SOA serial number of database 'db', version 'ver'.
 * Replace the SOA record in the database, and log the 
 * change in 'diff'.
 */

	/*
	 * XXXRTH  Failures in this routine will be worth logging, when
	 *         we have a logging system.  Failure to find the zonename
	 *	   or the SOA rdataset warrant at least an UNEXPECTED_ERROR().
	 */

static dns_result_t
increment_soa_serial(dns_db_t *db, dns_dbversion_t *ver,
		     dns_diff_t *diff, isc_mem_t *mctx)
{
	dns_difftuple_t *deltuple = NULL;
	dns_difftuple_t *addtuple = NULL;
	isc_uint32_t serial;
	dns_result_t result;
	
	CHECK(dns_db_createsoatuple(db, ver, mctx, DNS_DIFFOP_DEL, &deltuple));
	CHECK(dns_difftuple_copy(deltuple, &addtuple));
	addtuple->op = DNS_DIFFOP_ADD;

	serial = dns_soa_getserial(&addtuple->rdata);
	
	/* RFC1982 */
	serial = (serial + 1) & 0xFFFFFFFF;
	if (serial == 0) 
		serial = 1;

	dns_soa_setserial(serial, &addtuple->rdata);
	CHECK(do_one_tuple(&addtuple, db, ver, diff));
	CHECK(do_one_tuple(&deltuple, db, ver, diff));
	result = DNS_R_SUCCESS;
	
 failure:
	if (addtuple != NULL)
		dns_difftuple_free(&addtuple);
	if (deltuple != NULL)
		dns_difftuple_free(&deltuple);
	return (result);
}

/*
 * Check that the new SOA record at 'update_rdata' does not
 * illegally cause the SOA serial number to decrease relative to the
 * existing SOA in 'db'.
 *
 * Sets '*changed' to ISC_TRUE if the update changed the serial
 * number, to ISC_FALSE if not.
 *
 * Sets '*ok' to ISC_TRUE if the update is legal, ISC_FALSE if not.
 */
static dns_result_t
check_soa_increment(dns_db_t *db, dns_dbversion_t *ver, 
		    dns_rdata_t *update_rdata,
		    isc_boolean_t *changed, isc_boolean_t *ok)
{
	isc_uint32_t db_serial;
	isc_uint32_t update_serial;
	dns_result_t result;

	update_serial = dns_soa_getserial(update_rdata);
	
	result = dns_db_getsoaserial(db, ver, &db_serial);
	if (result != DNS_R_SUCCESS)
		return (result);

	if (db_serial != update_serial) {
		*changed = ISC_TRUE;
	} else {
		*changed = ISC_FALSE;
	}
	if (DNS_SERIAL_GT(db_serial, update_serial)) {
		*ok = ISC_FALSE;
	} else {
		*ok = ISC_TRUE;
	}

	return (DNS_R_SUCCESS);

}

/**************************************************************************/
/*
 * The actual update code in all its glory.  We try to follow
 * the RFC2136 pseudocode as closely as possible.
 */

static dns_result_t
ns_req_update(ns_client_t *client,
	      dns_message_t *request, dns_message_t **responsep) 
{
	dns_result_t result, render_result;
	dns_name_t *zonename;
	dns_rdataset_t *zone_rdataset;
	dns_db_t *db = NULL;
	dns_dbversion_t *ver = NULL;
	dns_rdataclass_t zoneclass;
	dns_message_t *response = NULL;
	dns_diff_t diff; 	/* Pending updates. */
	dns_diff_t temp; 	/* Pending RR existence assertions. */
	unsigned int response_rcode = dns_rcode_noerror;
	isc_boolean_t soa_serial_changed = ISC_FALSE;
	isc_mem_t *mctx = client->mctx;
	dns_rdatatype_t covers;
	
	dns_diff_init(mctx, &diff);
	dns_diff_init(mctx, &temp);
	
	printf("got update request\n");

	/*
	 * Interpret the zone section.
	 */
	result = dns_message_firstname(request, DNS_SECTION_ZONE);
	if (result != DNS_R_SUCCESS)
		FAILMSG(DNS_R_FORMERR,
			"update zone section empty");

	/*
	 * The zone section must contain exactly one "question", and
	 * it must be of type SOA.
	 */
	zonename = NULL;
	dns_message_currentname(request, DNS_SECTION_ZONE, &zonename);
	zone_rdataset = ISC_LIST_HEAD(zonename->list);
	zoneclass = zone_rdataset->rdclass;
	if (zone_rdataset->type != dns_rdatatype_soa)
		FAILMSG(DNS_R_FORMERR,
			"update zone section contains non-SOA");
	if (ISC_LIST_NEXT(zone_rdataset, link) != NULL)
		FAILMSG(DNS_R_FORMERR,
			"update zone section contains multiple RRs");

	/* The zone section must have exactly one name. */
	result = dns_message_nextname(request, DNS_SECTION_ZONE);
	if (result != DNS_R_NOMORE)
		FAILMSG(DNS_R_FORMERR,
			"update zone section contains multiple RRs");

	/* XXX check that the zone is a master zone,
	   forward request if slave */

	/* XXX we should get a class-specific dbtable from the view */

	result = dns_dbtable_find(client->view->dbtable, zonename, &db);
	if (result != DNS_R_SUCCESS)
		FAILMSG(DNS_R_NOTAUTH,
			"not authoritative for update zone");

	/* XXX this should go away when caches are no longer in the dbtable */
	if (dns_db_iscache(db))
		FAILMSG(DNS_R_NOTAUTH,
			"not authoritative for update zone");
	
	printf("zone section checked out OK\n");

	/* Create a new database version. */

	/* XXX should queue an update event here if someone else
	   has a writable version open */
	   
	CHECK(dns_db_newversion(db, &ver));
	
	printf("new database version created\n");
	
	/* Check prerequisites. */

	for (result = dns_message_firstname(request, DNS_SECTION_PREREQUISITE);
	     result == DNS_R_SUCCESS;
	     result = dns_message_nextname(request, DNS_SECTION_PREREQUISITE))
	{
		dns_name_t *name = NULL;
		dns_rdata_t rdata;
		dns_ttl_t ttl;
		dns_rdataclass_t update_class;
		isc_boolean_t flag;

		get_current_rr(request, DNS_SECTION_PREREQUISITE, zoneclass,
			       &name, &rdata, &covers, &ttl, &update_class);

		if (ttl != 0)
			FAILMSG(DNS_R_FORMERR, "prereq TTL != 0");

		if (! dns_name_issubdomain(name, zonename))
			FAILMSG(DNS_R_NOTZONE,
				"prereq name out of zone");

		if (update_class == dns_rdataclass_any) {
			if (rdata.length != 0)
				FAILMSG(DNS_R_FORMERR,
					"prereq data not empty");
			if (rdata.type == dns_rdatatype_any) {
				CHECK(name_exists(db, ver, name, &flag));
				if (! flag) {
					FAILMSG(DNS_R_NXDOMAIN,
						"'name in use' prereq "
						"not satisfied");
				}
			} else {
				CHECK(rrset_exists(db, ver, name,
						   rdata.type, covers, &flag));
				if (! flag) {
					/* RRset does not exist. */
					FAILMSG(DNS_R_NXRRSET,
					"'rrset exists (value independent)' "
					"prereq not satisfied");
				}
			}
		} else if (update_class == dns_rdataclass_none) {
			if (rdata.length != 0)
				FAILMSG(DNS_R_FORMERR,
					"prereq data not empty");
			if (rdata.type == dns_rdatatype_any) {
				CHECK(name_exists(db, ver, name, &flag));
				if (flag) {
					FAILMSG(DNS_R_YXDOMAIN,
						"'name not in use' prereq "
						"not satisfied");
				}
			} else {
				CHECK(rrset_exists(db, ver, name,
						   rdata.type, covers, &flag));
				if (flag) {
					/* RRset exists. */
					FAILMSG(DNS_R_YXRRSET,
						"'rrset does not exist' "
						"prereq not satisfied");
				}
			} 
		} else if (update_class == zoneclass) {
			/* "temp<rr.name, rr.type> += rr;" */
			result = temp_append(&temp, name, &rdata);
			if (result != DNS_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "temp entry creation failed: %s",
						 dns_result_totext(result));
				FAIL (DNS_R_UNEXPECTED);
			}
		} else {
			FAILMSG(DNS_R_FORMERR, "malformed prereq");
		}
	}
	if (result != DNS_R_NOMORE)
		FAIL(result);

	/*
	 * Perform the final check of the "rrset exists (value dependent)"
	 * prerequisites.
	 */
	result = temp_check(mctx, &temp, db, ver);
	if (result != DNS_R_SUCCESS)
		FAILMSG(result, "'rrset exists (value dependent)' prereq "
			"not satisfied");

	printf("prereqs ok\n");	

	/* XXX Check Requestor's Permissions Here */

	/* Perform the Update Section Prescan. */

	for (result = dns_message_firstname(request, DNS_SECTION_UPDATE);
	     result == DNS_R_SUCCESS;
	     result = dns_message_nextname(request, DNS_SECTION_UPDATE))
	{
		dns_name_t *name = NULL;
		dns_rdata_t rdata;
		dns_ttl_t ttl;
		dns_rdataclass_t update_class;		
		get_current_rr(request, DNS_SECTION_UPDATE, zoneclass,
			       &name, &rdata, &covers, &ttl, &update_class);

		if (! dns_name_issubdomain(name, zonename))
			FAILMSG(DNS_R_NOTZONE,
				"update RR is outside zone");
		if (update_class == zoneclass) {
			/*
			 * Check for meta-RRs.  The RFC2136 pseudocode says
			 * check for ANY|AXFR|MAILA|MAILB, but the text adds
			 * "or any other QUERY metatype"
			 */
			if (dns_rdatatype_ismeta(rdata.type)) {
				FAILMSG(DNS_R_FORMERR,
					"meta-RR in update");
			}
		} else if (update_class == dns_rdataclass_any) {
			if (ttl != 0 || rdata.length != 0 ||
			    (dns_rdatatype_ismeta(rdata.type) &&
			     rdata.type != dns_rdatatype_any))
				FAILMSG(DNS_R_FORMERR, 
					"meta-RR in update");
		} else if (update_class == dns_rdataclass_none) {
			if (ttl != 0 || 
			    dns_rdatatype_ismeta(rdata.type))
				FAILMSG(DNS_R_FORMERR, 
					"meta-RR in update");
		} else {
			printf("update RR has incorrect class %d\n", 
				update_class);
			FAIL(DNS_R_FORMERR);
		}
	}
	if (result != DNS_R_NOMORE)
		FAIL(result);

	printf("prescan ok\n");
	
	/* Process the Update Section. */

	for (result = dns_message_firstname(request, DNS_SECTION_UPDATE);
	     result == DNS_R_SUCCESS;
	     result = dns_message_nextname(request, DNS_SECTION_UPDATE))
	{
		dns_name_t *name = NULL;
		dns_rdata_t rdata;
		dns_ttl_t ttl;
		dns_rdataclass_t update_class;
		isc_boolean_t flag;
		
		get_current_rr(request, DNS_SECTION_UPDATE, zoneclass,
			       &name, &rdata, &covers, &ttl, &update_class);

		if (update_class == zoneclass) {
			if (rdata.type == dns_rdatatype_cname) {
				CHECK(cname_incompatible_rrset_exists(db, ver,
								      name,
								      &flag));
				if (flag) {
					printf("attempt to add cname "
					       "alongside non-cname "
					       "ignored\n");
					continue;
				}
			} else {
				CHECK(rrset_exists(db, ver, name,
						   dns_rdatatype_cname, 0,
						   &flag));
				if (flag && ! is_dnssec_type(rdata.type)) {
					printf("attempt to add non-cname "
					       "alongside cname ignored\n");
					continue;
				}
			}
			if (rdata.type == dns_rdatatype_soa) {
				isc_boolean_t changed, ok;
				CHECK(rrset_exists(db, ver, name, 
						   dns_rdatatype_soa, 0,
						   &flag));
				if (! flag) {
					printf("attempt to create extra SOA "
					       "ignored\n");
					continue;
				}
				CHECK(check_soa_increment(db, ver, &rdata,
							  &changed, &ok));
				if (! ok) {
					printf("attempt to decrement SOA "
					       "serial ignored\n");
					continue;
				}
				if (changed)
					soa_serial_changed = ISC_TRUE;
			}
			/*
			 * Add an RR.  If an identical RR already exists,
			 * do nothing.  If a similar but not identical 
			 * CNAME, SOA, or WKS exists, remove it first.
			 */
			CHECK(matching_rr_exists(rr_equal_p, db, ver, name,
						 rdata.type, covers, &rdata,
						 &flag));
			if (! flag) {
				printf("add an RR\n");
				CHECK(delete_if(replaces_p, db, ver, name,
						rdata.type, covers, &rdata,
						&diff));
				result = update_one_rr(db, ver, &diff,
						       DNS_DIFFOP_ADD,
						       name, ttl, &rdata);
				if (result != DNS_R_SUCCESS)
					FAIL(result);
			} else {
				printf("attempt to add existing RR ignored\n");
			}
		} else if (update_class == dns_rdataclass_any) {
			if (rdata.type == dns_rdatatype_any) {
				printf("delete all rrsets from a name\n");
				if (dns_name_equal(name, zonename)) {
					CHECK(delete_if(type_not_soa_nor_ns_p,
							db, ver, name, 
							dns_rdatatype_any, 0,
							&rdata, &diff));
				} else {
					CHECK(delete_if(true_p, db, ver, name, 
							dns_rdatatype_any, 0,
							&rdata, &diff));
				}
			} else if (dns_name_equal(name, zonename) &&
				   (rdata.type == dns_rdatatype_soa ||
				    rdata.type == dns_rdatatype_ns)) {
				printf("attempt to delete all SOA or NS "
				       "records ignored\n");
				continue;
			} else {
				printf("delete an rrset\n");
				CHECK(delete_if(true_p, db, ver, name,
						rdata.type, covers, &rdata,
						&diff));
			}
		} else if (update_class == dns_rdataclass_none) {
			if (rdata.type == dns_rdatatype_soa) {
				printf("attempt to delete SOA ignored\n");
				continue;
			}
			if (rdata.type == dns_rdatatype_ns) {
				int count;
				CHECK(rr_count(db, ver, name,
					       dns_rdatatype_ns, 0, &count));
				if (count == 1) {
					printf("attempt to delete last "
					       "NS ignored\n");
					continue;
				}
			}
			printf("delete an RR\n");
			CHECK(delete_if(rr_equal_p, db, ver, name,
					rdata.type, covers, &rdata, &diff));
		}
	}
	if (result != DNS_R_NOMORE)
		FAIL(result);

	/*
	 * If any changes were made, increment the SOA serial number
	 * and write the update to the journal.
	 */
	if (! ISC_LIST_EMPTY(diff.tuples)) {
		dns_journal_t *journal;

		/*
		 * Increment the SOA serial, but only if it was not changed as
		 * a result of an update operation.
		 */
		if (! soa_serial_changed) {
			CHECK(increment_soa_serial(db, ver, &diff, mctx));
		}

		printf("write journal\n");

		/* XXX use a real file name */
		journal = NULL;
		result = dns_journal_open(mctx, "journal", ISC_TRUE, &journal);
		if (result != DNS_R_SUCCESS)
			FAILMSG(result, "journal open failed");

		result = dns_journal_write_transaction(journal, &diff);
		if (result != DNS_R_SUCCESS) {
			dns_journal_destroy(&journal);
			FAILMSG(result, "journal write failed");
		}

		dns_journal_destroy(&journal);
	}

	/*
	 * XXXRTH  Just a note that this committing code will have to change
	 *         to handle databases that need two-phase commit, but this
	 *	   isn't a priority.
	 */
	printf("commit\n");
	dns_db_closeversion(db, &ver, ISC_TRUE);
	result = DNS_R_SUCCESS;
	response_rcode = dns_rcode_noerror;
	goto common;
	
 failure:
	printf("update failed: %s\n", dns_result_totext(result));

	if (ver != NULL) {
		printf("rollback\n");	
		dns_db_closeversion(db, &ver, ISC_FALSE);
	}

	response_rcode = dns_result_torcode(result);

 common:
	dns_diff_clear(&temp);
	dns_diff_clear(&diff);

	if (db != NULL)
		dns_db_detach(&db);
	
	/*
	 * Construct the response message.
	 */
	render_result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
					   &response);
	if (render_result != DNS_R_SUCCESS)
		goto render_failure;

	response->id = request->id;
	response->rcode = response_rcode;
	response->flags = request->flags;
	response->flags |= DNS_MESSAGEFLAG_QR;

	*responsep = response;

	goto render_success;
	
 render_failure:
	if (response != NULL)
		dns_message_destroy(&response);

 render_success:
	/*
	 * If we could send a response, we have succeded, even if it
	 * was a failure response.
	 */
	return (render_result);
}

void
ns_update_start(ns_client_t *client) {
	dns_message_t *response = NULL;
	ns_req_update(client, client->message, &response);
	dns_message_destroy(&client->message);
	client->message = response;
	ns_client_send(client);
}
