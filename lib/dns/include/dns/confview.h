/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#ifndef DNS_CONFIG_CONFVIEW_H
#define DNS_CONFIG_CONFVIEW_H 1

/*****
 ***** Module Info
 *****/

/*
 * Zones as seen by the config file parser. The data structures here define 
 * the zone data as it is in the config file. The data structures here do
 * *not* define the things like red-black trees for named's internal data
 * structures.
 *
 */

/*
 *
 * MP:
 *	Client must do necessary locking.
 *      
 * Reliability:
 *
 *	No problems.
 *
 * Resources:
 *
 *	Use memory managers supplied by client.
 *
 * Security:
 *
 *	N/A
 *      
 */

/***
 *** Imports
 ***/

#include <config.h>

#include <isc/mem.h>

/* XXX these next two are needed by rdatatype.h. It should be fixed to
 * include them itself.
 */
#include <isc/buffer.h>
#include <dns/result.h>

#include <dns/rdatatype.h>

#include <dns/confcommon.h>
#include <dns/confip.h>
#include <dns/confkeys.h>
#include <dns/confacl.h>
#include <dns/confip.h>
#include <dns/conflsn.h>
#include <dns/confrrset.h>

#define DNS_C_VIEWTABLE_MAGIC		0x76497774 /* vIwt */
#define DNS_C_VIEW_MAGIC 		0x56696557 /* VieW */

#define DNS_C_VIEWTABLE_VALID(ptr)  ISC_MAGIC_VALID(ptr, DNS_C_VIEWTABLE_MAGIC)
#define DNS_C_VIEW_VALID(ptr)       ISC_MAGIC_VALID(ptr, DNS_C_VIEW_MAGIC)
/***
 *** Types
 ***/

#if 0
/* this typedef moved to confcommon.h for confzone.h to get at (due to
 * circulare include file dependancies).
 */
typedef struct dns_c_view		dns_c_view_t;
#endif
typedef struct dns_c_viewtable		dns_c_viewtable_t;


struct dns_c_viewtable
{
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_view_t)	views;
};


struct dns_c_view
{
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;
	
	char 		       *name;

	dns_c_zonelist_t       *zonelist;

	dns_c_forw_t		forward;
	
	dns_c_ipmatchlist_t    *allowquery;
	dns_c_ipmatchlist_t    *allowupdateforwarding;
	dns_c_ipmatchlist_t    *transferacl;
	dns_c_ipmatchlist_t    *recursionacl;
	dns_c_ipmatchlist_t    *blackhole;
	dns_c_ipmatchlist_t    *sortlist;
	dns_c_ipmatchlist_t    *topology;

	dns_c_iplist_t         *forwarders;

	dns_c_lstnlist_t       *listens;
	
	dns_c_rrsolist_t       *ordering;
	
	dns_severity_t	check_names[DNS_C_TRANSCOUNT];
	
	dns_transfer_format_t	transfer_format;
	
	isc_boolean_t		auth_nx_domain;
	isc_boolean_t		dialup;
	isc_boolean_t		fetch_glue;
	isc_boolean_t		has_old_clients;
	isc_boolean_t		host_statistics;
	isc_boolean_t		maintain_ixfr_base;
	isc_boolean_t		multiple_cnames;
	isc_boolean_t		notify;
	isc_boolean_t		recursion;
	isc_boolean_t		rfc2308_type1;
	isc_boolean_t		use_id_pool;
	isc_boolean_t		fake_iquery;
	isc_boolean_t		use_ixfr;

	isc_int32_t		clean_interval;
	isc_int32_t		lamettl;
	isc_int32_t		max_log_size_ixfr;
	isc_int32_t		max_ncache_ttl;
	isc_int32_t		max_transfer_time_in;
	isc_int32_t		max_transfer_time_out;
	isc_int32_t		max_transfer_idle_in;
	isc_int32_t		max_transfer_idle_out;
	isc_int32_t		stats_interval;
	isc_int32_t		transfers_in;
	isc_int32_t		transfers_out;
	isc_int32_t		transfers_per_ns;

	dns_c_setbits_t		setflags;

	ISC_LINK(dns_c_view_t)	next;
};



/***
 *** Functions
 ***/

isc_result_t dns_c_viewtable_new(isc_mem_t *mem,
				 dns_c_viewtable_t **viewtable);

/*
 * Creates a new viewtable. Returns pointer to the new table through
 * NEWTABLE paramater. The memory is allocated from the MEM memory pool.
 *
 * Requires:
 *	mem is a valid memory pool
 *	newtable is a valid non-NULL pointer.
 *	mem remain a valuid memory pool until the table is destroyed.
 * 	
 * Returns:
 *	ISC_R_SUCCESS		-- all is well.
 *	ISC_R_NOMEMORY		-- not enough memory.
 * 
 */

isc_result_t dns_c_viewtable_delete(dns_c_viewtable_t **viewtable);
/*
 * Destroys the table pointed to by *VIEWTABLE and all the views in it. The
 * value of *VIEWTABLE can be NULL (which is a no-op).
 *
 * Requires:
 *	viewtable is a valid pointer.
 *	The memory pool used at creation time still be valid.
 * 
 * Returns:
 *	ISC_R_SUCCESS
 * 
 */


void dns_c_viewtable_addview(dns_c_viewtable_t *viewtable,
			     dns_c_view_t *view);

/*
 * Inserts the given view into the viewtable. The viewtable takes ownership 
 * of the view's allocations.
 *
 * Requires:
 *	viewtable be a pointer to a valid dns_c_viewtable_t
 *	view be a pointer to a valie dns_c_view_t
 *
 */

void dns_c_viewtable_rmview(dns_c_viewtable_t *viewtable,
			    dns_c_view_t *view);

/*
 * Removes the view from the given table. Does not memory
 * deallocations. Caller owns the view.
 *
 * Requires:
 *	viewtable be a pointer to a valid dns_c_viewtable_t
 *	view be a pointer to a valid dns_c_view_t
 *
 */

isc_result_t dns_c_viewtable_viewbyname(dns_c_viewtable_t *viewtable,
					const char *viewname,
					dns_c_view_t **retval);

/*
 * Looks up a view by name in the given table. The result is returned
 * through the parameter RETVAL. The returned view must not be modified.
 *
 * Requires:
 *	VIEWTABLE be a valid dns_c_viewtable_t
 * 	
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOTFOUND		-- view was not found
 * 
 */

isc_result_t dns_c_viewtable_rmviewbyname(dns_c_viewtable_t *viewtable,
					  const char *name);
/*
 * Removes a view from a view table. The view is looked up by name.
 *
 * Requires:
 *	viewtable be a pointer to a valie dns_viewtable_t
 *	name be a valid pointer to string of positive length.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOTFOUND		-- view was not in the table.
 * 
 */


isc_result_t dns_c_viewtable_clear(dns_c_viewtable_t *viewtable);
/*
 * Removes (and deletes) all the views in the viewtable.
 *
 * Requires:
 *	viewtable to be a pointer to a valid dns_c_viewtable_t
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 */

void dns_c_viewtable_print(FILE *fp, int indent,
			   dns_c_viewtable_t *table);

/*
 * Prints the viewtable TABLE to the stdio stream FP. An INDENT number of
 * tabs is printed at the start of each line.
 *
 * Requires:
 *	FP be a valid stdio stream
 *	table be a pointer to a valid dns_c_viewtable_t
 */


isc_result_t dns_c_view_new(isc_mem_t *mem, const char *name,
			    dns_c_view_t **newview);
/*
 * Creates a new view. The view is placed in the given viewtable.
 * The new view is returned via the newview parameter
 *
 * Requires:
 *	viewtable be a pointer to a valid view table.
 *	name be a pointer to a valid string of positive length
 *	newview be a valid non-NULL pointer.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- out of memory
 * 
 */

isc_result_t dns_c_view_delete(dns_c_view_t **view);
/*
 * Deletes the view and its contents.
 *
 * Requires:
 *	view be a pointer to a valid view.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *  
 */

isc_result_t dns_c_view_addzone(dns_c_view_t *view, dns_c_zone_t *zone);
/*
 * Puts the zone in the view's zonetable. Dosn't alter the 'owner' view of 
 * the zone.
 */

isc_result_t dns_c_view_setallowquery(dns_c_view_t *view,
				      dns_c_ipmatchlist_t *ipml,
				      isc_boolean_t deepcopy);
/*
 * Sets the ipmatch list of the allow-query field to the IPML. If DEEPCOPY
 * is true, then a full copy of IPML is made using the MEM memory pool. In
 * which case the caller still is the owner the memory IPML points to. If
 * DEEPCOPY is false, then the view takes ownership of the memory IPML
 * points to. If the view already has an allow-query list, then it is deleted
 * before the new one is added.
 *
 * Requires:
 *	mem be a pointer to a valid memory manager
 *	ipml be a valid dns_c_ipmatchlist_t
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- memory could not be allocated for the
 *				   deepcopy  .
 * 
 */


isc_result_t dns_c_view_setallowtransfer(dns_c_view_t *view,
					 dns_c_ipmatchlist_t *ipml,
					 isc_boolean_t deepcopy);
isc_result_t dns_c_view_setallowrecursion(dns_c_view_t *view,
					  dns_c_ipmatchlist_t *ipml,
					  isc_boolean_t deepcopy);
isc_result_t dns_c_view_setallowupdateforwarding(dns_c_view_t *view,
						 dns_c_ipmatchlist_t *ipml,
						 isc_boolean_t deepcopy);
isc_result_t dns_c_view_setblackhole(dns_c_view_t *view,
				     dns_c_ipmatchlist_t *ipml,
				     isc_boolean_t deepcopy);
isc_result_t dns_c_view_setforwarders(dns_c_view_t *view,
				      dns_c_iplist_t *ipml,
				      isc_boolean_t deepcopy);
isc_result_t dns_c_view_setsortlist(dns_c_view_t *view,
				    dns_c_ipmatchlist_t *ipml,
				    isc_boolean_t deepcopy);
isc_result_t dns_c_view_settopology(dns_c_view_t *view,
				    dns_c_ipmatchlist_t *ipml,
				    isc_boolean_t deepcopy);
isc_result_t dns_c_view_addlisten_on(dns_c_view_t *view, in_port_t port,
				     dns_c_ipmatchlist_t *ml,
				     isc_boolean_t copy);
isc_result_t dns_c_view_setrrsetorderlist(dns_c_view_t *view,
					  isc_boolean_t copy,
					  dns_c_rrsolist_t *olist);
isc_result_t dns_c_view_setchecknames(dns_c_view_t *view,
				      dns_c_trans_t transtype,
				      dns_severity_t sever);
isc_result_t dns_c_view_settransferformat(dns_c_view_t *view,
					  dns_transfer_format_t format);
					  
/* caller must not modifiy or delete returned values */
isc_result_t dns_c_view_getallowquery(dns_c_view_t *view,
				      dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getallowtransfer(dns_c_view_t *view,
					 dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getallowrecursion(dns_c_view_t *view,
					  dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getallowupdateforwarding(dns_c_view_t *view,
						 dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getblackhole(dns_c_view_t *view,
				     dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getforwarders(dns_c_view_t *view,
				      dns_c_iplist_t **ipml);
isc_result_t dns_c_view_getsortlist(dns_c_view_t *view,
				    dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_gettopology(dns_c_view_t *view,
				    dns_c_ipmatchlist_t **ipml);
isc_result_t dns_c_view_getlistenlist(dns_c_view_t *cfg,
				      dns_c_lstnlist_t **ll);
isc_result_t dns_c_view_getrrsetorderlist(dns_c_view_t *view,
					  dns_c_rrsolist_t **olist);
isc_result_t dns_c_view_getchecknames(dns_c_view_t *view,
				      dns_c_trans_t transtype,
				      dns_severity_t *sever);
isc_result_t dns_c_view_gettransferformat(dns_c_view_t *view,
					  dns_transfer_format_t *format);



isc_result_t dns_c_view_getallowqueryexpanded(isc_mem_t *mem,
					      dns_c_view_t *view,
					      dns_c_acltable_t *acltable,
					      dns_c_ipmatchlist_t **retval);
/*
 * Retuns a copy through the RETVAL parameter (the caller is responsible
 * for deleting the returned value) of the allow-query address-match
 * list. Any references in the list to acls or indirect address-match
 * lists. are recursivly expanded ((using the definitions in ACLTABLE) so
 * that the end result has no references in it. Memory allocation for the
 * copy is done via the memory pool pointed to by the MEM paramater.
 *
 * Requires:
 *	mem be a pointer to a valid memory manager
 *	acl be a pointer to a valid acl.
 *	retval be a valid non-NULL pointer.
 * 
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- not enough memory to make copy.
 *	ISC_R_FAILURE		-- an acl reference couldn't be expanded.
 * 
 */


void dns_c_view_print(FILE *fp, int indent,
		      dns_c_view_t *view);

/*	
 * Prints the view VIEW to the stdio stream FP. An INDENT number of
 * tabs is printed at the start of each line.
 *
 * Requires:
 *	FP be a valid stdio stream
 *	view be a pointer to a valid dns_c_view_t
 */


isc_result_t dns_c_view_getname(dns_c_view_t *view,
				const char **retval);

/*
 * Returns the name of the view. Caller must NOT free or touch the returned 
 * array.
 */


#endif /* DNS_CONFIG_CONFVIEW_H */
