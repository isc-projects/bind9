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

	dns_c_forw_t	       *forward;
	dns_c_iplist_t         *forwarders;

	dns_c_ipmatchlist_t    *allowquery;
	dns_c_ipmatchlist_t    *allowupdateforwarding;
	dns_c_ipmatchlist_t    *transferacl;
	dns_c_ipmatchlist_t    *recursionacl;
	dns_c_ipmatchlist_t    *blackhole;
	dns_c_ipmatchlist_t    *sortlist;
	dns_c_ipmatchlist_t    *topology;
	dns_c_ipmatchlist_t    *matchclients;

	dns_c_rrsolist_t       *ordering;
	
	dns_severity_t	       *check_names[DNS_C_TRANSCOUNT];
	
	/*
	 * These following boolean and int32 variables are not yet handled
	 * by the parser.
	 */
	isc_boolean_t	       *auth_nx_domain;
	isc_boolean_t	       *dialup;
	isc_boolean_t	       *fetch_glue;
	isc_boolean_t	       *has_old_clients;
	isc_boolean_t	       *host_statistics;
	isc_boolean_t	       *multiple_cnames;
	isc_boolean_t	       *notify;
	isc_boolean_t	       *recursion;
	isc_boolean_t	       *rfc2308_type1;
	isc_boolean_t	       *use_id_pool;
	isc_boolean_t	       *fake_iquery;
	isc_boolean_t	       *use_ixfr;
	isc_boolean_t	       *provide_ixfr;
	isc_boolean_t	       *request_ixfr;

	isc_int32_t	       *clean_interval;
	isc_int32_t	       *lamettl;
	isc_int32_t	       *max_log_size_ixfr;
	isc_int32_t	       *max_ncache_ttl;
	isc_int32_t	       *max_transfer_time_in;
	isc_int32_t	       *max_transfer_time_out;
	isc_int32_t	       *max_transfer_idle_in;
	isc_int32_t	       *max_transfer_idle_out;
	isc_int32_t	       *stats_interval;
	isc_int32_t	       *transfers_in;
	isc_int32_t	       *transfers_out;
	isc_int32_t	       *transfers_per_ns;

	ISC_LINK(dns_c_view_t)	next;
};



/***
 *** Functions
 ***/

isc_result_t	dns_c_viewtable_new(isc_mem_t *mem,
				    dns_c_viewtable_t **viewtable);
isc_result_t	dns_c_viewtable_delete(dns_c_viewtable_t **viewtable);
void		dns_c_viewtable_print(FILE *fp, int indent,
				      dns_c_viewtable_t *table);
void		dns_c_viewtable_addview(dns_c_viewtable_t *viewtable,
					dns_c_view_t *view);
void		dns_c_viewtable_rmview(dns_c_viewtable_t *viewtable,
				       dns_c_view_t *view);
isc_result_t	dns_c_viewtable_clear(dns_c_viewtable_t *table);
isc_result_t	dns_c_viewtable_viewbyname(dns_c_viewtable_t *viewtable,
					   const char *viewname,
					   dns_c_view_t **retval);
isc_result_t	dns_c_viewtable_rmviewbyname(dns_c_viewtable_t *viewtable,
					     const char *name);




isc_result_t	dns_c_view_new(isc_mem_t *mem,
			       const char *name, dns_c_view_t **newview);
isc_result_t	dns_c_view_delete(dns_c_view_t **viewptr);
void		dns_c_view_print(FILE *fp, int indent, dns_c_view_t *view);

isc_result_t	dns_c_view_getname(dns_c_view_t *view,
				   const char **retval);
isc_result_t	dns_c_view_addzone(dns_c_view_t *view, dns_c_zone_t *zone);

isc_result_t	dns_c_view_getzonelist(dns_c_view_t *view,
				       dns_c_zonelist_t **zonelist);
isc_result_t	dns_c_view_unsetzonelist(dns_c_view_t *view);


isc_result_t	dns_c_view_getforward(dns_c_view_t *view,
				     dns_c_forw_t *retval);
isc_result_t	dns_c_view_setforward(dns_c_view_t *view,
				     dns_c_forw_t newval);
isc_result_t	dns_c_view_unsetforward(dns_c_view_t *view);

isc_result_t	dns_c_view_setforwarders(dns_c_view_t *view,
					 dns_c_iplist_t *ipl,
					 isc_boolean_t deepcopy);
isc_result_t	dns_c_view_unsetforwarders(dns_c_view_t *view);
isc_result_t	dns_c_view_getforwarders(dns_c_view_t *view,
					 dns_c_iplist_t **ipl);


isc_result_t	dns_c_view_getordering(dns_c_view_t *view,
				       dns_c_rrsolist_t **olist);
isc_result_t	dns_c_view_setordering(dns_c_view_t *view,
				       isc_boolean_t copy,
				       dns_c_rrsolist_t *olist);
isc_result_t	dns_c_view_unsetordering(dns_c_view_t *view,
					 dns_c_rrsolist_t **olist);


isc_result_t	dns_c_view_setchecknames(dns_c_view_t *view,
					 dns_c_trans_t transtype,
					 dns_severity_t newval);
isc_result_t	dns_c_view_getchecknames(dns_c_view_t *view,
					 dns_c_trans_t transtype,
					 dns_severity_t *retval);
isc_result_t	dns_c_view_unsetchecknames(dns_c_view_t *view,
					   dns_c_trans_t transtype);



isc_result_t	dns_c_view_getallowquery(dns_c_view_t *view,
					 dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setallowquery(dns_c_view_t *view,
					 dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetallowquery(dns_c_view_t *view);



isc_result_t	dns_c_view_getallowupdateforwarding(dns_c_view_t *view,
						   dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setallowupdateforwarding(dns_c_view_t *view,
						    dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetallowupdateforwarding(dns_c_view_t *view);


isc_result_t	dns_c_view_getblackhole(dns_c_view_t *view,
					dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setblackhole(dns_c_view_t *view,
					dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetblackhole(dns_c_view_t *view);


isc_result_t	dns_c_view_getrecursionacl(dns_c_view_t *view,
					   dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setrecursionacl(dns_c_view_t *view,
					   dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetrecursionacl(dns_c_view_t *view);


isc_result_t	dns_c_view_getsortlist(dns_c_view_t *view,
				       dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setsortlist(dns_c_view_t *view,
				       dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetsortlist(dns_c_view_t *view);


isc_result_t	dns_c_view_gettopology(dns_c_view_t *view,
				       dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_settopology(dns_c_view_t *view,
				       dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsettopology(dns_c_view_t *view);


isc_result_t	dns_c_view_getmatchclients(dns_c_view_t *view,
				       dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_setmatchclients(dns_c_view_t *view,
				       dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsetmatchclients(dns_c_view_t *view);


isc_result_t	dns_c_view_gettransferacl(dns_c_view_t *view,
					  dns_c_ipmatchlist_t **rval);
isc_result_t	dns_c_view_settransferacl(dns_c_view_t *view,
					  dns_c_ipmatchlist_t *newval);
isc_result_t	dns_c_view_unsettransferacl(dns_c_view_t *view);


isc_result_t	dns_c_view_getauthnxdomain(dns_c_view_t *view,
					   isc_boolean_t *retval);
isc_result_t	dns_c_view_setauthnxdomain(dns_c_view_t *view,
					   isc_boolean_t newval);
isc_result_t	dns_c_view_unsetauthnxdomain(dns_c_view_t *view);


isc_result_t	dns_c_view_getdialup(dns_c_view_t *view,
				     isc_boolean_t *retval);
isc_result_t	dns_c_view_setdialup(dns_c_view_t *view,
				     isc_boolean_t newval);
isc_result_t	dns_c_view_unsetdialup(dns_c_view_t *view);


isc_result_t	dns_c_view_getfakeiquery(dns_c_view_t *view,
					 isc_boolean_t *retval);
isc_result_t	dns_c_view_setfakeiquery(dns_c_view_t *view,
					 isc_boolean_t newval);
isc_result_t	dns_c_view_unsetfakeiquery(dns_c_view_t *view);


isc_result_t	dns_c_view_getfetchglue(dns_c_view_t *view,
					isc_boolean_t *retval);
isc_result_t	dns_c_view_setfetchglue(dns_c_view_t *view,
					isc_boolean_t newval);
isc_result_t	dns_c_view_unsetfetchglue(dns_c_view_t *view);


isc_result_t	dns_c_view_gethasoldclients(dns_c_view_t *view,
					    isc_boolean_t *retval);
isc_result_t	dns_c_view_sethasoldclients(dns_c_view_t *view,
					    isc_boolean_t newval);
isc_result_t	dns_c_view_unsethasoldclients(dns_c_view_t *view);


isc_result_t	dns_c_view_gethoststatistics(dns_c_view_t *view,
					     isc_boolean_t *retval);
isc_result_t	dns_c_view_sethoststatistics(dns_c_view_t *view,
					     isc_boolean_t newval);
isc_result_t	dns_c_view_unsethoststatistics(dns_c_view_t *view);


isc_result_t	dns_c_view_getmultiplecnames(dns_c_view_t *view,
					     isc_boolean_t *retval);
isc_result_t	dns_c_view_setmultiplecnames(dns_c_view_t *view,
					     isc_boolean_t newval);
isc_result_t	dns_c_view_unsetmultiplecnames(dns_c_view_t *view);


isc_result_t	dns_c_view_getnotify(dns_c_view_t *view,
				     isc_boolean_t *retval);
isc_result_t	dns_c_view_setnotify(dns_c_view_t *view,
				     isc_boolean_t newval);
isc_result_t	dns_c_view_unsetnotify(dns_c_view_t *view);


isc_result_t	dns_c_view_getprovideixfr(dns_c_view_t *view,
					  isc_boolean_t *retval);
isc_result_t	dns_c_view_setprovideixfr(dns_c_view_t *view,
					  isc_boolean_t newval);
isc_result_t	dns_c_view_unsetprovideixfr(dns_c_view_t *view);


isc_result_t	dns_c_view_getrecursion(dns_c_view_t *view,
					isc_boolean_t *retval);
isc_result_t	dns_c_view_setrecursion(dns_c_view_t *view,
					isc_boolean_t newval);
isc_result_t	dns_c_view_unsetrecursion(dns_c_view_t *view);


isc_result_t	dns_c_view_getrequestixfr(dns_c_view_t *view,
					  isc_boolean_t *retval);
isc_result_t	dns_c_view_setrequestixfr(dns_c_view_t *view,
					  isc_boolean_t newval);
isc_result_t	dns_c_view_unsetrequestixfr(dns_c_view_t *view);


isc_result_t	dns_c_view_getrfc2308type1(dns_c_view_t *view,
					   isc_boolean_t *retval);
isc_result_t	dns_c_view_setrfc2308type1(dns_c_view_t *view,
					   isc_boolean_t newval);
isc_result_t	dns_c_view_unsetrfc2308type1(dns_c_view_t *view);


isc_result_t	dns_c_view_getuseidpool(dns_c_view_t *view,
					isc_boolean_t *retval);
isc_result_t	dns_c_view_setuseidpool(dns_c_view_t *view,
					isc_boolean_t newval);
isc_result_t	dns_c_view_unsetuseidpool(dns_c_view_t *view);


isc_result_t	dns_c_view_getuseixfr(dns_c_view_t *view,
				      isc_boolean_t *retval);
isc_result_t	dns_c_view_setuseixfr(dns_c_view_t *view,
				      isc_boolean_t newval);
isc_result_t	dns_c_view_unsetuseixfr(dns_c_view_t *view);


isc_result_t	dns_c_view_getcleaninterval(dns_c_view_t *view,
					    isc_int32_t *retval);
isc_result_t	dns_c_view_setcleaninterval(dns_c_view_t *view,
					    isc_int32_t newval);
isc_result_t	dns_c_view_unsetcleaninterval(dns_c_view_t *view);


isc_result_t	dns_c_view_getlamettl(dns_c_view_t *view,
				      isc_int32_t *retval);
isc_result_t	dns_c_view_setlamettl(dns_c_view_t *view,
				      isc_int32_t newval);
isc_result_t	dns_c_view_unsetlamettl(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxlogsizeixfr(dns_c_view_t *view,
					     isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxlogsizeixfr(dns_c_view_t *view,
					     isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxlogsizeixfr(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxncachettl(dns_c_view_t *view,
					   isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxncachettl(dns_c_view_t *view,
					   isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxncachettl(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxtransferidlein(dns_c_view_t *view,
						isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxtransferidlein(dns_c_view_t *view,
						isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxtransferidlein(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxtransferidleout(dns_c_view_t *view,
						 isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxtransferidleout(dns_c_view_t *view,
						 isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxtransferidleout(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxtransfertimein(dns_c_view_t *view,
						isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxtransfertimein(dns_c_view_t *view,
						isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxtransfertimein(dns_c_view_t *view);


isc_result_t	dns_c_view_getmaxtransfertimeout(dns_c_view_t *view,
						 isc_int32_t *retval);
isc_result_t	dns_c_view_setmaxtransfertimeout(dns_c_view_t *view,
						 isc_int32_t newval);
isc_result_t	dns_c_view_unsetmaxtransfertimeout(dns_c_view_t *view);


isc_result_t	dns_c_view_getstatsinterval(dns_c_view_t *view,
					    isc_int32_t *retval);
isc_result_t	dns_c_view_setstatsinterval(dns_c_view_t *view,
					    isc_int32_t newval);
isc_result_t	dns_c_view_unsetstatsinterval(dns_c_view_t *view);


isc_result_t	dns_c_view_gettransfersin(dns_c_view_t *view,
					  isc_int32_t *retval);
isc_result_t	dns_c_view_settransfersin(dns_c_view_t *view,
					  isc_int32_t newval);
isc_result_t	dns_c_view_unsettransfersin(dns_c_view_t *view);


isc_result_t	dns_c_view_gettransfersout(dns_c_view_t *view,
					   isc_int32_t *retval);
isc_result_t	dns_c_view_settransfersout(dns_c_view_t *view,
					   isc_int32_t newval);
isc_result_t	dns_c_view_unsettransfersout(dns_c_view_t *view);


isc_result_t	dns_c_view_gettransfersperns(dns_c_view_t *view,
					     isc_int32_t *retval);
isc_result_t	dns_c_view_settransfersperns(dns_c_view_t *view,
					     isc_int32_t newval);
isc_result_t	dns_c_view_unsettransfersperns(dns_c_view_t *view);






#endif /* DNS_CONFIG_CONFVIEW_H */
