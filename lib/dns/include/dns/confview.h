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

#ifndef DNS_CONFVIEW_H
#define DNS_CONFVIEW_H 1

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

#include <isc/lang.h>
#include <isc/magic.h>

#include <dns/confrrset.h>
#include <dns/confzone.h>

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


struct dns_c_viewtable {
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_view_t)	views;
};

struct dns_c_view {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;
	
	char 		       *name;

	dns_rdataclass_t	viewclass;
	
	dns_c_zonelist_t       *zonelist;

	dns_c_forw_t	       *forward;
	dns_c_iplist_t         *forwarders;

	dns_c_ipmatchlist_t    *allowquery;
	dns_c_ipmatchlist_t    *allowupdateforwarding;
	dns_c_ipmatchlist_t    *transferacl;
	dns_c_ipmatchlist_t    *recursionacl;
	dns_c_ipmatchlist_t    *sortlist;
	dns_c_ipmatchlist_t    *topology;
	dns_c_ipmatchlist_t    *matchclients;

	dns_c_rrsolist_t       *ordering; /* XXX not parsed yet */
	
	dns_severity_t	       *check_names[DNS_C_TRANSCOUNT];
	
	/*
	 * XXX to implement now.
	 */
	isc_boolean_t	       *auth_nx_domain;
	isc_boolean_t	       *recursion;
	isc_boolean_t	       *provide_ixfr;
	isc_boolean_t	       *request_ixfr;
	isc_boolean_t	       *fetch_glue;
	isc_boolean_t	       *notify;
	isc_boolean_t	       *rfc2308_type1;

	isc_sockaddr_t	       *query_source;
	isc_sockaddr_t	       *query_source_v6;
	isc_sockaddr_t	       *transfer_source;
	isc_sockaddr_t	       *transfer_source_v6;

	isc_int32_t	       *max_transfer_time_out;
	isc_int32_t	       *max_transfer_idle_out;
	isc_int32_t	       *clean_interval;
	isc_int32_t	       *min_roots;
	isc_int32_t	       *lamettl;
	isc_int32_t	       *max_ncache_ttl;
	isc_int32_t	       *max_cache_ttl;

	dns_c_addata_t	       *additional_data;
	dns_transfer_format_t  *transfer_format;

	dns_c_kdeflist_t       *keydefs;
	dns_peerlist_t	       *peerlist;

#if 0	
	/*
	 * To implement later.
	 */
	isc_int32_t	       *max_transfer_time_in;
	isc_int32_t	       *max_transfer_idle_in;
	isc_int32_t	       *transfers_per_ns;
	isc_int32_t	       *serial_queries;

#endif

	ISC_LINK(dns_c_view_t)	next;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_viewtable_new(isc_mem_t *mem, dns_c_viewtable_t **viewtable);

isc_result_t
dns_c_viewtable_delete(dns_c_viewtable_t **viewtable);

void
dns_c_viewtable_print(FILE *fp, int indent, dns_c_viewtable_t *table);

void
dns_c_viewtable_addview(dns_c_viewtable_t *viewtable, dns_c_view_t *view);

void
dns_c_viewtable_rmview(dns_c_viewtable_t *viewtable, dns_c_view_t *view);

isc_result_t
dns_c_viewtable_clear(dns_c_viewtable_t *table);

isc_result_t
dns_c_viewtable_viewbyname(dns_c_viewtable_t *viewtable, const char *viewname,
			   dns_c_view_t **retval);

isc_result_t
dns_c_viewtable_rmviewbyname(dns_c_viewtable_t *viewtable, const char *name);

isc_result_t
dns_c_viewtable_checkviews(dns_c_viewtable_t *viewtable);

/* NOTE: For the various get* functions. The caller must not delete the
 * returned value.
 *
 *	- For functions where retval is a dns_c_ipmatchlist_t
 *	  (e.g. dns_c_view_getallowquery) the caller must call
 *	  dns_c_ipmatcglist_detach() when finished with retval).
 *
 */

isc_result_t
dns_c_view_new(isc_mem_t *mem, const char *name, dns_rdataclass_t viewclass,
	       dns_c_view_t **newview);

isc_result_t
dns_c_view_delete(dns_c_view_t **viewptr);

void
dns_c_view_print(FILE *fp, int indent, dns_c_view_t *view);

isc_boolean_t
dns_c_view_keydefinedp(dns_c_view_t *view, const char *keyname);

isc_result_t
dns_c_view_getname(dns_c_view_t *view, const char **retval);

isc_result_t
dns_c_view_addzone(dns_c_view_t *view, dns_c_zone_t *zone);

isc_result_t
dns_c_view_getzonelist(dns_c_view_t *view, dns_c_zonelist_t **zonelist);

isc_result_t
dns_c_view_unsetzonelist(dns_c_view_t *view);

isc_result_t
dns_c_view_getviewclass(dns_c_view_t *view, dns_rdataclass_t *retval);

isc_result_t
dns_c_view_getforward(dns_c_view_t *view, dns_c_forw_t *retval);

isc_result_t
dns_c_view_setforward(dns_c_view_t *view, dns_c_forw_t newval);

isc_result_t
dns_c_view_unsetforward(dns_c_view_t *view);

isc_result_t
dns_c_view_setforwarders(dns_c_view_t *view, dns_c_iplist_t *ipl,
			 isc_boolean_t deepcopy);

isc_result_t
dns_c_view_unsetforwarders(dns_c_view_t *view);

isc_result_t
dns_c_view_getforwarders(dns_c_view_t *view, dns_c_iplist_t **ipl);

isc_result_t
dns_c_view_getallowquery(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_setallowquery(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsetallowquery(dns_c_view_t *view);

isc_result_t
dns_c_view_getallowupdateforwarding(dns_c_view_t *view,
				    dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_setallowupdateforwarding(dns_c_view_t *view,
				    dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsetallowupdateforwarding(dns_c_view_t *view);

isc_result_t
dns_c_view_gettransferacl(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_settransferacl(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsettransferacl(dns_c_view_t *view);

isc_result_t
dns_c_view_getrecursionacl(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_setrecursionacl(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsetrecursionacl(dns_c_view_t *view);

isc_result_t
dns_c_view_getsortlist(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_setsortlist(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsetsortlist(dns_c_view_t *view);

isc_result_t
dns_c_view_gettopology(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_settopology(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsettopology(dns_c_view_t *view);

isc_result_t
dns_c_view_getmatchclients(dns_c_view_t *view, dns_c_ipmatchlist_t **retval);

isc_result_t
dns_c_view_setmatchclients(dns_c_view_t *view, dns_c_ipmatchlist_t *newval);

isc_result_t
dns_c_view_unsetmatchclients(dns_c_view_t *view);

isc_result_t
dns_c_view_getordering(dns_c_view_t *view, dns_c_rrsolist_t **olist);

isc_result_t
dns_c_view_setordering(dns_c_view_t *view, isc_boolean_t copy,
		       dns_c_rrsolist_t *olist);

isc_result_t
dns_c_view_unsetordering(dns_c_view_t *view);

isc_result_t
dns_c_view_setchecknames(dns_c_view_t *view, dns_c_trans_t transtype,
			 dns_severity_t newval);

isc_result_t
dns_c_view_getchecknames(dns_c_view_t *view, dns_c_trans_t transtype,
			 dns_severity_t *retval);

isc_result_t
dns_c_view_unsetchecknames(dns_c_view_t *view, dns_c_trans_t transtype);

isc_result_t
dns_c_view_getauthnxdomain(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setauthnxdomain(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetauthnxdomain(dns_c_view_t *view);

isc_result_t
dns_c_view_getrecursion(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setrecursion(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetrecursion(dns_c_view_t *view);

isc_result_t
dns_c_view_getprovideixfr(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setprovideixfr(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetprovideixfr(dns_c_view_t *view);

isc_result_t
dns_c_view_getrequestixfr(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setrequestixfr(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetrequestixfr(dns_c_view_t *view);

isc_result_t
dns_c_view_getfetchglue(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setfetchglue(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetfetchglue(dns_c_view_t *view);

isc_result_t
dns_c_view_getnotify(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setnotify(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetnotify(dns_c_view_t *view);

isc_result_t
dns_c_view_getrfc2308type1(dns_c_view_t *view, isc_boolean_t *retval);

isc_result_t
dns_c_view_setrfc2308type1(dns_c_view_t *view, isc_boolean_t newval);

isc_result_t
dns_c_view_unsetrfc2308type1(dns_c_view_t *view);

isc_result_t
dns_c_view_settransfersource(dns_c_view_t *view,
			     isc_sockaddr_t transfer_source);

isc_result_t
dns_c_view_gettransfersource(dns_c_view_t *view,
			     isc_sockaddr_t *transfer_source);

isc_result_t
dns_c_view_unsettransfersource(dns_c_view_t *view);

isc_result_t
dns_c_view_settransfersourcev6(dns_c_view_t *view,
			       isc_sockaddr_t transfer_source_v6);

isc_result_t
dns_c_view_gettransfersourcev6(dns_c_view_t *view,
			       isc_sockaddr_t *transfer_source_v6);

isc_result_t
dns_c_view_unsettransfersourcev6(dns_c_view_t *view);

isc_result_t
dns_c_view_setquerysource(dns_c_view_t *view, isc_sockaddr_t query_source);

isc_result_t
dns_c_view_getquerysource(dns_c_view_t *view, isc_sockaddr_t *query_source);

isc_result_t
dns_c_view_unsetquerysource(dns_c_view_t *view);

isc_result_t
dns_c_view_setquerysourcev6(dns_c_view_t *view,
			    isc_sockaddr_t query_source_v6);

isc_result_t
dns_c_view_getquerysourcev6(dns_c_view_t *view,
			    isc_sockaddr_t *query_source_v6);

isc_result_t
dns_c_view_unsetquerysourcev6(dns_c_view_t *view);

isc_result_t
dns_c_view_getmaxtransferidleout(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxtransferidleout(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxtransferidleout(dns_c_view_t *view);

isc_result_t
dns_c_view_getmaxtransfertimeout(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxtransfertimeout(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxtransfertimeout(dns_c_view_t *view);

isc_result_t
dns_c_view_getcleaninterval(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setcleaninterval(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetcleaninterval(dns_c_view_t *view);

isc_result_t
dns_c_view_getminroots(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setminroots(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetminroots(dns_c_view_t *view);

isc_result_t
dns_c_view_getlamettl(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setlamettl(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetlamettl(dns_c_view_t *view);


isc_result_t
dns_c_view_getmaxncachettl(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxncachettl(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxncachettl(dns_c_view_t *view);


isc_result_t
dns_c_view_getmaxcachettl(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxcachettl(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxcachettl(dns_c_view_t *view);



isc_result_t
dns_c_view_setadditionaldata(dns_c_view_t *view, dns_c_addata_t newval);

isc_result_t
dns_c_view_getadditionaldata(dns_c_view_t *view, dns_c_addata_t *retval);

isc_result_t
dns_c_view_unsetadditionaldata(dns_c_view_t *cfg);



isc_result_t
dns_c_view_settransferformat(dns_c_view_t *view,
			     dns_transfer_format_t tformat);

isc_result_t
dns_c_view_gettransferformat(dns_c_view_t *view,
			     dns_transfer_format_t *tformat);

isc_result_t
dns_c_view_unsettransferformat(dns_c_view_t *cfg);

/*
 * Caller must not delete retval.
 */
isc_result_t
dns_c_view_getkeydefs(dns_c_view_t *view, dns_c_kdeflist_t **retval);

isc_result_t
dns_c_view_setkeydefs(dns_c_view_t *view, dns_c_kdeflist_t *newval);

isc_result_t
dns_c_view_unsetkeydefs(dns_c_view_t *view);

/*
 * Detach when done with retval.
 */
isc_result_t
dns_c_view_getpeerlist(dns_c_view_t *cfg, dns_peerlist_t **retval);

/*
 * cfg will attach to newval.
 */
isc_result_t
dns_c_view_setpeerlist(dns_c_view_t *cfg, dns_peerlist_t *newval);

isc_result_t
dns_c_view_unsetpeerlist(dns_c_view_t *cfg);

#if 0

/*
 * XXX waiting to server to implement these items before enabling them
 */

isc_result_t
dns_c_view_getmaxtransfertimein(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxtransfertimein(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxtransfertimein(dns_c_view_t *view);

isc_result_t
dns_c_view_getmaxtransferidlein(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setmaxtransferidlein(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetmaxtransferidlein(dns_c_view_t *view);

isc_result_t
dns_c_view_gettransfersperns(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_settransfersperns(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsettransfersperns(dns_c_view_t *view);

isc_result_t
dns_c_view_getserialqueries(dns_c_view_t *view, isc_int32_t *retval);

isc_result_t
dns_c_view_setserialqueries(dns_c_view_t *view, isc_int32_t newval);

isc_result_t
dns_c_view_unsetserialqueries(dns_c_view_t *view);

#endif

ISC_LANG_ENDDECLS

#endif /* DNS_CONFVIEW_H */
