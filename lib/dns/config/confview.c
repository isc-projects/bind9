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

/* $Id: confview.c,v 1.17 2000/04/05 15:18:42 brister Exp $ */

#include <config.h>

#include <sys/types.h>

#include <isc/assertions.h>
#include <isc/magic.h>
#include <isc/net.h>

#include <dns/confacl.h>
#include <dns/confzone.h>
#include <dns/confcommon.h>
#include <dns/confview.h>
#include <dns/confzone.h>
#include <dns/log.h>

#include "confpvt.h"



/*
** Due to the repetive nature of the fields in a view
** we have here a collection of macros to used in defining
** accessor/modifier functions for most of the fields in a view.
** Three functions are created: set, get and unset.
**
** In all the macros FUNC is a character sequence that is used in
** constructing the final function name. FIELD is the field in the view.
 */

#define SETBOOL(FUNC, FIELD) SETBYTYPE(isc_boolean_t, FUNC, FIELD)
#define GETBOOL(FUNC, FIELD) GETBYTYPE(isc_boolean_t, FUNC, FIELD)
#define UNSETBOOL(FUNC, FIELD) UNSETBYTYPE(isc_boolean_t, FUNC, FIELD)

#define SETINT32(FUNC, FIELD) SETBYTYPE(isc_int32_t, FUNC, FIELD)
#define GETINT32(FUNC, FIELD) GETBYTYPE(isc_int32_t, FUNC, FIELD)
#define UNSETINT32(FUNC, FIELD) UNSETBYTYPE(isc_int32_t, FUNC, FIELD)


#ifdef PVT_CONCAT
#undef PVT_CONCAT
#endif

#define PVT_CONCAT(x,y) x ## y


/*
** The SET, GET and UNSETBYTYPE macros are all used whene the field in the
** view is a pointer to a fundamental type that requires no special copying,
** such as integers or booleans.
*/

#define SETBYTYPE(TYPE, FUNCNAME, FIELDNAME)				    \
isc_result_t								    \
PVT_CONCAT(dns_c_view_set, FUNCNAME)(dns_c_view_t *view, TYPE newval)	    \
{									    \
	isc_boolean_t existed = ISC_FALSE;				    \
									    \
	REQUIRE(DNS_C_VIEW_VALID(view));				    \
									    \
	if (view->FIELDNAME == NULL) {					    \
		view->FIELDNAME = isc_mem_get(view->mem, sizeof (TYPE)); \
		if (view->FIELDNAME == NULL) {				    \
			return (ISC_R_NOMEMORY);			    \
		}							    \
	} else {							    \
		existed = ISC_TRUE;					    \
	}								    \
									    \
	*view->FIELDNAME = newval;					    \
									    \
	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);		    \
}

#define GETBYTYPE(TYPE, FUNCNAME, FIELDNAME)				\
isc_result_t								\
PVT_CONCAT(dns_c_view_get, FUNCNAME)(dns_c_view_t *view, TYPE *retval)	\
{									\
	REQUIRE(DNS_C_VIEW_VALID(view));				\
	REQUIRE(retval != NULL);					\
									\
	if (view->FIELDNAME == NULL) {					\
		return (ISC_R_NOTFOUND);				\
	} else {							\
		*retval = *view->FIELDNAME;				\
		return (ISC_R_SUCCESS);					\
	}								\
}

#define UNSETBYTYPE(TYPE, FUNCNAME, FIELDNAME)			\
isc_result_t							\
PVT_CONCAT(dns_c_view_unset, FUNCNAME)(dns_c_view_t *view)	\
{								\
	REQUIRE(DNS_C_VIEW_VALID(view));			\
								\
	if (view->FIELDNAME == NULL) {				\
		return (ISC_R_NOTFOUND);			\
	} else {						\
		isc_mem_put(view->mem, view->FIELDNAME,		\
			    sizeof (view->FIELDNAME));		\
		view->FIELDNAME = NULL;				\
								\
		return (ISC_R_SUCCESS);				\
	}							\
}



/*
** Now SET, GET and UNSET for dns_c_ipmatchlist_t fields
*/

#define SETIPMLIST(FUNCNAME, FIELDNAME)					\
isc_result_t								\
PVT_CONCAT(dns_c_view_set, FUNCNAME)(dns_c_view_t *view,		\
				     dns_c_ipmatchlist_t *newval)	\
{									\
	REQUIRE(DNS_C_VIEW_VALID(view));				\
	REQUIRE(DNS_C_IPMLIST_VALID(newval));				\
									\
	if (view->FIELDNAME != NULL) {					\
		dns_c_ipmatchlist_detach(&view->FIELDNAME);		\
	}								\
									\
	dns_c_ipmatchlist_attach(newval, &view->FIELDNAME);		\
	return (ISC_R_SUCCESS);						\
}



#define UNSETIPMLIST(FUNCNAME, FIELDNAME)			\
isc_result_t							\
PVT_CONCAT(dns_c_view_unset, FUNCNAME)(dns_c_view_t *view)	\
{								\
	REQUIRE(DNS_C_VIEW_VALID(view));			\
								\
	if (view->FIELDNAME != NULL) {				\
		dns_c_ipmatchlist_detach(&view->FIELDNAME);	\
		return (ISC_R_SUCCESS);				\
	} else {						\
		return (ISC_R_NOTFOUND);			\
	}							\
}
	

#define GETIPMLIST(FUNCNAME, FIELDNAME)					\
isc_result_t								\
PVT_CONCAT(dns_c_view_get, FUNCNAME)(dns_c_view_t *view,		\
				     dns_c_ipmatchlist_t **retval)	\
{									\
	REQUIRE(DNS_C_VIEW_VALID(view));				\
	REQUIRE(retval != NULL);					\
									\
	*retval = NULL;							\
									\
	if (view->FIELDNAME != NULL) {					\
		dns_c_ipmatchlist_attach(view->FIELDNAME, retval);	\
		return (ISC_R_SUCCESS);					\
	} else {							\
		return (ISC_R_NOTFOUND);				\
	}								\
}
	





isc_result_t
dns_c_viewtable_new(isc_mem_t *mem, dns_c_viewtable_t **viewtable)
{
	dns_c_viewtable_t *table;
	
	REQUIRE(viewtable != NULL);

	table = isc_mem_get(mem, sizeof *table);
	if (table == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Out of memory");
		return (ISC_R_NOMEMORY);
	}

	table->magic = DNS_C_VIEWTABLE_MAGIC;
	table->mem = mem;

	ISC_LIST_INIT(table->views);

	*viewtable = table;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_viewtable_delete(dns_c_viewtable_t **viewtable)
{
	dns_c_viewtable_t *table;
	
	REQUIRE(viewtable != NULL);
	REQUIRE(DNS_C_VIEWTABLE_VALID(*viewtable));

	table = *viewtable;
	*viewtable = NULL;
	
	dns_c_viewtable_clear(table);

	table->magic = 0;
	isc_mem_put(table->mem, table, sizeof *table);

	return (ISC_R_SUCCESS);
}



void
dns_c_viewtable_print(FILE *fp, int indent,
		      dns_c_viewtable_t *table)
{
	dns_c_view_t *view;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);
	REQUIRE(DNS_C_VIEWTABLE_VALID(table));

	view = ISC_LIST_HEAD(table->views);
	while (view != NULL) {
		dns_c_view_print(fp, indent, view);
		fprintf(fp, "\n");

		view  = ISC_LIST_NEXT(view, next);
	}
}


void
dns_c_viewtable_addview(dns_c_viewtable_t *viewtable, dns_c_view_t *view)
{
	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	REQUIRE(DNS_C_VIEW_VALID(view));
	
	ISC_LIST_APPEND(viewtable->views, view, next);
}



void
dns_c_viewtable_rmview(dns_c_viewtable_t *viewtable, dns_c_view_t *view)
{
	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	REQUIRE(DNS_C_VIEW_VALID(view));
	
	ISC_LIST_UNLINK(viewtable->views, view, next);
}



isc_result_t
dns_c_viewtable_clear(dns_c_viewtable_t *table)
{
	dns_c_view_t *elem;
	dns_c_view_t *tmpelem;
	isc_result_t r;
	
	REQUIRE(DNS_C_VIEWTABLE_VALID(table));
	
	elem = ISC_LIST_HEAD(table->views);
	while (elem != NULL) {
		tmpelem = ISC_LIST_NEXT(elem, next);
		ISC_LIST_UNLINK(table->views, elem, next);
		
		r = dns_c_view_delete(&elem);
		if (r != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG,
				      ISC_LOG_CRITICAL,
				      "failed to delete view");
			return (r);
		}

		elem = tmpelem;
	}

	return (ISC_R_SUCCESS);
}



isc_result_t
dns_c_viewtable_viewbyname(dns_c_viewtable_t *viewtable,
			   const char *viewname,
			   dns_c_view_t **retval)
{
	dns_c_view_t *elem;

	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	REQUIRE(retval != NULL);
	REQUIRE(viewname != NULL);
	REQUIRE(*viewname != '\0');

	elem = ISC_LIST_HEAD(viewtable->views);
	while (elem != NULL) {
		if (strcmp(viewname, elem->name) == 0) {
			break;
		}

		elem = ISC_LIST_NEXT(elem, next);
	}
	
	if (elem != NULL) {
		*retval = elem;
	}

	return (elem == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}



isc_result_t
dns_c_viewtable_rmviewbyname(dns_c_viewtable_t *viewtable,
					  const char *name)
{
	dns_c_view_t *view;
	isc_result_t res;

	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	
	res = dns_c_viewtable_viewbyname(viewtable, name, &view);
	if (res == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(viewtable->views, view, next);
		dns_c_view_delete(&view);
	}

	return (res);
}

	

/* ***************************************************************** */
/* ***************************************************************** */
/* ***************************************************************** */
/* ***************************************************************** */

isc_result_t
dns_c_view_new(isc_mem_t *mem, const char *name, dns_c_view_t **newview)
{
	dns_c_view_t *view;

	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');
	REQUIRE(newview != NULL);

	view = isc_mem_get(mem, sizeof *view);
	if (view == NULL) {
		return (ISC_R_NOMEMORY);
	}

	view->magic = DNS_C_VIEW_MAGIC;
	view->mem = mem;

	view->name = isc_mem_strdup(mem, name);
	if (view->name == NULL) {
		isc_mem_put(mem, view, sizeof *view);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Insufficient memory");
		return (ISC_R_NOMEMORY);
	}

	view->zonelist = NULL;

	view->forward = NULL;
	view->forwarders = NULL;

	view->allowquery = NULL;
	view->allowupdateforwarding = NULL;
	view->transferacl = NULL;
	view->recursionacl = NULL;
	view->blackhole = NULL;
	view->sortlist = NULL;
	view->topology = NULL;
	view->matchclients = NULL;

	view->ordering = NULL;

	view->check_names[dns_trans_primary] = NULL;
	view->check_names[dns_trans_secondary] = NULL;
	view->check_names[dns_trans_response] = NULL;

	view->auth_nx_domain = NULL;
	view->dialup = NULL;
	view->fetch_glue = NULL;
	view->has_old_clients = NULL;
	view->host_statistics = NULL;
	view->multiple_cnames = NULL;
	view->notify = NULL;
	view->recursion = NULL;
	view->rfc2308_type1 = NULL;
	view->use_id_pool = NULL;
	view->fake_iquery = NULL;
	view->use_ixfr = NULL;
	view->provide_ixfr = NULL;
	view->request_ixfr = NULL;

	view->clean_interval = NULL;
	view->lamettl = NULL;
	view->max_log_size_ixfr = NULL;
	view->max_ncache_ttl = NULL;
	view->max_transfer_time_in = NULL;
	view->max_transfer_time_out = NULL;
	view->max_transfer_idle_in = NULL;
	view->max_transfer_idle_out = NULL;
	view->stats_interval = NULL;
	view->transfers_in = NULL;
	view->transfers_out = NULL;
	view->transfers_per_ns = NULL;

	ISC_LINK_INIT(view, next);
	
	*newview = view;

	return (ISC_R_SUCCESS);
}


void
dns_c_view_print(FILE *fp, int indent, dns_c_view_t *view)
{
	dns_severity_t nameseverity;

	REQUIRE(DNS_C_VIEW_VALID(view));
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "view \"%s\" {\n", view->name);

#define PRINT_IPMLIST(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, NAME " ");				\
		dns_c_ipmatchlist_print(fp, indent + 2,		\
					view->FIELD);	\
		fprintf(fp, ";\n");				\
	}

#define PRINT_AS_BOOLEAN(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %s;\n", NAME,			\
			(*view->FIELD ? "true" : "false"));	\
	}


#define PRINT_INT32(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %d;\n",NAME,(int)view->FIELD);	\
	}
		
	PRINT_IPMLIST(allowquery, "allow-query");
	PRINT_IPMLIST(transferacl, "alllow-transfer");
	PRINT_IPMLIST(recursionacl, "allow-recursion");
	PRINT_IPMLIST(allowupdateforwarding, "allow-update-forwarding");
	PRINT_IPMLIST(blackhole, "backhole");
	PRINT_IPMLIST(sortlist, "sortlist");
	PRINT_IPMLIST(topology, "topology");
	PRINT_IPMLIST(matchclients, "match-clients");

	fprintf(fp, "\n");

	if (view->forwarders != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 2,
				   view->forwarders);
		fprintf(fp, ";\n");
	}

	if (view->ordering != NULL) {
		dns_c_rrsolist_print(fp, indent + 1, view->ordering);
	}

	if (view->check_names[dns_trans_primary] != NULL) {
		nameseverity = *view->check_names[dns_trans_primary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_primary, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}
		
	if (view->check_names[dns_trans_secondary] != NULL) {
		nameseverity = *view->check_names[dns_trans_secondary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_secondary, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}
		
	if (view->check_names[dns_trans_response] != NULL) {
		nameseverity = *view->check_names[dns_trans_response];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_response, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}


	PRINT_AS_BOOLEAN(auth_nx_domain, "auth-nxdomain");
	PRINT_AS_BOOLEAN(dialup, "dialup");
	PRINT_AS_BOOLEAN(fetch_glue, "fetch-glue");
	PRINT_AS_BOOLEAN(has_old_clients, "has-old-clients");
	PRINT_AS_BOOLEAN(host_statistics, "host-statistics");
	PRINT_AS_BOOLEAN(multiple_cnames, "multiple-cnames");
	PRINT_AS_BOOLEAN(notify, "notify");
	PRINT_AS_BOOLEAN(recursion, "recursion");
	PRINT_AS_BOOLEAN(rfc2308_type1, "rfc2308-type1");
	PRINT_AS_BOOLEAN(use_id_pool, "use-id-pool");
	PRINT_AS_BOOLEAN(fake_iquery, "fake-iquery");
	PRINT_AS_BOOLEAN(use_ixfr, "use-ixfr");
	PRINT_AS_BOOLEAN(provide_ixfr, "provide-ixfr");
	PRINT_AS_BOOLEAN(request_ixfr, "request-ixfr");
	

	PRINT_INT32(clean_interval, "cleaning-interval");
	PRINT_INT32(lamettl, "lamettl");
	PRINT_INT32(max_log_size_ixfr, "max_log_size_ixfr");
	PRINT_INT32(max_ncache_ttl, "max-ncache-ttl");
	PRINT_INT32(max_transfer_time_in, "max-transfer-time-in");
	PRINT_INT32(max_transfer_time_out, "max-transfer-time-out");
	PRINT_INT32(max_transfer_idle_in, "max-transfer-idle-in");
	PRINT_INT32(max_transfer_idle_out, "max-transfer-idle-out");
	PRINT_INT32(stats_interval, "statistics-interval");
	PRINT_INT32(transfers_in, "transfers-in");
	PRINT_INT32(transfers_out, "transfers-out");
	PRINT_INT32(transfers_per_ns, "transfers-per-ns");
	
	fprintf(fp, "\n");

	if (view->zonelist != NULL) {
		dns_c_zonelist_print(fp, indent + 1, view->zonelist);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");

#undef PRINT_IPMLIST
#undef PRINT_AS_BOOLEAN
#undef PRINT_INT32
	
}





isc_result_t
dns_c_view_delete(dns_c_view_t **viewptr)
{
	dns_c_view_t *view;

#define FREEIPMLIST(FIELD)				\
	do { if (view->FIELD != NULL) {			\
		dns_c_ipmatchlist_detach(&view->FIELD);	\
	} } while (0)

#define FREEFIELD(FIELD)						   \
	do { if (view->FIELD != NULL) {					   \
		isc_mem_put(view->mem, view->FIELD, sizeof (view->FIELD)); \
		view->FIELD = NULL;					   \
	} } while (0)
	
	REQUIRE(viewptr != NULL);
	REQUIRE(DNS_C_VIEW_VALID(*viewptr));

	view = *viewptr;

	isc_mem_free(view->mem, view->name);
	
	if (view->zonelist != NULL) {
		dns_c_zonelist_delete(&view->zonelist);
	}

	FREEFIELD(forward);

	if (view->forwarders != NULL) {
		dns_c_iplist_detach(&view->forwarders);
	}
		
	FREEIPMLIST(allowquery);
	FREEIPMLIST(allowupdateforwarding);
	FREEIPMLIST(transferacl);
	FREEIPMLIST(recursionacl);
	FREEIPMLIST(blackhole);
	FREEIPMLIST(sortlist);
	FREEIPMLIST(topology);
	FREEIPMLIST(matchclients);

	if (view->ordering != NULL) {
		dns_c_rrsolist_delete(&view->ordering);
	}


	FREEFIELD(check_names[dns_trans_primary]);
	FREEFIELD(check_names[dns_trans_secondary]);
	FREEFIELD(check_names[dns_trans_response]);

	FREEFIELD(auth_nx_domain);
	FREEFIELD(dialup);
	FREEFIELD(fetch_glue);
	FREEFIELD(has_old_clients);
	FREEFIELD(host_statistics);
	FREEFIELD(multiple_cnames);
	FREEFIELD(notify);
	FREEFIELD(recursion);
	FREEFIELD(rfc2308_type1);
	FREEFIELD(use_id_pool);
	FREEFIELD(fake_iquery);
	FREEFIELD(use_ixfr);
	FREEFIELD(provide_ixfr);
	FREEFIELD(request_ixfr);
	
	FREEFIELD(clean_interval);
	FREEFIELD(lamettl);
	FREEFIELD(max_log_size_ixfr);
	FREEFIELD(max_ncache_ttl);
	FREEFIELD(max_transfer_time_in);
	FREEFIELD(max_transfer_time_out);
	FREEFIELD(max_transfer_idle_in);
	FREEFIELD(max_transfer_idle_out);
	FREEFIELD(stats_interval);
	FREEFIELD(transfers_in);
	FREEFIELD(transfers_out);
	FREEFIELD(transfers_per_ns);
	
	view->magic = 0;
	isc_mem_put(view->mem, view, sizeof *view);
	
	return (ISC_R_SUCCESS);
}

	
isc_result_t
dns_c_view_getname(dns_c_view_t *view, const char **retval)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	*retval = view->name;

	return (ISC_R_SUCCESS);
}



/*
**
*/


isc_result_t
dns_c_view_addzone(dns_c_view_t *view, dns_c_zone_t *zone)
{
	isc_result_t res;
	dns_c_zone_t *attached;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_ZONE_VALID(zone));

	dns_c_zone_attach(zone, &attached);
	
	if (view->zonelist == NULL) {
		res = dns_c_zonelist_new(view->mem, &view->zonelist);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	return (dns_c_zonelist_addzone(view->zonelist, attached));
}


isc_result_t
dns_c_view_getzonelist(dns_c_view_t *view, dns_c_zonelist_t **zonelist)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(zonelist != NULL);

	*zonelist = view->zonelist;
	
	if (view->zonelist == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_view_unsetzonelist(dns_c_view_t *view)
{
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->zonelist == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		dns_c_zonelist_delete(&view->zonelist);
		return (ISC_R_SUCCESS);
	}
}


/*
**
*/


SETBYTYPE(dns_c_forw_t, forward, forward)
UNSETBYTYPE(dns_c_forw_t, forward, forward)
GETBYTYPE(dns_c_forw_t, forward, forward)

	
/*
**
*/

isc_result_t
dns_c_view_setforwarders(dns_c_view_t *view,
			 dns_c_iplist_t *ipl,
			 isc_boolean_t deepcopy)
{
	isc_boolean_t existed = ISC_FALSE;
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPLIST_VALID(ipl));

	if (view->forwarders != NULL) {
		existed = ISC_TRUE;
		dns_c_iplist_detach(&view->forwarders);
	}

	if (deepcopy) {
		res = dns_c_iplist_copy(view->mem, &view->forwarders, ipl);
	} else {
		dns_c_iplist_attach(ipl, &view->forwarders);
		res = ISC_R_SUCCESS;
	}

	if (res == ISC_R_SUCCESS) {
		return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
	} else {
		return (res);
	}
}
		


isc_result_t
dns_c_view_unsetforwarders(dns_c_view_t *view)
{
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->forwarders != NULL) {
		dns_c_iplist_detach(&view->forwarders);
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}
		
	

isc_result_t
dns_c_view_getforwarders(dns_c_view_t *view,
			 dns_c_iplist_t **ipl)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipl != NULL);
	
	*ipl = view->forwarders;

	return (*ipl == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


/*
**
*/

isc_result_t
dns_c_view_setordering(dns_c_view_t *view,
		       isc_boolean_t copy,
		       dns_c_rrsolist_t *olist)
{
	isc_boolean_t existed;
	isc_result_t res;

	REQUIRE(DNS_C_VIEW_VALID(view));

	existed = ISC_TF(view->ordering != NULL);

	if (copy) {
		if (view->ordering == NULL) {
			res = dns_c_rrsolist_new(view->mem,
						 &view->ordering);
			if (res != ISC_R_SUCCESS) {
				return (res);
			}
		} else {
			dns_c_rrsolist_clear(view->ordering);
		}
		
		res = dns_c_rrsolist_append(view->ordering, olist);
	} else {
		if (view->ordering != NULL) {
			dns_c_rrsolist_delete(&view->ordering);
		}
		
		view->ordering = olist;
		res = ISC_R_SUCCESS;
	}

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}
	
	return (res);
}

					  


isc_result_t
dns_c_view_getordering(dns_c_view_t *view,
		       dns_c_rrsolist_t **olist)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(olist != NULL);

	if (view->ordering != NULL) {
		*olist = view->ordering;
	}

	return (*olist == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_view_unsetordering(dns_c_view_t *view,
			 dns_c_rrsolist_t **olist)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(olist != NULL);

	if (view->ordering != NULL) {
		dns_c_rrsolist_delete(&view->ordering);
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}



/*
**
**
*/

isc_result_t
dns_c_view_setchecknames(dns_c_view_t *view,
			dns_c_trans_t transtype,
			dns_severity_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	dns_severity_t **ptr = NULL;
	
	REQUIRE(DNS_C_VIEW_VALID(view));

	switch(transtype) {
	case dns_trans_primary:
	case dns_trans_secondary:
	case dns_trans_response:
		ptr = &view->check_names[transtype];
		existed = ISC_TF(*ptr != NULL);
		break;

	default:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}

	if (!existed) {
		*ptr = isc_mem_get(view->mem, sizeof (**ptr));
	}

	**ptr = newval;
	
	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_view_getchecknames(dns_c_view_t *view,
			dns_c_trans_t transtype,
			dns_severity_t *retval)
{
	isc_result_t result;
	dns_severity_t **ptr = NULL;	
	REQUIRE(DNS_C_VIEW_VALID(view));

	switch (transtype) {
	case dns_trans_primary:
	case dns_trans_secondary:
	case dns_trans_response:
		ptr = &view->check_names[transtype];
		break;
		
	default:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}

	if (*ptr != NULL) {
		*retval = *view->check_names[transtype];
		result = ISC_R_SUCCESS;
	} else {
		result = ISC_R_NOTFOUND;
	}

	return (result);
}


isc_result_t
dns_c_view_unsetchecknames(dns_c_view_t *view,
			  dns_c_trans_t transtype)
{
	dns_severity_t **ptr = NULL;
	
	REQUIRE(DNS_C_VIEW_VALID(view));

	switch(transtype) {
	case dns_trans_primary:
	case dns_trans_secondary:
	case dns_trans_response:
		ptr = &view->check_names[transtype];
		break;

	default:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}

	if (*ptr == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	isc_mem_put(view->mem, *ptr, sizeof (**ptr));

	return (ISC_R_SUCCESS);
}


		
GETIPMLIST(allowquery, allowquery)
SETIPMLIST(allowquery, allowquery)
UNSETIPMLIST(allowquery, allowquery)

GETIPMLIST(allowupdateforwarding, allowupdateforwarding)
SETIPMLIST(allowupdateforwarding, allowupdateforwarding)
UNSETIPMLIST(allowupdateforwarding, allowupdateforwarding)

GETIPMLIST(blackhole, blackhole)
SETIPMLIST(blackhole, blackhole)
UNSETIPMLIST(blackhole, blackhole)

GETIPMLIST(recursionacl, recursionacl)
SETIPMLIST(recursionacl, recursionacl)
UNSETIPMLIST(recursionacl, recursionacl)

GETIPMLIST(sortlist, sortlist)
SETIPMLIST(sortlist, sortlist)
UNSETIPMLIST(sortlist, sortlist)

GETIPMLIST(topology, topology)
SETIPMLIST(topology, topology)
UNSETIPMLIST(topology, topology)

GETIPMLIST(matchclients, matchclients)
SETIPMLIST(matchclients, matchclients)
UNSETIPMLIST(matchclients, matchclients)

GETIPMLIST(transferacl, transferacl)
SETIPMLIST(transferacl, transferacl)
UNSETIPMLIST(transferacl, transferacl)

GETBOOL(authnxdomain, auth_nx_domain)
SETBOOL(authnxdomain, auth_nx_domain)
UNSETBOOL(authnxdomain, auth_nx_domain)

GETBOOL(dialup, dialup)
SETBOOL(dialup, dialup)
UNSETBOOL(dialup, dialup)

GETBOOL(fakeiquery, fake_iquery)
SETBOOL(fakeiquery, fake_iquery)
UNSETBOOL(fakeiquery, fake_iquery)

GETBOOL(fetchglue, fetch_glue)
SETBOOL(fetchglue, fetch_glue)
UNSETBOOL(fetchglue, fetch_glue)

GETBOOL(hasoldclients, has_old_clients)
SETBOOL(hasoldclients, has_old_clients)
UNSETBOOL(hasoldclients, has_old_clients)

GETBOOL(hoststatistics, host_statistics)
SETBOOL(hoststatistics, host_statistics)
UNSETBOOL(hoststatistics, host_statistics)

GETBOOL(multiplecnames, multiple_cnames)
SETBOOL(multiplecnames, multiple_cnames)
UNSETBOOL(multiplecnames, multiple_cnames)

GETBOOL(notify, notify)
SETBOOL(notify, notify)
UNSETBOOL(notify, notify)

GETBOOL(provideixfr, provide_ixfr)
SETBOOL(provideixfr, provide_ixfr)
UNSETBOOL(provideixfr, provide_ixfr)

GETBOOL(recursion, recursion)
SETBOOL(recursion, recursion)
UNSETBOOL(recursion, recursion)

GETBOOL(requestixfr, request_ixfr)
SETBOOL(requestixfr, request_ixfr)
UNSETBOOL(requestixfr, request_ixfr)

GETBOOL(rfc2308type1, rfc2308_type1)
SETBOOL(rfc2308type1, rfc2308_type1)
UNSETBOOL(rfc2308type1, rfc2308_type1)

GETBOOL(useidpool, use_id_pool)
SETBOOL(useidpool, use_id_pool)
UNSETBOOL(useidpool, use_id_pool)

GETBOOL(useixfr, use_ixfr)
SETBOOL(useixfr, use_ixfr)
UNSETBOOL(useixfr, use_ixfr)

GETINT32(cleaninterval, clean_interval)
SETINT32(cleaninterval, clean_interval)
UNSETINT32(cleaninterval, clean_interval)

GETINT32(lamettl, lamettl)
SETINT32(lamettl, lamettl)
UNSETINT32(lamettl, lamettl)

GETINT32(maxlogsizeixfr, max_log_size_ixfr)
SETINT32(maxlogsizeixfr, max_log_size_ixfr)
UNSETINT32(maxlogsizeixfr, max_log_size_ixfr)

GETINT32(maxncachettl, max_ncache_ttl)
SETINT32(maxncachettl, max_ncache_ttl)
UNSETINT32(maxncachettl, max_ncache_ttl)

GETINT32(maxtransferidlein, max_transfer_idle_in)
SETINT32(maxtransferidlein, max_transfer_idle_in)
UNSETINT32(maxtransferidlein, max_transfer_idle_in)

GETINT32(maxtransferidleout, max_transfer_idle_out)
SETINT32(maxtransferidleout, max_transfer_idle_out)
UNSETINT32(maxtransferidleout, max_transfer_idle_out)

GETINT32(maxtransfertimein, max_transfer_time_in)
SETINT32(maxtransfertimein, max_transfer_time_in)
UNSETINT32(maxtransfertimein, max_transfer_time_in)

GETINT32(maxtransfertimeout, max_transfer_time_out)
SETINT32(maxtransfertimeout, max_transfer_time_out)
UNSETINT32(maxtransfertimeout, max_transfer_time_out)

GETINT32(statsinterval, stats_interval)
SETINT32(statsinterval, stats_interval)
UNSETINT32(statsinterval, stats_interval)

GETINT32(transfersin, transfers_in)
SETINT32(transfersin, transfers_in)
UNSETINT32(transfersin, transfers_in)

GETINT32(transfersout, transfers_out)
SETINT32(transfersout, transfers_out)
UNSETINT32(transfersout, transfers_out)

GETINT32(transfersperns, transfers_per_ns)
SETINT32(transfersperns, transfers_per_ns)
UNSETINT32(transfersperns, transfers_per_ns)

