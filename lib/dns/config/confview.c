/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: confview.c,v 1.63 2000/12/06 20:37:01 gson Exp $ */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/confview.h>
#include <dns/log.h>
#include <dns/peer.h>

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
#define BOOL_FUNCS(FUNC, FIELD) \
	SETBOOL(FUNC, FIELD) \
	GETBOOL(FUNC, FIELD) \
	UNSETBOOL(FUNC, FIELD)


#define SETNOTIFYTYPE(FUNC, FIELD) SETBYTYPE(dns_notifytype_t, FUNC, FIELD)
#define GETNOTIFYTYPE(FUNC, FIELD) GETBYTYPE(dns_notifytype_t, FUNC, FIELD)
#define UNSETNOTIFYTYPE(FUNC, FIELD) UNSETBYTYPE(dns_notifytype_t, FUNC, FIELD)
#define NOTIFYTYPE_FUNCS(FUNC, FIELD) \
	SETNOTIFYTYPE(FUNC, FIELD) \
	GETNOTIFYTYPE(FUNC, FIELD) \
	UNSETNOTIFYTYPE(FUNC, FIELD)

#define SETDIALUPTYPE(FUNC, FIELD) SETBYTYPE(dns_dialuptype_t, FUNC, FIELD)
#define GETDIALUPTYPE(FUNC, FIELD) GETBYTYPE(dns_dialuptype_t, FUNC, FIELD)
#define UNSETDIALUPTYPE(FUNC, FIELD) UNSETBYTYPE(dns_dialuptype_t, FUNC, FIELD)
#define DIALUPTYPE_FUNCS(FUNC, FIELD) \
	SETDIALUPTYPE(FUNC, FIELD) \
	GETDIALUPTYPE(FUNC, FIELD) \
	UNSETDIALUPTYPE(FUNC, FIELD)

#define SETUINT32(FUNC, FIELD) SETBYTYPE(isc_uint32_t, FUNC, FIELD)
#define GETUINT32(FUNC, FIELD) GETBYTYPE(isc_uint32_t, FUNC, FIELD)
#define UNSETUINT32(FUNC, FIELD) UNSETBYTYPE(isc_uint32_t, FUNC, FIELD)
#define UINT32_FUNCS(FUNC, FIELD) \
	SETUINT32(FUNC, FIELD) \
	GETUINT32(FUNC, FIELD) \
	UNSETUINT32(FUNC, FIELD)

#define SETSOCKADDR(FUNC, FIELD) SETBYTYPE(isc_sockaddr_t, FUNC, FIELD)
#define GETSOCKADDR(FUNC, FIELD) GETBYTYPE(isc_sockaddr_t, FUNC, FIELD)
#define UNSETSOCKADDR(FUNC, FIELD) UNSETBYTYPE(isc_sockaddr_t, FUNC, FIELD)
#define SOCKADDR_FUNCS(FUNC, FIELD) \
	SETSOCKADDR(FUNC, FIELD) \
	GETSOCKADDR(FUNC, FIELD) \
	UNSETSOCKADDR(FUNC, FIELD)

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
PVT_CONCAT(dns_c_view_set, FUNCNAME)(dns_c_view_t *view, TYPE newval) {	    \
	isc_boolean_t existed = ISC_FALSE;				    \
									    \
	REQUIRE(DNS_C_VIEW_VALID(view));				    \
									    \
	if (view->FIELDNAME == NULL) {					    \
		view->FIELDNAME = isc_mem_get(view->mem, sizeof (TYPE));    \
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
PVT_CONCAT(dns_c_view_get, FUNCNAME)(dns_c_view_t *view, TYPE *retval) {\
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
PVT_CONCAT(dns_c_view_unset, FUNCNAME)(dns_c_view_t *view) {	\
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

#define BYTYPE_FUNCS(TYPE, FUNC, FIELD) \
	SETBYTYPE(TYPE, FUNC, FIELD) \
	GETBYTYPE(TYPE, FUNC, FIELD) \
	UNSETBYTYPE(TYPE, FUNC, FIELD)


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
PVT_CONCAT(dns_c_view_unset, FUNCNAME)(dns_c_view_t *view) {	\
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


#define IPMLIST_FUNCS(FUNC, FIELD) \
	SETIPMLIST(FUNC, FIELD) \
	GETIPMLIST(FUNC, FIELD) \
	UNSETIPMLIST(FUNC, FIELD)


isc_result_t
dns_c_viewtable_new(isc_mem_t *mem, dns_c_viewtable_t **viewtable) {
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


void
dns_c_viewtable_delete(dns_c_viewtable_t **viewtable) {
	dns_c_viewtable_t *table;

	REQUIRE(viewtable != NULL);
	REQUIRE(DNS_C_VIEWTABLE_VALID(*viewtable));

	table = *viewtable;
	*viewtable = NULL;

	dns_c_viewtable_clear(table);

	table->magic = 0;
	isc_mem_put(table->mem, table, sizeof *table);
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


isc_result_t
dns_c_viewtable_addview(dns_c_viewtable_t *viewtable, dns_c_view_t *view) {
	dns_c_view_t *elem;

	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	REQUIRE(DNS_C_VIEW_VALID(view));

	elem = ISC_LIST_HEAD(viewtable->views);
	while (elem != NULL) {
		if (strcmp(view->name, elem->name) == 0 &&
		    view->viewclass == elem->viewclass) {
			return (ISC_R_EXISTS);
		}

		elem = ISC_LIST_NEXT(elem, next);
	}
	
	ISC_LIST_APPEND(viewtable->views, view, next);
	return (ISC_R_SUCCESS);
}



void
dns_c_viewtable_rmview(dns_c_viewtable_t *viewtable, dns_c_view_t *view) {
	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));
	REQUIRE(DNS_C_VIEW_VALID(view));

	ISC_LIST_UNLINK(viewtable->views, view, next);
}



void
dns_c_viewtable_clear(dns_c_viewtable_t *table) {
	dns_c_view_t *elem;
	dns_c_view_t *tmpelem;

	REQUIRE(DNS_C_VIEWTABLE_VALID(table));

	elem = ISC_LIST_HEAD(table->views);
	while (elem != NULL) {
		tmpelem = ISC_LIST_NEXT(elem, next);
		ISC_LIST_UNLINK(table->views, elem, next);

		dns_c_view_delete(&elem);
		elem = tmpelem;
	}
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


isc_result_t
dns_c_viewtable_checkviews(dns_c_viewtable_t *viewtable) {
	dns_c_view_t *elem;
	isc_boolean_t bbval;
	isc_uint32_t buival;
	isc_result_t result = ISC_R_SUCCESS;
	dns_c_rrsolist_t *boval;
	dns_severity_t sevval;

	REQUIRE(DNS_C_VIEWTABLE_VALID(viewtable));

	elem = ISC_LIST_HEAD(viewtable->views);
	while (elem != NULL) {
		if (dns_c_view_getfetchglue(elem, &bbval) != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'fetch-glue' is obsolete");

		if (dns_c_view_getrfc2308type1(elem, &bbval) != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'rfc2308-type1' is not yet "
				      "implemented");

		if (dns_c_view_getmaxcachesize(elem, &buival) != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'max-cache-size' is not yet "
				      "implemented");

		if (dns_c_view_getminroots(elem, &buival) != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'min-roots' is obsolete");


		if (dns_c_view_getordering(elem, &boval) != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'rrset-order' is not yet "
				      "implemented");

		if (dns_c_view_getchecknames(elem, dns_trans_primary, &sevval)
		    != ISC_R_NOTFOUND)
			isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
				      "view 'check-names' is not "
				      "implemented");


		elem = ISC_LIST_NEXT(elem, next);
	}

	return (result);
}


/* ***************************************************************** */
/* ***************************************************************** */
/* ***************************************************************** */
/* ***************************************************************** */

isc_result_t
dns_c_view_new(isc_mem_t *mem, const char *name, dns_rdataclass_t viewclass,
	       dns_c_view_t **newview)
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
	view->viewclass = viewclass;

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
	view->also_notify = NULL;

#ifndef NOMINUM_PUBLIC
	view->allownotify = NULL;
#endif /* NOMINUM_PUBLIC */
	view->allowquery = NULL;
	view->allowupdateforwarding = NULL;
	view->transferacl = NULL;
	view->recursionacl = NULL;
	view->sortlist = NULL;
	view->topology = NULL;
	view->matchclients = NULL;

	view->ordering = NULL;

	view->check_names[dns_trans_primary] = NULL;
	view->check_names[dns_trans_secondary] = NULL;
	view->check_names[dns_trans_response] = NULL;

	view->auth_nx_domain = NULL;
	view->recursion = NULL;
	view->provide_ixfr = NULL;
	view->request_ixfr = NULL;
	view->fetch_glue = NULL;
	view->notify = NULL;
	view->dialup = NULL;
	view->statistics = NULL;
	view->rfc2308_type1 = NULL;
	view->additional_from_cache = NULL;
	view->additional_from_auth = NULL;

	view->notify_source = NULL;
	view->notify_source_v6 = NULL;
	view->transfer_source = NULL;
	view->transfer_source_v6 = NULL;
	view->query_source = NULL;
	view->query_source_v6 = NULL;

	view->max_transfer_time_out = NULL;
	view->max_transfer_idle_out = NULL;
	view->clean_interval = NULL;
	view->min_roots = NULL;
	view->lamettl = NULL;
	view->sig_valid_interval = NULL;
	view->max_cache_size = NULL;
	view->max_ncache_ttl = NULL;
	view->max_cache_ttl = NULL;

	view->min_retry_time = NULL;
	view->max_retry_time = NULL;
	view->min_refresh_time = NULL;
	view->max_refresh_time = NULL;

#ifndef NOMINUM_PUBLIC
	view->max_names = NULL;
	view->notify_forward = NULL;
#endif /* NOMINUM_PUBLIC */

	view->additional_data = NULL;
	view->transfer_format = NULL;
	view->keydefs = NULL;
	view->peerlist = NULL;

	view->trusted_keys = NULL;

#if 0
	view->max_transfer_time_in = NULL;
	view->max_transfer_idle_in = NULL;
	view->transfers_per_ns = NULL;
	view->serial_queries = NULL;
#endif

	ISC_LINK_INIT(view, next);

	*newview = view;

	return (ISC_R_SUCCESS);
}


void
dns_c_view_print(FILE *fp, int indent, dns_c_view_t *view) {
	dns_severity_t nameseverity;
	in_port_t port;

	REQUIRE(DNS_C_VIEW_VALID(view));

	dns_c_printtabs(fp, indent);
	fprintf(fp, "view \"%s\"", view->name);

	if (view->viewclass != dns_rdataclass_in) {
		fputc(' ', fp);
		dns_c_dataclass_tostream(fp, view->viewclass);
	}

	fprintf(fp, " {\n");

#define PRINT_IPANDPORT(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		port = isc_sockaddr_getport(view->FIELD);	\
								\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, NAME " address ");			\
								\
		dns_c_print_ipaddr(fp, view->FIELD);		\
								\
		if (port == 0) {				\
			fprintf(fp, " port *");			\
		} else {					\
			fprintf(fp, " port %d", port);		\
		}						\
		fprintf(fp, " ;\n");				\
	}

#define	 PRINT_IP(FIELD, NAME)				\
	if (view->FIELD != NULL) {			\
		dns_c_printtabs(fp, indent + 1);	\
		fprintf(fp, NAME " ");			\
		dns_c_print_ipaddr(fp, view->FIELD);	\
		fprintf(fp, ";\n");			\
	}

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


#define PRINT_AS_NOTIFYTYPE(FIELD, NAME)			\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s ", NAME);			\
		if (*view->FIELD == dns_notifytype_yes)		\
			fputs("yes", fp);			\
		else if (*view->FIELD == dns_notifytype_no)	\
			fputs("no", fp);			\
		else						\
			fputs("explicit", fp);			\
		fprintf(fp, ";\n");				\
	}

#define PRINT_AS_DIALUPTYPE(FIELD, NAME)			\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s ", NAME);			\
		if (*view->FIELD == dns_dialuptype_yes)		\
			fputs("yes", fp);			\
		else if (*view->FIELD == dns_dialuptype_no)	\
			fputs("no", fp);			\
		else if (*view->FIELD == dns_dialuptype_notify)	\
			fputs("notify", fp);			\
		else if (*view->FIELD == dns_dialuptype_notifypassive)	\
			fputs("notify-passive", fp);			\
		else if (*view->FIELD == dns_dialuptype_refresh) \
			fputs("refresh", fp);			\
		else						\
			fputs("passive", fp);			\
	}


#define PRINT_INT32(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %d;\n",NAME,(int)*view->FIELD);	\
	}

#define PRINT_AS_MINUTES(FIELD, NAME)				\
	if (view->FIELD != NULL) {				\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %lu;\n",NAME,			\
			(unsigned long)(*view->FIELD / 60));	\
	}

#define PRINT_AS_SIZE_CLAUSE(FIELD, NAME)				\
	if (view->FIELD != NULL) {					\
		dns_c_printtabs(fp, indent + 1);			\
		fprintf(fp, "%s ",NAME);				\
		if (*view->FIELD == DNS_C_SIZE_SPEC_DEFAULT) {	\
			fprintf(fp, "default");				\
		} else {						\
			dns_c_printinunits(fp, *view->FIELD);	\
		}							\
		fprintf(fp, ";\n");					\
	}


	if (view->forward != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(*view->forward, ISC_TRUE));
	}

	if (view->forwarders != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 2,
				   view->forwarders);
		fprintf(fp, ";\n");
	}

	if (view->also_notify != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "also-notify ");
		dns_c_iplist_print(fp, indent + 2,
				   view->also_notify);
		fprintf(fp, ";\n");
	}

#ifndef NOMINUM_PUBLIC
	PRINT_IPMLIST(allownotify, "allow-notify");
#endif /* NOMINUM_PUBLIC */
	PRINT_IPMLIST(allowquery, "allow-query");
	PRINT_IPMLIST(allowupdateforwarding, "allow-update-forwarding");
	PRINT_IPMLIST(transferacl, "alllow-transfer");
	PRINT_IPMLIST(recursionacl, "allow-recursion");
	PRINT_IPMLIST(sortlist, "sortlist");
	PRINT_IPMLIST(topology, "topology");
	PRINT_IPMLIST(matchclients, "match-clients");

	fprintf(fp, "\n");

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


	PRINT_AS_NOTIFYTYPE(notify, "notify");
	PRINT_AS_DIALUPTYPE(dialup, "dialup");
	
	PRINT_AS_BOOLEAN(auth_nx_domain, "auth-nxdomain");
	PRINT_AS_BOOLEAN(recursion, "recursion");
	PRINT_AS_BOOLEAN(provide_ixfr, "provide-ixfr");
	PRINT_AS_BOOLEAN(request_ixfr, "request-ixfr");
	PRINT_AS_BOOLEAN(fetch_glue, "fetch-glue");
	PRINT_AS_BOOLEAN(rfc2308_type1, "rfc2308-type1");
	PRINT_AS_BOOLEAN(additional_from_auth, "additional-from-auth");
	PRINT_AS_BOOLEAN(additional_from_cache, "additional-from-cache");
	PRINT_AS_BOOLEAN(statistics, "statistics");
#ifndef NOMINUM_PUBLIC
	PRINT_AS_BOOLEAN(notify_forward, "notify-forward");
#endif /* NOMINUM_PUBLIC */

	PRINT_IPANDPORT(notify_source, "notify-source");
	PRINT_IPANDPORT(notify_source_v6, "notify-source-v6");

	PRINT_IPANDPORT(transfer_source, "transfer-source");
	PRINT_IPANDPORT(transfer_source_v6, "transfer-source-v6");

	PRINT_IPANDPORT(query_source, "query-source");
	PRINT_IPANDPORT(query_source_v6, "query-source-v6");

	PRINT_AS_MINUTES(max_transfer_time_out, "max-transfer-time-out");
	PRINT_AS_MINUTES(max_transfer_idle_out, "max-transfer-idle-out");
	PRINT_AS_MINUTES(clean_interval, "cleaning-interval");

	PRINT_INT32(min_roots, "min-roots");
	PRINT_INT32(lamettl, "lame-ttl");
	PRINT_INT32(max_ncache_ttl, "max-ncache-ttl");
	PRINT_INT32(max_cache_ttl, "max-cache-ttl");
	PRINT_INT32(sig_valid_interval, "sig-validity-interval");

	PRINT_INT32(min_retry_time, "min-retry-time");
	PRINT_INT32(max_retry_time, "max-retry-time");
	PRINT_INT32(min_refresh_time, "min-refresh-time");
	PRINT_INT32(max_refresh_time, "max-refresh-time");

#ifndef NOMINUM_PUBLIC
	PRINT_INT32(max_names, "max-names");
#endif /* NOMINUM_PUBLIC */

	PRINT_AS_SIZE_CLAUSE(max_cache_size, "max-cache-size");

	if (view->additional_data != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "additional-data %s;\n",
			dns_c_addata2string(*view->additional_data, ISC_TRUE));
	}

	if (view->transfer_format != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(*view->transfer_format,
						 ISC_TRUE));
	}


	if (view->keydefs != NULL) {
		dns_c_kdeflist_print(fp, indent + 1, view->keydefs);
	}

	if (view->peerlist != NULL) {
		dns_c_peerlist_print(fp, indent + 1, view->peerlist);
	}


	if (view->trusted_keys != NULL) {
		dns_c_tkeylist_print(fp, indent + 1, view->trusted_keys);
		fprintf(fp, "\n");
	}


#if 0
	PRINT_INT32(max_transfer_time_in, "max-transfer-time-in");
	PRINT_INT32(max_transfer_idle_in, "max-transfer-idle-in");
	PRINT_INT32(transfers_per_ns, "transfers-per-ns");
#endif

	fprintf(fp, "\n");

	if (view->zonelist != NULL) {
		dns_c_zonelist_print(fp, indent + 1, view->zonelist, view);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");

#undef PRINT_IPMLIST
#undef PRINT_AS_BOOLEAN
#undef PRINT_INT32
#undef PRINT_IP
#undef PRINT_IPANDPORT

}





void
dns_c_view_delete(dns_c_view_t **viewptr) {
	dns_c_view_t *view;

#define FREEIPMLIST(FIELD)				\
	do { if (view->FIELD != NULL) {			\
		dns_c_ipmatchlist_detach(&view->FIELD);	\
	} } while (0)

#define FREEFIELD(FIELD)						   \
	do { if (view->FIELD != NULL) {					   \
		isc_mem_put(view->mem, view->FIELD, sizeof (*view->FIELD)); \
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

	if (view->also_notify != NULL) {
		dns_c_iplist_detach(&view->also_notify);
	}

#ifndef NOMINUM_PUBLIC
	FREEIPMLIST(allownotify);
#endif /* NOMINUM_PUBLIC */
	FREEIPMLIST(allowquery);
	FREEIPMLIST(allowupdateforwarding);
	FREEIPMLIST(transferacl);
	FREEIPMLIST(recursionacl);
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
	FREEFIELD(recursion);
	FREEFIELD(provide_ixfr);
	FREEFIELD(request_ixfr);
	FREEFIELD(fetch_glue);
	FREEFIELD(notify);
	FREEFIELD(dialup);
	FREEFIELD(statistics);
	FREEFIELD(rfc2308_type1);
	FREEFIELD(additional_from_auth);
	FREEFIELD(additional_from_cache);

	FREEFIELD(notify_source);
	FREEFIELD(notify_source_v6);
	FREEFIELD(transfer_source);
	FREEFIELD(transfer_source_v6);
	FREEFIELD(query_source);
	FREEFIELD(query_source_v6);

	FREEFIELD(max_transfer_time_out);
	FREEFIELD(max_transfer_idle_out);
	FREEFIELD(clean_interval);
	FREEFIELD(min_roots);
	FREEFIELD(lamettl);
	FREEFIELD(max_ncache_ttl);
	FREEFIELD(max_cache_ttl);
	FREEFIELD(sig_valid_interval);
	FREEFIELD(max_cache_size);

	FREEFIELD(min_retry_time);
	FREEFIELD(max_retry_time);
	FREEFIELD(min_refresh_time);
	FREEFIELD(max_refresh_time);

#ifndef NOMINUM_PUBLIC
	FREEFIELD(max_names);
	FREEFIELD(notify_forward);
#endif /* NOMINUM_PUBLIC */

	FREEFIELD(additional_data);
	FREEFIELD(transfer_format);

	dns_c_view_unsetkeydefs(view);
	dns_c_view_unsetpeerlist(view);

	dns_c_view_unsettrustedkeys(view);

#if 0
	FREEFIELD(max_transfer_time_in);
	FREEFIELD(max_transfer_idle_in);
	FREEFIELD(transfers_per_ns);
	FREEFIELD(serial_queries);
#endif


	view->magic = 0;
	isc_mem_put(view->mem, view, sizeof *view);
}


isc_boolean_t
dns_c_view_keydefinedp(dns_c_view_t *view, const char *keyname) {
	dns_c_kdef_t *keyid;
	isc_result_t res;
	isc_boolean_t rval = ISC_FALSE;

	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(keyname != NULL);
	REQUIRE(*keyname != '\0');

	if (view->keydefs != NULL) {
		res = dns_c_kdeflist_find(view->keydefs, keyname, &keyid);
		if (res == ISC_R_SUCCESS) {
			rval = ISC_TRUE;
		}
	}

	return rval;
}

isc_result_t
dns_c_view_getname(dns_c_view_t *view, const char **retval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	*retval = view->name;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_view_getviewclass(dns_c_view_t *view, dns_rdataclass_t *retval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	*retval = view->viewclass;

	return (ISC_R_SUCCESS);
}



/*
**
*/


isc_result_t
dns_c_view_addzone(dns_c_view_t *view, dns_c_zone_t *zone) {
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
dns_c_view_getzonelist(dns_c_view_t *view, dns_c_zonelist_t **zonelist) {
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
dns_c_view_unsetzonelist(dns_c_view_t *view) {
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


BYTYPE_FUNCS(dns_c_forw_t, forward, forward)
	

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
dns_c_view_unsetforwarders(dns_c_view_t *view) {
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
dns_c_view_setalsonotify(dns_c_view_t *view,
			 dns_c_iplist_t *ipl)
{
	isc_boolean_t existed = ISC_FALSE;

	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPLIST_VALID(ipl));

	if (view->also_notify != NULL) {
		existed = ISC_TRUE;
		dns_c_iplist_detach(&view->also_notify);
	}

	dns_c_iplist_attach(ipl, &view->also_notify);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}



isc_result_t
dns_c_view_unsetalsonotify(dns_c_view_t *view) {
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->also_notify != NULL) {
		dns_c_iplist_detach(&view->also_notify);
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}



isc_result_t
dns_c_view_getalsonotify(dns_c_view_t *view,
			 dns_c_iplist_t **ipl)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipl != NULL);

	if (view->also_notify == NULL)
		return (ISC_R_NOTFOUND);

	dns_c_iplist_attach(view->also_notify, ipl);
	return (ISC_R_SUCCESS);
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

	*olist = view->ordering;

	return (*olist == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_view_unsetordering(dns_c_view_t *view)
{
	REQUIRE(DNS_C_VIEW_VALID(view));

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


isc_result_t
dns_c_view_getkeydefs(dns_c_view_t *view, dns_c_kdeflist_t **retval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	*retval = view->keydefs;

	if (view->keydefs == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_view_setkeydefs(dns_c_view_t *view, dns_c_kdeflist_t *newval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_KDEFLIST_VALID(newval));

	if (view->keydefs != NULL) {
		dns_c_view_unsetkeydefs(view);
	}

	view->keydefs = newval;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_view_unsetkeydefs(dns_c_view_t *view) {
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->keydefs != NULL) {
		dns_c_kdeflist_delete(&view->keydefs);
		view->keydefs = NULL;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


/*
**
*/

isc_result_t
dns_c_view_getpeerlist(dns_c_view_t *view, dns_peerlist_t **retval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	if (view->peerlist == NULL) {
		*retval = NULL;
		return (ISC_R_NOTFOUND);
	} else {
		dns_peerlist_attach(view->peerlist, retval);
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_view_unsetpeerlist(dns_c_view_t *view) {
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->peerlist != NULL) {
		dns_peerlist_detach(&view->peerlist);
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_FAILURE);
	}
}


isc_result_t
dns_c_view_setpeerlist(dns_c_view_t *view, dns_peerlist_t *newval) {
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->peerlist != NULL) {
		dns_peerlist_detach(&view->peerlist);
	}

	dns_peerlist_attach(newval, &view->peerlist);

	return (ISC_R_SUCCESS);
}


/*
**
*/

isc_result_t
dns_c_view_gettrustedkeys(dns_c_view_t *view, dns_c_tkeylist_t **retval) {
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(retval != NULL);

	if (view->trusted_keys == NULL) {
		*retval = NULL;
		return (ISC_R_NOTFOUND);
	} else {
		*retval = view->trusted_keys;
/*	XXX need to replace above line with
	dns_tkeylist_attach(view->trusted_keys, retval);
*/
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_view_unsettrustedkeys(dns_c_view_t *view) {
	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->trusted_keys != NULL) {
		dns_c_tkeylist_delete(&view->trusted_keys);
/* XXX need to replace above line with
   dns_peerlist_detach(&view->trusted_keys);
*/
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_FAILURE);
	}
}


isc_result_t
dns_c_view_settrustedkeys(dns_c_view_t *view, dns_c_tkeylist_t *newval,
			  isc_boolean_t copy)
{
	isc_boolean_t existed;
	dns_c_tkeylist_t *newl;
	isc_result_t res;

	REQUIRE(DNS_C_VIEW_VALID(view));

	existed = ISC_TF(view->trusted_keys != NULL);

	if (view->trusted_keys != NULL) {
		dns_c_view_unsettrustedkeys(view);
	}

/* XXX need to replace below stuff with
   dns_peerlist_attach(newval, &view->trusted_keys);
*/

	if (copy) {
		res = dns_c_tkeylist_copy(view->mem, &newl, newval);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newl = newval;
	}

	view->trusted_keys = newl;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


/*
**
*/

#ifndef NOMINUM_PUBLIC
IPMLIST_FUNCS(allownotify, allownotify)
#endif /* NOMINUM_PUBLIC */
IPMLIST_FUNCS(allowquery, allowquery)
IPMLIST_FUNCS(allowupdateforwarding, allowupdateforwarding)
IPMLIST_FUNCS(transferacl, transferacl)
IPMLIST_FUNCS(recursionacl, recursionacl)
IPMLIST_FUNCS(sortlist, sortlist)
IPMLIST_FUNCS(topology, topology)
IPMLIST_FUNCS(matchclients, matchclients)

BOOL_FUNCS(authnxdomain, auth_nx_domain)
BOOL_FUNCS(recursion, recursion)
BOOL_FUNCS(provideixfr, provide_ixfr)
BOOL_FUNCS(requestixfr, request_ixfr)
BOOL_FUNCS(fetchglue, fetch_glue)
BOOL_FUNCS(statistics, statistics)

NOTIFYTYPE_FUNCS(notify, notify)
DIALUPTYPE_FUNCS(dialup, dialup)

#ifndef NOMINUM_PUBLIC
BOOL_FUNCS(notifyforward, notify_forward)
#endif /* NOMINUM_PUBLIC */

BOOL_FUNCS(rfc2308type1, rfc2308_type1)
BOOL_FUNCS(additionalfromcache, additional_from_cache)
BOOL_FUNCS(additionalfromauth, additional_from_auth)

SOCKADDR_FUNCS(notifysource, notify_source)
SOCKADDR_FUNCS(notifysourcev6, notify_source_v6)
SOCKADDR_FUNCS(transfersource, transfer_source)
SOCKADDR_FUNCS(transfersourcev6, transfer_source_v6)
SOCKADDR_FUNCS(querysource, query_source)
SOCKADDR_FUNCS(querysourcev6, query_source_v6)

UINT32_FUNCS(maxtransfertimeout, max_transfer_time_out)
UINT32_FUNCS(maxtransferidleout, max_transfer_idle_out)
UINT32_FUNCS(cleaninterval, clean_interval)
UINT32_FUNCS(minroots, min_roots)
UINT32_FUNCS(lamettl, lamettl)
UINT32_FUNCS(maxncachettl, max_ncache_ttl)
UINT32_FUNCS(maxcachettl, max_cache_ttl)
UINT32_FUNCS(sigvalidityinterval, sig_valid_interval)
UINT32_FUNCS(maxcachesize, max_cache_size)

UINT32_FUNCS(minretrytime, min_retry_time)
UINT32_FUNCS(maxretrytime, max_retry_time)
UINT32_FUNCS(minrefreshtime, min_refresh_time)
UINT32_FUNCS(maxrefreshtime, max_refresh_time)

#ifndef NOMINUM_PUBLIC	
UINT32_FUNCS(maxnames, max_names)
#endif /* NOMINUM_PUBLIC */

BYTYPE_FUNCS(dns_c_addata_t, additionaldata, additional_data)
BYTYPE_FUNCS(dns_transfer_format_t, transferformat, transfer_format)

#if 0
/*
 * XXX waiting for implementation in server to turn these on.
 */
UINT32_FUNCS(maxtransfertimein, max_transfer_time_in)
UINT32_FUNCS(maxtransferidlein, max_transfer_idle_in)
UINT32_FUNCS(transfersperns, transfers_per_ns)

#endif










