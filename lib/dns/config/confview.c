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

#define CHECKNAME_PRIM_BIT                       1
#define CHECKNAME_SEC_BIT                        2
#define CHECKNAME_RESP_BIT                       3
#define MULTIPLE_CNAMES_BIT                      4
#define DIALUP_BIT                               5
#define FETCH_GLUE_BIT                           6
#define HAS_OLD_CLIENTS_BIT                      7
#define HOST_STATISTICS_BIT                      8
#define MAINTAIN_IXFR_BASE_BIT                   9
#define NOTIFY_BIT                               11
#define RECURSION_BIT                            12
#define RFC2308_TYPE1_BIT                        13
#define USE_ID_POOL_BIT                          14
#define FAKE_IQUERY_BIT                          15
#define USE_IXFR_BIT                             16
#define TCP_CLIENTS_BIT                          17
#define RECURSIVE_CLIENTS_BIT                    18
#define CLEAN_INTERVAL_BIT                       19
#define MAX_LOG_SIZE_IXFR_BIT                    20
#define MAX_NCACHE_TTL_BIT                       21
#define MAX_TRANSFER_TIME_IN_BIT                 22
#define MAX_TRANSFER_TIME_OUT_BIT                23
#define MAX_TRANSFER_IDLE_IN_BIT                 24
#define MAX_TRANSFER_IDLE_OUT_BIT                25
#define STATS_INTERVAL_BIT                       26
#define TRANSFERS_IN_BIT                         27
#define TRANSFERS_OUT_BIT                        28
#define TRANSFERS_PER_NS_BIT                     29
#define TRANSFER_FORMAT_BIT			 30

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

	

isc_result_t
dns_c_view_new(isc_mem_t *mem, const char *name, dns_c_view_t **newview)
{
	dns_c_view_t *view;
	int i;
	

	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');
	REQUIRE(newview != NULL);

	view = isc_mem_get(mem, sizeof *view);
	if (view == NULL) {
		return (ISC_R_NOMEMORY);
	}

	/* XXXJAB not portable -- should set each field */
	memset(view, 0x0, sizeof *view); 

	memset(&view->setflags, 0x0, sizeof (view->setflags));
	
	view->magic = DNS_C_VIEW_MAGIC;
	view->mem = mem;

	view->allowquery = NULL;
	view->transferacl = NULL;
	view->recursionacl = NULL;
	view->blackhole = NULL;
	view->sortlist = NULL;
	view->topology = NULL;
	view->forwarders = NULL;
	view->listens = NULL;
	view->ordering = NULL;
	
	for (i = 0 ; i < DNS_C_TRANSCOUNT ; i++) {
		view->check_names[i] = dns_severity_fail;
	}

	view->transfer_format = dns_one_answer;

	view->auth_nx_domain = ISC_FALSE;
	view->dialup = ISC_FALSE;
	view->fetch_glue = ISC_FALSE;
	view->has_old_clients = ISC_FALSE;
	view->host_statistics = ISC_FALSE;
	view->maintain_ixfr_base = ISC_FALSE;
	view->multiple_cnames = ISC_FALSE;
	view->notify = ISC_FALSE;
	view->recursion = ISC_FALSE;
	view->rfc2308_type1 = ISC_FALSE;
	view->use_id_pool = ISC_FALSE;
	view->fake_iquery = ISC_FALSE;
	view->use_ixfr = ISC_FALSE;

	view->clean_interval = 0;
	view->lamettl = 0;		/* XXX not implemented */
	view->max_log_size_ixfr = 0;
	view->max_ncache_ttl = 0;
	view->max_transfer_time_in = 0;
	view->max_transfer_time_out = 0;
	view->max_transfer_idle_in = 0;
	view->max_transfer_idle_out = 0;
	view->stats_interval = 0;
	view->transfers_in = 0;
	view->transfers_out = 0;
	view->transfers_per_ns = 0;

	view->zonelist = NULL;
	view->name = isc_mem_strdup(mem, name);
	if (view->name == NULL) {
		isc_mem_put(mem, view, sizeof *view);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Insufficient memory");
	}

	*newview = view;

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
dns_c_view_print(FILE *fp, int indent, dns_c_view_t *view)
{
	dns_severity_t nameseverity;

	REQUIRE(DNS_C_VIEW_VALID(view));
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "view \"%s\" {\n", view->name);

	if (view->allowquery != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-query ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->allowquery);
		fprintf(fp, ";\n");
	}

	if (view->transferacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->transferacl);
		fprintf(fp, ";\n");
	}

	if (view->recursionacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-recursion ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->recursionacl);
		fprintf(fp, ";\n");
	}

	if (view->allowupdateforwarding != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-update-forwarding ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->allowupdateforwarding);
		fprintf(fp, ";\n");
	}

	if (view->blackhole != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "blackhole ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->blackhole);
		fprintf(fp, ";\n");
	}

	if (view->forwarders != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 2,
				   view->forwarders);
		fprintf(fp, ";\n");
	}

	if (view->sortlist != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "sortlist ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->sortlist);
		fprintf(fp, ";\n");
	}

	if (view->topology != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "topology ");
		dns_c_ipmatchlist_print(fp, indent + 2,
					view->topology);
		fprintf(fp, ";\n");
	}

	if (view->listens != NULL) {
		dns_c_lstnlist_print(fp, indent + 1, view->listens);
	}

	if (view->ordering != NULL) {
		dns_c_rrsolist_print(fp, indent + 1, view->ordering);
	}

	if (DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT, &view->setflags)) {
		nameseverity = view->check_names[dns_trans_primary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_primary,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_SEC_BIT, &view->setflags)) {
		nameseverity = view->check_names[dns_trans_secondary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_secondary,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_RESP_BIT, &view->setflags)) {
		nameseverity = view->check_names[dns_trans_response];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_response,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}


	if (DNS_C_CHECKBIT(TRANSFER_FORMAT_BIT, &view->setflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(view->transfer_format,
						 ISC_TRUE));
	}
		

	fprintf(fp, "\n");
	


	/* XXXJAB rest of view fields */

	if (view->zonelist != NULL) {
		dns_c_zonelist_print(fp, indent + 1, view->zonelist);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_view_setallowquery(dns_c_view_t *view,
			 dns_c_ipmatchlist_t *ipml,
			 isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->allowquery != NULL) {
		dns_c_ipmatchlist_detach(&view->allowquery);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->allowquery, ipml);
	} else {
		view->allowquery = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

isc_result_t
dns_c_view_setallowtransfer(dns_c_view_t *view,
			    dns_c_ipmatchlist_t *ipml,
			    isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->transferacl != NULL) {
		dns_c_ipmatchlist_detach(&view->transferacl);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->transferacl, ipml);
	} else {
		view->transferacl = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

isc_result_t
dns_c_view_setallowrecursion(dns_c_view_t *view,
			     dns_c_ipmatchlist_t *ipml,
			     isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->recursionacl != NULL) {
		dns_c_ipmatchlist_detach(&view->recursionacl);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->recursionacl, ipml);
	} else {
		view->recursionacl = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

isc_result_t
dns_c_view_setallowupdateforwarding(dns_c_view_t *view,
				    dns_c_ipmatchlist_t *ipml,
				    isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->allowupdateforwarding != NULL) {
		dns_c_ipmatchlist_detach(&view->allowupdateforwarding);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->allowupdateforwarding,
					     ipml);
	} else {
		view->allowupdateforwarding = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

isc_result_t
dns_c_view_setblackhole(dns_c_view_t *view,
			dns_c_ipmatchlist_t *ipml,
			isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->blackhole != NULL) {
		dns_c_ipmatchlist_detach(&view->blackhole);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->blackhole, ipml);
	} else {
		view->blackhole = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

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
		view->forwarders = ipl;
		res = ISC_R_SUCCESS;
	}

	if (res == ISC_R_SUCCESS) {
		return (existed ? ISC_R_EXISTS : res);
	} else {
		return (res);
	}
}
		
	

isc_result_t
dns_c_view_setsortlist(dns_c_view_t *view,
		       dns_c_ipmatchlist_t *ipml,
		       isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->sortlist != NULL) {
		dns_c_ipmatchlist_detach(&view->sortlist);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->sortlist, ipml);
	} else {
		view->sortlist = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}
	

isc_result_t
dns_c_view_settopology(dns_c_view_t *view,
		       dns_c_ipmatchlist_t *ipml,
		       isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	if (view->topology != NULL) {
		dns_c_ipmatchlist_detach(&view->topology);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(view->mem,
					     &view->topology, ipml);
	} else {
		view->topology = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}


isc_result_t
dns_c_view_getallowquery(dns_c_view_t *view, dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->allowquery;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}

isc_result_t dns_c_view_getallowtransfer(dns_c_view_t *view,
					 dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->transferacl;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_getallowrecursion(dns_c_view_t *view,
					  dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->recursionacl;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_getallowupdateforwarding(dns_c_view_t *view,
						 dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->allowupdateforwarding;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_getblackhole(dns_c_view_t *view,
				     dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->blackhole;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_getforwarders(dns_c_view_t *view,
				      dns_c_iplist_t **ipl)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipl != NULL);
	
	*ipl = view->forwarders;

	return (*ipl == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_getsortlist(dns_c_view_t *view,
				    dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->sortlist;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	
isc_result_t dns_c_view_gettopology(dns_c_view_t *view,
				    dns_c_ipmatchlist_t **ipml)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ipml != NULL);
	
	*ipml = view->topology;

	return (*ipml == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}
	


isc_result_t
dns_c_view_getallowqueryexpanded(isc_mem_t *mem,
				 dns_c_view_t *view,
				 dns_c_acltable_t *acltable,
				 dns_c_ipmatchlist_t **retval)
{
	dns_c_ipmatchlist_t *newlist;
	isc_result_t r;

	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(DNS_C_CONFACLTABLE_VALID(acltable));
	REQUIRE(retval != NULL);
	
	if (view->allowquery == NULL) {
		newlist = NULL;
		r = ISC_R_SUCCESS;
	} else {
		r = dns_c_ipmatchlist_copy(mem, &newlist, view->allowquery);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		r = dns_c_acl_expandacls(acltable, newlist);
	}

	*retval = newlist;
	
	return (r);
}



isc_result_t
dns_c_view_delete(dns_c_view_t **viewptr)
{
	dns_c_view_t *view;
	
	REQUIRE(viewptr != NULL);
	REQUIRE(DNS_C_VIEW_VALID(*viewptr));

	view = *viewptr;

	isc_mem_free(view->mem, view->name);
	
	if (view->allowquery != NULL)
		dns_c_ipmatchlist_detach(&view->allowquery);

	if (view->transferacl != NULL)
		dns_c_ipmatchlist_detach(&view->transferacl);

	if (view->recursionacl != NULL)
		dns_c_ipmatchlist_detach(&view->recursionacl);

	if (view->allowupdateforwarding != NULL)
		dns_c_ipmatchlist_detach(&view->allowupdateforwarding);

	if (view->blackhole != NULL)
		dns_c_ipmatchlist_detach(&view->blackhole);

	if (view->forwarders != NULL)
		dns_c_iplist_detach(&view->forwarders);

	if (view->sortlist != NULL)
		dns_c_ipmatchlist_detach(&view->sortlist);

	if (view->topology != NULL)
		dns_c_ipmatchlist_detach(&view->topology);

	if (view->listens != NULL) {
		dns_c_lstnlist_delete(&view->listens);
	}
	
	if (view->ordering != NULL) {
		dns_c_rrsolist_delete(&view->ordering);
	}
		
	if (view->zonelist != NULL) {
		dns_c_zonelist_delete(&view->zonelist);
	}

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
dns_c_view_addlisten_on(dns_c_view_t *view, in_port_t port,
			dns_c_ipmatchlist_t *ml,
		       isc_boolean_t copy)
{
	dns_c_lstnon_t *lo;
	isc_result_t res;

	REQUIRE(DNS_C_VIEW_VALID(view));

	if (view->listens == NULL) {
		res = dns_c_lstnlist_new(view->mem, &view->listens);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}

	res = dns_c_lstnon_new(view->mem, &lo);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	lo->port = port;
	res = dns_c_lstnon_setiml(lo, ml, copy);

	ISC_LIST_APPEND(view->listens->elements, lo, next);

	return (res);
}



isc_result_t
dns_c_view_getlistenlist(dns_c_view_t *view, dns_c_lstnlist_t **ll)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(ll != NULL);

	*ll = NULL;

	if (view->listens != NULL) {
		*ll = view->listens;
	}

	return (*ll == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}

isc_result_t dns_c_view_setrrsetorderlist(dns_c_view_t *view,
					  isc_boolean_t copy,
					  dns_c_rrsolist_t *olist)
{
	isc_boolean_t existed;
	isc_result_t res;

	REQUIRE(DNS_C_VIEW_VALID(view));

	existed = (view->ordering == NULL ? ISC_FALSE : ISC_TRUE);
	
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

					  


isc_result_t dns_c_view_getrrsetorderlist(dns_c_view_t *view,
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
dns_c_view_setchecknames(dns_c_view_t *view,
			 dns_c_trans_t transtype,
			 dns_severity_t sever)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_VIEW_VALID(view));

	switch(transtype) {
	case dns_trans_primary:
		existed = DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT,
					 &view->setflags);
		DNS_C_SETBIT(CHECKNAME_PRIM_BIT, &view->setflags);
		break;

	case dns_trans_secondary:
		existed = DNS_C_CHECKBIT(CHECKNAME_SEC_BIT,
					 &view->setflags);
		DNS_C_SETBIT(CHECKNAME_SEC_BIT, &view->setflags);
		break;

	case dns_trans_response:
		existed = DNS_C_CHECKBIT(CHECKNAME_RESP_BIT,
					 &view->setflags);
		DNS_C_SETBIT(CHECKNAME_RESP_BIT, &view->setflags);
		break;

	default:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}
	
	view->check_names[transtype] = sever;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}



isc_result_t
dns_c_view_getchecknames(dns_c_view_t *view,
			 dns_c_trans_t transtype,
			 dns_severity_t *sever)
{
	isc_boolean_t isset = ISC_FALSE;
	isc_result_t res;

	REQUIRE(DNS_C_VIEW_VALID(view));

	REQUIRE(sever != NULL);

	switch (transtype) {
	case dns_trans_primary:
		isset = DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT,
				       &view->setflags);
		break;

	case dns_trans_secondary:
		isset = DNS_C_CHECKBIT(CHECKNAME_SEC_BIT,
				       &view->setflags);
		break;

	case dns_trans_response:
		isset = DNS_C_CHECKBIT(CHECKNAME_RESP_BIT,
				       &view->setflags);
		break;

	default:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}

	if (isset) {
		*sever = view->check_names[transtype];
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t dns_c_view_settransferformat(dns_c_view_t *view,
					  dns_transfer_format_t format)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_VIEW_VALID(view));

	existed = DNS_C_CHECKBIT(TRANSFER_FORMAT_BIT,
				 &view->setflags);
	DNS_C_SETBIT(TRANSFER_FORMAT_BIT, &view->setflags);
	
	view->transfer_format = format;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t dns_c_view_gettransferformat(dns_c_view_t *view,
					  dns_transfer_format_t *format)
{
	REQUIRE(DNS_C_VIEW_VALID(view));
	REQUIRE(format != NULL);
	

	if (!DNS_C_CHECKBIT(TRANSFER_FORMAT_BIT, &view->setflags)) {
		return (ISC_R_NOTFOUND);
	}

	*format = view->transfer_format;

	return (ISC_R_SUCCESS);
}

		

