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

#ifndef DNS_CONFIG_CONFZONE_H
#define DNS_CONFIG_CONFZONE_H 1

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

/***
 *** Types
 ***/

typedef struct dns_c_master_zone	dns_c_masterzone_t;
typedef struct dns_c_slave_zone		dns_c_slavezone_t;
typedef struct dns_c_stub_zone		dns_c_stubzone_t;
typedef struct dns_c_forward_zone	dns_c_forwardzone_t;
typedef struct dns_c_hint_zone		dns_c_hintzone_t;
typedef struct dns_c_zone		dns_c_zone_t;
typedef struct dns_c_zone_list		dns_c_zonelist_t;

struct dns_c_zone_list
{
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_zone_t)	zones;
};


struct dns_c_master_zone
{
	char		       *file;
	dns_c_severity_t	check_names;
	dns_c_ipmatchlist_t    *allow_update;
	dns_c_ipmatchlist_t    *allow_query;
	dns_c_ipmatchlist_t    *allow_transfer;
	isc_boolean_t		dialup;
	isc_boolean_t		notify;
	dns_c_iplist_t	       *also_notify;
	char		       *ixfr_base;
	char		       *ixfr_tmp;
	isc_int32_t		max_ixfr_log;
	isc_boolean_t		maint_ixfr_base;
	dns_c_pubkey_t	       *pubkey;

	dns_c_setbits_t		setflags;
};


struct dns_c_slave_zone
{
	char		       *file;
	dns_c_severity_t	check_names;
	dns_c_ipmatchlist_t    *allow_update;
	dns_c_ipmatchlist_t    *allow_query;
	dns_c_ipmatchlist_t    *allow_transfer;
	dns_c_iplist_t	       *also_notify;
	isc_boolean_t		notify;
	isc_boolean_t		dialup;
	char		       *ixfr_base;
	char		       *ixfr_tmp;
	isc_boolean_t		maint_ixfr_base;
	isc_int32_t		max_ixfr_log;
	dns_c_pubkey_t	       *pubkey;
	in_port_t		master_port;
	dns_c_iplist_t	       *master_ips;
	isc_sockaddr_t		transfer_source;
	isc_int32_t		max_trans_time_in;

	dns_c_setbits_t		setflags;
};


struct dns_c_stub_zone
{
	char		       *file;
	dns_c_severity_t	check_names;
	dns_c_ipmatchlist_t    *allow_update; /* should be here??? */
	dns_c_ipmatchlist_t    *allow_query;
	dns_c_ipmatchlist_t    *allow_transfer; /* should be here??? */
	isc_boolean_t		dialup;
	dns_c_pubkey_t	       *pubkey;
	in_port_t		master_port;
	dns_c_iplist_t	       *master_ips;
	isc_sockaddr_t		transfer_source; 
	isc_int32_t		max_trans_time_in;

	dns_c_setbits_t		setflags;
};



struct dns_c_forward_zone
{
	dns_c_severity_t	check_names;
	dns_c_forw_t		forward;
	dns_c_iplist_t	       *forwarders;

	dns_c_setbits_t		setflags;
};


struct dns_c_hint_zone
{
	char		       *file;
	dns_c_severity_t	check_names;

	dns_c_setbits_t		setflags;
};


struct dns_c_zone
{
	dns_c_zonelist_t	       *mylist;

	char			       *name;
	dns_rdataclass_t		zclass; 
	
	dns_c_zonetype_t		ztype;
	union 
	{
		dns_c_masterzone_t	mzone;
		dns_c_slavezone_t	szone;
		dns_c_stubzone_t	tzone;
		dns_c_forwardzone_t	fzone;
		dns_c_hintzone_t	hzone;
	} u;

	isc_boolean_t			afteropts;

	ISC_LINK(dns_c_zone_t)		next;
};


/***
 *** Functions
 ***/

isc_result_t	dns_c_zonelist_new(isc_log_t *lctx, isc_mem_t *mem,
				   dns_c_zonelist_t **zlist);
isc_result_t	dns_c_zonelist_delete(isc_log_t *lctx,
				      dns_c_zonelist_t **zlist);
isc_result_t	dns_c_zonelist_find(isc_log_t *lctx, dns_c_zonelist_t *zlist,
				    const char *name, dns_c_zone_t **retval);
isc_result_t	dns_c_zonelist_rmbyname(isc_log_t *lctx,
					dns_c_zonelist_t *zlist,
					const char *name);
isc_result_t	dns_c_zonelist_rmzone(isc_log_t *lctx, dns_c_zonelist_t *zlist,
				      dns_c_zone_t *zone);
void		dns_c_zonelist_print(isc_log_t *lctx, FILE *fp, int indent,
				     dns_c_zonelist_t *list);
void		dns_c_zonelist_printpostopts(isc_log_t *lctx, FILE *fp,
					     int indent,
					     dns_c_zonelist_t *list);
void		dns_c_zonelist_printpreopts(isc_log_t *lctx, FILE *fp,
					    int indent,
					    dns_c_zonelist_t *list);
isc_result_t	dns_c_zone_new(isc_log_t *lctx, dns_c_zonelist_t *zlist,
			       dns_c_zonetype_t ztype, dns_rdataclass_t zclass,
			       const char *name,
			       dns_c_zone_t **zone);
void		dns_c_zone_print(isc_log_t *lctx, FILE *fp, int indent,
				 dns_c_zone_t *zone);
isc_result_t	dns_c_zone_setfile(isc_log_t *lctx, dns_c_zone_t *zone,
				   const char *newfile);
isc_result_t	dns_c_zone_setchecknames(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_severity_t severity);
isc_result_t	dns_c_zone_setallowupd(isc_log_t *lctx, dns_c_zone_t *zone,
				       dns_c_ipmatchlist_t *ipml,
				       isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_setallowquery(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_ipmatchlist_t *ipml,
					 isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_setallowtransfer(isc_log_t *lctx,
					    dns_c_zone_t *zone,
					    dns_c_ipmatchlist_t *ipml,
					    isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_setdialup(isc_log_t *lctx, dns_c_zone_t *zone,
				     isc_boolean_t newval);
isc_result_t	dns_c_zone_setnotify(isc_log_t *lctx, dns_c_zone_t *zone,
				     isc_boolean_t newval);
isc_result_t	dns_c_zone_setmaintixfrbase(isc_log_t *lctx,
					    dns_c_zone_t *zone,
					    isc_boolean_t newval);
isc_result_t	dns_c_zone_setalsonotify(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_iplist_t *newval,
					 isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_setixfrbase(isc_log_t *lctx, dns_c_zone_t *zone,
				       const char *newval);
isc_result_t	dns_c_zone_setixfrtmp(isc_log_t *lctx, dns_c_zone_t *zone,
				      const char *newval);
isc_result_t	dns_c_zone_setpubkey(isc_log_t *lctx, dns_c_zone_t *zone,
				     dns_c_pubkey_t *pubkey,
				     isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_setmasterport(isc_log_t *lctx, dns_c_zone_t *zone,
					 in_port_t port);
isc_result_t	dns_c_zone_setmasterips(isc_log_t *lctx, dns_c_zone_t *zone,
					dns_c_iplist_t *newval,
					isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_settransfersource(isc_log_t *lctx,
					     dns_c_zone_t *zone,
					     isc_sockaddr_t newval);
isc_result_t	dns_c_zone_setmaxtranstimein(isc_log_t *lctx,
					     dns_c_zone_t *zone,
					     isc_int32_t newval);
isc_result_t	dns_c_zone_setmaxixfrlog(isc_log_t *lctx, dns_c_zone_t *zone,
					 isc_int32_t new);
isc_result_t	dns_c_zone_setforward(isc_log_t *lctx, dns_c_zone_t *zone,
				      dns_c_forw_t newval);
isc_result_t	dns_c_zone_setforwarders(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_iplist_t *ipml,
					 isc_boolean_t deepcopy);
isc_result_t	dns_c_zone_getname(isc_log_t *lctx, dns_c_zone_t *zone,
				   const char **retval);
isc_result_t	dns_c_zone_getfile(isc_log_t *lctx, dns_c_zone_t *zone,
				   const char **retval);
isc_result_t	dns_c_zone_getchecknames(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_severity_t *retval);
isc_result_t	dns_c_zone_getallowupd(isc_log_t *lctx, dns_c_zone_t *zone,
				       dns_c_ipmatchlist_t **retval);
isc_result_t	dns_c_zone_getallowquery(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_ipmatchlist_t **retval);
isc_result_t	dns_c_zone_getallowtransfer(isc_log_t *lctx,
					    dns_c_zone_t *zone,
					    dns_c_ipmatchlist_t **retval);
isc_result_t	dns_c_zone_getdialup(isc_log_t *lctx, dns_c_zone_t *zone,
				     isc_boolean_t *retval);
isc_result_t	dns_c_zone_getnotify(isc_log_t *lctx, dns_c_zone_t *zone,
				     isc_boolean_t *retval);
isc_result_t	dns_c_zone_getmaintixfrbase(isc_log_t *lctx,
					    dns_c_zone_t *zone,
					    isc_boolean_t *retval);
isc_result_t	dns_c_zone_getalsonotify(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_iplist_t **retval);
isc_result_t	dns_c_zone_getixfrbase(isc_log_t *lctx, dns_c_zone_t *zone,
				       const char **retval);
isc_result_t	dns_c_zone_getixfrtmp(isc_log_t *lctx, dns_c_zone_t *zone,
				      const char **retval);
isc_result_t	dns_c_zone_getpubkey(isc_log_t *lctx, dns_c_zone_t *zone,
				     dns_c_pubkey_t **retval);
isc_result_t	dns_c_zone_getmasterport(isc_log_t *lctx, dns_c_zone_t *zone,
					 in_port_t *retval);
isc_result_t	dns_c_zone_getmasterips(isc_log_t *lctx, dns_c_zone_t *zone,
					dns_c_iplist_t **retval);
isc_result_t	dns_c_zone_gettransfersource(isc_log_t *lctx,
					     dns_c_zone_t *zone,
					     isc_sockaddr_t *retval);
isc_result_t	dns_c_zone_getmaxtranstimein(isc_log_t *lctx,
					     dns_c_zone_t *zone,
					     isc_int32_t *retval);
isc_result_t	dns_c_zone_getmaxixfrlog(isc_log_t *lctx, dns_c_zone_t *zone,
					 isc_int32_t *retval);
isc_result_t	dns_c_zone_getforward(isc_log_t *lctx, dns_c_zone_t *zone,
				      dns_c_forw_t *retval);
isc_result_t	dns_c_zone_getforwarders(isc_log_t *lctx, dns_c_zone_t *zone,
					 dns_c_iplist_t **retval);


#endif /* DNS_CONFIG_CONFZONE_H */
