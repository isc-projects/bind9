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

#ifndef DNS_CONFIG_CONFCTX_H
#define DNS_CONFIG_CONFCTX_H 1

/*****
 ***** Module Info
 *****/

/*
 * Defines the structures and accessor/modifier functions for the top level 
 * structures created by the config file parsing routines.
 */

/*
 *
 * MP:
 *	
 *
 * Reliability:
 *	
 *
 * Resources:
 *	
 *
 * Security:
 *	
 *
 * Standards:
 *	
 */

/***
 *** Imports
 ***/

#include <config.h>

#include <isc/mem.h>
#include <isc/int.h>
#include <isc/list.h>

#include <dns/confcommon.h>
#include <dns/confip.h>
#include <dns/confzone.h>
#include <dns/confkeys.h>
#include <dns/conflog.h>
#include <dns/confacl.h>
#include <dns/conflsn.h>
#include <dns/confrrset.h>
#include <dns/confctl.h>
#include <dns/confserv.h>
#include <dns/confview.h>
#include <dns/confcache.h>
#include <dns/confresolv.h>


/***
 *** Types
 ***/

typedef struct dns_c_options		dns_c_options_t;
typedef struct dns_c_ctx		dns_c_ctx_t;


/*
 * The main baby. A pointer to one of these is what the caller gets back
 * when the parsing routine is called.
 */
struct dns_c_ctx
{
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	int			warnings; /* semantic warning count */
	int			errors;	/* semantic error count */
	
	dns_c_options_t	       *options;
	dns_c_cache_t	       *cache;
	dns_c_resolv_t	       *resolver;
	dns_c_ctrllist_t       *controls;
	dns_c_srvlist_t	       *servers;
	dns_c_acltable_t       *acls;
	dns_c_kdeflist_t       *keydefs;
	dns_c_zonelist_t       *zlist;
	dns_c_tkeylist_t       *trusted_keys;
	dns_c_logginglist_t    *logging;
	dns_c_viewtable_t      *views;

	dns_c_zone_t	       *currzone;
	dns_c_view_t	       *currview;
};




/*
 * This structure holds all the values defined by a config file 'options'
 * statement
 */
struct dns_c_options 
{
	isc_mem_t	       *mem;
	isc_uint32_t		magic;
	
	char		       *directory;
	char		       *version;
	char		       *dump_filename;
	char		       *pid_filename;
	char		       *stats_filename;
	char		       *memstats_filename;
	char		       *named_xfer;
	char 		       *tkeydomain;

	char 		       *tkeydhkeycp;
	isc_int32_t		tkeydhkeyi;
	
	isc_uint32_t		flags;
	isc_uint32_t		max_ncache_ttl;

	isc_int32_t		transfers_in;
	isc_int32_t		transfers_per_ns;
	isc_int32_t		transfers_out;
	isc_int32_t		max_log_size_ixfr;
	isc_int32_t		clean_interval;
	isc_int32_t		interface_interval;
	isc_int32_t		stats_interval;
	isc_int32_t		heartbeat_interval;

	isc_int32_t		max_transfer_time_in;
	isc_int32_t		lamettl; /* XXX not implemented yet */
	

	isc_uint32_t		data_size;
	isc_uint32_t		stack_size;
	isc_uint32_t		core_size;
	isc_uint32_t		files;

	isc_boolean_t		expert_mode;
	isc_boolean_t		fake_iquery;
	isc_boolean_t		recursion;
	isc_boolean_t		fetch_glue;
	isc_boolean_t		notify;
	isc_boolean_t		host_statistics;
	isc_boolean_t		dealloc_on_exit;
	isc_boolean_t		use_ixfr;
	isc_boolean_t		maintain_ixfr_base;
	isc_boolean_t		has_old_clients;
	isc_boolean_t		auth_nx_domain;
	isc_boolean_t		multiple_cnames;
	isc_boolean_t		use_id_pool;
	isc_boolean_t		dialup;
	isc_boolean_t		rfc2038type1; /* XXX not implemented yet */
	
	isc_sockaddr_t		query_source_addr;
	short			query_source_port;

	dns_c_severity_t	check_names[DNS_C_TRANSCOUNT];

	dns_transfer_format_t	transfer_format;

	dns_c_ipmatchlist_t   *queryacl;
	dns_c_ipmatchlist_t   *transferacl;
	dns_c_ipmatchlist_t   *recursionacl;
	dns_c_ipmatchlist_t   *blackhole;
	dns_c_ipmatchlist_t   *topology;
	dns_c_ipmatchlist_t   *sortlist;

	dns_c_lstnlist_t      *listens;

	dns_c_forw_t		forward;
	dns_c_ipmatchlist_t   *forwarders;

	dns_c_rrsolist_t      *ordering;

	/*
	 * For the non-pointer fields of the struct a bit will be set in
	 * this field if a field value was explicitly set.
	 */
	dns_c_setbits_t		setflags1;
};



/***
 *** Functions
 ***/


isc_result_t	dns_c_ctx_new(isc_log_t *lctx,
			      isc_mem_t *mem, dns_c_ctx_t **cfg);
isc_result_t	dns_c_ctx_delete(isc_log_t *lctx,
				 dns_c_ctx_t **cfg);
isc_result_t	dns_c_ctx_getoptions(isc_log_t *lctx,
				     dns_c_ctx_t *cfg,
				     dns_c_options_t **options);
isc_result_t	dns_c_ctx_setlogging(isc_log_t *lctx,
				     dns_c_ctx_t *cfg,
				     dns_c_logginglist_t *newval,
				     isc_boolean_t deepcopy);
isc_result_t	dns_c_ctx_getlogging(isc_log_t *lctx,
				     dns_c_ctx_t *cfg,
				     dns_c_logginglist_t **retval);
isc_result_t	dns_c_ctx_addfile_channel(isc_log_t *lctx,
					  dns_c_ctx_t *cfg, const char *name,
					  dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addsyslogchannel(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   const char *name,
					   dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addnullchannel(isc_log_t *lctx,
					 dns_c_ctx_t *cfg, const char *name,
					 dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addcategory(isc_log_t *lctx,
				      dns_c_ctx_t *cfg,
				      dns_c_category_t category,
				      dns_c_logcat_t **newcat);
isc_result_t	dns_c_ctx_currchannel(isc_log_t *lctx,
				      dns_c_ctx_t *cfg,
				      dns_c_logchan_t **channel);
isc_result_t	dns_c_ctx_currcategory(isc_log_t *lctx,
				       dns_c_ctx_t *cfg,
				       dns_c_logcat_t **category);
isc_boolean_t	dns_c_ctx_keydefinedp(isc_log_t *lctx,
				      dns_c_ctx_t *ctx, const char *keyname);



isc_boolean_t	dns_c_ctx_channeldefinedp(isc_log_t *lctx,
					  dns_c_ctx_t *cfg,
					  const char *name);
isc_result_t	dns_c_ctx_optionsnew(isc_log_t *lctx,
				     isc_mem_t *mem,
				     dns_c_options_t **options);
isc_result_t	dns_c_ctx_optionsdelete(isc_log_t *lctx,
					dns_c_options_t **options);
isc_result_t	dns_c_ctx_erase_options(isc_log_t *lctx,
					dns_c_ctx_t *cfg);
void		dns_c_ctx_print(isc_log_t *lctx,
				FILE *fp, int indent, dns_c_ctx_t *cfg);
void		dns_c_ctx_optionsprint(isc_log_t *lctx,
				       FILE *fp, int indent,
				       dns_c_options_t *options);
void		dns_c_ctx_forwarderprint(isc_log_t *lctx,
					 FILE *fp, int indent,
					 dns_c_options_t *options);



/* The modifier functions below all return ISC_R_SUCCESS when the value is
 * successfully set. If the value had already been set, then the value
 * ISC_R_EXISTS is returned (the value is still set).
 *
 * In a few functions there is a boolean parameter named 'copy'. If that is
 * true, then a deep copy is made of the parameter and the parameter itself
 * is not touched. If the value is false, then the parameter is stored
 * directly in the dns_c_ctx_t structure, and the client looses ownership
 * of it. ISC_R_NOMEMORY is a possible return value for many of these
 * functions.
 *
 */
isc_result_t	dns_c_ctx_setcurrzone(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, dns_c_zone_t *zone);
isc_result_t	dns_c_ctx_setcurrview(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, dns_c_view_t *view);
isc_result_t	dns_c_ctx_setdirectory(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_setversion(isc_log_t *lctx,
				     dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_setdumpfilename(isc_log_t *lctx,
					  dns_c_ctx_t *cfg,
					  const char *newval);
isc_result_t	dns_c_ctx_setpidfilename(isc_log_t *lctx,
					 dns_c_ctx_t *cfg,
					 const char *newval);
isc_result_t	dns_c_ctx_setstatsfilename(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   const char *newval);
isc_result_t	dns_c_ctx_setmemstatsfilename(isc_log_t *lctx,
					      dns_c_ctx_t *cfg,
					      const char *newval);
isc_result_t	dns_c_ctx_setnamedxfer(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_settkeydomain(isc_log_t *lctx,
					dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_settkeydhkey(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       const char *newcpval,
				       isc_int32_t newival);
isc_result_t	dns_c_ctx_setmaxncachettl(isc_log_t *lctx,
					  dns_c_ctx_t *cfg,
					  isc_uint32_t newval);
isc_result_t	dns_c_ctx_settransfersin(isc_log_t *lctx,
					 dns_c_ctx_t *cfg,
					 isc_int32_t newval);
isc_result_t	dns_c_ctx_settransfersperns(isc_log_t *lctx,
					    dns_c_ctx_t *cfg,
					    isc_int32_t newval);
isc_result_t	dns_c_ctx_settransfersout(isc_log_t *lctx,
					  dns_c_ctx_t *cfg,
					  isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxlogsizeixfr(isc_log_t *lctx,
					    dns_c_ctx_t *cfg,
					    isc_int32_t newval);
isc_result_t	dns_c_ctx_setcleaninterval(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   isc_int32_t newval);
isc_result_t	dns_c_ctx_setinterfaceinterval(isc_log_t *lctx,
					       dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setstatsinterval(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   isc_int32_t newval);
isc_result_t	dns_c_ctx_setheartbeat_interval(isc_log_t *lctx,
						dns_c_ctx_t *cfg,
						isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxtransfertimein(isc_log_t *lctx,
					       dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setdatasize(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_setstacksize(isc_log_t *lctx,
				       dns_c_ctx_t *cfg,
				       isc_uint32_t newval);
isc_result_t	dns_c_ctx_setcoresize(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_setfiles(isc_log_t *lctx,
				   dns_c_ctx_t *cfg, isc_uint32_t newval);

isc_result_t	dns_c_ctx_setexpertmode(isc_log_t *lctx,
					dns_c_ctx_t *cfg,
					isc_boolean_t newval);
isc_result_t	dns_c_ctx_setfakeiquery(isc_log_t *lctx,
					dns_c_ctx_t *cfg,
					isc_boolean_t newval);
isc_result_t	dns_c_ctx_setrecursion(isc_log_t *lctx,
				       dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setfetchglue(isc_log_t *lctx,
				       dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setnotify(isc_log_t *lctx,
				    dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_sethoststatistics(isc_log_t *lctx,
					    dns_c_ctx_t *cfg,
					    isc_boolean_t newval);
isc_result_t	dns_c_ctx_setdealloconexit(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   isc_boolean_t newval);
isc_result_t	dns_c_ctx_setuseixfr(isc_log_t *lctx,
				     dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_setmaintainixfrbase(isc_log_t *lctx,
					      dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_sethasoldclients(isc_log_t *lctx,
					   dns_c_ctx_t *cfg,
					   isc_boolean_t newval);
isc_result_t	dns_c_ctx_setauthnxdomain(isc_log_t *lctx,
					  dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_setmultiplecnames(isc_log_t *lctx,
					    dns_c_ctx_t *cfg,
					    isc_boolean_t newval);
isc_result_t	dns_c_ctx_setuseidpool(isc_log_t *lctx,
				       dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setdialup(isc_log_t *lctx,
				    dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_setquerysourceaddr(isc_log_t *lctx,
					     dns_c_ctx_t *cfg,
					     isc_sockaddr_t addr);
isc_result_t	dns_c_ctx_setquerysourceport(isc_log_t *lctx,
					     dns_c_ctx_t *cfg, short port);
isc_result_t	dns_c_ctx_setchecknames(isc_log_t *lctx,
					dns_c_ctx_t *cfg,
					dns_c_trans_t transtype,
					dns_c_severity_t sever);
isc_result_t	dns_c_ctx_settransferformat(isc_log_t *lctx,
					    dns_c_ctx_t *cfg,
					    dns_transfer_format_t newval);
isc_result_t	dns_c_ctx_setqueryacl(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_settransferacl(isc_log_t *lctx,
					 dns_c_ctx_t *cfg, isc_boolean_t copy,
					 dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setrecursionacl(isc_log_t *lctx,
					  dns_c_ctx_t *cfg, isc_boolean_t copy,
					  dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setblackhole(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, isc_boolean_t copy,
				       dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_settopology(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setsortlist(isc_log_t *lctx,
				      dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setforward(isc_log_t *lctx,
				     dns_c_ctx_t *cfg, dns_c_forw_t forw);
isc_result_t	dns_c_ctx_setforwarders(isc_log_t *lctx, dns_c_ctx_t *cfg,
					dns_c_ipmatchlist_t *iml,
					isc_boolean_t copy);
isc_result_t	dns_c_ctx_setrrsetorderlist(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_boolean_t copy,
					    dns_c_rrsolist_t *olist);

isc_result_t	dns_c_ctx_addlisten_on(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, int port,
				       dns_c_ipmatchlist_t *ml,
				       isc_boolean_t copy);
isc_result_t	dns_c_ctx_settrustedkeys(isc_log_t *lctx,
					 dns_c_ctx_t *cfg,
					 dns_c_tkeylist_t *list,
					 isc_boolean_t copy);








/*
 * Accessor functions for the various fields in the config structure. The
 * value of the field is copied into the location pointed to by the RETVAL
 * paramater and ISC_R_SUCCESS is returned. The caller must not modify the
 * returned value, and should copy the value if it needs to hold on to it.
 *
 * If the value has not been set in the config structure, then
 * ISC_R_NOTFOUND is returned and the location pointed to by the RETVAL
 * paramater is not modified (i.e. the library assumes no particular
 * defaults for any unset values).
 */


dns_c_zone_t   *dns_c_ctx_getcurrzone(isc_log_t *lctx, dns_c_ctx_t *cfg);
dns_c_view_t   *dns_c_ctx_getcurrview(isc_log_t *lctx, dns_c_ctx_t *cfg);
isc_result_t	dns_c_ctx_getdirectory(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getversion(isc_log_t *lctx,
				     dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getdumpfilename(isc_log_t *lctx,
					  dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getpidfilename(isc_log_t *lctx,
					 dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getstatsfilename(isc_log_t *lctx,
					   dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getmemstatsfilename(isc_log_t *lctx,
					      dns_c_ctx_t *cfg,
					      char **retval);
isc_result_t	dns_c_ctx_getnamedxfer(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_gettkeydomain(isc_log_t *lctx,
				       dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_gettkeydhkey(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       char **retcpval, isc_int32_t *retival);
isc_result_t	dns_c_ctx_getmaxncachettl(isc_log_t *lctx, dns_c_ctx_t *cfg,
					  isc_uint32_t *retval);
isc_result_t	dns_c_ctx_gettransfersin(isc_log_t *lctx, dns_c_ctx_t *cfg,
					 isc_int32_t *retval);
isc_result_t	dns_c_ctx_gettransfersperns(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_int32_t *retval);
isc_result_t	dns_c_ctx_gettransfersout(isc_log_t *lctx, dns_c_ctx_t *cfg,
					  isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxlogsizeixfr(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_int32_t *retval);
isc_result_t	dns_c_ctx_getcleaninterval(isc_log_t *lctx, dns_c_ctx_t *cfg,
					   isc_int32_t *retval);
isc_result_t	dns_c_ctx_getinterfaceinterval(isc_log_t *lctx,
					       dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getstatsinterval(isc_log_t *lctx, dns_c_ctx_t *cfg,
					   isc_int32_t *retval);
isc_result_t	dns_c_ctx_getheartbeatinterval(isc_log_t *lctx,
					       dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxtransfertimein(isc_log_t *lctx,
					       dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getdatasize(isc_log_t *lctx, dns_c_ctx_t *cfg,
				      isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getstacksize(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getcoresize(isc_log_t *lctx, dns_c_ctx_t *cfg,
				      isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getfiles(isc_log_t *lctx,
				   dns_c_ctx_t *cfg, isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_expert_mode(isc_log_t *lctx, dns_c_ctx_t *cfg,
					  isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getfakeiquery(isc_log_t *lctx, dns_c_ctx_t *cfg,
					isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getrecursion(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getfetchglue(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getnotify(isc_log_t *lctx,
				    dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_gethoststatistics(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getdealloconexit(isc_log_t *lctx, dns_c_ctx_t *cfg,
					   isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getuseixfr(isc_log_t *lctx, dns_c_ctx_t *cfg,
				     isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getmaintainixfrbase(isc_log_t *lctx,
					      dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_gethasoldclients(isc_log_t *lctx, dns_c_ctx_t *cfg,
					   isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getauth_nx_domain(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getmultiplecnames(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getuseidpool(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getdialup(isc_log_t *lctx,
				    dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getquerysourceaddr(isc_log_t *lctx, dns_c_ctx_t *cfg,
					     isc_sockaddr_t *addr);
isc_result_t	dns_c_ctx_getquerysourceport(isc_log_t *lctx, dns_c_ctx_t *cfg,
					     short *port);
isc_result_t	dns_c_ctx_getchecknames(isc_log_t *lctx, dns_c_ctx_t *cfg,
					dns_c_trans_t transtype,
					dns_c_severity_t *sever);
isc_result_t	dns_c_ctx_gettransferformat(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    dns_transfer_format_t *retval);
isc_result_t	dns_c_ctx_getqueryacl(isc_log_t *lctx, dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_gettransferacl(isc_log_t *lctx, dns_c_ctx_t *cfg,
					 dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getrecursionacl(isc_log_t *lctx, dns_c_ctx_t *cfg,
					  dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getblackhole(isc_log_t *lctx, dns_c_ctx_t *cfg,
				       dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_gettopology(isc_log_t *lctx, dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getsortlist(isc_log_t *lctx, dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getlistenlist(isc_log_t *lctx, dns_c_ctx_t *cfg,
					dns_c_lstnlist_t **ll);
isc_result_t	dns_c_ctx_getforward(isc_log_t *lctx,
				     dns_c_ctx_t *cfg, dns_c_forw_t *forw);
isc_result_t	dns_c_ctx_getforwarders(isc_log_t *lctx, dns_c_ctx_t *cfg,
					dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getrrsetorderlist(isc_log_t *lctx, dns_c_ctx_t *cfg,
					    dns_c_rrsolist_t **olist);
isc_result_t	dns_c_ctx_gettrustedkeys(isc_log_t *lctx, dns_c_ctx_t *cfg,
					 dns_c_tkeylist_t **retval);
isc_result_t	dns_c_ctx_getlogging(isc_log_t *lctx, dns_c_ctx_t *cfg,
				     dns_c_logginglist_t **retval);





#endif /* DNS_CONFIG_CONFCTX_H */
