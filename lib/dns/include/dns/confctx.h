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

#include <dns/peer.h>
#include <dns/confcommon.h>
#include <dns/confip.h>
#include <dns/confzone.h>
#include <dns/confkeys.h>
#include <dns/conflog.h>
#include <dns/confacl.h>
#include <dns/conflsn.h>
#include <dns/confrrset.h>
#include <dns/confctl.h>
#include <dns/confview.h>
#include <dns/confcache.h>
#include <dns/confresolv.h>

#define DNS_C_CONFIG_MAGIC		0x434f4e46U /* CONF */
#define DNS_C_OPTION_MAGIC		0x4f707473U /* Opts */

#define DNS_C_CONFCTX_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_CONFIG_MAGIC)
#define DNS_C_CONFOPT_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_OPTION_MAGIC)



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
	dns_peerlist_t	       *peers;
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
	isc_int32_t		max_transfer_time_out;
	isc_int32_t		max_transfer_idle_in;
	isc_int32_t		max_transfer_idle_out;
	isc_int32_t		lamettl; /* XXX not implemented yet */
	isc_int32_t		tcp_clients;
	isc_int32_t		recursive_clients;
	
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
	isc_boolean_t		rfc2308_type1;
	isc_boolean_t		request_ixfr;
	isc_boolean_t		provide_ixfr;
	
	isc_sockaddr_t		transfer_source;
	isc_sockaddr_t		transfer_source_v6;
	isc_sockaddr_t		query_source;
	isc_sockaddr_t		query_source_v6;

	dns_c_iplist_t	       *also_notify;

	dns_severity_t 		check_names[DNS_C_TRANSCOUNT];

	dns_transfer_format_t	transfer_format;

	dns_c_ipmatchlist_t   *queryacl;
	dns_c_ipmatchlist_t   *transferacl;
	dns_c_ipmatchlist_t   *recursionacl;
	dns_c_ipmatchlist_t   *blackhole;
	dns_c_ipmatchlist_t   *topology;
	dns_c_ipmatchlist_t   *sortlist;

	dns_c_lstnlist_t      *listens;

	dns_c_forw_t		forward;
	dns_c_iplist_t   *forwarders;

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

isc_result_t	dns_c_checkconfig(dns_c_ctx_t *ctx);




isc_result_t	dns_c_ctx_new(isc_mem_t *mem, dns_c_ctx_t **cfg);
isc_result_t	dns_c_ctx_delete(dns_c_ctx_t **cfg);

void		dns_c_ctx_print(FILE *fp, int indent, dns_c_ctx_t *cfg);
void		dns_c_ctx_optionsprint(FILE *fp, int indent,
				       dns_c_options_t *options);
void		dns_c_ctx_forwarderprint(FILE *fp, int indent,
					 dns_c_options_t *options);

isc_result_t    dns_c_ctx_getcontrols(dns_c_ctx_t *cfg,
                                      dns_c_ctrllist_t **ctrls);
isc_result_t	dns_c_ctx_setcontrols(dns_c_ctx_t *cfg,
				      dns_c_ctrllist_t *ctrls);
isc_result_t	dns_c_ctx_getoptions(dns_c_ctx_t *cfg,
				     dns_c_options_t **options);

isc_result_t	dns_c_ctx_setlogging(dns_c_ctx_t *cfg,
				     dns_c_logginglist_t *newval,
				     isc_boolean_t deepcopy);
isc_result_t	dns_c_ctx_getlogging(dns_c_ctx_t *cfg,
				     dns_c_logginglist_t **retval);

isc_result_t	dns_c_ctx_getkdeflist(dns_c_ctx_t *cfg,
                                      dns_c_kdeflist_t **retval);
isc_result_t	dns_c_ctx_setkdeflist(dns_c_ctx_t *cfg,
                                      dns_c_kdeflist_t *newval,
                                      isc_boolean_t deepcopy);


isc_result_t	dns_c_ctx_addfile_channel(dns_c_ctx_t *cfg, const char *name,
					  dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addsyslogchannel(dns_c_ctx_t *cfg,
					   const char *name,
					   dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addnullchannel(dns_c_ctx_t *cfg, const char *name,
					 dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_addcategory(dns_c_ctx_t *cfg,
				      const char *catname,
				      dns_c_logcat_t **newcat);
isc_result_t	dns_c_ctx_currchannel(dns_c_ctx_t *cfg,
				      dns_c_logchan_t **channel);
isc_result_t	dns_c_ctx_currcategory(dns_c_ctx_t *cfg,
				       dns_c_logcat_t **category);
isc_boolean_t	dns_c_ctx_keydefinedp(dns_c_ctx_t *ctx, const char *keyname);



isc_boolean_t	dns_c_ctx_channeldefinedp(dns_c_ctx_t *cfg,
					  const char *name);
isc_result_t	dns_c_ctx_optionsnew(isc_mem_t *mem,
				     dns_c_options_t **options);
isc_result_t	dns_c_ctx_optionsdelete(dns_c_options_t **options);



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
isc_result_t	dns_c_ctx_setcurrzone(dns_c_ctx_t *cfg, dns_c_zone_t *zone);
isc_result_t	dns_c_ctx_setcurrview(dns_c_ctx_t *cfg, dns_c_view_t *view);
isc_result_t	dns_c_ctx_setdirectory(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_setversion(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_setdumpfilename(dns_c_ctx_t *cfg,
					  const char *newval);
isc_result_t	dns_c_ctx_setpidfilename(dns_c_ctx_t *cfg,
					 const char *newval);
isc_result_t	dns_c_ctx_setstatsfilename(dns_c_ctx_t *cfg,
					   const char *newval);
isc_result_t	dns_c_ctx_setmemstatsfilename(dns_c_ctx_t *cfg,
					      const char *newval);
isc_result_t	dns_c_ctx_setnamedxfer(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_settkeydomain(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_settkeydhkey(dns_c_ctx_t *cfg,
				       const char *newcpval,
				       isc_int32_t newival);
isc_result_t	dns_c_ctx_setmaxncachettl(dns_c_ctx_t *cfg,
					  isc_uint32_t newval);
isc_result_t	dns_c_ctx_settransfersin(dns_c_ctx_t *cfg,
					 isc_int32_t newval);
isc_result_t	dns_c_ctx_settransfersperns(dns_c_ctx_t *cfg,
					    isc_int32_t newval);
isc_result_t	dns_c_ctx_settransfersout(dns_c_ctx_t *cfg,
					  isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxlogsizeixfr(dns_c_ctx_t *cfg,
					    isc_int32_t newval);
isc_result_t	dns_c_ctx_setcleaninterval(dns_c_ctx_t *cfg,
					   isc_int32_t newval);
isc_result_t	dns_c_ctx_setinterfaceinterval(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setstatsinterval(dns_c_ctx_t *cfg,
					   isc_int32_t newval);
isc_result_t	dns_c_ctx_setheartbeat_interval(dns_c_ctx_t *cfg,
						isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxtransfertimein(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxtransfertimeout(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxtransferidlein(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_setmaxtransferidleout(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_settcpclients(dns_c_ctx_t *cfg, isc_int32_t newval);
isc_result_t	dns_c_ctx_setrecursiveclients(dns_c_ctx_t *cfg,
					      isc_int32_t newval);

isc_result_t	dns_c_ctx_setdatasize(dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_setstacksize(dns_c_ctx_t *cfg,
				       isc_uint32_t newval);
isc_result_t	dns_c_ctx_setcoresize(dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_setfiles(dns_c_ctx_t *cfg, isc_uint32_t newval);

isc_result_t	dns_c_ctx_setexpertmode(dns_c_ctx_t *cfg,
					isc_boolean_t newval);
isc_result_t	dns_c_ctx_setfakeiquery(dns_c_ctx_t *cfg,
					isc_boolean_t newval);
isc_result_t	dns_c_ctx_setrecursion(dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setfetchglue(dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setnotify(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_sethoststatistics(dns_c_ctx_t *cfg,
					    isc_boolean_t newval);
isc_result_t	dns_c_ctx_setdealloconexit(dns_c_ctx_t *cfg,
					   isc_boolean_t newval);
isc_result_t	dns_c_ctx_setuseixfr(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_setmaintainixfrbase(dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_sethasoldclients(dns_c_ctx_t *cfg,
					   isc_boolean_t newval);
isc_result_t	dns_c_ctx_setauthnxdomain(dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_setmultiplecnames(dns_c_ctx_t *cfg,
					    isc_boolean_t newval);
isc_result_t	dns_c_ctx_setuseidpool(dns_c_ctx_t *cfg,
				       isc_boolean_t newval);
isc_result_t	dns_c_ctx_setrfc2308type1(dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_setrequestixfr(dns_c_ctx_t *cfg,
                                         isc_boolean_t newval);
isc_result_t	dns_c_ctx_setprovideixfr(dns_c_ctx_t *cfg,
                                         isc_boolean_t newval);
isc_result_t	dns_c_ctx_setdialup(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_setalsonotify(dns_c_ctx_t *ctx,
					dns_c_iplist_t *newval,
					isc_boolean_t deepcopy);
isc_result_t	dns_c_ctx_settransfersource(dns_c_ctx_t *ctx,
					    isc_sockaddr_t newval);
isc_result_t	dns_c_ctx_settransfersourcev6(dns_c_ctx_t *ctx,
					      isc_sockaddr_t newval);

isc_result_t	dns_c_ctx_setquerysource(dns_c_ctx_t *cfg,
					 isc_sockaddr_t addr);
isc_result_t	dns_c_ctx_setquerysourcev6(dns_c_ctx_t *cfg,
					   isc_sockaddr_t addr);
isc_result_t	dns_c_ctx_setchecknames(dns_c_ctx_t *cfg,
					dns_c_trans_t transtype,
					dns_severity_t sever);
isc_result_t	dns_c_ctx_settransferformat(dns_c_ctx_t *cfg,
					    dns_transfer_format_t newval);
isc_result_t	dns_c_ctx_setqueryacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_settransferacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
					 dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setrecursionacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
					  dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setblackhole(dns_c_ctx_t *cfg, isc_boolean_t copy,
				       dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_settopology(dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setsortlist(dns_c_ctx_t *cfg, isc_boolean_t copy,
				      dns_c_ipmatchlist_t *iml);
isc_result_t	dns_c_ctx_setforward(dns_c_ctx_t *cfg, dns_c_forw_t forw);
isc_result_t	dns_c_ctx_setforwarders(dns_c_ctx_t *cfg, isc_boolean_t copy,
					dns_c_iplist_t *iml);
isc_result_t	dns_c_ctx_setrrsetorderlist(dns_c_ctx_t *cfg,
					    isc_boolean_t copy,
					    dns_c_rrsolist_t *olist);

isc_result_t	dns_c_ctx_addlisten_on(dns_c_ctx_t *cfg, int port,
				       dns_c_ipmatchlist_t *ml,
				       isc_boolean_t copy);
isc_result_t	dns_c_ctx_settrustedkeys(dns_c_ctx_t *cfg,
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


dns_c_zone_t   *dns_c_ctx_getcurrzone(dns_c_ctx_t *cfg);
dns_c_view_t   *dns_c_ctx_getcurrview(dns_c_ctx_t *cfg);
isc_result_t	dns_c_ctx_getdirectory(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getversion(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getdumpfilename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getpidfilename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getstatsfilename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_getmemstatsfilename(dns_c_ctx_t *cfg,
					      char **retval);
isc_result_t	dns_c_ctx_getnamedxfer(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_gettkeydomain(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_gettkeydhkey(dns_c_ctx_t *cfg,
				       char **retcpval, isc_int32_t *retival);
isc_result_t	dns_c_ctx_getmaxncachettl(dns_c_ctx_t *cfg,
					  isc_uint32_t *retval);
isc_result_t	dns_c_ctx_gettransfersin(dns_c_ctx_t *cfg,
					 isc_int32_t *retval);
isc_result_t	dns_c_ctx_gettransfersperns(dns_c_ctx_t *cfg,
					    isc_int32_t *retval);
isc_result_t	dns_c_ctx_gettransfersout(dns_c_ctx_t *cfg,
					  isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxlogsizeixfr(dns_c_ctx_t *cfg,
					    isc_int32_t *retval);
isc_result_t	dns_c_ctx_getcleaninterval(dns_c_ctx_t *cfg,
					   isc_int32_t *retval);
isc_result_t	dns_c_ctx_getinterfaceinterval(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getstatsinterval(dns_c_ctx_t *cfg,
					   isc_int32_t *retval);
isc_result_t	dns_c_ctx_getheartbeatinterval(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxtransfertimein(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxtransfertimeout(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxtransferidlein(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_getmaxtransferidleout(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_gettcpclients(dns_c_ctx_t *cfg,
					isc_int32_t *retval);
isc_result_t	dns_c_ctx_getrecursiveclients(dns_c_ctx_t *cfg,
					      isc_int32_t *retval);

isc_result_t	dns_c_ctx_getdatasize(dns_c_ctx_t *cfg,
				      isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getstacksize(dns_c_ctx_t *cfg,
				       isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getcoresize(dns_c_ctx_t *cfg,
				      isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getfiles(dns_c_ctx_t *cfg, isc_uint32_t *retval);
isc_result_t	dns_c_ctx_getexpertmode(dns_c_ctx_t *cfg,
					isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getfakeiquery(dns_c_ctx_t *cfg,
					isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getrecursion(dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getfetchglue(dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getnotify(dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_gethoststatistics(dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getdealloconexit(dns_c_ctx_t *cfg,
					   isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getuseixfr(dns_c_ctx_t *cfg,
				     isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getmaintainixfrbase(dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_gethasoldclients(dns_c_ctx_t *cfg,
					   isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getauthnxdomain(dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getmultiplecnames(dns_c_ctx_t *cfg,
					    isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getuseidpool(dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getrfc2308type1(dns_c_ctx_t *cfg,
					  isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getrequestixfr(dns_c_ctx_t *cfg,
                                         isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getprovideixfr(dns_c_ctx_t *cfg,
                                         isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getdialup(dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_getalsonotify(dns_c_ctx_t *ctx,
					dns_c_iplist_t **ret);
isc_result_t	dns_c_ctx_gettransfersource(dns_c_ctx_t *ctx,
					    isc_sockaddr_t *retval);
isc_result_t	dns_c_ctx_gettransfersourcev6(dns_c_ctx_t *ctx,
					      isc_sockaddr_t *retval);

isc_result_t	dns_c_ctx_getquerysource(dns_c_ctx_t *cfg,
					 isc_sockaddr_t *addr);
isc_result_t	dns_c_ctx_getquerysourcev6(dns_c_ctx_t *cfg,
					   isc_sockaddr_t *addr);
isc_result_t	dns_c_ctx_getchecknames(dns_c_ctx_t *cfg,
					dns_c_trans_t transtype,
					dns_severity_t *sever);
isc_result_t	dns_c_ctx_gettransferformat(dns_c_ctx_t *cfg,
					    dns_transfer_format_t *retval);
isc_result_t	dns_c_ctx_getqueryacl(dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_gettransferacl(dns_c_ctx_t *cfg,
					 dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getrecursionacl(dns_c_ctx_t *cfg,
					  dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getblackhole(dns_c_ctx_t *cfg,
				       dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_gettopology(dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getsortlist(dns_c_ctx_t *cfg,
				      dns_c_ipmatchlist_t **list);
isc_result_t	dns_c_ctx_getlistenlist(dns_c_ctx_t *cfg,
					dns_c_lstnlist_t **ll);
isc_result_t	dns_c_ctx_getforward(dns_c_ctx_t *cfg, dns_c_forw_t *forw);
isc_result_t	dns_c_ctx_getforwarders(dns_c_ctx_t *cfg,
					dns_c_iplist_t **list);
isc_result_t	dns_c_ctx_getrrsetorderlist(dns_c_ctx_t *cfg,
					    dns_c_rrsolist_t **olist);
isc_result_t	dns_c_ctx_gettrustedkeys(dns_c_ctx_t *cfg,
					 dns_c_tkeylist_t **retval);
isc_result_t	dns_c_ctx_getlogging(dns_c_ctx_t *cfg,
				     dns_c_logginglist_t **retval);





#endif /* DNS_CONFIG_CONFCTX_H */
