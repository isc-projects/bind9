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
	isc_mem_t      	       *mem;

	int			warnings; /* semantic warning count */
	int			errors;	/* semantic error count */
	
	dns_c_options_t	       *options;
	dns_c_ctrl_list_t      *controls;
	dns_c_srv_list_t       *servers;
	dns_c_acl_table_t      *acls;
	dns_c_kdef_list_t      *keydefs;
	dns_c_zone_list_t      *zlist;
	dns_c_tkey_list_t      *trusted_keys;
	dns_c_logging_list_t   *logging;
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
	
	dns_c_addr_t	 	query_source_addr;
	short 			query_source_port;

	dns_c_severity_t 	check_names[DNS_C_TRANSCOUNT];

	dns_transfer_format_t	transfer_format;

	dns_c_ipmatch_list_t   *queryacl;
	dns_c_ipmatch_list_t   *transferacl;
	dns_c_ipmatch_list_t   *blackhole;
	dns_c_ipmatch_list_t   *topology;
	dns_c_ipmatch_list_t   *sortlist;

	dns_c_lstn_list_t      *listens;

	dns_c_forw_t		forward;
	dns_c_ipmatch_list_t   *forwarders;

	dns_c_rrso_list_t      *ordering;

	/*
	 * For the non-pointer fields of the struct a bit will be set in
	 * this field if a field value was explicitly set.
	 */
	dns_setbits_t		setflags1;
};



/***
 *** Functions
 ***/


isc_result_t	dns_c_ctx_new(isc_mem_t *mem, dns_c_ctx_t **cfg);
isc_result_t	dns_c_ctx_delete(dns_c_ctx_t **cfg);
isc_result_t	dns_c_ctx_get_options(dns_c_ctx_t *cfg, dns_c_options_t **options);
isc_result_t	dns_c_ctx_set_logging(dns_c_ctx_t *cfg,
				      dns_c_logging_list_t *newval,
				      isc_boolean_t deepcopy);
isc_result_t	dns_c_ctx_get_logging(dns_c_ctx_t *cfg,
				      dns_c_logging_list_t **retval);
isc_result_t	dns_c_ctx_add_file_channel(dns_c_ctx_t *cfg, const char *name,
					   dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_add_syslog_channel(dns_c_ctx_t *cfg,
					     const char *name,
					     dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_add_null_channel(dns_c_ctx_t *cfg, const char *name,
					   dns_c_logchan_t **chan);
isc_result_t	dns_c_ctx_add_category(dns_c_ctx_t *cfg,
				       dns_c_category_t category,
				       dns_c_logcat_t **newcat);
isc_result_t	dns_c_ctx_currchannel(dns_c_ctx_t *cfg,
				      dns_c_logchan_t **channel);
isc_result_t	dns_c_ctx_currcategory(dns_c_ctx_t *cfg,
				       dns_c_logcat_t **category);
isc_boolean_t	dns_c_ctx_key_defined_p(dns_c_ctx_t *ctx, const char *keyname);



isc_boolean_t	dns_c_ctx_channel_defined_p(dns_c_ctx_t *cfg,
					    const char *name);
isc_result_t	dns_c_ctx_options_new(isc_mem_t *mem,
				      dns_c_options_t **options);
isc_result_t	dns_c_ctx_options_delete(dns_c_options_t **options);
isc_result_t	dns_c_ctx_erase_options(dns_c_ctx_t *cfg);
void		dns_c_ctx_print(FILE *fp, int indent, dns_c_ctx_t *cfg);
void		dns_c_ctx_options_print(FILE *fp, int indent,
					dns_c_options_t *options);
void		dns_c_ctx_forwarder_print(FILE *fp, int indent,
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
isc_result_t	dns_c_ctx_set_directory(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_set_version(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_set_dump_filename(dns_c_ctx_t *cfg,
					    const char *newval);
isc_result_t	dns_c_ctx_set_pid_filename(dns_c_ctx_t *cfg,
					   const char *newval);
isc_result_t	dns_c_ctx_set_stats_filename(dns_c_ctx_t *cfg,
					     const char *newval);
isc_result_t	dns_c_ctx_set_memstats_filename(dns_c_ctx_t *cfg,
						const char *newval);
isc_result_t	dns_c_ctx_set_named_xfer(dns_c_ctx_t *cfg, const char *newval);
isc_result_t	dns_c_ctx_set_max_ncache_ttl(dns_c_ctx_t *cfg,
					     isc_uint32_t newval);
isc_result_t	dns_c_ctx_set_transfers_in(dns_c_ctx_t *cfg,
					   isc_int32_t newval);
isc_result_t	dns_c_ctx_set_transfers_per_ns(dns_c_ctx_t *cfg,
					       isc_int32_t newval);
isc_result_t	dns_c_ctx_set_transfers_out(dns_c_ctx_t *cfg,
					    isc_int32_t newval);
isc_result_t	dns_c_ctx_set_max_log_size_ixfr(dns_c_ctx_t *cfg,
						isc_int32_t newval);
isc_result_t	dns_c_ctx_set_clean_interval(dns_c_ctx_t *cfg,
					     isc_int32_t newval);
isc_result_t	dns_c_ctx_set_interface_interval(dns_c_ctx_t *cfg,
						 isc_int32_t newval);
isc_result_t	dns_c_ctx_set_stats_interval(dns_c_ctx_t *cfg,
					     isc_int32_t newval);
isc_result_t	dns_c_ctx_set_heartbeat_interval(dns_c_ctx_t *cfg,
						 isc_int32_t newval);
isc_result_t	dns_c_ctx_set_max_transfer_time_in(dns_c_ctx_t *cfg,
						   isc_int32_t newval);
isc_result_t	dns_c_ctx_set_data_size(dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_set_stack_size(dns_c_ctx_t *cfg,
					 isc_uint32_t newval);
isc_result_t	dns_c_ctx_set_core_size(dns_c_ctx_t *cfg, isc_uint32_t newval);
isc_result_t	dns_c_ctx_set_files(dns_c_ctx_t *cfg, isc_uint32_t newval);

isc_result_t	dns_c_ctx_set_expert_mode(dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_fake_iquery(dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_recursion(dns_c_ctx_t *cfg,
					isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_fetch_glue(dns_c_ctx_t *cfg,
					 isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_notify(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_host_statistics(dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_dealloc_on_exit(dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_use_ixfr(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_maintain_ixfr_base(dns_c_ctx_t *cfg,
						 isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_has_old_clients(dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_auth_nx_domain(dns_c_ctx_t *cfg,
					     isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_multiple_cnames(dns_c_ctx_t *cfg,
					      isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_use_id_pool(dns_c_ctx_t *cfg,
					  isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_dialup(dns_c_ctx_t *cfg, isc_boolean_t newval);
isc_result_t	dns_c_ctx_set_query_source_addr(dns_c_ctx_t *cfg,
						dns_c_addr_t addr);
isc_result_t	dns_c_ctx_set_query_source_port(dns_c_ctx_t *cfg, short port);
isc_result_t	dns_c_ctx_set_checknames(dns_c_ctx_t *cfg,
					 dns_c_trans_t transtype,
					 dns_c_severity_t sever);
isc_result_t	dns_c_ctx_set_transfer_format(dns_c_ctx_t *cfg,
					      dns_transfer_format_t newval);
isc_result_t	dns_c_ctx_set_queryacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
				       dns_c_ipmatch_list_t *iml);
isc_result_t	dns_c_ctx_set_transferacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
					  dns_c_ipmatch_list_t *iml);
isc_result_t	dns_c_ctx_set_blackhole(dns_c_ctx_t *cfg, isc_boolean_t copy,
					dns_c_ipmatch_list_t *iml);
isc_result_t	dns_c_ctx_set_topology(dns_c_ctx_t *cfg, isc_boolean_t copy,
				       dns_c_ipmatch_list_t *iml);
isc_result_t	dns_c_ctx_set_sortlist(dns_c_ctx_t *cfg, isc_boolean_t copy,
				       dns_c_ipmatch_list_t *iml);
isc_result_t	dns_c_ctx_set_forward(dns_c_ctx_t *cfg, dns_c_forw_t forw);
isc_result_t	dns_c_ctx_set_forwarders(dns_c_ctx_t *cfg,
					 dns_c_ipmatch_list_t *iml,
					 isc_boolean_t copy);
isc_result_t	dns_c_ctx_set_rrsetorder_list(dns_c_ctx_t *cfg,
					      isc_boolean_t copy,
					      dns_c_rrso_list_t *olist);

isc_result_t	dns_c_ctx_add_listen_on(dns_c_ctx_t *cfg, int port,
					dns_c_ipmatch_list_t *ml,
					isc_boolean_t copy);
isc_result_t	dns_c_ctx_set_trusted_keys(dns_c_ctx_t *cfg,
					   dns_c_tkey_list_t *list,
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


isc_result_t	dns_c_ctx_get_directory(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_version(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_dump_filename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_pid_filename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_stats_filename(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_memstats_filename(dns_c_ctx_t *cfg,
						char **retval);
isc_result_t	dns_c_ctx_get_named_xfer(dns_c_ctx_t *cfg, char **retval);
isc_result_t	dns_c_ctx_get_max_ncache_ttl(dns_c_ctx_t *cfg,
					     isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_transfers_in(dns_c_ctx_t *cfg,
					   isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_transfers_per_ns(dns_c_ctx_t *cfg,
					       isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_transfers_out(dns_c_ctx_t *cfg,
					    isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_max_log_size_ixfr(dns_c_ctx_t *cfg,
						isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_clean_interval(dns_c_ctx_t *cfg,
					     isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_interface_interval(dns_c_ctx_t *cfg,
						 isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_stats_interval(dns_c_ctx_t *cfg,
					     isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_heartbeat_interval(dns_c_ctx_t *cfg,
						 isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_max_transfer_time_in(dns_c_ctx_t *cfg,
						   isc_int32_t *retval);
isc_result_t	dns_c_ctx_get_data_size(dns_c_ctx_t *cfg,
					isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_stack_size(dns_c_ctx_t *cfg,
					 isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_core_size(dns_c_ctx_t *cfg,
					isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_files(dns_c_ctx_t *cfg, isc_uint32_t *retval);
isc_result_t	dns_c_ctx_get_expert_mode(dns_c_ctx_t *cfg,
					  isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_fake_iquery(dns_c_ctx_t *cfg,
					  isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_recursion(dns_c_ctx_t *cfg,
					isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_fetch_glue(dns_c_ctx_t *cfg,
					 isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_notify(dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_host_statistics(dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_dealloc_on_exit(dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_use_ixfr(dns_c_ctx_t *cfg,
				       isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_maintain_ixfr_base(dns_c_ctx_t *cfg,
						 isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_has_old_clients(dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_auth_nx_domain(dns_c_ctx_t *cfg,
					     isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_multiple_cnames(dns_c_ctx_t *cfg,
					      isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_use_id_pool(dns_c_ctx_t *cfg,
					  isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_dialup(dns_c_ctx_t *cfg, isc_boolean_t *retval);
isc_result_t	dns_c_ctx_get_query_source_addr(dns_c_ctx_t *cfg,
						dns_c_addr_t *addr);
isc_result_t	dns_c_ctx_get_query_source_port(dns_c_ctx_t *cfg,
						short *port);
isc_result_t	dns_c_ctx_get_checknames(dns_c_ctx_t *cfg,
					 dns_c_trans_t transtype,
					 dns_c_severity_t *sever);
isc_result_t	dns_c_ctx_get_transfer_format(dns_c_ctx_t *cfg,
					      dns_transfer_format_t *retval);
isc_result_t	dns_c_ctx_get_queryacl(dns_c_ctx_t *cfg,
				       dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_transferacl(dns_c_ctx_t *cfg,
					  dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_blackhole(dns_c_ctx_t *cfg,
					dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_topology(dns_c_ctx_t *cfg,
				       dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_sortlist(dns_c_ctx_t *cfg,
				       dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_listen_list(dns_c_ctx_t *cfg,
					  dns_c_lstn_list_t **ll);
isc_result_t	dns_c_ctx_get_forward(dns_c_ctx_t *cfg, dns_c_forw_t *forw);
isc_result_t	dns_c_ctx_get_forwarders(dns_c_ctx_t *cfg,
					 dns_c_ipmatch_list_t **list);
isc_result_t	dns_c_ctx_get_rrsetorder_list(dns_c_ctx_t *cfg,
					      dns_c_rrso_list_t **olist);
isc_result_t	dns_c_ctx_get_trusted_keys(dns_c_ctx_t *cfg,
					   dns_c_tkey_list_t **retval);
isc_result_t	dns_c_ctx_get_logging(dns_c_ctx_t *cfg,
				      dns_c_logging_list_t **retval);





#endif /* DNS_CONFIG_CONFCTX_H */
