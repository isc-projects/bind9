/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

/****
 **** MODULE INFO
 ****/

/*
 * Top level Data structure and accessors for the data defined in the
 * config file.
 *
 * MP:
 *
 *	Caller must do necessary locking.
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
 
#if !defined(CONFIGCTX_H)
#define CONFIGCTX_H 1

#include <isc/mem.h>

#include "zone.h"

/* Data from an 'options' config file statement */
typedef struct isc_cfgoptions 
{
	isc_textregion_t directory;
	isc_textregion_t version;
	isc_textregion_t dump_filename;
	isc_textregion_t pid_filename;
	isc_textregion_t stats_filename;
	isc_textregion_t memstats_filename;
	isc_textregion_t named_xfer;

	unsigned int flags;
	unsigned int max_ncache_ttl;

	int transfers_in;
	int transfers_per_ns;
	int transfers_out;
 	int max_log_size_ixfr;
	int clean_interval;
	int interface_interval;
	int stats_interval;
	int heartbeat_interval;

	isc_boolean_t fake_iquery;
	isc_boolean_t recursion;
	isc_boolean_t fetch_glue;
	isc_boolean_t notify;
	isc_boolean_t hoststats;
	isc_boolean_t dealloc_on_exit;
	isc_boolean_t use_ixfr;
	isc_boolean_t maintain_ixfr_base;
	isc_boolean_t has_old_clients;
	isc_boolean_t auth_nx_domain;
	isc_boolean_t multiple_cnames;
	isc_boolean_t use_id_pool;
	isc_boolean_t dialup;
	
	long max_transfer_time_in;

	unsigned long data_size;
	unsigned long stack_size;
	unsigned long core_size;
	unsigned long files;

#if 0
	struct sockaddr_in query_source;
	ip_match_list query_acl;
	ip_match_list transfer_acl;
	ip_match_list blackhole_acl;
	ip_match_list topology;
#ifdef SORT_RESPONSE
	ip_match_list sortlist;
#endif /* SORT_RESPONSE */

	enum axfr_format transfer_format;

	enum severity check_names[num_trans];
	listen_info_list listen_list;
	struct fwdinfo *fwdtab;

	rrset_order_list ordering;
#endif

	/* For the non-pointer members of the struct a bit will be set in
	 * this field if a value was explicitly set.
	 */
	isc_uint64_t set_flags1;
	isc_uint64_t set_flags2;
} isc_cfgoptions_t;


/* Master config structure. All the information defined in a config file is 
 * reachable through here.
 */
typedef struct isc_cfgctx
{
	int warnings;			/* number of parse warnings */
	int errors;			/* number of parse semantic errors */
	
	isc_mem_t *mem;			/* where we get our memory from */

	isc_cfgoptions_t *options;
	isc_zonectx_t *zonecontext;
	
	/* XXX other config stuff like trusted keys, acls, logging etc. */
} isc_cfgctx_t;


isc_result_t isc_cfg_newctx(isc_mem_t *mem, isc_cfgctx_t **ctx);
isc_result_t isc_cfg_freectx(isc_cfgctx_t **ctx);

/* Reset the options back to virgin state.  */
isc_result_t isc_cfg_erase_options(isc_cfgctx_t *ctx);

/* Send a properly formatted context to the given stream */
void isc_cfg_dump_config(FILE *fp, isc_cfgctx_t *ctx);
void isc_cfg_dump_options(FILE *fp, isc_cfgoptions_t *options);


/* Set functions for all the options fields. */

isc_result_t isc_cfg_set_directory(isc_cfgctx_t *ctx, const char *directory);
isc_result_t isc_cfg_set_version(isc_cfgctx_t *ctx, const char *directory);
isc_result_t isc_cfg_set_dump_filename(isc_cfgctx_t *ctx,
				       const char *directory);
isc_result_t isc_cfg_set_pid_filename(isc_cfgctx_t *ctx,
				      const char *directory);
isc_result_t isc_cfg_set_stats_filename(isc_cfgctx_t *ctx,
				      const char *directory);
isc_result_t isc_cfg_set_memstats_filename(isc_cfgctx_t *ctx,
					   const char *directory);
isc_result_t isc_cfg_set_named_xfer(isc_cfgctx_t *ctx, const char *directory);
isc_result_t isc_cfg_set_max_ncache_ttl(isc_cfgctx_t*ctx, unsigned int value);
isc_result_t isc_cfg_set_transfers_in(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_transfers_per_ns(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_transfers_out(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_max_log_size_ixfr(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_clean_interval(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_interface_interval(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_stats_interval(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_heartbeat_interval(isc_cfgctx_t*ctx, int value);
isc_result_t isc_cfg_set_max_transfer_time_in(isc_cfgctx_t*ctx, long value);
isc_result_t isc_cfg_set_data_size(isc_cfgctx_t *ctx, unsigned long value);
isc_result_t isc_cfg_set_stack_size(isc_cfgctx_t *ctx, unsigned long value);
isc_result_t isc_cfg_set_core_size(isc_cfgctx_t *ctx, unsigned long value);
isc_result_t isc_cfg_set_files(isc_cfgctx_t *ctx, unsigned long value);

isc_result_t isc_cfg_set_fake_iquery(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_recursion(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_fetch_glue(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_notify(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_hoststats(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_dealloc_on_exit(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_use_ixfr(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_maintain_ixfr_base(isc_cfgctx_t *ctx,
					    isc_boolean_t bv);
isc_result_t isc_cfg_set_has_old_clients(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_auth_nx_domain(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_multiple_cnames(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_use_id_pool(isc_cfgctx_t *ctx, isc_boolean_t bv);
isc_result_t isc_cfg_set_dialup(isc_cfgctx_t *ctx, isc_boolean_t bv);


/* Get functions for all the option fields. Caller must not modify the
 * results. If the fields was not set, the ISC_R_NOTFOUND is returned,
 * otherwise  ISC_R_SUCCESS
 */
isc_result_t isc_cfg_get_named_xfer(isc_cfgctx_t *ctx, const char **result);
isc_result_t isc_cfg_get_directory(isc_cfgctx_t *ctx, const char **result);
isc_result_t isc_cfg_get_version(isc_cfgctx_t *ctx, const char **result);
isc_result_t isc_cfg_get_dump_filename(isc_cfgctx_t *ctx,
				       const char **result);
isc_result_t isc_cfg_get_pid_filename(isc_cfgctx_t *ctx,
				      const char **result);
isc_result_t isc_cfg_get_stats_filename(isc_cfgctx_t *ctx,
					const char **result);
isc_result_t isc_cfg_get_memstats_filename(isc_cfgctx_t *ctx,
					   const char **result);
isc_result_t isc_cfg_get_max_ncache_ttl(isc_cfgctx_t *ctx,
					unsigned int *result);
isc_result_t isc_cfg_get_transfers_in(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_transfers_per_ns(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_transfers_out(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_max_log_size_ixfr(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_clean_interval(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_interface_interval(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_stats_interval(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_heartbeat_interval(isc_cfgctx_t *ctx, int *result);
isc_result_t isc_cfg_get_max_transfer_time_in(isc_cfgctx_t *ctx, long *result);
isc_result_t isc_cfg_get_data_size(isc_cfgctx_t *ctx, unsigned long *result);
isc_result_t isc_cfg_get_stack_size(isc_cfgctx_t *ctx, unsigned long *result);
isc_result_t isc_cfg_get_core_size(isc_cfgctx_t *ctx, unsigned long *result);
isc_result_t isc_cfg_get_files(isc_cfgctx_t *ctx, unsigned long *result);

isc_result_t isc_cfg_get_fake_iquery(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_recursion(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_fetch_glue(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_notify(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_hoststats(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_dealloc_on_exit(isc_cfgctx_t *ctx,
					 isc_boolean_t *result);
isc_result_t isc_cfg_get_use_ixfr(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_maintain_ixfr_base(isc_cfgctx_t *ctx,
					    isc_boolean_t *result);
isc_result_t isc_cfg_get_has_old_clients(isc_cfgctx_t *ctx,
					 isc_boolean_t *result);
isc_result_t isc_cfg_get_auth_nx_domain(isc_cfgctx_t *ctx,
					isc_boolean_t *result);
isc_result_t isc_cfg_get_multiple_cnames(isc_cfgctx_t *ctx,
					 isc_boolean_t *result);
isc_result_t isc_cfg_get_use_id_pool(isc_cfgctx_t *ctx, isc_boolean_t *result);
isc_result_t isc_cfg_get_dialup(isc_cfgctx_t *ctx, isc_boolean_t *result);


	

#endif
