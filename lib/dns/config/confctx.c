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

#include <config.h>

#include <syslog.h>

#include <isc/assertions.h>
#include <isc/error.h>

#include <dns/confctx.h>
#include <dns/confcommon.h>
#include "confpvt.h"



#define CONFIG_MAGIC		0x434f4e46U /* CONF */
#define OPTION_MAGIC		0x4f707473U /* Opts */
#define CHECK_CONFIG(c)		REQUIRE(DNS_C_VALID_STRUCT(c,CONFIG_MAGIC))
#define CHECK_OPTION(o)		REQUIRE(DNS_C_VALID_STRUCT(o,OPTION_MAGIC))


/*
 * Bit positions in the flags fields of the dns_c_options_t structure.
 */
#define MAX_NCACHE_TTL_BIT		0 
#define TRANSFERS_IN_BIT		1 
#define TRANSFERS_PER_NS_BIT		2 
#define TRANSFERS_OUT_BIT		3 
#define MAX_LOG_SIZE_IXFR_BIT		4 
#define CLEAN_INTERVAL_BIT		5 
#define INTERFACE_INTERVAL_BIT		6 
#define STATS_INTERVAL_BIT		7 
#define HEARTBEAT_INTERVAL_BIT		8 
#define MAX_TRANSFER_TIME_IN_BIT	9 
#define DATA_SIZE_BIT			10
#define STACK_SIZE_BIT			11
#define CORE_SIZE_BIT			12
#define FILES_BIT			13
#define QUERY_SOURCE_ADDR_BIT		14
#define QUERY_SOURCE_PORT_BIT		15
#define FAKE_IQUERY_BIT			16
#define RECURSION_BIT			17
#define FETCH_GLUE_BIT			18
#define NOTIFY_BIT			19
#define HOST_STATISTICS_BIT		20
#define DEALLOC_ON_EXIT_BIT		21
#define USE_IXFR_BIT			22
#define MAINTAIN_IXFR_BASE_BIT		23
#define HAS_OLD_CLIENTS_BIT		24
#define AUTH_NX_DOMAIN_BIT		25
#define MULTIPLE_CNAMES_BIT		26
#define USE_ID_POOL_BIT			27
#define DIALUP_BIT			28
#define CHECKNAME_PRIM_BIT		29
#define CHECKNAME_SEC_BIT		30
#define CHECKNAME_RESP_BIT		31
#define OPTIONS_TRANSFER_FORMAT_BIT	32
#define FORWARD_BIT			33
#define EXPERT_MODE_BIT			34


static isc_result_t cfg_set_iplist(dns_c_options_t *options,
				   dns_c_ipmatch_list_t **fieldaddr,
				   dns_c_ipmatch_list_t *newval,
				   isc_boolean_t copy);
static isc_result_t cfg_set_boolean(dns_c_options_t *options,
				    isc_boolean_t *fieldaddr,
				    isc_boolean_t newval,
				    dns_setbits_t *setfield,
				    isc_uint32_t bitnumber);
static isc_result_t cfg_set_int32(dns_c_options_t *options,
				  isc_int32_t *fieldaddr,
				  isc_int32_t newval,
				  dns_setbits_t *setfield,
				  isc_uint32_t bitnumber);
static isc_result_t cfg_set_uint32(dns_c_options_t *options,
				   isc_uint32_t *fieldaddr,
				   isc_uint32_t newval,
				   dns_setbits_t *setfield,
				   isc_uint32_t bitnumber);
static isc_result_t cfg_set_string(dns_c_options_t *options,
				   char **field,
				   const char *newval);

static isc_result_t cfg_get_uint32(dns_c_options_t *options,
				   isc_uint32_t *field,
				   isc_uint32_t *result,
				   dns_setbits_t *setfield,
				   isc_uint32_t bitnumber);
static isc_result_t cfg_get_int32(dns_c_options_t *options,
				  isc_int32_t *field,
				  isc_int32_t *result,
				  dns_setbits_t *setfield,
				  isc_uint32_t bitnumber);
static isc_result_t cfg_get_boolean(dns_c_options_t *options,
				    isc_boolean_t *field,
				    isc_boolean_t *result,
				    dns_setbits_t *setfield,
				    isc_uint32_t bitnumber);
static isc_result_t cfg_get_iplist(dns_c_options_t *options,
				   dns_c_ipmatch_list_t *field,
				   dns_c_ipmatch_list_t **resval);
static isc_result_t acl_init(dns_c_ctx_t *cfg);
static isc_result_t logging_init (dns_c_ctx_t *cfg);


isc_result_t
dns_c_ctx_new(isc_mem_t *mem, dns_c_ctx_t **ctx)
{
	dns_c_ctx_t *cfg;
	isc_result_t r;
	
	REQUIRE(mem != NULL);

	cfg = isc_mem_get(mem, sizeof *cfg);
	if (cfg == NULL) {
		return (ISC_R_NOMEMORY);
	}

	cfg->magic = CONFIG_MAGIC;
	cfg->mem = mem;
	cfg->warnings = 0;
	cfg->errors = 0;
	cfg->acls = NULL;
	cfg->options = NULL;
	cfg->zlist = NULL;
	cfg->servers = NULL;
	cfg->acls = NULL;
	cfg->keydefs = NULL;
	cfg->trusted_keys = NULL;
	cfg->logging = NULL;
	
	
	r = acl_init(cfg);
	if (r != ISC_R_SUCCESS) {
		return (r);
	}

	r = logging_init(cfg);
	if (r != ISC_R_SUCCESS) {
		return (r);
	}
	
	
	r = dns_c_ctrl_list_new(mem, &cfg->controls);
	if (r != ISC_R_SUCCESS) {
		dns_c_ctx_delete(&cfg);
		return r;
	}

	*ctx = cfg;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_delete(dns_c_ctx_t **cfg)
{
	dns_c_ctx_t *c;

	REQUIRE(cfg != NULL);
	REQUIRE(*cfg != NULL);
	CHECK_CONFIG(*cfg);

	c = *cfg;

	REQUIRE(c->mem != NULL);

	dns_c_ctx_options_delete(&c->options);
	dns_c_ctrl_list_delete(&c->controls);
	dns_c_srv_list_delete(&c->servers);
	dns_c_acl_table_delete(&c->acls);
	dns_c_kdef_list_delete(&c->keydefs);
	dns_c_zone_list_delete(&c->zlist);
	dns_c_tkey_list_delete(&c->trusted_keys);
	dns_c_logging_list_delete(&c->logging);
	
	isc_mem_put(c->mem, c, sizeof *c);
	*cfg = NULL;
	
	return (ISC_R_SUCCESS);
}


void
dns_c_ctx_print(FILE *fp, int indent, dns_c_ctx_t *cfg)
{
	REQUIRE(fp != NULL);
	CHECK_CONFIG(cfg);

	dns_c_logging_list_print(fp, indent, cfg->logging, ISC_FALSE);
	fprintf(fp,"\n");
	
	dns_c_acl_table_print(fp, indent, cfg->acls);
	fprintf(fp,"\n");

	dns_c_kdef_list_print(fp, indent, cfg->keydefs);
	fprintf(fp, "\n");

	dns_c_tkey_list_print(fp, indent, cfg->trusted_keys);
	fprintf(fp, "\n");

	dns_c_zone_list_print_preopts(fp, indent, cfg->zlist);
	fprintf(fp, "\n");
	
	dns_c_ctx_options_print(fp, indent, cfg->options);
	fprintf(fp,"\n");
	
	dns_c_zone_list_print_postopts(fp, indent, cfg->zlist);
	fprintf(fp, "\n");
	
	dns_c_ctrl_list_print(fp, indent, cfg->controls);
	fprintf(fp, "\n");

	dns_c_srv_list_print(fp, indent, cfg->servers);
	fprintf(fp, "\n");
}


void
dns_c_ctx_forwarder_print(FILE *fp, int indent, dns_c_options_t *options)
{
	if (options == NULL) {
		return;
	}

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);
	CHECK_OPTION(options);

	if (DNS_C_CHECKBIT(FORWARD_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(options->forward, ISC_TRUE));
	}

	if (options->forwarders != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 options->forwarders);
	}
}


isc_result_t
dns_c_ctx_get_options(dns_c_ctx_t *cfg, dns_c_options_t **options)
{
	CHECK_CONFIG(cfg);
	if (cfg->options != NULL) {
		CHECK_OPTION(cfg->options);
	}
	
	*options = cfg->options;
	
	return (cfg->options == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_logging(dns_c_ctx_t *cfg, dns_c_logging_list_t **retval)
{
	CHECK_CONFIG(cfg);

	*retval = cfg->logging;

	return (cfg->logging == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_logging(dns_c_ctx_t *cfg, dns_c_logging_list_t *newval,
		      isc_boolean_t deepcopy)
{
	dns_c_logging_list_t *ll;
	isc_result_t res;
	isc_boolean_t existed;
	
	CHECK_CONFIG(cfg);

	existed = (cfg->logging != NULL);
	
	if (deepcopy) {
		res = dns_c_logging_list_copy(cfg->mem, &ll, newval);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		ll = newval;
	}
	
	cfg->logging = ll;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_add_file_channel(dns_c_ctx_t *cfg, const char *name,
			   dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	CHECK_CONFIG(cfg);
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name, dns_c_logchan_file, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logging_list_add_channel(cfg->logging, newc, ISC_FALSE);

	*chan = newc;

	return (res);
}


isc_result_t
dns_c_ctx_add_syslog_channel(dns_c_ctx_t *cfg, const char *name,
			     dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	CHECK_CONFIG(cfg);
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name,
				dns_c_logchan_syslog, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logging_list_add_channel(cfg->logging, newc, ISC_FALSE);

	*chan = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_add_null_channel(dns_c_ctx_t *cfg, const char *name,
			   dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	CHECK_CONFIG(cfg);
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name, dns_c_logchan_null, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logging_list_add_channel(cfg->logging, newc, ISC_FALSE);

	*chan = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_add_category(dns_c_ctx_t *cfg, dns_c_category_t category,
		       dns_c_logcat_t **newcat)
{
	dns_c_logcat_t *newc;
	isc_result_t res;

	CHECK_CONFIG(cfg);
	REQUIRE(newcat != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logcat_new(cfg->mem, category, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	res = dns_c_logging_list_add_category(cfg->logging, newc, ISC_FALSE);

	*newcat = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_currchannel(dns_c_ctx_t *cfg, dns_c_logchan_t **channel)
{
	dns_c_logchan_t *newc;

	CHECK_CONFIG(cfg);
	REQUIRE(channel != NULL);
	REQUIRE(cfg->logging != NULL);

	newc = ISC_LIST_TAIL(cfg->logging->channels);

	*channel = newc;
	
	return (newc == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_boolean_t
dns_c_ctx_channel_defined_p(dns_c_ctx_t *cfg, const char *name)
{
	isc_result_t res;
	dns_c_logchan_t *chan;
	
	res = dns_c_logging_list_chanbyname(cfg->logging, name, &chan);

	return (res == ISC_R_SUCCESS);
}



isc_result_t
dns_c_ctx_currcategory(dns_c_ctx_t *cfg, dns_c_logcat_t **category)
{
	dns_c_logcat_t *newc;
	dns_c_logging_list_t *llist;
	isc_result_t res;

	CHECK_CONFIG(cfg);
	REQUIRE(category != NULL);

	res = dns_c_ctx_get_logging(cfg, &llist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	newc = ISC_LIST_TAIL(llist->categories);

	*category = newc;
	
	return (newc == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


/*
 * Modifiers for options.
 */


isc_result_t
dns_c_ctx_set_directory(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->directory,
			       newval));
}


isc_result_t
dns_c_ctx_set_version(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->version,
			       newval));
}


isc_result_t
dns_c_ctx_set_dump_filename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->dump_filename,
			       newval));
}


isc_result_t
dns_c_ctx_set_pid_filename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->pid_filename,
			       newval));
}


isc_result_t
dns_c_ctx_set_stats_filename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->stats_filename,
			       newval));
}


isc_result_t
dns_c_ctx_set_memstats_filename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->memstats_filename,
			       newval));
}


isc_result_t
dns_c_ctx_set_named_xfer(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_string(cfg->options,
			       &cfg->options->named_xfer,
			       newval));
}


isc_result_t
dns_c_ctx_set_max_ncache_ttl(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_uint32(cfg->options, 
			       &cfg->options->max_ncache_ttl,
			       newval,
			       &cfg->options->setflags1,
			       MAX_NCACHE_TTL_BIT));
}


isc_result_t
dns_c_ctx_set_transfers_in(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options, 
			      &cfg->options->transfers_in,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_IN_BIT));
}


isc_result_t
dns_c_ctx_set_transfers_per_ns(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options, 
			      &cfg->options->transfers_per_ns,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_PER_NS_BIT));
}


isc_result_t
dns_c_ctx_set_transfers_out(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->transfers_out,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_OUT_BIT));
}


isc_result_t
dns_c_ctx_set_max_log_size_ixfr(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_log_size_ixfr,
			      newval,
			      &cfg->options->setflags1,
			      MAX_LOG_SIZE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_set_clean_interval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->clean_interval,
			      newval,
			      &cfg->options->setflags1,
			      CLEAN_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_set_interface_interval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->interface_interval,
			      newval,
			      &cfg->options->setflags1,
			      INTERFACE_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_set_stats_interval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->stats_interval,
			      newval,
			      &cfg->options->setflags1,
			      STATS_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_set_heartbeat_interval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->heartbeat_interval,
			      newval,
			      &cfg->options->setflags1,
			      HEARTBEAT_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_set_max_transfer_time_in(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_transfer_time_in,
			      newval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_IN_BIT));
}


isc_result_t
dns_c_ctx_set_data_size(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_uint32(cfg->options,
			       &cfg->options->data_size,
			       newval,
			       &cfg->options->setflags1,
			       DATA_SIZE_BIT));
}


isc_result_t
dns_c_ctx_set_stack_size(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_uint32(cfg->options,
			       &cfg->options->stack_size,
			       newval,
			       &cfg->options->setflags1,
			       STACK_SIZE_BIT));
}


isc_result_t
dns_c_ctx_set_core_size(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_uint32(cfg->options,
			       &cfg->options->core_size,
			       newval,
			       &cfg->options->setflags1,
			       CORE_SIZE_BIT));
}


isc_result_t
dns_c_ctx_set_files(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_uint32(cfg->options,
			       &cfg->options->files,
			       newval,
			       &cfg->options->setflags1,
			       FILES_BIT));
}


isc_result_t
dns_c_ctx_set_expert_mode(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->expert_mode,
				newval,
				&cfg->options->setflags1,
				EXPERT_MODE_BIT));
}


isc_result_t
dns_c_ctx_set_fake_iquery(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->fake_iquery,
				newval,
				&cfg->options->setflags1,
				FAKE_IQUERY_BIT));
}


isc_result_t
dns_c_ctx_set_recursion(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->recursion,
				newval,
				&cfg->options->setflags1,
				RECURSION_BIT));
}


isc_result_t
dns_c_ctx_set_fetch_glue(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->fetch_glue,
				newval,
				&cfg->options->setflags1,
				FETCH_GLUE_BIT));
}


isc_result_t
dns_c_ctx_set_notify(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->notify,
				newval,
				&cfg->options->setflags1,
				NOTIFY_BIT));
}


isc_result_t
dns_c_ctx_set_host_statistics(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->host_statistics,
				newval,
				&cfg->options->setflags1,
				HOST_STATISTICS_BIT));
}


isc_result_t
dns_c_ctx_set_dealloc_on_exit(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->dealloc_on_exit,
				newval,
				&cfg->options->setflags1,
				DEALLOC_ON_EXIT_BIT));
}


isc_result_t
dns_c_ctx_set_use_ixfr(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->use_ixfr,
				newval,
				&cfg->options->setflags1,
				USE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_set_maintain_ixfr_base(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->maintain_ixfr_base,
				newval,
				&cfg->options->setflags1,
				MAINTAIN_IXFR_BASE_BIT));
}


isc_result_t
dns_c_ctx_set_has_old_clients(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->has_old_clients,
				newval,
				&cfg->options->setflags1,
				HAS_OLD_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_set_auth_nx_domain(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->auth_nx_domain,
				newval,
				&cfg->options->setflags1,
				AUTH_NX_DOMAIN_BIT));
}


isc_result_t
dns_c_ctx_set_multiple_cnames(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->multiple_cnames,
				newval,
				&cfg->options->setflags1,
				MULTIPLE_CNAMES_BIT));
}


isc_result_t
dns_c_ctx_set_use_id_pool(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->use_id_pool,
				newval,
				&cfg->options->setflags1,
				USE_ID_POOL_BIT));
}


isc_result_t
dns_c_ctx_set_dialup(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	return (cfg_set_boolean(cfg->options,
				&cfg->options->dialup,
				newval,
				&cfg->options->setflags1,
				DIALUP_BIT));
}


isc_result_t
dns_c_ctx_set_query_source_addr(dns_c_ctx_t *cfg, dns_c_addr_t addr)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	existed = DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(QUERY_SOURCE_ADDR_BIT, &cfg->options->setflags1);
	
	cfg->options->query_source_addr = addr;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_query_source_port(dns_c_ctx_t *cfg, short port)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	existed = DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(QUERY_SOURCE_PORT_BIT, &cfg->options->setflags1);
	
	cfg->options->query_source_port = port;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_transfer_format(dns_c_ctx_t *cfg,
			      dns_transfer_format_t newval)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	existed = DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(OPTIONS_TRANSFER_FORMAT_BIT, &cfg->options->setflags1);
	
	cfg->options->transfer_format = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_checknames(dns_c_ctx_t *cfg,
			 dns_c_trans_t transtype,
			 dns_c_severity_t sever)
{
	isc_boolean_t existed = ISC_FALSE;
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	switch(transtype) {
	case dns_trans_primary:
		existed = DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT,
					 &cfg->options->setflags1);
		DNS_C_SETBIT(CHECKNAME_PRIM_BIT, &cfg->options->setflags1);
		break;

	case dns_trans_secondary:
		existed = DNS_C_CHECKBIT(CHECKNAME_SEC_BIT,
					 &cfg->options->setflags1);
		DNS_C_SETBIT(CHECKNAME_SEC_BIT, &cfg->options->setflags1);
		break;

	case dns_trans_response:
		existed = DNS_C_CHECKBIT(CHECKNAME_RESP_BIT,
					 &cfg->options->setflags1);
		DNS_C_SETBIT(CHECKNAME_RESP_BIT, &cfg->options->setflags1);
		break;

	default:
		dns_c_error(0, "bad transport value: %d\n", transtype);
		return (ISC_R_FAILURE);
	}
	
	cfg->options->check_names[transtype] = sever;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_queryacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
		       dns_c_ipmatch_list_t *iml)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->queryacl, iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_transferacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
			  dns_c_ipmatch_list_t *iml)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->transferacl,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_blackhole(dns_c_ctx_t *cfg, isc_boolean_t copy,
			dns_c_ipmatch_list_t *iml)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->blackhole,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_topology(dns_c_ctx_t *cfg, isc_boolean_t copy,
		       dns_c_ipmatch_list_t *iml)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->topology, iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_sortlist(dns_c_ctx_t *cfg, isc_boolean_t copy,
		       dns_c_ipmatch_list_t *iml)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->sortlist, iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_forward(dns_c_ctx_t *cfg, dns_c_forw_t forw)
{
	isc_boolean_t existed;
	isc_result_t res;

	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	existed = DNS_C_CHECKBIT(FORWARD_BIT, &cfg->options->setflags1);
	DNS_C_SETBIT(FORWARD_BIT, &cfg->options->setflags1);
	
	cfg->options->forward = forw;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_set_forwarders(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t *iml,
			 isc_boolean_t copy)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);
	
	res = cfg_set_iplist(cfg->options, &cfg->options->forwarders,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_set_rrsetorder_list(dns_c_ctx_t *cfg, isc_boolean_t copy,
			      dns_c_rrso_list_t *olist)
{
	isc_boolean_t existed;
	dns_c_options_t *opts;
	isc_result_t res;

	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		res = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	CHECK_OPTION(cfg->options);

	opts = cfg->options;

	existed = (opts->ordering == NULL ? ISC_FALSE : ISC_TRUE);
	
	if (copy) {
		if (opts->ordering == NULL) {
			res = dns_c_rrso_list_new(opts->mem,
						  &opts->ordering);
			if (res != ISC_R_SUCCESS) {
				return (res);
			}
		} else {
			dns_c_rrso_list_clear(opts->ordering);
		}
		
		res = dns_c_rrso_list_append(opts->ordering, olist);
	} else {
		if (opts->ordering != NULL) {
			dns_c_rrso_list_delete(&opts->ordering);
		}
		
		opts->ordering = olist;
		res = ISC_R_SUCCESS;
	}

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}
	
	return (res);
}


isc_result_t
dns_c_ctx_add_listen_on(dns_c_ctx_t *cfg,int port, dns_c_ipmatch_list_t *ml,
			isc_boolean_t copy)
{
	dns_c_lstn_on_t *lo;
	isc_result_t result;
	dns_c_options_t *opts;

	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		result = dns_c_ctx_options_new(cfg->mem, &cfg->options);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}
				   
	CHECK_OPTION(cfg->options);
	REQUIRE(port >= 0 && port <= 65535);

	opts = cfg->options;

	if (opts->listens == NULL) {
		result = dns_c_lstn_list_new(cfg->mem, &opts->listens);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

#if 0	
	lo = ISC_LIST_HEAD(opts->listens->elements);
	while (lo != NULL) {
		/* XXX we should probably check that a listen on statement
		 * hasn't been done for the same post, ipmatch list
		 * combination
		 */
		if (lo->port == port) {	/* XXX incomplete */
			return (ISC_R_FAILURE);
		}
		lo = ISC_LIST_NEXT(lo, next);
	}
#endif	

	result = dns_c_lstn_on_new(cfg->mem, &lo);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	
	lo->port = port;
	result = dns_c_lstn_on_setiml(lo, ml, copy);

	ISC_LIST_APPEND(opts->listens->elements, lo, next);

	return (result);
}


isc_result_t
dns_c_ctx_set_trusted_keys(dns_c_ctx_t *cfg, dns_c_tkey_list_t *list,
			   isc_boolean_t copy)
{
	isc_boolean_t existed;
	dns_c_tkey_list_t *newl;
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	existed = (cfg->trusted_keys == NULL ? ISC_FALSE : ISC_TRUE);

	if (cfg->trusted_keys != NULL) {
		res = dns_c_tkey_list_delete(&cfg->trusted_keys);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	if (copy) {
		res = dns_c_tkey_list_copy(cfg->mem, &newl, list);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newl = list;
	}

	cfg->trusted_keys = newl;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


/**
 ** Accessors
 **/

isc_result_t
dns_c_ctx_get_directory(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->directory;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_version(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->version;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_dump_filename(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->dump_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_pid_filename(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->pid_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_stats_filename(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->stats_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_memstats_filename(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->memstats_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_named_xfer(dns_c_ctx_t *cfg, char **retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);

	*retval = cfg->options->named_xfer;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_max_ncache_ttl(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->max_ncache_ttl,
			       retval,
			       &cfg->options->setflags1,
			       MAX_NCACHE_TTL_BIT));
}


isc_result_t
dns_c_ctx_get_transfers_in(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	CHECK_OPTION(cfg->options);

	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_in,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_IN_BIT));
}


isc_result_t
dns_c_ctx_get_transfers_per_ns(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
		
	CHECK_OPTION(cfg->options);
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_per_ns,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_PER_NS_BIT));
}


isc_result_t
dns_c_ctx_get_transfers_out(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
		    
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_out,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_OUT_BIT));
}


isc_result_t
dns_c_ctx_get_max_log_size_ixfr(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_log_size_ixfr,
			      retval,
			      &cfg->options->setflags1,
			      MAX_LOG_SIZE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_get_clean_interval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->clean_interval,
			      retval,
			      &cfg->options->setflags1,
			      CLEAN_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_get_interface_interval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);
	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->interface_interval,
			      retval,
			      &cfg->options->setflags1,
			      INTERFACE_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_get_stats_interval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->stats_interval,
			      retval,
			      &cfg->options->setflags1,
			      STATS_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_get_heartbeat_interval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);
	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->heartbeat_interval,
			      retval,
			      &cfg->options->setflags1,
			      HEARTBEAT_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_get_max_transfer_time_in(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	CHECK_CONFIG(cfg);
	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_transfer_time_in,
			      retval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_IN_BIT));
}


isc_result_t
dns_c_ctx_get_data_size(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->data_size,
			       retval,
			       &cfg->options->setflags1,
			       DATA_SIZE_BIT));
}


isc_result_t
dns_c_ctx_get_stack_size(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->stack_size,
			       retval,
			       &cfg->options->setflags1,
			       STACK_SIZE_BIT));
}


isc_result_t
dns_c_ctx_get_core_size(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->core_size,
			       retval,
			       &cfg->options->setflags1,
			       CORE_SIZE_BIT));
}


isc_result_t
dns_c_ctx_get_files(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->files,
			       retval,
			       &cfg->options->setflags1,
			       FILES_BIT));
}


isc_result_t
dns_c_ctx_get_fake_iquery(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->fake_iquery,
				retval,
				&cfg->options->setflags1,
				FAKE_IQUERY_BIT));
}


isc_result_t
dns_c_ctx_get_recursion(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->recursion,
				retval,
				&cfg->options->setflags1,
				RECURSION_BIT));
}


isc_result_t
dns_c_ctx_get_fetch_glue(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->fetch_glue,
				retval,
				&cfg->options->setflags1,
				FETCH_GLUE_BIT));
}


isc_result_t
dns_c_ctx_get_notify(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->notify,
				retval,
				&cfg->options->setflags1,
				NOTIFY_BIT));
}


isc_result_t
dns_c_ctx_get_host_statistics(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->host_statistics,
				retval,
				&cfg->options->setflags1,
				HOST_STATISTICS_BIT));
}


isc_result_t
dns_c_ctx_get_dealloc_on_exit(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->dealloc_on_exit,
				retval,
				&cfg->options->setflags1,
				DEALLOC_ON_EXIT_BIT));
}


isc_result_t
dns_c_ctx_get_use_ixfr(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->use_ixfr,
				retval,
				&cfg->options->setflags1,
				USE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_get_maintain_ixfr_base(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->maintain_ixfr_base,
				retval,
				&cfg->options->setflags1,
				MAINTAIN_IXFR_BASE_BIT));
}


isc_result_t
dns_c_ctx_get_has_old_clients(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->has_old_clients,
				retval,
				&cfg->options->setflags1,
				HAS_OLD_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_get_auth_nx_domain(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->auth_nx_domain,
				retval,
				&cfg->options->setflags1,
				AUTH_NX_DOMAIN_BIT));
}


isc_result_t
dns_c_ctx_get_multiple_cnames(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->multiple_cnames,
				retval,
				&cfg->options->setflags1,
				MULTIPLE_CNAMES_BIT));
}


isc_result_t
dns_c_ctx_get_use_id_pool(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->use_id_pool,
				retval,
				&cfg->options->setflags1,
				USE_ID_POOL_BIT));
}


isc_result_t
dns_c_ctx_get_dialup(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->dialup,
				retval,
				&cfg->options->setflags1,
				DIALUP_BIT));
}


isc_result_t
dns_c_ctx_get_query_source_addr(dns_c_ctx_t *cfg, dns_c_addr_t *addr)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(addr != NULL);

	if (DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT, &cfg->options->setflags1)) {
		*addr = cfg->options->query_source_addr;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_ctx_get_query_source_port(dns_c_ctx_t *cfg, short *port)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(port != NULL);

	if (DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT, &cfg->options->setflags1)) {
		*port = cfg->options->query_source_port;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_ctx_get_transfer_format(dns_c_ctx_t *cfg, dns_transfer_format_t *retval)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT,
			   &cfg->options->setflags1)) {
		*retval = cfg->options->transfer_format;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_ctx_get_checknames(dns_c_ctx_t *cfg,
			 dns_c_trans_t transtype,
			 dns_c_severity_t *sever)
{
	isc_boolean_t isset = ISC_FALSE;
	isc_result_t res;

	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(sever != NULL);

	switch (transtype) {
	case dns_trans_primary:
		isset = DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT,
				       &cfg->options->setflags1);
		break;

	case dns_trans_secondary:
		isset = DNS_C_CHECKBIT(CHECKNAME_SEC_BIT,
				       &cfg->options->setflags1);
		break;

	case dns_trans_response:
		isset = DNS_C_CHECKBIT(CHECKNAME_RESP_BIT,
				       &cfg->options->setflags1);
		break;

	default:
		dns_c_error(0, "bad transport value: %d\n", transtype);
		return (ISC_R_FAILURE);
	}

	if (isset) {
		*sever = cfg->options->check_names[transtype];
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_ctx_get_queryacl(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->queryacl, list));
}


isc_result_t
dns_c_ctx_get_transferacl(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->transferacl, list));
}


isc_result_t
dns_c_ctx_get_blackhole(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->blackhole, list));
}


isc_result_t
dns_c_ctx_get_topology(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->topology, list));
}


isc_result_t
dns_c_ctx_get_sortlist(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->sortlist, list));
}


isc_result_t
dns_c_ctx_get_listen_list(dns_c_ctx_t *cfg, dns_c_lstn_list_t **ll)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(ll != NULL);

	*ll = NULL;

	if (cfg->options->listens != NULL) {
		*ll = cfg->options->listens;
	}

	return (*ll == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_get_forward(dns_c_ctx_t *cfg, dns_c_forw_t *forw)
{
	isc_result_t res;
	
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(forw != NULL);

	if (DNS_C_CHECKBIT(FORWARD_BIT, &cfg->options->setflags1)) {
		return (ISC_R_NOTFOUND);
	} else {
		*forw = cfg->options->forward;
		res = ISC_R_SUCCESS;
	}

	return (res);
}


isc_result_t
dns_c_ctx_get_forwarders(dns_c_ctx_t *cfg, dns_c_ipmatch_list_t **list)
{
	CHECK_CONFIG(cfg);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->forwarders, list));
}


isc_result_t
dns_c_ctx_get_rrsetorder_list(dns_c_ctx_t *cfg, dns_c_rrso_list_t **retval)
{
	CHECK_CONFIG(cfg);
	REQUIRE(retval != NULL);

	if (cfg->options == NULL || cfg->options->ordering == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*retval = cfg->options->ordering;
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_ctx_get_trusted_keys(dns_c_ctx_t *cfg, dns_c_tkey_list_t **retval)
{
	CHECK_CONFIG(cfg);
	REQUIRE(retval != NULL);

	if (cfg->trusted_keys == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*retval = cfg->trusted_keys;
		return (ISC_R_SUCCESS);
	}
}



isc_result_t
dns_c_ctx_options_new(isc_mem_t *mem, dns_c_options_t **options)
{
	int i;
	dns_c_options_t *opts = NULL;

	REQUIRE(mem != NULL);
	REQUIRE(options != NULL);

	*options = NULL;
	
	opts = isc_mem_get(mem, sizeof *opts);
	if (opts == NULL) {
		return (ISC_R_NOMEMORY);
	}

	opts->directory = NULL;
	opts->version = NULL;
	opts->dump_filename = NULL;
	opts->pid_filename = NULL;
	opts->stats_filename = NULL;
	opts->memstats_filename = NULL;
	opts->named_xfer = NULL;

	opts->mem = mem;
	opts->magic = OPTION_MAGIC;
	opts->flags = 0;
	opts->max_ncache_ttl = 0;
	
	opts->transfers_in = 0;
	opts->transfers_per_ns = 0;
	opts->transfers_out = 0;
	opts->max_log_size_ixfr = 0;
	opts->clean_interval = 0;
	opts->interface_interval = 0;
	opts->stats_interval = 0;
	opts->heartbeat_interval = 0;
	
	opts->fake_iquery = ISC_FALSE;
	opts->recursion = ISC_FALSE;
	opts->fetch_glue = ISC_FALSE;
	opts->notify = ISC_FALSE;
	opts->host_statistics = ISC_FALSE;
	opts->dealloc_on_exit = ISC_FALSE;
	opts->use_ixfr = ISC_FALSE;
	opts->maintain_ixfr_base = ISC_FALSE;
	opts->has_old_clients = ISC_FALSE;
	opts->auth_nx_domain = ISC_FALSE;
	opts->multiple_cnames = ISC_FALSE;
	opts->use_id_pool = ISC_FALSE;
	opts->dialup = ISC_FALSE;

	opts->max_transfer_time_in = 0;

	opts->data_size = 0;
	opts->stack_size = 0;
	opts->core_size = 0;
	opts->files = 0;
	
	opts->transfer_format = dns_one_answer;
	
	for (i = 0 ; i < DNS_C_TRANSCOUNT ; i++) {
		opts->check_names[i] = dns_c_severity_fail;
	}

	opts->queryacl = NULL;
	opts->transferacl = NULL;
	opts->blackhole = NULL;
	opts->topology = NULL;
	opts->sortlist = NULL;
	opts->listens = NULL;
	opts->ordering = NULL;

	opts->forward = dns_c_forw_only;
	opts->forwarders = NULL;

	memset(&opts->setflags1, 0x0, sizeof opts->setflags1);
	
	*options = opts;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_options_delete(dns_c_options_t **opts)
{
	dns_c_options_t *options;
	isc_result_t r;
	
	REQUIRE(opts != NULL);

	options = *opts;
	if (options == NULL) {
		return (ISC_R_SUCCESS);
	}
	
	CHECK_OPTION(options);

	if (options->directory != NULL) {
		isc_mem_free(options->mem, options->directory);
	}

	if (options->version != NULL) {
		isc_mem_free(options->mem, options->version);
	}

	if (options->dump_filename != NULL) {
		isc_mem_free(options->mem, options->dump_filename);
	}

	if (options->pid_filename != NULL) {
		isc_mem_free(options->mem, options->pid_filename);
	}

	if (options->stats_filename != NULL) {
		isc_mem_free(options->mem, options->stats_filename);
	}

	if (options->memstats_filename != NULL) {
		isc_mem_free(options->mem, options->memstats_filename);
	}

	if (options->named_xfer != NULL) {
		isc_mem_free(options->mem, options->named_xfer);
	}

	r = dns_c_ipmatch_list_delete(&options->queryacl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_delete(&options->transferacl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_delete(&options->blackhole);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_delete(&options->topology);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_delete(&options->sortlist);
	if (r != ISC_R_SUCCESS) return (r);

	r = dns_c_lstn_list_delete(&options->listens);
	if (r != ISC_R_SUCCESS) return (r);

	r = dns_c_rrso_list_delete(&options->ordering);
	if (r != ISC_R_SUCCESS) return (r);

	r = dns_c_ipmatch_list_delete(&options->forwarders);
	if (r != ISC_R_SUCCESS) return (r);

	*opts = NULL;

	isc_mem_put(options->mem, options, sizeof *options);
	
	return (ISC_R_SUCCESS);
}


void
dns_c_ctx_options_print(FILE *fp, int indent, dns_c_options_t *options)
{
	dns_c_severity_t nameseverity;
	
	if (options == NULL) {
		return;
	}
	
	REQUIRE(fp != NULL);

	CHECK_OPTION(options);

#define PRINT_INTEGER(field, bit, name, bitfield)			\
	if (DNS_C_CHECKBIT(bit, &options->bitfield)) {			\
		dns_c_printtabs(fp, indent + 1);			\
		fprintf(fp, "%s %d;\n",name,(int)options->field);	\
	}
	
#define PRINT_AS_MINUTES(field, bit, name, bitfield)		\
	if (DNS_C_CHECKBIT(bit, &options->bitfield)) {		\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %lu;\n",name,			\
			(unsigned long)options->field / 60);	\
	}

#define PRINT_AS_BOOLEAN(field, bit, name, bitfield)		\
	if (DNS_C_CHECKBIT(bit, &options->bitfield)) {		\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s %s;\n",name,			\
			(options->field ? "true" : "false"));	\
	}

#define PRINT_AS_SIZE_CLAUSE(field, bit, name, bitfield)	\
	if (DNS_C_CHECKBIT(bit, &options->bitfield)) {		\
		dns_c_printtabs(fp, indent + 1);		\
		fprintf(fp, "%s ",name);			\
		if (options->field == DNS_C_SIZE_SPEC_DEFAULT) { \
			fprintf(fp, "default");			\
		} else {					\
			dns_c_print_in_units(fp, options->data_size); \
		}						\
		fprintf(fp, ";\n");				\
	}

#define PRINT_CHAR_P(field, name)					\
	if (options->field != NULL) {					\
		dns_c_printtabs(fp, indent + 1);			\
		fprintf(fp, "%s \"%s\";\n", name, options->field);	\
	}
	


	dns_c_printtabs (fp, indent);
	fprintf (fp, "options {\n");

	PRINT_CHAR_P(version, "version");
	PRINT_CHAR_P(directory, "directory");
	PRINT_CHAR_P(dump_filename, "dump-file");
	PRINT_CHAR_P(pid_filename, "pid-file");
	PRINT_CHAR_P(stats_filename, "statistics-file");
	PRINT_CHAR_P(memstats_filename, "memstatistics-file");
	PRINT_CHAR_P(named_xfer, "named-xfer");

	PRINT_INTEGER(transfers_in, TRANSFERS_IN_BIT,
		      "transfers-in", setflags1);
	PRINT_INTEGER(transfers_per_ns, TRANSFERS_PER_NS_BIT,
		      "transfers-per-ns", setflags1);
	PRINT_INTEGER(transfers_out, TRANSFERS_OUT_BIT,
		      "transfers-out", setflags1);
	PRINT_INTEGER(max_log_size_ixfr, MAX_LOG_SIZE_IXFR_BIT,
		      "max-ixfr-log-size", setflags1);
	
	PRINT_INTEGER(max_ncache_ttl, MAX_NCACHE_TTL_BIT,
		      "max-ncache-ttl", setflags1);
	
	PRINT_AS_MINUTES(clean_interval, CLEAN_INTERVAL_BIT,
			 "cleaning-interval", setflags1);
	PRINT_AS_MINUTES(interface_interval, INTERFACE_INTERVAL_BIT,
			 "interface-interval", setflags1);
	PRINT_AS_MINUTES(stats_interval, STATS_INTERVAL_BIT,
			 "statistics-interval", setflags1);
	PRINT_AS_MINUTES(heartbeat_interval, HEARTBEAT_INTERVAL_BIT,
			 "heartbeat-interval", setflags1);
	PRINT_AS_MINUTES(max_transfer_time_in, MAX_TRANSFER_TIME_IN_BIT,
			 "max-transfer-time-in", setflags1);

	PRINT_AS_SIZE_CLAUSE(data_size, DATA_SIZE_BIT, "datasize",
			     setflags1);	
	PRINT_AS_SIZE_CLAUSE(stack_size, STACK_SIZE_BIT, "stacksize",
			     setflags1);	
	PRINT_AS_SIZE_CLAUSE(core_size, CORE_SIZE_BIT, "coresize",
			     setflags1);	
	PRINT_AS_SIZE_CLAUSE(files, FILES_BIT, "files",
			     setflags1);

	PRINT_AS_BOOLEAN(expert_mode, EXPERT_MODE_BIT,
			 "expert-mode", setflags1);
	PRINT_AS_BOOLEAN(fake_iquery, FAKE_IQUERY_BIT,
			 "fake-iquery", setflags1);
	PRINT_AS_BOOLEAN(recursion, RECURSION_BIT,
			 "recursion", setflags1);
	PRINT_AS_BOOLEAN(fetch_glue, FETCH_GLUE_BIT,
			 "fetch-glue", setflags1);
	PRINT_AS_BOOLEAN(notify, NOTIFY_BIT,
			 "notify", setflags1);
	PRINT_AS_BOOLEAN(host_statistics, HOST_STATISTICS_BIT,
			 "host-statistics", setflags1);
	PRINT_AS_BOOLEAN(dealloc_on_exit, DEALLOC_ON_EXIT_BIT,
			 "deallocate-on-exit", setflags1);
	PRINT_AS_BOOLEAN(use_ixfr, USE_IXFR_BIT,
			 "use-ixfr", setflags1);
	PRINT_AS_BOOLEAN(maintain_ixfr_base, MAINTAIN_IXFR_BASE_BIT,
			 "maintain-ixfr-base", setflags1);
	PRINT_AS_BOOLEAN(has_old_clients, HAS_OLD_CLIENTS_BIT,
			 "has-old-clients", setflags1);
	PRINT_AS_BOOLEAN(auth_nx_domain, AUTH_NX_DOMAIN_BIT,
			 "auth-nxdomain", setflags1);
	PRINT_AS_BOOLEAN(multiple_cnames, MULTIPLE_CNAMES_BIT,
			 "multiple-cnames", setflags1);
	PRINT_AS_BOOLEAN(use_id_pool, USE_ID_POOL_BIT,
			 "use-id-pool", setflags1);
	PRINT_AS_BOOLEAN(dialup, DIALUP_BIT,
			 "dialup", setflags1);

	if (DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(options->transfer_format,
						 ISC_TRUE));
	}
	
	
	if (DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT, &options->setflags1) ||
	    DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "query-source");
		if (options->query_source_addr.u.a.s_addr ==
		    htonl(INADDR_ANY)) {
			fprintf(fp, " address *");
		} else {
			fprintf(fp, " address ");
			dns_c_print_ipaddr(fp, &options->query_source_addr);
		}
		if (options->query_source_port == htons(0)) {
			fprintf(fp, " port *");
		} else {
			fprintf(fp, " port %d",
				(int)ntohs(options->query_source_port));
		}
		fprintf(fp, " ;\n");
	}


	if (DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_primary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_primary, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_SEC_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_secondary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_secondary, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_RESP_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_response];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_response, ISC_TRUE),
			dns_c_nameseverity2string(nameseverity, ISC_TRUE));
	}

	fprintf(fp, "\n");
	
	if (options->queryacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-query ");
		dns_c_ipmatch_list_print(fp, 2, options->queryacl);
		fprintf(fp, "\n");
	}

	if (options->transferacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatch_list_print(fp, 2, options->transferacl);
		fprintf(fp, "\n");
	}

	if (options->blackhole != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "blackhole ");
		dns_c_ipmatch_list_print(fp, 2, options->blackhole);
		fprintf(fp, "\n");
	}

	if (options->topology != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "topology ");
		dns_c_ipmatch_list_print(fp, 2, options->topology);
		fprintf(fp, "\n");
	}

	if (options->sortlist != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "sortlist ");
		dns_c_ipmatch_list_print(fp, 2, options->sortlist);
		fprintf(fp, "\n");
	}

	dns_c_lstn_list_print(fp, indent + 1, options->listens);

	dns_c_ctx_forwarder_print(fp, indent + 1, options);

	dns_c_rrso_list_print(fp, indent + 1, options->ordering);

	dns_c_printtabs(fp, indent);
	fprintf(fp,"};\n");
}


isc_boolean_t
dns_c_ctx_key_defined_p(dns_c_ctx_t *ctx, const char *keyname)
{
	dns_c_kdef_t *keyid;
	isc_result_t res;
	isc_boolean_t rval = ISC_FALSE;

	REQUIRE(ctx != NULL);
	REQUIRE(keyname != NULL);
	REQUIRE(strlen(keyname) > 0);
	
	if (ctx->keydefs != NULL) {
		res = dns_c_kdef_list_find(ctx->keydefs, keyname, &keyid);
		if (res == ISC_R_SUCCESS) {
			rval = ISC_TRUE;
		}
	}

	return rval;
}




/***************************************************************************/


static isc_result_t
cfg_set_string(dns_c_options_t *options, char **field, const char *newval)
{
	char *p;
	isc_boolean_t existed = ISC_FALSE;
	
	CHECK_OPTION(options);
	REQUIRE(field != NULL);

	p = *field;
	*field = NULL;

	if (p != NULL) {
		existed = ISC_TRUE;
	}
	
	if (newval == NULL) {
		if (p != NULL) {
			isc_mem_free(options->mem, p);
		}
		p = NULL;
	} else if (p == NULL) {
		p = isc_mem_strdup(options->mem, newval);
		if (p == NULL) {
			return (ISC_R_NOMEMORY);
		}
	} else if (strlen(p) >= strlen(newval)) {
		strcpy(p, newval);
	} else {
		isc_mem_free(options->mem, p);
		p = isc_mem_strdup(options->mem, newval);
		if (p == NULL) {
			return (ISC_R_NOMEMORY);
		}
	}

	*field = p;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


/* XXX This can get removed and replaced with set_ipmatch_list_field */
static isc_result_t
cfg_set_iplist(dns_c_options_t *options,
	       dns_c_ipmatch_list_t **fieldaddr,
	       dns_c_ipmatch_list_t *newval,
	       isc_boolean_t copy)
{
	isc_result_t res;
	isc_boolean_t existed = ISC_FALSE;
	
	CHECK_OPTION(options);
	REQUIRE(fieldaddr != NULL);

	if (*fieldaddr != NULL) {
		existed = ISC_TRUE;
	}
	
	if (newval == NULL) {
		res = dns_c_ipmatch_list_new(options->mem, fieldaddr);
	} else if (copy) {
		if (*fieldaddr != NULL) {
			res = dns_c_ipmatch_list_empty(*fieldaddr);
			if (res == ISC_R_SUCCESS && newval != NULL) {
				res = dns_c_ipmatch_list_append(*fieldaddr,
								newval,
								ISC_FALSE);
			}
		} else {
			res = dns_c_ipmatch_list_copy(options->mem,
						      fieldaddr, newval);
		}
	} else {
		if (*fieldaddr != NULL) {
			res = dns_c_ipmatch_list_delete(fieldaddr);
			if (res != ISC_R_SUCCESS) {
				return (res);
			}
		} 

		res = ISC_R_SUCCESS;
		
		*fieldaddr = newval;
	}

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}
	
	return (res);
}


static isc_result_t
cfg_set_boolean(dns_c_options_t *options,
		isc_boolean_t *fieldaddr,
		isc_boolean_t newval,
		dns_setbits_t *setfield,
		isc_uint32_t bitnumber)
{
	isc_boolean_t existed;
	
	CHECK_OPTION(options);
	REQUIRE(setfield != NULL);
	REQUIRE(fieldaddr != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

	*fieldaddr = newval;

	existed = DNS_C_CHECKBIT(bitnumber, setfield);
	DNS_C_SETBIT(bitnumber, setfield);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


static isc_result_t
cfg_set_int32(dns_c_options_t *options,
	      isc_int32_t *fieldaddr,
	      isc_int32_t newval,
	      dns_setbits_t *setfield,
	      isc_uint32_t bitnumber)
{
	isc_boolean_t existed;

	CHECK_OPTION(options);
	REQUIRE(setfield != NULL);
	REQUIRE(fieldaddr != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

	*fieldaddr = newval;

	existed = DNS_C_CHECKBIT(bitnumber, setfield);
	DNS_C_SETBIT(bitnumber, setfield);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


static isc_result_t
cfg_set_uint32(dns_c_options_t *options,
	       isc_uint32_t *fieldaddr,
	       isc_uint32_t newval,
	       dns_setbits_t *setfield,
	       isc_uint32_t bitnumber)
{
	isc_boolean_t existed;

	CHECK_OPTION(options);
	REQUIRE(setfield != NULL);
	REQUIRE(fieldaddr != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

	*fieldaddr = newval;

	existed = DNS_C_CHECKBIT(bitnumber, setfield);
	DNS_C_SETBIT(bitnumber, setfield);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


static isc_result_t
cfg_get_iplist(dns_c_options_t *options,
	       dns_c_ipmatch_list_t *field,
	       dns_c_ipmatch_list_t **resval)
{
	isc_result_t res;
	
	CHECK_OPTION(options);
	REQUIRE(resval != NULL);

	if (field != NULL && !ISC_LIST_EMPTY(field->elements)) {
		*resval = field;
		res = ISC_R_SUCCESS;
	} else {
		*resval = NULL;
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


static isc_result_t
cfg_get_boolean(dns_c_options_t *options,
		isc_boolean_t *field,
		isc_boolean_t *result,
		dns_setbits_t *setfield,
		isc_uint32_t bitnumber)
{
	isc_result_t res;
	
	CHECK_OPTION(options);
	REQUIRE(result != NULL);

	if (DNS_C_CHECKBIT(bitnumber,setfield)) {
		*result = *field;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


static isc_result_t
cfg_get_int32(dns_c_options_t *options,
	      isc_int32_t *field,
	      isc_int32_t *result,
	      dns_setbits_t *setfield,
	      isc_uint32_t bitnumber)
{
	isc_result_t res;
	
	CHECK_OPTION(options);
	REQUIRE(result != NULL);

	if (DNS_C_CHECKBIT(bitnumber,setfield)) {
		*result = *field;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


static isc_result_t
cfg_get_uint32(dns_c_options_t *options,
	       isc_uint32_t *field,
	       isc_uint32_t *result,
	       dns_setbits_t *setfield,
	       isc_uint32_t bitnumber)
{
	isc_result_t res;
	
	CHECK_OPTION(options);
	REQUIRE(result != NULL);

	if (DNS_C_CHECKBIT(bitnumber,setfield)) {
		*result = *field;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


static isc_result_t
acl_init(dns_c_ctx_t *cfg)
{
	dns_c_ipmatch_element_t *ime;
	dns_c_ipmatch_list_t *iml;
	dns_c_addr_t addr;
	dns_c_acl_t *acl;
	isc_result_t r;

	CHECK_CONFIG(cfg);

	addr.u.a.s_addr = 0U;

	r = dns_c_acl_table_new(cfg->mem, &cfg->acls);
	if (r != ISC_R_SUCCESS) return (r);


	/*
	 * The ANY acl.
	 */
	r = dns_c_acl_new(cfg->acls, "any", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_pattern_new(cfg->mem, &ime, addr, 0);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_set_ipml(acl, iml, ISC_FALSE);
	iml = NULL;
	

	/*
	 * The NONE acl
	 */

	r = dns_c_acl_new(cfg->acls, "none", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_pattern_new(cfg->mem, &ime, addr, 0);
	if (r != ISC_R_SUCCESS) return (r);

	dns_c_ipmatch_negate(ime);

	r = dns_c_ipmatch_list_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);
	
	dns_c_acl_set_ipml(acl, iml, ISC_FALSE);
	iml = NULL;
	

	/*
	 * The LOCALHOST acl
	 */
	r = dns_c_acl_new(cfg->acls, "localhost", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_localhost_new(cfg->mem, &ime);
	if (r != ISC_R_SUCCESS) return (r);

	r = dns_c_ipmatch_list_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_set_ipml(acl, iml, ISC_FALSE);
	iml = NULL;
	
	
	/*
	 * The LOCALNETS acl
	 */
	r = dns_c_acl_new(cfg->acls, "localnets", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_localnets_new(cfg->mem, &ime);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatch_list_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_set_ipml(acl, iml, ISC_FALSE);
	iml = NULL;
	
	return (ISC_R_SUCCESS);
}



static isc_result_t
logging_init (dns_c_ctx_t *cfg)
{
	isc_result_t res;
	dns_c_logcat_t *cat;
	dns_c_logchan_t *chan;
	
	REQUIRE(cfg != NULL);
	REQUIRE(cfg->logging == NULL);

	res = dns_c_logging_list_new(cfg->mem, &cfg->logging);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	/* default_syslog channel */
	chan = NULL;
	res = dns_c_ctx_add_syslog_channel(cfg, DNS_C_DEFAULT_SYSLOG, &chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_set_predef(chan, ISC_TRUE);
	dns_c_logchan_set_facility(chan, LOG_DAEMON);
	dns_c_logchan_set_severity(chan, dns_c_log_info);

	
	/* default_debug channel */
	chan = NULL;
	res = dns_c_ctx_add_file_channel(cfg, DNS_C_DEFAULT_DEBUG, &chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_set_predef(chan, ISC_TRUE);
	dns_c_logchan_set_path(chan, DNS_C_DEFAULT_DEBUG_PATH);
	dns_c_logchan_set_severity(chan, dns_c_log_dynamic);


	/* null channel */
	chan = NULL;
	res = dns_c_ctx_add_null_channel(cfg, DNS_C_NULL, &chan);
	dns_c_logchan_set_predef(chan, ISC_TRUE);


	/* default_stderr channel */
	chan = NULL;
	res = dns_c_ctx_add_file_channel(cfg, DNS_C_DEFAULT_STDERR, &chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_set_predef(chan, ISC_TRUE);
	dns_c_logchan_set_path(chan, DNS_C_STDERR_PATH);
	dns_c_logchan_set_severity(chan, dns_c_log_info);


	/* default category */
	cat = NULL;
	res = dns_c_ctx_add_category(cfg, dns_c_cat_default, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_set_predef(cat, ISC_TRUE);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_SYSLOG);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_DEBUG);
	

	/* panic category */
	cat = NULL;
	res = dns_c_ctx_add_category(cfg, dns_c_cat_panic, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_set_predef(cat, ISC_TRUE);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_SYSLOG);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_DEBUG);

	
	/* eventlib category */
	cat = NULL;
	res = dns_c_ctx_add_category(cfg, dns_c_cat_eventlib, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_set_predef(cat, ISC_TRUE);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_DEBUG);


	/* packet category */
	cat = NULL;
	res = dns_c_ctx_add_category(cfg, dns_c_cat_packet, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_set_predef(cat, ISC_TRUE);
	dns_c_logcat_add_name(cat, DNS_C_DEFAULT_DEBUG);

	
	return (ISC_R_SUCCESS);
}

