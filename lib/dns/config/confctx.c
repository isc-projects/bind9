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

#include <syslog.h>	/* XXXRTH */
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/magic.h>

#include <dns/confctx.h>
#include <dns/confcommon.h>
#include <dns/log.h>

#include "confpvt.h"



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
#define MAX_TRANSFER_TIME_OUT_BIT	10
#define MAX_TRANSFER_IDLE_IN_BIT	11
#define MAX_TRANSFER_IDLE_OUT_BIT	12
#define DATA_SIZE_BIT			13
#define STACK_SIZE_BIT			14
#define CORE_SIZE_BIT			15
#define FILES_BIT			16
#define QUERY_SOURCE_ADDR_BIT		17
#define QUERY_SOURCE_PORT_BIT		18
#define FAKE_IQUERY_BIT			19
#define RECURSION_BIT			20
#define FETCH_GLUE_BIT			21
#define NOTIFY_BIT			22
#define HOST_STATISTICS_BIT		23
#define DEALLOC_ON_EXIT_BIT		24
#define USE_IXFR_BIT			25
#define MAINTAIN_IXFR_BASE_BIT		26
#define HAS_OLD_CLIENTS_BIT		27
#define AUTH_NX_DOMAIN_BIT		28
#define MULTIPLE_CNAMES_BIT		29
#define USE_ID_POOL_BIT			30
#define DIALUP_BIT			31
#define CHECKNAME_PRIM_BIT		32
#define CHECKNAME_SEC_BIT		33
#define CHECKNAME_RESP_BIT		34
#define OPTIONS_TRANSFER_FORMAT_BIT	35
#define FORWARD_BIT			36
#define EXPERT_MODE_BIT			37
#define RFC2308_TYPE1_BIT		38
#define TCP_CLIENTS_BIT			39
#define RECURSIVE_CLIENTS_BIT		40
#define TRANSFER_SOURCE_BIT		41


static isc_result_t cfg_set_iplist(dns_c_options_t *options,
				   dns_c_iplist_t **fieldaddr,
				   dns_c_iplist_t *newval,
				   isc_boolean_t copy);
static isc_result_t cfg_set_ipmatchlist(dns_c_options_t *options,
					dns_c_ipmatchlist_t **fieldaddr,
					dns_c_ipmatchlist_t *newval,
					isc_boolean_t copy);
static isc_result_t cfg_set_boolean(dns_c_options_t *options,
				    isc_boolean_t *fieldaddr,
				    isc_boolean_t newval,
				    dns_c_setbits_t *setfield,
				    isc_uint32_t bitnumber);
static isc_result_t cfg_set_int32(dns_c_options_t *options,
				  isc_int32_t *fieldaddr,
				  isc_int32_t newval,
				  dns_c_setbits_t *setfield,
				  isc_uint32_t bitnumber);
static isc_result_t cfg_set_uint32(dns_c_options_t *options,
				   isc_uint32_t *fieldaddr,
				   isc_uint32_t newval,
				   dns_c_setbits_t *setfield,
				   isc_uint32_t bitnumber);
static isc_result_t cfg_set_string(dns_c_options_t *options,
				   char **field,
				   const char *newval);

static isc_result_t cfg_get_uint32(dns_c_options_t *options,
				   isc_uint32_t *field,
				   isc_uint32_t *result,
				   dns_c_setbits_t *setfield,
				   isc_uint32_t bitnumber);
static isc_result_t cfg_get_int32(dns_c_options_t *options,
				  isc_int32_t *field,
				  isc_int32_t *result,
				  dns_c_setbits_t *setfield,
				  isc_uint32_t bitnumber);
static isc_result_t cfg_get_boolean(dns_c_options_t *options,
				    isc_boolean_t *field,
				    isc_boolean_t *result,
				    dns_c_setbits_t *setfield,
				    isc_uint32_t bitnumber);
static isc_result_t cfg_get_ipmatchlist(dns_c_options_t *options,
					dns_c_ipmatchlist_t *field,
					dns_c_ipmatchlist_t **resval);
static isc_result_t cfg_get_iplist(dns_c_options_t *options,
				   dns_c_iplist_t *field,
				   dns_c_iplist_t **resval);
static isc_result_t acl_init(dns_c_ctx_t *cfg);
static isc_result_t logging_init (dns_c_ctx_t *cfg);
static isc_result_t  make_options(dns_c_ctx_t *cfg);



isc_result_t
dns_c_checkconfig(dns_c_ctx_t *ctx)
{
	isc_boolean_t 		bval;
	char     	       *cpval;
	dns_severity_t	severity;
	isc_int32_t		intval;
	dns_c_ipmatchlist_t    *ipml;

	if (dns_c_ctx_getnamedxfer(ctx, &cpval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "named-xfer is now obsolete");
	}

	
	if (dns_c_ctx_getdumpfilename(ctx, &cpval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "dump-file is not yet implemented.");
	}
	
		
	if (dns_c_ctx_getmemstatsfilename(ctx, &cpval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "memstatistics-file is not yet implemented.");
	}
	

	if ((dns_c_ctx_getauthnxdomain(ctx, &bval)) == ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "the default for auth-nxdomain is now ``no''");
	}


	if (dns_c_ctx_getdealloconexit(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "deallocate-on-exit is obsolete.");
	}

	
	if (dns_c_ctx_getfakeiquery(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "fake-iquery is obsolete.");
	}


	if (dns_c_ctx_getfetchglue(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "fetch-glue is not yet implemented.");
	}


	if (dns_c_ctx_gethasoldclients(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "has-old-clients is obsolete.");
	}


	if (dns_c_ctx_gethoststatistics(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "host-statistics is not yet implemented.");
	}

	
	if (dns_c_ctx_getmultiplecnames(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "multiple-cnames is obsolete.");
	}


	if (dns_c_ctx_getuseidpool(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "use-id-pool is obsolete.");
	}


	if ((dns_c_ctx_getchecknames(ctx, dns_trans_primary,
				     &severity) != ISC_R_NOTFOUND) ||
	    (dns_c_ctx_getchecknames(ctx, dns_trans_secondary,
				     &severity) != ISC_R_NOTFOUND) ||
	    (dns_c_ctx_getchecknames(ctx, dns_trans_response,
				     &severity) != ISC_R_NOTFOUND)) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "check-names are not yet implemented.");
	}
	

	if (dns_c_ctx_getmaxlogsizeixfr(ctx, &intval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "max-ixfr-log-size is not yet implemented.");
	}
	

	if (dns_c_ctx_getstatsinterval(ctx, &intval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "statistics-interval is not yet implemented.");
	}

	
	if (dns_c_ctx_gettopology(ctx, &ipml) != ISC_R_NOTFOUND) {
		dns_c_ipmatchlist_detach(&ipml);
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "topology is not yet implemented.");
	}

	if (dns_c_ctx_getsortlist(ctx, &ipml) != ISC_R_NOTFOUND) {
		dns_c_ipmatchlist_detach(&ipml);
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "sortlist is not yet implemented.");
	}


	if (dns_c_ctx_getrfc2308type1(ctx, &bval) != ISC_R_NOTFOUND) {
		isc_log_write(dns_lctx,DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_WARNING,
			      "rfc2308-type-1 is not yet implemented.");
	}



	/*
  	named-xfer              obsolete
	dump-file               not yet implemented
	memstatistics-file      not yet implemented
	auth-nxdomain           default changed (to "no")
	deallocate-on-exit      obsolete (always "yes")
	fake-iquery             obsolete (always "no")
	fetch-glue              not yet implemented (always "no")
	has-old-clients         obsolete (always "no")
	host-statistics         not yet implemented
	multiple-cnames         obsolete (always "no")
	use-id-pool             obosolete (always "yes")
	maintain-ixfr-base      obosolete (always "yes")
	check-names             not yet implemented
	max-ixfr-log-size       not yet implemented
	statistics-interval     not yet implemented
	topology                not yet implemented
	sortlist                not yet implemented
	*/

	
	return (ISC_R_SUCCESS);
}


/* ************************************************************************ */

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

	cfg->magic = DNS_C_CONFIG_MAGIC;
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
	cfg->resolver = NULL;
	cfg->cache = NULL;
	cfg->views = NULL;

	cfg->currview = NULL;
	cfg->currzone = NULL;
	
	r = acl_init(cfg);
	if (r != ISC_R_SUCCESS) {
		return (r);
	}

	r = logging_init(cfg);
	if (r != ISC_R_SUCCESS) {
		return (r);
	}
	
	
#if 1					/* XXX brister */
	cfg->controls = NULL;
#else	
	r = dns_c_ctrllist_new(mem, &cfg->controls);
	if (r != ISC_R_SUCCESS) {
		dns_c_ctx_delete(&cfg);
		return r;
	}
#endif	

	*ctx = cfg;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_delete(dns_c_ctx_t **cfg)
{
	dns_c_ctx_t *c;

	REQUIRE(cfg != NULL);
	REQUIRE(*cfg != NULL);
	REQUIRE(DNS_C_CONFCTX_VALID(*cfg));

	c = *cfg;

	REQUIRE(c->mem != NULL);

	if (c->options != NULL)
		dns_c_ctx_optionsdelete(&c->options);
	
	if (c->controls != NULL)
		dns_c_ctrllist_delete(&c->controls);
	
	if (c->servers != NULL)
		dns_c_srvlist_delete(&c->servers);
	
	if (c->acls != NULL)
		dns_c_acltable_delete(&c->acls);
	
	if (c->keydefs != NULL)
		dns_c_kdeflist_delete(&c->keydefs);
	
	if (c->zlist != NULL)
		dns_c_zonelist_delete(&c->zlist);
	
	if (c->trusted_keys != NULL)
		dns_c_tkeylist_delete(&c->trusted_keys);
	
	if (c->logging != NULL)
		dns_c_logginglist_delete(&c->logging);
	
	if (c->views != NULL)
		dns_c_viewtable_delete(&c->views);

	c->magic = 0;
	isc_mem_put(c->mem, c, sizeof *c);
	*cfg = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setcontrols(dns_c_ctx_t *cfg, dns_c_ctrllist_t *ctrls)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(DNS_C_CONFCTLLIST_VALID(ctrls));

	if (cfg->controls != NULL) {
		existed = ISC_TRUE;
		dns_c_ctrllist_delete(&cfg->controls);
	}

	cfg->controls = ctrls;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}

isc_result_t
dns_c_ctx_getcontrols(dns_c_ctx_t *cfg, dns_c_ctrllist_t **ctrls)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	*ctrls = cfg->controls;

	return (cfg->controls != NULL ? ISC_R_SUCCESS : ISC_R_NOTFOUND);
}

	

		      
isc_result_t
dns_c_ctx_setcurrzone(dns_c_ctx_t *cfg, dns_c_zone_t *zone)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	cfg->currzone = zone;		/* zone may be NULL */

	/* XXX should we validate that the zone is in our table? */

	return (ISC_R_SUCCESS);
}



dns_c_zone_t *
dns_c_ctx_getcurrzone(dns_c_ctx_t *cfg)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	return (cfg->currzone);
}

	

isc_result_t
dns_c_ctx_setcurrview(dns_c_ctx_t *cfg,
		      dns_c_view_t *view)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	cfg->currview = view;

	/* XXX should we validate that the zone is in our table? */

	return (ISC_R_SUCCESS);
}



dns_c_view_t *
dns_c_ctx_getcurrview(dns_c_ctx_t *cfg)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	return (cfg->currview);
}

	

void
dns_c_ctx_print(FILE *fp, int indent, dns_c_ctx_t *cfg)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->logging != NULL) {
		dns_c_logginglist_print(fp, indent,
					cfg->logging, ISC_FALSE);
		fprintf(fp,"\n");
	}
	
	
	if (cfg->keydefs != NULL) {
		dns_c_kdeflist_print(fp, indent, cfg->keydefs);
		fprintf(fp, "\n");
	}
	

	if (cfg->trusted_keys != NULL) {
		dns_c_tkeylist_print(fp, indent, cfg->trusted_keys);
		fprintf(fp, "\n");
	}
	

	if (cfg->acls != NULL) {
		dns_c_acltable_print(fp, indent, cfg->acls);
		fprintf(fp,"\n");
	}
	

	if (cfg->zlist != NULL) {
		dns_c_zonelist_printpreopts(fp, indent, cfg->zlist);
		fprintf(fp, "\n");
	}
	
	
	if (cfg->options != NULL) {
		dns_c_ctx_optionsprint(fp, indent, cfg->options);
		fprintf(fp,"\n");
	}
	

	if (cfg->views != NULL) {
		dns_c_viewtable_print(fp, indent, cfg->views);
		fprintf(fp, "\n");
	}
	
	
	if (cfg->zlist != NULL) {
		dns_c_zonelist_printpostopts(fp, indent, cfg->zlist);
		fprintf(fp, "\n");
	}

	if (cfg->controls != NULL) {
		dns_c_ctrllist_print(fp, indent, cfg->controls);
		fprintf(fp, "\n");
	}
	

	if (cfg->servers != NULL) {
		dns_c_srvlist_print(fp, indent, cfg->servers);
		fprintf(fp, "\n");
	}
}


void
dns_c_ctx_forwarderprint(FILE *fp, int indent, dns_c_options_t *options)
{
	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (options == NULL) {
		return;
	}

	REQUIRE(DNS_C_CONFOPT_VALID(options));

	if (DNS_C_CHECKBIT(FORWARD_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(options->forward, ISC_TRUE));
	}

	if (options->forwarders != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 1,
				   options->forwarders);
		fprintf(fp, ";\n");
	}
}


isc_result_t
dns_c_ctx_getoptions(dns_c_ctx_t *cfg, dns_c_options_t **options)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(options != NULL);
	
	if (cfg->options != NULL) {
		REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));
	}
	
	*options = cfg->options;
	
	return (cfg->options == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}



isc_result_t
dns_c_ctx_getlogging(dns_c_ctx_t *cfg, dns_c_logginglist_t **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	*retval = cfg->logging;

	return (cfg->logging == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setlogging(dns_c_ctx_t *cfg, dns_c_logginglist_t *newval,
		     isc_boolean_t deepcopy)
{
	dns_c_logginglist_t *ll;
	isc_result_t res;
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	existed = ISC_TF(cfg->logging != NULL);
	
	if (deepcopy) {
		res = dns_c_logginglist_copy(cfg->mem, &ll, newval);
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
dns_c_ctx_getkdeflist(dns_c_ctx_t *cfg,
                      dns_c_kdeflist_t **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
        REQUIRE(retval != NULL);

	*retval = cfg->keydefs;
	
        if (cfg->keydefs == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_ctx_setkdeflist(dns_c_ctx_t *cfg,
		      dns_c_kdeflist_t *newval, isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->keydefs != NULL) {
		dns_c_kdeflist_delete(&cfg->keydefs);
	}
	
	if (newval == NULL) {
		cfg->keydefs = NULL;
		res = ISC_R_SUCCESS;
	} else if (deepcopy) {
		res = dns_c_kdeflist_copy(cfg->mem,
					  &cfg->keydefs, newval);
	} else {
		cfg->keydefs = newval;
		res = ISC_R_SUCCESS;
	}

	return (res);
}

	
isc_result_t
dns_c_ctx_addfile_channel(dns_c_ctx_t *cfg, const char *name,
			  dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name, dns_c_logchan_file,
				&newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logginglist_addchannel(cfg->logging, newc,
					   ISC_FALSE);

	*chan = newc;

	return (res);
}


isc_result_t
dns_c_ctx_addsyslogchannel(dns_c_ctx_t *cfg, const char *name,
			   dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name,
				dns_c_logchan_syslog, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logginglist_addchannel(cfg->logging, newc,
					   ISC_FALSE);

	*chan = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_addnullchannel(dns_c_ctx_t *cfg, const char *name,
			 dns_c_logchan_t **chan)
{
	dns_c_logchan_t *newc;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(name != NULL);
	REQUIRE(chan != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logchan_new(cfg->mem, name, dns_c_logchan_null,
				&newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_logginglist_addchannel(cfg->logging, newc,
					   ISC_FALSE);

	*chan = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_addcategory(dns_c_ctx_t *cfg, dns_c_category_t category,
		      dns_c_logcat_t **newcat)
{
	dns_c_logcat_t *newc;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(newcat != NULL);
	REQUIRE(cfg->logging != NULL);

	res = dns_c_logcat_new(cfg->mem, category, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	res = dns_c_logginglist_addcategory(cfg->logging, newc,
					    ISC_FALSE);

	*newcat = newc;
	
	return (res);
}


isc_result_t
dns_c_ctx_currchannel(dns_c_ctx_t *cfg, dns_c_logchan_t **channel)
{
	dns_c_logchan_t *newc;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(channel != NULL);
	REQUIRE(cfg->logging != NULL);

	newc = ISC_LIST_TAIL(cfg->logging->channels);

	*channel = newc;
	
	return (newc == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_boolean_t
dns_c_ctx_channeldefinedp(dns_c_ctx_t *cfg, const char *name)
{
	isc_result_t res;
	dns_c_logchan_t *chan;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);

	res = dns_c_logginglist_chanbyname(cfg->logging, name, &chan);

	return (ISC_TF(res == ISC_R_SUCCESS));
}



isc_result_t
dns_c_ctx_currcategory(dns_c_ctx_t *cfg, dns_c_logcat_t **category)
{
	dns_c_logcat_t *newc;
	dns_c_logginglist_t *llist;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(category != NULL);

	res = dns_c_ctx_getlogging(cfg, &llist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	newc = ISC_LIST_TAIL(llist->categories);

	*category = newc;
	
	return (newc == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


/*
 * Modifiers for options.
 *
 */


isc_result_t
dns_c_ctx_setdirectory(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->directory,
			       newval));
}


isc_result_t
dns_c_ctx_setversion(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->version,
			       newval));
}


isc_result_t
dns_c_ctx_setdumpfilename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->dump_filename,
			       newval));
}


isc_result_t
dns_c_ctx_setpidfilename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->pid_filename,
			       newval));
}


isc_result_t
dns_c_ctx_setstatsfilename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->stats_filename,
			       newval));
}


isc_result_t
dns_c_ctx_setmemstatsfilename(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->memstats_filename,
			       newval));
}


isc_result_t
dns_c_ctx_setnamedxfer(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->named_xfer,
			       newval));
}


isc_result_t
dns_c_ctx_settkeydomain(dns_c_ctx_t *cfg, const char *newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_string(cfg->options,
			       &cfg->options->tkeydomain,
			       newval));
}


isc_result_t
dns_c_ctx_settkeydhkey(dns_c_ctx_t *cfg,
		       const char *charval, isc_int32_t intval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	cfg->options->tkeydhkeyi = intval;
	return (cfg_set_string(cfg->options,
			       &cfg->options->tkeydhkeycp,
			       charval));
}


isc_result_t
dns_c_ctx_setmaxncachettl(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_uint32(cfg->options, 
			       &cfg->options->max_ncache_ttl,
			       newval,
			       &cfg->options->setflags1,
			       MAX_NCACHE_TTL_BIT));
}


isc_result_t
dns_c_ctx_settransfersin(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options, 
			      &cfg->options->transfers_in,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_IN_BIT));
}


isc_result_t
dns_c_ctx_settransfersperns(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options, 
			      &cfg->options->transfers_per_ns,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_PER_NS_BIT));
}


isc_result_t
dns_c_ctx_settransfersout(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->transfers_out,
			      newval,
			      &cfg->options->setflags1,
			      TRANSFERS_OUT_BIT));
}


isc_result_t
dns_c_ctx_setmaxlogsizeixfr(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_log_size_ixfr,
			      newval,
			      &cfg->options->setflags1,
			      MAX_LOG_SIZE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_setcleaninterval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->clean_interval,
			      newval,
			      &cfg->options->setflags1,
			      CLEAN_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_setinterfaceinterval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->interface_interval,
			      newval,
			      &cfg->options->setflags1,
			      INTERFACE_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_setstatsinterval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->stats_interval,
			      newval,
			      &cfg->options->setflags1,
			      STATS_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_setheartbeat_interval(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->heartbeat_interval,
			      newval,
			      &cfg->options->setflags1,
			      HEARTBEAT_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_setmaxtransfertimein(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_transfer_time_in,
			      newval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_IN_BIT));
}


isc_result_t
dns_c_ctx_setmaxtransfertimeout(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_transfer_time_out,
			      newval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_OUT_BIT));
}


isc_result_t
dns_c_ctx_setmaxtransferidlein(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_transfer_idle_in,
			      newval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_IDLE_IN_BIT));
}


isc_result_t
dns_c_ctx_setmaxtransferidleout(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->max_transfer_idle_out,
			      newval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_IDLE_OUT_BIT));
}


isc_result_t
dns_c_ctx_settcpclients(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->tcp_clients,
			      newval,
			      &cfg->options->setflags1,
			      TCP_CLIENTS_BIT));
}

isc_result_t
dns_c_ctx_setrecursiveclients(dns_c_ctx_t *cfg, isc_int32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_int32(cfg->options,
			      &cfg->options->recursive_clients,
			      newval,
			      &cfg->options->setflags1,
			      RECURSIVE_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_setdatasize(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_uint32(cfg->options,
			       &cfg->options->data_size,
			       newval,
			       &cfg->options->setflags1,
			       DATA_SIZE_BIT));
}


isc_result_t
dns_c_ctx_setstacksize(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_uint32(cfg->options,
			       &cfg->options->stack_size,
			       newval,
			       &cfg->options->setflags1,
			       STACK_SIZE_BIT));
}


isc_result_t
dns_c_ctx_setcoresize(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_uint32(cfg->options,
			       &cfg->options->core_size,
			       newval,
			       &cfg->options->setflags1,
			       CORE_SIZE_BIT));
}


isc_result_t
dns_c_ctx_setfiles(dns_c_ctx_t *cfg, isc_uint32_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_uint32(cfg->options,
			       &cfg->options->files,
			       newval,
			       &cfg->options->setflags1,
			       FILES_BIT));
}


isc_result_t
dns_c_ctx_setexpertmode(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->expert_mode,
				newval,
				&cfg->options->setflags1,
				EXPERT_MODE_BIT));
}


isc_result_t
dns_c_ctx_setfakeiquery(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->fake_iquery,
				newval,
				&cfg->options->setflags1,
				FAKE_IQUERY_BIT));
}


isc_result_t
dns_c_ctx_setrecursion(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->recursion,
				newval,
				&cfg->options->setflags1,
				RECURSION_BIT));
}


isc_result_t
dns_c_ctx_setfetchglue(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->fetch_glue,
				newval,
				&cfg->options->setflags1,
				FETCH_GLUE_BIT));
}


isc_result_t
dns_c_ctx_setnotify(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->notify,
				newval,
				&cfg->options->setflags1,
				NOTIFY_BIT));
}


isc_result_t
dns_c_ctx_sethoststatistics(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->host_statistics,
				newval,
				&cfg->options->setflags1,
				HOST_STATISTICS_BIT));
}


isc_result_t
dns_c_ctx_setdealloconexit(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->dealloc_on_exit,
				newval,
				&cfg->options->setflags1,
				DEALLOC_ON_EXIT_BIT));
}


isc_result_t
dns_c_ctx_setuseixfr(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->use_ixfr,
				newval,
				&cfg->options->setflags1,
				USE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_setmaintainixfrbase(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->maintain_ixfr_base,
				newval,
				&cfg->options->setflags1,
				MAINTAIN_IXFR_BASE_BIT));
}


isc_result_t
dns_c_ctx_sethasoldclients(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->has_old_clients,
				newval,
				&cfg->options->setflags1,
				HAS_OLD_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_setauthnxdomain(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->auth_nx_domain,
				newval,
				&cfg->options->setflags1,
				AUTH_NX_DOMAIN_BIT));
}


isc_result_t
dns_c_ctx_setmultiplecnames(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->multiple_cnames,
				newval,
				&cfg->options->setflags1,
				MULTIPLE_CNAMES_BIT));
}


isc_result_t
dns_c_ctx_setuseidpool(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->use_id_pool,
				newval,
				&cfg->options->setflags1,
				USE_ID_POOL_BIT));
}


isc_result_t
dns_c_ctx_setrfc2308type1(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->rfc2308_type1,
				newval,
				&cfg->options->setflags1,
				RFC2308_TYPE1_BIT));
}


isc_result_t
dns_c_ctx_setdialup(dns_c_ctx_t *cfg, isc_boolean_t newval)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	return (cfg_set_boolean(cfg->options,
				&cfg->options->dialup,
				newval,
				&cfg->options->setflags1,
				DIALUP_BIT));
}


isc_result_t
dns_c_ctx_setquerysourceaddr(dns_c_ctx_t *cfg, isc_sockaddr_t addr)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	existed = DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(QUERY_SOURCE_ADDR_BIT, &cfg->options->setflags1);
	
	cfg->options->query_source_addr = addr;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setquerysourceport(dns_c_ctx_t *cfg, in_port_t port)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	existed = DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(QUERY_SOURCE_PORT_BIT, &cfg->options->setflags1);
	
	cfg->options->query_source_port = port;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_settransferformat(dns_c_ctx_t *cfg,
			    dns_transfer_format_t newval)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	existed = DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(OPTIONS_TRANSFER_FORMAT_BIT, &cfg->options->setflags1);
	
	cfg->options->transfer_format = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setchecknames(dns_c_ctx_t *cfg,
			dns_c_trans_t transtype,
			dns_severity_t sever)
{
	isc_boolean_t existed = ISC_FALSE;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
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
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
		return (ISC_R_FAILURE);
	}
	
	cfg->options->check_names[transtype] = sever;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setqueryacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
		      dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->queryacl,
				  iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_settransferacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
			 dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->transferacl,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_setrecursionacl(dns_c_ctx_t *cfg, isc_boolean_t copy,
			  dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->recursionacl,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_setblackhole(dns_c_ctx_t *cfg, isc_boolean_t copy,
		       dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->blackhole,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_settopology(dns_c_ctx_t *cfg, isc_boolean_t copy,
		      dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->topology,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_setsortlist(dns_c_ctx_t *cfg, isc_boolean_t copy,
		      dns_c_ipmatchlist_t *iml)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_ipmatchlist(cfg->options, &cfg->options->sortlist,
			     iml, copy);

	return (res);
}


isc_result_t
dns_c_ctx_setforward(dns_c_ctx_t *cfg, dns_c_forw_t forw)
{
	isc_boolean_t existed;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	existed = DNS_C_CHECKBIT(FORWARD_BIT, &cfg->options->setflags1);
	DNS_C_SETBIT(FORWARD_BIT, &cfg->options->setflags1);
	
	cfg->options->forward = forw;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_setforwarders(dns_c_ctx_t *cfg, isc_boolean_t copy,
			dns_c_iplist_t *ipl)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	res = cfg_set_iplist(cfg->options, &cfg->options->forwarders,
			     ipl, copy);

	return (res);
}


isc_result_t
dns_c_ctx_setrrsetorderlist(dns_c_ctx_t *cfg, isc_boolean_t copy,
			    dns_c_rrsolist_t *olist)
{
	isc_boolean_t existed;
	dns_c_options_t *opts;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	opts = cfg->options;

	existed = (opts->ordering == NULL ? ISC_FALSE : ISC_TRUE);
	
	if (copy) {
		if (opts->ordering == NULL) {
			res = dns_c_rrsolist_new(opts->mem,
						 &opts->ordering);
			if (res != ISC_R_SUCCESS) {
				return (res);
			}
		} else {
			dns_c_rrsolist_clear(opts->ordering);
		}
		
		res = dns_c_rrsolist_append(opts->ordering, olist);
	} else {
		if (opts->ordering != NULL) {
			dns_c_rrsolist_delete(&opts->ordering);
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
dns_c_ctx_addlisten_on(dns_c_ctx_t *cfg,int port, dns_c_ipmatchlist_t *ml,
		       isc_boolean_t copy)
{
	dns_c_lstnon_t *lo;
	isc_result_t res;
	dns_c_options_t *opts;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(port >= 0 && port <= 65535);

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	opts = cfg->options;

	if (opts->listens == NULL) {
		res = dns_c_lstnlist_new(cfg->mem, &opts->listens);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}

#if 0	
	lo = ISC_LIST_HEAD(opts->listens->elements);
	while (lo != NULL) {
		/* XXX we should probably check that a listen on statement
		 * hasn't been done for the same post, ipmatch list
		 * combination
		 */
		if (lo->port == port) { /* XXX incomplete */
			return (ISC_R_FAILURE);
		}
		lo = ISC_LIST_NEXT(lo, next);
	}
#endif	

	res = dns_c_lstnon_new(cfg->mem, &lo);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	lo->port = port;
	res = dns_c_lstnon_setiml(lo, ml, copy);

	ISC_LIST_APPEND(opts->listens->elements, lo, next);

	return (res);
}


isc_result_t
dns_c_ctx_settrustedkeys(dns_c_ctx_t *cfg, dns_c_tkeylist_t *list,
			 isc_boolean_t copy)
{
	isc_boolean_t existed;
	dns_c_tkeylist_t *newl;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	existed = (cfg->trusted_keys == NULL ? ISC_FALSE : ISC_TRUE);

	if (cfg->trusted_keys != NULL) {
		res = dns_c_tkeylist_delete(&cfg->trusted_keys);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	if (copy) {
		res = dns_c_tkeylist_copy(cfg->mem, &newl, list);
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
dns_c_ctx_getdirectory(dns_c_ctx_t *cfg, char **retval)
{

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->directory;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getversion(dns_c_ctx_t *cfg, char **retval)
{

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->version;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getdumpfilename(dns_c_ctx_t *cfg, char **retval)
{

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->dump_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getpidfilename(dns_c_ctx_t *cfg, char **retval)
{

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->pid_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getstatsfilename(dns_c_ctx_t *cfg, char **retval)
{

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->stats_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getmemstatsfilename(dns_c_ctx_t *cfg, char **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->memstats_filename;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_getnamedxfer(dns_c_ctx_t *cfg, char **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->named_xfer;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_gettkeydomain(dns_c_ctx_t *cfg, char **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	*retval = cfg->options->tkeydomain;

	return (*retval == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_gettkeydhkey(dns_c_ctx_t *cfg,
		       char **charpval, isc_int32_t *intval)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(charpval != NULL);
	REQUIRE(intval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	if (cfg->options->tkeydhkeycp == NULL) {
		res = ISC_R_NOTFOUND;
	} else {
		*charpval = cfg->options->tkeydhkeycp;
		*intval = cfg->options->tkeydhkeyi;
		res = ISC_R_SUCCESS;
	}

	return (res);
}


isc_result_t
dns_c_ctx_getmaxncachettl(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->max_ncache_ttl,
			       retval,
			       &cfg->options->setflags1,
			       MAX_NCACHE_TTL_BIT));
}


isc_result_t
dns_c_ctx_gettransfersin(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_in,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_IN_BIT));
}


isc_result_t
dns_c_ctx_gettransfersperns(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
		
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_per_ns,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_PER_NS_BIT));
}


isc_result_t
dns_c_ctx_gettransfersout(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}

	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->transfers_out,
			      retval,
			      &cfg->options->setflags1,
			      TRANSFERS_OUT_BIT));
}


isc_result_t
dns_c_ctx_getmaxlogsizeixfr(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_log_size_ixfr,
			      retval,
			      &cfg->options->setflags1,
			      MAX_LOG_SIZE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_getcleaninterval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	return (cfg_get_int32(cfg->options, 
			      &cfg->options->clean_interval,
			      retval,
			      &cfg->options->setflags1,
			      CLEAN_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_getinterfaceinterval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->interface_interval,
			      retval,
			      &cfg->options->setflags1,
			      INTERFACE_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_getstatsinterval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->stats_interval,
			      retval,
			      &cfg->options->setflags1,
			      STATS_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_getheartbeatinterval(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->heartbeat_interval,
			      retval,
			      &cfg->options->setflags1,
			      HEARTBEAT_INTERVAL_BIT));
}


isc_result_t
dns_c_ctx_getmaxtransfertimein(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_transfer_time_in,
			      retval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_IN_BIT));
}


isc_result_t
dns_c_ctx_getmaxtransfertimeout(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_transfer_time_out,
			      retval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_TIME_OUT_BIT));
}


isc_result_t
dns_c_ctx_getmaxtransferidlein(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_transfer_idle_in,
			      retval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_IDLE_IN_BIT));
}


isc_result_t
dns_c_ctx_getmaxtransferidleout(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->max_transfer_idle_out,
			      retval,
			      &cfg->options->setflags1,
			      MAX_TRANSFER_IDLE_OUT_BIT));
}


isc_result_t
dns_c_ctx_gettcpclients(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->tcp_clients,
			      retval,
			      &cfg->options->setflags1,
			      TCP_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_getrecursiveclients(dns_c_ctx_t *cfg, isc_int32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_int32(cfg->options, 
			      &cfg->options->recursive_clients,
			      retval,
			      &cfg->options->setflags1,
			      RECURSIVE_CLIENTS_BIT));
}


isc_result_t
dns_c_ctx_getdatasize(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->data_size,
			       retval,
			       &cfg->options->setflags1,
			       DATA_SIZE_BIT));
}


isc_result_t
dns_c_ctx_getstacksize(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->stack_size,
			       retval,
			       &cfg->options->setflags1,
			       STACK_SIZE_BIT));
}


isc_result_t
dns_c_ctx_getcoresize(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->core_size,
			       retval,
			       &cfg->options->setflags1,
			       CORE_SIZE_BIT));
}


isc_result_t
dns_c_ctx_getfiles(dns_c_ctx_t *cfg, isc_uint32_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_uint32(cfg->options, 
			       &cfg->options->files,
			       retval,
			       &cfg->options->setflags1,
			       FILES_BIT));
}


isc_result_t
dns_c_ctx_getexpertmode(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
			       &cfg->options->expert_mode,
			       retval,
			       &cfg->options->setflags1,
			       EXPERT_MODE_BIT));
}


isc_result_t
dns_c_ctx_getfakeiquery(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->fake_iquery,
				retval,
				&cfg->options->setflags1,
				FAKE_IQUERY_BIT));
}


isc_result_t
dns_c_ctx_getrecursion(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->recursion,
				retval,
				&cfg->options->setflags1,
				RECURSION_BIT));
}


isc_result_t
dns_c_ctx_getfetchglue(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->fetch_glue,
				retval,
				&cfg->options->setflags1,
				FETCH_GLUE_BIT));
}


isc_result_t
dns_c_ctx_getnotify(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->notify,
				retval,
				&cfg->options->setflags1,
				NOTIFY_BIT));
}


isc_result_t
dns_c_ctx_gethoststatistics(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->host_statistics,
				retval,
				&cfg->options->setflags1,
				HOST_STATISTICS_BIT));
}


isc_result_t
dns_c_ctx_getdealloconexit(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->dealloc_on_exit,
				retval,
				&cfg->options->setflags1,
				DEALLOC_ON_EXIT_BIT));
}


isc_result_t
dns_c_ctx_getuseixfr(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->use_ixfr,
				retval,
				&cfg->options->setflags1,
				USE_IXFR_BIT));
}


isc_result_t
dns_c_ctx_getmaintainixfrbase(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->maintain_ixfr_base,
				retval,
				&cfg->options->setflags1,
				MAINTAIN_IXFR_BASE_BIT));
}


isc_result_t
dns_c_ctx_gethasoldclients(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->has_old_clients,
				retval,
				&cfg->options->setflags1,
				HAS_OLD_CLIENTS_BIT));
}



isc_result_t
dns_c_ctx_getauthnxdomain(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->auth_nx_domain,
				retval,
				&cfg->options->setflags1,
				AUTH_NX_DOMAIN_BIT));
}


isc_result_t
dns_c_ctx_getmultiplecnames(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->multiple_cnames,
				retval,
				&cfg->options->setflags1,
				MULTIPLE_CNAMES_BIT));
}


isc_result_t
dns_c_ctx_getuseidpool(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->use_id_pool,
				retval,
				&cfg->options->setflags1,
				USE_ID_POOL_BIT));
}


isc_result_t
dns_c_ctx_getrfc2308type1(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->rfc2308_type1,
				retval,
				&cfg->options->setflags1,
				RFC2308_TYPE1_BIT));
}


isc_result_t
dns_c_ctx_getdialup(dns_c_ctx_t *cfg, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	
	return (cfg_get_boolean(cfg->options, 
				&cfg->options->dialup,
				retval,
				&cfg->options->setflags1,
				DIALUP_BIT));
}


isc_result_t
dns_c_ctx_getquerysourceaddr(dns_c_ctx_t *cfg, isc_sockaddr_t *addr)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

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
dns_c_ctx_getquerysourceport(dns_c_ctx_t *cfg, in_port_t *port)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

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
dns_c_ctx_gettransferformat(dns_c_ctx_t *cfg,
			    dns_transfer_format_t *retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	

	if (DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT,
			   &cfg->options->setflags1)) {
		*retval = cfg->options->transfer_format;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_ctx_getchecknames(dns_c_ctx_t *cfg,
			dns_c_trans_t transtype,
			dns_severity_t *sever)
{
	isc_boolean_t isset = ISC_FALSE;
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

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
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "bad transport value: %d", transtype);
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
dns_c_ctx_getqueryacl(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options, cfg->options->queryacl,
				    list));
}


isc_result_t
dns_c_ctx_gettransferacl(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options,
				    cfg->options->transferacl, list));
}


isc_result_t
dns_c_ctx_getrecursionacl(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options, cfg->options->recursionacl,
				    list));
}


isc_result_t
dns_c_ctx_getblackhole(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options,
				    cfg->options->blackhole, list));
}


isc_result_t
dns_c_ctx_gettopology(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options,
				    cfg->options->topology, list));
}


isc_result_t
dns_c_ctx_getsortlist(dns_c_ctx_t *cfg, dns_c_ipmatchlist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_ipmatchlist(cfg->options,
				    cfg->options->sortlist, list));
}


isc_result_t
dns_c_ctx_getlistenlist(dns_c_ctx_t *cfg, dns_c_lstnlist_t **ll)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

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
dns_c_ctx_getforward(dns_c_ctx_t *cfg, dns_c_forw_t *forw)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

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
dns_c_ctx_getforwarders(dns_c_ctx_t *cfg, dns_c_iplist_t **list)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(list != NULL);

	return (cfg_get_iplist(cfg->options,
			       cfg->options->forwarders, list));
}


isc_result_t
dns_c_ctx_getrrsetorderlist(dns_c_ctx_t *cfg, dns_c_rrsolist_t **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->options == NULL || cfg->options->ordering == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*retval = cfg->options->ordering;
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_ctx_gettrustedkeys(dns_c_ctx_t *cfg, dns_c_tkeylist_t **retval)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(retval != NULL);

	if (cfg->trusted_keys == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*retval = cfg->trusted_keys;
		return (ISC_R_SUCCESS);
	}
}



isc_result_t
dns_c_ctx_optionsnew(isc_mem_t *mem, dns_c_options_t **options)
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
	opts->tkeydomain = NULL;
	opts->also_notify = NULL;
	opts->tkeydhkeycp = NULL;
	opts->tkeydhkeyi = 0;

	opts->mem = mem;
	opts->magic = DNS_C_OPTION_MAGIC;
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
	opts->expert_mode = ISC_FALSE;
	opts->auth_nx_domain = ISC_FALSE;
	opts->multiple_cnames = ISC_FALSE;
	opts->use_id_pool = ISC_FALSE;
	opts->rfc2308_type1 = ISC_FALSE;
	opts->dialup = ISC_FALSE;

	opts->tcp_clients = 0;
	opts->recursive_clients = 0;

	opts->max_transfer_time_in = 0;
	opts->max_transfer_time_out = 0;
	opts->max_transfer_idle_in = 0;
	opts->max_transfer_idle_out = 0;

	opts->data_size = 0;
	opts->stack_size = 0;
	opts->core_size = 0;
	opts->files = 0;
	
	opts->transfer_format = dns_one_answer;
	
	for (i = 0 ; i < DNS_C_TRANSCOUNT ; i++) {
		opts->check_names[i] = dns_severity_fail;
	}

	opts->queryacl = NULL;
	opts->transferacl = NULL;
	opts->recursionacl = NULL;
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
dns_c_ctx_optionsdelete(dns_c_options_t **opts)
{
	dns_c_options_t *options;
	isc_result_t r, result;
	
	REQUIRE(opts != NULL);

	options = *opts;
	if (options == NULL) {
		return (ISC_R_SUCCESS);
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(options));

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

	if (options->also_notify != NULL) {
		dns_c_iplist_detach(&options->also_notify);
	}

	if (options->tkeydomain != NULL) {
		isc_mem_free(options->mem, options->tkeydomain);
	}
	
	if (options->tkeydhkeycp != NULL) {
		isc_mem_free(options->mem, options->tkeydhkeycp);
	}

	result = ISC_R_SUCCESS;
	
	if (options->queryacl != NULL) {
		r = dns_c_ipmatchlist_detach(&options->queryacl);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->transferacl != NULL) {
		r = dns_c_ipmatchlist_detach(&options->transferacl);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->recursionacl != NULL) {
		r = dns_c_ipmatchlist_detach(&options->recursionacl);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->blackhole != NULL) {
		r = dns_c_ipmatchlist_detach(&options->blackhole);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->topology != NULL) {
		r = dns_c_ipmatchlist_detach(&options->topology);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->sortlist != NULL) {
		r = dns_c_ipmatchlist_detach(&options->sortlist);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->listens != NULL) {
		r = dns_c_lstnlist_delete(&options->listens);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->ordering != NULL) {
		r = dns_c_rrsolist_delete(&options->ordering);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	if (options->forwarders != NULL) {
		r = dns_c_iplist_detach(&options->forwarders);
		if (r != ISC_R_SUCCESS)
			result = r;
	}
	
	*opts = NULL;
	options->magic = 0;
	
	isc_mem_put(options->mem, options, sizeof *options);
	
	return (result);
}


void
dns_c_ctx_optionsprint(FILE *fp, int indent, dns_c_options_t *options)
{
	dns_severity_t nameseverity;
	
	REQUIRE(fp != NULL);

	if (options == NULL) {
		return;
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(options));

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
			dns_c_printinunits(fp, options->field); \
		}						\
		fprintf(fp, ";\n");				\
	}

#define PRINT_CHAR_P(field, name)					\
	if (options->field != NULL) {					\
		dns_c_printtabs(fp, indent + 1);			\
		fprintf(fp, "%s \"%s\";\n", name, options->field);	\
	}
	


	dns_c_printtabs(fp, indent);
	fprintf (fp, "options {\n");

	PRINT_CHAR_P(version, "version");
	PRINT_CHAR_P(directory, "directory");
	PRINT_CHAR_P(dump_filename, "dump-file");
	PRINT_CHAR_P(pid_filename, "pid-file");
	PRINT_CHAR_P(stats_filename, "statistics-file");
	PRINT_CHAR_P(memstats_filename, "memstatistics-file");
	PRINT_CHAR_P(named_xfer, "named-xfer");
	PRINT_CHAR_P(tkeydomain, "tkey-domain");

	if (options->tkeydhkeycp != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "tkey-dhkey \"%s\" %d ;\n",
			options->tkeydhkeycp, options->tkeydhkeyi);
	}
	
	PRINT_INTEGER(transfers_in, TRANSFERS_IN_BIT,
		      "transfers-in", setflags1);
	PRINT_INTEGER(transfers_per_ns, TRANSFERS_PER_NS_BIT,
		      "transfers-per-ns", setflags1);
	PRINT_INTEGER(transfers_out, TRANSFERS_OUT_BIT,
		      "transfers-out", setflags1);
	PRINT_INTEGER(max_log_size_ixfr, MAX_LOG_SIZE_IXFR_BIT,
		      "max-ixfr-log-size", setflags1);
	PRINT_INTEGER(tcp_clients, TCP_CLIENTS_BIT,
		      "tcp-clients", setflags1);
	PRINT_INTEGER(recursive_clients, RECURSIVE_CLIENTS_BIT,
		      "recursive-clients", setflags1);
	
	
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
	PRINT_AS_MINUTES(max_transfer_time_out, MAX_TRANSFER_TIME_OUT_BIT,
			 "max-transfer-time-out", setflags1);
	PRINT_AS_MINUTES(max_transfer_idle_in, MAX_TRANSFER_IDLE_IN_BIT,
			 "max-transfer-idle-in", setflags1);
	PRINT_AS_MINUTES(max_transfer_idle_out, MAX_TRANSFER_IDLE_OUT_BIT,
			 "max-transfer-idle-out", setflags1);

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
	PRINT_AS_BOOLEAN(rfc2308_type1, RFC2308_TYPE1_BIT,
			 "rfc2308-type1", setflags1);
	PRINT_AS_BOOLEAN(dialup, DIALUP_BIT,
			 "dialup", setflags1);

#undef PRINT_INTEGER
#undef PRINT_AS_MINUTES
#undef PRINT_AS_BOOLEAN
#undef PRINT_AS_SIZE_CLAUSE
#undef PRINT_CHAR_P


	if (DNS_C_CHECKBIT(OPTIONS_TRANSFER_FORMAT_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(options->transfer_format,
						 ISC_TRUE));
	}
	
	
	if (DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT, &options->setflags1) ||
	    DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "query-source ");

		if (DNS_C_CHECKBIT(QUERY_SOURCE_ADDR_BIT,
				   &options->setflags1)) {
			fprintf(fp, "address ");
			dns_c_print_ipaddr(fp, &options->query_source_addr);
		}

		if (DNS_C_CHECKBIT(QUERY_SOURCE_PORT_BIT,
				   &options->setflags1)) {
			if (options->query_source_port == 0) {
				fprintf(fp, " port *");
			} else {
				fprintf(fp, " port %d",
					options->query_source_port);
			}
		}
		fprintf(fp, " ;\n");
	}


	if (DNS_C_CHECKBIT(CHECKNAME_PRIM_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_primary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_primary,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_SEC_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_secondary];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_secondary,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}
		
	if (DNS_C_CHECKBIT(CHECKNAME_RESP_BIT, &options->setflags1)) {
		nameseverity = options->check_names[dns_trans_response];
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "check-names %s %s;\n",
			dns_c_transport2string(dns_trans_response,
					       ISC_TRUE),
			dns_c_nameseverity2string(nameseverity,
						  ISC_TRUE));
	}

	fprintf(fp, "\n");
	
	if (options->queryacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-query ");
		dns_c_ipmatchlist_print(fp, 2, options->queryacl);
		fprintf(fp, ";\n");
	}

	if (options->transferacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatchlist_print(fp, 2, options->transferacl);
		fprintf(fp, ";\n");
	}

	if (options->recursionacl != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "allow-recursion ");
		dns_c_ipmatchlist_print(fp, 2, options->recursionacl);
		fprintf(fp, ";\n");
	}

	if (options->blackhole != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "blackhole ");
		dns_c_ipmatchlist_print(fp, 2, options->blackhole);
		fprintf(fp, ";\n");
	}

	if (options->topology != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "topology ");
		dns_c_ipmatchlist_print(fp, 2, options->topology);
		fprintf(fp, ";\n");
	}

	if (options->sortlist != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "sortlist ");
		dns_c_ipmatchlist_print(fp, 2, options->sortlist);
		fprintf(fp, ";\n");
	}

	if (options->listens != NULL) {
		dns_c_lstnlist_print(fp, indent + 1,
				     options->listens);
	}
	
	dns_c_ctx_forwarderprint(fp, indent + 1, options);

	if (options->ordering != NULL) {
		dns_c_rrsolist_print(fp, indent + 1, options->ordering);
	}

	if (options->also_notify != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "also-notify ") ;
		dns_c_iplist_print(fp, indent + 2, options->also_notify);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(TRANSFER_SOURCE_BIT, &options->setflags1)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-source ");
		dns_c_print_ipaddr(fp, &options->transfer_source);
		fprintf(fp, ";\n");
	}
	

	dns_c_printtabs(fp, indent);
	fprintf(fp,"};\n");
}


isc_boolean_t
dns_c_ctx_keydefinedp(dns_c_ctx_t *ctx, const char *keyname)
{
	dns_c_kdef_t *keyid;
	isc_result_t res;
	isc_boolean_t rval = ISC_FALSE;

	REQUIRE(DNS_C_CONFCTX_VALID(ctx));
	REQUIRE(keyname != NULL);
	REQUIRE(strlen(keyname) > 0);
	
	if (ctx->keydefs != NULL) {
		res = dns_c_kdeflist_find(ctx->keydefs, keyname, &keyid);
		if (res == ISC_R_SUCCESS) {
			rval = ISC_TRUE;
		}
	}

	return rval;
}


isc_result_t
dns_c_ctx_setalsonotify(dns_c_ctx_t *cfg,
			dns_c_iplist_t *iml,
			isc_boolean_t copy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	REQUIRE(iml != NULL);

	res = cfg_set_iplist(cfg->options, &cfg->options->also_notify,
			     iml, copy);

	return (res);
}
	

isc_result_t
dns_c_ctx_getalsonotify(dns_c_ctx_t *cfg, dns_c_iplist_t **ret)
{
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(ret != NULL);

	return (cfg_get_iplist(cfg->options, cfg->options->also_notify, ret));
}


isc_result_t
dns_c_ctx_settransfersource(dns_c_ctx_t *cfg, isc_sockaddr_t newval)
{
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	res = make_options(cfg);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	existed = DNS_C_CHECKBIT(TRANSFER_SOURCE_BIT,
				 &cfg->options->setflags1);
	DNS_C_SETBIT(TRANSFER_SOURCE_BIT, &cfg->options->setflags1);
	
	cfg->options->transfer_source = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctx_gettransfersource(dns_c_ctx_t *cfg, isc_sockaddr_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		return (ISC_R_NOTFOUND);
	}
	
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(TRANSFER_SOURCE_BIT, &cfg->options->setflags1)) {
		*retval = cfg->options->transfer_source;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}
	



/***************************************************************************/


static isc_result_t
cfg_set_string(dns_c_options_t *options, char **field, const char *newval)
{
	char *p;
	isc_boolean_t existed = ISC_FALSE;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
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


static isc_result_t
cfg_set_iplist(dns_c_options_t *options,
	       dns_c_iplist_t **fieldaddr,
	       dns_c_iplist_t *newval,
	       isc_boolean_t copy)
{
	isc_result_t res;
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(fieldaddr != NULL);

	if (*fieldaddr != NULL) {
		existed = ISC_TRUE;
	}
	
	if (newval == NULL) {
		res = dns_c_iplist_new(options->mem,
				       newval->size,
				       fieldaddr);
	} else if (copy) {
		if (*fieldaddr != NULL) {
			dns_c_iplist_detach(fieldaddr);
		}
		
		res = dns_c_iplist_copy(options->mem, fieldaddr,
					newval);
	} else {
		if (*fieldaddr != NULL) {
			res = dns_c_iplist_detach(fieldaddr);
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
cfg_set_ipmatchlist(dns_c_options_t *options,
		    dns_c_ipmatchlist_t **fieldaddr,
		    dns_c_ipmatchlist_t *newval,
		    isc_boolean_t copy)
{
        isc_result_t res;
        isc_boolean_t existed = ISC_FALSE;
        
        REQUIRE(DNS_C_CONFOPT_VALID(options));
        REQUIRE(fieldaddr != NULL);

        if (*fieldaddr != NULL) {
                existed = ISC_TRUE;
        }
        
        if (newval == NULL) {
                res = dns_c_ipmatchlist_new(options->mem, fieldaddr);
        } else if (copy) {
                if (*fieldaddr != NULL) {
                        res = dns_c_ipmatchlist_empty(*fieldaddr);
                        if (res == ISC_R_SUCCESS && newval != NULL) {
                                res = dns_c_ipmatchlist_append(*fieldaddr,
                                                               newval,
                                                               ISC_FALSE);
                        }
                } else {
                        res = dns_c_ipmatchlist_copy(options->mem,
                                                     fieldaddr, newval);
                }
        } else {
                if (*fieldaddr != NULL) {
                        res = dns_c_ipmatchlist_detach(fieldaddr);
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
		dns_c_setbits_t *setfield,
		isc_uint32_t bitnumber)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
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
	      dns_c_setbits_t *setfield,
	      isc_uint32_t bitnumber)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
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
	       dns_c_setbits_t *setfield,
	       isc_uint32_t bitnumber)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(setfield != NULL);
	REQUIRE(fieldaddr != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

	*fieldaddr = newval;

	existed = DNS_C_CHECKBIT(bitnumber, setfield);
	DNS_C_SETBIT(bitnumber, setfield);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


static isc_result_t
cfg_get_ipmatchlist(dns_c_options_t *options,
		    dns_c_ipmatchlist_t *field,
		    dns_c_ipmatchlist_t **resval)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(resval != NULL);

	if (field != NULL && !ISC_LIST_EMPTY(field->elements)) {
		dns_c_ipmatchlist_attach(field, resval);
		res = ISC_R_SUCCESS;
	} else {
		*resval = NULL;
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


static isc_result_t
cfg_get_iplist(dns_c_options_t *options,
	       dns_c_iplist_t *field,
	       dns_c_iplist_t **resval)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(resval != NULL);

	if (field != NULL && field->nextidx != 0) {
		dns_c_iplist_attach(field, resval);
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
		dns_c_setbits_t *setfield,
		isc_uint32_t bitnumber)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(result != NULL);
	REQUIRE(field != NULL);
	REQUIRE(setfield != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

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
	      dns_c_setbits_t *setfield,
	      isc_uint32_t bitnumber)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(result != NULL);
	REQUIRE(field != NULL);
	REQUIRE(setfield != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

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
	       dns_c_setbits_t *setfield,
	       isc_uint32_t bitnumber)
{
	isc_result_t res;

	REQUIRE(DNS_C_CONFOPT_VALID(options));
	REQUIRE(result != NULL);
	REQUIRE(field != NULL);
	REQUIRE(setfield != NULL);
	REQUIRE(bitnumber < DNS_C_SETBITS_SIZE);

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
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchlist_t *iml;
	isc_sockaddr_t addr;
	dns_c_acl_t *acl;
	isc_result_t r;
	static struct in_addr zeroaddr;

	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	isc_sockaddr_fromin(&addr, &zeroaddr, 0);

	r = dns_c_acltable_new(cfg->mem, &cfg->acls);
	if (r != ISC_R_SUCCESS) return (r);


	/*
	 * The ANY acl.
	 */
	r = dns_c_acl_new(cfg->acls, "any", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchpattern_new(cfg->mem, &ime, addr, 0);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchlist_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_setipml(acl, iml, ISC_FALSE);
	iml = NULL;
	

	/*
	 * The NONE acl
	 */

	r = dns_c_acl_new(cfg->acls, "none", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchpattern_new(cfg->mem, &ime, addr, 0);
	if (r != ISC_R_SUCCESS) return (r);

	dns_c_ipmatch_negate(ime);

	r = dns_c_ipmatchlist_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);
	
	dns_c_acl_setipml(acl, iml, ISC_FALSE);
	iml = NULL;
	

	/*
	 * The LOCALHOST acl
	 */
	r = dns_c_acl_new(cfg->acls, "localhost", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchlocalhost_new(cfg->mem, &ime);
	if (r != ISC_R_SUCCESS) return (r);

	r = dns_c_ipmatchlist_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_setipml(acl, iml, ISC_FALSE);
	iml = NULL;
	
	
	/*
	 * The LOCALNETS acl
	 */
	r = dns_c_acl_new(cfg->acls, "localnets", ISC_TRUE, &acl);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchlocalnets_new(cfg->mem, &ime);
	if (r != ISC_R_SUCCESS) return (r);
	
	r = dns_c_ipmatchlist_new(cfg->mem, &iml);
	if (r != ISC_R_SUCCESS) return (r);
	
	ISC_LIST_APPEND(iml->elements, ime, next);

	dns_c_acl_setipml(acl, iml, ISC_FALSE);
	iml = NULL;
	
	return (ISC_R_SUCCESS);
}



static isc_result_t
logging_init (dns_c_ctx_t *cfg)
{
	isc_result_t res;
	dns_c_logcat_t *cat;
	dns_c_logchan_t *chan;
	
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));
	REQUIRE(cfg->logging == NULL);

	res = dns_c_logginglist_new(cfg->mem, &cfg->logging);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	/* default_syslog channel */
	chan = NULL;
	res = dns_c_ctx_addsyslogchannel(cfg, DNS_C_DEFAULT_SYSLOG,
					 &chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_setpredef(chan, ISC_TRUE);
	dns_c_logchan_setfacility(chan, LOG_DAEMON);
	dns_c_logchan_setseverity(chan, dns_c_log_info);

	
	/* default_debug channel */
	chan = NULL;
	res = dns_c_ctx_addfile_channel(cfg, DNS_C_DEFAULT_DEBUG, &chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_setpredef(chan, ISC_TRUE);
	dns_c_logchan_setpath(chan, DNS_C_DEFAULT_DEBUG_PATH);
	dns_c_logchan_setseverity(chan, dns_c_log_dynamic);


	/* null channel */
	chan = NULL;
	res = dns_c_ctx_addnullchannel(cfg, DNS_C_NULL, &chan);
	dns_c_logchan_setpredef(chan, ISC_TRUE);


	/* default_stderr channel */
	chan = NULL;
	res = dns_c_ctx_addfile_channel(cfg, DNS_C_DEFAULT_STDERR,
					&chan);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logchan_setpredef(chan, ISC_TRUE);
	dns_c_logchan_setpath(chan, DNS_C_STDERR_PATH);
	dns_c_logchan_setseverity(chan, dns_c_log_info);


	/* default category */
	cat = NULL;
	res = dns_c_ctx_addcategory(cfg, dns_c_cat_default, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_setpredef(cat, ISC_TRUE);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_SYSLOG);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_DEBUG);
	

	/* panic category */
	cat = NULL;
	res = dns_c_ctx_addcategory(cfg, dns_c_cat_panic, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_setpredef(cat, ISC_TRUE);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_SYSLOG);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_DEBUG);

	
	/* eventlib category */
	cat = NULL;
	res = dns_c_ctx_addcategory(cfg, dns_c_cat_eventlib, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_setpredef(cat, ISC_TRUE);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_DEBUG);


	/* packet category */
	cat = NULL;
	res = dns_c_ctx_addcategory(cfg, dns_c_cat_packet, &cat);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	dns_c_logcat_setpredef(cat, ISC_TRUE);
	dns_c_logcat_addname(cat, DNS_C_DEFAULT_DEBUG);
	
	return (ISC_R_SUCCESS);
}



static isc_result_t
make_options(dns_c_ctx_t *cfg)
{
	isc_result_t res = ISC_R_SUCCESS;
	REQUIRE(DNS_C_CONFCTX_VALID(cfg));

	if (cfg->options == NULL) {
		res = dns_c_ctx_optionsnew(cfg->mem, &cfg->options);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	REQUIRE(DNS_C_CONFOPT_VALID(cfg->options));

	return (res);
}


