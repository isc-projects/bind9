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


#include <config.h>

#include <string.h>
#include <limits.h>

#include <isc/assertions.h>

#include "configctx.h"


/* these are the bit definitions for the flag set 1 */
#define NCACHE_TTL_BIT		(1 << 1)
#define TRANSFERS_IN_BIT 	(1 << 2)
#define TRANSFERS_PER_NS_BIT 	(1 << 3)
#define TRANSFERS_OUT_BIT 	(1 << 4)
#define MAX_LOG_BIT 		(1 << 5)
#define CLEAN_INT_BIT 		(1 << 6)
#define INTERFACE_INT_BIT 	(1 << 7)
#define STATS_INT_BIT 		(1 << 8)
#define HEARDBEAT_INT_BIT 	(1 << 9)
#define MAX_TRANS_TIME_BIT 	(1 << 10)
#define DATA_SIZE_BIT 		(1 << 11)
#define STACK_SIZE_BIT 		(1 << 12)
#define CORE_SIZE_BIT 		(1 << 13)
#define FILES_BIT 		(1 << 14)
#define QUERY_SOURCE_BIT 	(1 << 15)
#define QUERY_ACL_BIT 		(1 << 16)
#define TRANSFER_ACL_BIT 	(1 << 17)
#define BLOCKHOLE_ACL_BIT 	(1 << 18)
#define TOPOLOGY_BIT 		(1 << 19)
#define TRANSFER_FORMAT_BIT 	(1 << 20)
#define FAKE_IQUERY_BIT		(1 << 21)
#define RECURSION_BIT		(1 << 22)
#define FETCH_GLUE_BIT		(1 << 23)
#define NOTIFY_BIT		(1 << 24)
#define HOSTSTATS_BIT		(1 << 25)
#define DEALLOC_ON_EXIT_BIT	(1 << 26)
#define USE_IXFR_BIT		(1 << 27)
#define MAINTAIN_IXFR_BASE_BIT	(1 << 28)
#define HAS_OLD_CLIENTS_BIT	(1 << 29)
#define AUTH_NX_DOMAIN_BIT	(1 << 30)
#define MULTIPLE_CNAMES_BIT	(1 << 0)

/* these are the bit definitions for the flag set 2 */
#define CHECK_NAMES_BIT		(1 << 1)
#define USE_ID_POOL_BIT		(1 << 2)
#define DIALUP_BIT		(1 << 3)



#define CHECKBIT(bit,flags) (((flags) & (bit)) == (bit))
#define SETBIT(bit, flags) ((flags) |= (bit))
#define CLEARBIT(bit, flags) ((flags) &= ~(bit))

#define CHECKREGION(r) \
	INSIST(((r)->base == NULL && (r)->length == 0) || \
	       ((r)->base != NULL && (r)->length > 0))

#define FREE_TEXT_REGION(r,m) \
	do { CHECKREGION(r) ; \
	     if ((r)->base != NULL) { \
		isc_mem_put(m,(r)->base,(r)->length); \
	     	(r)->base = NULL; (r)->length = 0; \
	     } \
        } while(0)


/* I don't much like this, but there's a huge amount of code duplication
 * that these macros eliminate
 */

#define FUNC_SET_FIELD(field, bit, bitset, type)        \
isc_result_t						\
isc_cfg_set_ ## field (isc_cfgctx_t *ctx, type value)	\
{							\
	INSIST(ctx != NULL);				\
	INSIST(ctx->options != NULL);			\
							\
	ctx->options->field = value;			\
							\
	SETBIT(bit, ctx->options->bitset);		\
							\
	return (ISC_R_SUCCESS);				\
}

#define FUNC_GET_FIELD(field, bit, bitset, type)        \
isc_result_t						\
isc_cfg_get_ ## field (isc_cfgctx_t *ctx, type *result)	\
{							\
	INSIST(ctx != NULL);				\
	INSIST(ctx->options != NULL);			\
	INSIST(result != NULL);				\
							\
	if (CHECKBIT(bit,ctx->options->bitset)) {	\
		*result = ctx->options->field;		\
		return (ISC_R_SUCCESS);			\
	} else {					\
		return (ISC_R_NOTFOUND);		\
	}						\
}


#define FUNC_SET_TEXTFIELD(field)					\
isc_result_t								\
isc_cfg_set_ ## field(isc_cfgctx_t *ctx, const char *value)		\
{									\
	isc_result_t res;						\
									\
	INSIST(ctx != NULL);						\
									\
	res = set_text_region(ctx->mem, &ctx->options->field, value);	\
									\
	return (res);							\
}


#define FUNC_GET_TEXTFIELD(field)				\
isc_result_t							\
isc_cfg_get_ ## field(isc_cfgctx_t *ctx, const char **result)	\
{								\
	INSIST(ctx != NULL);					\
	INSIST(ctx->options != NULL);				\
	INSIST(result != NULL);					\
								\
	if (ctx->options->field.base != NULL) {			\
		*result = ctx->options->field.base;		\
		return (ISC_R_SUCCESS);				\
	} else {						\
		return (ISC_R_NOTFOUND);			\
	}							\
}





static void freeoptions(isc_cfgoptions_t *opts, isc_mem_t *mem);
static isc_result_t set_text_region(isc_mem_t *mem,
				    isc_textregion_t *region,
				    const char *value);
static void opt_print_textregion(FILE *fp, const char *name,
				 isc_textregion_t r);


/***
 *** PUBLIC
 ***/

isc_result_t
isc_cfg_newctx(isc_mem_t *mem, isc_cfgctx_t **ctx)
{
	isc_cfgctx_t *cfg = NULL;
	isc_cfgoptions_t *opts = NULL;
	isc_zonectx_t *zonectx = NULL;
	isc_result_t res;
	
	INSIST(mem != NULL);

	cfg = isc_mem_get(mem, sizeof *cfg);
	if (cfg == NULL) {
		return (ISC_R_NOMEMORY);
	}

	memset(cfg, 0x0, sizeof *cfg);

	cfg->mem = mem;
	
	opts = isc_mem_get(mem, sizeof *opts);
	if (opts == NULL) {
		isc_mem_put(mem, cfg, sizeof *cfg);
		return (ISC_R_NOMEMORY);
	}
	memset (opts, 0x0, sizeof *opts);
	cfg->options = opts;

	if ((res = isc_zone_newcontext(mem, &zonectx)) != ISC_R_SUCCESS) {
		isc_mem_put(mem, opts, sizeof *opts);
		isc_mem_put(mem, cfg, sizeof *cfg);

		return (res);
	}
	cfg->zonecontext = zonectx;
	
	*ctx = cfg ;

	return (ISC_R_SUCCESS);
}

	


isc_result_t
isc_cfg_freectx(isc_cfgctx_t **ctx)
{
	isc_cfgctx_t *c ;

	INSIST(ctx != NULL);

	c = *ctx;

	INSIST(c->mem != NULL);

	
	if (c->options != NULL) {
		freeoptions(c->options, c->mem);
	}

	isc_mem_put(c->mem, c, sizeof *c);
	*ctx = NULL;
	
	return (ISC_R_SUCCESS);
}



	
isc_result_t
isc_cfg_erase_options(isc_cfgctx_t *ctx)
{
	INSIST(ctx != NULL);
	INSIST(ctx->options != NULL);
	
	freeoptions(ctx->options, ctx->mem);
	ctx->options = isc_mem_get(ctx->mem, sizeof *ctx->options);
	if (ctx->options == NULL) {
		return (ISC_R_NOMEMORY);
	}
	memset (ctx->options, 0x0, sizeof *ctx->options);

	return (ISC_R_SUCCESS);
}


void
isc_cfg_dump_config(FILE *fp, isc_cfgctx_t *cfg)
{
	INSIST(cfg != NULL);
	INSIST(fp != NULL);

	isc_cfg_dump_options(fp, cfg->options);
	if (cfg->zonecontext != NULL) {
		isc_zonectx_dump(fp, cfg->zonecontext);
	}
}


static void
print_in_units(FILE *fp, unsigned long val)
{
	unsigned long one_gig = (1024 * 1024 * 1024);
	unsigned long one_meg = (1024 * 1024);
	unsigned long one_k = 1024;
	
	if ((val % one_gig) == 0)
		fprintf(fp, "%luG", val / one_gig);
	else if ((val % one_meg) == 0)
		fprintf(fp, "%luM", val / one_meg);
	else if ((val % one_k) == 0)
		fprintf(fp, "%luK", val / one_k);
	else if (val == ULONG_MAX)
		fprintf(fp, "unlimited");
	else
		fprintf(fp, "%lu", val);
}

void
isc_cfg_dump_options(FILE *fp, isc_cfgoptions_t *options)
{
	INSIST(options != NULL);
	INSIST(fp != NULL);

#define PRINT_AS_MINUTES(field, bit, name, bitfield)			\
	if (CHECKBIT(bit, options->bitfield)) {				\
		fprintf(fp, "\t%s %lu;\n",name,				\
			(unsigned long)options->field / 60);		\
	}

#define PRINT_AS_BOOLEAN(field, bit, name, bitfield)		\
	if (CHECKBIT(bit, options->bitfield)) {			\
		fprintf(fp, "\t%s %s;\n",name,			\
			(options->field ? "true" : "false"));	\
	}

#define PRINT_AS_SIZE_CLAUSE(field, bit, name, bitfield)	\
	if (CHECKBIT(bit,options->bitfield)) {			\
		fprintf(fp, "\t%s ",name);			\
		if (options->field == 0) {			\
			fprintf(fp, "default");			\
		} else {					\
			print_in_units(fp,options->data_size);	\
		}						\
		fprintf(fp, ";\n");				\
	}
	
	

	fprintf (fp, "options {\n");
	opt_print_textregion(fp, "version", options->version);
	opt_print_textregion(fp, "directory", options->directory);
	opt_print_textregion(fp, "named-xfer", options->named_xfer);
	opt_print_textregion(fp, "pid-file", options->pid_filename);
	opt_print_textregion(fp, "statistics-file", options->stats_filename);
	opt_print_textregion(fp, "memstatistics-file",
			     options->memstats_filename);
	opt_print_textregion(fp, "dump-file", options->dump_filename);

	PRINT_AS_BOOLEAN(fake_iquery, FAKE_IQUERY_BIT,
			 "fake-iquery", set_flags1);
	PRINT_AS_BOOLEAN(recursion, RECURSION_BIT,
			 "recursion", set_flags1);
	PRINT_AS_BOOLEAN(fetch_glue, FETCH_GLUE_BIT,
			 "fetch-glue", set_flags1);
	PRINT_AS_BOOLEAN(notify, NOTIFY_BIT,
			 "notify", set_flags1);
	PRINT_AS_BOOLEAN(hoststats, HOSTSTATS_BIT,
			 "hoststats", set_flags1);
	PRINT_AS_BOOLEAN(dealloc_on_exit, DEALLOC_ON_EXIT_BIT,
			 "deallocate-on-exit", set_flags1);
	PRINT_AS_BOOLEAN(use_ixfr, USE_IXFR_BIT,
			 "use_ixfr", set_flags1);
	PRINT_AS_BOOLEAN(maintain_ixfr_base, MAINTAIN_IXFR_BASE_BIT,
			 "maintain-ixfr-base", set_flags1);
	PRINT_AS_BOOLEAN(has_old_clients, HAS_OLD_CLIENTS_BIT,
			 "has-old-clients", set_flags1);
	PRINT_AS_BOOLEAN(auth_nx_domain, AUTH_NX_DOMAIN_BIT,
			 "auth-nxdomain", set_flags1);
	PRINT_AS_BOOLEAN(multiple_cnames, MULTIPLE_CNAMES_BIT,
			 "multiple-cnames", set_flags1);
	PRINT_AS_BOOLEAN(use_id_pool, USE_ID_POOL_BIT,
			 "use-id-pool", set_flags2);
	PRINT_AS_BOOLEAN(dialup, DIALUP_BIT,
			 "dialup", set_flags2);

	PRINT_AS_SIZE_CLAUSE(data_size, DATA_SIZE_BIT, "datasize",
			     set_flags1);	
	PRINT_AS_SIZE_CLAUSE(stack_size, STACK_SIZE_BIT, "stacksize",
			     set_flags1);	
	PRINT_AS_SIZE_CLAUSE(core_size, CORE_SIZE_BIT, "coresize",
			     set_flags1);	
	PRINT_AS_SIZE_CLAUSE(files, FILES_BIT, "files",
			     set_flags1);

	PRINT_AS_MINUTES(max_transfer_time_in, MAX_TRANS_TIME_BIT,
			 "max-transfer-time-in", set_flags1);
	PRINT_AS_MINUTES(clean_interval, CLEAN_INT_BIT,
			 "cleaning-interval", set_flags1);
	PRINT_AS_MINUTES(interface_interval, INTERFACE_INT_BIT,
			 "interface-interval", set_flags1);
	PRINT_AS_MINUTES(stats_interval, STATS_INT_BIT,
			 "statistics-interval", set_flags1);

	fprintf(fp,"};\n");
}



/****
 **** ACCESSORS/MODIFIERS
 ****/

/* This is seriously ugly, but we have nothing like C++ templates here.... */

FUNC_SET_TEXTFIELD(directory)
FUNC_GET_TEXTFIELD(directory)

FUNC_SET_TEXTFIELD(version)
FUNC_GET_TEXTFIELD(version)

FUNC_SET_TEXTFIELD(dump_filename)
FUNC_GET_TEXTFIELD(dump_filename)

FUNC_SET_TEXTFIELD(pid_filename)
FUNC_GET_TEXTFIELD(pid_filename)

FUNC_SET_TEXTFIELD(stats_filename)
FUNC_GET_TEXTFIELD(stats_filename)

FUNC_SET_TEXTFIELD(memstats_filename)
FUNC_GET_TEXTFIELD(memstats_filename)

FUNC_SET_TEXTFIELD(named_xfer)
FUNC_GET_TEXTFIELD(named_xfer)

FUNC_SET_FIELD(max_ncache_ttl, NCACHE_TTL_BIT, set_flags1, unsigned int)
FUNC_GET_FIELD(max_ncache_ttl, NCACHE_TTL_BIT, set_flags1, unsigned int)

FUNC_SET_FIELD(transfers_in, TRANSFERS_IN_BIT, set_flags1, int)
FUNC_GET_FIELD(transfers_in, TRANSFERS_IN_BIT, set_flags1, int)

FUNC_SET_FIELD(transfers_per_ns, TRANSFERS_PER_NS_BIT, set_flags1, int)
FUNC_GET_FIELD(transfers_per_ns, TRANSFERS_PER_NS_BIT, set_flags1, int)

FUNC_SET_FIELD(transfers_out, TRANSFERS_OUT_BIT, set_flags1, int)
FUNC_GET_FIELD(transfers_out, TRANSFERS_OUT_BIT, set_flags1, int)

FUNC_SET_FIELD(max_log_size_ixfr, MAX_LOG_BIT, set_flags1, int)
FUNC_GET_FIELD(max_log_size_ixfr, MAX_LOG_BIT, set_flags1, int)

FUNC_SET_FIELD(clean_interval, CLEAN_INT_BIT, set_flags1, int)
FUNC_GET_FIELD(clean_interval, CLEAN_INT_BIT, set_flags1, int)

FUNC_SET_FIELD(interface_interval, INTERFACE_INT_BIT, set_flags1, int)
FUNC_GET_FIELD(interface_interval, INTERFACE_INT_BIT, set_flags1, int)

FUNC_SET_FIELD(stats_interval, STATS_INT_BIT, set_flags1, int)
FUNC_GET_FIELD(stats_interval, STATS_INT_BIT, set_flags1, int)

FUNC_SET_FIELD(heartbeat_interval, HEARDBEAT_INT_BIT, set_flags1, int)
FUNC_GET_FIELD(heartbeat_interval, HEARDBEAT_INT_BIT, set_flags1, int)

FUNC_SET_FIELD(max_transfer_time_in,MAX_TRANS_TIME_BIT, set_flags1, long)
FUNC_GET_FIELD(max_transfer_time_in,MAX_TRANS_TIME_BIT, set_flags1, long)

FUNC_SET_FIELD(data_size, DATA_SIZE_BIT, set_flags1, unsigned long)
FUNC_GET_FIELD(data_size, DATA_SIZE_BIT, set_flags1, unsigned long)

FUNC_SET_FIELD(stack_size, STACK_SIZE_BIT, set_flags1, unsigned long)
FUNC_GET_FIELD(stack_size, STACK_SIZE_BIT, set_flags1, unsigned long)

FUNC_SET_FIELD(core_size, CORE_SIZE_BIT, set_flags1, unsigned long)
FUNC_GET_FIELD(core_size, CORE_SIZE_BIT, set_flags1, unsigned long)

FUNC_SET_FIELD(files, FILES_BIT, set_flags1, unsigned long)
FUNC_GET_FIELD(files, FILES_BIT, set_flags1, unsigned long)

FUNC_SET_FIELD(fake_iquery, FAKE_IQUERY_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(fake_iquery, FAKE_IQUERY_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(recursion, RECURSION_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(recursion, RECURSION_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(fetch_glue, FETCH_GLUE_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(fetch_glue, FETCH_GLUE_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(notify, NOTIFY_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(notify, NOTIFY_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(hoststats, HOSTSTATS_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(hoststats, HOSTSTATS_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(dealloc_on_exit, DEALLOC_ON_EXIT_BIT, set_flags1,
	       isc_boolean_t)
FUNC_GET_FIELD(dealloc_on_exit, DEALLOC_ON_EXIT_BIT, set_flags1,
	       isc_boolean_t)

FUNC_SET_FIELD(use_ixfr, USE_IXFR_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(use_ixfr, USE_IXFR_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(maintain_ixfr_base, MAINTAIN_IXFR_BASE_BIT, set_flags1,
	       isc_boolean_t)
FUNC_GET_FIELD(maintain_ixfr_base, MAINTAIN_IXFR_BASE_BIT, set_flags1,
	       isc_boolean_t)

FUNC_SET_FIELD(has_old_clients, HAS_OLD_CLIENTS_BIT, set_flags1,
	       isc_boolean_t)
FUNC_GET_FIELD(has_old_clients, HAS_OLD_CLIENTS_BIT, set_flags1,
	       isc_boolean_t)

FUNC_SET_FIELD(auth_nx_domain, AUTH_NX_DOMAIN_BIT, set_flags1, isc_boolean_t)
FUNC_GET_FIELD(auth_nx_domain, AUTH_NX_DOMAIN_BIT, set_flags1, isc_boolean_t)

FUNC_SET_FIELD(multiple_cnames, MULTIPLE_CNAMES_BIT, set_flags1,
	       isc_boolean_t)
FUNC_GET_FIELD(multiple_cnames, MULTIPLE_CNAMES_BIT, set_flags1,
	       isc_boolean_t)

FUNC_SET_FIELD(use_id_pool, USE_ID_POOL_BIT, set_flags2, isc_boolean_t)
FUNC_GET_FIELD(use_id_pool, USE_ID_POOL_BIT, set_flags2, isc_boolean_t)

FUNC_SET_FIELD(dialup, DIALUP_BIT, set_flags2, isc_boolean_t)
FUNC_GET_FIELD(dialup, DIALUP_BIT, set_flags2, isc_boolean_t)




/***
 *** PRIVATE
 ***/
  
static isc_result_t
set_text_region(isc_mem_t *mem, isc_textregion_t *region, const char *value)
{
	size_t len;

	INSIST(mem != NULL);
	INSIST(value != NULL);
	INSIST(region != NULL);

	len = strlen(value) + 1;
	
	INSIST(len > 1);
	CHECKREGION(region);

	if (region->base != NULL && region->length < len) {
		isc_mem_put(mem, region->base, region->length);
		region->base = NULL;
		region->length = 0;
	}

	if (region->base == NULL) {
		region->base = isc_mem_get(mem, len);
		if (region->base == NULL) {
			return (ISC_R_NOMEMORY);
		}
		region->length = len;
	}

	strcpy(region->base, value);

	return (ISC_R_SUCCESS);
}


	

static void
freeoptions(isc_cfgoptions_t *opts, isc_mem_t *mem)
{	
	INSIST(opts != NULL);

	FREE_TEXT_REGION(&opts->directory, mem);
	FREE_TEXT_REGION(&opts->version, mem);
	FREE_TEXT_REGION(&opts->dump_filename, mem);
	FREE_TEXT_REGION(&opts->pid_filename, mem);
	FREE_TEXT_REGION(&opts->stats_filename, mem);
	FREE_TEXT_REGION(&opts->memstats_filename, mem);
	FREE_TEXT_REGION(&opts->named_xfer, mem);

	isc_mem_put(mem, opts, sizeof *opts);
}

	
static void
opt_print_textregion(FILE *fp, const char *name, isc_textregion_t r)
{
	CHECKREGION(&r);
	
	if (r.length > 0) {
		fprintf(fp,"\t%s \"%s\";\n", name, r.base);
	}
}
