/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

%module DNSConf

%{

#include <stdio.h>
#include <isc/result.h>
#include <dns/confctx.h>
#include <dns/log.h>

#include "DNSConf-macros.h"

#define DEBUG_PRINT 1

#if DEBUG_PRINT
#define DBGPRINT xprintf
#else
#define DBGPRINT ((void) 0)
#endif

static struct {
	isc_mem_t *mem;
	isc_log_t *log;
	isc_logconfig_t *logcfg;
	int count;
} ctx ;

typedef struct DNSConf {
	dns_c_ctx_t *confctx;
} DNSConf;



int xprintf(const char *fmt, ...) {
	va_list ap ;

	va_start (ap, fmt) ;
	vfprintf (stderr, fmt, ap) ;
	va_end (ap) ;
}


int ctx_init(void) {
	int returnval = 0;

	DBGPRINT("Starting ctx_init()\n");

	if (ctx.mem != NULL) {
		returnval = 1;
		goto done;
	}

	isc_mem_create(&ctx.mem);

	isc_log_create(ctx.mem, &ctx.log, &ctx.logcfg);

	isc_log_setcontext(ctx.log);
	dns_log_init(ctx.log);
	dns_log_setcontext(ctx.log);

	if (isc_log_usechannel(ctx.logcfg, "default_stderr", NULL, NULL) !=
	    ISC_R_SUCCESS)
		goto done;

	dns_lctx = ctx.log;

	ctx.count = 0;

	returnval = 1;

done:
	DBGPRINT("Finished ctx_init()\n");

	return (returnval);
}

void *ctx_destroy(void) {
	DBGPRINT("starting ctx_destroy()\n");

	if (ctx.count == 0) {
		DBGPRINT("count == 0\n");
		return NULL;
	}

	if (--ctx.count > 0) {
		DBGPRINT("count > 0\n");
		return NULL;
	}

	DBGPRINT("destroying ctx\n");

	dns_lctx = NULL;
	isc_log_destroy(&ctx.log);
	isc_mem_destroy(&ctx.mem);

	DBGPRINT("finished ctx_destroy\n");
}


DNSConf *new_DNSConf() {
	DNSConf *ptr = malloc(sizeof (DNSConf));

	DBGPRINT("inside new_DNSConf\n");

	ptr->confctx = NULL;

	return ptr;
}

void clear_DNSConf(DNSConf *ctx) {
	if (ctx->confctx != NULL) {
		DBGPRINT("deleting config context\n");
		dns_c_ctx_delete(&ctx->confctx);
		ctx_destroy();
	}
}


void delete_DNSConf(DNSConf *ctx) {
	DBGPRINT("inside delete_DNSConf\n");

	clear_DNSConf(ctx);

	free(ctx);
}

int DNSConf_parse(DNSConf *conf, const char *filename) {

	DBGPRINT("inside parse\n");

	if (!ctx_init())
		return;

	clear_DNSConf(conf);

	if (dns_c_parse_namedconf(filename, ctx.mem, &conf->confctx, NULL)
	    == ISC_R_SUCCESS) {
		ctx.count++;

		DBGPRINT("count now: %d\n", ctx.count);

		return 1;
	} else {
		return 0;
	}
}

int DNSConf_initctx(DNSConf *cfg) {
	if (cfg == NULL)
		return 0;

	if (cfg->confctx != NULL)
		return 1;

	if (!ctx_init())
		return 0;

	if (dns_c_ctx_new(ctx.mem, &cfg->confctx) != ISC_R_SUCCESS)
		return 0;

	ctx.count++;

	DBGPRINT("count is now: %d\n", ctx.count);

	return 1;
}



void DNSConf_print(DNSConf *ptr, FILE *outfile) {

	DBGPRINT("inside print\n");

	if (ptr == NULL || ptr->confctx == NULL)
		return;

	dns_c_ctx_print(outfile, 0, ptr->confctx);
}


#if 0

void DNSConf_setdirectory(DNSConf *cfg, const char *directory) {

	DBGPRINT("inside DNSConf_setdirectory\n");

	if (!DNSConf_initctx(cfg))
		return;

	if (directory == NULL) {
		DBGPRINT("null pointer\n");
		dns_c_ctx_unsetdirectory(cfg->confctx);
	} else if (*directory == '\0') {
		DBGPRINT("empty string\n");
		dns_c_ctx_unsetdirectory(cfg->confctx);
	} else
		dns_c_ctx_setdirectory(cfg->confctx, directory);
}

char *DNSConf_getdirectory(DNSConf *cfg) {
	char *dir = NULL;
	isc_result_t tmpres;

	if (cfg == NULL || cfg->confctx == NULL)
		return NULL;

	tmpres = dns_c_ctx_getdirectory(cfg->confctx, &dir);
	if (tmpres == ISC_R_NOTFOUND)
		return NULL;

	return dir;
}

#else

STRING_FIELD_DEFS(directory)
STRING_FIELD_DEFS(version)
STRING_FIELD_DEFS(dumpfilename)
STRING_FIELD_DEFS(pidfilename)
STRING_FIELD_DEFS(statsfilename)
STRING_FIELD_DEFS(memstatsfilename)
STRING_FIELD_DEFS(namedxfer)



void DNSConf_settransfersin(DNSConf *cfg, unsigned int *transfersin) {

	DBGPRINT("inside DNSConf_settransfersin %p\n", transfersin);

	if (!DNSConf_initctx(cfg))
		return;

	if (transfersin == NULL) {
		DBGPRINT("null pointer\n");
		dns_c_ctx_unsettransfersin(cfg->confctx);
	} else
		dns_c_ctx_settransfersin(cfg->confctx, transfersin);
}

unsigned int DNSConf_gettransfersin(DNSConf *cfg) {
	unsigned int result;
	isc_result_t tmpres;

	if (cfg == NULL || cfg->confctx == NULL)
		return NULL;

	tmpres = dns_c_ctx_gettransfersin(cfg->confctx, &result);
	if (tmpres == ISC_R_NOTFOUND)
		return NULL;

	return result;
}



INT_FIELD_DEFS(transfersin)
INT_FIELD_DEFS(transfersperns)
INT_FIELD_DEFS(transfersout)
INT_FIELD_DEFS(maxlogsizeixfr)
INT_FIELD_DEFS(cleaninterval)
INT_FIELD_DEFS(interfaceinterval)
INT_FIELD_DEFS(statsinterval)
INT_FIELD_DEFS(heartbeatinterval)
INT_FIELD_DEFS(maxtransfertimein)
INT_FIELD_DEFS(maxtransfertimeout)
INT_FIELD_DEFS(maxtransferidlein)
INT_FIELD_DEFS(maxtransferidleout)
INT_FIELD_DEFS(lamettl)
INT_FIELD_DEFS(tcpclients)
INT_FIELD_DEFS(recursiveclients)
INT_FIELD_DEFS(minroots)
INT_FIELD_DEFS(serialqueries)
INT_FIELD_DEFS(sigvalidityinterval)
INT_FIELD_DEFS(datasize)
INT_FIELD_DEFS(stacksize)
INT_FIELD_DEFS(coresize)
INT_FIELD_DEFS(files)
INT_FIELD_DEFS(maxcachesize)
INT_FIELD_DEFS(maxncachettl)
INT_FIELD_DEFS(maxcachettl)


#endif

%}


%typemap(perl5, out) char * {
	$target = sv_newmortal();
	sv_setpv($target,$source);
	argvi++;
}

%typemap(perl5, out) int, short, long {
	$target = sv_newmortal();
	sv_setiv($target,(IV)$source);
	argvi++;
}

%typemap(perl5,in) FILE * {
	$target = IoIFP(sv_2io($source));
}


%typemap(perl5, in) unsigned int {
	static unsigned int val;
	val = $target;
	$source = &val;
}


struct DNSConf {
	%addmethods {
		DNSConf();
		~DNSConf();
		void print(FILE *outfile);
		void parse(const char *filename);

		void setdirectory(const char *arg);
		char *getdirectory();

		void settransfersin(unsigned int arg);
		unsigned int gettransfersin();
	}
	%readonly
	dns_c_ctx_t *confctx;
};
