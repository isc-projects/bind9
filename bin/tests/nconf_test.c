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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <isc/mem.h>

#include <dns/log.h>
#include <dns/namedconf.h>

#include <isc/error.h>

isc_result_t zonecbk(dns_c_ctx_t *ctx, dns_c_zone_t *zone,
		     dns_c_view_t *view, void *uap);
isc_result_t optscbk(dns_c_ctx_t *ctx, void *uap);


isc_result_t
zonecbk(dns_c_ctx_t *ctx, dns_c_zone_t *zone, dns_c_view_t *view, void *uap)
{
	const char *zname;
	const char *vname;

	(void) ctx;
	(void) uap;
	
	dns_c_zone_getname(zone, &zname);

#if 0
	if (view != NULL) {
		dns_c_view_getname(NULL, view, &vname);
	} else {
		vname = "no current view";
	}
#else
	(void) view;
	vname = "foo";
#endif	

	fprintf(stderr, "handling zone %s, view %s\n", zname, vname);

	return (ISC_R_SUCCESS);
}


isc_result_t
optscbk(dns_c_ctx_t *ctx, void *uap)
{
	(void) ctx;
	(void) uap;
	
	fprintf(stderr, "Processing options in callback.\n");
	return (ISC_R_SUCCESS);
}


	
int main (int argc, char **argv) {
	dns_c_ctx_t *configctx = NULL;
	const char *conffile;
	FILE *outfp;
	isc_mem_t *mem = NULL;
	dns_c_cbks_t callbacks;
	isc_log_t *log = NULL;
	isc_logconfig_t *logcfg = NULL;
	
#if 1
	callbacks.zonecbk = NULL;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbk = NULL;
	callbacks.optscbkuap = NULL;
#else
	callbacks.zonecbk = zonecbk;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbk = optscbk;
	callbacks.optscbkuap = NULL;
#endif
	
	if (argc > 1 && strcmp(argv[1],"-d") == 0) {
		argv++;
		argc--;
		debug_mem_print = ISC_TRUE;
	}
	
	conffile = getenv("NAMED_CONF");
	if (argc > 1)
		conffile = argv[1];
	if (conffile == NULL || conffile[0] == '\0')
		conffile = "/etc/named.conf";

	RUNTIME_CHECK(isc_mem_create(0, 0, &mem) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_log_create(mem, &log, &logcfg) == ISC_R_SUCCESS);
	dns_log_init(log);
	
	RUNTIME_CHECK(isc_log_usechannel(logcfg, "default_stderr", NULL, NULL)
		      == ISC_R_SUCCESS);

	dns_lctx = log;
	
	if (dns_c_parse_namedconf(conffile, mem, &configctx, &callbacks) !=
	    ISC_R_SUCCESS) {
		fprintf(stderr, "parse_configuration failed.\n");
		exit(1);
	}

	if (configctx->errors > 0) {
		fprintf(stderr,
			"There were %d semantic errors in the config file.\n",
			configctx->errors);
	}

	outfp = stdout;
	if (argc > 2) {
		if ((outfp = fopen(argv[2], "w")) == NULL) {
			fprintf(stderr, "Cannot open %s: %s",
				argv[2], strerror(errno));
			outfp = stderr;
		}
	}
	
	dns_c_ctx_print(outfp, 0, configctx);

#if 0
	/* Test the acl expansion */
	{
		dns_ipmatch_list_t *list;
		dns_acl_t *acl;

		dns_acl_table_get_acl(configctx->acls, "cannot_query", &acl);
		dns_acl_get_ipml_expanded(mem, acl, &list);
		dns_ipmatch_list_print(outfp, 0, list);
	}
#endif
	
	if (outfp != stderr) {
		fclose(outfp);
	}

	dns_c_ctx_delete(&configctx);

	dns_lctx = NULL;
	isc_log_destroy(&log);
	
	isc_mem_destroy(&mem);

	return (0);
}
	
	

	
