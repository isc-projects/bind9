/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: named-checkconf.c,v 1.4 2001/01/29 03:23:11 marka Exp $ */

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <isc/commandline.h>
#include <isc/dir.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/namedconf.h>

#include "check-tool.h"

static void
usage(void) {
        fprintf(stderr, "usage: named-checkconf [-t directory] [named.conf]\n");
        exit(1);
}

static isc_result_t
zonecbk(dns_c_ctx_t *ctx, dns_c_zone_t *zone, dns_c_view_t *view, void *uap) {

	UNUSED(ctx);
	UNUSED(uap);
	UNUSED(zone);
	UNUSED(view);

	return (ISC_R_SUCCESS);
}

static isc_result_t
optscbk(dns_c_ctx_t *ctx, void *uap) {
	UNUSED(ctx);
	UNUSED(uap);

	return (ISC_R_SUCCESS);
}

int
main(int argc, char **argv) {
	int c;
	dns_c_ctx_t *configctx = NULL;
	const char *conffile = NULL;
	isc_mem_t *mctx = NULL;
	dns_c_cbks_t callbacks;
	isc_log_t *log = NULL;
	isc_result_t result;

	callbacks.zonecbk = zonecbk;
	callbacks.optscbk = optscbk;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbkuap = NULL;

	while ((c = isc_commandline_parse(argc, argv, "t:")) != EOF) {
		switch (c) {
		case 't':
			result = isc_dir_chroot(isc_commandline_argument);
			if (result != ISC_R_SUCCESS) {
				fprintf(stderr, "isc_dir_chroot: %s\n",
					isc_result_totext(result));
				exit(1);
			}
			result = isc_dir_chdir("/");
			if (result != ISC_R_SUCCESS) {
				fprintf(stderr, "isc_dir_chdir: %s\n",
					isc_result_totext(result));
				exit(1);
			}
			break;

		default:
			usage();
		}
	}

	if (argv[isc_commandline_index] != NULL)
		conffile = argv[isc_commandline_index];
	if (conffile == NULL || conffile[0] == '\0')
		conffile = "/etc/named.conf";

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(setup_logging(mctx, &log) == ISC_R_SUCCESS);

	if (dns_c_parse_namedconf(conffile, mctx, &configctx, &callbacks) !=
	    ISC_R_SUCCESS) {
		exit(1);
	}

	dns_c_ctx_delete(&configctx);

	isc_log_destroy(&log);

	isc_mem_destroy(&mctx);

	return (0);
}
