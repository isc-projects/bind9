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

/* $Id: named-checkconf.c,v 1.2.2.1 2001/01/09 22:31:16 bwelling Exp $ */

#include <config.h>

#include <errno.h>
#include <stdlib.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/namedconf.h>

#include "check-tool.h"

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
	dns_c_ctx_t *configctx = NULL;
	const char *conffile = NULL;
	isc_mem_t *mctx = NULL;
	dns_c_cbks_t callbacks;
	isc_log_t *log = NULL;

	callbacks.zonecbk = zonecbk;
	callbacks.optscbk = optscbk;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbkuap = NULL;

	if (argc > 1)
		conffile = argv[1];
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
