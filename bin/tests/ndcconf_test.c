/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: ndcconf_test.c,v 1.10 2000/08/01 01:13:06 tale Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/confndc.h>


int
main(int argc, char **argv) {
	dns_c_ndcctx_t *ndcctx = NULL;
	const char *conffile;
	isc_mem_t *mem = NULL;
	isc_log_t *log = NULL;
	isc_logconfig_t *logcfg = NULL;
	const char *program = NULL;

	program = strrchr(argv[0], '/');
	if (program == NULL) {
		program = argv[0];
	} else {
		program++;
	}

	argc--;
	argv++;

	if (argc == 0) {
		fprintf(stderr, "usage: %s file\n", program);
		exit (1);
	}

	conffile = argv[0];

	RUNTIME_CHECK(isc_mem_create(0, 0, &mem) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_log_create(mem, &log, &logcfg) == ISC_R_SUCCESS);
	isc_log_setcontext(log);
	dns_log_init(log);
	dns_log_setcontext(log);

	RUNTIME_CHECK(isc_log_usechannel(logcfg, "default_stderr", NULL, NULL)
		      == ISC_R_SUCCESS);

	dns_lctx = log;

	if (dns_c_ndcparseconf(conffile, mem, &ndcctx) != ISC_R_SUCCESS) {
		fprintf(stderr, "parse_configuration failed.\n");
		exit(1);
	} else {
		dns_c_ndcctx_print(stderr, ndcctx);
	}


	dns_c_ndcctx_destroy(&ndcctx);

	dns_lctx = NULL;
	isc_log_destroy(&log);

	isc_mem_destroy(&mem);

	return (0);
}

