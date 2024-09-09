/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

static void
output(void *closure ISC_ATTR_UNUSED, const char *text, int textlen) {
	(void)fwrite(text, 1, textlen, stdout);
}

static void
usage(void) {
	fprintf(stderr, "usage: cfg_test --rndc|--named "
			"[--grammar] [--zonegrammar] [--active] "
			"[--memstats] conffile\n");
	exit(EXIT_FAILURE);
}

static void
setup_logging(void) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, ISC_LOG_PRINTTIME,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);
}

int
main(int argc, char **argv) {
	isc_result_t result;
	isc_mem_t *mctx = NULL;
	cfg_parser_t *pctx = NULL;
	cfg_obj_t *cfg = NULL;
	cfg_type_t *type = NULL;
	bool grammar = false;
	bool memstats = false;
	char *filename = NULL;
	unsigned int zonetype = 0;
	unsigned int pflags = 0;

	isc_mem_create(&mctx);

	setup_logging();

	/*
	 * Set the initial debug level.
	 */
	isc_log_setdebuglevel(2);

	if (argc < 3) {
		usage();
	}

	while (argc > 1) {
		if (strcmp(argv[1], "--active") == 0) {
			pflags |= CFG_PRINTER_ACTIVEONLY;
		} else if (strcmp(argv[1], "--grammar") == 0) {
			grammar = true;
		} else if (strcmp(argv[1], "--zonegrammar") == 0) {
			argv++, argc--;
			if (argc <= 1) {
				usage();
			}
			if (strcmp(argv[1], "master") == 0 ||
			    strcmp(argv[1], "primary") == 0)
			{
				zonetype = CFG_ZONE_PRIMARY;
			} else if (strcmp(argv[1], "slave") == 0 ||
				   strcmp(argv[1], "secondary") == 0)
			{
				zonetype = CFG_ZONE_SECONDARY;
			} else if (strcmp(argv[1], "mirror") == 0) {
				zonetype = CFG_ZONE_MIRROR;
			} else if (strcmp(argv[1], "stub") == 0) {
				zonetype = CFG_ZONE_STUB;
			} else if (strcmp(argv[1], "static-stub") == 0) {
				zonetype = CFG_ZONE_STATICSTUB;
			} else if (strcmp(argv[1], "hint") == 0) {
				zonetype = CFG_ZONE_HINT;
			} else if (strcmp(argv[1], "forward") == 0) {
				zonetype = CFG_ZONE_FORWARD;
			} else if (strcmp(argv[1], "redirect") == 0) {
				zonetype = CFG_ZONE_REDIRECT;
			} else if (strcmp(argv[1], "in-view") == 0) {
				zonetype = CFG_ZONE_INVIEW;
			} else {
				usage();
			}
		} else if (strcmp(argv[1], "--memstats") == 0) {
			memstats = true;
		} else if (strcmp(argv[1], "--named") == 0) {
			type = &cfg_type_namedconf;
		} else if (strcmp(argv[1], "--rndc") == 0) {
			type = &cfg_type_rndcconf;
		} else if (argv[1][0] == '-') {
			usage();
		} else {
			filename = argv[1];
		}
		argv++, argc--;
	}

	if (grammar) {
		if (type == NULL) {
			usage();
		}
		cfg_print_grammar(type, pflags, output, NULL);
	} else if (zonetype != 0) {
		cfg_print_zonegrammar(zonetype, pflags, output, NULL);
	} else {
		if (type == NULL || filename == NULL) {
			usage();
		}
		RUNTIME_CHECK(cfg_parser_create(mctx, &pctx) == ISC_R_SUCCESS);

		result = cfg_parse_file(pctx, filename, type, &cfg);

		fprintf(stderr, "read config: %s\n", isc_result_totext(result));

		if (result != ISC_R_SUCCESS) {
			exit(EXIT_FAILURE);
		}

		cfg_print(cfg, output, NULL);

		cfg_obj_destroy(pctx, &cfg);

		cfg_parser_destroy(&pctx);
	}

	if (memstats) {
		isc_mem_stats(mctx, stderr);
	}
	isc_mem_detach(&mctx);

	fflush(stdout);
	if (ferror(stdout)) {
		fprintf(stderr, "write error\n");
		return 1;
	}

	return 0;
}
