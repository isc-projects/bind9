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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include <tests/isc.h>

static isc_logcategory_t categories[] = { { "", 0 },
					  { "client", 0 },
					  { "network", 0 },
					  { "update", 0 },
					  { "queries", 0 },
					  { "unmatched", 0 },
					  { "update-security", 0 },
					  { "query-errors", 0 },
					  { NULL, 0 } };

ISC_SETUP_TEST_IMPL(group) {
	isc_result_t result;
	isc_logdestination_t destination;
	isc_logconfig_t *logconfig = NULL;

	isc_log_create(mctx, &lctx, &logconfig);
	isc_log_registercategories(lctx, categories);
	isc_log_setcontext(lctx);

	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	isc_log_createchannel(logconfig, "stderr", ISC_LOG_TOFILEDESC,
			      ISC_LOG_DYNAMIC, &destination, 0);
	result = isc_log_usechannel(logconfig, "stderr", NULL, NULL);

	if (result != ISC_R_SUCCESS) {
		return (-1);
	}

	return (0);
}

ISC_TEARDOWN_TEST_IMPL(group) {
	if (lctx == NULL) {
		return (-1);
	}

	isc_log_setcontext(NULL);
	isc_log_destroy(&lctx);

	return (0);
}

struct duration_conf {
	const char *string;
	uint32_t time;
};
typedef struct duration_conf duration_conf_t;

/* test cfg_obj_asduration() */
ISC_RUN_TEST_IMPL(cfg_obj_asduration) {
	isc_result_t result;
	duration_conf_t durations[] = {
		{ .string = "PT0S", .time = 0 },
		{ .string = "PT42S", .time = 42 },
		{ .string = "PT10m", .time = 600 },
		{ .string = "PT10m4S", .time = 604 },
		{ .string = "pT2H", .time = 7200 },
		{ .string = "Pt2H3S", .time = 7203 },
		{ .string = "PT2h1m3s", .time = 7263 },
		{ .string = "p7d", .time = 604800 },
		{ .string = "P7DT2h", .time = 612000 },
		{ .string = "P2W", .time = 1209600 },
		{ .string = "P3M", .time = 8035200 },
		{ .string = "P3MT10M", .time = 8035800 },
		{ .string = "p5y", .time = 157680000 },
		{ .string = "P5YT2H", .time = 157687200 },
		{ .string = "P1Y1M1DT1H1M1S", .time = 34304461 },
		{ .string = "0", .time = 0 },
		{ .string = "30", .time = 30 },
		{ .string = "42s", .time = 42 },
		{ .string = "10m", .time = 600 },
		{ .string = "2H", .time = 7200 },
		{ .string = "7d", .time = 604800 },
		{ .string = "2w", .time = 1209600 },
	};
	int num = 22;
	isc_buffer_t buf1;
	cfg_parser_t *p1 = NULL;
	cfg_obj_t *c1 = NULL;

	for (int i = 0; i < num; i++) {
		const cfg_listelt_t *element;
		const cfg_obj_t *kasps = NULL;
		char conf[64];
		sprintf(&conf[0],
			"dnssec-policy \"dp\"\n{\nsignatures-refresh %s;\n};\n",
			durations[i].string);

		isc_buffer_init(&buf1, conf, strlen(conf) - 1);
		isc_buffer_add(&buf1, strlen(conf) - 1);

		/* Parse with default line numbering */
		result = cfg_parser_create(mctx, lctx, &p1);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = cfg_parse_buffer(p1, &buf1, "text1", 0,
					  &cfg_type_namedconf, 0, &c1);
		assert_int_equal(result, ISC_R_SUCCESS);

		(void)cfg_map_get(c1, "dnssec-policy", &kasps);
		assert_non_null(kasps);
		for (element = cfg_list_first(kasps); element != NULL;
		     element = cfg_list_next(element))
		{
			const cfg_obj_t *d1 = NULL;
			const cfg_obj_t *kopts = NULL;
			cfg_obj_t *kconf = cfg_listelt_value(element);
			assert_non_null(kconf);

			kopts = cfg_tuple_get(kconf, "options");
			result = cfg_map_get(kopts, "signatures-refresh", &d1);
			assert_int_equal(result, ISC_R_SUCCESS);

			assert_int_equal(durations[i].time,
					 cfg_obj_asduration(d1));
		}

		cfg_obj_destroy(p1, &c1);
		cfg_parser_destroy(&p1);
	}
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(cfg_obj_asduration)

ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, teardown_test_group)
