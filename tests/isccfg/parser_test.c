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

#include <inttypes.h>
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
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include <tests/isc.h>

ISC_SETUP_TEST_IMPL(group) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	return 0;
}

/* mimic calling nzf_append() */
static void
append(void *arg, const char *str, int len) {
	char *buf = arg;
	size_t l = strlen(buf);
	snprintf(buf + l, 1024 - l, "%.*s", len, str);
}

ISC_RUN_TEST_IMPL(addzoneconf) {
	isc_result_t result;
	isc_buffer_t b;
	const char *tests[] = {
		"zone \"test4.baz\" { type primary; file \"e.db\"; };",
		"zone \"test/.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\\".baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\\\.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\032.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\010.baz\" { type primary; file \"e.db\"; };"
	};
	char buf[1024];

	/* Parse with default line numbering */
	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		cfg_obj_t *conf = NULL;
		const cfg_obj_t *obj = NULL, *zlist = NULL;

		isc_buffer_constinit(&b, tests[i], strlen(tests[i]));
		isc_buffer_add(&b, strlen(tests[i]));

		result = cfg_parse_buffer(&b, "text1", 0, &cfg_type_namedconf,
					  0, &conf);
		assert_int_equal(result, ISC_R_SUCCESS);

		/*
		 * Mimic calling nzf_append() from bin/named/server.c
		 * and check that the output matches the input.
		 */
		result = cfg_map_get(conf, "zone", &zlist);
		assert_int_equal(result, ISC_R_SUCCESS);

		obj = cfg_listelt_value(cfg_list_first(zlist));
		assert_ptr_not_equal(obj, NULL);

		strlcpy(buf, "zone ", sizeof(buf));
		cfg_printx(obj, CFG_PRINTER_ONELINE, append, buf);
		strlcat(buf, ";", sizeof(buf));
		assert_string_equal(tests[i], buf);

		cfg_obj_detach(&conf);
	}
}

/* test cfg_parse_buffer() */
ISC_RUN_TEST_IMPL(parse_buffer) {
	isc_result_t result;
	int fresult;
	unsigned char text[] = "options\n{\nidonotexists yes;\n};\n";
	char logfilebuf[512];
	size_t logfilelen;
	isc_buffer_t buf;
	cfg_obj_t *c = NULL;

	/*
	 * Redirect parser errors into a specific file for checking the output
	 * later.
	 */
	constexpr char logfilename[] = "./cfglog.out";
	FILE *logfile = fopen(logfilename, "w+");
	assert_non_null(logfile);

	isc_logdestination_t *logdest = ISC_LOGDESTINATION_FILE(logfile);
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(logconfig, "default_stderr",
				    ISC_LOG_TOFILEDESC, ISC_LOG_DYNAMIC,
				    logdest, 0, ISC_LOGCATEGORY_DEFAULT,
				    ISC_LOGMODULE_DEFAULT);

	/* Parse with default line numbering. */
	isc_buffer_init(&buf, &text[0], sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	result = cfg_parse_buffer(&buf, "text1", 0, &cfg_type_namedconf, 0, &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Parse with changed line number. */
	isc_buffer_first(&buf);
	result = cfg_parse_buffer(&buf, "text2", 100, &cfg_type_namedconf, 0,
				  &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Parse with changed line number and no name. */
	isc_buffer_first(&buf);
	result = cfg_parse_buffer(&buf, NULL, 100, &cfg_type_namedconf, 0, &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Check log values (and, specifically, line numbers). */
	logfilelen = ftell(logfile);
	assert_uint_in_range(logfilelen, 0, sizeof(logfilebuf));

	fresult = fseek(logfile, 0, SEEK_SET);
	assert_int_equal(fresult, 0);

	fresult = fread(logfilebuf, 1, logfilelen, logfile);
	assert_int_equal(fresult, logfilelen);

	logfilebuf[logfilelen] = 0;

	assert_non_null(
		strstr(logfilebuf, "text1:3: unknown option 'idonotexists'"));
	assert_non_null(
		strstr(logfilebuf, "text2:102: unknown option 'idonotexists'"));
	assert_non_null(
		strstr(logfilebuf, "none:102: unknown option 'idonotexists'"));

	fclose(logfile);
	remove(logfilename);
}

/* test cfg_map_firstclause() */
ISC_RUN_TEST_IMPL(cfg_map_firstclause) {
	const void *clauses = NULL;
	unsigned int idx;
	const cfg_clausedef_t *clause = NULL;

	clause = cfg_map_firstclause(&cfg_type_zoneopts, &clauses, &idx);
	assert_non_null(clause);
	assert_non_null(clause->name);
	assert_non_null(clauses);
	assert_int_equal(idx, 0);
}

/* test cfg_map_nextclause() */
ISC_RUN_TEST_IMPL(cfg_map_nextclause) {
	const void *clauses = NULL;
	unsigned int idx;
	const cfg_clausedef_t *clause = NULL;

	clause = cfg_map_firstclause(&cfg_type_zoneopts, &clauses, &idx);
	assert_non_null(clause);
	assert_non_null(clause->name);
	assert_non_null(clauses);
	assert_int_equal(idx, ISC_R_SUCCESS);

	do {
		clause = cfg_map_nextclause(&cfg_type_zoneopts, &clauses, &idx);
		if (clause != NULL) {
			assert_non_null(clauses);
		} else {
			assert_null(clauses);
			assert_int_equal(idx, 0);
		}
	} while (clause != NULL);
}

static void
cfg_clone_copy_dumpconf(void *closure, const char *text, int textlen) {
	isc_buffer_putmem((isc_buffer_t *)closure, (const unsigned char *)text,
			  textlen);
}

ISC_RUN_TEST_IMPL(cfg_clone_copy) {
	cfg_obj_t *orig = NULL;
	cfg_obj_t *clone = NULL;
	isc_result_t result;
	isc_buffer_t buf;
	isc_buffer_t dumpb1;
	char dumpbdata1[10024];
	size_t dumpblen1;
	isc_buffer_t dumpb2;
	char dumpbdata2[10024];
	size_t dumpblen2;

	/*
	 * This is a modified subset of the default conf which contains
	 * all the possible types cloned and copied.
	 */
	static char conf[] = "\
options {\n\
	answer-cookie yes;\n\
	cookie-algorithm siphash24;\n\
	dump-file \"named_dump.db\";\n\
	listen-on port 53 tls \"foobar\" {\n\
		127.0.0.1/32;\n\
	};\n\
	notify-rate 20;\n\
	allow-recursion {\n\
		\"localhost\";\n\
		\"localnets\";\n\
	};\n\
	prefetch 2 9;\n\
	check-dup-records warn;\n\
	max-ixfr-ratio 100%;\n\
};\n\
remote-servers \"foo\" {\n\
	2801:1b8:10::b;\n\
	192.0.32.132;\n\
};\n\
view \"_bind\" chaos {\n\
	zone \"version.bind\" chaos {\n\
		type primary;\n\
		database \"_builtin version\";\n\
		update-policy {\n\
			grant \"int\" zonesub \"any\";\n\
		};\n\
	};\n\
	max-cache-size 2097152;\n\
	rate-limit {\n\
		min-table-size 10;\n\
		slip 0;\n\
	};\n\
};\n";

	isc_buffer_init(&buf, conf, sizeof(conf));
	isc_buffer_add(&buf, sizeof(conf) - 1);

	result = cfg_parse_buffer(&buf, "", 0, &cfg_type_namedconf, 0, &orig);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_init(&dumpb1, dumpbdata1, sizeof(dumpbdata1));
	cfg_printx(orig, 0, cfg_clone_copy_dumpconf, &dumpb1);

	/*
	 * The point of the test is not really to test the stringify code of the
	 * cfg_obj_t tree, but let's do it as a sanity check first.
	 */
	dumpblen1 = isc_buffer_remaininglength(&dumpb1);
	assert_int_equal(sizeof(conf) - 1, dumpblen1);
	assert_memory_equal(conf, dumpbdata1, dumpblen1);

	/*
	 * The original tree can be freed anytime, it is not connected in any
	 * way to the clone.
	 */
	cfg_obj_clone(orig, &clone);
	cfg_obj_detach(&orig);

	/*
	 * Dumping the clone and comparing its output to the original
	 * dump of the orinal config verify-ish the two assumptions above.
	 */
	isc_buffer_init(&dumpb2, dumpbdata2, sizeof(dumpbdata2));
	cfg_printx(clone, 0, cfg_clone_copy_dumpconf, &dumpb2);

	dumpblen1 = isc_buffer_remaininglength(&dumpb1);
	dumpblen2 = isc_buffer_remaininglength(&dumpb2);
	assert_int_equal(dumpblen1, dumpblen2);
	assert_memory_equal(dumpbdata1, dumpbdata2, dumpblen1);

	cfg_obj_detach(&clone);
}

static const cfg_clausedef_t *const empty_clausesets[] = { NULL };

static cfg_type_t cfg_type_empty_map = {
	"empty_map", NULL, NULL, NULL, &cfg_rep_map, &empty_clausesets,
};

ISC_RUN_TEST_IMPL(cfg_map_findclause_empty) {
	const cfg_clausedef_t *result = cfg_map_findclause(&cfg_type_empty_map,
							   "anything");
	assert_null(result);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(addzoneconf)
ISC_TEST_ENTRY(parse_buffer)
ISC_TEST_ENTRY(cfg_map_firstclause)
ISC_TEST_ENTRY(cfg_map_nextclause)
ISC_TEST_ENTRY(cfg_clone_copy)
ISC_TEST_ENTRY(cfg_map_findclause_empty)

ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, NULL)
