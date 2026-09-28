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
#include <isccfg/tokens.h>

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

/* Preserve lexical spelling, including quoted punctuation and escapes. */
ISC_RUN_TEST_IMPL(tokens_roundtrip) {
	const char *spelling[] = {
		"plain",     "\"plain\"",     "\"\"",	       "\"a\\ b\"",
		"\"a\\;b\"", "\"a\\#b\"",     "\"a\\/b\"",     "\"a\\!b\"",
		"\"a\\{b\"", "\"a\\}b\"",     "\"a\\\tb\"",    "\"a\\\"b\"",
		"tail\\",    "tail\\\\",      "\"tail\\\\\"",  "\"a\\\\\\\"b\"",
		"\"/\"",     "\"/\"",	      "\"/\"",	       "\"*\"",
		"\"!\"",     CFG_TOKEN_SLASH, CFG_TOKEN_BANG,  CFG_TOKEN_OPEN,
		"nested",    CFG_TOKEN_END,   CFG_TOKEN_CLOSE, CFG_TOKEN_END,
		NULL
	};
	unsigned int flags[] = { 0, CFG_PRINTER_ONELINE };
	char input[1024] = "{ ";

	for (const char *const *t = spelling; *t != NULL; t++) {
		const char *text = *t;
		if (text == CFG_TOKEN_OPEN) {
			text = "{";
		} else if (text == CFG_TOKEN_CLOSE) {
			text = "}";
		} else if (text == CFG_TOKEN_END) {
			text = ";";
		} else if (text == CFG_TOKEN_SLASH) {
			text = "/";
		} else if (text == CFG_TOKEN_BANG) {
			text = "!";
		}
		strlcat(input, text, sizeof(input));
		strlcat(input, " ", sizeof(input));
	}
	strlcat(input, "}", sizeof(input));

	for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
		cfg_obj_t *obj = NULL, *copy = NULL;
		char printed[1024] = "";
		isc_buffer_t b;

		isc_buffer_constinit(&b, input, strlen(input));
		isc_buffer_add(&b, strlen(input));
		assert_int_equal(cfg_parse_buffer(&b, "tokens", 1,
						  &cfg_type_bracketed_tokens, 0,
						  &obj),
				 ISC_R_SUCCESS);
		cfg_printx(obj, flags[i], append, printed);
		isc_buffer_constinit(&b, printed, strlen(printed));
		isc_buffer_add(&b, strlen(printed));
		assert_int_equal(cfg_parse_buffer(&b, "printed", 1,
						  &cfg_type_bracketed_tokens, 0,
						  &copy),
				 ISC_R_SUCCESS);

		const char *const *original = cfg_obj_astokens(obj);
		const char *const *reparsed = cfg_obj_astokens(copy);
		for (size_t j = 0; j < ARRAY_SIZE(spelling); j++) {
			if (spelling[j] != NULL &&
			    CFG_TOKEN_ISSTRING(spelling[j]))
			{
				assert_non_null(original[j]);
				assert_non_null(reparsed[j]);
				assert_true(CFG_TOKEN_ISSTRING(original[j]));
				assert_true(CFG_TOKEN_ISSTRING(reparsed[j]));
				assert_string_equal(original[j], spelling[j]);
				assert_string_equal(reparsed[j], spelling[j]);
			} else {
				assert_ptr_equal(original[j], spelling[j]);
				assert_ptr_equal(reparsed[j], spelling[j]);
			}
		}
		cfg_obj_detach(&obj);
		cfg_obj_detach(&copy);
	}
}

/* Decoding leaves lexical tokens intact and previous results valid. */
ISC_RUN_TEST_IMPL(tokens_strings) {
	const char *tokens[] = { "\"dynamic-\"", "\"\"",
				 "\"a\\\"b\"",	 "\"a\\ b\"",
				 "\"tail\\\\\"", "\"a\\\\\\\"b\"",
				 "a\\\"b",	 "\"a\nb\"",
				 "plain",	 NULL };
	const char *expected[] = { "dynamic-", "",	   "a\"b",
				   "a\\ b",    "tail\\\\", "a\\\\\"b",
				   "a\\\"b",   "a\nb",	   "plain" };
	const char *values[ARRAY_SIZE(expected)] = { NULL };
	cfg_tokens_t tok;

	cfg_tokens_init(&tok, tokens, "strings", 1);
	for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
		assert_ptr_equal(cfg_tokens_peek(&tok), tokens[i]);
		assert_int_equal(cfg_tokens_getstring(&tok, &values[i]),
				 ISC_R_SUCCESS);
	}
	assert_null(cfg_tokens_peek(&tok));
	for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
		assert_string_equal(values[i], expected[i]);
	}
	assert_string_equal(tokens[0], "\"dynamic-\"");
	cfg_tokens_clear(&tok);
}

/* ACL keywords, named references, and addresses must stay distinct. */
ISC_RUN_TEST_IMPL(tokens_aml) {
	const char *aml = "{ \"key\"; \"geoip\"; \"192.0.2.1\"; \"::1\"; "
			  "!10.0.0.0/8; key \"key name\"; any; { ::1; }; }";
	char input[1024] = "{ ", printed[1024] = "", expected[1024] = "";
	cfg_obj_t *direct = NULL, *tokens = NULL, *copy = NULL, *obj = NULL;
	isc_buffer_t b;
	cfg_tokens_t tok;

	isc_buffer_constinit(&b, aml, strlen(aml));
	isc_buffer_add(&b, strlen(aml));
	assert_int_equal(cfg_parse_buffer(&b, "aml", 1, &cfg_type_bracketed_aml,
					  0, &direct),
			 ISC_R_SUCCESS);
	cfg_printx(direct, CFG_PRINTER_ONELINE, append, expected);
	strlcat(input, aml, sizeof(input));
	strlcat(input, " }", sizeof(input));
	isc_buffer_constinit(&b, input, strlen(input));
	isc_buffer_add(&b, strlen(input));
	assert_int_equal(cfg_parse_buffer(&b, "tokens", 1,
					  &cfg_type_bracketed_tokens, 0,
					  &tokens),
			 ISC_R_SUCCESS);
	cfg_printx(tokens, CFG_PRINTER_ONELINE, append, printed);
	isc_buffer_constinit(&b, printed, strlen(printed));
	isc_buffer_add(&b, strlen(printed));
	assert_int_equal(cfg_parse_buffer(&b, "printed", 1,
					  &cfg_type_bracketed_tokens, 0, &copy),
			 ISC_R_SUCCESS);
	cfg_tokens_init(&tok, cfg_obj_astokens(copy), "printed", 1);
	assert_int_equal(cfg_tokens_getaml(&tok, &obj), ISC_R_SUCCESS);
	assert_null(cfg_tokens_next(&tok));
	printed[0] = '\0';
	cfg_printx(obj, CFG_PRINTER_ONELINE, append, printed);
	assert_string_equal(printed, expected);
	cfg_tokens_clear(&tok);
	cfg_obj_detach(&direct);
	cfg_obj_detach(&tokens);
	cfg_obj_detach(&copy);
	cfg_obj_detach(&obj);
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
	isc_logconfig_t *logconfig = NULL;
	isc_logconfig_create(&logconfig);
	isc_log_createandusechannel(logconfig, "default_stderr",
				    ISC_LOG_TOFILEDESC, ISC_LOG_DYNAMIC,
				    logdest, 0, ISC_LOGCATEGORY_DEFAULT,
				    ISC_LOGMODULE_DEFAULT);
	isc_logconfig_set(logconfig);

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

	/*
	 * Restore logging to stderr before closing the file, so that
	 * later tests do not write into a closed stream.
	 */
	logconfig = NULL;
	isc_logconfig_create(&logconfig);
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);
	isc_logconfig_set(logconfig);

	fclose(logfile);
	remove(logfilename);
}

/*
 * A raw NUL byte embedded in a quoted string must be rejected rather
 * than silently truncated (a truncated "directory" or "include" path
 * would act on something other than what the config file shows).  The
 * NUL is embedded with an explicit buffer length, since strlen() would
 * hide it.
 */
ISC_RUN_TEST_IMPL(parse_nulbyte) {
	isc_result_t result;
	isc_buffer_t buf;
	cfg_obj_t *c = NULL;
	unsigned char text[] =
		"zone \"test.baz\" { type primary; file \"a\0b\"; };\n";

	UNUSED(state);

	isc_buffer_init(&buf, &text[0], sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);

	result = cfg_parse_buffer(&buf, "text1", 0, &cfg_type_namedconf, 0, &c);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(c);
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

ISC_TEST_ENTRY(tokens_roundtrip)
ISC_TEST_ENTRY(tokens_strings)
ISC_TEST_ENTRY(tokens_aml)
ISC_TEST_ENTRY(addzoneconf)
ISC_TEST_ENTRY(parse_buffer)
ISC_TEST_ENTRY(parse_nulbyte)
ISC_TEST_ENTRY(cfg_map_firstclause)
ISC_TEST_ENTRY(cfg_map_nextclause)
ISC_TEST_ENTRY(cfg_clone_copy)
ISC_TEST_ENTRY(cfg_map_findclause_empty)

ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, NULL)
