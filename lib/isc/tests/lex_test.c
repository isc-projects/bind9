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

#if HAVE_CMOCKA

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/util.h>

#include "isctest.h"

static bool debug = false;

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

/* check handling of 0xff */
static void
lex_0xff(void **state) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t death_buf;
	isc_token_t token;

	unsigned char death[] = { EOF, 'A' };

	UNUSED(state);

	result = isc_lex_create(test_mctx, 1024, &lex);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_init(&death_buf, &death[0], sizeof(death));
	isc_buffer_add(&death_buf, sizeof(death));

	result = isc_lex_openbuffer(lex, &death_buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_gettoken(lex, 0, &token);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_lex_destroy(&lex);
}

/* check setting of source line */
static void
lex_setline(void **state) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	unsigned char text[] = "text\nto\nbe\nprocessed\nby\nlexer";
	isc_buffer_t buf;
	isc_token_t token;
	unsigned long line;
	int i;

	UNUSED(state);

	result = isc_lex_create(test_mctx, 1024, &lex);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_init(&buf, &text[0], sizeof(text));
	isc_buffer_add(&buf, sizeof(text));

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_setsourceline(lex, 100);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (i = 0; i < 6; i++) {
		result = isc_lex_gettoken(lex, 0, &token);
		assert_int_equal(result, ISC_R_SUCCESS);

		line = isc_lex_getsourceline(lex);
		assert_int_equal(line, 100U + i);
	}

	result = isc_lex_gettoken(lex, 0, &token);
	assert_int_equal(result, ISC_R_EOF);

	line = isc_lex_getsourceline(lex);
	assert_int_equal(line, 105U);

	isc_lex_destroy(&lex);
}

/*%
 * keypair is <string>=<qstring>.  This has implications double quotes
 * in key names.
 */
static void
lex_keypair(void **state) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_result_t result;
	isc_token_t token;
	size_t i;

	struct {
		const char *text;
		const char *value;
		isc_result_t result;
		isc_tokentype_t type;
	} tests[] = {
		{ "", "", ISC_R_SUCCESS, isc_tokentype_eof },
		{ "1234", "1234", ISC_R_SUCCESS, isc_tokentype_string },
		{ "1234=", "1234=", ISC_R_SUCCESS, isc_tokentype_vpair },
		{ "1234=foo", "1234=foo", ISC_R_SUCCESS, isc_tokentype_vpair },
		{ "1234=\"foo", NULL, ISC_R_UNEXPECTEDEND, 0 },
		{ "1234=\"foo\"", "1234=foo", ISC_R_SUCCESS,
		  isc_tokentype_qvpair },
		{ "key", "key", ISC_R_SUCCESS, isc_tokentype_string },
		{ "\"key=", "\"key=", ISC_R_SUCCESS, isc_tokentype_vpair },
		{ "\"key=\"", NULL, ISC_R_UNEXPECTEDEND, 0 },
		{ "key=\"\"", "key=", ISC_R_SUCCESS, isc_tokentype_qvpair },
		{ "key=\"a b\"", "key=a b", ISC_R_SUCCESS,
		  isc_tokentype_qvpair },
		{ "key=\"a\tb\"", "key=a\tb", ISC_R_SUCCESS,
		  isc_tokentype_qvpair },
		/* double quote not immediately after '=' is not special. */
		{ "key=c\"a b\"", "key=c\"a", ISC_R_SUCCESS,
		  isc_tokentype_vpair },
		/* remove special meaning for '=' by escaping */
		{ "key\\=", "key\\=", ISC_R_SUCCESS, isc_tokentype_string },
		{ "key\\=\"a\"", "key\\=\"a\"", ISC_R_SUCCESS,
		  isc_tokentype_string },
		{ "key\\=\"a \"", "key\\=\"a", ISC_R_SUCCESS,
		  isc_tokentype_string },
		/* vpair with a key of 'key\=' (would need to be deescaped) */
		{ "key\\==", "key\\==", ISC_R_SUCCESS, isc_tokentype_vpair },
		/* qvpair with a key of 'key\=' (would need to be deescaped) */
		{ "key\\==\"\"", "key\\==", ISC_R_SUCCESS,
		  isc_tokentype_qvpair },
	};

	UNUSED(state);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		result = isc_lex_create(test_mctx, 1024, &lex);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_buffer_constinit(&buf, tests[i].text,
				     strlen(tests[i].text));
		isc_buffer_add(&buf, strlen(tests[i].text));

		result = isc_lex_openbuffer(lex, &buf);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = isc_lex_setsourceline(lex, 100);
		assert_int_equal(result, ISC_R_SUCCESS);

		memset(&token, 0, sizeof(token));
		result = isc_lex_getmastertoken(lex, &token,
						isc_tokentype_qvpair, true);
		if (debug) {
			fprintf(stdout, "# '%s' -> result=%s/%s, type=%u/%u\n",
				tests[i].text, isc_result_toid(result),
				isc_result_toid(tests[i].result), token.type,
				tests[i].type);
		}

		assert_int_equal(result, tests[i].result);
		if (result == ISC_R_SUCCESS) {
			switch (token.type) {
			case isc_tokentype_string:
			case isc_tokentype_qstring:
			case isc_tokentype_vpair:
			case isc_tokentype_qvpair:
				if (debug) {
#define AS_STR(x) (x).value.as_textregion.base
					fprintf(stdout, "# value='%s'\n",
						AS_STR(token));
				}
				assert_int_equal(token.type, tests[i].type);
				assert_string_equal(AS_STR(token),
						    tests[i].value);
				break;
			default:
				assert_int_equal(token.type, tests[i].type);
				break;
			}
		}

		isc_lex_destroy(&lex);
	}
}

int
main(int argc, char *argv[]) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(lex_0xff),
		cmocka_unit_test(lex_keypair),
		cmocka_unit_test(lex_setline),
	};

	UNUSED(argv);

	if (argc > 1) {
		debug = true;
	}

	return (cmocka_run_group_tests(tests, _setup, _teardown));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
