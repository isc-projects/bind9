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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/mem.h>
#include <isc/url.h>
#include <isc/util.h>

#include <tests/isc.h>

/*
 * Extract the substring of component 'uf' from 'buf' and compare it with
 * 'expected'. A field that is not set is treated as the empty string.
 */
static void
check_field(const isc_url_parser_t *up, const char *buf, isc_url_field_t uf,
	    const char *expected) {
	char got[256] = { 0 };

	if ((up->field_set & (1 << uf)) != 0) {
		uint16_t off = up->field_data[uf].off;
		uint16_t len = up->field_data[uf].len;

		INSIST(len < sizeof(got));
		memmove(got, buf + off, len);
	}

	assert_string_equal(got, expected);
}

ISC_RUN_TEST_IMPL(parse) {
	isc_result_t result;
	isc_url_parser_t up = { 0 };
	const char *url = NULL;

	/* Test an empty buffer. */
	url = "";
	result = isc_url_parse(url, strlen(url), false, &up);
	assert_int_equal(ISC_R_RANGE, result);

	/* Test a buffer with a valid URI. */
	url = "http://user:pass@example.com:8080/test?a=b&c=d";
	result = isc_url_parse(url, strlen(url), false, &up);
	assert_int_equal(ISC_R_SUCCESS, result);
	assert_int_equal(0, up.field_data[ISC_UF_SCHEMA].off);
	assert_int_equal(4, up.field_data[ISC_UF_SCHEMA].len);
	assert_int_equal(17, up.field_data[ISC_UF_HOST].off);
	assert_int_equal(11, up.field_data[ISC_UF_HOST].len);
	assert_int_equal(29, up.field_data[ISC_UF_PORT].off);
	assert_int_equal(4, up.field_data[ISC_UF_PORT].len);
	assert_int_equal(33, up.field_data[ISC_UF_PATH].off);
	assert_int_equal(5, up.field_data[ISC_UF_PATH].len);
	assert_int_equal(39, up.field_data[ISC_UF_QUERY].off);
	assert_int_equal(7, up.field_data[ISC_UF_QUERY].len);
	assert_int_equal(0, up.field_data[ISC_UF_FRAGMENT].off);
	assert_int_equal(0, up.field_data[ISC_UF_FRAGMENT].len);
	assert_int_equal(7, up.field_data[ISC_UF_USERINFO].off);
	assert_int_equal(9, up.field_data[ISC_UF_USERINFO].len);

	/*
	 * Test the maximum accepted buffer length (UINT16_MAX). A path of
	 * exactly UINT16_MAX bytes also drives ISC_UF_PATH.len to its
	 * uint16_t maximum without overflowing.
	 */
	size_t max_len = UINT16_MAX;
	char *max_buf = isc_mem_get(mctx, max_len);
	memset(max_buf, 'a', max_len);
	max_buf[0] = '/';
	result = isc_url_parse(max_buf, max_len, false, &up);
	isc_mem_put(mctx, max_buf, max_len);
	assert_int_equal(ISC_R_SUCCESS, result);
	assert_int_equal(0, up.field_data[ISC_UF_PATH].off);
	assert_int_equal(UINT16_MAX, up.field_data[ISC_UF_PATH].len);

	/* Test a too big buffer (UINT16_MAX + 1). */
	size_t buf_len = UINT16_MAX + 2;
	char *buf = isc_mem_get(mctx, buf_len);
	memset(buf, 'a', buf_len);
	buf[0] = '/';
	result = isc_url_parse(buf, UINT16_MAX + 1, false, &up);
	isc_mem_put(mctx, buf, buf_len);
	assert_int_equal(ISC_R_RANGE, result);
}

/*
 * isc_url_parse() splits an absolute URI / request target into components;
 * it does NOT resolve relative references or remove dot-segments
 * (RFC 3986 section 5). The inputs below are the base URI and a
 * representative subset of the resolved targets from RFC 3986 section 5.4,
 * parsed as standalone absolute URIs. Note in particular that '.'/'..' and
 * embedded slashes inside the query and fragment are preserved verbatim
 * rather than normalized.
 */
ISC_RUN_TEST_IMPL(parse_rfc3986) {
	static const struct {
		const char *uri;
		isc_result_t result;
		/* Expected components (when result is ISC_R_SUCCESS). */
		const char *scheme;
		const char *userinfo;
		const char *host;
		const char *port;
		const char *path;
		const char *query;
		const char *fragment;
	} testcases[] = {
		/* The base URI used throughout RFC 3986 section 5.4. */
		{ "http://a/b/c/d;p?q", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/d;p", "q", "" },

		/* Normal examples (section 5.4.1). */
		{ "http://a/b/c/g", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/g", "", "" },
		{ "http://a/g", ISC_R_SUCCESS, "http", "", "a", "", "/g", "",
		  "" },
		{ "http://g", ISC_R_SUCCESS, "http", "", "g", "", "", "", "" },
		{ "http://a/", ISC_R_SUCCESS, "http", "", "a", "", "/", "",
		  "" },
		{ "http://a/b/c/;x", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/;x", "", "" },
		{ "http://a/b/c/g;x?y#s", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/g;x", "y", "s" },
		{ "http://a/b/c/d;p?q#s", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/d;p", "q", "s" },

		/*
		 * Abnormal examples (section 5.4.2): dot-segments and slashes
		 * embedded in the query and fragment are not normalized.
		 */
		{ "http://a/b/c/..g", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/..g", "", "" },
		{ "http://a/b/c/g..", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/g..", "", "" },
		{ "http://a/b/c/g?y/./x", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/g", "y/./x", "" },
		{ "http://a/b/c/g#s/../x", ISC_R_SUCCESS, "http", "", "a", "",
		  "/b/c/g", "", "s/../x" },

		/* The full generic-syntax example from RFC 3986 section 3. */
		{ "foo://example.com:8042/over/there?name=ferret#nose",
		  ISC_R_SUCCESS, "foo", "", "example.com", "8042",
		  "/over/there", "name=ferret", "nose" },

		/*
		 * Relative references cannot be parsed as request targets:
		 * a scheme requires an authority, and a bare reference has no
		 * host.
		 */
		{ "g:h", ISC_R_FAILURE, "", "", "", "", "", "", "" },
		{ "g", ISC_R_FAILURE, "", "", "", "", "", "", "" },
		{ "http:g", ISC_R_FAILURE, "", "", "", "", "", "", "" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		isc_url_parser_t up = { 0 };
		const char *uri = testcases[i].uri;
		isc_result_t result = isc_url_parse(uri, strlen(uri), false,
						    &up);

		assert_int_equal(result, testcases[i].result);
		if (result != ISC_R_SUCCESS) {
			continue;
		}

		check_field(&up, uri, ISC_UF_SCHEMA, testcases[i].scheme);
		check_field(&up, uri, ISC_UF_USERINFO, testcases[i].userinfo);
		check_field(&up, uri, ISC_UF_HOST, testcases[i].host);
		check_field(&up, uri, ISC_UF_PORT, testcases[i].port);
		check_field(&up, uri, ISC_UF_PATH, testcases[i].path);
		check_field(&up, uri, ISC_UF_QUERY, testcases[i].query);
		check_field(&up, uri, ISC_UF_FRAGMENT, testcases[i].fragment);
	}
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(parse)
ISC_TEST_ENTRY(parse_rfc3986)

ISC_TEST_LIST_END

ISC_TEST_MAIN
