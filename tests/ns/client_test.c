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
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/net.h>
#include <isc/timer.h>
#include <isc/tls.h>
#include <isc/util.h>

#include <ns/client.h>

#include <tests/isc.h>

typedef struct {
	uint16_t code;
	const char *txt;
} client_tests_ede_expected_t;

static ns_clientmgr_t client_ede_test_dummy_manager;

static ns_client_t *
client_ede_test_initclient(void) {
	client_ede_test_dummy_manager.mctx = mctx;

	ns_client_t *client = isc_mem_get(mctx, sizeof(*client));
	memset(client, 0, sizeof(*client));
	client->magic = NS_CLIENT_MAGIC;
	client->manager = &client_ede_test_dummy_manager;

	return client;
}

static void
client_ede_test_free(ns_client_t *client) {
	for (size_t i = 0; i < DNS_EDE_MAX_ERRORS; i++) {
		dns_ednsopt_t *ede = client->ede[i];

		if (ede) {
			isc_mem_put(mctx, ede->value, ede->length);
			isc_mem_put(mctx, ede, sizeof(*ede));
		}
		client->ede[i] = NULL;
	}
	isc_mem_put(mctx, client, sizeof(*client));
}

static void
client_ede_test_equals(const client_tests_ede_expected_t *expected,
		       size_t expected_count, const ns_client_t *client) {
	size_t count = 0;

	for (size_t i = 0; i < DNS_EDE_MAX_ERRORS; i++) {
		dns_ednsopt_t *edns = client->ede[i];

		if (edns == NULL) {
			break;
		}

		uint16_t code;
		const size_t codelen = sizeof(code);
		const unsigned char *txt;

		assert_in_range(count, 0, expected_count);
		assert_int_equal(edns->code, DNS_OPT_EDE);

		code = ISC_U8TO16_BE(edns->value);
		assert_int_equal(code, expected[count].code);

		if (edns->length > codelen) {
			assert_non_null(expected[count].txt);
			txt = edns->value + codelen;
			assert_memory_equal(expected[count].txt, txt,
					    edns->length - codelen);
		} else {
			assert_null(expected[count].txt);
		}

		count++;
	}
	assert_int_equal(count, expected_count);
}

ISC_RUN_TEST_IMPL(client_ede_test_text_max_count) {
	ns_client_t *client = client_ede_test_initclient();

	const char *txt1 = "foobar";
	const char *txt2 = "It's been a long time since I rock-and-rolled"
			   "Ooh, let me get it back, let me get it back";

	ns_client_extendederror(client, 2, txt1);
	ns_client_extendederror(client, 22, NULL);
	ns_client_extendederror(client, 3, txt2);

	const client_tests_ede_expected_t expected[3] = {
		{ .code = 2, .txt = "foobar" },
		{ .code = 22, .txt = NULL },
		{ .code = 3,
		  .txt = "It's been a long time since I rock-and-rolledOoh, "
			 "let me get it " }
	};

	client_ede_test_equals(expected, 3, client);
	client_ede_test_free(client);
}

ISC_RUN_TEST_IMPL(client_ede_test_max_count) {
	ns_client_t *client = client_ede_test_initclient();

	ns_client_extendederror(client, 1, NULL);
	ns_client_extendederror(client, 22, "two");
	ns_client_extendederror(client, 3, "three");
	ns_client_extendederror(client, 4, "four");
	ns_client_extendederror(client, 5, "five");

	const client_tests_ede_expected_t expected[3] = {
		{ .code = 1, .txt = NULL },
		{ .code = 22, .txt = "two" },
		{ .code = 3, .txt = "three" },
	};

	client_ede_test_equals(expected, 3, client);
	client_ede_test_free(client);
}

ISC_RUN_TEST_IMPL(client_ede_test_duplicates) {
	ns_client_t *client = client_ede_test_initclient();

	ns_client_extendederror(client, 1, NULL);
	ns_client_extendederror(client, 1, "two");
	ns_client_extendederror(client, 1, "three");

	const client_tests_ede_expected_t expected[] = {
		{ .code = 1, .txt = NULL },
	};

	client_ede_test_equals(expected, 1, client);

	client_ede_test_free(client);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(client_ede_test_text_max_count)
ISC_TEST_ENTRY(client_ede_test_max_count)
ISC_TEST_ENTRY(client_ede_test_duplicates)

ISC_TEST_LIST_END

ISC_TEST_MAIN
