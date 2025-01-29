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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/list.h>

#include <dns/ede.h>

#include "../../lib/dns/ede.c"

#include <tests/isc.h>

const struct {
	uint16_t info_code;
	char *extra_text;
} vectors[DNS_EDE_MAX_ERRORS] = {
	{
		22,
		NULL,
	},
	{
		12,
		(char *)"abcd",
	},
	{
		4,
		(char *)"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"
			"dabcdabcdadcdabcd",
	},
};

ISC_RUN_TEST_IMPL(dns_edectx) {
	dns_edectx_t edectx = { 0 };
	size_t pos = 0;
	uint16_t becode;
	uint8_t buf[sizeof(becode) + DNS_EDE_EXTRATEXT_LEN];

	dns_ede_init(mctx, &edectx);

	for (size_t i = 0; i < DNS_EDE_MAX_ERRORS; i++) {
		dns_ede_add(&edectx, vectors[i].info_code,
			    vectors[i].extra_text);
	}

	for (size_t i = 0; pos < DNS_EDE_MAX_ERRORS; pos++) {
		dns_ednsopt_t *edns = edectx.ede[i];
		size_t textlen = 0;

		becode = htobe16(vectors[i].info_code);
		memmove(buf, &becode, sizeof(becode));
		if (vectors[i].extra_text != NULL) {
			textlen = strlen(vectors[i].extra_text);
			memcpy(edns->value + sizeof(becode),
			       vectors[i].extra_text, textlen);
		}

		assert_memory_equal(buf, edectx.ede[i]->value,
				    sizeof(becode) + textlen);
	}

	dns_ede_reset(&edectx);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(dns_edectx)

ISC_TEST_LIST_END

ISC_TEST_MAIN
