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

#include <config.h>

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/print.h>

#include "../lwconfig.c"

#define UNIT_TESTING
#include <cmocka.h>

static void
setup_test() {
	/*
	 * The caller might run from another directory, so tests
	 * that access test data files must first chdir to the proper
	 * location.
	 */
	assert_int_not_equal(chdir(TESTS), -1);
}

/* lwres_conf_parse link-local nameserver */
static void
parse_linklocal(void **state) {
	lwres_result_t result;
	lwres_context_t *ctx = NULL;
	unsigned char addr[16] = { 0xfe, 0x80, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x01 };

	UNUSED(state);

	setup_test();

	lwres_context_create(&ctx, NULL, NULL, NULL,
			     LWRES_CONTEXT_USEIPV4 | LWRES_CONTEXT_USEIPV6);
	assert_int_equal(ctx->confdata.nsnext, 0);
	assert_int_equal(ctx->confdata.nameservers[0].zone, 0);

	result = lwres_conf_parse(ctx, "testdata/link-local.conf");
	assert_int_equal(result, LWRES_R_SUCCESS);
	assert_int_equal(ctx->confdata.nsnext, 1);
	assert_int_equal(ctx->confdata.nameservers[0].zone, 1);
	assert_memory_equal(ctx->confdata.nameservers[0].address, addr, 16);
	lwres_context_destroy(&ctx);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(parse_linklocal),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif
