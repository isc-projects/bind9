/*
 * Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lwconfig.c"

static void
setup_test() {
	/*
	 * atf-run changes us to a /tmp directory, so tests
	 * that access test data files must first chdir to the proper
	 * location.
	 */
	ATF_CHECK(chdir(TESTS) != -1);
}

ATF_TC(parse_linklocal);
ATF_TC_HEAD(parse_linklocal, tc) {
	atf_tc_set_md_var(tc, "descr", "lwres_conf_parse link-local nameserver");
}
ATF_TC_BODY(parse_linklocal, tc) {
	lwres_result_t result;
	lwres_context_t *ctx = NULL;
	unsigned char addr[16] = { 0xfe, 0x80, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x01 };

	UNUSED(tc);

	setup_test();

	lwres_context_create(&ctx, NULL, NULL, NULL,
			     LWRES_CONTEXT_USEIPV4 | LWRES_CONTEXT_USEIPV6);
	ATF_CHECK_EQ(ctx->confdata.nsnext, 0);
	ATF_CHECK_EQ(ctx->confdata.nameservers[0].zone, 0);

	result = lwres_conf_parse(ctx, "testdata/link-local.conf");
	ATF_CHECK_EQ(result, LWRES_R_SUCCESS);
	ATF_CHECK_EQ(ctx->confdata.nsnext, 1);
	ATF_CHECK_EQ(ctx->confdata.nameservers[0].zone, 1);
	ATF_CHECK_EQ(memcmp(ctx->confdata.nameservers[0].address, addr, 16), 0);
	lwres_context_destroy(&ctx);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, parse_linklocal);
	return (atf_no_error());
}
