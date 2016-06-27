/*
 * Copyright (C) 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
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

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/util.h>

ATF_TC(lex);
ATF_TC_HEAD(lex, tc) {
	atf_tc_set_md_var(tc, "descr", "check handling of 0xff");
}
ATF_TC_BODY(lex, tc) {
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t death_buf;
	isc_token_t token;

	unsigned char death[] = { EOF, 'A' };

	UNUSED(tc);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = isc_lex_create(mctx, 1024, &lex);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_buffer_init(&death_buf, &death[0], sizeof(death));
	isc_buffer_add(&death_buf, sizeof(death));

	result = isc_lex_openbuffer(lex, &death_buf);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = isc_lex_gettoken(lex, 0, &token);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, lex);
	return (atf_no_error());
}

