/*
 * Copyright (C) 2014, 2015  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

/*! \file */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/name.h>
#include <dns/fixedname.h>

#include "dnstest.h"

/*
 * Individual unit tests
 */

ATF_TC(fullcompare);
ATF_TC_HEAD(fullcompare, tc) {
	atf_tc_set_md_var(tc, "descr", "dns_name_fullcompare test");
}
ATF_TC_BODY(fullcompare, tc) {
	dns_fixedname_t fixed1;
	dns_fixedname_t fixed2;
	dns_name_t *name1;
	dns_name_t *name2;
	dns_namereln_t relation;
	int i;
	isc_result_t result;
	struct {
		const char *name1;
		const char *name2;
		dns_namereln_t relation;
		int order;
		unsigned int nlabels;
	} data[] = {
		/* relative */
		{ "", "", dns_namereln_equal, 0, 0 },
		{ "foo", "", dns_namereln_subdomain, 1, 0 },
		{ "", "foo", dns_namereln_contains, -1, 0 },
		{ "foo", "bar", dns_namereln_none, 4, 0 },
		{ "bar", "foo", dns_namereln_none, -4, 0 },
		{ "bar.foo", "foo", dns_namereln_subdomain, 1, 1 },
		{ "foo", "bar.foo", dns_namereln_contains, -1, 1 },
		{ "baz.bar.foo", "bar.foo", dns_namereln_subdomain, 1, 2 },
		{ "bar.foo", "baz.bar.foo", dns_namereln_contains, -1, 2 },
		{ "foo.example", "bar.example", dns_namereln_commonancestor,
		  4, 1 },

		/* absolute */
		{ ".", ".", dns_namereln_equal, 0, 1 },
		{ "foo.", "bar.", dns_namereln_commonancestor, 4, 1 },
		{ "bar.", "foo.", dns_namereln_commonancestor, -4, 1 },
		{ "foo.example.", "bar.example.", dns_namereln_commonancestor,
		  4, 2 },
		{ "bar.foo.", "foo.", dns_namereln_subdomain, 1, 2 },
		{ "foo.", "bar.foo.", dns_namereln_contains, -1, 2 },
		{ "baz.bar.foo.", "bar.foo.", dns_namereln_subdomain, 1, 3 },
		{ "bar.foo.", "baz.bar.foo.", dns_namereln_contains, -1, 3 },
		{ NULL, NULL, dns_namereln_none, 0, 0 }
	};

	UNUSED(tc);

	dns_fixedname_init(&fixed1);
	name1 = dns_fixedname_name(&fixed1);
	dns_fixedname_init(&fixed2);
	name2 = dns_fixedname_name(&fixed2);
	for (i = 0; data[i].name1 != NULL; i++) {
		int order = 3000;
		unsigned int nlabels = 3000;

		if (data[i].name1[0] == 0) {
			dns_fixedname_init(&fixed1);
		} else {
			result = dns_name_fromstring2(name1, data[i].name1,
						      NULL, 0, NULL);
			ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		}
		if (data[i].name2[0] == 0) {
			dns_fixedname_init(&fixed2);
		} else {
			result = dns_name_fromstring2(name2, data[i].name2,
						      NULL, 0, NULL);
			ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		}
		relation = dns_name_fullcompare(name1, name1, &order, &nlabels);
		ATF_REQUIRE_EQ(relation, dns_namereln_equal);
		ATF_REQUIRE_EQ(order, 0);
		ATF_REQUIRE_EQ(nlabels, name1->labels);

		/* Some random initializer */
		order = 3001;
		nlabels = 3001;

		relation = dns_name_fullcompare(name1, name2, &order, &nlabels);
		ATF_REQUIRE_EQ(relation, data[i].relation);
		ATF_REQUIRE_EQ(order, data[i].order);
		ATF_REQUIRE_EQ(nlabels, data[i].nlabels);
	}
}

static void
compress_test(dns_name_t *name1, dns_name_t *name2, dns_name_t *name3,
	      unsigned char *expected, unsigned int length,
	      dns_compress_t *cctx, dns_decompress_t *dctx)
{
	isc_buffer_t source;
	isc_buffer_t target;
	dns_name_t name;
	unsigned char buf1[1024];
	unsigned char buf2[1024];

	isc_buffer_init(&source, buf1, sizeof(buf1));
	isc_buffer_init(&target, buf2, sizeof(buf2));

	ATF_REQUIRE_EQ(dns_name_towire(name1, cctx, &source), ISC_R_SUCCESS);

	ATF_CHECK_EQ(dns_name_towire(name2, cctx, &source), ISC_R_SUCCESS);
	ATF_CHECK_EQ(dns_name_towire(name2, cctx, &source), ISC_R_SUCCESS);
	ATF_CHECK_EQ(dns_name_towire(name3, cctx, &source), ISC_R_SUCCESS);

	isc_buffer_setactive(&source, source.used);

	dns_name_init(&name, NULL);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, ISC_FALSE,
					&target) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, ISC_FALSE,
					&target) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, ISC_FALSE,
					&target) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, ISC_FALSE,
					&target) == ISC_R_SUCCESS);
	dns_decompress_invalidate(dctx);

	ATF_CHECK_EQ(target.used, length);
	ATF_CHECK(memcmp(target.base, expected, target.used) == 0);
}

ATF_TC(compression);
ATF_TC_HEAD(compression, tc) {
	atf_tc_set_md_var(tc, "descr", "name compression test");
}
ATF_TC_BODY(compression, tc) {
	unsigned int allowed;
	dns_compress_t cctx;
	dns_decompress_t dctx;
	dns_name_t name1;
	dns_name_t name2;
	dns_name_t name3;
	isc_region_t r;
	unsigned char plain1[] = "\003yyy\003foo";
	unsigned char plain2[] = "\003bar\003yyy\003foo";
	unsigned char plain3[] = "\003xxx\003bar\003foo";
	unsigned char plain[] = "\003yyy\003foo\0\003bar\003yyy\003foo\0\003"
				"bar\003yyy\003foo\0\003xxx\003bar\003foo";

	dns_test_begin(NULL, ISC_FALSE);

	dns_name_init(&name1, NULL);
	r.base = plain1;
	r.length = sizeof(plain1);
	dns_name_fromregion(&name1, &r);

	dns_name_init(&name2, NULL);
	r.base = plain2;
	r.length = sizeof(plain2);
	dns_name_fromregion(&name2, &r);

	dns_name_init(&name3, NULL);
	r.base = plain3;
	r.length = sizeof(plain3);
	dns_name_fromregion(&name3, &r);

	/* Test 1: NONE */
	allowed = DNS_COMPRESS_NONE;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test2: GLOBAL14 */
	allowed = DNS_COMPRESS_GLOBAL14;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test3: ALL */
	allowed = DNS_COMPRESS_ALL;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test4: NONE disabled */
	allowed = DNS_COMPRESS_NONE;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test5: GLOBAL14 disabled */
	allowed = DNS_COMPRESS_GLOBAL14;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test6: ALL disabled */
	allowed = DNS_COMPRESS_ALL;
	ATF_REQUIRE_EQ(dns_compress_init(&cctx, -1, mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain),
		      &cctx, &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, fullcompare);
	ATF_TP_ADD_TC(tp, compression);

	return (atf_no_error());
}

