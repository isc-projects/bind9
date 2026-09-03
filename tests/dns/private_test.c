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
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>
#include <dns/nsec3.h>
#include <dns/private.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>

#include <dst/dst.h>

#include <tests/dns.h>

static dns_rdatatype_t privatetype = 65534;

typedef struct {
	dst_algorithm_t alg;
	dns_keytag_t keyid;
	bool remove;
	bool complete;
	const char *result;
} signing_testcase_t;

typedef struct {
	unsigned char hash;
	unsigned char flags;
	unsigned int iterations;
	unsigned long salt;
	bool remove;
	bool pending;
	bool nonsec;
	const char *result;
} nsec3_testcase_t;

static void
make_private(dns_rdata_t *private, unsigned char *buf, size_t len) {
	dns_rdata_init(private);

	private->data = buf;
	private->length = len;
	private->type = privatetype;
	private->rdclass = dns_rdataclass_in;
}

static void
make_signing(signing_testcase_t *testcase, dns_rdata_t *private,
	     unsigned char *buf, size_t len) {
	buf[0] = dst_algorithm_tosecalg(testcase->alg);
	buf[1] = (testcase->keyid & 0xff00) >> 8;
	buf[2] = (testcase->keyid & 0xff);
	buf[3] = testcase->remove;
	buf[4] = testcase->complete;
	if (len >= 7) {
		buf[5] = (testcase->alg & 0xff00) >> 8;
		buf[6] = testcase->alg & 0xff;
	}
	make_private(private, buf, len);
}

static void
make_nsec3(nsec3_testcase_t *testcase, dns_rdata_t *private,
	   unsigned char *pbuf, size_t pbufsize) {
	isc_result_t result;
	dns_rdata_nsec3param_t params;
	dns_rdata_t nsec3param = DNS_RDATA_INIT;
	unsigned char bufdata[BUFSIZ];
	isc_buffer_t buf;
	uint32_t salt;
	unsigned char *sp;
	int slen = 4;

	/* for simplicity, we're using a maximum salt length of 4 */
	salt = htonl(testcase->salt);
	sp = (unsigned char *)&salt;
	while (slen > 0 && *sp == '\0') {
		slen--;
		sp++;
	}

	params.common.rdclass = dns_rdataclass_in;
	params.common.rdtype = dns_rdatatype_nsec3param;
	params.hash = testcase->hash;
	params.iterations = testcase->iterations;
	params.salt = (isc_region_t){ .base = sp, .length = slen };

	params.flags = testcase->flags;
	if (testcase->remove) {
		params.flags |= DNS_NSEC3FLAG_REMOVE;
		if (testcase->nonsec) {
			params.flags |= DNS_NSEC3FLAG_NONSEC;
		}
	} else {
		params.flags |= DNS_NSEC3FLAG_CREATE;
		if (testcase->pending) {
			params.flags |= DNS_NSEC3FLAG_INITIAL;
		}
	}

	isc_buffer_init(&buf, bufdata, sizeof(bufdata));
	result = dns_rdata_fromstruct(&nsec3param, dns_rdataclass_in,
				      dns_rdatatype_nsec3param, &params, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_rdata_init(private);

	dns_nsec3param_toprivate(&nsec3param, private, privatetype, pbuf,
				 pbufsize);
}

/* convert private signing records to text */
ISC_RUN_TEST_IMPL(private_signing_totext) {
	dns_rdata_t private;
	size_t i;

	signing_testcase_t testcases[] = {
		{ DST_ALG_RSASHA512, 12345, 0, 0,
		  "Signing with key 12345/RSASHA512" },
		{ DST_ALG_RSASHA256, 54321, 1, 0,
		  "Removing signatures for key 54321/RSASHA256" },
		{ DST_ALG_NSEC3RSASHA1, 22222, 0, 1,
		  "Done signing with key 22222/NSEC3RSASHA1" },
		{ DST_ALG_RSASHA1, 33333, 1, 1,
		  "Done removing signatures for key 33333/RSASHA1" },
		{ DST_ALG_RSASHA256PRIVATEOID, 4444, 0, 0,
		  "Signing with key 4444/RSASHA256OID" }
	};
	UNUSED(state);

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		unsigned char data[7];
		char output[BUFSIZ];
		isc_buffer_t buf;
		isc_result_t result;

		if (testcases[i].alg <= 255) {
			memset(output, 0, sizeof(output));
			isc_buffer_init(&buf, output, sizeof(output));
			make_signing(&testcases[i], &private, data, 5);
			result = dns_private_totext(&private, &buf);
			assert_int_equal(result, ISC_R_SUCCESS);
			assert_string_equal(output, testcases[i].result);
		}

		memset(output, 0, sizeof(output));
		isc_buffer_init(&buf, output, sizeof(output));
		make_signing(&testcases[i], &private, data, 7);
		result = dns_private_totext(&private, &buf);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_string_equal(output, testcases[i].result);
	}
}

/* convert private chain records to text */
ISC_RUN_TEST_IMPL(private_nsec3_totext) {
	dns_rdata_t private;
	size_t i;

	nsec3_testcase_t testcases[] = {
		{ 1, 0, 1, 0xbeef, 0, 0, 0, "Creating NSEC3 chain 1 0 1 BEEF" },
		{ 1, 1, 10, 0xdadd, 0, 0, 0,
		  "Creating NSEC3 chain 1 1 10 DADD" },
		{ 1, 0, 20, 0xbead, 0, 1, 0,
		  "Pending NSEC3 chain 1 0 20 BEAD" },
		{ 1, 0, 30, 0xdeaf, 1, 0, 0,
		  "Removing NSEC3 chain 1 0 30 DEAF / creating NSEC chain" },
		{ 1, 0, 100, 0xfeedabee, 1, 0, 1,
		  "Removing NSEC3 chain 1 0 100 FEEDABEE" },
	};
	UNUSED(state);

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		unsigned char data[DNS_PRIVATE_BUFFERSIZE];
		char output[BUFSIZ];
		isc_buffer_t buf;
		isc_result_t result;

		memset(output, 0, sizeof(output));
		isc_buffer_init(&buf, output, sizeof(output));

		make_nsec3(&testcases[i], &private, data, sizeof(data));
		result = dns_private_totext(&private, &buf);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_string_equal(output, testcases[i].result);
	}
}

/*
 * Run dns_private_chains() over a zone database whose apex holds the
 * given private-type records (and no NSEC/NSEC3PARAM RRsets) and check
 * the reported chain-building requirements.
 */
static void
check_private_chains(dns_rdata_t *privates, size_t nprivates,
		     bool expected_nsec, bool expected_nsec3) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_dbversion_t *ver = NULL;
	bool build_nsec = !expected_nsec;
	bool build_nsec3 = !expected_nsec3;

	result = dns_db_create(isc_g_mctx, ZONEDB_DEFAULT, dns_rootname,
			       dns_dbtype_zone, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_db_newversion(db, &ver);
	assert_non_null(ver);

	if (nprivates > 0) {
		dns_dbnode_t *node = NULL;
		dns_rdatalist_t rdatalist;
		dns_rdataset_t rdataset;

		dns_rdatalist_init(&rdatalist);
		rdatalist.rdclass = dns_rdataclass_in;
		rdatalist.type = privatetype;
		for (size_t i = 0; i < nprivates; i++) {
			ISC_LIST_APPEND(rdatalist.rdata, &privates[i], link);
		}
		dns_rdataset_init(&rdataset);
		dns_rdatalist_tordataset(&rdatalist, &rdataset);

		result = dns_db_getoriginnode(db, &node);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_db_addrdataset(db, node, ver, 0, &rdataset, 0,
					    NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_rdataset_disassociate(&rdataset);
		dns_db_detachnode(&node);
	}

	result = dns_private_chains(db, ver, privatetype, &build_nsec,
				    &build_nsec3);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(build_nsec, expected_nsec);
	assert_int_equal(build_nsec3, expected_nsec3);

	dns_db_closeversion(db, &ver, false);
	dns_db_detach(&db);
}

/* detect chain building requirements from private signing records */
ISC_RUN_TEST_IMPL(private_chains) {
	UNUSED(state);

	/* No private RRset at the apex. */
	check_private_chains(NULL, 0, false, false);

	{
		/* Old form signing record, signing in progress. */
		signing_testcase_t testcase = { DST_ALG_RSASHA256, 12345, 0,
						0 };
		unsigned char data[5];
		dns_rdata_t private;

		make_signing(&testcase, &private, data, sizeof(data));
		check_private_chains(&private, 1, true, false);
	}

	{
		/* New form signing record for a PRIVATEOID algorithm. */
		unsigned char data[7] = { DNS_KEYALG_PRIVATEOID,
					  0x30,
					  0x39,
					  0,
					  0,
					  DST_ALG_RSASHA256PRIVATEOID >> 8,
					  DST_ALG_RSASHA256PRIVATEOID & 0xff };
		dns_rdata_t private;

		make_private(&private, data, sizeof(data));
		check_private_chains(&private, 1, true, false);
	}

	{
		/*
		 * New form record whose DNSSEC algorithm octet doesn't
		 * match its DST algorithm.
		 */
		unsigned char data[7] = { DNS_KEYALG_PRIVATEDNS,
					  0x30,
					  0x39,
					  0,
					  0,
					  DST_ALG_RSASHA256PRIVATEOID >> 8,
					  DST_ALG_RSASHA256PRIVATEOID & 0xff };
		dns_rdata_t private;

		make_private(&private, data, sizeof(data));
		check_private_chains(&private, 1, false, false);
	}

	{
		/* New form signing record, signing already complete. */
		unsigned char data[7] = { DNS_KEYALG_PRIVATEOID,
					  0x30,
					  0x39,
					  0,
					  1,
					  DST_ALG_RSASHA256PRIVATEOID >> 8,
					  DST_ALG_RSASHA256PRIVATEOID & 0xff };
		dns_rdata_t private;

		make_private(&private, data, sizeof(data));
		check_private_chains(&private, 1, false, false);
	}

	{
		/* New form signing record plus NSEC3 chain creation. */
		unsigned char sbuf[7] = { DNS_KEYALG_PRIVATEOID,
					  0x30,
					  0x39,
					  0,
					  0,
					  DST_ALG_RSASHA256PRIVATEOID >> 8,
					  DST_ALG_RSASHA256PRIVATEOID & 0xff };
		unsigned char nbuf[DNS_PRIVATE_BUFFERSIZE];
		nsec3_testcase_t nsec3case = { 1, 0, 10, 0xbeef, 0, 0, 0 };
		dns_rdata_t privates[2];

		make_private(&privates[0], sbuf, sizeof(sbuf));
		make_nsec3(&nsec3case, &privates[1], nbuf, sizeof(nbuf));
		check_private_chains(privates, 2, false, true);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(private_signing_totext)
ISC_TEST_ENTRY(private_nsec3_totext)
ISC_TEST_ENTRY(private_chains)
ISC_TEST_LIST_END

ISC_TEST_MAIN
