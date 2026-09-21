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

/* Include OpenSSL before cmocka redefines the allocator names. */
#include <openssl/err.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/tsig.h>

#include "dst_internal.h"
#include "tsig_p.h"

#include <tests/dns.h>

#define TEST_ORIGIN "test"

static isc_result_t
add_mac(dst_context_t *tsigctx, isc_buffer_t *buf) {
	dns_rdata_any_tsig_t tsig;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_buffer_t databuf;
	isc_region_t r;
	isc_result_t result;
	unsigned char tsigbuf[1024];

	isc_buffer_usedregion(buf, &r);
	dns_rdata_fromregion(&rdata, dns_rdataclass_any, dns_rdatatype_tsig,
			     &r);
	isc_buffer_init(&databuf, tsigbuf, sizeof(tsigbuf));
	CHECK(dns_rdata_tostruct(&rdata, &tsig, NULL));
	isc_buffer_putuint16(&databuf, tsig.siglen);
	isc_buffer_putmem(&databuf, tsig.signature, tsig.siglen);
	isc_buffer_usedregion(&databuf, &r);
	result = dst_context_adddata(tsigctx, &r);
	dns_rdata_freestruct(&tsig);
cleanup:
	return result;
}

static isc_result_t
add_tsig(dst_context_t *tsigctx, dns_tsigkey_t *key, isc_buffer_t *target,
	 isc_stdtime_t now, bool mangle_sig) {
	dns_compress_t cctx;
	dns_rdata_any_tsig_t tsig;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_buffer_t *dynbuf = NULL;
	isc_buffer_t databuf;
	isc_buffer_t sigbuf;
	isc_region_t r;
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char tsigbuf[1024];
	unsigned int count;
	unsigned int sigsize = 0;

	memset(&tsig, 0, sizeof(tsig));

	dns_compress_init(&cctx, isc_g_mctx, 0);

	tsig.common.rdclass = dns_rdataclass_any;
	tsig.common.rdtype = dns_rdatatype_tsig;
	dns_name_init(&tsig.algorithm);
	dns_name_clone(dns_tsigkey_algorithm(key), &tsig.algorithm);

	tsig.timesigned = now;
	tsig.fudge = DNS_TSIG_FUDGE;
	tsig.originalid = 50;
	tsig.error = dns_rcode_noerror;
	tsig.otherlen = 0;
	tsig.other = NULL;

	isc_buffer_init(&databuf, tsigbuf, sizeof(tsigbuf));
	isc_buffer_putuint48(&databuf, tsig.timesigned);
	isc_buffer_putuint16(&databuf, tsig.fudge);
	isc_buffer_usedregion(&databuf, &r);
	CHECK(dst_context_adddata(tsigctx, &r));

	CHECK(dst_key_sigsize(key->key, &sigsize));
	tsig.signature = isc_mem_get(isc_g_mctx, sigsize);
	isc_buffer_init(&sigbuf, tsig.signature, sigsize);
	CHECK(dst_context_sign(tsigctx, &sigbuf));
	tsig.siglen = isc_buffer_usedlength(&sigbuf);
	assert_int_equal(sigsize, tsig.siglen);
	if (mangle_sig) {
		isc_random_buf(tsig.signature, tsig.siglen);
	}

	isc_buffer_allocate(isc_g_mctx, &dynbuf, 512);
	CHECK(dns_rdata_fromstruct(&rdata, dns_rdataclass_any,
				   dns_rdatatype_tsig, &tsig, dynbuf));
	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_any;
	rdatalist.type = dns_rdatatype_tsig;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);
	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);
	CHECK(dns_rdataset_towire(&rdataset, key->name, 0, &cctx, target, false,
				  0, &count));

	/*
	 * Fixup additional record count.
	 */
	((unsigned char *)target->base)[11]++;
	if (((unsigned char *)target->base)[11] == 0) {
		((unsigned char *)target->base)[10]++;
	}
cleanup:
	if (tsig.signature != NULL) {
		isc_mem_put(isc_g_mctx, tsig.signature, sigsize);
	}
	if (dynbuf != NULL) {
		isc_buffer_free(&dynbuf);
	}
	dns_compress_invalidate(&cctx);

	return result;
}

static void
printmessage(dns_message_t *msg) {
	isc_buffer_t b;
	char *buf = NULL;
	int len = 1024;
	isc_result_t result = ISC_R_SUCCESS;

	if (!debug) {
		return;
	}

	do {
		buf = isc_mem_get(isc_g_mctx, len);

		isc_buffer_init(&b, buf, len);
		result = dns_message_totext(msg, &dns_master_style_debug, 0,
					    &b);
		if (result == ISC_R_NOSPACE) {
			isc_mem_put(isc_g_mctx, buf, len);
			len *= 2;
		} else if (result == ISC_R_SUCCESS) {
			printf("%.*s\n", (int)isc_buffer_usedlength(&b), buf);
		}
	} while (result == ISC_R_NOSPACE);

	if (buf != NULL) {
		isc_mem_put(isc_g_mctx, buf, len);
	}
}

static void
render(isc_buffer_t *buf, unsigned int flags, dns_tsigkey_t *key,
       isc_buffer_t **tsigin, isc_buffer_t **tsigout, dst_context_t *tsigctx) {
	dns_message_t *msg = NULL;
	dns_compress_t cctx;
	isc_result_t result;

	dns_message_create(isc_g_mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER,
			   &msg);
	assert_non_null(msg);

	msg->id = 50;
	msg->rcode = dns_rcode_noerror;
	msg->flags = flags;

	/*
	 * XXXMPA: this hack needs to be replaced with use of
	 * dns_message_reply() at some point.
	 */
	if ((flags & DNS_MESSAGEFLAG_QR) != 0) {
		msg->verified_sig = 1;
	}

	if (tsigin == tsigout) {
		msg->tcp_continuation = 1;
	}

	if (tsigctx == NULL) {
		result = dns_message_settsigkey(msg, key);
		assert_int_equal(result, ISC_R_SUCCESS);

		dns_message_setquerytsig(msg, *tsigin);
	}

	dns_compress_init(&cctx, isc_g_mctx, 0);

	result = dns_message_renderbegin(msg, &cctx, buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_message_renderend(msg);
	assert_int_equal(result, ISC_R_SUCCESS);

	if (tsigctx != NULL) {
		isc_region_t r;

		isc_buffer_usedregion(buf, &r);
		result = dst_context_adddata(tsigctx, &r);
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		if (tsigin == tsigout && *tsigin != NULL) {
			isc_buffer_free(tsigin);
		}

		result = dns_message_getquerytsig(msg, isc_g_mctx, tsigout);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	dns_compress_invalidate(&cctx);
	dns_message_detach(&msg);
}

static void
tsig_tcp(isc_stdtime_t now, isc_result_t expected_result, bool mangle_sig) {
	const dns_name_t *tsigowner = NULL;
	dns_fixedname_t fkeyname;
	dns_message_t *msg = NULL;
	dns_name_t *keyname;
	dns_tsigkeyring_t *ring = NULL;
	dns_tsigkey_t *key = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t *querytsig = NULL;
	isc_buffer_t *tsigin = NULL;
	isc_buffer_t *tsigout = NULL;
	isc_result_t result;
	unsigned char secret[16] = { 0 };
	dst_context_t *tsigctx = NULL;
	dst_context_t *outctx = NULL;

	/* isc_log_setdebuglevel(lctx, 99); */

	keyname = dns_fixedname_initname(&fkeyname);
	result = dns_name_fromstring(keyname, "test", dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_tsigkeyring_create(isc_g_mctx, &ring);
	assert_non_null(ring);

	result = dns_tsigkey_create(keyname, DST_ALG_HMACSHA256, secret,
				    sizeof(secret), isc_g_mctx, &key);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_tsigkeyring_add(ring, key);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(key);

	/*
	 * Create request.
	 */
	isc_buffer_allocate(isc_g_mctx, &buf, 65535);
	render(buf, 0, key, &tsigout, &querytsig, NULL);
	isc_buffer_free(&buf);

	/*
	 * Create response message 1.
	 */
	isc_buffer_allocate(isc_g_mctx, &buf, 65535);
	render(buf, DNS_MESSAGEFLAG_QR, key, &querytsig, &tsigout, NULL);
	assert_non_null(tsigout);

	/*
	 * Process response message 1.
	 */
	dns_message_create(isc_g_mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE,
			   &msg);
	assert_non_null(msg);

	result = dns_message_settsigkey(msg, key);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_message_parse(msg, buf, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	printmessage(msg);

	dns_message_setquerytsig(msg, querytsig);

	result = dns_tsig_verify(buf, msg, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(msg->verified_sig, 1);
	assert_int_equal(msg->tsigstatus, dns_rcode_noerror);

	/*
	 * Check that we have a TSIG in the first message.
	 */
	assert_non_null(dns_message_gettsig(msg, &tsigowner));

	result = dns_message_getquerytsig(msg, isc_g_mctx, &tsigin);
	assert_int_equal(result, ISC_R_SUCCESS);

	tsigctx = msg->tsigctx;
	msg->tsigctx = NULL;
	isc_buffer_free(&buf);
	dns_message_detach(&msg);

	result = dst_context_create(key->key, isc_g_mctx,
				    DNS_LOGCATEGORY_DNSSEC, false, &outctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(outctx);

	/*
	 * Start digesting.
	 */
	result = add_mac(outctx, tsigout);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Create response message 2.
	 */
	isc_buffer_allocate(isc_g_mctx, &buf, 65535);

	assert_int_equal(result, ISC_R_SUCCESS);
	render(buf, DNS_MESSAGEFLAG_QR, key, &tsigout, &tsigout, outctx);

	/*
	 * Process response message 2.
	 */
	dns_message_create(isc_g_mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE,
			   &msg);
	assert_non_null(msg);

	msg->tcp_continuation = 1;
	msg->tsigctx = tsigctx;
	tsigctx = NULL;

	result = dns_message_settsigkey(msg, key);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_message_parse(msg, buf, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	printmessage(msg);

	dns_message_setquerytsig(msg, tsigin);

	result = dns_tsig_verify(buf, msg, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(msg->verified_sig, 0);
	assert_int_equal(msg->tsigstatus, dns_rcode_noerror);

	/*
	 * Check that we don't have a TSIG in the second message.
	 */
	tsigowner = NULL;
	assert_true(dns_message_gettsig(msg, &tsigowner) == NULL);

	tsigctx = msg->tsigctx;
	msg->tsigctx = NULL;
	isc_buffer_free(&buf);
	dns_message_detach(&msg);

	/*
	 * Create response message 3.
	 */
	isc_buffer_allocate(isc_g_mctx, &buf, 65535);
	render(buf, DNS_MESSAGEFLAG_QR, key, &tsigout, &tsigout, outctx);

	result = add_tsig(outctx, key, buf, now, mangle_sig);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Process response message 3.
	 */
	dns_message_create(isc_g_mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE,
			   &msg);
	assert_non_null(msg);

	msg->tcp_continuation = 1;
	msg->tsigctx = tsigctx;
	tsigctx = NULL;

	result = dns_message_settsigkey(msg, key);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_message_parse(msg, buf, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	printmessage(msg);

	/*
	 * Check that we had a TSIG in the third message.
	 */
	assert_non_null(dns_message_gettsig(msg, &tsigowner));

	dns_message_setquerytsig(msg, tsigin);

	result = dns_tsig_verify(buf, msg, NULL, NULL);
	switch (expected_result) {
	case ISC_R_SUCCESS:
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(msg->verified_sig, 1);
		assert_int_equal(msg->tsigstatus, dns_rcode_noerror);
		break;
	case DNS_R_CLOCKSKEW:
		assert_int_equal(result, DNS_R_CLOCKSKEW);
		assert_int_equal(msg->verified_sig, 1);
		assert_int_equal(msg->tsigstatus, dns_tsigerror_badtime);
		break;
	case DNS_R_TSIGVERIFYFAILURE:
		assert_int_equal(result, DNS_R_TSIGVERIFYFAILURE);
		assert_int_equal(msg->verified_sig, 0);
		assert_int_equal(msg->tsigstatus, dns_tsigerror_badsig);
		break;
	default:
		if (debug) {
			fprintf(stderr, "# result = %s\n",
				isc_result_totext(result));
		}
		UNREACHABLE();
	}

	if (tsigin != NULL) {
		isc_buffer_free(&tsigin);
	}

	result = dns_message_getquerytsig(msg, isc_g_mctx, &tsigin);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_free(&buf);
	dns_message_detach(&msg);

	if (outctx != NULL) {
		dst_context_destroy(&outctx);
	}
	if (querytsig != NULL) {
		isc_buffer_free(&querytsig);
	}
	if (tsigin != NULL) {
		isc_buffer_free(&tsigin);
	}
	if (tsigout != NULL) {
		isc_buffer_free(&tsigout);
	}
	dns_tsigkey_detach(&key);
	if (ring != NULL) {
		dns_tsigkeyring_detach(&ring);
	}
}

/*
 * Test tsig tcp-continuation validation:
 * Check that a simulated three message TCP sequence where the first
 * and last messages contain TSIGs but the intermediate message doesn't
 * correctly verifies.
 */
ISC_RUN_TEST_IMPL(tsig_tcp) {
	/* Run with correct current time */
	tsig_tcp(isc_stdtime_now(), ISC_R_SUCCESS, false);
}

ISC_RUN_TEST_IMPL(tsig_badtime) {
	/* Run with time outside of the fudge */
	tsig_tcp(isc_stdtime_now() - 2 * DNS_TSIG_FUDGE, DNS_R_CLOCKSKEW,
		 false);
	tsig_tcp(isc_stdtime_now() + 2 * DNS_TSIG_FUDGE, DNS_R_CLOCKSKEW,
		 false);
}

ISC_RUN_TEST_IMPL(tsig_badsig) {
	tsig_tcp(isc_stdtime_now(), DNS_R_TSIGVERIFYFAILURE, true);
}

/*
 * dns_tsigkey_delete() must be idempotent: a second call on a key
 * that has already been removed from the keyring is a no-op and must
 * not touch the key's refcount.
 */
static void
tsig_delete(bool generated) {
	dns_fixedname_t fkeyname;
	dns_name_t *keyname = dns_fixedname_initname(&fkeyname);

	isc_result_t result = dns_name_fromstring(keyname, "tsig-key",
						  dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_tsigkeyring_t *ring = NULL;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	assert_non_null(ring);

	dns_tsigkey_t *key = NULL;
	result = dns_tsigkey_createfromkey(keyname, DST_ALG_HMACSHA256, NULL,
					   generated, false, NULL, 0, 0,
					   isc_g_mctx, &key);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_tsigkeyring_add(ring, key);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_tsigkey_delete(ring, key);
	dns_tsigkey_delete(ring, key);

	dns_tsigkey_detach(&key);
	dns_tsigkeyring_detach(&ring);
}

ISC_RUN_TEST_IMPL(tsig_delete) {
	tsig_delete(false);
	tsig_delete(true);
}

ISC_RUN_TEST_IMPL(tsig_maxkeys) {
	dns_fixedname_t fkeyname;
	dns_name_t *keyname = dns_fixedname_initname(&fkeyname);
	dns_tsigkeyring_t *ring = NULL;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	assert_non_null(ring);

	/*
	 * Insert more than the the maximum allowed generated keys. When full,
	 * the last created key should be findable, i.e. not evicted.
	 */
	for (size_t i = 0; i < DNS_TSIG_MAXGENERATEDKEYS + 1; i++) {
		char str[32];
		isc_result_t result;

		snprintf(str, sizeof(str), "tsig-key-%zu", i);
		result = dns_name_fromstring(keyname, str, dns_rootname, 0,
					     NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		/* Add a new key. */
		dns_tsigkey_t *key = NULL;
		result = dns_tsigkey_createfromkey(keyname, DST_ALG_HMACSHA256,
						   NULL, true, false, NULL, 0,
						   0, isc_g_mctx, &key);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_tsigkeyring_add(ring, key);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_tsigkey_detach(&key);

		/* Find the newly created key. */
		result = dns_tsigkey_find(&key, keyname, NULL, ring);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_tsigkey_detach(&key);
	}

	dns_tsigkeyring_detach(&ring);
}

/*
 * dns_tsigkeyring_dump() can only write a key whose DST provider
 * implements dump(), which in practice means GSS-TSIG.  Stand in for the
 * provider with a copy of the HMAC function table so that the dump paths
 * can be exercised without a Kerberos session.
 */
#define MOCK_KEYDATA   "dGVzdA=="
#define TEST_INCEPTION 4242
#define TEST_CREATOR   "creator.example"

static dst_func_t dump_funcs;
static isc_result_t dump_result;

static isc_result_t
mock_dump(dst_key_t *key, isc_mem_t *mctx, char **buffer, int *length) {
	UNUSED(key);

	if (dump_result != ISC_R_SUCCESS) {
		return dump_result;
	}

	*length = sizeof(MOCK_KEYDATA) - 1;
	*buffer = isc_mem_get(mctx, *length);
	memmove(*buffer, MOCK_KEYDATA, *length);

	return ISC_R_SUCCESS;
}

/*
 * Add a key to 'ring'.  Only a generated, unexpired key with a working
 * provider dump() is eligible to be written out.
 */
static void
add_key(dns_tsigkeyring_t *ring, const char *namestr, bool generated,
	isc_stdtime_t expire, bool dumpable) {
	unsigned char secret[] = "a test secret";
	dns_fixedname_t fname, fcreator;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_name_t *creator = dns_fixedname_initname(&fcreator);
	dns_tsigkey_t *tkey = NULL, *tmp = NULL;
	isc_result_t result;

	result = dns_name_fromstring(name, namestr, dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_name_fromstring(creator, TEST_CREATOR, dns_rootname, 0,
				     NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* dns_tsigkey_create() derives the DST key from the secret. */
	result = dns_tsigkey_create(name, DST_ALG_HMACSHA256, secret,
				    sizeof(secret), isc_g_mctx, &tmp);
	assert_int_equal(result, ISC_R_SUCCESS);

	if (dumpable) {
		dump_funcs = *tmp->key->func;
		dump_funcs.dump = mock_dump;
		tmp->key->func = &dump_funcs;
	}

	result = dns_tsigkey_createfromkey(
		name, DST_ALG_HMACSHA256, tmp->key, generated, false, creator,
		TEST_INCEPTION, expire, isc_g_mctx, &tkey);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_tsigkey_detach(&tmp);

	result = dns_tsigkeyring_add(ring, tkey);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_tsigkey_detach(&tkey);
}

#define TEST_KEYFILE BUILDDIR "/tsigkeys.test"

static void
remove_keyfile(void) {
	(void)unlink(TEST_KEYFILE);
}

static bool
keyfile_exists(void) {
	return access(TEST_KEYFILE, F_OK) == 0;
}

/*
 * Parse the dumped key file, returning the number of keys it holds.  The
 * out parameters describe the last key read.
 */
static unsigned int
read_keyfile(char *namestr, char *creatorstr, char *algstr, char *keystr,
	     isc_stdtime_t *inception, isc_stdtime_t *expire) {
	char line[4096] = { 0 };
	unsigned int keys = 0;
	FILE *fp = fopen(TEST_KEYFILE, "r");
	assert_non_null(fp);

	while (fgets(line, sizeof(line), fp) != NULL) {
		/* Each field buffer holds DNS_NAME_FORMATSIZE (1024). */
		assert_int_equal(sscanf(line,
					"%1023s %1023s %u %u %1023s %1023s",
					namestr, creatorstr, inception, expire,
					algstr, keystr),
				 6);
		keys++;
	}
	int ret = fclose(fp);
	assert_int_equal(ret, 0);

	return keys;
}

/*
 * A reload shares the dynamic keyring between the old and the new view.
 * Exporting a GSS context consumes it, so only the final owner may dump.
 */
ISC_RUN_TEST_IMPL(tsig_dumpanddetach_shared) {
	char namestr[DNS_NAME_FORMATSIZE], creatorstr[DNS_NAME_FORMATSIZE];
	char algstr[DNS_NAME_FORMATSIZE], keystr[4096];
	isc_stdtime_t inception, expire, now = isc_stdtime_now();
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_tsigkeyring_t *ring = NULL, *shared = NULL;
	dns_tsigkey_t *found = NULL;
	isc_result_t result;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "session.example", true, now + 3600, true);
	dns_tsigkeyring_attach(ring, &shared);

	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, DNS_R_CONTINUE);
	assert_null(ring);
	assert_false(keyfile_exists());

	/* The surviving owner still resolves the key. */
	result = dns_name_fromstring(name, "session.example", dns_rootname, 0,
				     NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_tsigkey_find(&found, name, NULL, shared);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_tsigkey_detach(&found);

	result = dns_tsigkeyring_dumpanddetach(&shared, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_null(shared);
	assert_int_equal(read_keyfile(namestr, creatorstr, algstr, keystr,
				      &inception, &expire),
			 1);
	assert_string_equal(namestr, "session.example");
	remove_keyfile();
}

ISC_RUN_TEST_IMPL(tsig_dumpanddetach_nothing) {
	isc_stdtime_t now = isc_stdtime_now();
	dns_tsigkeyring_t *ring = NULL;
	isc_result_t result;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;

	/* An empty ring. */
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_null(ring);

	/* A statically configured key is not written out. */
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "static.example", false, now + 3600, true);
	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* An expired generated key is not written out. */
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "expired.example", true, now - 1, true);
	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* A provider without dump() support, i.e. every non-GSS key. */
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "hmac.example", true, now + 3600, false);
	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* A provider whose dump() fails. */
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "broken.example", true, now + 3600, true);
	dump_result = ISC_R_FAILURE;
	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* Nothing above may have published a key file. */
	assert_false(keyfile_exists());
}

ISC_RUN_TEST_IMPL(tsig_dumpanddetach_key) {
	char namestr[DNS_NAME_FORMATSIZE], creatorstr[DNS_NAME_FORMATSIZE];
	char algstr[DNS_NAME_FORMATSIZE], keystr[4096];
	isc_stdtime_t inception, expire, now = isc_stdtime_now();
	dns_tsigkeyring_t *ring = NULL;
	isc_result_t result;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "session.example", true, now + 3600, true);

	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_null(ring);

	assert_int_equal(read_keyfile(namestr, creatorstr, algstr, keystr,
				      &inception, &expire),
			 1);
	assert_string_equal(namestr, "session.example");
	assert_string_equal(creatorstr, TEST_CREATOR);
	assert_int_equal(inception, TEST_INCEPTION);
	assert_int_equal(expire, now + 3600);
	assert_string_equal(algstr, "hmac-sha256");
	assert_string_equal(keystr, MOCK_KEYDATA);
	remove_keyfile();
}

/* An undumpable key must not suppress the keys that can be dumped. */
ISC_RUN_TEST_IMPL(tsig_dumpanddetach_skips_undumpable) {
	char namestr[DNS_NAME_FORMATSIZE], creatorstr[DNS_NAME_FORMATSIZE];
	char algstr[DNS_NAME_FORMATSIZE], keystr[4096];
	isc_stdtime_t inception, expire, now = isc_stdtime_now();
	dns_tsigkeyring_t *ring = NULL;
	isc_result_t result;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "hmac.example", true, now + 3600, false);
	add_key(ring, "session.example", true, now + 3600, true);

	result = dns_tsigkeyring_dumpanddetach(&ring, TEST_KEYFILE);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(read_keyfile(namestr, creatorstr, algstr, keystr,
				      &inception, &expire),
			 1);
	assert_string_equal(namestr, "session.example");
	remove_keyfile();
}

/* A key file that cannot be published must not be left half written. */
ISC_RUN_TEST_IMPL(tsig_dumpanddetach_unwritable) {
	isc_stdtime_t now = isc_stdtime_now();
	dns_tsigkeyring_t *ring = NULL;
	isc_result_t result;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "session.example", true, now + 3600, true);

	result = dns_tsigkeyring_dumpanddetach(&ring,
					       TEST_KEYFILE "/nonexistent/x");
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_int_not_equal(result, DNS_R_CONTINUE);
	assert_null(ring);
	assert_false(keyfile_exists());
}

typedef struct {
	dns_tsigkeyring_t *ring;
	atomic_bool *start;
	isc_result_t result;
} dump_thread_t;

static void *
dump_thread(void *arg) {
	dump_thread_t *ctx = arg;

	while (!atomic_load_acquire(ctx->start)) {
		isc_thread_yield();
	}
	ctx->result = dns_tsigkeyring_dumpanddetach(&ctx->ring, TEST_KEYFILE);

	return NULL;
}

/* Exactly one owner may dump, however the detaches interleave. */
ISC_RUN_TEST_IMPL(tsig_dumpanddetach_concurrent) {
	isc_stdtime_t now = isc_stdtime_now();
	dns_tsigkeyring_t *ring = NULL;
	isc_thread_t threads[8];
	dump_thread_t contexts[8] = { 0 };
	atomic_bool start = false;
	unsigned int dumped = 0, continued = 0;

	remove_keyfile();
	dump_result = ISC_R_SUCCESS;
	dns_tsigkeyring_create(isc_g_mctx, &ring);
	add_key(ring, "session.example", true, now + 3600, true);

	for (size_t i = 0; i < ARRAY_SIZE(threads); i++) {
		dns_tsigkeyring_attach(ring, &contexts[i].ring);
		contexts[i].start = &start;
		isc_thread_create(dump_thread, &contexts[i], &threads[i]);
	}
	dns_tsigkeyring_detach(&ring);
	atomic_store_release(&start, true);

	for (size_t i = 0; i < ARRAY_SIZE(threads); i++) {
		isc_thread_join(threads[i], NULL);
		assert_null(contexts[i].ring);
		if (contexts[i].result == ISC_R_SUCCESS) {
			dumped++;
		} else {
			assert_int_equal(contexts[i].result, DNS_R_CONTINUE);
			continued++;
		}
	}
	assert_int_equal(dumped, 1);
	assert_int_equal(continued, ARRAY_SIZE(threads) - 1);
	assert_true(keyfile_exists());
	remove_keyfile();
}

/* Tests the dns__tsig_algvalid function */
ISC_RUN_TEST_IMPL(algvalid) {
	UNUSED(state);

	assert_true(dns__tsig_algvalid(DST_ALG_HMACMD5));

	assert_true(dns__tsig_algvalid(DST_ALG_HMACSHA1));
	assert_true(dns__tsig_algvalid(DST_ALG_HMACSHA224));
	assert_true(dns__tsig_algvalid(DST_ALG_HMACSHA256));
	assert_true(dns__tsig_algvalid(DST_ALG_HMACSHA384));
	assert_true(dns__tsig_algvalid(DST_ALG_HMACSHA512));

	assert_false(dns__tsig_algvalid(DST_ALG_GSSAPI));
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(algvalid)
ISC_TEST_ENTRY(tsig_badsig)
ISC_TEST_ENTRY(tsig_badtime)
ISC_TEST_ENTRY(tsig_delete)
ISC_TEST_ENTRY(tsig_tcp)
ISC_TEST_ENTRY(tsig_maxkeys)
ISC_TEST_ENTRY(tsig_dumpanddetach_shared)
ISC_TEST_ENTRY(tsig_dumpanddetach_nothing)
ISC_TEST_ENTRY(tsig_dumpanddetach_key)
ISC_TEST_ENTRY(tsig_dumpanddetach_skips_undumpable)
ISC_TEST_ENTRY(tsig_dumpanddetach_unwritable)
ISC_TEST_ENTRY(tsig_dumpanddetach_concurrent)
ISC_TEST_LIST_END

ISC_TEST_MAIN
