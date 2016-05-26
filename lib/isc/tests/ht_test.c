/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
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

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <isc/hash.h>
#include <isc/ht.h>
#include <isc/mem.h>
#include <isc/util.h>

static void *
default_memalloc(void *arg, size_t size) {
	UNUSED(arg);
	if (size == 0U)
		size = 1;
	return (malloc(size));
}

static void
default_memfree(void *arg, void *ptr) {
	UNUSED(arg);
	free(ptr);
}


static void test_ht_full(int bits, int count) {
	isc_ht_t *ht = NULL;
	isc_result_t result;
	isc_mem_t *mctx = NULL;
	isc_int64_t i;

	result = isc_mem_createx2(0, 0, default_memalloc, default_memfree,
				  NULL, &mctx, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_ht_init(&ht, mctx, bits);
	for (i = 1; i < count; i++) {
		/*
		 * Note that the string we're snprintfing is always > 16 bytes
		 * so we are always filling the key.
		 */
		unsigned char key[16];
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_add(ht, key, 16, (void *) i);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_find(ht, key, 16, &f);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE_EQ(i, (isc_int64_t) f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_add(ht, key, 16, (void *) i);
		ATF_REQUIRE_EQ(result, ISC_R_EXISTS);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		snprintf((char *)key, 64, "%lld key of a str hashtable!!", i);
		result = isc_ht_add(ht, (const unsigned char *) key,
				    strlen(key), (void *) i);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, 16, "%lld KEY of a raw hashtable!!", i);
		result = isc_ht_find(ht, key, 16, &f);
		ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
		ATF_REQUIRE_EQ(f, NULL);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		void *f = NULL;
		snprintf((char *)key, 64, "%lld key of a str hashtable!!", i);
		result = isc_ht_find(ht, (const unsigned char *) key,
				     strlen(key), &f);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE_EQ(f, (void *) i);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_delete(ht, key, 16);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		result = isc_ht_find(ht, key, 16, &f);
		ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
		ATF_REQUIRE_EQ(f, NULL);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		snprintf((char *)key, 16, "%lld KEY of a raw hashtable!!", i);
		result = isc_ht_add(ht, key, 16, (void *) i);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	for (i = 1; i < count; i++) {
		char key[64];
		void *f = NULL;
		snprintf((char *)key, 64, "%lld key of a str hashtable!!", i);
		result = isc_ht_delete(ht, (const unsigned char *) key,
				       strlen(key));
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		result = isc_ht_find(ht, (const unsigned char *) key,
				     strlen(key), &f);
		ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
		ATF_REQUIRE_EQ(f, NULL);
	}


	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, 16, "%lld KEY of a raw hashtable!!", i);
		result = isc_ht_find(ht, key, 16, &f);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE_EQ(i, (isc_int64_t) f);
	}

	for (i = 1; i < count; i++) {
		unsigned char key[16];
		void *f = NULL;
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_find(ht, key, 16, &f);
		ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
		ATF_REQUIRE_EQ(f, NULL);
	}

	isc_ht_destroy(&ht);
	ATF_REQUIRE_EQ(ht, NULL);
}

static isc_uint32_t walked = 0;

typedef enum {
	REGULAR,
	ERASEEVEN,
	ERASEODD,
	CRASH
} walkmode_t;

static isc_result_t walker(void *udata, const unsigned char *key,
			   isc_uint32_t keysize, void *data)
{
	char mykey[16];
	isc_uint64_t ii = (isc_uint64_t) data;
	walkmode_t mode = (isc_uint64_t) udata;
	ATF_REQUIRE_EQ(keysize, 16);

	snprintf(mykey, 16, "%lld key of a raw hashtable!!", ii);
	ATF_REQUIRE_EQ(memcmp(mykey, key, 16), 0);

	walked++;
	switch (mode) {
	case REGULAR:
		break;
	case ERASEEVEN:
		if (ii % 2 == 0) {
			return (ISC_R_EXISTS);
		}
		break;
	case ERASEODD:
		if (ii % 2 != 0) {
			return (ISC_R_EXISTS);
		}
		break;
	case CRASH:
		if (walked == 100) {
			/* something as odd as possible */
			return (ISC_R_HOSTUNREACH);
		}
		break;
	}

	return (ISC_R_SUCCESS);
}

static void test_ht_walk() {
	isc_ht_t *ht = NULL;
	isc_result_t result;
	isc_mem_t *mctx = NULL;
	isc_int64_t i;
	isc_uint32_t count = 10000;

	result = isc_mem_createx2(0, 0, default_memalloc, default_memfree,
				  NULL, &mctx, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = isc_ht_init(&ht, mctx, 16);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(ht != NULL);
	for (i = 1; i <= count; i++) {
		/*
		 * Note that the string we're snprintfing is always > 16 bytes
		 * so we are always filling the key.
		 */
		unsigned char key[16];
		snprintf((char *)key, 16, "%lld key of a raw hashtable!!", i);
		result = isc_ht_add(ht, key, 16, (void *) i);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	walked = 0;
	result = isc_ht_walk(ht, walker, (void *) REGULAR);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(walked, count);

	walked = 0;
	result = isc_ht_walk(ht, walker, (void *) CRASH);
	ATF_REQUIRE_EQ(result, ISC_R_HOSTUNREACH);
	ATF_REQUIRE_EQ(walked, 100);

	walked = 0;
	result = isc_ht_walk(ht, walker, (void *) ERASEODD);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(walked, count);

	walked = 0;
	result = isc_ht_walk(ht, walker, (void *) ERASEEVEN);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(walked, count/2);

	walked = 0;
	result = isc_ht_walk(ht, walker, (void *) REGULAR);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(walked, 0);

	isc_ht_destroy(&ht);
	ATF_REQUIRE_EQ(ht, NULL);
}

ATF_TC(isc_ht_20);
ATF_TC_HEAD(isc_ht_20, tc) {
	atf_tc_set_md_var(tc, "descr", "20 bit, 2M elements test");
}

ATF_TC_BODY(isc_ht_20, tc) {
	UNUSED(tc);
	test_ht_full(20, 2000000);
}


ATF_TC(isc_ht_8);
ATF_TC_HEAD(isc_ht_8, tc) {
	atf_tc_set_md_var(tc, "descr", "8 bit, 20000 elements crowded test");
}

ATF_TC_BODY(isc_ht_8, tc) {
	UNUSED(tc);
	test_ht_full(8, 20000);
}

ATF_TC(isc_ht_1);
ATF_TC_HEAD(isc_ht_1, tc) {
	atf_tc_set_md_var(tc, "descr", "1 bit, 100 elements corner case test");
}

ATF_TC_BODY(isc_ht_1, tc) {
	UNUSED(tc);
	test_ht_full(1, 100);
}

ATF_TC(isc_ht_32);
ATF_TC_HEAD(isc_ht_32, tc) {
	atf_tc_set_md_var(tc, "descr", "32 bit, 10000 elements corner case test");
}

ATF_TC_BODY(isc_ht_32, tc) {
	UNUSED(tc);
	test_ht_full(32, 10000);
}

ATF_TC(isc_ht_walk);
ATF_TC_HEAD(isc_ht_walk, tc) {
	atf_tc_set_md_var(tc, "descr", "hashtable walking");
}

ATF_TC_BODY(isc_ht_walk, tc) {
	UNUSED(tc);
	test_ht_walk();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_ht_20);
	ATF_TP_ADD_TC(tp, isc_ht_8);
	ATF_TP_ADD_TC(tp, isc_ht_1);
	ATF_TP_ADD_TC(tp, isc_ht_32);
	ATF_TP_ADD_TC(tp, isc_ht_walk);
	return (atf_no_error());
}

