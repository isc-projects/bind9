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

#if HAVE_CMOCKA

#include <fcntl.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/file.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/util.h>

#include "../mem_p.h"
#include "isctest.h"

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

#define MP1_FREEMAX  10
#define MP1_FILLCNT  10
#define MP1_MAXALLOC 30

#define MP2_FREEMAX 25
#define MP2_FILLCNT 25

/* general memory system tests */
static void
isc_mem_test(void **state) {
	void *items1[50];
	void *items2[50];
	void *tmp;
	isc_mempool_t *mp1 = NULL, *mp2 = NULL;
	unsigned int i, j;
	int rval;

	UNUSED(state);

	isc_mempool_create(test_mctx, 24, &mp1);
	isc_mempool_create(test_mctx, 31, &mp2);

	isc_mempool_setfreemax(mp1, MP1_FREEMAX);
	isc_mempool_setfillcount(mp1, MP1_FILLCNT);

	/*
	 * Allocate MP1_MAXALLOC items from the pool.  This is our max.
	 */
	for (i = 0; i < MP1_MAXALLOC; i++) {
		items1[i] = isc_mempool_get(mp1);
		assert_non_null(items1[i]);
	}

	/*
	 * Free the first 11 items.  Verify that there are 10 free items on
	 * the free list (which is our max).
	 */
	for (i = 0; i < 11; i++) {
		isc_mempool_put(mp1, items1[i]);
		items1[i] = NULL;
	}

#if !__SANITIZE_ADDRESS__
	rval = isc_mempool_getfreecount(mp1);
	assert_int_equal(rval, 10);
#endif /* !__SANITIZE_ADDRESS__ */

	rval = isc_mempool_getallocated(mp1);
	assert_int_equal(rval, 19);

	/*
	 * Now, beat up on mp2 for a while.  Allocate 50 items, then free
	 * them, then allocate 50 more, etc.
	 */

	isc_mempool_setfreemax(mp2, 25);
	isc_mempool_setfillcount(mp2, 25);

	for (j = 0; j < 500000; j++) {
		for (i = 0; i < 50; i++) {
			items2[i] = isc_mempool_get(mp2);
			assert_non_null(items2[i]);
		}
		for (i = 0; i < 50; i++) {
			isc_mempool_put(mp2, items2[i]);
			items2[i] = NULL;
		}
	}

	/*
	 * Free all the other items and blow away this pool.
	 */
	for (i = 11; i < MP1_MAXALLOC; i++) {
		isc_mempool_put(mp1, items1[i]);
		items1[i] = NULL;
	}

	isc_mempool_destroy(&mp1);
	isc_mempool_destroy(&mp2);

	isc_mempool_create(test_mctx, 2, &mp1);

	tmp = isc_mempool_get(mp1);
	assert_non_null(tmp);

	isc_mempool_put(mp1, tmp);

	isc_mempool_destroy(&mp1);
}

/* test TotalUse calculation */
static void
isc_mem_total_test(void **state) {
	isc_mem_t *mctx2 = NULL;
	size_t before, after;
	ssize_t diff;
	int i;

	UNUSED(state);

	/* Local alloc, free */
	mctx2 = NULL;
	isc_mem_create(&mctx2);

	before = isc_mem_total(mctx2);

	for (i = 0; i < 100000; i++) {
		void *ptr;

		ptr = isc_mem_get(mctx2, 2048);
		isc_mem_put(mctx2, ptr, 2048);
	}

	after = isc_mem_total(mctx2);
	diff = after - before;

	assert_int_equal(diff, (2048) * 100000);

	/* ISC_MEMFLAG_INTERNAL */

	before = isc_mem_total(test_mctx);

	for (i = 0; i < 100000; i++) {
		void *ptr;

		ptr = isc_mem_get(test_mctx, 2048);
		isc_mem_put(test_mctx, ptr, 2048);
	}

	after = isc_mem_total(test_mctx);
	diff = after - before;

	assert_int_equal(diff, (2048) * 100000);

	isc_mem_destroy(&mctx2);
}

/* test InUse calculation */
static void
isc_mem_inuse_test(void **state) {
	isc_mem_t *mctx2 = NULL;
	size_t before, after;
	ssize_t diff;
	void *ptr;

	UNUSED(state);

	mctx2 = NULL;
	isc_mem_create(&mctx2);

	before = isc_mem_inuse(mctx2);
	ptr = isc_mem_allocate(mctx2, 1024000);
	isc_mem_free(mctx2, ptr);
	after = isc_mem_inuse(mctx2);

	diff = after - before;

	assert_int_equal(diff, 0);

	isc_mem_destroy(&mctx2);
}

static void
isc_mem_zeroget_test(void **state) {
	uint8_t *data = NULL;
	UNUSED(state);

	data = isc_mem_get(test_mctx, 0);
	assert_non_null(data);
	isc_mem_put(test_mctx, data, 0);
}

#define REGET_INIT_SIZE	  1024
#define REGET_GROW_SIZE	  2048
#define REGET_SHRINK_SIZE 512

static void
isc_mem_reget_test(void **state) {
	uint8_t *data = NULL;

	UNUSED(state);

	/* test that we can reget NULL */
	data = isc_mem_reget(test_mctx, NULL, 0, REGET_INIT_SIZE);
	assert_non_null(data);
	isc_mem_put(test_mctx, data, REGET_INIT_SIZE);

	/* test that we can re-get a zero-length allocation */
	data = isc_mem_get(test_mctx, 0);
	assert_non_null(data);

	data = isc_mem_reget(test_mctx, data, 0, REGET_INIT_SIZE);
	assert_non_null(data);

	for (size_t i = 0; i < REGET_INIT_SIZE; i++) {
		data[i] = i % UINT8_MAX;
	}

	data = isc_mem_reget(test_mctx, data, REGET_INIT_SIZE, REGET_GROW_SIZE);
	assert_non_null(data);

	for (size_t i = 0; i < REGET_INIT_SIZE; i++) {
		assert_int_equal(data[i], i % UINT8_MAX);
	}

	for (size_t i = REGET_GROW_SIZE; i > 0; i--) {
		data[i - 1] = i % UINT8_MAX;
	}

	data = isc_mem_reget(test_mctx, data, REGET_GROW_SIZE,
			     REGET_SHRINK_SIZE);
	assert_non_null(data);

	for (size_t i = REGET_SHRINK_SIZE; i > 0; i--) {
		assert_int_equal(data[i - 1], i % UINT8_MAX);
	}

	isc_mem_put(test_mctx, data, REGET_SHRINK_SIZE);
}

#if ISC_MEM_TRACKLINES

/* test mem with no flags */
static void
isc_mem_noflags_test(void **state) {
	isc_result_t result;
	isc_mem_t *mctx2 = NULL;
	char buf[4096], *p, *q;
	FILE *f;
	void *ptr;

	result = isc_stdio_open("mem.output", "w", &f);
	assert_int_equal(result, ISC_R_SUCCESS);

	UNUSED(state);

	isc_mem_create(&mctx2);
	isc_mem_debugging = 0;
	ptr = isc_mem_get(mctx2, 2048);
	assert_non_null(ptr);
	isc__mem_printactive(mctx2, f);
	isc_mem_put(mctx2, ptr, 2048);
	isc_mem_destroy(&mctx2);
	isc_stdio_close(f);

	memset(buf, 0, sizeof(buf));
	result = isc_stdio_open("mem.output", "r", &f);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_stdio_read(buf, sizeof(buf), 1, f, NULL);
	assert_int_equal(result, ISC_R_EOF);
	isc_stdio_close(f);
	isc_file_remove("mem.output");

	buf[sizeof(buf) - 1] = 0;

	p = strchr(buf, '\n');
	assert_non_null(p);
	assert_in_range(p, 0, buf + sizeof(buf) - 3);
	p += 2;
	q = strchr(p, '\n');
	assert_non_null(q);
	*q = '\0';
	assert_string_equal(p, "None.");

	isc_mem_debugging = ISC_MEM_DEBUGRECORD;
}

/* test mem with record flag */
static void
isc_mem_recordflag_test(void **state) {
	isc_result_t result;
	isc_mem_t *mctx2 = NULL;
	char buf[4096], *p;
	FILE *f;
	void *ptr;

	result = isc_stdio_open("mem.output", "w", &f);
	assert_int_equal(result, ISC_R_SUCCESS);

	UNUSED(state);

	isc_mem_create(&mctx2);
	ptr = isc_mem_get(mctx2, 2048);
	assert_non_null(ptr);
	isc__mem_printactive(mctx2, f);
	isc_mem_put(mctx2, ptr, 2048);
	isc_mem_destroy(&mctx2);
	isc_stdio_close(f);

	memset(buf, 0, sizeof(buf));
	result = isc_stdio_open("mem.output", "r", &f);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_stdio_read(buf, sizeof(buf), 1, f, NULL);
	assert_int_equal(result, ISC_R_EOF);
	isc_stdio_close(f);
	isc_file_remove("mem.output");

	buf[sizeof(buf) - 1] = 0;

	p = strchr(buf, '\n');
	assert_non_null(p);
	assert_in_range(p, 0, buf + sizeof(buf) - 3);
	assert_memory_equal(p + 2, "ptr ", 4);
	p = strchr(p + 1, '\n');
	assert_non_null(p);
	assert_int_equal(strlen(p), 1);
}

/* test mem with trace flag */
static void
isc_mem_traceflag_test(void **state) {
	isc_result_t result;
	isc_mem_t *mctx2 = NULL;
	char buf[4096], *p;
	FILE *f;
	void *ptr;

	/* redirect stderr so we can check trace output */
	f = freopen("mem.output", "w", stderr);
	assert_non_null(f);

	UNUSED(state);

	isc_mem_create(&mctx2);
	isc_mem_debugging = ISC_MEM_DEBUGTRACE;
	ptr = isc_mem_get(mctx2, 2048);
	assert_non_null(ptr);
	isc__mem_printactive(mctx2, f);
	isc_mem_put(mctx2, ptr, 2048);
	isc_mem_destroy(&mctx2);
	isc_stdio_close(f);

	memset(buf, 0, sizeof(buf));
	result = isc_stdio_open("mem.output", "r", &f);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_stdio_read(buf, sizeof(buf), 1, f, NULL);
	assert_int_equal(result, ISC_R_EOF);
	isc_stdio_close(f);
	isc_file_remove("mem.output");

	/* return stderr to TTY so we can see errors */
	f = freopen("/dev/tty", "w", stderr);

	buf[sizeof(buf) - 1] = 0;

	assert_memory_equal(buf, "add ", 4);
	p = strchr(buf, '\n');
	assert_non_null(p);
	p = strchr(p + 1, '\n');
	assert_non_null(p);
	assert_in_range(p, 0, buf + sizeof(buf) - 3);
	assert_memory_equal(p + 2, "ptr ", 4);
	p = strchr(p + 1, '\n');
	assert_non_null(p);
	assert_memory_equal(p + 1, "del ", 4);

	isc_mem_debugging = ISC_MEM_DEBUGRECORD;
}
#endif /* if ISC_MEM_TRACKLINES */

#if !defined(__SANITIZE_THREAD__)

#define ITERS	  512
#define NUM_ITEMS 1024 /* 768 */
#define ITEM_SIZE 65534

static atomic_size_t mem_size;

static isc_threadresult_t
mem_thread(isc_threadarg_t arg) {
	isc_mem_t *mctx = (isc_mem_t *)arg;
	void *items[NUM_ITEMS];
	size_t size = atomic_load(&mem_size);
	while (!atomic_compare_exchange_weak(&mem_size, &size, size / 2))
		;

	for (int i = 0; i < ITERS; i++) {
		for (int j = 0; j < NUM_ITEMS; j++) {
			items[j] = isc_mem_get(mctx, size);
		}
		for (int j = 0; j < NUM_ITEMS; j++) {
			isc_mem_put(mctx, items[j], size);
		}
	}

	return ((isc_threadresult_t)0);
}

static void
isc_mem_benchmark(void **state) {
	int nthreads = ISC_MAX(ISC_MIN(isc_os_ncpus(), 32), 1);
	isc_thread_t threads[32];
	isc_time_t ts1, ts2;
	double t;
	isc_result_t result;

	UNUSED(state);

	atomic_init(&mem_size, ITEM_SIZE);

	result = isc_time_now(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (int i = 0; i < nthreads; i++) {
		isc_thread_create(mem_thread, test_mctx, &threads[i]);
	}
	for (int i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	result = isc_time_now(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("[ TIME     ] isc_mem_benchmark: "
	       "%d isc_mem_{get,put} calls, %f seconds, %f calls/second\n",
	       nthreads * ITERS * NUM_ITEMS, t / 1000000.0,
	       (nthreads * ITERS * NUM_ITEMS) / (t / 1000000.0));
}

#endif /* __SANITIZE_THREAD */

/*
 * Main
 */

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(isc_mem_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mem_total_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mem_inuse_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mem_zeroget_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mem_reget_test, _setup,
						_teardown),

#if !defined(__SANITIZE_THREAD__)
		cmocka_unit_test_setup_teardown(isc_mem_benchmark, _setup,
						_teardown),
#endif /* __SANITIZE_THREAD__ */
#if ISC_MEM_TRACKLINES
		cmocka_unit_test_setup_teardown(isc_mem_noflags_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mem_recordflag_test, _setup,
						_teardown),
		/*
		 * traceflag_test closes stderr, which causes weird
		 * side effects for any next test trying to use libuv.
		 * This test has to be the last one to avoid problems.
		 */
		cmocka_unit_test_setup_teardown(isc_mem_traceflag_test, _setup,
						_teardown),
#endif /* if ISC_MEM_TRACKLINES */
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
