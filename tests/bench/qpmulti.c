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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/qp.h>
#include <dns/types.h>

#include "qp_p.h"

#include <tests/qp.h>

#define ITEM_COUNT ((size_t)1000000)

#define MS_PER_SEC 1000
#define US_PER_SEC 1000000
#define NS_PER_SEC 1000000000

static double
doubletime(isc_time_t t0, isc_time_t t1) {
	return ((double)isc_time_microdiff(&t1, &t0) / (double)US_PER_SEC);
}

static struct {
	bool present;
	uint8_t len;
	dns_qpkey_t key;
} *item;

static void
item_refcount(void *ctx, void *pval, uint32_t ival) {
	UNUSED(ctx);
	UNUSED(pval);
	UNUSED(ival);
}

static size_t
item_makekey(dns_qpkey_t key, void *ctx, void *pval, uint32_t ival) {
	UNUSED(ctx);
	UNUSED(pval);
	memmove(key, item[ival].key, item[ival].len);
	return (item[ival].len);
}

static void
benchname(void *ctx, char *buf, size_t size) {
	UNUSED(ctx);
	strlcpy(buf, "bench", size);
}

const struct dns_qpmethods item_methods = {
	item_refcount,
	item_refcount,
	item_makekey,
	benchname,
};

static uint8_t
random_byte(void) {
	return (isc_random_uniform(SHIFT_OFFSET - SHIFT_NOBYTE) + SHIFT_NOBYTE);
}

static void
init_items(isc_mem_t *mctx) {
	isc_time_t t0, t1;
	void *pval = NULL;
	uint32_t ival = ~0U;
	dns_qp_t *qp = NULL;

	size_t bytes = ITEM_COUNT * sizeof(*item);

	item = isc_mem_allocatex(mctx, bytes, ISC_MEM_ZERO);

	isc_time_now_hires(&t0);

	/* ensure there are no duplicate names */
	dns_qp_create(mctx, &item_methods, NULL, &qp);
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		do {
			size_t len = isc_random_uniform(16) + 4;
			item[i].len = len;
			for (size_t off = 0; off < len; off++) {
				item[i].key[off] = random_byte();
			}
			item[i].key[len] = SHIFT_NOBYTE;
		} while (dns_qp_getkey(qp, item[i].key, item[i].len, &pval,
				       &ival) == ISC_R_SUCCESS);
		INSIST(dns_qp_insert(qp, &item[i], i) == ISC_R_SUCCESS);
	}
	dns_qp_destroy(&qp);

	isc_time_now_hires(&t1);
	double time = doubletime(t0, t1);
	printf("%f sec to create %zu items, %f/sec\n", time, ITEM_COUNT,
	       ITEM_COUNT / time);
}

static void
init_multi(isc_mem_t *mctx, dns_qpmulti_t **qpmp, uint32_t max) {
	isc_time_t t0, t1;
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	size_t count = 0;

	isc_time_now_hires(&t0);

	dns_qpmulti_create(mctx, &item_methods, NULL, qpmp);
	multi = *qpmp;

	/* initial contents of the trie */
	dns_qpmulti_update(multi, &qp);
	for (size_t i = 0; i < max; i++) {
		if (isc_random_uniform(2) == 0) {
			continue;
		}
		INSIST(dns_qp_insert(qp, &item[i], i) == ISC_R_SUCCESS);
		item[i].present = true;
		count++;
	}
	dns_qpmulti_commit(multi, &qp);

	isc_time_now_hires(&t1);
	double time = doubletime(t0, t1);
	printf("%f sec to load %zu items, %f/sec\n", time, count, count / time);
}

static void
init_logging(isc_mem_t *mctx) {
	isc_result_t result;
	isc_logdestination_t destination;
	isc_logconfig_t *logconfig = NULL;
	isc_log_t *lctx = NULL;

	isc_log_create(mctx, &lctx, &logconfig);
	isc_log_setcontext(lctx);
	dns_log_init(lctx);
	dns_log_setcontext(lctx);

	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	isc_log_createchannel(logconfig, "stderr", ISC_LOG_TOFILEDESC,
			      ISC_LOG_DYNAMIC, &destination,
			      ISC_LOG_PRINTPREFIX | ISC_LOG_PRINTTIME |
				      ISC_LOG_ISO8601);

	// isc_log_setdebuglevel(lctx, 1);

	result = isc_log_usechannel(logconfig, "stderr",
				    ISC_LOGCATEGORY_DEFAULT, NULL);
	INSIST(result == ISC_R_SUCCESS);
}

typedef void
transaction_fun(dns_qpmulti_t *multi, uint32_t max, uint32_t ops,
		uint64_t *absent_r, uint64_t *present_r);

static transaction_fun read_transaction, update_transaction;

struct thread_args {
	transaction_fun *txfun; /* (in) */
	dns_qpmulti_t *multi;	/* (in) */
	isc_thread_t tid;	/* (in) */
	uint32_t max;		/* item index (in) */
	uint32_t ops;		/* per transaction (in) */
	uint64_t absent;	/* items not found or inserted (out) */
	uint64_t present;	/* items found or deleted (out) */
	uint64_t transactions;	/* (out) */
	isc_time_t t0;		/* (out) */
	isc_time_t t1;		/* (out) */
};

static void
read_transaction(dns_qpmulti_t *multi, uint32_t max, uint32_t ops,
		 uint64_t *absent_r, uint64_t *present_r) {
	dns_qpread_t *qp = NULL;
	uint64_t absent = 0;
	uint64_t present = 0;
	void *pval;
	uint32_t ival;
	isc_result_t result;

	dns_qpmulti_query(multi, &qp);
	for (uint32_t n = 0; n < ops; n++) {
		uint32_t i = isc_random_uniform(max);
		result = dns_qp_getkey(qp, item[i].key, item[i].len, &pval,
				       &ival);
		if (result == ISC_R_SUCCESS) {
			++present;
		} else {
			++absent;
		}
	}
	dns_qpread_destroy(multi, &qp);
	*present_r = present;
	*absent_r = absent;
}

static void
update_transaction(dns_qpmulti_t *multi, uint32_t max, uint32_t ops,
		   uint64_t *absent_r, uint64_t *present_r) {
	dns_qp_t *qp = NULL;
	uint64_t absent = 0;
	uint64_t present = 0;
	isc_result_t result;

	if (multi->read->generation & 255) {
		dns_qpmulti_write(multi, &qp);
	} else {
		dns_qpmulti_update(multi, &qp);
	}
	for (uint32_t n = 0; n < ops; n++) {
		uint32_t i = isc_random_uniform(max);
		if (item[i].present) {
			result = dns_qp_deletekey(qp, item[i].key, item[i].len);
			INSIST(result == ISC_R_SUCCESS);
			item[i].present = false;
			++present;
		} else {
			result = dns_qp_insert(qp, &item[i], i);
			INSIST(result == ISC_R_SUCCESS);
			item[i].present = true;
			++absent;
		}
	}
	dns_qpmulti_commit(multi, &qp);
	*present_r += present;
	*absent_r += absent;
}

static isc_refcount_t stop;

static void *
thread_loop(void *args_v) {
	struct thread_args *args = args_v;
	transaction_fun *txfun = args->txfun;
	dns_qpmulti_t *multi = args->multi;
	uint32_t max = args->max;
	uint32_t ops = args->ops;
	uint64_t absent = 0;
	uint64_t present = 0;
	uint64_t transactions = 0;

#if HAVE_LIBURCU
	rcu_register_thread();
#endif
	isc_time_now_hires(&args->t0);
	while (isc_refcount_current(&stop) == 0) {
		txfun(multi, max, ops, &absent, &present);
		++transactions;
	}
	isc_time_now_hires(&args->t1);
	args->absent = absent;
	args->present = present;
	args->transactions = transactions;
#if HAVE_LIBURCU
	rcu_unregister_thread();
#endif
	return (args);
}

static void
dispatch_threads(dns_qpmulti_t *multi, useconds_t runtime, uint32_t max,
		 uint32_t updaters, uint32_t updateops, uint32_t readers,
		 uint32_t readops) {
	struct thread_args thread[64];
	uint32_t threads = updaters + readers;

	REQUIRE(threads <= ARRAY_SIZE(thread));

	for (uint32_t t = 0; t < threads; t++) {
		thread[t] = (struct thread_args){
			.txfun = t < updaters ? update_transaction
					      : read_transaction,
			.multi = multi,
			.max = max,
			.ops = t < updaters ? updateops : readops,
		};
	}

	isc_refcount_init(&stop, 0);

	for (uint32_t t = 0; t < threads; t++) {
		isc_thread_create(thread_loop, &thread[t], &thread[t].tid);
	}

	usleep(runtime);
	isc_refcount_increment0(&stop);

	for (uint32_t t = 0; t < threads; t++) {
		isc_thread_join(thread[t].tid, NULL);
	}

	struct {
		double time, txns, ops;
	} stats[2] = {};

	for (uint32_t t = 0; t < threads; t++) {
		struct thread_args *tp = &thread[t];
		stats[t < updaters].time += doubletime(tp->t0, tp->t1);
		stats[t < updaters].txns += tp->transactions;
		stats[t < updaters].ops += tp->transactions * tp->ops;
	}
	printf("%2u up %2u ops/tx %7.3f txn/ms %5.3f ops/us   ", updaters,
	       updateops,
	       stats[1].txns / (stats[1].time * MS_PER_SEC / updaters),
	       stats[1].ops / (stats[1].time * US_PER_SEC / updaters));
	printf("%2u rd %2u ops/tx %8.3f txn/ms %7.3f ops/us %6.3f ops/us/thr\n",
	       readers, readops,
	       stats[0].txns / (stats[0].time * MS_PER_SEC / readers),
	       stats[0].ops / (stats[0].time * US_PER_SEC / readers),
	       stats[0].ops / (stats[0].time * US_PER_SEC));
}

int
main(void) {
	dns_qpmulti_t *multi = NULL;
	isc_mem_t *mctx = NULL;

	isc_mem_create(&mctx);
	isc_mem_setdestroycheck(mctx, true);
	init_logging(mctx);
	init_items(mctx);

	uint32_t threads = 12;
	uint32_t max = ITEM_COUNT;
	useconds_t runtime = 0.2 * US_PER_SEC;

	init_multi(mctx, &multi, max);
	for (uint32_t t = 2; t <= threads; t++) {
		dispatch_threads(multi, runtime, max, 1, 64, t - 1, 8);
	}
	dns_qpmulti_destroy(&multi);

	for (max = 1000; max <= ITEM_COUNT; max *= 10) {
		init_multi(mctx, &multi, max);
		for (uint32_t t = 1; t <= threads; t++) {
			dispatch_threads(multi, runtime, max, 0, 0, t, 64);
		}
		dns_qpmulti_destroy(&multi);
	}

	isc_log_destroy(&dns_lctx);
	isc_mem_free(mctx, item);
	isc_mem_destroy(&mctx);
	isc_mem_checkdestroyed(stderr);

	return (0);
}
