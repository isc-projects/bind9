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

/*! \file */

#include <string.h>

#include <isc/mem.h>
#include <isc/pool.h>
#include <isc/random.h>
#include <isc/util.h>

/***
 *** Types.
 ***/

struct isc_pool {
	isc_mem_t *mctx;
	unsigned int count;
	isc_pooldeallocator_t free;
	isc_poolinitializer_t init;
	void *initarg;
	void **pool;
};

/***
 *** Functions.
 ***/

isc_result_t
isc_pool_create(isc_mem_t *mctx, unsigned int count,
		isc_pooldeallocator_t release, isc_poolinitializer_t init,
		void *initarg, isc_pool_t **poolp) {
	isc_pool_t *pool = NULL;
	isc_result_t result;
	unsigned int i;

	INSIST(count > 0);

	/* Allocate the pool structure */
	pool = isc_mem_get(mctx, sizeof(*pool));
	*pool = (isc_pool_t){
		.count = count,
		.free = release,
		.init = init,
		.initarg = initarg,
	};
	isc_mem_attach(mctx, &pool->mctx);
	pool->pool = isc_mem_get(mctx, count * sizeof(void *));
	memset(pool->pool, 0, count * sizeof(void *));

	/* Populate the pool */
	for (i = 0; i < count; i++) {
		result = init(&pool->pool[i], initarg);
		if (result != ISC_R_SUCCESS) {
			isc_pool_destroy(&pool);
			return (result);
		}
	}

	*poolp = pool;
	return (ISC_R_SUCCESS);
}

void *
isc_pool_get(isc_pool_t *pool, unsigned int tid) {
	REQUIRE(tid < pool->count);

	return (pool->pool[tid]);
}

void
isc_pool_destroy(isc_pool_t **poolp) {
	unsigned int i;
	isc_pool_t *pool = *poolp;
	*poolp = NULL;
	for (i = 0; i < pool->count; i++) {
		if (pool->free != NULL && pool->pool[i] != NULL) {
			pool->free(&pool->pool[i]);
		}
	}
	isc_mem_put(pool->mctx, pool->pool, pool->count * sizeof(void *));
	isc_mem_putanddetach(&pool->mctx, pool, sizeof(*pool));
}
