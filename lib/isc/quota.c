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

#include <stddef.h>

#include <isc/atomic.h>
#include <isc/quota.h>
#include <isc/util.h>

#define QUOTA_MAGIC    ISC_MAGIC('Q', 'U', 'O', 'T')
#define VALID_QUOTA(p) ISC_MAGIC_VALID(p, QUOTA_MAGIC)

void
isc_quota_init(isc_quota_t *quota, unsigned int max) {
	atomic_init(&quota->max, max);
	atomic_init(&quota->used, 0);
	atomic_init(&quota->soft, 0);
	atomic_init(&quota->waiting, 0);
	ISC_LIST_INIT(quota->jobs);
	isc_mutex_init(&quota->cblock);
	ISC_LINK_INIT(quota, link);
	quota->magic = QUOTA_MAGIC;
}

void
isc_quota_soft(isc_quota_t *quota, unsigned int soft) {
	REQUIRE(VALID_QUOTA(quota));
	atomic_store_relaxed(&quota->soft, soft);
}

void
isc_quota_max(isc_quota_t *quota, unsigned int max) {
	REQUIRE(VALID_QUOTA(quota));
	atomic_store_relaxed(&quota->max, max);
}

unsigned int
isc_quota_getmax(isc_quota_t *quota) {
	REQUIRE(VALID_QUOTA(quota));
	return (atomic_load_relaxed(&quota->max));
}

unsigned int
isc_quota_getsoft(isc_quota_t *quota) {
	REQUIRE(VALID_QUOTA(quota));
	return (atomic_load_relaxed(&quota->soft));
}

unsigned int
isc_quota_getused(isc_quota_t *quota) {
	REQUIRE(VALID_QUOTA(quota));
	return (atomic_load_relaxed(&quota->used));
}

/* Must be quota->cblock locked */
static void
enqueue(isc_quota_t *quota, isc_job_t *cb) {
	REQUIRE(cb != NULL);
	ISC_LIST_ENQUEUE(quota->jobs, cb, link);
	atomic_fetch_add_relaxed(&quota->waiting, 1);
}

/* Must be quota->cblock locked */
static isc_job_t *
dequeue(isc_quota_t *quota) {
	isc_job_t *cb = ISC_LIST_HEAD(quota->jobs);
	if (cb != NULL) {
		ISC_LIST_DEQUEUE(quota->jobs, cb, link);
		atomic_fetch_sub_relaxed(&quota->waiting, 1);
	}
	return (cb);
}

void
isc_quota_release(isc_quota_t *quota) {
	uint_fast32_t used;

	/*
	 * This is opportunistic - we might race with a failing quota_attach_cb
	 * and not detect that something is waiting, but eventually someone will
	 * be releasing quota and will detect it, so we don't need to worry -
	 * and we're saving a lot by not locking cblock every time.
	 */

	if (atomic_load_acquire(&quota->waiting) > 0) {
		isc_job_t *cb = NULL;
		LOCK(&quota->cblock);
		cb = dequeue(quota);
		UNLOCK(&quota->cblock);
		if (cb != NULL) {
			cb->cb(cb->cbarg);
			return;
		}
	}

	used = atomic_fetch_sub_release(&quota->used, 1);
	INSIST(used > 0);
}

isc_result_t
isc_quota_acquire_cb(isc_quota_t *quota, isc_job_t *job, isc_job_cb cb,
		     void *cbarg) {
	REQUIRE(VALID_QUOTA(quota));
	REQUIRE(job == NULL || cb != NULL);

	uint_fast32_t used = atomic_fetch_add_release(&quota->used, 1);

	uint_fast32_t max = atomic_load_relaxed(&quota->max);
	if (max != 0 && used >= max) {
		(void)atomic_fetch_sub_relaxed(&quota->used, 1);
		if (job != NULL) {
			job->cb = cb;
			job->cbarg = cbarg;
			LOCK(&quota->cblock);
			enqueue(quota, job);
			UNLOCK(&quota->cblock);
		}
		return (ISC_R_QUOTA);
	}

	uint_fast32_t soft = atomic_load_relaxed(&quota->soft);
	if (soft != 0 && used >= soft) {
		return (ISC_R_SOFTQUOTA);
	}

	return (ISC_R_SUCCESS);
}

void
isc_quota_destroy(isc_quota_t *quota) {
	REQUIRE(VALID_QUOTA(quota));
	quota->magic = 0;

	INSIST(atomic_load(&quota->used) == 0);
	INSIST(atomic_load(&quota->waiting) == 0);
	INSIST(ISC_LIST_EMPTY(quota->jobs));
	isc_mutex_destroy(&quota->cblock);
}
