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


/*! \file */

#include <config.h>

#include <stddef.h>

#include <isc/quota.h>
#include <isc/util.h>

isc_result_t
isc_quota_init(isc_quota_t *quota, int max) {
	quota->max = max;
	quota->used = 0;
	quota->soft = 0;
	return (isc_mutex_init(&quota->lock));
}

void
isc_quota_destroy(isc_quota_t *quota) {
	INSIST(quota->used == 0);
	quota->max = 0;
	quota->used = 0;
	quota->soft = 0;
	DESTROYLOCK(&quota->lock);
}

void
isc_quota_soft(isc_quota_t *quota, int soft) {
	LOCK(&quota->lock);
	quota->soft = soft;
	UNLOCK(&quota->lock);
}

void
isc_quota_max(isc_quota_t *quota, int max) {
	LOCK(&quota->lock);
	quota->max = max;
	UNLOCK(&quota->lock);
}

isc_result_t
isc_quota_reserve(isc_quota_t *quota) {
	isc_result_t result;
	LOCK(&quota->lock);
	if (quota->max == 0 || quota->used < quota->max) {
		if (quota->soft == 0 || quota->used < quota->soft)
			result = ISC_R_SUCCESS;
		else
			result = ISC_R_SOFTQUOTA;
		quota->used++;
	} else
		result = ISC_R_QUOTA;
	UNLOCK(&quota->lock);
	return (result);
}

void
isc_quota_release(isc_quota_t *quota) {
	LOCK(&quota->lock);
	INSIST(quota->used > 0);
	quota->used--;
	UNLOCK(&quota->lock);
}

static isc_result_t
doattach(isc_quota_t *quota, isc_quota_t **p, bool force) {
	isc_result_t result;
	REQUIRE(p != NULL && *p == NULL);

	result = isc_quota_reserve(quota);
	if (result == ISC_R_SUCCESS || result == ISC_R_SOFTQUOTA) {
		*p = quota;
	} else if (result == ISC_R_QUOTA && force) {
		/* attach anyway */
		LOCK(&quota->lock);
		quota->used++;
		UNLOCK(&quota->lock);

		*p = quota;
		result = ISC_R_SUCCESS;
	}

	return (result);
}

isc_result_t
isc_quota_attach(isc_quota_t *quota, isc_quota_t **p) {
	return (doattach(quota, p, false));
}

isc_result_t
isc_quota_force(isc_quota_t *quota, isc_quota_t **p) {
	return (doattach(quota, p, true));
}

void
isc_quota_detach(isc_quota_t **p) {
	INSIST(p != NULL && *p != NULL);
	isc_quota_release(*p);
	*p = NULL;
}

unsigned int
isc_quota_getused(isc_quota_t *quota) {
	int used;

	LOCK(&quota->lock);
	used = quota->used;
	UNLOCK(&quota->lock);
	return (used);
}
