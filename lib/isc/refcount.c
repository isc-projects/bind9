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


#include <config.h>

#include <stddef.h>

#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/util.h>

#if defined(ISC_PLATFORM_USETHREADS) && !defined(ISC_REFCOUNT_HAVEATOMIC)
unsigned int
isc_refcount_current(isc_refcount_t *ref) {
	isc_result_t result;
	unsigned int answer;

	result = isc_mutex_lock(&ref->lock);
	ISC_ERROR_RUNTIMECHECK(result == ISC_R_SUCCESS);
	answer = ref->refs;
	result = isc_mutex_unlock(&ref->lock);
	ISC_ERROR_RUNTIMECHECK(result == ISC_R_SUCCESS);
	return (answer);
}
#endif

isc_result_t
isc_refcount_init(isc_refcount_t *ref, unsigned int n) {
	REQUIRE(ref != NULL);

	ref->refs = n;
#if defined(ISC_PLATFORM_USETHREADS) && !defined(ISC_REFCOUNT_HAVEATOMIC)
	return (isc_mutex_init(&ref->lock));
#else
	return (ISC_R_SUCCESS);
#endif
}
