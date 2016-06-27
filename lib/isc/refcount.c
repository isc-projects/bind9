/*
 * Copyright (C) 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: refcount.c,v 1.5 2007/06/19 23:47:17 tbox Exp $ */

#include <config.h>

#include <stddef.h>

#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>

isc_result_t
isc_refcount_init(isc_refcount_t *ref, unsigned int n) {
	REQUIRE(ref != NULL);

	ref->refs = n;
#if defined(ISC_PLATFORM_USETHREADS) && !defined(ISC_PLATFORM_HAVEXADD)
	return (isc_mutex_init(&ref->lock));
#else
	return (ISC_R_SUCCESS);
#endif
}
