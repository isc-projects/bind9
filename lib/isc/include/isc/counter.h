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

#pragma once

/*! \file isc/counter.h
 *
 * \brief The isc_counter_t object is a simplified version of the
 * isc_quota_t object; it tracks the consumption of limited
 * resources, returning an error condition when the quota is
 * exceeded.  However, unlike isc_quota_t, attaching and detaching
 * from a counter object does not increment or decrement the counter.
 */

#include <stddef.h>

#include <isc/refcount.h>
#include <isc/types.h>

void
isc_counter_create(isc_mem_t *mctx, size_t limit, isc_counter_t **counterp);
/**<
 * \brief
 * Allocate and initialize a counter object.
 */

isc_result_t
isc_counter_increment(isc_counter_t *counter);
/**<
 * \brief
 * Increment the counter.
 *
 * \details
 * The counter is incremented regardless of return value.
 *
 * \retval ISC_R_QUOTA if the counter limit is non-zero and has been reached.
 * \retval ISC_R_SUCCESS otherwise
 */

size_t
isc_counter_used(isc_counter_t *counter);
/**<
 * \brief
 * Return the current counter value.
 */

void
isc_counter_setlimit(isc_counter_t *counter, size_t limit);
/**<
 * \brief
 * Set the counter limit.
 */

size_t
isc_counter_getlimit(isc_counter_t *counter);
/**<
 * \brief
 * Get the counter limit.
 */

ISC_REFCOUNT_DECL(isc_counter);
