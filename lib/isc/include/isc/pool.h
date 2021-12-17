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

/*****
***** Module Info
*****/

/*! \file isc/pool.h
 * \brief An object pool is a mechanism for sharing a small pool of
 * fungible objects among a large number of objects that depend on them.
 *
 * This is useful, for example, when it causes performance problems for
 * large number of zones to share a single memory context or task object,
 * but it would create a different set of problems for them each to have an
 * independent task or memory context.
 */

/***
 *** Imports.
 ***/

#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/*****
***** Types.
*****/

typedef void (*isc_pooldeallocator_t)(void **object);

typedef isc_result_t (*isc_poolinitializer_t)(void **target, void *arg);

typedef struct isc_pool isc_pool_t;

/*****
***** Functions.
*****/

isc_result_t
isc_pool_create(isc_mem_t *mctx, unsigned int count, isc_pooldeallocator_t free,
		isc_poolinitializer_t init, void *initarg, isc_pool_t **poolp);
/*%<
 * Create a pool of "count" object pointers. If 'free' is not NULL,
 * it points to a function that will detach the objects.  'init'
 * points to a function that will initialize the arguments, and
 * 'arg' to an argument to be passed into that function (for example,
 * a relevant manager or context object).
 *
 * Requires:
 *
 *\li	'mctx' is a valid memory context.
 *
 *\li	init != NULL
 *
 *\li	poolp != NULL && *poolp == NULL
 *
 * Ensures:
 *
 *\li	On success, '*poolp' points to the new object pool.
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	#ISC_R_UNEXPECTED
 */

void *
isc_pool_get(isc_pool_t *pool);
/*%<
 * Returns a pointer to an object from the pool. Currently the object
 * is chosen from the pool at random.
 */

void
isc_pool_destroy(isc_pool_t **poolp);
/*%<
 * Destroy a task pool.  The tasks in the pool are detached but not
 * shut down.
 *
 * Requires:
 * \li	'*poolp' is a valid task pool.
 */

ISC_LANG_ENDDECLS
