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

#include <isc/crypto.h>
#include <isc/hash.h>
#include <isc/iterated_hash.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/refcount.h>
#include <isc/tls.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>
#include <isc/xml.h>

#include "mem_p.h"
#include "mutex_p.h"
#include "os_p.h"
#include "thread_p.h"

/***
 *** Functions
 ***/

static isc_refcount_t isc__lib_references = 0;

void
isc__lib_initialize(void);
void
isc__lib_shutdown(void);

void
isc__lib_initialize(void) {
	if (isc_refcount_increment0(&isc__lib_references) > 0) {
		return;
	}

	rcu_register_thread();
	isc__thread_initialize();
	isc__os_initialize();
	isc__mutex_initialize();
	isc__mem_initialize();
	isc__log_initialize();
	isc__crypto_initialize();
	isc__uv_initialize();
	isc__xml_initialize();
	isc__hash_initialize();
	isc__iterated_hash_initialize();
	(void)isc_os_ncpus();
}

void
isc__lib_shutdown(void) {
	if (isc_refcount_decrement(&isc__lib_references) > 1) {
		return;
	}

	isc__iterated_hash_shutdown();
	isc__xml_shutdown();
	isc__uv_shutdown();
	isc__crypto_shutdown();
	isc__log_shutdown();
	isc__mem_shutdown();
	isc__mutex_shutdown();
	isc__os_shutdown();
	isc__thread_shutdown();
	/* should be after isc__mem_shutdown() which calls rcu_barrier() */
	rcu_unregister_thread();
}
