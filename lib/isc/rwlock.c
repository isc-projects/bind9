/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

#include <ck_rwlock.h>

#include <isc/magic.h>
#include <isc/msgs.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

inline
isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota)
{
	UNUSED(read_quota);
	UNUSED(write_quota);

	ck_rwlock_init(rwl);

	return (ISC_R_SUCCESS);
}

inline
void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	UNUSED(rwl);
	return;
}

inline
isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {

	switch (type) {
	case isc_rwlocktype_read: ck_rwlock_read_lock(rwl); break;
	case isc_rwlocktype_write: ck_rwlock_write_lock(rwl); break;
	default: INSIST(0);
	}

	return (ISC_R_SUCCESS);
}

inline
isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	bool ret = false;
	switch (type) {
	case isc_rwlocktype_read: ret = ck_rwlock_read_trylock(rwl); break;
	case isc_rwlocktype_write: ret = ck_rwlock_write_trylock(rwl); break;
	default: INSIST(0);
	}

	return ((ret)?ISC_R_SUCCESS:ISC_R_LOCKBUSY);
}

inline
isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	switch (type) {
	case isc_rwlocktype_read: ck_rwlock_read_unlock(rwl); break;
	case isc_rwlocktype_write: ck_rwlock_write_unlock(rwl); break;
	default: INSIST(0);
	}

	return (ISC_R_SUCCESS);
}

inline
isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	UNUSED(rwl);
	return (ISC_R_LOCKBUSY);
}

inline
void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	ck_rwlock_write_downgrade(rwl);
}
