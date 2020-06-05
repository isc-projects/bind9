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

/*! \file
 * \brief
 * This file contains the OS-independent functionality of the API.
 */
#include <stdbool.h>

#include <isc/fsaccess.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include "fsaccess_common_p.h"

void
isc_fsaccess_add(int trustee, int permission, isc_fsaccess_t *access) {
	REQUIRE(trustee <= 0x7);
	REQUIRE(permission <= 0xFF);

	if ((trustee & ISC_FSACCESS_OWNER) != 0) {
		*access |= permission;
	}

	if ((trustee & ISC_FSACCESS_GROUP) != 0) {
		*access |= (permission << GROUP);
	}

	if ((trustee & ISC_FSACCESS_OTHER) != 0) {
		*access |= (permission << OTHER);
	}
}

void
isc_fsaccess_remove(int trustee, int permission, isc_fsaccess_t *access) {
	REQUIRE(trustee <= 0x7);
	REQUIRE(permission <= 0xFF);

	if ((trustee & ISC_FSACCESS_OWNER) != 0) {
		*access &= ~permission;
	}

	if ((trustee & ISC_FSACCESS_GROUP) != 0) {
		*access &= ~(permission << GROUP);
	}

	if ((trustee & ISC_FSACCESS_OTHER) != 0) {
		*access &= ~(permission << OTHER);
	}
}

isc_result_t
isc__fsaccess_check_bad_bits(isc_fsaccess_t access, bool is_dir) {
	isc_fsaccess_t bits;

	/*
	 * Check for disallowed user bits.
	 */
	if (is_dir) {
		bits = ISC_FSACCESS_READ | ISC_FSACCESS_WRITE |
		       ISC_FSACCESS_EXECUTE;
	} else {
		bits = ISC_FSACCESS_CREATECHILD | ISC_FSACCESS_ACCESSCHILD |
		       ISC_FSACCESS_DELETECHILD | ISC_FSACCESS_LISTDIRECTORY;
	}

	/*
	 * Set group bad bits.
	 */
	bits |= bits << STEP;
	/*
	 * Set other bad bits.
	 */
	bits |= bits << STEP;

	if ((access & bits) != 0) {
		if (is_dir) {
			return (ISC_R_NOTFILE);
		} else {
			return (ISC_R_NOTDIRECTORY);
		}
	}

	return (ISC_R_SUCCESS);
}
