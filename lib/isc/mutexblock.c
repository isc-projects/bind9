/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

/*! \file */

#include <config.h>

#include <isc/mutexblock.h>
#include <isc/util.h>

isc_result_t
isc_mutexblock_init(isc_mutex_t *block, unsigned int count) {
	isc_result_t result;
	unsigned int i;

	for (i = 0; i < count; i++) {
		result = isc_mutex_init(&block[i]);
		if (result != ISC_R_SUCCESS) {
			while (i > 0U) {
				i--;
				DESTROYLOCK(&block[i]);
			}
			return (result);
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mutexblock_destroy(isc_mutex_t *block, unsigned int count) {
	isc_result_t result;
	unsigned int i;

	for (i = 0; i < count; i++) {
		result = isc_mutex_destroy(&block[i]);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	return (ISC_R_SUCCESS);
}
